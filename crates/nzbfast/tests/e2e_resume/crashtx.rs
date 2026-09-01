//! X5-03, the engine half: a crash between journal retirement and the
//! terminal commit must not cost the payload that was already delivered.
//!
//! The row (X5-03 of the 30 Aug 2026 adversarial-row set, recorded in
//! `research/X5-03-CRASH-TRANSACTION-2026-08-31.md`) asks what a restart finds when the process dies in the window between
//! `Journal::remove` and the terminal commit, with the post gone by then.
//! It was dispositioned "harness" through three capability rounds for one
//! reason: `run_get` runs the job to completion, so nothing could stop a
//! run mid-flight. `run_get_spawn` is that harness, and `get::tail`'s
//! `test_park_after_journal_retire` is the barrier - the product says
//! where the window is and holds still, so the kill lands INSIDE it
//! rather than near it.
//!
//! WHAT THIS PINS AND WHAT IT DOES NOT, because the row has two oracles
//! and only one of them is a question about the engine. "The exact
//! output remains" is asked here, and the answer is YES. "Restart
//! performs zero BODY requests" is NOT, and must not be retrofitted: it
//! is a claim about a PERSISTED TERMINAL STATE, which the `get` CLI does
//! not have and is not meant to have. The journal IS the CLI's only
//! durable record of what arrived (`get/plan.rs`'s `resuming` arm reads
//! nothing else), retiring it on a verified finish is correct, and a
//! plain no-PAR2 post leaves nothing on disk that certifies the bytes -
//! so a second `nzbfast get` over the same directory cannot know the
//! file is complete, and refetching is the only honest thing it can do.
//! Measured on this fixture: run 2 asks for 23 bodies, gets 23 refusals,
//! writes nothing, and leaves the delivered file exactly as it was.
//!
//! The zero-BODY half belongs to the DAEMON, where the queue row is the
//! durable terminal state the row is really about ("the row reaches
//! Completed"). It is BUILT, in `daemon_crashtx`, and it is RED: the
//! nonterminal `Finishing` restores as `Queued`, the journal is gone, the
//! job re-runs and files Failed after 44 refused BODY requests. That
//! probe is landed `#[ignore]`d with a live control beside it; see
//! `research/X5-03-CRASH-TRANSACTION-2026-08-31.md` section 7.
//!
//! A child of `e2e_resume` rather than a new top-level module: the
//! subject is what survives a SIGKILL and what run 2 then does with the
//! bytes on disk, which is this directory end to end. The filing rule is
//! `e2e_lateset::chainset`'s, and the reason is `e2e.rs`'s size-gate
//! baseline note.

use super::*;

/// The marker `get::tail::test_park_after_engine_finish` prints. Typed
/// here a second time because a test binary cannot see a private const
/// in the library; if the two ever part, `wait_for` below fails LOUDLY
/// with the whole log rather than passing on a window it never reached.
const PARKED: &str = "engine finish settled - parked for the crash-transaction probe";

/// The wedge bound handed to the barrier. It is not a wait - the test
/// waits for `PARKED` - only the ceiling on how long a parked run holds
/// if the test dies before killing it.
const PARK_MS: &str = "60000";

/// A SIGKILL in the X5-03 window, followed by a restart against a post
/// that has gone away, must leave the delivered payload byte-exact and
/// must leave no debris beside it.
///
/// Run 1 completes a plain no-PAR2 job, so at the barrier the bytes are
/// on disk and the journal is gone - the exact state the row names.
/// SIGKILL there, take the post down, and run again: the provider now
/// answers 430 for every BODY, which is what makes the question sharp. A
/// restart that refetches has nothing to refetch WITH, so anything it
/// does to the good file it does for nothing - and the failing tail it
/// then walks (`quarantine_failed_payload`, and the truncating fresh
/// creation in `nzbkit::disk`) is where the row predicted the loss.
#[tokio::test(flavor = "multi_thread")]
async fn x5_03_a_crash_after_journal_retirement_keeps_the_delivered_payload() {
    let mut fx = Fixture::new("crashtx");
    let data = payload(600_000, 11);
    fx.add_file("movie.bin", &data, 60_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let landed = out.join("movie.bin");
    let journal = out.join(".nzbfast.journal");

    // Run 1, killed inside the window. The whole sequence is off the
    // runtime's worker threads: `wait_for` and `kill9` block, and the
    // mock server this run is talking to lives on the same runtime.
    {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        let (landed, journal) = (landed.clone(), journal.clone());
        let data = data.clone();
        tokio::task::spawn_blocking(move || {
            let run = run_get_spawn(
                &cfg,
                &nzb,
                &out,
                &[("NZBFAST_TEST_PARK_AFTER_ENGINE_FINISH_MS", PARK_MS)],
                &[],
                GET_CONNS,
                GET_WINDOW,
            );
            let log = run.wait_for(PARKED);
            // The premise, asserted rather than assumed: at the barrier
            // the job really has delivered and the journal really is
            // gone. Without both, the kill below is a crash somewhere
            // else and every verdict after it is about a different
            // question.
            assert_eq!(
                std::fs::read(&landed).expect("the payload is on disk at the barrier"),
                data,
                "run 1 parked without the payload complete:\n{log}"
            );
            // The barrier is common to both front ends now, so this
            // asserts what the CLI'S OWN owner did with the file rather
            // than a property of the barrier: `JournalOwner::Run` means
            // this run retired it, and a CLI that stopped doing so would
            // be a different product (see that type's own note - a
            // second `get` has nothing else on disk to read).
            assert!(
                !journal.exists(),
                "run 1 parked with the journal still on disk - a CLI run owns its own \
                 retirement and must have unlinked it before the barrier:\n{log}"
            );
            run.kill9();
        })
        .await
        .unwrap();
    }

    // The post is gone: every BODY is now a 430, so run 2 cannot rebuild
    // anything it destroys.
    assert!(
        srv.take_down() > 0,
        "the fixture posted nothing to take down"
    );

    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    // Run 2 fails, and that is correct: it has no record of run 1 and
    // every article it asks for is refused. What it must not do is take
    // the good bytes with it.
    assert!(!ok, "run 2 succeeded against a post that is gone:\n{log}");
    assert_eq!(
        std::fs::read(&landed).unwrap_or_default(),
        data,
        "the restart destroyed a payload it had already delivered:\n{log}"
    );
    // Graded by NAME as well as by bytes: `quarantine_failed_payload`
    // takes a failed run's payload out of circulation by RENAMING it,
    // so a run that both kept the bytes and moved them would satisfy the
    // read above while handing an *arr a directory with no `movie.bin`
    // in it. Everything but the file and a fresh journal is debris.
    let mut left: Vec<String> = std::fs::read_dir(&out)
        .expect("the output directory survives")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != "movie.bin" && n != ".nzbfast.journal")
        .collect();
    left.sort();
    assert!(
        left.is_empty(),
        "the restart left {left:?} beside the delivered payload:\n{log}"
    );
}
