//! `smart` unit tests, part 1: the mover's I/O policy, the trash
//! backends, rule matching, and TV filing (which episode a name
//! claims, and which files a delete may take). Part 2 is
//! sweep_rename_tests.rs; shared helpers are in testkit.rs.
//!
//! A child module file rather than an inline `mod tests`: smart.rs
//! sits under a size-gate baseline (TODO 106) and these cases were
//! most of its length, same pattern as cleanup_mode_tests.rs.

//! Unit tests for `smart` - the cleanup, trash, move and rename
//! helpers. A child module file rather than an inline `mod tests`:
//! smart.rs sits under a size-gate baseline (TODO 106) and 3,200
//! lines of table-driven cases were most of the parent, same pattern
//! as cleanup_mode_tests.rs beside it.

use super::movetree::*;
use super::testkit::*;
use super::*;

/// The move-I/O demotion must RESTORE the thread's policy on drop:
/// moves run on tokio's pooled blocking threads, so a policy left set
/// would demote whatever unrelated work that thread picks up next.
#[cfg(target_os = "macos")]
#[test]
fn background_io_restores_the_thread_policy() {
    // Own thread: the assertion is about THIS thread's policy, and the
    // test harness's threads are shared.
    // SAFETY: every call in this closure is a getiopolicy_np /
    // setiopolicy_np pair taking three ints and touching no memory, and
    // each acts on the calling thread - which is this freshly spawned
    // one, owned entirely by the test.
    std::thread::spawn(|| unsafe {
        let before = iopol::getiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD);
        let prev = before;
        let guard = BackgroundIo { prev };
        assert_eq!(
            iopol::setiopolicy_np(
                iopol::IOPOL_TYPE_DISK,
                iopol::IOPOL_SCOPE_THREAD,
                iopol::IOPOL_THROTTLE
            ),
            0
        );
        assert_eq!(
            iopol::getiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD),
            iopol::IOPOL_THROTTLE
        );
        drop(guard);
        assert_eq!(
            iopol::getiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD),
            before
        );
    })
    .join()
    .unwrap();
}

/// A copy whose destination holds every byte passes; the verify is
/// what runs between "copied" and "the source may now be deleted".
#[test]
fn copy_verified_accepts_a_whole_copy() {
    let dir = std::env::temp_dir().join(format!("nzbfast-copy-verified-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let from = dir.join("a.bin");
    let to = dir.join("b.bin");
    std::fs::write(&from, vec![7u8; 1 << 20]).unwrap();
    copy_verified(&from, &to).unwrap();
    assert_eq!(std::fs::metadata(&to).unwrap().len(), 1 << 20);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A mover failure must say which operation on which path refused,
/// keep the OS's own "(os error N)" text for `disk_full_failure`,
/// and keep the error kind. The 7 Aug 2026 SMB incident was a bare
/// "Permission denied (os error 13)" out of a dozen possible
/// syscalls over two trees - undiagnosable as printed.
#[test]
fn mover_errors_name_the_operation_and_path() {
    let dir = std::env::temp_dir().join(format!("nzbfast-copy-ctx-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let from = dir.join("missing.bin");
    let to = dir.join("out.bin");

    let plain = copy_verified(&from, &to).unwrap_err();
    assert_eq!(plain.kind(), std::io::ErrorKind::NotFound);
    let said = plain.to_string();
    assert!(
        said.contains("copy") && said.contains("missing.bin") && said.contains("(os error"),
        "unpaced: operation, path and OS text must all survive: {said}"
    );

    let noop: &PaceFn<'_> = &|_| {};
    let paced = copy_verified_paced(&from, &to, Some(noop)).unwrap_err();
    assert_eq!(paced.kind(), std::io::ErrorKind::NotFound);
    let said = paced.to_string();
    assert!(
        said.contains("open source") && said.contains("missing.bin") && said.contains("(os error"),
        "paced: operation, path and OS text must all survive: {said}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn staged_delete_leaves_the_tree_synchronously() {
    let _steady = trash_globals_steady();
    // The §64 contract: by the time `stage` returns, the file is OUT
    // of the job tree - so finalize can move the directory the very
    // next instant without racing the delete - and the worker disposes
    // of the parked copy behind us. Under cfg(test) the trash global
    // defaults off, so the disposal is a direct delete rather than a
    // real Trash conversation.
    let parent = std::env::temp_dir().join(format!("nzbfast-defer-trash-{}", std::process::id()));
    let job = parent.join("job");
    std::fs::create_dir_all(&job).unwrap();
    let f = job.join("junk.par2");
    std::fs::write(&f, b"x").unwrap();
    let staging = trash_staging_dir(&job).unwrap();
    let r = deferred_trash::stage(&f, &staging);
    assert!(r.is_ok(), "stage: {r:?}");
    assert!(!f.exists(), "the rename must be synchronous");
    deferred_trash::drained();
    assert!(
        !staging.exists(),
        "the worker must dispose of the parked file and prune the empty staging dir"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

#[test]
fn first_stage_drains_a_predecessors_leftovers() {
    let _steady = trash_globals_steady();
    // A crash between park and disposal strands files in the staging
    // folder. The first stage into that folder after a restart queues
    // whatever it finds, so leftovers cannot accumulate forever.
    let parent =
        std::env::temp_dir().join(format!("nzbfast-defer-leftover-{}", std::process::id()));
    let job = parent.join("job");
    std::fs::create_dir_all(&job).unwrap();
    let staging = trash_staging_dir(&job).unwrap();
    std::fs::create_dir_all(&staging).unwrap();
    let leftover = staging.join("99999-0-stranded.nfo");
    std::fs::write(&leftover, b"x").unwrap();
    let f = job.join("junk.nfo");
    std::fs::write(&f, b"x").unwrap();
    deferred_trash::stage(&f, &staging).unwrap();
    deferred_trash::drained();
    assert!(
        !leftover.exists() && !staging.exists(),
        "the leftover must go with the freshly staged file"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

/// The staging root is DRAINED, not the folder it happens to share a
/// name with - and never through a symlink.
///
/// `.nzbfast-trash` is a fixed name in the user's own downloads folder,
/// which a NAS share, a sync client, a container bind-mount or a second
/// application can all write to. The first-touch drain used to send
/// EVERY entry it found there straight to `remove_user_file`: unrelated
/// files were adopted as our garbage and moved to the user's Trash, or
/// hard-unlinked outright whenever the cleanup setting said Delete (the
/// worker re-reads that flag per file at disposal time, so an ordinary
/// Settings change between staging and disposal is enough). And
/// `create_dir_all` answers Ok for an existing `is_dir()` path, which
/// FOLLOWS symlinks, so a link at that name carried the whole thing into
/// somebody else's directory.
#[test]
fn the_drain_takes_only_what_this_module_staged() {
    let _steady = trash_globals_steady();
    let parent = std::env::temp_dir().join(format!("nzbfast-defer-adopt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&parent);
    let job = parent.join("job");
    std::fs::create_dir_all(&job).unwrap();
    let staging = trash_staging_dir(&job).unwrap();
    std::fs::create_dir_all(&staging).unwrap();

    // Somebody else's file, and somebody else's folder, already sitting
    // in the staging root.
    let sentinel = staging.join("users-photo.jpg");
    std::fs::write(&sentinel, b"mine").unwrap();
    let sentinel_dir = staging.join("someone-elses-folder");
    std::fs::create_dir_all(sentinel_dir.join("inner")).unwrap();
    // ...and one real leftover of ours, which MUST still be drained.
    let ours = staging.join("99999-0-stranded.nfo");
    std::fs::write(&ours, b"x").unwrap();

    let f = job.join("junk.nfo");
    std::fs::write(&f, b"x").unwrap();
    deferred_trash::stage(&f, &staging).unwrap();

    // The fence, and not a poll on `ours`: a poll returns as soon as our
    // own leftover goes, which is BEFORE the worker has had the chance
    // to adopt anything else - so the two sentinel asserts below were
    // passing on a worker that had not got to them yet, whether it would
    // have taken them or not.
    deferred_trash::drained();
    assert!(!ours.exists(), "our own leftover is still drained");
    assert!(sentinel.exists(), "an unrelated FILE must survive");
    assert!(sentinel_dir.exists(), "an unrelated FOLDER must survive");
    let _ = std::fs::remove_dir_all(&parent);
}

/// A symlink at the staging root is REFUSED, so nothing is renamed into
/// it and nothing on the other side of it is enumerated.
///
/// `stage`'s contract is that any Err means "park unavailable" and the
/// caller deletes inline instead, which is the behaviour that predates
/// the staging folder entirely - so refusing here costs nothing.
#[cfg(unix)]
#[test]
fn a_symlinked_staging_root_is_refused() {
    let _steady = trash_globals_steady();
    let parent = std::env::temp_dir().join(format!("nzbfast-defer-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&parent);
    let job = parent.join("job");
    let elsewhere = parent.join("elsewhere");
    std::fs::create_dir_all(&job).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    let sentinel = elsewhere.join("users-photo.jpg");
    std::fs::write(&sentinel, b"mine").unwrap();

    let staging = trash_staging_dir(&job).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &staging).unwrap();

    let f = job.join("junk.nfo");
    std::fs::write(&f, b"x").unwrap();
    assert!(
        deferred_trash::stage(&f, &staging).is_err(),
        "a symlinked root must not be adopted"
    );
    assert!(f.exists(), "and the caller's file is left for it to delete");
    assert!(sentinel.exists(), "nothing through the link was touched");
    assert!(
        std::fs::read_dir(&elsewhere).unwrap().count() == 1,
        "and nothing was renamed into it either"
    );
    let _ = std::fs::remove_file(&staging);
    let _ = std::fs::remove_dir_all(&parent);
}

/// A REFUSED disposal must be retried inside this process, not at the
/// next restart.
///
/// `SEEN` latches a staging root at its first stage, and every later
/// stage into it sends only its own file - so a file the disposal
/// refused sat in `.nzbfast-trash` beside the user's downloads with
/// nothing to ask about it again. `first_stage_drains_a_predecessors_leftovers`
/// covers the restart; this covers the day that never comes.
///
/// The refusal is forced the one way a test can force one without a
/// broken Trash: a staged entry that is a NON-EMPTY DIRECTORY, which
/// `remove_file` cannot take (EPERM on macOS, EISDIR on Linux).
#[test]
fn a_refused_disposal_is_retried_by_the_next_stage() {
    let _steady = trash_globals_steady();
    let parent = std::env::temp_dir().join(format!("nzbfast-defer-refused-{}", std::process::id()));
    let job = parent.join("job");
    std::fs::create_dir_all(&job).unwrap();
    let staging = trash_staging_dir(&job).unwrap();
    std::fs::create_dir_all(&staging).unwrap();

    // A leftover the worker cannot dispose of, in the shape a crashed
    // predecessor leaves behind.
    let stuck = staging.join("99999-0-stuck.nfo");
    std::fs::create_dir_all(stuck.join("inner")).unwrap();

    // First stage: drains the root, disposes of its own file, and is
    // refused by the leftover.
    let first = job.join("one.par2");
    std::fs::write(&first, b"x").unwrap();
    deferred_trash::stage(&first, &staging).unwrap();
    // The fence, and not a poll: the worker prunes an emptied staging
    // root at the END of the same iteration that disposed of the file,
    // and a poll on the folder cannot see that step pending. Clearing
    // `stuck` below empties the root, so a poll that returned early
    // handed the pending prune the staging folder - and the write after
    // it failed `NotFound`. See `deferred_trash::drained`.
    deferred_trash::drained();
    assert!(
        std::fs::read_dir(&staging)
            .map(Iterator::count)
            .unwrap_or(0)
            == 1
            && stuck.exists(),
        "the refused leftover is all that should be left in the staging folder"
    );

    // Whatever was refusing it clears (here: the same name becomes an
    // ordinary file, since `remove_file` refuses a directory whether or
    // not it is empty). Nothing re-lists the folder on its own, so the
    // retry has to ride the next stage.
    std::fs::remove_dir_all(&stuck).unwrap();
    std::fs::write(&stuck, b"x").unwrap();
    let second = job.join("two.par2");
    std::fs::write(&second, b"x").unwrap();
    deferred_trash::stage(&second, &staging).unwrap();
    deferred_trash::drained();
    assert!(
        !staging.exists(),
        "the second stage must re-drain the root it was refused in, \
         so the leftover goes and the empty folder is pruned"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

#[test]
fn latched_swept_delete_stays_inline() {
    // With the latch set there is no Trash to park FOR, so the sweep
    // must not create a staging folder: a hidden folder beside the
    // user's downloads that nobody will ever drain is exactly the
    // Unraid `.Trash-<uid>` complaint in our own handwriting.
    //
    // Serialized with the other latch-writing tests: this one leaves
    // TRASH_UNRESPONSIVE set for the length of a delete, and
    // `a_junk_delete_is_recoverable_and_the_opt_out_is_not` deletes
    // into the real Trash and fails if it reads the latch set.
    let _serial = one_trash_test_at_a_time();
    let parent = std::env::temp_dir().join(format!("nzbfast-defer-latched-{}", std::process::id()));
    let job = parent.join("job");
    std::fs::create_dir_all(&job).unwrap();
    let f = job.join("junk.sfv");
    std::fs::write(&f, b"x").unwrap();
    let staging = trash_staging_dir(&job).unwrap();
    TRASH_UNRESPONSIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    let r = remove_swept_file(&f, true, Some(&staging));
    TRASH_UNRESPONSIVE.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(!staging.exists(), "no staging dir on the latched path");
    assert!(r.is_err(), "a refused sweep must report, not claim success");
    assert!(
        f.exists(),
        "and the file it could not bin must still be there"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

/// The rule this whole path exists for: a delete the user asked to be
/// RECOVERABLE never becomes a permanent one behind their back.
///
/// It used to. Any Trash failure - a headless Finder timing out, or
/// (live, 3 Aug 2026) a `-10010` from a directory on an external
/// volume - fell through to `remove_file`/`remove_dir_all`, so the one
/// setting that promised a wrong guess could be undone became the
/// thing that made it permanent. Both shapes are covered: a swept junk
/// file, and a whole finished download.
#[test]
fn a_refused_trash_leaves_the_files_alone() {
    let _serial = one_trash_test_at_a_time();
    let dir = std::env::temp_dir().join(format!("nzbfast-trash-refused-{}", std::process::id()));
    let job = dir.join("Some.Release.2026");
    std::fs::create_dir_all(&job).unwrap();
    let f = dir.join("junk.par2");
    std::fs::write(&f, b"x").unwrap();
    std::fs::write(job.join("feature.mkv"), b"payload").unwrap();

    TRASH_UNRESPONSIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    let file = remove_user_file(&f, true);
    let whole_job = remove_user_dir(&job, true);
    TRASH_UNRESPONSIVE.store(false, std::sync::atomic::Ordering::Relaxed);

    assert!(file.is_err(), "a refused file delete must report it");
    assert!(f.exists(), "the file must survive a Trash that refused it");
    assert!(
        whole_job.is_err(),
        "a refused directory delete must report it"
    );
    assert!(
        job.join("feature.mkv").exists(),
        "a finished download must survive a Trash that refused it"
    );
    // It has to say what happened and what to do, not just that
    // something went wrong: this string is read by a person, in the
    // log and in the dashboard's kept-files notice. It no longer
    // repeats the outcome ("left where they are") - both surfaces put
    // this after a line that has already said the files are still
    // there, and it said the same thing three times over.
    let said = whole_job.unwrap_err().to_string();
    assert!(
        said.contains("the Trash would not take it")
            && said.contains("Deleted files go to the Trash"),
        "the error must name the cause and the setting: {said}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A path that is already gone is a no-op, not a Trash failure.
///
/// macOS's Finder route reports an unresolvable path as `-10010`
/// ("Handler can't handle objects of this class"), because the crate
/// canonicalizes only the PARENT and a missing leaf reaches the
/// AppleScript intact. That printed "could not move <a user's
/// download> to the Trash - deleting it instead" for a directory that
/// had already gone - the live line that started all this. With the
/// refusal rule it would be worse than noise: a delete would come back
/// as an error for work already done.
#[test]
fn a_path_that_is_already_gone_is_not_a_refusal() {
    let _serial = one_trash_test_at_a_time();
    let dir = std::env::temp_dir().join(format!("nzbfast-trash-ghost-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ghost_file = dir.join("already-binned.nfo");
    let ghost_dir = dir.join("already-deleted-job");
    // Deliberately never created - and the latch is NOT set, so a
    // regression here reaches the real backend rather than short-
    // circuiting on it.
    assert!(
        remove_user_file(&ghost_file, true).is_ok(),
        "a file that is already gone is a success"
    );
    assert!(
        remove_user_dir(&ghost_dir, true).is_ok(),
        "a directory that is already gone is a success"
    );
    let _ = std::fs::remove_dir(&dir);
}

/// The give-up path, which is the entire point of the change and the
/// one case a healthy developer machine cannot produce: a Trash call
/// that never comes back must not hold the caller.
#[test]
fn a_hanging_trash_call_does_not_hold_the_caller() {
    let started = std::time::Instant::now();
    let out = run_bounded(std::time::Duration::from_millis(150), || {
        std::thread::sleep(std::time::Duration::from_secs(30));
        "finished"
    });
    assert!(
        out.is_none(),
        "a call past its deadline must report giving up"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the caller waited {:?} on a call it had given up on",
        started.elapsed()
    );
}

/// ...and a call that DOES answer in time is passed straight through,
/// so bounding it costs a healthy Finder nothing.
#[test]
fn a_prompt_trash_call_is_returned_unchanged() {
    let out = run_bounded(std::time::Duration::from_secs(30), || 7);
    assert_eq!(out, Some(7), "a prompt call must return its own result");
}

/// After giving up, the direct delete races the abandoned Finder call.
/// If Finder wins, the file is already gone and `remove_file` fails
/// NotFound - the outcome we wanted, so it must not surface as an
/// error. Without this the job would report a cleanup failure for a
/// file that was successfully binned.
#[test]
fn losing_the_race_to_the_trash_is_not_a_failure() {
    let _serial = one_trash_test_at_a_time();
    let dir = std::env::temp_dir().join(format!("nzbfast-trash-race-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let gone = dir.join("already-binned.nfo");
    // Never created: stands in for the file the abandoned call binned
    // a moment before we got to it.
    TRASH_UNRESPONSIVE.store(true, std::sync::atomic::Ordering::Relaxed);
    let r = remove_user_file(&gone, true);
    TRASH_UNRESPONSIVE.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(
        r.is_ok(),
        "a file that is already gone is a success, not {r:?}"
    );
    let _ = std::fs::remove_dir(&dir);
}

/// The bug the gate exists for: callers that overlap each read the
/// latch before any of them set it, so each started its own probe and
/// each paid the full deadline. Observed on a headless bench box as
/// the "not responding" line printed twice and ~60 s added to a 208 s
/// queue. One probe for the process, however many callers overlap -
/// the deferred worker, a library delete and the watch dir can all be
/// in here at once.
#[test]
fn concurrent_callers_probe_a_dead_trash_only_once() {
    use std::sync::atomic::Ordering::Relaxed;
    let _serial = one_trash_test_at_a_time();
    TRASH_UNRESPONSIVE.store(false, Relaxed);
    TRASH_ANSWERED.store(false, Relaxed);

    const CALLERS: usize = 4;
    const PROBE: std::time::Duration = std::time::Duration::from_millis(300);
    let probes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start = std::sync::Arc::new(std::sync::Barrier::new(CALLERS));
    let began = std::time::Instant::now();
    let callers: Vec<_> = (0..CALLERS)
        .map(|_| {
            let probes = probes.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                // All four inside the check-then-call window together,
                // which is what made the real callers each probe.
                start.wait();
                trash_delete_gated(|| {
                    probes.fetch_add(1, Relaxed);
                    // Stands in for a Finder that never answers: the
                    // real one is bounded at TRASH_DEADLINE and comes
                    // back exactly like this.
                    std::thread::sleep(PROBE);
                    Err("timed out".to_string())
                })
            })
        })
        .collect();
    let verdicts: Vec<_> = callers.into_iter().map(|c| c.join().unwrap()).collect();
    let elapsed = began.elapsed();
    TRASH_UNRESPONSIVE.store(false, Relaxed);
    TRASH_ANSWERED.store(false, Relaxed);

    assert_eq!(
        probes.load(Relaxed),
        1,
        "{CALLERS} concurrent callers must cost one probe, not one each"
    );
    assert_eq!(
        verdicts.iter().filter(|v| matches!(v, Err(None))).count(),
        CALLERS - 1,
        "every caller but the prober must be told to delete directly: {verdicts:?}"
    );
    assert!(
        elapsed < PROBE * 2,
        "the callers took {elapsed:?} - a single {PROBE:?} probe should cover all {CALLERS}"
    );
}

fn rule(pattern: &str) -> Rule {
    Rule {
        name: String::new(),
        pattern: pattern.into(),
        not_match: String::new(),
        min_size: 0,
        max_size: 0,
        category: String::new(),
        tv_sort: false,
    }
}

#[test]
fn keyword_and_regex_matching() {
    // Keyword (valid trivial regex) - case-insensitive substring.
    assert!(rule("matrix").matches("The.Matrix.1999.1080p.BluRay-GRP", 0));
    assert!(!rule("matrix").matches("Inception.2010.1080p", 0));
    // Real regex.
    assert!(rule(r"^The\.Bear\.S\d+E\d+").matches("The.Bear.S03E05.1080p.WEB-X", 0));
    assert!(!rule(r"^The\.Bear\.S\d+E\d+").matches("Not.The.Bear.S03E05", 0));
    // Alternation.
    assert!(rule("2160p|1080p").matches("Show.S01E01.2160p.WEB", 0));
    // Invalid regex falls back to keyword substring.
    assert!(rule("kill bill (").matches("My.Kill Bill (.Collection", 0));
    assert!(!rule("kill bill (").matches("Kill.Bill.2003", 0));
    // Empty pattern matches everything (size-only rules).
    assert!(rule("").matches("anything", 123));
}

#[test]
fn not_match_and_sizes() {
    let mut r = rule("1080p");
    r.not_match = "x265".into();
    assert!(r.matches("Show.S01E01.1080p.x264-GRP", 0));
    assert!(!r.matches("Show.S01E01.1080p.x265-GRP", 0));
    let mut r = rule("");
    r.min_size = 200_000_000;
    r.max_size = 4_000_000_000;
    assert!(!r.matches("small", 100_000_000));
    assert!(r.matches("mid", 1_000_000_000));
    assert!(!r.matches("big", 5_000_000_000));
}

#[test]
fn first_match_wins() {
    let mut a = rule("1080p");
    a.category = "tv-hd".into();
    let mut b = rule("1080p");
    b.category = "tv".into();
    let rules = [a, b];
    assert_eq!(
        first_match(&rules, "Show.S01E01.1080p", 0)
            .unwrap()
            .category,
        "tv-hd"
    );
    assert!(first_match(&rules, "Show.S01E01.720p", 0).is_none());
}

#[test]
fn size_strings_deserialize() {
    let r: Rule = serde_json::from_str(
        r#"{"name":"x","match":"a","min_size":"200M","max_size":4000000000,"category":"tv"}"#,
    )
    .unwrap();
    assert_eq!(r.min_size, 200_000_000);
    assert_eq!(r.max_size, 4_000_000_000);
    let r: Rule = serde_json::from_str(r#"{"match":"a","min_size":""}"#).unwrap();
    assert_eq!(r.min_size, 0);
}

#[test]
fn tv_rename_mapping() {
    assert_eq!(
        tv_path("The.Bear.S03E05.1080p.WEB.h264-GRP"),
        Some((
            "The Bear/Season 03".into(),
            Some("The Bear - S03E05".into())
        ))
    );
    // Multi-episode posts keep the full range in the filed name
    // (§7b: the second episode used to vanish from the library).
    assert_eq!(
        tv_path("The.Bear.S03E05E06.1080p.WEB.h264-GRP"),
        Some((
            "The Bear/Season 03".into(),
            Some("The Bear - S03E05-E06".into())
        ))
    );
    assert_eq!(
        tv_path("The.Bear.S03E05-E06.1080p.WEB.h264-GRP"),
        Some((
            "The Bear/Season 03".into(),
            Some("The Bear - S03E05-E06".into())
        ))
    );
    // Season pack: directory but no rename base.
    assert_eq!(
        tv_path("Severance.S02.2160p.WEB-DL.COMPLETE-X"),
        Some(("Severance/Season 02".into(), None))
    );
    // 3x07 form.
    assert_eq!(
        tv_path("the-flash-3x07-720p-hdtv-x264"),
        Some((
            "The Flash/Season 03".into(),
            Some("The Flash - S03E07".into())
        ))
    );
    // Movies and obfuscated names refuse.
    assert_eq!(tv_path("Inception.2010.1080p.BluRay.x264-GRP"), None);
    assert_eq!(tv_path("2137d880a074ab31de52"), None);
}

/// A daily show has no season or episode number, only an air date -
/// so requiring a season left every one of them where it landed,
/// under its raw release name.
#[test]
fn dated_shows_file_by_air_date() {
    // Dotted date.
    assert_eq!(
        tv_path("The.Daily.Show.2026.07.21.1080p.WEB.x264-GRP"),
        Some((
            "The Daily Show/Season 2026".into(),
            Some("The Daily Show - 2026.07.21".into())
        ))
    );
    // Compact YYMMDD datecode - the other convention the parser
    // knows, normalized to the same name.
    assert_eq!(
        tv_path("At.Midnight.150615.720p.HDTV.x264-GRP"),
        Some((
            "At Midnight/Season 2015".into(),
            Some("At Midnight - 2015.06.15".into())
        ))
    );
    // Full YYYYMMDD datecode.
    assert_eq!(
        tv_path("At.Midnight.20150615.720p.HDTV.x264-GRP"),
        Some((
            "At Midnight/Season 2015".into(),
            Some("At Midnight - 2015.06.15".into())
        ))
    );
    // A compact YYMMDD the parser had to fix up on its own (no
    // four-digit year to lean on) files exactly like the dotted form.
    assert_eq!(
        tv_path("At.Midnight.260721.1080p.WEB.x264-GRP"),
        Some((
            "At Midnight/Season 2026".into(),
            Some("At Midnight - 2026.07.21".into())
        ))
    );
    // A numbered season still wins: a show that carries both is not
    // filed by date.
    assert_eq!(
        tv_path("Show.S03E05.2026.07.21.1080p.WEB-GRP"),
        Some(("Show/Season 03".into(), Some("Show - S03E05".into())))
    );
    assert_eq!(
        tv_path("Show.S03E05.260721.1080p.WEB-GRP"),
        Some(("Show/Season 03".into(), Some("Show - S03E05".into())))
    );
    // A one-word show is a real title, not a blob - the hash guard
    // must not swallow it.
    assert_eq!(
        tv_path("Newsnight.2026.07.21.1080p.WEB-GRP"),
        Some((
            "Newsnight/Season 2026".into(),
            Some("Newsnight - 2026.07.21".into())
        ))
    );
    // The show title gets the same portability treatment as every
    // other emitted component.
    let (dir, base) = tv_path("Alien: Romulus 2026.07.21 1080p WEB-GRP").unwrap();
    assert_eq!(dir, "Alien - Romulus/Season 2026");
    assert_eq!(base.as_deref(), Some("Alien - Romulus - 2026.07.21"));
    for part in dir.split('/') {
        assert_portable(part);
    }
    assert_portable(&base.unwrap());
}

/// The declines. The `daily` flag fires on ANY 8-digit run because
/// all it has to decide is "not a movie"; a name written to disk
/// needs more than that, so anything short of a real date and a
/// presentable title stays where it landed. A six-digit run that is
/// not a date never even reaches here - the parser leaves it in the
/// title and the release stays a Movie.
#[test]
fn a_shaky_date_never_files() {
    // Digit runs that are not calendar dates.
    for stem in [
        "Blob.999999.1080p.WEB-GRP",   // month 99
        "Blob.20261332.1080p.WEB-GRP", // month 13, day 32
        "Blob.150600.1080p.WEB-GRP",   // day 00
        "Blob.150015.1080p.WEB-GRP",   // month 00
        "Blob.123456.1080p.WEB-GRP",   // an id, not a date
    ] {
        assert_eq!(tv_path(stem), None, "{stem}");
    }
    // A real date under a title that is a hash: nothing to present,
    // so the poster's own name stands.
    assert_eq!(
        tv_path("1fRbH6e0eX8v5hv7fSyXgBb.2026.07.21.1080p.WEB-GRP"),
        None
    );
    assert_eq!(tv_path("nzqymzflnjiyztgyntcynzzytq.150615.720p-GRP"), None);
    // A film with a release year is not a dated episode.
    assert_eq!(tv_path("Inception.2010.1080p.BluRay.x264-GRP"), None);
    assert_eq!(tv_path("Blade.Runner.2049.2017.2160p.WEB-DL-GRP"), None);
    // Sports and event posts keep whatever kind they parse as; the
    // ones that read as Movie are the movie path's business and must
    // not be dragged into TV filing by this.
    for stem in [
        "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.H265-MWR",
        "NFL.2025.Week.03.Chiefs.vs.Bills.1080p.WEB.h264-SPORTSNET",
    ] {
        assert_eq!(tv_path(stem), None, "{stem}");
    }
}

/// Filing a dated episode must not teach the delete/play matcher to
/// read a date as an episode number - a neighbouring air date in the
/// same year folder is a different episode, and the only copy of it.
#[test]
fn date_shapes_are_not_episode_numbers() {
    let _steady = trash_globals_steady();
    // Unchanged verdicts: a bare digit run is an episode number
    // whatever its width, and a dotted date is not a single token.
    assert!(reads_as_episode_number("2026"));
    assert!(reads_as_episode_number("07"));
    assert!(!reads_as_episode_number("2026.07.21"));
    assert!(!reads_as_episode_number("07.21"));
    // Our own tail after a dated base is still just the extension.
    assert!(is_rename_tail(".mkv"));
    assert!(is_rename_tail(" [1080p].mkv"));
    // What follows a dated base in someone else's library is not.
    assert!(!is_rename_tail(" - Guest Name.mkv"));
    assert!(!is_rename_tail(".2026.07.22.mkv"));
    assert!(!is_rename_tail("-2026.07.22.mkv"));

    // And end to end: a job filed for the 21st never touches the
    // 22nd, or the user's own copy of the 21st.
    let root = scratch("dailydel");
    for f in [
        "The Daily Show - 2026.07.21 [1080p].mkv",
        "The Daily Show - 2026.07.22 [1080p].mkv",
        "The Daily Show - 2026.07.21 - Guest Name.mkv",
    ] {
        std::fs::write(root.join(f), b"v").unwrap();
    }
    let stem = "The.Daily.Show.2026.07.21.1080p.WEB.x264-GRP";
    assert_eq!(
        delete_filed_episode(&root, stem, &FiledTail::suffix(" [1080p]")).removed,
        1
    );
    assert!(
        !root
            .join("The Daily Show - 2026.07.21 [1080p].mkv")
            .exists()
    );
    assert!(
        root.join("The Daily Show - 2026.07.22 [1080p].mkv")
            .exists()
    );
    assert!(
        root.join("The Daily Show - 2026.07.21 - Guest Name.mkv")
            .exists()
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Stage 4's shape for a daily: Season-filed under the air year when
/// tv_sort is on, renamed in place when it is off.
#[test]
fn a_dated_episode_files_and_renames() {
    let stem = "The.Daily.Show.2026.07.21.1080p.WEB.x264-GRP";

    let root = scratch("dailyfile");
    let out = root.join("job");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
    let dest = tv_organize(
        &root.join("tv"),
        stem,
        &out,
        " [1080p]",
        &EpisodeTitles::default(),
    )
    .unwrap();
    assert_eq!(
        dest,
        root.join("tv").join("The Daily Show").join("Season 2026")
    );
    assert!(
        dest.join("The Daily Show - 2026.07.21 [1080p].mkv")
            .exists()
    );
    let _ = std::fs::remove_dir_all(&root);

    // tv_sort off: same name, in place.
    let dir = scratch("dailyren");
    std::fs::write(dir.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
    std::fs::write(dir.join("sample.mkv"), b"s").unwrap();
    assert_eq!(
        tv_rename(&dir, stem, " [1080p]", &EpisodeTitles::default()),
        1
    );
    assert!(dir.join("The Daily Show - 2026.07.21 [1080p].mkv").exists());
    assert!(dir.join("sample.mkv").exists(), "samples keep their names");

    // Running it again is a no-op - the target is already there.
    assert_eq!(
        tv_rename(&dir, stem, " [1080p]", &EpisodeTitles::default()),
        0
    );
    let _ = std::fs::remove_dir_all(&dir);

    // Per-file stem beats the job stem, exactly as for numbered
    // seasons: a batch of dailies renames each to its own air date.
    let dir = scratch("dailybatch");
    std::fs::write(
        dir.join("The.Daily.Show.2026.07.22.1080p.WEB.x264-GRP.mkv"),
        b"v",
    )
    .unwrap();
    assert_eq!(
        tv_rename(&dir, stem, " [1080p]", &EpisodeTitles::default()),
        1
    );
    assert!(dir.join("The Daily Show - 2026.07.22 [1080p].mkv").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn delete_filed_episode_spares_siblings() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-filed-del-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A shared season folder holding several episodes + a sidecar.
    for f in [
        "The Bear - S03E04.mkv",
        "The Bear - S03E05.mkv",
        "The Bear - S03E05.en.srt",
        "The Bear - S03E06.mkv",
    ] {
        std::fs::write(dir.join(f), b"x").unwrap();
    }
    // Delete only the E05 the old release filed to. Empty suffix =
    // auto-rename off, so the episode base is all filing had to go on.
    let n =
        delete_filed_episode(&dir, "The.Bear.S03E05.720p.HDTV-A", &FiledTail::suffix("")).removed;
    assert_eq!(n, 2, "should remove the E05 video and its .srt sidecar");
    assert!(!dir.join("The Bear - S03E05.mkv").exists());
    assert!(!dir.join("The Bear - S03E05.en.srt").exists());
    // Siblings survive - this is the data-loss bug the fix prevents.
    assert!(dir.join("The Bear - S03E04.mkv").exists());
    assert!(dir.join("The Bear - S03E06.mkv").exists());
    // A release that doesn't parse to a specific episode is a no-op,
    // never a broad delete.
    assert_eq!(
        delete_filed_episode(&dir, "2137d880a074ab31de52", &FiledTail::suffix("")).removed,
        0
    );
    assert!(dir.join("The Bear - S03E04.mkv").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Regression: pressing Play on a completed filed TV row served
/// "the biggest media file in out_dir", and out_dir is the whole
/// SHARED season folder - so E01's history row played E02 whenever the
/// sibling was the larger file. Ownership is decided exactly as the
/// delete decides it.
#[test]
fn find_filed_episode_media_serves_this_episode_not_a_bigger_sibling() {
    let dir = std::env::temp_dir().join(format!("nzbfast-filed-play-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // E06 is deliberately the biggest file in the folder.
    std::fs::write(dir.join("The Bear - S03E04.mkv"), vec![0u8; 2048]).unwrap();
    std::fs::write(dir.join("The Bear - S03E05.mkv"), vec![0u8; 1024]).unwrap();
    std::fs::write(dir.join("The Bear - S03E06.mkv"), vec![0u8; 8192]).unwrap();
    std::fs::write(dir.join("The Bear - S03E05.en.srt"), b"subs").unwrap();
    let got = find_filed_episode_media(&dir, "The.Bear.S03E05.720p.HDTV-A", &FiledTail::suffix(""));
    assert_eq!(
        got.as_deref(),
        Some(dir.join("The Bear - S03E05.mkv").as_path())
    );
    // A stem that doesn't parse as a specific episode owns nothing
    // here, so there is nothing safe to play: no fallback guess.
    assert_eq!(
        find_filed_episode_media(&dir, "2137d880a074ab31de52", &FiledTail::suffix("")),
        None
    );
    // Neither does an episode that was never filed into this folder.
    assert_eq!(
        find_filed_episode_media(&dir, "The.Bear.S03E09.720p.HDTV-A", &FiledTail::suffix("")),
        None
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The quality suffix is what makes the match release-specific: two
/// copies of the same episode live in one season folder while an
/// upgrade lands, and the row that asked must not play the other one.
#[test]
fn find_filed_episode_media_matches_this_releases_suffix() {
    let dir = std::env::temp_dir().join(format!("nzbfast-filed-sfx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("The Bear - S03E05 [720p].mkv"), vec![0u8; 1024]).unwrap();
    std::fs::write(
        dir.join("The Bear - S03E05 [1080p]-GRP.mkv"),
        vec![0u8; 4096],
    )
    .unwrap();
    let stem = "The.Bear.S03E05.720p.HDTV-A";
    assert_eq!(
        find_filed_episode_media(&dir, stem, &FiledTail::suffix(" [720p]")).as_deref(),
        Some(dir.join("The Bear - S03E05 [720p].mkv").as_path()),
        "the smaller file is the one this row downloaded"
    );
    assert_eq!(
        find_filed_episode_media(&dir, stem, &FiledTail::suffix(" [1080p]-GRP")).as_deref(),
        Some(dir.join("The Bear - S03E05 [1080p]-GRP.mkv").as_path())
    );
    // A suffix that matches nothing on disk (the naming settings
    // changed since filing) reports nothing rather than guessing.
    assert_eq!(
        find_filed_episode_media(&dir, stem, &FiledTail::suffix(" [2160p]")),
        None
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Only a video is playable, and only the season folder itself is
/// ours: a subdirectory that moved in with the job keeps its own name
/// and may hold anybody's episode.
#[test]
fn find_filed_episode_media_ignores_sidecars_and_subdirs() {
    let dir = std::env::temp_dir().join(format!("nzbfast-filed-side-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("Subs")).unwrap();
    std::fs::write(dir.join("The Bear - S03E05.en.srt"), b"subs").unwrap();
    std::fs::write(dir.join("The Bear - S03E05.nfo"), b"info").unwrap();
    std::fs::write(dir.join("Subs/The Bear - S03E05.mkv"), vec![0u8; 4096]).unwrap();
    assert_eq!(
        find_filed_episode_media(&dir, "The.Bear.S03E05.720p.HDTV-A", &FiledTail::suffix("")),
        None
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Regression: the delete matched the episode base followed by ANY
/// space, which is the DEFAULT Sonarr/Plex layout ("The Bear - S03E05 -
/// Children.mkv"). With M33 filing a job into the user's real library
/// season folder, an upgrade or a history "delete files" therefore
/// deleted the user's own copy of the episode - a file we never
/// downloaded and cannot fetch again.
#[test]
fn delete_filed_episode_spares_the_users_own_library_file() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-filed-lib-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ours = [
        "The Bear - S03E05 [1080p].mkv",
        "The Bear - S03E05 [1080p WEB h264].mkv",
        "The Bear - S03E05-GRP.mkv",
        // Real groups that merely START with a digit are still ours -
        // refusing these would leave our own files behind forever.
        "The Bear - S03E05-3LT0N.mkv",
        "The Bear - S03E05-2HD.mkv",
        "The Bear - S03E05.en.srt",
        "The Bear - S03E05.nfo",
    ];
    let theirs = [
        // Sonarr / Plex default naming, pre-existing in the library.
        "The Bear - S03E05 - Children.mkv",
        "The Bear - S03E05 - Children [Bluray-1080p].mkv",
        "The Bear - S03E05 - Children.en.srt",
        // Our own multi-episode name carries E06's only copy too.
        "The Bear - S03E05-E06.mkv",
        // …and so does the bare-number multi-episode convention, which
        // reads as a release group unless all-digit groups are refused.
        "The Bear - S03E05-06.mkv",
        // Every other separator the same convention is written with.
        // The dot spellings reach the extension arm rather than the
        // group arm, so they were accepted as ours and deleted.
        "The Bear - S03E05.06.mkv",
        "The Bear - S03E05.E06.mkv",
        "The Bear - S03E05.S03E06.mkv",
        "The Bear - S03E05 [1080p].06.mkv",
        "The Bear - S03E05-S03E06.mkv",
        "The Bear - S03E05x06.mkv",
        "The Bear - S03E05_06.mkv",
        // Siblings.
        "The Bear - S03E06.mkv",
    ];
    for f in ours.iter().chain(theirs.iter()) {
        std::fs::write(dir.join(f), b"x").unwrap();
    }
    let n = delete_filed_episode(
        &dir,
        "The.Bear.S03E05.1080p.WEB.h264-GRP",
        &FiledTail::suffix(""),
    )
    .removed;
    assert_eq!(n, ours.len(), "every file this job filed, and only those");
    for f in ours {
        assert!(!dir.join(f).exists(), "{f} is ours and should have gone");
    }
    for f in theirs {
        assert!(dir.join(f).exists(), "{f} is not ours to delete");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// BUG (HIGH, data loss): a watchlist upgrade deletes the replacement
/// it just downloaded.
///
/// The upgrade files the BETTER copy into the same `Show/Season NN`
/// folder under the same episode base - `Show - S03E05` - differing
/// only in the quality suffix. Matching the base plus ANY rename tail
/// is therefore quality-blind, so the delete of the superseded copy
/// swept up the freshly-downloaded one beside it and the user was left
/// with neither.
///
/// Both names are built from the REAL `quality_suffix` for each
/// release, so the test breaks if the naming and the matching ever
/// drift apart.
#[test]
fn delete_filed_episode_spares_the_upgrade_that_replaced_it() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-filed-up-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let style = crate::wall::NameStyle {
        resolution: true,
        video_codec: true,
        audio_codec: false,
        source: true,
        group: true,
        // This test is about the suffix DIFFERING between qualities,
        // not about its punctuation, so exercise the bracketed shape:
        // it is the one with delimiters that a tail match could trip on.
        year_parens: true,
        quality_brackets: true,
        extra_words: true,
    };
    let old_stem = "The.Bear.S03E05.720p.HDTV-A";
    let new_stem = "The.Bear.S03E05.1080p.WEB.h264-GRP";
    let suffix =
        |stem: &str| crate::wall::quality_suffix(&crate::wall::parse_release(stem), &style);
    let (old_sfx, new_sfx) = (suffix(old_stem), suffix(new_stem));
    assert!(
        !old_sfx.is_empty(),
        "auto-rename is on, so filing appended a suffix"
    );
    assert_ne!(old_sfx, new_sfx, "the upgrade is a different quality");

    let old_file = format!("The Bear - S03E05{old_sfx}.mkv");
    let new_file = format!("The Bear - S03E05{new_sfx}.mkv");
    let sibling = "The Bear - S03E06 [1080p WEB h264]-GRP.mkv";
    for f in [old_file.as_str(), new_file.as_str(), sibling] {
        std::fs::write(dir.join(f), b"x").unwrap();
    }

    // The upgrade landed; drop the copy it supersedes.
    let n = delete_filed_episode(&dir, old_stem, &FiledTail::suffix(&old_sfx)).removed;
    assert_eq!(n, 1, "exactly the superseded release, and nothing else");
    assert!(!dir.join(&old_file).exists(), "the superseded copy is gone");
    assert!(
        dir.join(&new_file).exists(),
        "the replacement we just downloaded must survive its own upgrade"
    );
    assert!(
        dir.join(sibling).exists(),
        "a sibling episode is never touched"
    );

    // And the other direction: deleting the NEW record later must not
    // reach back to a copy that carries a different suffix.
    std::fs::write(dir.join(&old_file), b"x").unwrap();
    assert_eq!(
        delete_filed_episode(&dir, new_stem, &FiledTail::suffix(&new_sfx)).removed,
        1
    );
    assert!(
        dir.join(&old_file).exists(),
        "the other quality is not this record's"
    );

    // A suffix that no longer matches what is on disk (the user changed
    // the naming settings after filing) is a no-op, never a guess: a
    // leftover beats a destroyed episode.
    assert_eq!(
        delete_filed_episode(&dir, old_stem, &FiledTail::suffix(" [2160p REMUX]-ZZZ")).removed,
        0
    );
    assert!(dir.join(&old_file).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The `-Group` arm of the rename tail, at the granularity the file-level
/// test can't reach. `delete_filed_episode` lowercases the whole file name
/// before calling this, so every case here is lowercase.
#[test]
fn rename_tail_group_arm() {
    // Ours: a group is one word, and may begin with a digit.
    assert!(is_rename_tail("-grp.mkv"));
    assert!(is_rename_tail("-3lt0n.mkv"));
    assert!(is_rename_tail("-2hd.mkv"));
    assert!(is_rename_tail(" [1080p web h264]-3lt0n.mkv"));
    // Ours: no group at all, and a sidecar on the renamed stem.
    assert!(is_rename_tail(".mkv"));
    assert!(is_rename_tail(" [1080p].mkv"));
    assert!(is_rename_tail(".en.srt"));
    // Not ours: an all-digit "group" is the second episode of a range
    // ("Show - S03E05-06.mkv"), whose only copy of E06 this would delete.
    assert!(!is_rename_tail("-06.mkv"));
    assert!(!is_rename_tail("-6.mkv"));
    assert!(!is_rename_tail(" [1080p]-06.mkv"));
    // Not ours: the E-prefixed spelling of the same range.
    assert!(!is_rename_tail("-e06.mkv"));
    // Not ours: the user's own Sonarr/Plex episode title.
    assert!(!is_rename_tail(" - children.mkv"));
    assert!(!is_rename_tail(" - children [bluray-1080p].mkv"));
    // Not ours: a longer episode number, or no extension at all.
    assert!(!is_rename_tail("0.mkv"));
    assert!(!is_rename_tail("-grp"));
}

/// Every spelling of a multi-episode range, at tail granularity.
///
/// The `-` arm was hardened first (`-E06`, then bare `-06`), but the
/// SAME convention is written with other separators, and the ones that
/// put a dot there ("The Bear - S03E05.06.mkv") landed in the extension
/// arm instead, which accepted any non-empty tail. Such a file is the
/// only copy of E06 as well, and we never downloaded E06.
#[test]
fn rename_tail_refuses_every_range_spelling() {
    // Dot-separated range: reached the extension arm, not the `-` arm.
    assert!(!is_rename_tail(".06.mkv"));
    assert!(!is_rename_tail(".6.mkv"));
    assert!(!is_rename_tail(".e06.mkv"));
    assert!(!is_rename_tail(".s03e06.mkv"));
    // …with our quality suffix in front, or the user's behind.
    assert!(!is_rename_tail(" [1080p].06.mkv"));
    assert!(!is_rename_tail(" [1080p].e06.mkv"));
    assert!(!is_rename_tail(".06 [1080p].mkv"));
    // …on a sidecar sharing the stem, and with no extension at all.
    assert!(!is_rename_tail(".06.en.srt"));
    assert!(!is_rename_tail(".06"));
    // A three-episode range: only the FIRST segment can be episode two.
    assert!(!is_rename_tail(".06.07.mkv"));
    // The `-` arm, including the full-code spelling it used to accept.
    assert!(!is_rename_tail("-06.mkv"));
    assert!(!is_rename_tail("-6.mkv"));
    assert!(!is_rename_tail("-e06.mkv"));
    assert!(!is_rename_tail("-s03e06.mkv"));
    assert!(!is_rename_tail(" [1080p]-06.mkv"));
    assert!(!is_rename_tail("-06 [1080p].mkv"));
    // Separators that never reach either arm - refused already, pinned
    // here so a future "simplification" can't quietly re-admit them.
    assert!(!is_rename_tail("x06.mkv"));
    assert!(!is_rename_tail("_06.mkv"));
    assert!(!is_rename_tail("e06.mkv"));
    assert!(!is_rename_tail(" - e06.mkv"));
    assert!(!is_rename_tail(" 06.mkv"));
    assert!(!is_rename_tail("+06.mkv"));
    assert!(!is_rename_tail("&06.mkv"));
    assert!(!is_rename_tail(",06.mkv"));
}

/// The other half of the same bug: narrowing the tail must not strand
/// our OWN files, or every filed episode leaves orphans behind.
#[test]
fn rename_tail_still_accepts_our_own_output() {
    assert!(is_rename_tail(".mkv"));
    assert!(is_rename_tail(" [1080p].mkv"));
    assert!(is_rename_tail(" [1080p web h264]-3lt0n.mkv"));
    assert!(is_rename_tail("-grp.mkv"));
    // Real groups that merely BEGIN with a digit.
    assert!(is_rename_tail("-3lt0n.mkv"));
    assert!(is_rename_tail("-2hd.mkv"));
    // Sidecars on the renamed stem.
    assert!(is_rename_tail(".en.srt"));
    assert!(is_rename_tail(".nfo"));
    assert!(is_rename_tail(".eng.forced.srt"));
    // An extension that merely STARTS with a digit is not an episode
    // number - "3gp" has a non-digit in it, "264" would not.
    assert!(is_rename_tail(".3gp"));
    // Quality tokens are not episode numbers either.
    assert!(is_rename_tail(".x264.mkv"));
    assert!(is_rename_tail(".1080p.mkv"));
}

#[test]
fn ext_list_parsing() {
    assert_eq!(
        parse_ext_list("par2, SFV, *.srr, .url, ,"),
        vec!["par2", "sfv", "srr", "url"]
    );
    assert!(parse_ext_list("").is_empty());
}

/// §163 item 2. The leading-`*.` strip is why `*.par2` still means the
/// par2 EXTENSION, and it is also what used to flatten a real pattern
/// down to one. Both halves are pinned here, because the second is only
/// safe while the first is unchanged.
#[test]
fn ext_list_keeps_a_real_pattern_and_still_flattens_a_pasted_extension() {
    // Unchanged: anything that reduces to a bare extension still does.
    for (input, want) in [
        ("*.par2", "par2"),
        (".SRR", "srr"),
        ("**.nfo", "nfo"),
        ("url", "url"),
        // A lone wildcard reduces to nothing and is dropped, exactly as
        // it was before - a cleanup list that says "*" must not mean
        // "delete the download".
        ("*", ""),
    ] {
        assert_eq!(
            parse_ext_list(input),
            if want.is_empty() {
                Vec::new()
            } else {
                vec![want.to_string()]
            },
            "{input}"
        );
    }
    // Kept whole: a separator, or a wildcard that survives the strip.
    for input in ["subs/*", "*sample*.mkv", "*.r??", "sub?/*.nfo"] {
        assert_eq!(parse_ext_list(input), vec![input], "{input}");
    }
    // Windows spelling of a path pattern folds to the posix one, so the
    // sweep has a single separator to match against.
    assert_eq!(parse_ext_list("Subs\\*"), vec!["subs/*"]);
    // And the classifier itself, on the pair that makes the rule subtle.
    assert!(!is_cleanup_pattern("*.par2"), "strips to a bare extension");
    assert!(is_cleanup_pattern("*.r??"), "strips to a wild one");
}

#[test]
fn encrypted_rar_scan() {
    use super::unlockpw::encrypted_rar;
    let dir = std::env::temp_dir().join(format!("nzbfast-smart-enc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Plain store volume → nothing to unlock.
    std::fs::write(
        dir.join("plain.rar"),
        nzbkit::rar::fixtures::rar4_volume(&[("a.bin", 4, b"data", false, false)]),
    )
    .unwrap();
    std::fs::write(dir.join("video.mkv"), b"x").unwrap();
    assert_eq!(encrypted_rar(&dir), None);
    // Add an encrypted-header volume → found.
    std::fs::write(
        dir.join("locked.rar"),
        nzbkit::rar::fixtures::rar4_encrypted_headers(64),
    )
    .unwrap();
    assert_eq!(encrypted_rar(&dir), Some(dir.join("locked.rar")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cleanup_two_levels() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-smart-clean-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    for p in [
        "a.mkv",
        "a.par2",
        "a.vol00+1.PAR2",
        "a.sfv",
        "sub/b.par2",
        "sub/b.mkv",
    ] {
        std::fs::write(dir.join(p), b"x").unwrap();
    }
    let (n, par2) = cleanup(&dir, &parse_ext_list("par2, sfv"));
    assert_eq!(n, 4);
    // 3 of the 4 were .par2 - the drawer's "(M par2 recovery files)"
    // half of the count.
    assert_eq!(par2, 3);
    assert!(dir.join("a.mkv").exists());
    assert!(dir.join("sub/b.mkv").exists());
    assert!(!dir.join("a.par2").exists());
    assert!(!dir.join("a.vol00+1.PAR2").exists());
    assert!(!dir.join("sub/b.par2").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// §163 item 2: the sweep honours patterns as well as extensions, and a
/// pattern is matched against the filename or the relative path
/// depending on whether it carries a separator - the distinction that
/// makes `Subs/*` mean the folder rather than any file called Subs.
#[test]
fn cleanup_matches_paths_and_wildcards() {
    let _steady = trash_globals_steady();
    let dir = std::env::temp_dir().join(format!("nzbfast-smart-clean-pat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("Subs")).unwrap();
    std::fs::create_dir_all(dir.join("keep")).unwrap();
    for p in [
        "Show.S01E01.mkv",
        "Show.S01E01-sample.mkv",
        "Show.S01E01.nfo",
        "Subs/eng.srt",
        "Subs/nor.srt",
        "keep/eng.srt",
    ] {
        std::fs::write(dir.join(p), b"x").unwrap();
    }
    let (n, par2) = cleanup(&dir, &parse_ext_list("Subs/*, *sample*, nfo"));
    assert_eq!(n, 4, "two subtitles, one sample, one nfo");
    assert_eq!(par2, 0, "nothing here is recovery data");
    // The separator pattern took the Subs folder and left the
    // identically-named files under a different one.
    assert!(!dir.join("Subs/eng.srt").exists());
    assert!(!dir.join("Subs/nor.srt").exists());
    assert!(dir.join("keep/eng.srt").exists(), "a different folder");
    // The bare wildcard is about the NAME, so it reaches any level.
    assert!(!dir.join("Show.S01E01-sample.mkv").exists());
    // The extension arm still works beside them, and the payload stays.
    assert!(!dir.join("Show.S01E01.nfo").exists());
    assert!(dir.join("Show.S01E01.mkv").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tv_organize_moves_and_renames() {
    let root = std::env::temp_dir().join(format!("nzbfast-smart-org-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
    let out = root.join("tv").join(stem);
    std::fs::create_dir_all(out.join("extras")).unwrap();
    std::fs::write(out.join(format!("{stem}.mkv")), b"video").unwrap();
    std::fs::write(out.join(format!("{stem}.nfo")), b"info").unwrap();
    std::fs::write(out.join("sample.mkv"), b"s").unwrap();
    std::fs::write(out.join("extras/x.srt"), b"subs").unwrap();
    let dest = tv_organize(
        &root.join("tv"),
        stem,
        &out,
        " [1080p]",
        &EpisodeTitles::default(),
    )
    .unwrap();
    assert_eq!(dest, root.join("tv/My Show/Season 01"));
    assert_eq!(
        std::fs::read(dest.join("My Show - S01E02 [1080p].mkv")).unwrap(),
        b"video"
    );
    assert!(
        dest.join(format!("{stem}.nfo")).exists(),
        "non-video keeps its name"
    );
    assert!(
        dest.join("sample.mkv").exists(),
        "sample moved but not renamed"
    );
    assert!(dest.join("extras/x.srt").exists(), "subdir moved whole");
    assert!(!out.exists(), "emptied job dir removed");
    // A movie stem refuses and leaves the directory alone.
    let mout = root.join("Movie.2020.1080p");
    std::fs::create_dir_all(&mout).unwrap();
    assert!(
        tv_organize(
            &root,
            "Movie.2020.1080p",
            &mout,
            "",
            &EpisodeTitles::default()
        )
        .is_none()
    );
    assert!(mout.exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn tv_organize_collision_spares_the_existing_library_file() {
    let root = std::env::temp_dir().join(format!("nzbfast-tv-collision-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let out = root.join("job");
    let season = root.join("tv/Show/Season 01");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&season).unwrap();
    std::fs::write(out.join("posted.release.mkv"), b"ours").unwrap();
    let canonical = season.join("Show - S01E02 1080p.mkv");
    std::fs::write(&canonical, b"library").unwrap();

    assert!(
        tv_organize(
            &root.join("tv"),
            "Show.S01E02.1080p.WEB.x265-GRP",
            &out,
            " 1080p",
            &EpisodeTitles::default(),
        )
        .is_none(),
        "a collision must keep the job private"
    );
    assert_eq!(std::fs::read(&canonical).unwrap(), b"library");
    assert_eq!(
        std::fs::read(out.join("posted.release.mkv")).unwrap(),
        b"ours"
    );
    std::fs::remove_dir_all(root).unwrap();
}

/// Filing NOTHING must not claim the shared season folder. An
/// all-junk repost (NFOFIX/DIRFIX: only .nfo/.sfv/.par2) is emptied by
/// sweep_junk before tv_organize runs, so `planned` is empty - and the
/// tail fell straight through to Some(dest). That sets `filed`, and
/// delete_filed_episode then matches by canonical NAME in the shared
/// folder and removes the user's real episode for a job that moved
/// zero bytes. Reachable from a history delete-with-files and from
/// both watchlist upgrade paths, the last two with no user action.
#[test]
fn tv_organize_refuses_the_season_folder_when_there_was_nothing_to_file() {
    let root = std::env::temp_dir().join(format!("nzbfast-tv-empty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let out = root.join("job");
    let season = root.join("tv/Show/Season 01");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&season).unwrap();
    // The user's real episode already lives there.
    let theirs = season.join("Show - S01E05 1080p.mkv");
    std::fs::write(&theirs, b"library").unwrap();

    // Our job has nothing left to place at all.
    assert!(
        tv_organize(
            &root.join("tv"),
            "Show.S01E05.1080p.WEB-GRP",
            &out,
            " 1080p",
            &EpisodeTitles::default(),
        )
        .is_none(),
        "a job with nothing to file must not claim the season folder"
    );
    assert_eq!(
        std::fs::read(&theirs).unwrap(),
        b"library",
        "the user's episode must be untouched"
    );
    std::fs::remove_dir_all(root).unwrap();
}

/// A shared subfolder must not stop the episode filing. The
/// collision abort was whole-job and covered directories, so the
/// SECOND episode of a season shipping a `Subs/` folder never filed
/// at all - silently, since the caller records nothing when filing
/// returns None. Scene TV ships `Subs/` constantly, and sweep_junk
/// preserves subtitles by design, so this hit ordinary users.
#[test]
fn tv_organize_shared_subfolder_does_not_block_the_episode() {
    let root = std::env::temp_dir().join(format!("nzbfast-tv-subs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let out = root.join("job");
    let season = root.join("tv/Show/Season 01");
    std::fs::create_dir_all(out.join("Subs")).unwrap();
    // The season folder already has a Subs/ from an earlier episode.
    std::fs::create_dir_all(season.join("Subs")).unwrap();
    std::fs::write(out.join("posted.release.mkv"), b"ours").unwrap();
    std::fs::write(out.join("Subs/en.srt"), b"subs").unwrap();

    let dest = tv_organize(
        &root.join("tv"),
        "Show.S01E03.1080p.WEB-GRP",
        &out,
        " 1080p",
        &EpisodeTitles::default(),
    )
    .expect("a shared Subs/ folder must not stop the episode filing");
    assert_eq!(dest, season);
    assert!(
        season.join("Show - S01E03 1080p.mkv").is_file(),
        "the episode itself must reach the season folder"
    );
    // The colliding folder is left behind rather than merged - not
    // ours to own, and no data is lost either way.
    assert!(out.join("Subs/en.srt").is_file());
    std::fs::remove_dir_all(root).unwrap();
}

/// A job that moved NOTHING must not claim the shared season folder.
/// The caller turns Some(dest) into `filed`, and cleanup then deletes
/// by canonical NAME - so a failed move made "delete this job" delete
/// whichever episode really was there. Renames fail in ordinary life
/// (NAS read-only blip, EXDEV, a media server holding the file open).
#[test]
#[cfg(unix)]
fn tv_organize_refuses_the_season_folder_when_nothing_moved() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("nzbfast-tv-nomove-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let out = root.join("job");
    let season = root.join("tv/Show/Season 01");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&season).unwrap();
    std::fs::write(out.join("posted.release.mkv"), b"ours").unwrap();
    // The rename must fail WITHOUT the target existing, or the
    // collision branch handles it and this never reaches the move
    // loop at all. (A directory at the canonical name does not work:
    // `target.exists()` is true for a directory, so the first draft
    // of this test passed against the unfixed code.) A read-only
    // season folder is the honest reproduction of the NAS blip.
    let mut perms = std::fs::metadata(&season).unwrap().permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&season, perms).unwrap();

    assert!(
        tv_organize(
            &root.join("tv"),
            "Show.S01E04.1080p.WEB-GRP",
            &out,
            " 1080p",
            &EpisodeTitles::default(),
        )
        .is_none(),
        "a job whose move failed must not claim the season folder"
    );
    assert_eq!(
        std::fs::read(out.join("posted.release.mkv")).unwrap(),
        b"ours",
        "and its file stays where it was"
    );
    let mut perms = std::fs::metadata(&season).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&season, perms).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn move_tree_renames_when_dest_absent() {
    let root = std::env::temp_dir().join(format!("nzbfast-mv1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let src = root.join("out/movies/Film.2020");
    std::fs::create_dir_all(src.join("extras")).unwrap();
    std::fs::write(src.join("Film.mkv"), b"v").unwrap();
    std::fs::write(src.join("extras/x.srt"), b"s").unwrap();
    let dst = root.join("nas/movies/Film.2020");
    move_tree(&src, &dst).unwrap();
    assert_eq!(std::fs::read(dst.join("Film.mkv")).unwrap(), b"v");
    assert_eq!(std::fs::read(dst.join("extras/x.srt")).unwrap(), b"s");
    assert!(!src.exists(), "source dir gone after move");
    let _ = std::fs::remove_dir_all(&root);
}

/// A completed job containing `extras -> /external` must not make the
/// mover walk into the link and relocate files that live outside the job.
/// `Path::is_dir` follows symlinks, so it used to do exactly that: the
/// external directory's children were moved into the destination and
/// deleted from where they actually were.
#[cfg(unix)]
#[test]
fn move_tree_does_not_walk_through_a_directory_symlink() {
    let root = std::env::temp_dir().join(format!("nzbfast-mvlink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let external = root.join("external");
    std::fs::create_dir_all(&external).unwrap();
    std::fs::write(external.join("someone-elses.txt"), b"not yours").unwrap();

    let src = root.join("job");
    let dst = root.join("done");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("payload.mkv"), b"v").unwrap();
    std::os::unix::fs::symlink(&external, src.join("extras")).unwrap();

    move_tree(&src, &dst).unwrap();

    assert_eq!(
        std::fs::read(external.join("someone-elses.txt")).unwrap(),
        b"not yours",
        "a file outside the job was moved or deleted through the link"
    );
    assert!(external.join("someone-elses.txt").exists());
    assert_eq!(std::fs::read(dst.join("payload.mkv")).unwrap(), b"v");
    let _ = std::fs::remove_dir_all(&root);
}

/// Same hole on the delete side: the cleanup walkers classified with
/// `is_file`/`is_dir`, both of which resolve links, and then deleted what
/// they found - so removing `job/extras/x.nfo` reached the real file.
#[cfg(unix)]
#[test]
fn cleanup_walkers_do_not_delete_through_a_directory_symlink() {
    let _steady = trash_globals_steady();
    let root = std::env::temp_dir().join(format!("nzbfast-cleanlink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let external = root.join("external");
    std::fs::create_dir_all(&external).unwrap();
    std::fs::write(external.join("keep.nfo"), b"outside").unwrap();
    std::fs::write(external.join("keep.mkv"), b"outside").unwrap();

    let job = root.join("job");
    std::fs::create_dir_all(&job).unwrap();
    std::fs::write(job.join("real.nfo"), b"inside").unwrap();
    std::os::unix::fs::symlink(&external, job.join("extras")).unwrap();

    cleanup(&job, &["nfo".to_string()]);
    assert!(
        external.join("keep.nfo").exists(),
        "cleanup deleted outside the job"
    );

    sweep_junk(&job);
    assert!(
        external.join("keep.nfo").exists(),
        "sweep_junk deleted outside the job"
    );

    keep_media_only(&job);
    assert!(
        external.join("keep.nfo").exists(),
        "keep_media_only deleted outside the job"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `exists()` is not an ownership primitive: two movers racing the same
/// destination both saw the name as free and both took it, so one
/// payload was overwritten and both sources deleted - with both movers
/// reporting success. Reservation is atomic, so each caller gets its own.
#[test]
fn reserving_a_name_never_hands_the_same_path_to_two_callers() {
    let root = std::env::temp_dir().join(format!("nzbfast-reserve-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let wanted = root.join("Episode.mkv");

    let mut claimed = Vec::new();
    for _ in 0..5 {
        claimed.push(reserve_free_name(&wanted).unwrap());
    }
    let unique: std::collections::HashSet<_> = claimed.iter().collect();
    assert_eq!(
        unique.len(),
        claimed.len(),
        "a name was handed out twice: {claimed:?}"
    );
    assert_eq!(
        claimed[0], wanted,
        "the first caller still gets the plain name"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn move_tree_merges_and_uncollides() {
    let root = std::env::temp_dir().join(format!("nzbfast-mv2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    // Destination Season dir already holds an earlier episode AND a
    // same-named file - merge must keep both bytes.
    let src = root.join("out/tv/My Show/Season 01");
    let dst = root.join("nas/tv/My Show/Season 01");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(src.join("E02.mkv"), b"new").unwrap();
    std::fs::write(src.join("E01.mkv"), b"ours").unwrap();
    std::fs::write(dst.join("E01.mkv"), b"theirs").unwrap();
    move_tree(&src, &dst).unwrap();
    assert_eq!(std::fs::read(dst.join("E02.mkv")).unwrap(), b"new");
    assert_eq!(
        std::fs::read(dst.join("E01.mkv")).unwrap(),
        b"theirs",
        "existing destination file kept"
    );
    assert_eq!(
        std::fs::read(dst.join("E01 (2).mkv")).unwrap(),
        b"ours",
        "colliding file lands beside it"
    );
    assert!(!src.exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// The cross-device route, driven directly - a unit test cannot conjure
/// a second filesystem. Everything is copied into staging first and
/// published in one pass, so merge and collision behaviour has to match
/// the rename route exactly.
#[test]
fn a_staged_move_publishes_the_whole_tree_then_drains_the_source() {
    let root = std::env::temp_dir().join(format!("nzbfast-stage1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let src = root.join("out/tv/My Show/Season 01");
    let dst = root.join("nas/tv/My Show/Season 01");
    std::fs::create_dir_all(src.join("Subs")).unwrap();
    std::fs::write(src.join("E01.mkv"), b"ours").unwrap();
    std::fs::write(src.join("Subs/E01.srt"), b"s").unwrap();
    // The Season folder already holds an earlier episode AND a file of
    // the same name as ours.
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(dst.join("E02.mkv"), b"earlier").unwrap();
    std::fs::write(dst.join("E01.mkv"), b"theirs").unwrap();

    let staging = dst.with_file_name(".Season 01.moving");
    staged_move(&src, &dst, &staging, None).unwrap();

    assert_eq!(std::fs::read(dst.join("E02.mkv")).unwrap(), b"earlier");
    assert_eq!(
        std::fs::read(dst.join("E01.mkv")).unwrap(),
        b"theirs",
        "existing kept"
    );
    assert_eq!(
        std::fs::read(dst.join("E01 (2).mkv")).unwrap(),
        b"ours",
        "ours beside it"
    );
    assert_eq!(
        std::fs::read(dst.join("Subs/E01.srt")).unwrap(),
        b"s",
        "subdir published"
    );
    assert!(!src.exists(), "drained source dir removed");
    assert!(!staging.exists(), "staging cleaned up");
    let _ = std::fs::remove_dir_all(&root);
}

/// Regression: the drain re-walked the source and deleted every file it
/// found, rather than the ones the copy pass actually reproduced. A file
/// created between the two - a post-processing script's output, a user's
/// drop-in - was therefore deleted without ever having been copied, so
/// it existed nowhere afterwards.
#[test]
fn a_staged_move_does_not_drain_what_it_never_copied() {
    let root = std::env::temp_dir().join(format!("nzbfast-stage3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let src = root.join("out/Film.2020");
    let dst = root.join("nas/Film.2020");
    std::fs::create_dir_all(src.join("Subs")).unwrap();
    std::fs::write(src.join("Film.mkv"), b"v").unwrap();
    std::fs::write(src.join("Subs/Film.srt"), b"s").unwrap();
    let staging = dst.with_file_name(".Film.2020.moving");

    // Stand in for the window between the copy pass and the drain: copy
    // and publish by hand, drop a new file in, then drain.
    let mut copied = std::collections::HashSet::new();
    copy_tree_into_paced(&src, &staging, &mut copied, None).unwrap();
    publish_staged(&staging, &dst).unwrap();
    std::fs::write(src.join("post-process.log"), b"late").unwrap();
    std::fs::write(src.join("Subs/late.srt"), b"late").unwrap();
    drain_copied(&src, &copied);

    assert_eq!(
        std::fs::read(dst.join("Film.mkv")).unwrap(),
        b"v",
        "payload published"
    );
    assert_eq!(std::fs::read(dst.join("Subs/Film.srt")).unwrap(), b"s");
    assert!(!src.join("Film.mkv").exists(), "what was copied is drained");
    assert_eq!(
        std::fs::read(src.join("post-process.log")).unwrap(),
        b"late",
        "arrived after the copy: never copied, so never deleted"
    );
    assert_eq!(std::fs::read(src.join("Subs/late.srt")).unwrap(), b"late");
    let _ = std::fs::remove_dir_all(&root);
}

/// Regression: a cross-device move that failed partway had already
/// deleted every source file whose copy had landed, so the payload was
/// SPLIT across two filesystems while the caller was told nothing had
/// moved - and an importer pointed at either half took the fragment for
/// the whole release. Staging fails whole: the source keeps every byte
/// and the destination gains nothing.
#[test]
fn a_failed_staged_move_leaves_the_source_whole() {
    let root = std::env::temp_dir().join(format!("nzbfast-stage2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let src = root.join("out/Film.2020");
    let dst = root.join("nas/Film.2020");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("Film.mkv"), b"v").unwrap();
    std::fs::write(src.join("Film.nfo"), b"n").unwrap();
    std::fs::create_dir_all(root.join("nas")).unwrap();
    // A plain file where staging wants a directory: the copy cannot
    // start, standing in for the share that drops mid-move.
    let staging = dst.with_file_name(".Film.2020.moving");
    std::fs::write(&staging, b"in the way").unwrap();

    assert!(staged_move(&src, &dst, &staging, None).is_err());
    assert_eq!(
        std::fs::read(src.join("Film.mkv")).unwrap(),
        b"v",
        "source untouched"
    );
    assert_eq!(
        std::fs::read(src.join("Film.nfo")).unwrap(),
        b"n",
        "source untouched"
    );
    assert!(!dst.exists(), "nothing half-published at the destination");
    let _ = std::fs::remove_dir_all(&root);
}

/// A directory whose only lock is a zip: `encrypted_archive` must SEE
/// it, and `unlock` must actually unpack it.
///
/// Both halves were broken and each hid the other. Detection was
/// RAR+7z-only, so a locked zip never set `password_required` and the
/// drawer offered "show the folder" for a job whose whole remedy is a
/// password. And `unlock` reached its non-RAR arms only when
/// `reextract_dir` FAILED - which a directory holding no RAR volumes
/// never does (it answers "nothing to re-extract" and returns Ok(true)),
/// so a typed password reported success over a set still packed.
#[test]
fn a_locked_zip_is_detected_and_the_password_unpacks_it() {
    use nzbkit::zip::fixtures::{Encrypt, Spec, zip_of};
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + 3) as u8).collect();
    for (tag, enc) in [
        ("zipcrypto", Encrypt::ZipCrypto { password: "pw123" }),
        (
            "ae",
            Encrypt::Ae {
                password: "pw123",
                strength: 3,
                vendor_version: 2,
            },
        ),
    ] {
        let d = scratch(&format!("lockedzip-{tag}"));
        std::fs::write(
            d.join("payload.zip"),
            zip_of(&[Spec {
                encrypt: Some(enc),
                ..Spec::deflated("movie.mkv", &payload)
            }]),
        )
        .unwrap();

        let found = encrypted_archive(&d).unwrap_or_else(|| panic!("{tag}: lock not detected"));
        assert_eq!(found.file_name().unwrap(), "payload.zip", "{tag}");
        // `Err(None)`, exactly: a wrong password is not a refusal that
        // names itself, and inventing a reason here would put one in
        // front of the user (see `unlock`).
        assert_eq!(
            unlock(&d, "wrong"),
            Err(None),
            "{tag}: a wrong password must not pass"
        );
        assert!(
            !d.join("movie.mkv").exists(),
            "{tag}: nothing published on a wrong password"
        );
        assert_eq!(
            unlock(&d, "pw123"),
            Ok(()),
            "{tag}: the right password must unlock"
        );
        assert_eq!(
            std::fs::read(d.join("movie.mkv")).unwrap(),
            payload,
            "{tag}: the payload must be byte-correct"
        );
        // ...and once its content sits beside it, the spent container is
        // no longer a lock anyone can act on.
        assert!(
            encrypted_archive(&d).is_none(),
            "{tag}: a delivered container must not keep asking for a password"
        );
    }
}

/// H2 (29 Aug 2026 sweep): a destination INSIDE the source is refused
/// before anything is created or moved.
///
/// `move_completed = <download root>/<job>/done` computes a target of
/// `<job>/done/<job>`. The rename to a descendant fails on every kernel,
/// so the merge fallback ran: it created `done/`, then `read_dir`'d the
/// job folder, found the directory it had just made, and walked into it -
/// `done/J/done/J/...` until a path-length or I/O error stopped it, with
/// real payload entries left in whichever level the walk was at. Nothing
/// in the setter can refuse the CONFIG (the collision depends on the
/// job's own relative path), so the question is asked per move.
#[test]
fn move_tree_refuses_a_destination_inside_its_own_source() {
    let root = std::env::temp_dir().join(format!("nzbfast-mvnest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let src = root.join("downloads/J");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("payload.mkv"), b"v").unwrap();
    std::fs::write(src.join("sub/second.mkv"), b"w").unwrap();

    let dst = src.join("done/J");
    let e = move_tree(&src, &dst).expect_err("a descendant destination must be refused");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
    assert!(
        !src.join("done").exists(),
        "the refusal must come before the destination is created - creating it \
         is what puts the target inside the tree the merge then walks"
    );
    assert_eq!(std::fs::read(src.join("payload.mkv")).unwrap(), b"v");
    assert_eq!(std::fs::read(src.join("sub/second.mkv")).unwrap(), b"w");

    // The source itself is the same refusal: move_tree with dst == src
    // merged a directory with itself and renamed every real file to
    // "Episode (2).mkv" (see `relocate_completed`'s own note).
    assert!(move_tree(&src, &src).is_err(), "src == dst must be refused");

    // ...and an ordinary sibling move is untouched.
    let ok = root.join("nas/J");
    move_tree(&src, &ok).unwrap();
    assert_eq!(std::fs::read(ok.join("payload.mkv")).unwrap(), b"v");
    let _ = std::fs::remove_dir_all(&root);
}

/// The symlinked-parent half of the same guard: a destination that only
/// resolves inside the source THROUGH a link is still inside it, and a
/// raw component compare answers about a path that is not the one being
/// written.
#[cfg(unix)]
#[test]
fn move_tree_refuses_a_destination_inside_its_source_through_a_symlink() {
    let root = std::env::temp_dir().join(format!("nzbfast-mvlnest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let src = root.join("job");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("payload.mkv"), b"v").unwrap();
    // `nas` looks like a sibling and resolves into the job folder.
    std::os::unix::fs::symlink(&src, root.join("nas")).unwrap();

    let e = move_tree(&src, &root.join("nas/done"))
        .expect_err("a link into the source is still the source");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
    assert_eq!(std::fs::read(src.join("payload.mkv")).unwrap(), b"v");
    let _ = std::fs::remove_dir_all(&root);
}

/// Both copy arms used to reach their destination by a name they never
/// bound: the paced one through `File::create`, which TRUNCATES through
/// a symlink, and the unpaced one through `std::fs::copy`, which
/// OVERWRITES through one. The leaf comes from the SOURCE tree, which is
/// post-derived, so the name is the poster's to choose.
///
/// It bites: put `std::fs::File::create(to)` back in `copy_verified_paced`,
/// or `std::fs::copy(from, to)` back in `copy_verified`, and the sentinel
/// outside the destination is overwritten with the payload's bytes.
#[cfg(unix)]
#[test]
fn a_copy_refuses_an_alias_at_its_destination() {
    const SENTINEL: &[u8] = b"nothing a move does may touch this inode\n";
    let root = std::env::temp_dir().join(format!("nzbfast-mvbind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let out = root.join("done");
    let outside = root.join("outside");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let from = root.join("payload.mkv");
    std::fs::write(&from, b"the payload").unwrap();

    let noop: &PaceFn<'_> = &|_| {};
    // Once per arm, and the pacing hook is what selects them: `None` is
    // the `std::io::copy` path and `Some` the chunked loop, and they had
    // one defect each.
    for paced in [false, true] {
        // A LIVE link, over a file that must not move.
        let sentinel = outside.join("sentinel.bin");
        std::fs::write(&sentinel, SENTINEL).unwrap();
        let to = out.join("payload.mkv");
        std::os::unix::fs::symlink(&sentinel, &to).unwrap();
        let e = if paced {
            copy_verified_paced(&from, &to, Some(noop)).unwrap_err()
        } else {
            copy_verified(&from, &to).unwrap_err()
        };
        assert!(
            e.to_string().contains("an alias is in the way"),
            "paced={paced}: unexpected error: {e}"
        );
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            SENTINEL,
            "paced={paced}: the copy wrote through a live alias"
        );
        std::fs::remove_file(&to).unwrap();

        // A DANGLING one. `Path::exists` answers false for this, so
        // every check phrased as "is something already there?" misses it
        // and the copy creates the file it points at.
        let elsewhere = outside.join("elsewhere.bin");
        std::os::unix::fs::symlink(&elsewhere, &to).unwrap();
        assert!(if paced {
            copy_verified_paced(&from, &to, Some(noop)).is_err()
        } else {
            copy_verified(&from, &to).is_err()
        });
        assert!(
            !elsewhere.exists(),
            "paced={paced}: the copy followed a dangling alias out of the destination"
        );
        std::fs::remove_file(&to).unwrap();
    }

    // And the PARENT swapped for a link, which is the other half of what
    // `open_out_leaf` binds.
    let deep = out.join("Season 01");
    std::os::unix::fs::symlink(&outside, &deep).unwrap();
    let e = copy_verified(&from, &deep.join("E01.mkv")).unwrap_err();
    assert!(
        e.to_string().contains("not a real directory"),
        "unexpected error: {e}"
    );
    assert!(!outside.join("E01.mkv").exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// The same refusal reached through the public door, which is how a
/// cross-device move copies every byte it moves: `staged_move` fills a
/// staging directory with `copy_tree_into_paced`, and that had no
/// reservation of any kind - `dst.join(entry.file_name())` straight into
/// the copy.
#[cfg(unix)]
#[test]
fn copy_tree_refuses_an_alias_planted_at_a_payload_name() {
    const SENTINEL: &[u8] = b"outside the tree being copied\n";
    let root = std::env::temp_dir().join(format!("nzbfast-cptreebind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let src = root.join("job");
    let dst = root.join("staging");
    let outside = root.join("outside");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(src.join("E01.mkv"), b"episode").unwrap();
    let sentinel = outside.join("sentinel.bin");
    std::fs::write(&sentinel, SENTINEL).unwrap();
    std::os::unix::fs::symlink(&sentinel, dst.join("E01.mkv")).unwrap();

    assert!(copy_tree(&src, &dst).is_err());
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        SENTINEL,
        "the tree copy wrote through an alias at the payload's own name"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The cost of that refusal, and the reason the doors resolve their root
/// first: a user whose destination IS a symlink - a symlinked volume, a
/// season kept on the other drive - must still get their download filed.
/// `open_out_leaf` refuses a symlinked immediate PARENT, and for a flat
/// name that parent is the destination directory itself, so without
/// `resolve_out_root` at the door this arrangement would have started
/// erroring instead of writing.
#[cfg(unix)]
#[test]
fn a_symlinked_destination_root_still_takes_the_payload() {
    let root = std::env::temp_dir().join(format!("nzbfast-mvroot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let real = root.join("volume/Library/Season 01");
    std::fs::create_dir_all(&real).unwrap();
    let src = root.join("job");
    std::fs::create_dir_all(src.join("extras")).unwrap();
    std::fs::write(src.join("E01.mkv"), b"episode").unwrap();
    std::fs::write(src.join("extras/behind.mkv"), b"extra").unwrap();

    // The destination the caller names is a link to the real folder.
    let linked = root.join("Season 01");
    std::os::unix::fs::symlink(&real, &linked).unwrap();

    // The copy door, which is the one that actually reaches `open_dest`
    // for every file: a merge into an occupied destination.
    copy_tree(&src, &linked).unwrap();
    assert_eq!(std::fs::read(real.join("E01.mkv")).unwrap(), b"episode");
    assert_eq!(
        std::fs::read(real.join("extras/behind.mkv")).unwrap(),
        b"extra"
    );

    // And the move door, over the copies the line above left behind, so
    // it takes the merge path rather than the one-rename fast path.
    move_tree(&src, &linked).unwrap();
    assert!(!src.exists(), "the source should have drained");
    assert_eq!(std::fs::read(real.join("E01 (2).mkv")).unwrap(), b"episode");
    let _ = std::fs::remove_dir_all(&root);
}

// -- The two-symlink escape, and the 31 Aug 2026 ruling on both halves ---
//
// Both defects were MEASURED with a throwaway probe on this tree before
// anything was changed. They were left open, deliberately and with the
// measurement recorded, by
// research/MOVETREE-BOUND-DESTINATION-2026-08-31.md; the fix and what
// each door actually leaked are
// research/MOVETREE-SYMLINK-ESCAPE-2026-08-31.md. Chained they were a
// containment escape: job 1 planted a link in the library, job 2 filed
// its payload through it, and `move_tree` returned `Ok(())` with the
// episode sitting outside the destination entirely.
//
// Neither half is mechanical hardening - each is a decision about what a
// user may arrange inside their OWN library - so both were settled as
// product judgements rather than fixed in passing. The ruling: leave a
// source link in place, and refuse a link standing at a destination
// subdirectory.

/// HALF ONE. A symlink in a finished job is left where it is, on the
/// SAME filesystem as well as across devices.
///
/// The leave-it-in-place arm used to sit inside the `rename` FAILURE
/// branch, so it only ever covered the cross-device case. On one
/// filesystem the rename SUCCEEDS, so the link object was filed into the
/// library still pointing outside it - which is what made the second half
/// below reachable by an ordinary later job.
#[cfg(unix)]
#[test]
fn a_symlink_in_the_job_is_never_published_into_the_library() {
    let root = std::env::temp_dir().join(format!("nzbfast-mvsrclink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("someone-elses.txt"), b"not yours").unwrap();

    let src = root.join("job");
    let dst = root.join("library/My Show");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    // Occupy the destination so this takes the MERGE path and not the
    // one-rename fast path, which is where the defect lived.
    std::fs::write(dst.join("already-here.txt"), b"x").unwrap();
    std::fs::write(src.join("E01.mkv"), b"episode").unwrap();
    std::os::unix::fs::symlink(&outside, src.join("link")).unwrap();

    move_tree(&src, &dst).unwrap();

    // The payload still files.
    assert_eq!(std::fs::read(dst.join("E01.mkv")).unwrap(), b"episode");
    // The link does not, by any name the collision reservation would
    // have picked for it.
    assert!(
        !dst.join("link").exists() && !is_symlink_t(&dst.join("link")),
        "a symlink from the job was published into the library"
    );
    assert!(!is_symlink_t(&dst.join("link (2)")));
    // It stays where the user put it, and the source folder therefore
    // stays too - exactly what a cross-device move has always left.
    assert!(
        is_symlink_t(&src.join("link")),
        "the link should have been left in place"
    );
    // Nothing outside the job was read, copied or deleted through it.
    assert_eq!(
        std::fs::read(outside.join("someone-elses.txt")).unwrap(),
        b"not yours"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// HALF TWO, and the escape itself. A LIVE symlink at a destination
/// SUBDIRECTORY is refused, naming the path, rather than filed through.
///
/// The recursion tested `!dst.exists()`, which FOLLOWS links: a live
/// `Season 01 -> outside/` meant the fast rename was skipped, the merge's
/// own `create_dir_all` followed the link, and every episode landed
/// outside the library. Driven through all three doors that carry the
/// shape, because they were three separate holes and a fix at one says
/// nothing about the others.
///
/// WHAT EACH DOOR ACTUALLY LEAKED was measured rather than assumed, and
/// the three are not equal. `move_tree` and `publish_staged` filed the
/// PAYLOAD outside the destination and returned `Ok(())`. `copy_tree`
/// did not: `open_dest`'s no-follow PARENT refusal, which landed with
/// the bound-destination work on 31 Aug 2026, already stopped every byte
/// - but only where there is a file to write. A subtree of DIRECTORIES
/// reaches no leaf, so it sailed through `create_dir_all`, built the
/// user's folder structure outside their library and reported success.
/// Both shapes are driven below for that reason.
#[cfg(unix)]
#[test]
fn a_merge_refuses_a_symlink_standing_at_a_destination_subdirectory() {
    let root = std::env::temp_dir().join(format!("nzbfast-mvdstlink-{}", std::process::id()));

    // THE COPY DOOR'S OWN ESCAPE, pinned deterministically, and FIRST in
    // this test on purpose. In the shared loop below, the file in the
    // source fails before the directory does, so the copy door is judged
    // there by its MESSAGE and the escape assertion rests on `read_dir`
    // order - which means a copy-door regression is caught, but not by
    // the assertion that names what went wrong. This leg has no such
    // ordering: a source of DIRECTORIES ONLY reaches no leaf, so
    // `open_dest`'s no-follow parent refusal never fires and there is
    // nothing else in the way: without [`bind_dst_dir`] this returns
    // `Ok(())` having built the user's folders outside their library.
    let base = root.join("copy-dirs-only");
    let outside = base.join("outside");
    let show = base.join("library/My Show");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&show).unwrap();
    std::os::unix::fs::symlink(&outside, show.join("Season 01")).unwrap();
    let src = base.join("job");
    std::fs::create_dir_all(src.join("Season 01/Extras/Deeper")).unwrap();
    let e = copy_tree(&src, &show).unwrap_err();
    assert!(
        e.to_string()
            .contains("refusing to file through the symlink"),
        "copy/dirs-only: wrong refusal: {e}"
    );
    assert!(
        !outside.join("Extras").exists(),
        "copy/dirs-only: a folder was built OUTSIDE the destination"
    );

    for (leg, dangling) in [("live", false), ("dangling", true)] {
        for door in ["move", "copy"] {
            let base = root.join(format!("{leg}-{door}"));
            let _ = std::fs::remove_dir_all(&base);
            let outside = base.join("outside");
            let show = base.join("library/My Show");
            std::fs::create_dir_all(&show).unwrap();
            if dangling {
                std::os::unix::fs::symlink(base.join("gone"), show.join("Season 01")).unwrap();
            } else {
                std::fs::create_dir_all(&outside).unwrap();
                std::os::unix::fs::symlink(&outside, show.join("Season 01")).unwrap();
            }

            let src = base.join("job");
            // A file AND a directory-only branch beside it: the file is
            // what the move door carried outside, and the bare directory
            // is the shape that reaches no leaf, so it is all the copy
            // door's own no-follow leaf refusal can never see.
            std::fs::create_dir_all(src.join("Season 01/Extras/Deeper")).unwrap();
            std::fs::write(src.join("Season 01/E01.mkv"), b"episode").unwrap();

            let e = match door {
                "move" => move_tree(&src, &show).unwrap_err(),
                _ => copy_tree(&src, &show).unwrap_err(),
            };
            assert!(
                e.to_string()
                    .contains("refusing to file through the symlink"),
                "{leg}/{door}: wrong refusal: {e}"
            );
            assert!(
                e.to_string().contains("Season 01"),
                "{leg}/{door}: the refusal must name the path: {e}"
            );
            assert!(
                !outside.join("E01.mkv").exists(),
                "{leg}/{door}: the payload was filed OUTSIDE the destination"
            );
            assert!(
                !outside.join("Extras").exists(),
                "{leg}/{door}: a folder was built OUTSIDE the destination"
            );
            // The source is untouched, so nothing is lost by refusing.
            assert!(src.join("Season 01/E01.mkv").exists(), "{leg}/{door}");
            // The user's link is left exactly as they arranged it.
            assert!(is_symlink_t(&show.join("Season 01")), "{leg}/{door}");
        }
    }

    // And the CROSS-DEVICE publish carries the identical shape, so it is
    // driven directly: `staged_move` copies into a staging directory this
    // process minted and `publish_staged` walks it into the destination.
    let base = root.join("publish");
    let outside = base.join("outside");
    let show = base.join("library/My Show");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&show).unwrap();
    std::os::unix::fs::symlink(&outside, show.join("Season 01")).unwrap();
    let staging = base.join("staging");
    std::fs::create_dir_all(staging.join("Season 01")).unwrap();
    std::fs::write(staging.join("Season 01/E01.mkv"), b"episode").unwrap();
    let e = publish_staged(&staging, &show).unwrap_err();
    assert!(
        e.to_string()
            .contains("refusing to file through the symlink"),
        "publish_staged: wrong refusal: {e}"
    );
    assert!(!outside.join("E01.mkv").exists(), "publish_staged escaped");

    let _ = std::fs::remove_dir_all(&root);
}

/// `is_symlink` is private to `movetree`, and these three cases care
/// about the LINK rather than what it points at.
#[cfg(unix)]
fn is_symlink_t(p: &std::path::Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
}

// -- F5: a job whose declared size is UNKNOWN ------------------------------
//
// `serve::daemon_enqueue::resolve_add_identity` hands `first_match` the
// job's `Nzb::eager_bytes`, and that figure is 0 when the manifest
// declared no `bytes=` attributes anywhere. `nzbkit::nzb`'s own
// `<segment>` comment states the position on that shape outright - "0
// posted bytes means unknown, not zero" - and this end of the pipe
// cannot tell the two apart. The three tests below PIN what happens
// today rather than assert that it is right: which answer a size-gated
// rule should give when the size is unknown is the open product
// question in the zero-declared-bytes handoff (claim
// `nzb-zero-bytes-downstream`).

/// Today's answer, both directions. A `min_size` rule DECLINES a job
/// whose size is unknown and a `max_size` rule ACCEPTS one, and neither
/// is a judgement about the job - both are `0` being read as a
/// measurement.
#[test]
fn a_size_gated_rule_reads_an_unknown_size_as_zero() {
    let mut floor = rule("The.Bear");
    floor.min_size = 100_000_000;
    floor.category = "tv".into();
    assert!(
        !floor.matches("The.Bear.S03E05.1080p.WEB-X", 0),
        "a min_size rule declines the job, so it files under the default \
         category with nothing saying the rule was never really judged"
    );
    assert!(
        floor.matches("The.Bear.S03E05.1080p.WEB-X", 2_500_000_000),
        "control: the same rule on a job that DID declare its bytes"
    );

    let mut ceiling = rule("sample");
    ceiling.max_size = 500_000_000;
    ceiling.category = "samples".into();
    assert!(
        ceiling.matches("Some.Release.sample", 0),
        "a max_size rule waves the same unknown through - the silence \
         points the other way and is no better informed"
    );
}

/// The population the unknown reaches. Zero here is the common list
/// (no size bounds anywhere), which is why `resolve_add_identity` logs
/// conditionally rather than once per add.
#[test]
fn size_gated_counts_the_rules_the_unknown_reaches() {
    let plain = rule("1080p");
    let mut floor = rule("");
    floor.min_size = 1;
    let mut ceiling = rule("");
    ceiling.max_size = 1;
    let mut both = rule("");
    both.min_size = 1;
    both.max_size = 2;

    assert_eq!(size_gated(&[]), 0, "an empty list asks no size question");
    assert_eq!(size_gated(std::slice::from_ref(&plain)), 0);
    assert_eq!(size_gated(&[plain, floor, ceiling, both]), 3);
}

/// What the fix is NOT. `Nzb::geometry_bytes` is the figure that already
/// answers "how big could this post be" elsewhere
/// (`repair::sidefetch::volume_prealloc_cap`), and substituting it here
/// would be worse than the silence it replaces: it is a preallocation
/// CEILING of declared articles times 16 MiB, and a real article is
/// 768000 or 716800 bytes, so it runs 21.8x to 23.4x above the truth on
/// an ordinary post. This test drives the arithmetic on real thresholds
/// rather than asserting it in prose, because the next reader of F5 will
/// reach for that function first.
#[test]
fn geometry_bytes_cannot_stand_in_for_an_unknown_size() {
    const MAX_ARTICLE_BYTES: u64 = 16 << 20;
    // A 190 MB post at a realistic 768000-byte article, and the
    // geometry ceiling the same article count produces.
    let real: u64 = 190_000_000;
    let articles = real.div_ceil(768_000);
    let geometry = articles * MAX_ARTICLE_BYTES;
    assert!(
        geometry > 4_000_000_000,
        "sanity: {articles} articles reserve {geometry} bytes of ceiling"
    );

    let mut movies = rule("");
    movies.min_size = 4_000_000_000;
    assert!(
        !movies.matches("Small.Release", real),
        "the truth: a 190 MB post is not a film"
    );
    assert!(
        movies.matches("Small.Release", geometry),
        "the substitution: geometry calls it one, which is a MISROUTE \
         where today's answer merely declines"
    );

    // The ceiling direction fails the same way. A 24 MB sample.
    let small: u64 = 24_000_000;
    let sgeom = small.div_ceil(768_000) * MAX_ARTICLE_BYTES;
    let mut samples = rule("");
    samples.max_size = 500_000_000;
    assert!(samples.matches("Some.sample", small), "the truth");
    assert!(
        !samples.matches("Some.sample", sgeom),
        "the substitution refuses a job that is well inside the bound"
    );
}

// ---------------------------------------------------------------------
// Names AT the component cap, in the three `smart` doors that decorate
// one. Every leaf below is a `sanitize_out_name` result, so for a long
// posted name it is EXACTLY 255 bytes - capping is what produced it -
// and anything composed onto it is a name no filesystem creates
// (measured on APFS 31 Aug 2026: 255 creates, 256 is `ENAMETOOLONG`).
// ---------------------------------------------------------------------

/// The premise, asserted rather than assumed.
fn a_name_at_the_cap(ext: &str) -> String {
    let n = nzbkit::disk::sanitize_out_name(&format!("{}{ext}", "y".repeat(400)));
    assert_eq!(n.len(), 255, "the premise moved");
    n
}

fn cap_tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-namecap-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The uncollide ladder must hand back a name the disk takes.
///
/// `reserve_free_name` CLAIMS each rung with `create_new`, and
/// `ENAMETOOLONG` is not the `AlreadyExists` arm - it is the `Err(e)`
/// arm, which returns. So the whole move failed on the FIRST collision
/// of a longest-named payload, which is exactly the meeting this ladder
/// exists to resolve.
#[test]
fn reserving_past_a_name_at_the_cap_still_yields_a_writable_name() {
    let root = cap_tmpdir("reserve");
    let name = a_name_at_the_cap(".mkv");
    let wanted = root.join(&name);

    let first = reserve_free_name(&wanted).expect("the plain name is free");
    assert_eq!(first, wanted, "the first caller still gets the plain name");
    let second = reserve_free_name(&wanted).expect("the ladder must not fail on the cap");
    assert_ne!(second, first);
    let leaf = second.file_name().unwrap().to_string_lossy();
    assert!(leaf.len() <= 255, "{} bytes: {leaf}", leaf.len());
    // `reserve_free_name` created it, which is the whole assertion.
    assert!(second.is_file());

    // Nothing that works today moves: inside the cap the rung is still
    // the plain `format!`, byte for byte.
    let plain = root.join("Episode.mkv");
    reserve_free_name(&plain).unwrap();
    assert_eq!(
        reserve_free_name(&plain).unwrap(),
        root.join("Episode (2).mkv")
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The whole-job move stages under a sibling of the DESTINATION, and
/// that sibling's name decorates the destination's own leaf.
///
/// Worse than a niggle: `rename_reaches` renames a probe onto that very
/// name to decide whether the pair is same-device, so an unwritable one
/// reads as CROSS-device and the copying path it then takes fails on the
/// identical name a moment later. A completed job whose folder was at
/// the cap could not be moved to the completed folder at all.
#[test]
fn a_destination_named_at_the_cap_can_still_be_moved_into() {
    let root = cap_tmpdir("movestage");
    let src = root.join("src");
    std::fs::create_dir_all(src.join("inner")).unwrap();
    std::fs::write(src.join("episode.mkv"), b"payload").unwrap();
    std::fs::write(src.join("inner/note.nfo"), b"note").unwrap();

    // The destination EXISTS, which is what puts the move on the staging
    // path rather than the plain same-directory rename.
    let dst = root.join(a_name_at_the_cap(""));
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(dst.join("already.txt"), b"kept").unwrap();

    move_tree(&src, &dst).expect("a destination at the cap must still be movable into");

    assert_eq!(std::fs::read(dst.join("episode.mkv")).unwrap(), b"payload");
    assert_eq!(std::fs::read(dst.join("inner/note.nfo")).unwrap(), b"note");
    assert_eq!(
        std::fs::read(dst.join("already.txt")).unwrap(),
        b"kept",
        "the merge keeps what was there"
    );
    // No staging directory survives a successful move.
    let strays: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".moving."))
        .collect();
    assert!(strays.is_empty(), "staging left behind: {strays:?}");

    let _ = std::fs::remove_dir_all(&root);
}

/// The deferred-trash park prefixes `<pid>-<seq>-` onto the swept file's
/// own name, so a payload at the cap could not be parked - it fell back
/// to the inline Trash call, which is correct and is the §64 stall this
/// module exists to keep off `finalize_completed`.
///
/// The parked name cannot be read back directly (the worker disposes of
/// it behind us), so the drain is what asserts it: a FRESH staging root
/// takes the first-touch path, which sends only entries `is_staged_entry`
/// recognises - so a pruned staging directory says the parked name was
/// both written and recognisable, which is the pair the cap has to keep.
#[test]
fn a_swept_file_named_at_the_cap_can_still_be_parked() {
    let _steady = trash_globals_steady();
    let root = cap_tmpdir("park");
    let staging = root.join(".nzbfast-trash");
    let name = a_name_at_the_cap(".par2");
    let f = root.join(&name);
    std::fs::write(&f, b"spent").unwrap();

    deferred_trash::stage(&f, &staging).expect("a name at the cap must still park");
    assert!(!f.exists(), "the rename must be synchronous");
    deferred_trash::drained();
    assert!(
        !staging.exists(),
        "the parked name must be one the drain recognises and disposes of"
    );

    let _ = std::fs::remove_dir_all(&root);
}
