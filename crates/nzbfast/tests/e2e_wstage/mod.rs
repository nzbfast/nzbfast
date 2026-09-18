//! The one-pass writer's write-coalescing window, exercised END TO END
//! with the window ARMED - which is coverage nothing else in this tree
//! has since `79dbef8f7` (17 Sep 2026) took
//! `nzbkit::disk::stage::COALESCE_CAP_DEFAULT` back to 0.
//!
//! **WHY THIS MODULE EXISTS, AND WHY IT IS NOT A UNIT TEST.** The
//! measurement that turned the window off
//! (`research/WSTAGE-WINDOW-DEFAULT-2026-09-17.md`: a wall loss on both
//! an SSD and a rotational array, a win on neither) stands and nothing
//! here revisits it. What the flip also did, unintentionally, is put the
//! window back into the state round 44 of
//! `research/RAR-PERF-AUDIT-2026-09-02.md` named as its own most
//! transferable finding - "a feature shipped default-off is a feature no
//! suite runs". Round 44 found TWO REAL DEFECTS purely by turning the
//! default on, and both are integration-level, so 26 unit sites forcing
//! `FileWriter::coalescing(true)` do not cover them:
//!
//! 1. **The §217 resume mark came out EMPTY.** `prefix_hash()` was a door
//!    that did not flush, and `WriteStage::take_all` flushed a file's
//!    open runs in BIRTH order, which hands `PrefixHash` a hole and
//!    freezes it at the first run out of sequence. The observable was a
//!    whole missing ledger in
//!    `e2e_chaseresume::a_forfeited_7z_chase_resumes_its_member_on_disk`,
//!    which needs a forfeited chase, a disk pass and a 36 MB member -
//!    none of which a `disk.rs` unit test has.
//! 2. **A SIGKILL cost 1 to 4 extra refetched articles**, over
//!    `fault_contract::contract_crash_in_fault_window`'s budget, because
//!    a staged byte is in RAM while the journal has already landed a
//!    record naming it. The fix was the per-file ARMING RULE, and the
//!    only way to see it work is a real kill against a real journal.
//!
//! **EVERY LEG HERE PROVES THE WINDOW ACTUALLY ARMED**, which is the
//! trap rather than a nicety: the window arms per FILE only once that
//! file has taken `run_cap` bytes inside one `STAGE_MAX_AGE_DEFAULT`
//! bound, so a leg that sets `NZBFAST_WRITE_COALESCE_KB` and grades an
//! outcome can run the UNSTAGED path end to end and report a pass over a
//! feature it never touched. Round 44 hit exactly that when its 100 KB
//! `manysmall` leg declined to arm. [`armed_spans`] reads the run's own
//! `[write-window]` line, which `get::tail::print_write_window` emits
//! from `stage::staged_totals` - cumulative counters, because every
//! other reading of the window is a LEVEL that is back to zero by the
//! time a test can look.
//!
//! **BOTH ARMING PROBES ARE PROCESS-WIDE, AND A LEG WITH TWO WRITERS
//! MUST READ THEM THAT WAY** (17 Sep 2026, claim
//! `e2e-wstage-forfeit-flake-17sep`). `stage::announce_first_arming`
//! says ONCE PER PROCESS that some file armed, and `staged_totals`
//! counts every file's spans together, so neither names the writer. In
//! the forfeited-chase leg below that is not a quibble: its container
//! (`release.7z`, 700,000 byte articles) ARMS and then stages nothing -
//! every one of those articles is over `STAGE_MAX_ARTICLE_DEFAULT` - so
//! the in-flight line is always present and is never a statement about
//! the member, which is the only writer whose bytes that leg is about.
//! A leg with two writers grades on the SPAN COUNT; the latch line is a
//! statement about a killed process and nothing more.
//!
//! A sibling-dir child module (the `e2e_repair` pattern, harness reached
//! through `super::*`) so `e2e.rs` stays inside its size-gate baseline.

use super::*;
use std::sync::atomic::Ordering;

/// The per-file window every leg here dials, in the env spelling the
/// shipped binary reads. 4 MiB is exactly what `COALESCE_CAP_DEFAULT`
/// was through the fortnight it shipped on, so these legs run the
/// configuration round 44 shipped rather than a test-only one.
const WINDOW_ENV: (&str, &str) = ("NZBFAST_WRITE_COALESCE_KB", "4096");

/// The run cap the FORFEITED-CHASE leg dials, and the reason it is not
/// the shipped `stage::RUN_CAP_DEFAULT` (1 MiB).
///
/// **THE ARMING PROBE COUNTS WRITES, NOT BYTES, AND THAT LEG'S WRITES
/// ARE 8 KiB** (17 Sep 2026, claim `e2e-wstage-forfeit-flake-17sep`).
/// The file that stages in that leg is the MEMBER, `movie.mkv`, and the
/// 7z chase routes it through `FileWriter::write_article_at` in 8,192
/// byte pieces - its sink's copy buffer, not an article. So the shipped
/// 1 MiB run cap asks that leg for **128 positioned writes inside one
/// `STAGE_MAX_AGE_DEFAULT` (100 ms) bound**, which is a rate the fixture
/// hopes for rather than sets, and it is the whole of that leg's flake.
///
/// **THE MARGIN IS MEASURED BY SHRINKING THE BOUND, and that instrument
/// is the reason this fix can be stated as a number at all.** The flake
/// is a load race, so a box that happens to be fast reproduces nothing
/// (12 concurrent copies of the leg passed 36 of 36 here on the day it
/// was fixed, while two other boxes were seeing 40-50%). Setting
/// `NZBFAST_WRITE_COALESCE_MAX_AGE_MS` BELOW the shipped 100 ms models
/// a slower box on the one clause that binds, and the smallest bound a
/// leg still passes at is its margin. Measured on the dev Mac:
///
/// - the 1 MiB cap FAILS at 2 ms and 5 ms and passes at 20 ms, with the
///   exact panic the field reports - `write window ARMED on a file`
///   present, `staged 0 span(s)` - so it wants about a fifth of the
///   shipped bound and ships with roughly 5x of margin;
/// - 64 KB passes 4 of 4 at **1 ms**, and did so at load1 74 against
///   the 1 MiB arm's load1 12, so its margin is ≥100x and was taken on
///   the worse box of the two.
///
/// 64 KB is eight pieces, and it is not a loosened assertion:
/// [`assert_armed`] is untouched and still refuses a run that staged
/// nothing. What it costs is stated rather than hidden. A run now holds
/// eight spans instead of 128, so the window still COALESCES (8:1) and
/// still holds an open partial run when `prefix_hash()` takes the mark,
/// which is the door defect 1 lives behind - but the prefix is a whole
/// number of pieces, so one forfeit in eight lands on an exactly empty
/// window and cannot see that defect. Against a leg that does not arm
/// at all on a loaded box, which is what it was, 7 in 8 is the
/// improvement and not the price.
///
/// **DO NOT INSTRUMENT THIS PATH PER WRITE TO RE-MEASURE ANY OF THIS.**
/// A probe that appends one line to a file inside
/// `FileWriter::write_article_at` costs more than the 8 KiB write it is
/// watching, and it does not merely inflate a timing: it collapses the
/// chase's whole pre-forfeit prefix from ~200 pieces to 1 or 2, because
/// the held-bytes cap trips on arrival outrunning the decode and the
/// probe is charged to the decode. Every figure that instrument
/// produced here was wrong in both magnitude and sign of conclusion.
/// The bound ladder above needs no instrumentation and is the
/// measurement to repeat.
///
/// **THE OTHER TWO LEGS DO NOT TAKE THIS AND MUST NOT.** They set
/// article size and arrival rate themselves and reason about the
/// shipped 1 MiB run cap in those terms (250 KB articles over eight
/// connections is five articles to a run, an order of magnitude of
/// headroom); the arming rule is the subject of
/// [`the_window_declines_to_arm_at_a_real_lines_rate`], so moving its
/// constant there would be moving the thing under test.
const RUN_ENV: (&str, &str) = ("NZBFAST_WRITE_COALESCE_RUN_KB", "64");

/// Spans this run staged, read out of its own `[write-window]` line.
///
/// **PANICS WHEN THE LINE IS ABSENT, and that is deliberate.** An absent
/// line means the binary did not emit one, which means the window was
/// not configured on at all - a leg that treated that as "nothing was
/// staged" would be reporting its own blindness as a result, which is
/// CLAUDE.md's "failing to find is failing". A line reading `0 span(s)`
/// is a different and honest answer: configured on, never armed.
fn armed_spans(log: &str) -> u64 {
    let line = log
        .lines()
        .find(|l| l.contains("write window on at"))
        .unwrap_or_else(|| {
            panic!("no [write-window] line - the run never had the window configured on:\n{log}")
        });
    // "... staged N span(s), ..."
    let after = line
        .split("staged ")
        .nth(1)
        .unwrap_or_else(|| panic!("malformed [write-window] line: {line}"));
    after
        .split(' ')
        .next()
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("malformed [write-window] line: {line}"))
}

/// The arming proof a run that was SIGKILLED can still give: the
/// once-per-process line `stage::announce_first_arming` emits AT the
/// latch, inside the run, rather than in a summary the kill prevents.
///
/// Weaker than [`assert_armed`] on purpose - it says a file armed, not
/// how many spans it then staged - and it is the strongest statement
/// available about a process that was stopped between two instructions.
fn assert_armed_in_flight(log: &str, what: &str) {
    assert!(
        log.contains("write window ARMED on a file"),
        "the window was configured on and never ARMED in {what}, so this leg          graded the unstaged path and proves nothing about coalescing -          see this module's header:\n{log}"
    );
}

/// The assertion every leg opens with: this run genuinely took the
/// staged path. Answers the span count so a leg can print it.
fn assert_armed(log: &str, what: &str) -> u64 {
    let spans = armed_spans(log);
    assert!(
        spans > 0,
        "the window was configured on and never ARMED in {what}, so this leg \
         graded the unstaged path and proves nothing about coalescing - \
         see this module's header:\n{log}"
    );
    spans
}

/// Defect 1: the §217 forfeit-resume ledger survives a member whose
/// bytes passed through the window.
///
/// The same fixture as
/// `e2e_chaseresume::a_forfeited_7z_chase_resumes_its_member_on_disk` -
/// deliberately, because that is the leg round 44's `prefix_hash` defect
/// reddened - with the window armed.
///
/// **THE ARMING IS SET BY [`RUN_ENV`], NOT HOPED FOR, and the sentence
/// that stood here is why** (17 Sep 2026). It read "a 36 MB stored
/// member decoded into a chase is exactly the shape that arms: one
/// output file taking far more than a run's worth of bytes inside one
/// age bound", and it is wrong in the clause that matters. The member
/// does take far more than a run's worth of BYTES - 1.4 to 2.3 MB of
/// prefix before the forfeit, measured under contention - but the chase
/// routes them in 8 KiB pieces, so a run's worth is 128 separate
/// positioned writes and the age bound is a question about the BOX. It
/// answered no 40-50% of the time, measured independently on two
/// development machines - 8 of 16 on one, and on the other 6
/// consecutive failures in one window against 13 consecutive passes in
/// another on the SAME binary with nothing changed but load. The
/// per-push `e2e` shards run at `retries = 1`, which made that about a
/// one-in-five red main per push. The panic it left
/// reads oddly and is worth recognising - `write window ARMED on a
/// file` PRESENT and `staged 0 span(s)` - because
/// `stage::announce_first_arming` fires once per PROCESS and the
/// container's own writer wins the race to it: `release.7z` takes two
/// 700,000 byte articles inside a bound, latches, and then stages
/// nothing at all, every one of those articles being over
/// `STAGE_MAX_ARTICLE_DEFAULT`. So the line is the CONTAINER's and the
/// spans are the MEMBER's, and only the span count grades this leg.
///
/// What would fail here and nowhere else: a `prefix_hash()` that does
/// not flush (the mark is taken over an open run, so the ledger names a
/// prefix whose tail is in RAM), and a `take_all` that flushes in birth
/// rather than ascending offset order (the hash freezes at the first run
/// out of sequence and the ledger comes out empty).
#[tokio::test(flavor = "multi_thread")]
async fn a_forfeited_chase_keeps_its_resume_mark_with_the_window_armed() {
    let log = crate::e2e_chaseresume::forfeited_arm(
        "res7zwin",
        "release.7z",
        false,
        &[WINDOW_ENV, RUN_ENV],
    )
    .await;
    let spans = assert_armed(&log, "the forfeited 7z chase");
    assert!(
        log.contains("resuming 1 member(s)"),
        "the window was armed ({spans} span(s)) and the ledger came out empty, \
         so the member re-extracted from byte zero - this is round 44's \
         prefix-hash defect:\n{log}"
    );
}

/// One kill-and-resume leg, parameterized by the only two things that
/// decide whether the window ARMS: how big an article is and how fast
/// they arrive. Both legs below run the same 48 MB single-file corpus
/// through the same SIGKILL and the same clause-5 arithmetic, and the
/// only difference between them is the regime - which is the comparison
/// round 44's arming rule is a claim about.
///
/// One file, so every article feeds one writer and the arming probe sees
/// the whole fleet's rate. No PAR2 and no container: the writer under
/// test is `write_article_direct`, which is where a staged byte meets
/// the journal.
struct KillLeg {
    run1_log: String,
    run2_log: String,
    refetched: usize,
    redone: usize,
    gap: usize,
    journalled: usize,
    budget: usize,
    slack: usize,
}

async fn kill_leg(tag: &str, article_bytes: usize, delay_ms: u64, conns: u32) -> KillLeg {
    let mut fx = Fixture::new(tag);
    let data = payload(48 << 20, 91);
    fx.add_file("winkill.bin", &data, article_bytes);
    let total = fx.articles.len() as u64;
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // Run 1: kill once ~40% is served AND the journal holds placements
    // for run 2 to resume from. Paced by the caller so the kill is
    // reachable at all - unpaced, the corpus can land before the poll
    // loop sees the mark, the trap `e2e_resume`'s own helper documents.
    let run1_log = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        let served2 = served.clone();
        tokio::task::spawn_blocking(move || {
            let run = run_get_spawn(&cfg, &nzb, &out, &[WINDOW_ENV], &[], conns, 4);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let journal = out.join(".nzbfast.journal");
            while served2.load(Ordering::Relaxed) < total * 2 / 5
                || !std::fs::read_to_string(&journal).is_ok_and(|s| s.lines().count() > 1)
            {
                if std::time::Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            run.kill9()
        })
        .await
        .unwrap()
    };
    let served_run1 = served.load(Ordering::Relaxed);
    assert!(
        served_run1 >= total * 2 / 5,
        "run 1 made no progress ({served_run1}/{total}) - nothing below was tested\n{run1_log}"
    );
    let recorded_at_kill = nzbkit::journal::Journal::peek(&out)
        .map(|r| r.recorded_ids())
        .unwrap_or_default();
    assert!(
        !recorded_at_kill.is_empty(),
        "the journal held nothing at the kill, so clause 5 below is vacuous\n{run1_log}"
    );
    let asked_run1 = srv.serve_counts();

    // Run 2: resume to a clean, byte-exact finish.
    let (run2_log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[WINDOW_ENV]))
            .await
            .unwrap()
    };
    assert!(ok, "resume run failed\n{run2_log}");
    assert_eq!(
        std::fs::read(out.join("winkill.bin")).expect("payload after the resume"),
        data,
        "the resumed payload is wrong - a byte was lost across the kill"
    );

    // Clause 5, in `fault_contract::contract_crash_in_fault_window`'s
    // arithmetic and deliberately not a second spelling of it: the gap
    // is READ from the journal at the kill rather than derived from the
    // wire, for the reason that test's own comment gives at length.
    let after = srv.serve_counts();
    let refetched: Vec<&String> = after
        .iter()
        .filter(|(id, n)| **n > asked_run1.get(*id).copied().unwrap_or(0))
        .filter(|(id, _)| asked_run1.contains_key(*id))
        .map(|(id, _)| id)
        .collect();
    let gap = asked_run1
        .keys()
        .filter(|id| !recorded_at_kill.contains(*id))
        .count();
    // The same slack `fault_contract` allows, for the same reason (a
    // record whose bytes the kill tore re-reads, fails its crc and
    // refetches) and in the same quantity: one fleet's worth of
    // connections. DO NOT WIDEN IT BY A CONSTANT to make an armed window
    // fit - that is precisely the edit round 44 refused, and the answer
    // it took instead was the arming rule.
    let slack = conns as usize;
    let budget = gap + slack;
    let redone = refetched
        .iter()
        .filter(|id| recorded_at_kill.contains(**id))
        .count();
    assert!(
        refetched.len() <= budget,
        "the resume refetched {} of the {} articles run 1 had asked for (budget \
         {budget}: the {gap} the crash left un-journalled plus {slack} slack)\n{run2_log}",
        refetched.len(),
        asked_run1.len(),
    );
    assert!(
        redone <= slack,
        "the resume re-asked for {redone} articles run 1 had already JOURNALLED. A \
         staged byte is in RAM and a kill takes it while its record has landed - \
         this is round 44's refetch-budget defect, and the fix is the per-file \
         arming rule, never a bigger constant: {refetched:?}\n{run2_log}",
    );
    KillLeg {
        run1_log,
        run2_log,
        refetched: refetched.len(),
        redone,
        gap,
        journalled: recorded_at_kill.len(),
        budget,
        slack,
    }
}

/// Defect 2, the ARMED half: a SIGKILL with bytes in the window still
/// refetches only the gap.
///
/// 250 KB articles - just under `STAGE_MAX_ARTICLE_DEFAULT` (256 KiB),
/// the largest the window will hold and so the fewest articles a 1 MiB
/// run needs - over eight connections at 12 ms each. That is about 160
/// MB/s to one file against the 10 MB/s the probe wants, an order of
/// magnitude of headroom, so the arming assertion is a guard rather than
/// a race.
///
/// What this stands over is the bound that makes an armed window safe:
/// `STAGE_MAX_AGE_DEFAULT` is the journal's own `BATCH_AGE`, the SAME
/// constant, so an article's bytes reach disk within the same window its
/// record does and the kill that loses one loses the other. Drift those
/// two apart, or lose a flush door, and `redone` below goes unbounded -
/// it is 0 to 3 against a slack of 8 as this landed, which is the
/// measured cost of the feature and not headroom to spend.
#[tokio::test(flavor = "multi_thread")]
async fn a_kill_with_the_window_armed_refetches_only_the_gap() {
    let leg = kill_leg("winkill", 250_000, 12, 8).await;
    // THE ARMING PROOF, on the run whose SIGKILL is under test. Run 1 is
    // stopped between two instructions and prints no summary, so this
    // reads the in-flight latch line; run 2's summary is asserted too,
    // because the resume writes the remaining 60% through the same
    // window and a resume that quietly fell off the staged path would
    // make everything above a statement about the unstaged one.
    assert_armed_in_flight(&leg.run1_log, "run 1 (the killed run)");
    let spans = assert_armed(&leg.run2_log, "run 2 (the resume)");
    eprintln!(
        "[wstage] armed kill: run 1 latched, resume staged {spans} span(s), {} refetched \
         ({} journalled at the kill, gap {}, budget {}), {} redone against {} slack",
        leg.refetched, leg.journalled, leg.gap, leg.budget, leg.redone, leg.slack,
    );
}

/// Defect 2, the half that stands over the ARMING RULE ITSELF - which is
/// the fix round 44 actually took, and the one the leg above cannot see
/// because its fixture arms either way.
///
/// The same corpus at a REAL LINE'S per-file rate: 48 KB articles over
/// four connections at 40 ms each, about 1.6 MB/s to the one file, so a
/// 100 ms bound carries ~160 KB against the 1 MiB a run wants. The
/// window is configured ON and must decline to arm, which is exactly
/// what makes the write path byte-for-byte the one round 41 shipped in
/// the regime where round 23 found the write call nowhere near the
/// critical path.
///
/// **THE ASSERTION IS AN ABSENCE, SO IT IS GUARDED FROM BOTH SIDES.**
/// [`armed_spans`] panics when the summary line is missing entirely -
/// that would mean the binary never read `NZBFAST_WRITE_COALESCE_KB` and
/// the whole leg was the shipped default with extra steps - and the leg
/// then asserts the line says `0 span(s)` and that no file ever latched.
/// Delete the arming probe and this goes red on the latch line before it
/// ever reaches the refetch budget round 44 blew.
#[tokio::test(flavor = "multi_thread")]
async fn the_window_declines_to_arm_at_a_real_lines_rate() {
    let leg = kill_leg("winkillslow", 48_000, 40, 4).await;
    assert!(
        !leg.run1_log.contains("write window ARMED on a file"),
        "a file armed at about 1.6 MB/s, which is a run's worth of bytes nowhere \
         near one age bound - the arming probe is not doing what round 44 shipped \
         it to do:\n{}",
        leg.run1_log
    );
    assert_eq!(
        armed_spans(&leg.run2_log),
        0,
        "the window staged a span at a real line's rate:\n{}",
        leg.run2_log
    );
    eprintln!(
        "[wstage] unarmed kill: window on, 0 spans staged, {} refetched \
         ({} journalled at the kill, gap {}, budget {}), {} redone",
        leg.refetched, leg.journalled, leg.gap, leg.budget, leg.redone,
    );
}
