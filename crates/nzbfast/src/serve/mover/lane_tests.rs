//! Per-target mover lanes (§129 census item b). Two things are being
//! pinned here: the LANE KEY (two roots on one volume are one lane, and
//! anything unresolvable is one lane) and the lane MACHINERY (different
//! keys run side by side, one key stays FIFO, a busy job blocks nobody,
//! the fleet cap holds, one pacing bucket serves them all).
//!
//! A genuinely different device is not constructible portably, so the
//! machinery tests hand `Lanes::dispatch` the keys directly - the piece
//! that maps a job to a key is covered by the key tests above them, and
//! the dispatcher joins the two in one line. There are no wall-clock
//! overlap assertions: concurrency is asserted structurally (lane
//! count, moves in flight at the `moving` fence, completion order),
//! which is the one shape of this test that cannot flake. The
//! before/after numbers live in `mover_lane_bench` at the bottom,
//! ignored because they need two real volumes.
//!
//! The ASSERTIONS were the only half that sentence ever covered, and
//! for a while this file read as though it covered the WAITS too. It
//! did not: every wait below was an absolute `Duration::from_secs`
//! deadline, and three of these tests failed together on a loaded box
//! (`cargo test -p nzbfast --bin nzbfast`, 31 Aug 2026 - 3 failed at
//! load ~40, 0 at ~27, all passing in isolation) reporting a job that
//! had simply not finished yet as a wrong ANSWER. What replaced them
//! is [`NO_PROGRESS`] and the [`settle_all`] family; the mechanism,
//! and why a per-STEP budget is the only one that can be sized here,
//! is written up there.

use super::*;
use crate::serve::job::{JobState, job_from_json};
use crate::serve::testutil::test_daemon;
use serde_json::json;
use std::time::Duration;

/// The move delay is a process-global, so the tests that use it take
/// turns. Held for the whole body - across awaits, hence the async
/// mutex - and released, with the delay cleared, by `DelayGuard` even
/// on a panic.
static MOVE_DELAY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct DelayGuard;

impl DelayGuard {
    fn set(ms: u64) -> Self {
        TEST_MOVE_DELAY_MS.store(ms, Ordering::Relaxed);
        Self
    }
}

impl Drop for DelayGuard {
    fn drop(&mut self) {
        TEST_MOVE_DELAY_MS.store(0, Ordering::Relaxed);
    }
}

fn scratch(tag: &str) -> crate::testscratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-lane-{tag}-{}", std::process::id()));
    crate::testscratch::ScratchDir::attach(&dir)
}

/// A parked Completed job with a payload on disk and its move owed.
fn pending_job(d: &Arc<Daemon>, name: &str, cat: &str) -> Arc<Mutex<Job>> {
    pending_job_of(d, name, cat, b"bytes".len())
}

/// [`pending_job`] with a payload of a chosen size - the bench needs
/// one big enough for a paced copy to take real time.
fn pending_job_of(d: &Arc<Daemon>, name: &str, cat: &str, bytes: usize) -> Arc<Mutex<Job>> {
    let job_dir = d.out_dir().join(name);
    std::fs::create_dir_all(&job_dir).unwrap();
    std::fs::write(job_dir.join("payload.bin"), vec![b'x'; bytes]).unwrap();
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": format!("SABnzbd_nzo_{name}"),
            "name": name,
            "nzb_path": d.out_dir().join(format!("{name}.nzb")).to_string_lossy(),
            "out_dir": job_dir.to_string_lossy(),
            "state": "Completed",
            "category": cat,
            "move_pending": true,
        }))
        .unwrap(),
    ));
    assert_eq!(job.lock_ok().state, JobState::Completed);
    d.history.lock_ok().push(job.clone());
    job
}

/// How long a wait here tolerates the mover settling NOTHING at all.
///
/// A NO-PROGRESS GAP, deliberately, and never a total - which is the
/// whole of what these waits get wrong when they are written as
/// `Instant::now() + Duration::from_secs(20)`. The cost of one move is
/// not the mover's own work (a 150 ms test delay and a rename); it is
/// that work PLUS an unbounded queue behind `Daemon::hold_queue_writes`,
/// a PROCESS-GLOBAL mutex every `save_queue` takes and every one of the
/// ~2,650 tests in `cargo test -p nzbfast --bin nzbfast` shares. Two of
/// its holders (`altcand`'s park transaction, `editqueue_delete`'s
/// custody transaction) do filesystem work under it. So the wait a
/// single move must absorb is set by what the REST of the binary is
/// doing, and no total is sizeable from in here.
///
/// Measured 31 Aug 2026 on the 32-core dev Mac, one process, the lock
/// instrumented: 143-208 waits over 200 ms per sweep, the longest 978
/// ms - and that is under CPU load alone, with none of the disk
/// contention the failing runs had. Which is also why the three that
/// failed together were exactly the three whose moves run SERIALLY in
/// one lane (FIFO, the busy job's lane-mate, the dispatcher's two jobs
/// on one device): a serial chain pays that queue once per move, in
/// series, where `two_lanes_...` and `the_cap_...` pay it in parallel
/// and so need one much worse outlier rather than N ordinary ones.
///
/// EXPOSED LATER IS NOT EXEMPT, and it is worth knowing which way that
/// cuts before trusting a green here.
/// `two_lanes_run_side_by_side_and_both_jobs_land` was measured flaky
/// 2/2 the day before, 30 Aug 2026, under heavier contention still -
/// 383 daemon processes and eighteen build trees - and left unclaimed,
/// by one lane; a second lane then claimed this file under a different
/// spelling 51 seconds before the claim this work landed under. Two
/// lanes, two days, each thinking it had seen the module fail once.
/// Its two waits were one move each against 10 s, so it takes a single
/// step over ~10 s to break where FIFO takes three averaging over
/// ~6.7 s. Every wait in this file is on the budget below for that
/// reason, not just the three that were caught.
///
/// What that leaves bounded is one STEP. The number of steps is a
/// property of the test and not of the box, so a test that grows a
/// fourth job does not need this re-derived - the same argument
/// `crates/nzbfast/tests/e2e_wave5_cost/mod.rs` makes for its cost
/// rows, in the form a WAIT can take it.
///
/// 60 s is ~21x the slowest single settle seen under 6x CPU
/// oversubscription (2.84 s) and 30x the lane's own 2 s requeue period.
/// It is deliberately not sized tighter, because it is PAID ONCE - at
/// the stall, not per step - so a genuinely dead mover costs this much
/// in total and never N times it, and the trade against a false red on
/// main is not close.
///
/// AND IT STILL CANNOT COVER A STARVED BOX, which is worth knowing
/// before reading a trip here as a defect. Measured 31 Aug 2026 by the
/// lane that wrote up the `terminate-after = 600` ceiling
/// (`37bdf653f`): at load 130-160 with seventeen `cargo-nextest`
/// processes across worktrees, a test that runs in 3.3 s took SEVEN
/// MINUTES - 127x, state `U` at 0.0% CPU, 5.9 s of CPU for 7 minutes
/// elapsed. That is disk starvation, not a product hang, and no budget
/// a test can name survives it. So the reading rule is that commit's:
/// above ~load 100 a trip here is a statement about the MACHINE, run
/// `uptime` before believing it, and trust the failure KIND - a wrong
/// ORDER or a broken cap is real at any load, a no-progress trip under
/// contention is not.
///
/// THE NUMBER ITSELF NOW LIVES IN `serve::testutil`, and this block
/// stays the write-up. It moved there on 31 Aug 2026 when three more
/// waits in this binary were put on it - `serve::tests_api`'s redrive
/// settle and its drain-count settle, and
/// `serve::daemon::daemon_tests`'s picker spin - because it has already
/// been RE-MEASURED once, from 30 s to 60 s in `cea15ceed`, hours after
/// it was written. Four sites each spelling their own 60 is a fifth
/// measurement that moves one and leaves three, which is CLAUDE.md's
/// fourteenth gate's argument about a threshold in four copy-paste
/// sibling drivers. That entry also records which sites must NOT take
/// it, which is the half a grep gets wrong.
const NO_PROGRESS: Duration = crate::serve::testutil::NO_PROGRESS;

/// How often the waits below sample. Every assertion in this file that
/// reads `Daemon::moving` reads it on this tick, so it is also the
/// resolution of the `peak` observations - 30 samples per 150 ms move.
const TICK: Duration = Duration::from_millis(5);

/// Wait for every job in `jobs` to settle, sampling `each_tick` as it
/// goes. Answers the order they settled in, or `None` when the mover
/// went [`NO_PROGRESS`] without settling one more of them.
///
/// The clock is reset by PROGRESS - another job settling - so a box
/// that makes every step slow does not fail a test that is still
/// moving; only a mover that has stopped does.
async fn settle_all_watching(
    jobs: &[Arc<Mutex<Job>>],
    gap: Duration,
    mut each_tick: impl FnMut(),
) -> Option<Vec<usize>> {
    let mut order: Vec<usize> = Vec::new();
    let mut last_progress = Instant::now();
    while order.len() < jobs.len() {
        each_tick();
        let before = order.len();
        for (i, job) in jobs.iter().enumerate() {
            if !job.lock_ok().move_pending && !order.contains(&i) {
                order.push(i);
            }
        }
        if order.len() > before {
            last_progress = Instant::now();
            continue;
        }
        if last_progress.elapsed() >= gap {
            return None;
        }
        tokio::time::sleep(TICK).await;
    }
    Some(order)
}

/// [`settle_all_watching`] with nothing to sample.
async fn settle_all(jobs: &[Arc<Mutex<Job>>]) -> Option<Vec<usize>> {
    settle_all_watching(jobs, NO_PROGRESS, || {}).await
}

/// One job's move. Returns false only when the mover made no progress
/// for [`NO_PROGRESS`], so the caller can say what it was waiting for -
/// and so a give-up is never reported as a wrong answer.
async fn settled(job: &Arc<Mutex<Job>>) -> bool {
    settle_all(std::slice::from_ref(job)).await.is_some()
}

/// [`settled`] against a budget the CALLER can size, which only
/// `mover_lane_bench` can: its copies are real bytes against a fixed
/// cap, so `bytes / cap` is a number, where a machinery test's move is
/// a rename plus however long the rest of the binary holds the global
/// queue-write lock. Same helper, and the difference between the two
/// budgets is the whole of [`NO_PROGRESS`]'s argument.
async fn settled_within(job: &Arc<Mutex<Job>>, gap: Duration) -> bool {
    settle_all_watching(std::slice::from_ref(job), gap, || {})
        .await
        .is_some()
}

/// Two roots on ONE volume are one lane, whether they sit side by side
/// or one inside the other. The nested pair is the case a path key got
/// wrong: a global root and a category root under it are the same NAS,
/// and splitting them would point two bulk copies at one device.
#[test]
fn lane_key_pins_two_roots_on_one_volume_to_one_lane() {
    let dir = scratch("key-onevol");
    let global = dir.join("done");
    let nested = global.join("tv");
    let sibling = dir.join("other");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::create_dir_all(&sibling).unwrap();

    assert_eq!(lane_key(&global), lane_key(&nested));
    assert_eq!(lane_key(&global), lane_key(&sibling));
    assert!(!lane_key(&global).is_empty(), "a real root must resolve");
    // A root that does not exist yet - the first move creates it - keys
    // off the deepest ancestor that does, so it lands on the volume it
    // is about to be created on.
    assert_eq!(
        lane_key(&global),
        lane_key(&dir.join("not-yet").join("deep"))
    );
}

/// Unresolvable root = the single shared lane. Falling back to serial
/// is always correct; a wrong split is not.
#[test]
fn lane_key_falls_back_to_the_shared_lane() {
    assert_eq!(lane_key(Path::new("")), "");
}

/// The lane key and the move must read the SAME root, or a lane is
/// keyed off a device the copy never touches.
#[test]
fn lane_key_for_reads_the_root_the_move_will_use() {
    let dir = scratch("key-root");
    let d = test_daemon(&dir);
    // Feature off: no destination, no lane of its own.
    assert_eq!(d.move_dest_root(""), None);
    assert!(!d.move_destination_configured("tv"));
    assert_eq!(lane_key_for(&d, "tv"), "");

    let global = dir.join("nas").join("done");
    let tv = dir.join("nas").join("series");
    std::fs::create_dir_all(&global).unwrap();
    std::fs::create_dir_all(&tv).unwrap();
    *d.move_completed.write_ok() = Some(global.clone());
    d.move_completed_cats
        .write_ok()
        .push(("tv".to_string(), tv.clone()));

    assert_eq!(d.move_dest_root(""), Some((global.clone(), false)));
    assert_eq!(
        d.move_dest_root("tv"),
        Some((tv.clone(), true)),
        "a category override IS that category's root"
    );
    assert!(d.move_destination_configured("movies"));
    // Both roots live on this machine's one volume, so both jobs share
    // one lane - which is the guarantee, not a limitation.
    assert_eq!(lane_key_for(&d, "tv"), lane_key(&tv));
    assert_eq!(lane_key_for(&d, "movies"), lane_key(&global));
}

/// Two keys, two lanes, both payloads land where their own destination
/// says. The lane count is the structural half of "they do not queue
/// behind each other".
#[tokio::test(flavor = "multi_thread")]
async fn two_lanes_run_side_by_side_and_both_jobs_land() {
    let dir = scratch("two-lanes");
    let d = test_daemon(&dir);
    let global = dir.join("nas-a");
    let tv = dir.join("nas-b");
    *d.move_completed.write_ok() = Some(global.clone());
    d.move_completed_cats
        .write_ok()
        .push(("tv".to_string(), tv.clone()));
    let a = pending_job(&d, "Film.Release", "");
    let b = pending_job(&d, "Show.S01E01", "tv");

    let mut lanes = Lanes::new();
    lanes.dispatch(&d, "dev:a".to_string(), a.clone());
    lanes.dispatch(&d, "dev:b".to_string(), b.clone());
    assert_eq!(lanes.len(), 2, "two destinations must get two lanes");

    assert!(settled(&a).await, "lane a stalled");
    assert!(settled(&b).await, "lane b stalled");
    assert_eq!(a.lock_ok().out_dir, global.join("Film.Release"));
    assert_eq!(b.lock_ok().out_dir, tv.join("Show.S01E01"));
    assert!(global.join("Film.Release").join("payload.bin").exists());
    assert!(tv.join("Show.S01E01").join("payload.bin").exists());
}

/// One lane is one destination, and one destination is still strictly
/// serial and FIFO - the invariant every review pass should try to
/// break. Observed by giving each move a visible width and recording
/// the order the moves settle in.
#[tokio::test(flavor = "multi_thread")]
async fn one_lane_moves_in_enqueue_order() {
    let _turn = MOVE_DELAY_LOCK.lock().await;
    let _delay = DelayGuard::set(150);
    let dir = scratch("fifo");
    let d = test_daemon(&dir);
    let nas = dir.join("nas");
    *d.move_completed.write_ok() = Some(nas.clone());
    let jobs: Vec<_> = (0..3)
        .map(|i| pending_job(&d, &format!("Release.{i}"), ""))
        .collect();

    let mut lanes = Lanes::new();
    for job in &jobs {
        lanes.dispatch(&d, "dev:one".to_string(), job.clone());
    }
    assert_eq!(lanes.len(), 1, "one destination is one lane");

    let mut peak = 0;
    // Serial is the other half of FIFO, and the half a settle order
    // alone cannot see: two moves running at once would settle in one
    // poll tick and still read as ordered.
    let order = settle_all_watching(&jobs, NO_PROGRESS, || {
        peak = peak.max(d.moving.lock_ok().len())
    })
    .await;
    // Reported as the STALL it is. Falling through to the order
    // assertion with a short vector was how a job that had not
    // finished yet came out as `left: [0, 1] right: [0, 1, 2]` - a
    // wrong-ORDER verdict on a lane that had ordered nothing wrongly.
    let order = order.expect("a lane stopped moving: no job settled for the no-progress budget");
    // `peak` is a floor - sampling can only ever under-count - so the
    // equality is doing two jobs: no two moves at once, AND the
    // sampler saw a move at all. It gets ~30 samples per 150 ms move
    // and the wait above no longer gives up early, so an under-count
    // needs the poller descheduled across all three.
    assert_eq!(peak, 1, "one lane must never run two moves at once");
    assert_eq!(
        order,
        vec![0, 1, 2],
        "one lane must settle in enqueue order"
    );
    for (i, job) in jobs.iter().enumerate() {
        assert_eq!(job.lock_ok().out_dir, nas.join(format!("Release.{i}")));
    }
}

/// A job whose files another actor holds (the `moving` fence: a
/// recategorize mid-flight) is paused and sent to the back of its own
/// lane. It must hold up neither the job behind it nor the other lane -
/// and it must still move once the fence comes down.
#[tokio::test(flavor = "multi_thread")]
async fn a_busy_job_blocks_neither_its_lane_nor_the_other() {
    let dir = scratch("busy");
    let d = test_daemon(&dir);
    let nas = dir.join("nas");
    *d.move_completed.write_ok() = Some(nas.clone());
    let held = pending_job(&d, "Held.Release", "");
    let behind = pending_job(&d, "Behind.Release", "");
    let other = pending_job(&d, "Other.Release", "");
    let held_id = held.lock_ok().nzo_id.clone();
    // Another actor owns the payload right now.
    assert!(d.moving.lock_ok().insert(held_id.clone()));

    let mut lanes = Lanes::new();
    lanes.dispatch(&d, "dev:a".to_string(), held.clone());
    lanes.dispatch(&d, "dev:a".to_string(), behind.clone());
    lanes.dispatch(&d, "dev:b".to_string(), other.clone());

    assert!(
        settle_all(&[behind.clone(), other.clone()]).await.is_some(),
        "the job behind a busy one, and the other lane, must not wait for it"
    );
    assert!(
        held.lock_ok().move_pending,
        "the held job still owes its move"
    );

    d.moving.lock_ok().remove(&held_id);
    assert!(
        settled(&held).await,
        "a busy job must move once the fence comes down"
    );
    assert!(nas.join("Held.Release").join("payload.bin").exists());
}

/// Lanes free the DESTINATIONS from each other, but they all read one
/// source volume and share one blocking pool, so the fleet is capped.
/// Counted at the `moving` fence - one entry per move actually running
/// - rather than off the semaphore that enforces it, so the assertion
/// does not just re-read its own mechanism. Sampling, not clocks: an
/// under-count cannot fail this test, only an over-count can.
#[tokio::test(flavor = "multi_thread")]
async fn the_cap_bounds_moves_in_flight_across_lanes() {
    let _turn = MOVE_DELAY_LOCK.lock().await;
    let _delay = DelayGuard::set(400);
    let dir = scratch("cap");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let jobs: Vec<_> = (0..5)
        .map(|i| pending_job(&d, &format!("Capped.{i}"), ""))
        .collect();

    let mut lanes = Lanes::new();
    for (i, job) in jobs.iter().enumerate() {
        lanes.dispatch(&d, format!("dev:{i}"), job.clone());
    }
    assert_eq!(lanes.len(), 5);

    let mut peak = 0;
    let landed = settle_all_watching(&jobs, NO_PROGRESS, || {
        peak = peak.max(d.moving.lock_ok().len())
    })
    .await;
    assert!(
        peak <= MOVER_MAX_CONCURRENT,
        "{peak} moves in flight breaks the cap of {MOVER_MAX_CONCURRENT}"
    );
    assert!(peak >= 2, "five lanes must overlap at all: peak was {peak}");
    assert!(
        landed.is_some(),
        "every capped move must land: the mover settled nothing for the \
         no-progress budget"
    );
}

/// The dispatcher end of it: the boot rescan's shape - jobs enqueued on
/// `mover_q` with their moves owed, `spawn_mover` started after them -
/// still moves everything, across two configured destinations.
#[tokio::test(flavor = "multi_thread")]
async fn the_dispatcher_drains_the_queue_into_lanes() {
    let dir = scratch("dispatch");
    let d = test_daemon(&dir);
    let global = dir.join("nas-a");
    let tv = dir.join("nas-b");
    *d.move_completed.write_ok() = Some(global.clone());
    d.move_completed_cats
        .write_ok()
        .push(("tv".to_string(), tv.clone()));
    let a = pending_job(&d, "Film.Replay", "");
    let b = pending_job(&d, "Show.S02E02", "tv");
    d.mover_enqueue(&a);
    d.mover_enqueue(&b);

    spawn_mover(&d);

    assert!(settled(&a).await, "replay of a");
    assert!(settled(&b).await, "replay of b");
    assert!(global.join("Film.Replay").join("payload.bin").exists());
    assert!(tv.join("Show.S02E02").join("payload.bin").exists());
}

/// The pacer's bucket belongs to the DAEMON, not to the call. Two
/// pacers handed out separately must charge one budget - per-call state
/// would have given every lane the full yield-mode ceiling.
#[test]
fn concurrent_pacers_share_one_bucket() {
    let dir = scratch("pacer");
    let d = test_daemon(&dir);
    // A fixed 1 MB/s cap: three modes, and this is the one that does
    // not depend on a live download rate.
    *d.move_pace.lock_ok() = "1".to_string();
    assert_eq!(d.mover_budget_bps(0), Some(1_000_000));

    // The bucket's WINDOW is reset immediately before each call, and
    // that is load-bearing rather than tidiness. `mover_pacer` rolls
    // the window and zeroes `sent` once 2 s have passed since it was
    // last rolled (mover.rs) - correct production behaviour, so a
    // caller does not pay one debt twice. The window here is born at
    // `PaceState::default()`, i.e. inside `test_daemon`, so on a loaded
    // box a slow construction - or a descheduled gap between these two
    // calls - silently zeroed the counter the assertions below read
    // (`left: 0, right: 65536`, 3 of 3 stress runs, 24 Aug 2026).
    // Resetting the window touches nothing the test is about: `sent` is
    // left alone, so the accumulation being asserted is unchanged.
    let chunk = 64 * 1024;
    d.mover_bucket.lock_ok().window = Instant::now();
    mover_pacer(&d)(chunk);
    assert_eq!(d.mover_bucket.lock_ok().sent, chunk);
    // A SECOND pacer, handed out separately, adds to the same bucket.
    d.mover_bucket.lock_ok().window = Instant::now();
    mover_pacer(&d)(chunk);
    assert_eq!(
        d.mover_bucket.lock_ok().sent,
        2 * chunk,
        "two pacers must charge one bucket"
    );

    // And the sharing is what the clock sees: 1.31 MB of chunks split
    // across two threads costs ~1.3 s against one 1 MB/s budget, where
    // a bucket each would have cost ~0.65 s. Asserted as a FLOOR with
    // room to spare - a slow machine only ever makes this longer.
    {
        let mut g = d.mover_bucket.lock_ok();
        g.sent = 0;
        g.window = Instant::now();
    }
    let started = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..2 {
            s.spawn(|| {
                let pace = mover_pacer(&d);
                for _ in 0..10 {
                    pace(chunk);
                }
            });
        }
    });
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1000),
        "two concurrent movers must divide one budget, not take it each: {elapsed:?}"
    );
}

/// The measurement behind this change: a small move to one volume,
/// enqueued behind a large paced move to another. Serial, that small
/// move waits out the large one; with lanes it does not.
///
/// It needs two roots on two genuinely DIFFERENT devices, which no CI
/// box has - hence ignored, and hence the env vars. Two attached disk
/// images make them on macOS:
///
/// ```text
/// hdiutil create -size 700m -fs APFS -volname LANEA -quiet a.dmg
/// hdiutil create -size 200m -fs APFS -volname LANEB -quiet b.dmg
/// hdiutil attach a.dmg -quiet && hdiutil attach b.dmg -quiet
/// NZBFAST_LANE_BENCH_A=/Volumes/LANEA NZBFAST_LANE_BENCH_B=/Volumes/LANEB \
///   cargo test -p nzbfast --bin nzbfast mover_lane_bench -- --ignored --nocapture
/// ```
///
/// This is also the only place a genuinely different device exercises
/// the lane key, so it asserts the two roots key apart.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn mover_lane_bench() {
    let (Ok(root_a), Ok(root_b)) = (
        std::env::var("NZBFAST_LANE_BENCH_A"),
        std::env::var("NZBFAST_LANE_BENCH_B"),
    ) else {
        panic!("set NZBFAST_LANE_BENCH_A and _B to roots on two different volumes");
    };
    const BIG_MB: usize = 200;
    const SMALL_MB: usize = 4;
    // A fixed cap, so the copy takes a knowable time rather than
    // whatever the two images feel like today.
    const CAP_MB_S: &str = "20";

    // (label, one lane for both jobs?) - the serial leg first, so the
    // page cache is no kinder to it than to the lane leg.
    let mut results: Vec<(&str, Duration, Duration)> = Vec::new();
    for (label, one_lane) in [("serial (one lane)", true), ("lanes", false)] {
        let dir = scratch("bench");
        let d = test_daemon(&dir);
        let big_root = PathBuf::from(&root_a).join("bench-big");
        let small_root = PathBuf::from(&root_b).join("bench-small");
        let _ = std::fs::remove_dir_all(&big_root);
        let _ = std::fs::remove_dir_all(&small_root);
        *d.move_completed.write_ok() = Some(big_root.clone());
        d.move_completed_cats
            .write_ok()
            .push(("small".to_string(), small_root.clone()));
        *d.move_pace.lock_ok() = CAP_MB_S.to_string();
        let big = pending_job_of(&d, "Big.Release", "", BIG_MB << 20);
        let small = pending_job_of(&d, "Small.Release", "small", SMALL_MB << 20);

        let key_big = lane_key_for(&d, "");
        let key_small = lane_key_for(&d, "small");
        assert_ne!(
            key_big, key_small,
            "two volumes must key apart or there is nothing to measure"
        );
        let mut lanes = Lanes::new();
        let started = Instant::now();
        lanes.dispatch(&d, key_big.clone(), big.clone());
        lanes.dispatch(
            &d,
            if one_lane { key_big } else { key_small },
            small.clone(),
        );
        assert_eq!(lanes.len(), if one_lane { 1 } else { 2 });

        assert!(settled_within(&small, Duration::from_secs(600)).await);
        let small_at = started.elapsed();
        assert!(settled_within(&big, Duration::from_secs(600)).await);
        let both_at = started.elapsed();
        println!(
            "[bench] {label}: small ({SMALL_MB} MB) landed at {:.2?}, both ({BIG_MB} MB + \
             {SMALL_MB} MB, cap {CAP_MB_S} MB/s) at {:.2?}",
            small_at, both_at
        );
        results.push((label, small_at, both_at));
        let _ = std::fs::remove_dir_all(&big_root);
        let _ = std::fs::remove_dir_all(&small_root);
    }
    let (serial, lanes) = (results[0], results[1]);
    println!(
        "[bench] the small move stopped waiting: {:.2?} -> {:.2?}",
        serial.1, lanes.1
    );
    assert!(
        lanes.1 < serial.1,
        "the whole point is that the small move stops waiting"
    );
    println!(
        "[bench] the pair still costs the same: {:.2?} -> {:.2?}",
        serial.2, lanes.2
    );

    // Third leg: the budget half. Two copies of the SAME size, one per
    // volume, both running. Sharing one bucket they cost the pair's
    // bytes at the cap; a bucket each would have cost half that, which
    // is the "never slow a live download" promise breaking by exactly
    // the number of lanes.
    const EACH_MB: usize = 80;
    let dir = scratch("bench-budget");
    let d = test_daemon(&dir);
    let root_one = PathBuf::from(&root_a).join("bench-one");
    let root_two = PathBuf::from(&root_b).join("bench-two");
    let _ = std::fs::remove_dir_all(&root_one);
    let _ = std::fs::remove_dir_all(&root_two);
    *d.move_completed.write_ok() = Some(root_one.clone());
    d.move_completed_cats
        .write_ok()
        .push(("two".to_string(), root_two.clone()));
    *d.move_pace.lock_ok() = CAP_MB_S.to_string();
    let one = pending_job_of(&d, "Even.One", "", EACH_MB << 20);
    let two = pending_job_of(&d, "Even.Two", "two", EACH_MB << 20);
    let mut lanes = Lanes::new();
    let started = Instant::now();
    lanes.dispatch(&d, lane_key_for(&d, ""), one.clone());
    lanes.dispatch(&d, lane_key_for(&d, "two"), two.clone());
    assert_eq!(lanes.len(), 2);
    assert!(settled_within(&one, Duration::from_secs(600)).await);
    assert!(settled_within(&two, Duration::from_secs(600)).await);
    let paired = started.elapsed();
    let ideal = Duration::from_secs_f64((2 * EACH_MB) as f64 / CAP_MB_S.parse::<f64>().unwrap());
    println!(
        "[bench] two {EACH_MB} MB copies on two lanes, cap {CAP_MB_S} MB/s: {:.2?} \
         (one shared budget = {:.2?}, a bucket each = {:.2?})",
        paired,
        ideal,
        ideal / 2
    );
    assert!(
        paired > ideal.mul_f64(0.8),
        "two lanes took {paired:?} for what one budget prices at {ideal:?} - each took the cap whole"
    );
    let _ = std::fs::remove_dir_all(&root_one);
    let _ = std::fs::remove_dir_all(&root_two);
}
