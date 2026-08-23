//! The run's terminal seal: how a pool that lost every worker still
//! emits exactly one outcome per article.
//!
//! Split out of pool/unit_tests.rs under the size gate (TODO 106) -
//! sealing is one subject, and the L10 leg below is the second test of
//! it. A child module of `pool`, so the private internals stay
//! reachable through `super::*`.

use super::unit_tests::{fresh, server};
use super::*;

#[test]
fn seal_run_blocking_fails_orphans_exactly_once() {
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    let (tx, mut rx) = mpsc::channel(8);
    // Live workers: not this path's job - the async seal owns it.
    sh.workers_live.store(1, Ordering::Release);
    assert_eq!(seal_run_blocking(&sh, &tx, "shards stopped"), 0);
    sh.workers_live.store(0, Ordering::Release);
    // A draining run keeps its queue intact for the resume.
    sh.draining.store(true, Ordering::Release);
    assert_eq!(seal_run_blocking(&sh, &tx, "shards stopped"), 0);
    sh.draining.store(false, Ordering::Release);
    // One orphan still queued, one stranded in flight: both must reach
    // a terminal Failed, and the pending count must reach zero.
    {
        let mut q = sh.queue.try_lock().unwrap();
        let w = q.pop_front().unwrap();
        drop(q);
        sh.register_inflight(&w, 0);
    }
    assert_eq!(seal_run_blocking(&sh, &tx, "all shard runtimes stopped"), 2);
    let mut failed = Vec::new();
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Failed { id, error } => {
                assert_eq!(error, "all shard runtimes stopped");
                failed.push(id);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    failed.sort();
    assert_eq!(failed, vec!["<a@x>".into(), "<b@x>".into()]);
    assert_eq!(sh.pending.load(Ordering::Acquire), 0);
    // Nothing left: the pending==0 early return, and no double report.
    assert_eq!(seal_run_blocking(&sh, &tx, "again"), 0);
}

/// Codex F-15 (22 Aug 2026): shard threads used to come up through bare
/// `std::thread::spawn`, which PANICS when the OS refuses a thread -
/// unwinding `fetch_all_sharded` mid-run, detaching whatever shards had
/// already started, and leaking the failed shard plan's pre-born lives
/// so no surviving shard could ever seal. `thread::Builder` returns the
/// refusal instead; the unspawned plan drops, its lives release exactly
/// as if the workers had died, and the blocking seal at the end of the
/// join owes every article its terminal outcome.
///
/// The refusal is injected (`SHARD_SPAWN_DENY`) - real thread
/// exhaustion is not something a unit test may inflict on the box. Both
/// halves of the fix are load-bearing here: a panic reddens this test
/// directly, and leaked lives would leave `workers_live` above zero, so
/// the seal would refuse and the outcome asserts fail.
#[test]
fn a_refused_shard_thread_is_survivable_and_every_article_still_seals() {
    SHARD_SPAWN_DENY.with(|d| d.set(u64::MAX)); // every shard this run asks for
    let cfg = PoolConfig {
        connections: 1,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let (tx, mut rx) = mpsc::channel(16);
    let stats = fetch_all_sharded(
        vec![(server("s"), cfg)],
        fresh(&["<a@x>", "<b@x>"]),
        tx,
        2,
        None,
    );
    SHARD_SPAWN_DENY.with(|d| d.set(0));
    assert_eq!(
        stats.len(),
        1,
        "the run returns its stats, it does not unwind"
    );
    let mut failed = Vec::new();
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Failed { id, error } => {
                assert_eq!(error, "all shard runtimes stopped");
                failed.push(id);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    failed.sort();
    assert_eq!(
        failed,
        vec!["<a@x>".into(), "<b@x>".into()],
        "every article gets exactly one terminal outcome despite zero spawned shards"
    );
}

/// Sweep 8, L10: a queue lock held by a control thread must DELAY the
/// terminal seal, never empty it.
///
/// The seal used to `try_lock` once and read a failure as "the queue is
/// empty". The caller drops the outcome channel on the next line, so
/// every id still queued got no terminal outcome at all - silently, and
/// against the one-outcome-per-id contract the run promises. The
/// trigger needs an OS/runtime resource failure (every shard runtime
/// failing to build) plus a control thread inside the lock, which is
/// what makes it a Low and not what makes it acceptable.
///
/// The guard is held from another thread and released after the seal
/// has certainly started, so the seal is forced through the contended
/// path rather than winning a race.
#[test]
fn a_contended_queue_lock_delays_the_seal_it_does_not_empty_it() {
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    let (tx, mut rx) = mpsc::channel(8);
    let held = std::sync::Arc::new(std::sync::Barrier::new(2));
    let holder = {
        let sh = sh.clone();
        let held = held.clone();
        std::thread::spawn(move || {
            let g = sh.queue.blocking_lock();
            held.wait();
            // TWICE the bound (SEAL_LOCK_TRIES x 10 ms): the seal meets
            // the lock, runs out its bound, complains once - and keeps
            // waiting (F-14) instead of sealing an empty queue. The old
            // margin of +300 ms was inside the bound's own sleep
            // overshoot (200 x 10 ms sleeps measure ~2.3 s on a loaded
            // box), so the pre-F-14 give-up could win the race and pass
            // this test; at 2x the bound the crossing is certain.
            std::thread::sleep(std::time::Duration::from_millis(
                u64::from(SEAL_LOCK_TRIES) * 10 * 2,
            ));
            drop(g);
        })
    };
    held.wait();
    assert_eq!(
        seal_run_blocking(&sh, &tx, "all shard runtimes stopped"),
        2,
        "both queued articles must still reach a terminal outcome"
    );
    holder.join().unwrap();

    let mut failed = Vec::new();
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Failed { id, .. } => failed.push(id),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    failed.sort();
    assert_eq!(failed, vec!["<a@x>".into(), "<b@x>".into()]);
    assert_eq!(sh.pending.load(Ordering::Acquire), 0);
}
