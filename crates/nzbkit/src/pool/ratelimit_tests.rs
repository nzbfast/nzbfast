//! Rate-limit and connection-target unit tests, moved out of pool.rs's
//! inline `tests` mod to keep the file inside its size-gate baseline.
//! Self-contained: none of these touch the inline mod's own helpers.

use super::*;

#[tokio::test]
async fn rate_limit_paces_charges() {
    // 1 MB charged in 100 KB chunks at 10 MB/s ≈ 100 ms. Generous
    // bounds only - CI machines wobble.
    let rl = RateLimit::new(10_000_000);
    let t0 = Instant::now();
    for _ in 0..10 {
        rl.throttle(100_000).await;
    }
    let el = t0.elapsed();
    assert!(el >= Duration::from_millis(60), "too fast: {el:?}");
    assert!(el <= Duration::from_secs(2), "too slow: {el:?}");
}

/// The shipped-default bug: with the old byte-window the per-call
/// sleep was clamped to 5 s and the debt was never forgiven, so the
/// aggregate could not be held below `connections * article / 5 s` -
/// ~1.28 MB/s at 8 connections, i.e. every cap under ~10 Mbit/s was
/// silently exceeded.
///
/// Necessarily slower than a unit test wants: the clamp is 5 s of
/// WALL time, so nothing under that can observe it. 8 workers x
/// 150 KB at 150 KB/s owes 8 s; the old code answered in ~5.
#[tokio::test]
async fn rate_limit_holds_a_cap_below_the_old_clamp_floor() {
    const CAP: u64 = 150_000;
    const WORKERS: u64 = 8;
    let rl = RateLimit::new(CAP);
    let t0 = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..WORKERS {
        let rl = rl.clone();
        set.spawn(async move { rl.throttle(CAP).await });
    }
    while set.join_next().await.is_some() {}
    let el = t0.elapsed();
    // Owed is WORKERS seconds (each charges exactly one second's
    // worth). Generous lower bound: anything near 5 s is the clamp.
    assert!(
        el >= Duration::from_secs_f64(WORKERS as f64 * 0.8),
        "the cap was exceeded - {el:?} for {WORKERS}s of charged bytes"
    );
    assert!(
        el <= Duration::from_secs(WORKERS * 3),
        "far too slow: {el:?}"
    );
}

/// A live cap change must not leave a worker asleep against the old
/// one. The virtual clock prices each charge when it is charged, so a
/// decrease never re-prices old bytes; the generation bump is what
/// releases anyone already waiting.
#[tokio::test]
async fn a_live_cap_change_releases_a_sleeping_worker() {
    let rl = RateLimit::new(1_000); // 1 KB/s: 100 KB owes 100 s
    let t0 = Instant::now();
    let waiter = {
        let rl = rl.clone();
        tokio::spawn(async move { rl.throttle(100_000).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    rl.set(0); // the user removed the limit
    waiter.await.unwrap();
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "stranded against the old cap"
    );
}

#[tokio::test]
async fn rate_limit_zero_is_unlimited() {
    let rl = RateLimit::new(0);
    let t0 = Instant::now();
    for _ in 0..100 {
        rl.throttle(10_000_000).await;
    }
    assert!(t0.elapsed() < Duration::from_millis(100));
    // And a live set() takes effect.
    rl.set(1_000_000);
    assert_eq!(rl.get(), 1_000_000);
    let t0 = Instant::now();
    rl.throttle(300_000).await; // fresh window: ~300 ms owed
    assert!(t0.elapsed() >= Duration::from_millis(100));
}

/// Codex F-11 (22 Aug 2026): `throttle` used to load the cap and the
/// generation on the unlocked fast path and carry both into the locked
/// pricing. A worker parked in that gap while `set` swapped cap, reset
/// the clock and bumped the generation then reserved OLD-cap debt into
/// the FRESH clock: the worker itself escaped through the generation
/// check, but the poisoned horizon stayed, and every later charge
/// queued behind ~n/old_cap seconds of debt that no longer corresponded
/// to any configured limit. The fix re-reads cap and generation under
/// the `next` mutex, the same lock `set` swaps them under, so a price
/// and the clock it lands on are always the same cap's.
///
/// The seam is `reserve_barrier`, sitting exactly in the pre-fix gap.
#[test]
fn a_cap_swap_against_a_parked_worker_prices_at_the_new_cap() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    // 1 B/s: at the OLD price, the 50 MB below is ~50M seconds of debt.
    let rl = RateLimit::new(1);
    let entered = Arc::new(std::sync::Barrier::new(2));
    let released = Arc::new(std::sync::Barrier::new(2));
    *rl.reserve_barrier.lock_ok() = Some((entered.clone(), released.clone()));
    let worker = {
        let rl = rl.clone();
        rt.spawn(async move { rl.throttle(50_000_000).await })
    };
    entered.wait(); // the worker stands in the gap, price not yet fixed
    *rl.reserve_barrier.lock_ok() = None; // one trip only
    rl.set(1_000_000_000); // the user raises the cap: clock reset, generation bumped
    released.wait();
    rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), worker)
            .await
            .expect("worker stranded against the swapped-out cap")
            .unwrap();
    });
    // The reservation must be priced at the cap in force when it landed
    // on the clock: 50 MB at 1 GB/s is 50 ms, not 50M seconds.
    let debt = rl.debt_horizon().saturating_duration_since(Instant::now());
    assert!(
        debt < Duration::from_secs(30),
        "old-cap debt landed on the new clock: {debt:?} outstanding on a 1 GB/s limit"
    );
}

/// Codex F-24 (22 Aug 2026): the line cap's decide-and-set on a
/// [`ConnTarget`] used to be a bare read, rule, write - so the §112
/// live tuner could lower the same target between the read and the
/// write and have the cap's older, higher value clobber it back up.
/// `update` runs the closure under the watch channel's write lock, the
/// same lock `set` writes under, so the interleaving cannot exist.
///
/// The closure gives the racing `set` a 300 ms window on purpose: on
/// the fixed code the tuner blocks outside the lock for the whole
/// window and its lower target lands LAST; on the pre-fix shape it
/// lands inside the window and the stale write tramples it.
#[test]
fn a_lowered_target_survives_a_concurrent_stale_update() {
    let t = ConnTarget::new(10);
    let (in_tx, in_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let updater = {
        let t = t.clone();
        std::thread::spawn(move || {
            t.update(move |cur| {
                assert_eq!(cur, 10, "the update reads the target it decides over");
                in_tx.send(()).unwrap();
                let _ = done_rx.recv_timeout(Duration::from_millis(300));
                Some(8) // the line cap's share, derived from cur = 10
            })
        })
    };
    in_rx.recv().unwrap();
    let tuner = {
        let t = t.clone();
        std::thread::spawn(move || {
            t.set(4); // the live tuner lowering the same target
            done_tx.send(()).ok();
        })
    };
    assert!(
        updater.join().unwrap(),
        "the update itself still moves the target"
    );
    tuner.join().unwrap();
    assert_eq!(
        t.get(),
        4,
        "the cap's stale higher target overwrote the tuner's newer lower one"
    );
}

#[test]
fn conn_target_clamps_to_one() {
    // 0 would park the whole fleet with work pending - the
    // `connections: 0` hang, reached through the side door.
    let t = ConnTarget::new(0);
    assert_eq!(t.get(), 1);
    t.set(0);
    assert_eq!(t.get(), 1);
    t.set(5);
    assert_eq!(t.get(), 5);
}
