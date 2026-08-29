//! BufPool gauge accounting and the PooledBuf guard.
//!
//! `BufPool::new_gauged` had no test of any kind before 26 Aug 2026, and
//! its charge/release pairing is the whole reason a missed give is worse
//! than a lost recycle: a lost recycle costs one allocation, a lost
//! release climbs the outstanding gauge for the rest of the run and the
//! memory floor reads it as resident bytes nobody can attribute. These
//! pin the accounting, and the last one pins what the guard buys.
//!
//! Every one of these takes `one_gauge_test_at_a_time()` as its FIRST
//! statement, so it drops LAST: `memgauge`'s `CUR`/`PEAK` are process-
//! global, so under `cargo test` (and the `unit-one-process` job) a
//! neighbour moving the same gauge would be read as this test's own
//! charge. It is the same lock `memgauge`'s own tests take - one of our
//! own would serialize us against nobody.
//!
//! A child of `unit_tests`, out here for the size gate (TODO 106), the
//! same move `next_work_tests` made on 22 Aug 2026 and for the same
//! reason: on 27 Aug the parent went 16 lines OVER the 3,000-line file
//! ceiling when `capacity_bounce_parks_the_extras_and_the_run_finishes`
//! grew the barrier that forces the extra dials it had only asserted.
//! This block is the cleanest seam in the file - it is the only group
//! that is about `bufpool` rather than about the pool's own state
//! machine, and it already carried its own import. The module is named
//! for its file so size-gate.py's CFG_TEST_MOD resolver still reads it
//! as test code, and `use super::*` brings the parent's imports along.

use super::*;

use crate::memgauge::{Sub, cur, one_gauge_test_at_a_time, reset_for_tests};

#[test]
fn a_gauged_take_charges_outstanding_and_only_a_pooled_buffer_leaves_the_free_list() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    let pool = BufPool::new_gauged(4, Sub::RawFree, Sub::RawOut);

    // A fresh buffer was never on the free list, so only outstanding moves.
    let a = pool.take();
    let cap = a.capacity() as u64;
    assert_eq!(cur(Sub::RawOut), cap);
    assert_eq!(cur(Sub::RawFree), 0);

    // Back to the pool: the charge moves from outstanding to the free list.
    drop(a);
    assert_eq!(cur(Sub::RawOut), 0);
    assert_eq!(cur(Sub::RawFree), cap);

    // A POPPED buffer leaves the free list as it becomes outstanding.
    let b = pool.take();
    assert_eq!(cur(Sub::RawOut), cap);
    assert_eq!(cur(Sub::RawFree), 0);
    drop(b);
}

#[test]
fn a_gauged_give_releases_outstanding_before_every_early_return() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    // max_held 1, so the second give has nowhere to park.
    let pool = BufPool::new_gauged(1, Sub::OutFree, Sub::OutOut);

    // Over the keep-cap: `give` returns early WITHOUT parking, and the
    // outstanding release has to have happened before that return.
    let mut big = pool.take();
    big.reserve(5 * 1024 * 1024);
    assert!(big.capacity() > 4 * 1024 * 1024);
    drop(big);
    assert_eq!(
        cur(Sub::OutOut),
        0,
        "the oversized early return must not skip the outstanding release"
    );
    assert_eq!(
        cur(Sub::OutFree),
        0,
        "an oversized buffer is freed, never parked, so the free list is untouched"
    );

    // Past max_held: released from outstanding, not added to the free list.
    let x = pool.take();
    let y = pool.take();
    let xc = x.capacity() as u64;
    drop(x);
    assert_eq!(cur(Sub::OutFree), xc);
    drop(y);
    assert_eq!(
        cur(Sub::OutOut),
        0,
        "a surplus give releases outstanding even though the buffer is dropped"
    );
    assert_eq!(
        cur(Sub::OutFree),
        xc,
        "the surplus buffer was dropped, so the free list did not grow"
    );
}

#[test]
fn a_dying_gauged_pool_hands_back_its_whole_free_list() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    let pool = BufPool::new_gauged(4, Sub::RawFree, Sub::RawOut);
    let a = pool.take();
    let b = pool.take();
    let held = a.capacity() as u64 + b.capacity() as u64;
    drop(a);
    drop(b);
    assert_eq!(cur(Sub::RawFree), held);
    drop(pool);
    assert_eq!(
        cur(Sub::RawFree),
        0,
        "a job's pool dies with its free list - without this the gauge \
         carries the dead pool's bytes into the next job forever"
    );
}

#[test]
fn an_ungauged_pool_charges_nothing() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    let pool = BufPool::new(2);
    drop(pool.take());
    let snap = crate::memgauge::snapshot();
    for s in [Sub::RawFree, Sub::RawOut, Sub::OutFree, Sub::OutOut] {
        assert_eq!(snap.cur_of(s), 0, "{} moved on an ungauged pool", s.name());
    }
}

#[test]
fn a_guarded_buffer_comes_back_from_an_early_return_and_a_panic() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    let pool = BufPool::new_gauged(4, Sub::RawFree, Sub::RawOut);
    let cap = {
        let b = pool.take();
        b.capacity() as u64
    };

    // The shape the bare take/give pair could not defend: a consumer
    // that leaves between the two halves. `?` on a fresh buffer.
    fn early_return(pool: &BufPool) -> Result<(), ()> {
        let _b = pool.take();
        Err(())
    }
    assert!(early_return(&pool).is_err());
    assert_eq!(cur(Sub::RawOut), 0, "an early return returns the buffer");
    assert_eq!(cur(Sub::RawFree), cap);

    // And an unwind, which no amount of remembering can cover.
    let hit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _b = pool.take();
        panic!("consumer blew up mid-article");
    }));
    assert!(hit.is_err());
    assert_eq!(cur(Sub::RawOut), 0, "an unwind returns the buffer");
    assert_eq!(cur(Sub::RawFree), cap);
}

#[test]
fn into_vec_disarms_the_guard_and_adopt_re_arms_it() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    let pool = BufPool::new_gauged(4, Sub::RawFree, Sub::RawOut);
    let b = pool.take();
    let cap = b.capacity() as u64;

    // Handing the bytes down the outcome channel: the guard stops
    // guarding, and the outstanding charge travels WITH the buffer.
    let raw = b.into_vec();
    assert_eq!(cur(Sub::RawOut), cap, "the charge follows the bytes");
    assert_eq!(cur(Sub::RawFree), 0);

    // The far end re-guards it. `adopt` charges nothing - these bytes
    // were charged by the `take` that minted them - and its drop is the
    // one matching release.
    let readopted = pool.adopt(raw);
    assert_eq!(cur(Sub::RawOut), cap, "adopt must not double-charge");
    drop(readopted);
    assert_eq!(cur(Sub::RawOut), 0);
    assert_eq!(cur(Sub::RawFree), cap);
}
