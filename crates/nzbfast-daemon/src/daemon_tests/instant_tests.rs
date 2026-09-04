//! §74's instant-arrival kick and the ordering it depends on, moved out
//! of daemon_tests.rs under the size gate (TODO 106). `use super::*`
//! carries `with_daemon` and everything daemon.rs's test module already
//! has in scope.

use super::*;

// -- instant kick -----------------------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn instant_kick_dedupes_hints_and_caps_from_the_front() {
    with_daemon("kickhint", |d| {
        // max 0 = unmetered, so this test is about the hint list alone.
        d.watchlist_instant_max.store(0, Ordering::Relaxed);
        assert!(!d.instant_kick(&[], 1000), "empty names never wake");

        let names: Vec<String> = vec!["a".into(), "b".into()];
        assert!(d.instant_kick(&names, 1000));
        let again: Vec<String> = vec!["b".into(), "c".into()];
        assert!(d.instant_kick(&again, 1001));
        assert_eq!(*d.instant_hint.lock_ok(), vec!["a", "b", "c"], "dedupe");

        d.instant_hint.lock_ok().clear();
        let flood: Vec<String> = (0..300).map(|i| format!("n{i}")).collect();
        assert!(d.instant_kick(&flood, 1002));
        let hint = d.instant_hint.lock_ok();
        assert_eq!(hint.len(), 256, "HINT_CAP");
        assert_eq!(hint[0], "n44", "drained from the front (oldest)");
        assert_eq!(hint[255], "n299");
    });
}

#[cfg(feature = "indexer")]
#[test]
fn instant_kick_rate_limit_refuses_without_touching_hints() {
    with_daemon("kicklimit", |d| {
        d.watchlist_instant_max.store(1, Ordering::Relaxed);
        let a: Vec<String> = vec!["a".into()];
        let b: Vec<String> = vec!["b".into()];
        assert!(d.instant_kick(&a, 5000));
        assert!(!d.instant_kick(&b, 5001), "allowance for the hour is spent");
        assert_eq!(*d.instant_hint.lock_ok(), vec!["a"], "refusal adds no hint");
        // A new hour restores the allowance.
        assert!(d.instant_kick(&b, 5000 + 3_600));
    });
}

/// §74, half one of the ordering: the hint is never staged EARLIER than
/// the republish.
///
/// Pinned as the DEFENSIVE ordering it is, not as a correctness claim.
/// §74 justified it with "a hint published ahead of the republish is
/// taken by a pass that then searches the stale snapshot and finds
/// nothing", and that story does not survive a read of `Index::ingest`:
/// it commits each of its passes internally and journals the watch hits
/// after the commit, so the rows are visible to every connection long
/// before either call here. See `nzbfast-scan-leg-swallows-arrivals`. The ordering costs nothing and
/// keeps the two halves in a defined sequence, so it stays pinned -
/// just do not reason from the old mechanism.
///
/// Holding `index` here stands in for a reader mid-`with_index`: while
/// it is held, NOTHING may have been staged. A thread that has not
/// reached the call yet also stages nothing, so the mid-test assert can
/// only ever fail late, never early - it cannot flake red. Half two,
/// which this one cannot see, is
/// `the_arrival_hint_is_staged_while_the_index_mutex_is_still_held`.
#[cfg(feature = "indexer")]
#[test]
fn the_arrival_hint_is_never_staged_before_the_republish() {
    with_daemon("kickatomic", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        d.watchlist_instant_max.store(0, Ordering::Relaxed);
        let era = d.index_era();
        let fresh = nzbkit::index::Index::open(&d.index_db).expect("open index");

        let held = d.index.lock_ok();
        let d2 = d.clone();
        let publisher = std::thread::spawn(move || {
            d2.publish_index_with_arrivals(era, fresh, &["Arriving.Release".to_string()], 1000)
        });
        // Long enough for the thread to get there if it could.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            d.instant_hint.lock_ok().is_empty(),
            "the hint was staged without the index mutex, ahead of the \
             republish - the intended sequence is the other way round"
        );
        drop(held);

        assert!(publisher.join().expect("publisher panicked"), "staged");
        assert_eq!(*d.instant_hint.lock_ok(), vec!["Arriving.Release"]);
        assert!(
            d.index.lock_ok().is_some(),
            "the same hold must have published the connection too"
        );
    });
}

/// §74, half two: the hint is never staged LATER than the republish
/// either - the two are ONE hold of the `index` mutex.
///
/// The bug this pins. `publish_index` then `instant_kick` left a window
/// where the arriving release was already visible to `watchlist_pass`
/// (which reads that same handle through `with_index`) while
/// `instant_hint` was still empty. A pass already in flight in that
/// window took an empty hint, grabbed the release anyway, and never
/// recorded it as an instant grab: the dashboard badge under-reported,
/// and the kick that followed spent one of the hour's six instant
/// passes waking a pass that found the slot already filled.
///
/// This test is the ONLY level the fix is observable at.
/// `watchlist_instant`'s scan-leg case passes either way once its own
/// setup pass is gone (2ed3470c), so do not reach for it as the oracle
/// here - it was measured green against two holds, one hold, and one
/// hold with 300 ms in front of it.
///
/// Narrowing, not closing: a pass can still grab the arrival before
/// either half runs, because the rows are committed inside
/// `Index::ingest`. What this pins is only that nothing can slip
/// BETWEEN the two. See `nzbfast-scan-leg-swallows-arrivals`.
///
/// Held the other way round to see it. This test takes `instant_hint`
/// and keeps it, so the publisher parks on the staging step - and the
/// question is whether it is still holding `index` while it waits. One
/// hold: it is, so `index` is locked and STAYS locked. Two holds: it
/// published, let `index` go, and only then reached for the hint, so
/// `index` is free the whole time and the poll below times out.
///
/// The second look 300 ms later is what makes the first meaningful:
/// under two holds `index` is also briefly locked, for the publish
/// itself, and a single try_lock could land on that microsecond.
#[cfg(feature = "indexer")]
#[test]
fn the_arrival_hint_is_staged_while_the_index_mutex_is_still_held() {
    with_daemon("kickheld", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        // Unmetered: this is about the lock, not the allowance. A
        // refusal returns before `instant_hint` is ever touched and the
        // publisher would never park at all.
        d.watchlist_instant_max.store(0, Ordering::Relaxed);
        let era = d.index_era();
        let fresh = nzbkit::index::Index::open(&d.index_db).expect("open index");

        let hint_held = d.instant_hint.lock_ok();
        let d2 = d.clone();
        let publisher = std::thread::spawn(move || {
            d2.publish_index_with_arrivals(era, fresh, &["Arriving.Release".to_string()], 1000)
        });

        // Generous, because a slow starter is the only thing that can
        // make this wait: once the publisher is parked on the hint, one
        // hold pins `index` until this test lets go of it.
        let mut pinned = false;
        for _ in 0..200 {
            if d.index.try_lock().is_err() {
                pinned = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(
            pinned,
            "the publisher reached the hint with `index` already released - \
             a pass can take the mutex in between and see the release with \
             no hint to explain it"
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            d.index.try_lock().is_err(),
            "`index` came free while the publisher was still staging - \
             the two are not one hold"
        );

        drop(hint_held);
        assert!(publisher.join().expect("publisher panicked"), "staged");
        assert_eq!(*d.instant_hint.lock_ok(), vec!["Arriving.Release"]);
    });
}

/// The other half of the ordering, which the hold above cannot show: a
/// refused kick (the hour's allowance spent) must still publish, and
/// must report false so the caller does not announce an arrival or
/// wake anyone.
#[cfg(feature = "indexer")]
#[test]
fn a_rate_limited_arrival_still_republishes_the_connection() {
    with_daemon("kickatomiclimit", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        d.watchlist_instant_max.store(1, Ordering::Relaxed);
        assert!(d.instant_kick(&["first".to_string()], 5000), "spends it");

        let era = d.index_era();
        let fresh = nzbkit::index::Index::open(&d.index_db).expect("open index");
        assert!(
            !d.publish_index_with_arrivals(era, fresh, &["second".to_string()], 5001),
            "the allowance is spent, so nothing is staged and nobody wakes"
        );
        assert_eq!(*d.instant_hint.lock_ok(), vec!["first"], "no new hint");
        assert!(
            d.index.lock_ok().is_some(),
            "but the publish still happened"
        );
    });
}
