//! The interleaving half of the gate handback: a write that arrives in
//! the MIDDLE of the maintenance slice must land there, not after it.
//!
//! `pass_gate.rs` pins the primitive - a queued waiter gets the gate at
//! the handback, an uncontended handback keeps it. What that cannot see
//! is whether the lap's own legs actually call it, and that is the whole
//! item: the fold loops handed back the write MUTEX between all ~200 of
//! their slices and handed back the GATE never, so the lanes hung on the
//! gate - the tip watcher, the index compactor, the seed-harvest replay
//! - ran only in the interval sleep, at a duty cycle measured as low as
//! 28.6% on the live daemon
//! (research/INDEX-LAP-DUTY-CYCLE-2026-09-02.md).
//!
//! Deleting one `gate.handback().await` from `maintenance_slice` brings
//! that back with nothing else failing and no line in any log, which is
//! why this test reads the peer's clock rather than the lap's: it
//! asserts the peer got in BEFORE `maintenance_slice` returned, which is
//! a fact no amount of "it completed eventually" can fake.

use super::*;
use indexer::{PassGate, maintenance_slice};

/// A throwaway daemon on its own temp directory. A fourth copy of the
/// helper `quality_lap_tests` and `picker_index_tests` each carry, for
/// the reason both of them record: a sibling `#[cfg(test)]` module
/// cannot reach either of the others.
fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
    let dir = std::env::temp_dir().join(format!("nzbfast-dmn-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::testutil::test_daemon(&dir);
    f(&d);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A peer queued on `index_pass_gate` gets it, and gets its index write
/// in, while the maintenance slice is still running.
///
/// A current-thread runtime on purpose. The peer can only make progress
/// when this task awaits, so a pass means the handback's own await point
/// let it through - never a lucky interleaving on another core - and a
/// failure is a real absence rather than a lost race. It also means the
/// assertion after the call is exact: this task still holds the
/// `PassGate` at that moment, so if the peer has the gate it can only
/// have taken it mid-slice.
#[test]
fn a_write_that_arrives_mid_slice_lands_mid_slice() {
    with_daemon("gate-handback", |d| {
        // Spots on, groups off - the same configuration the two sibling
        // test files use, so `maintenance_slice`'s entry gate is open
        // with an empty group vector and the call below is the one the
        // scan loop makes.
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(true, Ordering::Relaxed);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let gate = Arc::new(tokio::sync::Mutex::new(()));
            let mut lap = PassGate::acquire(&gate).await;

            let wrote = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (gate2, daemon2, wrote2) = (gate.clone(), d.clone(), wrote.clone());
            let peer = tokio::spawn(async move {
                // Exactly what a dashboard write or a watch-folder add
                // does: win the gate, then write through the index.
                let _held = gate2.lock().await;
                let ok = daemon2
                    .with_index_mut(|ix| Some(ix.kv_set("gate_handback_probe", "1").is_ok()))
                    .unwrap_or(false);
                wrote2.store(ok, Ordering::SeqCst);
            });

            // Let the peer reach `lock().await` and queue behind us.
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(
                !wrote.load(Ordering::SeqCst),
                "the lap holds the gate here: a peer that got in before \
                 the slice even started would make the assertion below \
                 vacuous"
            );

            assert!(
                maintenance_slice(d, false, true, &|| false, &mut lap).await,
                "the slice must run to the end - it stands down only for \
                 a download, and there is none"
            );

            assert!(
                wrote.load(Ordering::SeqCst),
                "a write queued on index_pass_gate must land BETWEEN the \
                 slice's legs. It did not, so the lap is holding the gate \
                 for its whole run again and every lane on that gate is \
                 back to the interval sleep"
            );
            assert_eq!(
                d.with_index(|ix| Some(ix.kv_get("gate_handback_probe")))
                    .expect("the index is open"),
                Some("1".to_string()),
                "and the write itself must have gone through"
            );

            drop(lap);
            peer.await.unwrap();
        });
    });
}
