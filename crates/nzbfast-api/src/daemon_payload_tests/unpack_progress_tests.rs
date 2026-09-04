//! TODO 205: the queue row's disk-unpack numbers, from the hub entry the
//! ladder arms to the JSON the dashboard reads.
//!
//! The failure this pins is issue #47's: a 130-volume obfuscated set
//! unpacking for minutes behind the single word "unpacking", with no way
//! to tell whether it was one volume or a hundred and thirty, or how far
//! in it was. The engine-side half is proved end to end in
//! `repair::repair_tests`; this is the payload half - that the counters
//! reach the row, on the right row, and that every other row and every
//! other stage still says nothing.
//!
//! A child of daemon_tests, out here for the size gate (TODO 106); the
//! module is named for its file so size-gate.py's CFG_TEST_MOD resolver
//! still reads it as test code, and `use super::*` brings `with_daemon`
//! and `jv`.

// The daemon crate's root vocabulary, which `use super::*` reached while
// this file lived there: `super::` means `serve` here, and serve's globs
// carry the daemon UNITS but not that crate root's own imports.
use nzbfast_daemon::MutexExt;
use nzbfast_daemon::daemon::Daemon;
use nzbfast_daemon::testutil::{jv, with_daemon};
use serde_json::Value;
use std::sync::Arc;

/// The row the queue payload builds for `id`.
fn row(d: &Arc<Daemon>, id: &str) -> Value {
    let v = crate::sabcompat::queue_json(d, &std::collections::HashMap::new());
    v["queue"]["slots"]
        .as_array()
        .expect("slots array")
        .iter()
        .find(|s| s["nzo_id"] == id)
        .cloned()
        .unwrap_or(Value::Null)
}

#[test]
fn only_the_unpacking_row_carries_its_ladder_counters() {
    with_daemon("unpackprog", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv("nzo-a", "Set.A-GRP", serde_json::json!({})));
            q.push_back(jv("nzo-b", "Set.B-GRP", serde_json::json!({})));
        }
        // Nothing unpacking: the key is there (the dashboard reads it on
        // every poll) and says nothing, so the page falls back to the
        // phrase it has always shown.
        assert_eq!(row(d, "nzo-a")["unpack"], Value::Null);
        assert_eq!(row(d, "nzo-b")["unpack"], Value::Null);

        // Job A's disk ladder arms. `arm` is the ladder's own entry
        // point, so this is the same registration `unpack_tail` makes.
        let hub = d.hub.clone();
        let arm = crate::unpackprog::arm(Some(&hub.unpack), "nzo-a", 130);
        let a = row(d, "nzo-a");
        assert_eq!(a["unpack"]["volumes"], 130, "the count is knowable first");
        assert_eq!(a["unpack"]["total"], 0, "no set parsed yet");
        assert_eq!(a["unpack"]["done"], 0);
        // ...and job B, downloading behind it, is untouched: the whole
        // reason this is keyed by nzo_id rather than held in one slot.
        assert_eq!(row(d, "nzo-b")["unpack"], Value::Null);

        // The ladder's first set parses and starts producing. `watch`
        // cannot raise a total from an empty archive list, so the figure
        // comes from the same call the plain feed route uses - the
        // arithmetic that derives a real total from real headers is
        // pinned in `unpacked_total`'s own tests, and end to end on all
        // four routes in `repair::unpackprog_tests`.
        let written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        crate::unpackprog::watch(&written, &[], 0);
        crate::unpackprog::raise_total(40_000_000_000);
        written.store(9_000_000_000, std::sync::atomic::Ordering::Relaxed);
        let a = row(d, "nzo-a");
        assert_eq!(a["unpack"]["total"], 40_000_000_000u64);
        assert_eq!(a["unpack"]["done"], 9_000_000_000u64);

        // The ladder ends. A row that is no longer unpacking must not go
        // on claiming to be - the reason the arm owns the entry.
        drop(arm);
        assert_eq!(row(d, "nzo-a")["unpack"], Value::Null);
    });
}

/// The same payload, driven by a REAL unpack rather than by the
/// counters directly - and on the route that reported a volume count
/// and nothing else until 23 Aug 2026.
///
/// `reextract_dir`'s plain branch feeds its volumes to nzbkit's own
/// extractor, so it registered no bytes anywhere: the row said
/// "unpacking 2 volumes" and held its last figure for the length of the
/// unpack, which on issue #47's NAS is minutes of a queue row that
/// reads as a hang. What this asserts is the whole chain in one go -
/// an extraction on disk, through the hub entry, into the JSON the
/// dashboard draws the lane from.
#[test]
fn a_real_disk_unpack_puts_a_byte_lane_on_the_row() {
    with_daemon("unpackprog-live", |d| {
        d.queue
            .lock_ok()
            .push_back(jv("nzo-live", "Set.Live-GRP", serde_json::json!({})));
        assert_eq!(row(d, "nzo-live")["unpack"], Value::Null);

        let dir =
            std::env::temp_dir().join(format!("nzbfast-unpackprog-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let payload: Vec<u8> = (0..400_000u32)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add(11))
            .collect();
        let half = payload.len() / 2;
        let n = payload.len() as u64;
        use nzbkit::rar::fixtures::rar5_volume_n;
        std::fs::write(
            dir.join("x.rar"),
            rar5_volume_n(&[("film.mkv", n, &payload[..half], false, true)], 0),
        )
        .unwrap();
        std::fs::write(
            dir.join("x.r00"),
            rar5_volume_n(&[("film.mkv", n, &payload[half..], true, false)], 1),
        )
        .unwrap();

        // The arm outlives the extraction, exactly as `unpack_tail`
        // holds it to the end of the tail - a row that is still
        // unpacking must still be reporting.
        let arm = crate::unpackprog::arm(Some(&d.hub.unpack), "nzo-live", 2);
        assert!(crate::repair::reextract_dir(&dir, None).unwrap());
        let r = row(d, "nzo-live");
        assert_eq!(r["unpack"]["volumes"], 2);
        assert_eq!(r["unpack"]["total"], 400_000);
        assert_eq!(r["unpack"]["done"], 400_000);

        drop(arm);
        assert_eq!(row(d, "nzo-live")["unpack"], Value::Null);
        let _ = std::fs::remove_dir_all(&dir);
    });
}
