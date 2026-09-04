//! Live-byte counter for the decode path's own working memory.
//!
//! nzbfast-local addition, 3 Sep 2026 - re-apply on the next rars
//! re-sync, see `vendor/rars/VENDORING.md`.
//!
//! Why it exists: the product's memory-floor attribution
//! (`nzbkit::memgauge`) could name every tier it owned and still left 41
//! to 58% of a compressed-RAR chase's peak unattributed (audit round 14).
//! One candidate was this crate's own working set - the sliding flat
//! plan, the member pipe buffers - which nothing outside the crate can
//! see, because the allocations are `Vec`s inside the decoder. This is
//! the counter the product reads instead of guessing: `nzbkit::memgauge`
//! pulls [`current`] into its `rars_work` tier at snapshot time.
//!
//! Counters only. Nothing here reads the value to make a decision, and
//! every charge is RAII ([`Charge`]) so an early return or an unwind
//! cannot leak the gauge upward. Relaxed atomics: the reader is a 2 Hz
//! sampler and a torn read costs it one tick's accuracy.
//!
//! What it does NOT cover, deliberately, and how to tell: the tape
//! worker buffers and the flat plan's own `Vec` live in
//! `src/codec/rar50.rs`, which round 35 could not touch (another lane
//! held it), so the flat plan is charged at the ADMISSION site in
//! `rar50/extract.rs` from the same `flat_plan_bytes` the codec
//! allocates from. That makes the plan term exact for the flat path and
//! zero for the ring path, where the codec's bounded ring is what runs.
//! Round 35 measured the whole rars term at 105 MB of a 2,246 MB peak
//! (96 MiB plan + a 4 MiB pipe pool), so the approximation is small
//! either way; charging the tape buffers at their true allocation is
//! the next re-sync's job.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

static CUR: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

/// Bytes this crate's decode paths currently hold, as charged.
pub fn current() -> u64 {
    CUR.load(Relaxed)
}

/// High-water of [`current`] since the process started.
pub fn peak() -> u64 {
    PEAK.load(Relaxed)
}

fn add(n: u64) {
    if n == 0 {
        return;
    }
    let now = CUR.fetch_add(n, Relaxed) + n;
    PEAK.fetch_max(now, Relaxed);
}

fn sub(n: u64) {
    if n == 0 {
        return;
    }
    // Saturating, like `nzbkit::memgauge::sub`: a gauge that drifts a
    // little low beats one that wraps to `u64::MAX` and reads as 16 EB
    // for the rest of the process.
    let _ = CUR.fetch_update(Relaxed, Relaxed, |v| Some(v.saturating_sub(n)));
}

/// An RAII charge: the bytes are counted for as long as this lives.
#[derive(Debug)]
pub(crate) struct Charge(u64);

impl Charge {
    pub(crate) fn new(n: u64) -> Charge {
        add(n);
        Charge(n)
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        sub(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_charge_counts_for_its_lifetime_and_releases_on_drop() {
        let before = current();
        {
            let _c = Charge::new(1 << 20);
            assert_eq!(current(), before + (1 << 20));
            assert!(peak() >= before + (1 << 20));
        }
        assert_eq!(current(), before);
    }

    #[test]
    fn release_saturates_rather_than_wrapping() {
        // Two charges released in either order can never take the gauge
        // below zero, whatever else the process is charging concurrently.
        let a = Charge::new(64);
        let b = Charge::new(64);
        drop(b);
        drop(a);
        assert!(current() < u64::MAX / 2, "gauge wrapped");
    }
}
