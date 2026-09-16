//! How long the index write paths actually hold their lock, per call
//! site.
//!
//! Every ingest site in the engine takes a lock that somebody else is
//! queued behind, and until 16 Sep 2026 nothing in the tree measured
//! any of them on a running daemon. Two different locks, and the
//! difference is the whole reason this exists:
//!
//! * the tip walker's `ix.ingest` runs inside `Daemon::with_index_mut`,
//!   so its hold is the daemon's **in-process index mutex** - the thing
//!   every in-process reader waits out, the dashboard and the API and
//!   the wall enricher included (`daemon_indexbusy` records an ~80 s one
//!   on the live daemon, 14 Aug 2026; four HTTP workers queued behind a
//!   62 s hold wedged a dashboard tab on 28 Jul);
//! * the deepen pass and the gapfill leg ingest on an `open_scratch`
//!   connection, so theirs is a SQLite **write-lock** hold, waited out
//!   against the 10 s `busy_timeout`.
//!
//! `research/INDEXER-SCAN-CPU-AUDIT-2026-09-03.md` and
//! `research/INDEX-SCAN-CHUNK-SWEEP-2026-09-16.md` both price the
//! second one on a rig, and both say in their own stated limits that
//! nothing had measured the first. This is the instrument that closes
//! that, and the numbers it took are in section 8 of the sweep.
//!
//! # Why a ring of samples and not a histogram
//!
//! Because the populations are small and the question is a ratio. A tip
//! catch-up over the whole `TIP_HANDOFF` window is 50 holds at
//! `INGEST_BATCH` = 10,000, and was 25 at the 20,000 this instrument
//! was written to price; a bucketed histogram would answer a p90 over
//! 25 samples to within a bucket width, and the step being priced was
//! 35%. A bounded ring of the last [`RING`] durations gives an EXACT
//! p50/p90/p99 over that window for the price of one write, and the
//! lifetime count/sum/max beside it are exact over all time.
//!
//! `sum` is the field that answers "what share of a pass is ingest":
//! divide it by the wall of the pass that produced it. That question is
//! the other half of the 16 Sep item and is why the accumulator is not
//! only percentiles.
//!
//! # Cost
//!
//! One `Instant::now()` pair and one short mutex around a `HashMap`
//! lookup plus a slot write, per hold. The holds themselves are
//! milliseconds to seconds - the tables above are in whole seconds at
//! the shipped batch size - so the instrument is some six orders of
//! magnitude below what it measures and ships ON rather than behind a
//! feature. It is deliberately NOT on the read paths, which are short
//! and frequent and would be a different trade.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Samples kept per site for the percentile window. 4,096 holds is
/// hours of tip walking and more than a full deepen pass of a large
/// group, so in practice the window is "this run" rather than a
/// trailing slice; the bound is there so a daemon that runs for months
/// does not grow.
pub const RING: usize = 4096;

/// One call site's holds. Lifetime totals are exact; the percentiles
/// are over the last [`RING`].
#[derive(Default)]
struct Site {
    count: u64,
    total_us: u64,
    max_us: u64,
    ring: Vec<u32>,
    next: usize,
}

/// A site's holds, as a caller reads them out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteHolds {
    /// `<kind> <file>:<line>` - the kind names what the hold IS, the
    /// location names which call site took it.
    pub site: String,
    /// Holds recorded since the last [`reset`], over all time.
    pub count: u64,
    /// Their total, which is the numerator of "what share of the pass
    /// was this".
    pub total_us: u64,
    /// The worst single hold, over all time.
    pub max_us: u64,
    /// Exact percentiles over the last [`RING`] holds.
    pub p50_us: u64,
    pub p90_us: u64,
    pub p99_us: u64,
    /// How many holds those percentiles are over.
    pub window: usize,
}

type Key = (&'static str, &'static str, u32);

fn table() -> &'static Mutex<HashMap<Key, Site>> {
    static T: OnceLock<Mutex<HashMap<Key, Site>>> = OnceLock::new();
    T.get_or_init(Default::default)
}

/// Record one hold. `kind` says what was held, `file`/`line` say where -
/// pass `std::panic::Location::caller()`'s pair from a `#[track_caller]`
/// wrapper, or `file!()`/`line!()` at the site itself.
///
/// A poisoned table is ignored rather than propagated: this is an
/// observer, and it must not be able to fail the write it is watching.
pub fn record(kind: &'static str, file: &'static str, line: u32, d: Duration) {
    let us = d.as_micros().min(u64::MAX as u128) as u64;
    let Ok(mut t) = table().lock() else { return };
    let s = t.entry((kind, file, line)).or_default();
    s.count += 1;
    s.total_us = s.total_us.saturating_add(us);
    s.max_us = s.max_us.max(us);
    let clipped = us.min(u32::MAX as u64) as u32;
    if s.ring.len() < RING {
        s.ring.push(clipped);
    } else {
        s.ring[s.next] = clipped;
        s.next = (s.next + 1) % RING;
    }
}

/// Time a hold and record it when the guard drops. The guard is what
/// makes the measurement span the WHOLE hold including an early return
/// out of the closure.
pub struct Timer {
    kind: &'static str,
    file: &'static str,
    line: u32,
    t0: Instant,
}

impl Timer {
    pub fn start(kind: &'static str, file: &'static str, line: u32) -> Self {
        Self {
            kind,
            file,
            line,
            t0: Instant::now(),
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        record(self.kind, self.file, self.line, self.t0.elapsed());
    }
}

/// Every site with at least one hold, worst total first - which orders
/// them by how much of the pass each one actually cost, not by how bad
/// a single one got.
pub fn snapshot() -> Vec<SiteHolds> {
    let Ok(t) = table().lock() else {
        return Vec::new();
    };
    let mut out: Vec<SiteHolds> = t
        .iter()
        .map(|(&(kind, file, line), s)| {
            let mut w = s.ring.clone();
            w.sort_unstable();
            let pick = |p: f64| -> u64 {
                if w.is_empty() {
                    return 0;
                }
                // Nearest-rank: the smallest sample at or above the
                // percentile, which is the reading that cannot claim a
                // value no hold actually took.
                let rank = ((w.len() as f64) * p).ceil().max(1.0) as usize;
                w[rank.min(w.len()) - 1] as u64
            };
            SiteHolds {
                site: format!("{kind} {file}:{line}"),
                count: s.count,
                total_us: s.total_us,
                max_us: s.max_us,
                p50_us: pick(0.50),
                p90_us: pick(0.90),
                p99_us: pick(0.99),
                window: w.len(),
            }
        })
        .collect();
    out.sort_by(|a, b| b.total_us.cmp(&a.total_us).then(a.site.cmp(&b.site)));
    out
}

/// Forget everything, so a measurement leg starts from zero. The
/// counters are lifetime figures by design, so an A/B needs this
/// between arms.
pub fn reset() {
    if let Ok(mut t) = table().lock() {
        t.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONE test, deliberately. The table is process-global and `reset`
    /// is part of what is under test, so two test THREADS in the same
    /// process would race each other - and `cargo test --lib` is exactly
    /// that one process (nextest's per-test process would hide it, which
    /// is the blind spot CLAUDE.md's one-process lines exist for).
    #[test]
    fn holds_accumulate_per_site_with_exact_percentiles_and_uncapped_totals() {
        reset();
        for ms in 1..=100u64 {
            record("t", "a.rs", 1, Duration::from_millis(ms));
        }
        record("t", "a.rs", 2, Duration::from_millis(5));
        let snap = snapshot();
        assert_eq!(snap.len(), 2, "two sites: {snap:?}");
        // Ordered by total, so the 100-hold site comes first.
        assert_eq!(snap[0].site, "t a.rs:1");
        assert_eq!(snap[0].count, 100);
        assert_eq!(snap[0].total_us, (1..=100).map(|m| m * 1000).sum::<u64>());
        assert_eq!(snap[0].max_us, 100_000);
        assert_eq!(snap[0].window, 100);
        // Nearest-rank over 1..=100 ms: p50 is the 50th sample, p90 the
        // 90th - values a hold actually took, never an interpolation.
        assert_eq!(snap[0].p50_us, 50_000);
        assert_eq!(snap[0].p90_us, 90_000);
        assert_eq!(snap[0].p99_us, 99_000);
        assert_eq!(snap[1].site, "t a.rs:2");
        assert_eq!(snap[1].count, 1);

        // The lifetime columns must stay exact past the ring, because
        // `total_us` is what answers "what share of the pass was
        // ingest" and a pass can be longer than the window.
        reset();
        let n = RING + 500;
        for _ in 0..n {
            record("t", "b.rs", 1, Duration::from_millis(2));
        }
        let snap = snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].count, n as u64, "lifetime count is not capped");
        assert_eq!(snap[0].total_us, n as u64 * 2_000);
        assert_eq!(snap[0].window, RING, "the percentile window IS capped");
        assert_eq!(snap[0].p90_us, 2_000);

        // The guard is the shape every call site uses, so it has to be
        // the shape the table sees.
        reset();
        {
            let _t = Timer::start("t", "c.rs", 7);
            std::thread::sleep(Duration::from_millis(2));
        }
        let snap = snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].site, "t c.rs:7");
        assert_eq!(snap[0].count, 1);
        assert!(snap[0].max_us >= 1_000, "{:?}", snap[0]);
        reset();
        assert!(snapshot().is_empty(), "reset clears");
    }
}
