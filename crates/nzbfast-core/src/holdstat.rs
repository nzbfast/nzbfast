//! How long the index write paths cost a queued reader, per call site,
//! split into the WAIT for the lock and the HOLD of it.
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
//! that, and the numbers it took are in sections 9, 10 and 11 of the
//! sweep.
//!
//! # Wait and hold are different questions and this records both
//!
//! Until 17 Sep 2026 a site kept ONE population and `with_index_mut`
//! started its timer before taking the mutex, so every `index_mut`
//! figure in the tree was **wait plus hold** written up as a hold.
//! That is not a spelling mistake in a doc comment: it changes what a
//! reading means. The correction and the case that exposed it are in
//! the sweep's section 11 subsection "What `index_mut` actually
//! measures, which is not only the hold" - sites whose p50 was 0.0 ms
//! carrying maxima of 4,000.2 ms and 4,008.5 ms, which are the shatter
//! fold's 4 s budget seen from the QUEUE and not a daemon-wide stall.
//!
//! Neither half is the interesting one on its own:
//!
//! * **the wait** is what `Daemon::HTTP_INDEX_WAIT` bounds - a bounded
//!   HTTP door that gives up after 5 s gave up because of a WAIT, not
//!   because of anybody's hold - so an instrument that measured only
//!   the hold would be a worse instrument, not a more accurate one;
//! * **the hold** is what a time budget can be written against
//!   (`index_fold_secs`, `CORR_BACKLOG_HOLD`), because a site can only
//!   shorten what it holds;
//! * **their sum** is the latency a queued reader actually sees, and is
//!   what every figure taken before 17 Sep 2026 is.
//!
//! So a site keeps all three exactly. `total_us` / `max_us` /
//! `p50_us`..`p99_us` still mean wait+hold, unchanged, so a snapshot
//! archived before the split is still comparable column for column;
//! `wait_*` and `hold_*` are added beside them.
//!
//! A site that never calls [`Timer::acquired`] - the two `scan.rs`
//! ingest legs - records its whole span as HOLD and a zero wait, which
//! is honest about what can be seen from here rather than pretending:
//! those legs own their connection, so there is no in-process lock to
//! wait on, and any SQLite `busy_timeout` wait they pay is inside
//! `ix.ingest` where this instrument cannot reach it. Read `hold` at
//! those two sites as "ingest, including any write-lock wait it paid".
//!
//! # Why a ring of samples and not a histogram
//!
//! Because the populations are small and the question is a ratio. A tip
//! catch-up over the whole `TIP_HANDOFF` window is 50 holds at
//! `INGEST_BATCH` = 10,000, and was 25 at the 20,000 this instrument
//! was written to price; a bucketed histogram would answer a p90 over
//! 25 samples to within a bucket width, and the step being priced was
//! 35%. A bounded ring of the last [`RING`] samples gives an EXACT
//! p50/p90/p99 over that window for the price of one write, and the
//! lifetime count/sum/max beside it are exact over all time.
//!
//! The ring holds the PAIR rather than one number, which is what lets
//! the wait, the hold and their sum each have exact percentiles of
//! their own. Two sorted projections of one ring cost nothing to keep
//! and cannot be reconstructed from each other: a p90 of the sum says
//! nothing about which half it was, and the maxima come from different
//! samples. The price is 8 bytes a slot instead of 4 - 32 KiB a site
//! at a full ring, against 16 KiB, and the live daemon files 21 sites,
//! most of them far below the bound.
//!
//! `sum` is the field that answers "what share of a pass is ingest":
//! divide it by the wall of the pass that produced it. That question is
//! the other half of the 16 Sep item and is why the accumulator is not
//! only percentiles.
//!
//! # Cost
//!
//! Two `Instant::now()` calls at a site that splits (three in total per
//! sample: start, acquisition, drop) and one short mutex around a
//! `HashMap` lookup plus a slot write. The holds themselves are
//! milliseconds to seconds - the tables in the sweep are in whole
//! seconds at the shipped batch size - so the instrument is some six
//! orders of magnitude below what it measures and ships ON rather than
//! behind a feature. The acquisition stamp added on 17 Sep 2026 is one
//! more `Instant::now()` per hold, tens of nanoseconds against holds of
//! seconds, so that argument is unchanged rather than merely assumed
//! to be. It is deliberately NOT on the read paths, which are short and
//! frequent and would be a different trade.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Samples kept per site for the percentile window. 4,096 holds is
/// hours of tip walking and more than a full deepen pass of a large
/// group, so in practice the window is "this run" rather than a
/// trailing slice; the bound is there so a daemon that runs for months
/// does not grow.
pub const RING: usize = 4096;

/// One call site's samples. Lifetime totals are exact; the percentiles
/// are over the last [`RING`].
#[derive(Default)]
struct Site {
    count: u64,
    wait_total_us: u64,
    hold_total_us: u64,
    wait_max_us: u64,
    hold_max_us: u64,
    /// Worst wait+hold of any ONE sample, which is not the sum of the
    /// two maxima above - they can come from different samples.
    max_us: u64,
    /// `(wait_us, hold_us)` per sample, each clipped to `u32`.
    ring: Vec<(u32, u32)>,
    next: usize,
}

/// A site's samples, as a caller reads them out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteHolds {
    /// `<kind> <file>:<line>` - the kind names what the hold IS, the
    /// location names which call site took it.
    pub site: String,
    /// Samples recorded since the last [`reset`], over all time.
    pub count: u64,
    /// Wait plus hold, totalled - the numerator of "what share of the
    /// pass was this", and the figure every reading taken before
    /// 17 Sep 2026 is.
    pub total_us: u64,
    /// The worst single wait+hold, over all time.
    pub max_us: u64,
    /// Exact percentiles of wait+hold over the last [`RING`] samples.
    pub p50_us: u64,
    pub p90_us: u64,
    pub p99_us: u64,
    /// How many samples those percentiles are over.
    pub window: usize,
    /// The queued half: time spent waiting for the lock, which is what
    /// `HTTP_INDEX_WAIT` bounds. Zero at a site that never stamps an
    /// acquisition - see the module header.
    pub wait_total_us: u64,
    pub wait_max_us: u64,
    pub wait_p50_us: u64,
    pub wait_p90_us: u64,
    pub wait_p99_us: u64,
    /// The held half: time the lock was actually held, which is what a
    /// time budget at the site can shorten.
    pub hold_total_us: u64,
    pub hold_max_us: u64,
    pub hold_p50_us: u64,
    pub hold_p90_us: u64,
    pub hold_p99_us: u64,
}

type Key = (&'static str, &'static str, u32);

fn table() -> &'static Mutex<HashMap<Key, Site>> {
    static T: OnceLock<Mutex<HashMap<Key, Site>>> = OnceLock::new();
    T.get_or_init(Default::default)
}

/// Record one sample. `kind` says what was held, `file`/`line` say
/// where - pass `std::panic::Location::caller()`'s pair from a
/// `#[track_caller]` wrapper, or `file!()`/`line!()` at the site
/// itself. `wait` is time spent queued for the lock and `hold` is time
/// spent holding it; a site with nothing to wait on passes
/// `Duration::ZERO` for the first.
///
/// A poisoned table is ignored rather than propagated: this is an
/// observer, and it must not be able to fail the write it is watching.
pub fn record(kind: &'static str, file: &'static str, line: u32, wait: Duration, hold: Duration) {
    let us = |d: Duration| d.as_micros().min(u64::MAX as u128) as u64;
    let (w, h) = (us(wait), us(hold));
    let Ok(mut t) = table().lock() else { return };
    let s = t.entry((kind, file, line)).or_default();
    s.count += 1;
    s.wait_total_us = s.wait_total_us.saturating_add(w);
    s.hold_total_us = s.hold_total_us.saturating_add(h);
    s.wait_max_us = s.wait_max_us.max(w);
    s.hold_max_us = s.hold_max_us.max(h);
    s.max_us = s.max_us.max(w.saturating_add(h));
    let clip = |v: u64| v.min(u32::MAX as u64) as u32;
    let slot = (clip(w), clip(h));
    if s.ring.len() < RING {
        s.ring.push(slot);
    } else {
        s.ring[s.next] = slot;
        s.next = (s.next + 1) % RING;
    }
}

/// Time a wait and a hold and record them when the guard drops. The
/// guard is what makes the measurement span the WHOLE hold including an
/// early return out of the closure.
///
/// Call [`Timer::acquired`] at the instant the lock is taken to split
/// the sample; a guard that never does records its whole span as hold.
pub struct Timer {
    kind: &'static str,
    file: &'static str,
    line: u32,
    t0: Instant,
    at: Cell<Option<Instant>>,
}

impl Timer {
    pub fn start(kind: &'static str, file: &'static str, line: u32) -> Self {
        Self {
            kind,
            file,
            line,
            t0: Instant::now(),
            at: Cell::new(None),
        }
    }

    /// Stamp the moment the lock was acquired: everything before is
    /// WAIT, everything after is HOLD. The FIRST call wins, so a site
    /// that retries an acquisition still reports the whole queue as
    /// wait rather than restarting the clock on the last attempt.
    ///
    /// Takes `&self` so it can be called from inside the closure that
    /// holds the lock while the guard lives outside it, which is the
    /// shape `Daemon::with_index_mut` has.
    pub fn acquired(&self) {
        if self.at.get().is_none() {
            self.at.set(Some(Instant::now()));
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let span = self.t0.elapsed();
        let wait = match self.at.get() {
            Some(t1) => t1.saturating_duration_since(self.t0).min(span),
            None => Duration::ZERO,
        };
        record(self.kind, self.file, self.line, wait, span - wait);
    }
}

/// Every site with at least one sample, worst total first - which
/// orders them by how much of the pass each one actually cost, not by
/// how bad a single one got.
pub fn snapshot() -> Vec<SiteHolds> {
    let Ok(t) = table().lock() else {
        return Vec::new();
    };
    // Nearest-rank: the smallest sample at or above the percentile,
    // which is the reading that cannot claim a value no sample actually
    // took. `w` must already be sorted.
    fn pick(w: &[u64], p: f64) -> u64 {
        if w.is_empty() {
            return 0;
        }
        let rank = ((w.len() as f64) * p).ceil().max(1.0) as usize;
        w[rank.min(w.len()) - 1]
    }
    let mut out: Vec<SiteHolds> = t
        .iter()
        .map(|(&(kind, file, line), s)| {
            let sorted = |f: &dyn Fn(&(u32, u32)) -> u64| {
                let mut v: Vec<u64> = s.ring.iter().map(f).collect();
                v.sort_unstable();
                v
            };
            let tot = sorted(&|&(w, h)| w as u64 + h as u64);
            let wait = sorted(&|&(w, _)| w as u64);
            let hold = sorted(&|&(_, h)| h as u64);
            SiteHolds {
                site: format!("{kind} {file}:{line}"),
                count: s.count,
                total_us: s.wait_total_us.saturating_add(s.hold_total_us),
                max_us: s.max_us,
                p50_us: pick(&tot, 0.50),
                p90_us: pick(&tot, 0.90),
                p99_us: pick(&tot, 0.99),
                window: s.ring.len(),
                wait_total_us: s.wait_total_us,
                wait_max_us: s.wait_max_us,
                wait_p50_us: pick(&wait, 0.50),
                wait_p90_us: pick(&wait, 0.90),
                wait_p99_us: pick(&wait, 0.99),
                hold_total_us: s.hold_total_us,
                hold_max_us: s.hold_max_us,
                hold_p50_us: pick(&hold, 0.50),
                hold_p90_us: pick(&hold, 0.90),
                hold_p99_us: pick(&hold, 0.99),
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
            record("t", "a.rs", 1, Duration::ZERO, Duration::from_millis(ms));
        }
        record("t", "a.rs", 2, Duration::ZERO, Duration::from_millis(5));
        let snap = snapshot();
        assert_eq!(snap.len(), 2, "two sites: {snap:?}");
        // Ordered by total, so the 100-sample site comes first.
        assert_eq!(snap[0].site, "t a.rs:1");
        assert_eq!(snap[0].count, 100);
        assert_eq!(snap[0].total_us, (1..=100).map(|m| m * 1000).sum::<u64>());
        assert_eq!(snap[0].max_us, 100_000);
        assert_eq!(snap[0].window, 100);
        // Nearest-rank over 1..=100 ms: p50 is the 50th sample, p90 the
        // 90th - values a sample actually took, never an interpolation.
        assert_eq!(snap[0].p50_us, 50_000);
        assert_eq!(snap[0].p90_us, 90_000);
        assert_eq!(snap[0].p99_us, 99_000);
        // A site that never stamps an acquisition is all hold and no
        // wait, and the summed columns must equal the hold columns.
        assert_eq!(snap[0].wait_total_us, 0);
        assert_eq!(snap[0].wait_max_us, 0);
        assert_eq!(snap[0].wait_p90_us, 0);
        assert_eq!(snap[0].hold_total_us, snap[0].total_us);
        assert_eq!(snap[0].hold_p90_us, 90_000);
        assert_eq!(snap[0].hold_max_us, 100_000);
        assert_eq!(snap[1].site, "t a.rs:2");
        assert_eq!(snap[1].count, 1);

        // The two halves are separate populations and neither can be
        // reconstructed from the sum: here the worst wait and the worst
        // hold are different samples, so `max_us` is 10 ms and NOT the
        // 18 ms adding the two maxima would claim.
        reset();
        record(
            "t",
            "d.rs",
            1,
            Duration::from_millis(1),
            Duration::from_millis(9),
        );
        record(
            "t",
            "d.rs",
            1,
            Duration::from_millis(9),
            Duration::from_millis(1),
        );
        let s = &snapshot()[0];
        assert_eq!(s.count, 2);
        assert_eq!(s.total_us, 20_000);
        assert_eq!(
            s.max_us, 10_000,
            "worst SAMPLE, not worst wait plus worst hold"
        );
        assert_eq!(s.wait_max_us, 9_000);
        assert_eq!(s.hold_max_us, 9_000);
        assert_eq!(s.wait_total_us, 10_000);
        assert_eq!(s.hold_total_us, 10_000);
        assert_eq!((s.p50_us, s.p90_us), (10_000, 10_000));

        // The lifetime columns must stay exact past the ring, because
        // `total_us` is what answers "what share of the pass was
        // ingest" and a pass can be longer than the window.
        reset();
        let n = RING + 500;
        for _ in 0..n {
            record(
                "t",
                "b.rs",
                1,
                Duration::from_millis(1),
                Duration::from_millis(2),
            );
        }
        let snap = snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].count, n as u64, "lifetime count is not capped");
        assert_eq!(snap[0].total_us, n as u64 * 3_000);
        assert_eq!(snap[0].wait_total_us, n as u64 * 1_000);
        assert_eq!(snap[0].hold_total_us, n as u64 * 2_000);
        assert_eq!(snap[0].window, RING, "the percentile window IS capped");
        assert_eq!(snap[0].p90_us, 3_000);
        assert_eq!(snap[0].wait_p90_us, 1_000);
        assert_eq!(snap[0].hold_p90_us, 2_000);

        // The guard is the shape every call site uses, so it has to be
        // the shape the table sees - and the acquisition stamp has to
        // land the wait on the wait side and the rest on the hold side.
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
        assert_eq!(snap[0].wait_total_us, 0, "no stamp means no wait");

        reset();
        {
            let t = Timer::start("t", "c.rs", 8);
            std::thread::sleep(Duration::from_millis(4));
            t.acquired();
            // A second stamp must not move the split: the first
            // acquisition is the one that ended the queue.
            t.acquired();
            std::thread::sleep(Duration::from_millis(8));
        }
        let s = &snapshot()[0];
        assert!(s.wait_total_us >= 3_000, "wait side: {s:?}");
        assert!(s.hold_total_us >= 7_000, "hold side: {s:?}");
        assert!(
            s.hold_total_us > s.wait_total_us,
            "the 8 ms half must be the hold: {s:?}"
        );
        assert_eq!(
            s.total_us,
            s.wait_total_us + s.hold_total_us,
            "the sum column is the two halves"
        );

        reset();
        assert!(snapshot().is_empty(), "reset clears");
    }
}
