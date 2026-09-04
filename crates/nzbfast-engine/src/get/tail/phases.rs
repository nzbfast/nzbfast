//! The tail timed as a phase (3 Sep 2026, claim `wire-tls-and-tail-phase`).
//!
//! Everything after the last article lands - settle verification, the
//! repair ladder, `Extractor::finish`, the deferred renames, the journal
//! flush and the unrar ladder - runs between the download's last byte
//! and the job's exit, and until now the only figure over any of it was
//! the daemon's `postproc_secs`: ONE number for the whole tail, written
//! only by the daemon's `run_tail`, and never present at all on a
//! `nzbfast get`. A tail that costs a second per 24 GB and a tail that
//! costs a second because one rung re-reads every file are the same
//! number there.
//!
//! This is that number split at the rungs, printed once as `[tail]` and
//! normalised per GB so the reading transfers between a 2 GB set and a
//! 24 GB one. Instrument-first: no behaviour hangs off it.
//!
//! Cost of the instrument itself: one `Instant::now()` per rung (seven
//! on the ordinary path), against a tail measured in hundreds of
//! milliseconds. Not a knob, not gated - a phase breakdown that only
//! appears when somebody thought to ask for it is a phase breakdown
//! that is missing from every log a user actually sends in.

use std::time::Instant;
use tracing::info;

/// A tail's rungs and what each cost. Marks are recorded in the order
/// they are taken, which is the order the tail runs them.
pub(crate) struct TailPhases {
    start: Instant,
    last: Instant,
    marks: Vec<(&'static str, f64)>,
}

impl TailPhases {
    /// Start timing at the top of the tail - the instant the network
    /// drain returned.
    pub(crate) fn start() -> Self {
        let now = Instant::now();
        TailPhases {
            start: now,
            last: now,
            marks: Vec::with_capacity(8),
        }
    }

    /// Close the rung that has been running since the last mark and
    /// call it `name`.
    pub(crate) fn mark(&mut self, name: &'static str) {
        let now = Instant::now();
        self.marks
            .push((name, now.duration_since(self.last).as_secs_f64()));
        self.last = now;
    }

    /// One `[tail]` line: the whole tail, its cost per GB of payload,
    /// and every rung that cost at least a millisecond.
    ///
    /// `bytes` is the payload this job decoded, so the per-GB figure is
    /// against the same denominator the `[get]` rate line uses. A job
    /// that decoded nothing prints the absolute figures only - there is
    /// no rate to report and a division by zero would print `inf`.
    pub(crate) fn print(&self, bytes: u64) {
        let total = self.start.elapsed().as_secs_f64();
        let gb = bytes as f64 / 1e9;
        // A rung under a millisecond is noise beside a tail measured in
        // hundreds; listing all seven every time buries the one that
        // matters. The TOTAL is always the whole tail, so nothing the
        // filter hides goes unaccounted for - it is the difference
        // between the total and the sum of what is shown.
        let shown: Vec<String> = self
            .marks
            .iter()
            .filter(|(_, s)| *s >= 0.001)
            .map(|(n, s)| format!("{n} {:.0} ms", s * 1000.0))
            .collect();
        let per_gb = if gb > 0.0 {
            format!(" · {:.0} ms/GB", total * 1000.0 / gb)
        } else {
            String::new()
        };
        info!(
            target: "tail",
            "tail {:.2} s over {gb:.2} GB{per_gb}: {}",
            total,
            if shown.is_empty() {
                "nothing over 1 ms".to_string()
            } else {
                shown.join(" · ")
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::TailPhases;

    /// The marks come out in the order they were taken, and each one
    /// measures only its own rung.
    #[test]
    fn marks_are_ordered_and_disjoint() {
        let mut p = TailPhases::start();
        p.mark("first");
        p.mark("second");
        assert_eq!(
            p.marks.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        // Disjoint: no rung may exceed the whole.
        let total = p.start.elapsed().as_secs_f64();
        for (n, s) in &p.marks {
            assert!(*s <= total, "{n} ({s}) is longer than the tail ({total})");
        }
    }

    /// A job that decoded nothing must still print, and must not divide
    /// by zero doing it.
    #[test]
    fn a_zero_byte_job_prints_without_a_rate() {
        let mut p = TailPhases::start();
        p.mark("verify");
        p.print(0);
    }

    /// The total is the whole tail, not the sum of the shown rungs -
    /// so a sub-millisecond rung being filtered out cannot make the
    /// line under-report.
    #[test]
    fn the_total_covers_rungs_the_filter_hides() {
        let mut p = TailPhases::start();
        p.mark("instant"); // certainly under a millisecond
        std::thread::sleep(std::time::Duration::from_millis(5));
        p.mark("slow");
        assert!(p.marks[0].1 < 0.001, "the first rung should be filtered");
        assert!(p.start.elapsed().as_secs_f64() >= 0.005);
        p.print(1_000_000_000);
    }
}
