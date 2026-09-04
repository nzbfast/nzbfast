//! Provider shaping decay detection (conn-tuning design §6, 8 Aug 2026).
//!
//! The live tuner watches what one socket actually delivers each clean
//! epoch (`rate / connected`) and compares it against a stored
//! reference for the same time-of-day bucket. A provider that quietly
//! drops to a fraction of its usual per-connection rate - the Giganews
//! specimen sits at ~10-15% of its reference - gets a `shaped` flag the
//! dashboard can name, replacing the hand-run gn-ladder cron.
//!
//! The thresholds only make sense together: provider throughput swings
//! 2-3x minute to minute, so a single low reading decides nothing. The
//! raise bar (50%) is defensible ONLY because the figure fed in is a
//! whole epoch's average, the quorum needs [`SHAPE_QUORUM_EPOCHS`]
//! consecutive clean epochs, and those epochs must span at least
//! [`SHAPE_QUORUM_STRETCHES`] separate download stretches - one bad
//! evening is one bad evening. A 4-vs-5 Gbps class shortfall
//! deliberately does NOT trip it; that gap belongs to the line-speed
//! accounting, not to a per-host alarm.
//!
//! Pure state machine, no I/O, no clocks - the caller owns what a
//! "reference" is (the bucketed store), what an epoch measured, and
//! what raising or clearing the flag does. Contaminated epochs are not
//! evidence in either direction: they neither advance nor reset a
//! quorum, exactly like the controller's own contamination rule.

/// A clean epoch's per-connection rate below this fraction of the
/// reference counts toward raising the flag.
pub const SHAPE_RAISE_FRAC: f64 = 0.50;

/// While the flag is raised, a clean epoch at or above this fraction of
/// the reference it fell from counts toward clearing it. Asymmetric on
/// purpose: recovery has to be most of the way back, not merely above
/// the alarm line, or the flag would flap around the raise bar.
pub const SHAPE_CLEAR_FRAC: f64 = 0.80;

/// Consecutive qualifying clean epochs a verdict needs.
pub const SHAPE_QUORUM_EPOCHS: u32 = 10;

/// Distinct download stretches the qualifying run must span.
pub const SHAPE_QUORUM_STRETCHES: u32 = 2;

/// What one epoch did to the flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeVerdict {
    /// Nothing changed (most epochs).
    Hold,
    /// The quorum filled: the host is now flagged as shaped.
    Raised,
    /// The recovery quorum filled: the flag cleared.
    Cleared,
}

/// Per-host decay detector. Feed one call per epoch; the caller
/// persists the flag transition and the reference it fell from.
#[derive(Debug)]
pub struct ShapeDetector {
    shaped: bool,
    /// Consecutive qualifying clean epochs toward the NEXT transition.
    run: u32,
    /// Distinct stretch ids inside the current run.
    run_stretches: u32,
    last_stretch: u64,
}

impl ShapeDetector {
    /// `shaped` restores a persisted flag across a daemon restart, so
    /// the clear quorum picks up where it left off instead of the flag
    /// silently reverting to healthy.
    pub fn new(shaped: bool) -> Self {
        ShapeDetector {
            shaped,
            run: 0,
            run_stretches: 0,
            last_stretch: 0,
        }
    }

    pub fn shaped(&self) -> bool {
        self.shaped
    }

    /// A fresh ladder wrote a new reference: whatever the flag said was
    /// measured against the old one, so the flag clears and every
    /// quorum restarts. (Design §6: the decayed rate, once confirmed by
    /// a ladder, BECOMES the reference - the flag means "recently
    /// fell", not "worse than the best week ever".)
    pub fn reset_reference(&mut self) {
        self.shaped = false;
        self.run = 0;
        self.run_stretches = 0;
    }

    /// Feed one epoch. `per_conn_bps` is delivered rate / connected
    /// sockets for the epoch; `reference_bps` is the stored figure to
    /// judge against (the current bucket's median while healthy, the
    /// rate the host fell FROM while flagged); `stretch` identifies the
    /// download stretch the epoch belongs to (any id that changes when
    /// one download run ends and another begins); `clean` is the
    /// controller's own contamination verdict for the epoch.
    pub fn on_epoch(
        &mut self,
        per_conn_bps: f64,
        reference_bps: f64,
        stretch: u64,
        clean: bool,
    ) -> ShapeVerdict {
        if !clean {
            // Not evidence either way: a scan-contaminated or
            // rate-limited epoch measures the wrong thing, and letting
            // it RESET the run would let background noise hold the
            // flag off a genuinely shaped host forever.
            return ShapeVerdict::Hold;
        }
        // NaN is the reason this is not `reference_bps <= 0.0`: a
        // reference computed from an empty epoch divides 0 by 0, and NaN
        // fails EVERY comparison - so `<= 0.0` would wave it through as
        // a usable reference and judge the host against nothing.
        if reference_bps.is_nan() || reference_bps <= 0.0 || !per_conn_bps.is_finite() {
            return ShapeVerdict::Hold;
        }
        let qualifies = if self.shaped {
            per_conn_bps >= reference_bps * SHAPE_CLEAR_FRAC
        } else {
            per_conn_bps < reference_bps * SHAPE_RAISE_FRAC
        };
        if !qualifies {
            self.run = 0;
            self.run_stretches = 0;
            return ShapeVerdict::Hold;
        }
        if self.run == 0 || stretch != self.last_stretch {
            self.run_stretches += 1;
        }
        self.last_stretch = stretch;
        self.run += 1;
        if self.run >= SHAPE_QUORUM_EPOCHS && self.run_stretches >= SHAPE_QUORUM_STRETCHES {
            self.shaped = !self.shaped;
            self.run = 0;
            self.run_stretches = 0;
            return if self.shaped {
                ShapeVerdict::Raised
            } else {
                ShapeVerdict::Cleared
            };
        }
        ShapeVerdict::Hold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REF: f64 = 100e6;

    fn feed(d: &mut ShapeDetector, per_conn: f64, n: u32, stretch: u64) -> Vec<ShapeVerdict> {
        (0..n)
            .map(|_| d.on_epoch(per_conn, REF, stretch, true))
            .collect()
    }

    /// The Giganews shape: ~10-15% of reference, sustained. Ten epochs
    /// inside ONE stretch must not raise - one bad evening is one bad
    /// evening - and the flag comes up only once a second stretch
    /// corroborates.
    #[test]
    fn one_bad_stretch_never_raises() {
        let mut d = ShapeDetector::new(false);
        let v = feed(&mut d, 12e6, 30, 1);
        assert!(v.iter().all(|v| *v == ShapeVerdict::Hold), "{v:?}");
        assert!(!d.shaped());
        // A second stretch at the same decayed rate fills the quorum
        // as soon as both conditions hold.
        let v = feed(&mut d, 12e6, 5, 2);
        assert!(v.contains(&ShapeVerdict::Raised), "{v:?}");
        assert!(d.shaped());
    }

    /// A 20% dip is inside ordinary provider variation and must never
    /// trip the flag, however long it lasts or how many stretches it
    /// spans.
    #[test]
    fn a_twenty_percent_dip_is_not_shaping() {
        let mut d = ShapeDetector::new(false);
        for stretch in 1..=6u64 {
            let v = feed(&mut d, REF * 0.8, 20, stretch);
            assert!(v.iter().all(|v| *v == ShapeVerdict::Hold));
        }
        assert!(!d.shaped());
    }

    /// One healthy clean epoch resets the raise quorum: "10 consecutive"
    /// means consecutive.
    #[test]
    fn a_healthy_epoch_resets_the_run() {
        let mut d = ShapeDetector::new(false);
        feed(&mut d, 12e6, 9, 1);
        feed(&mut d, REF, 1, 2); // recovery blip
        let v = feed(&mut d, 12e6, 9, 2);
        assert!(v.iter().all(|v| *v == ShapeVerdict::Hold), "{v:?}");
        assert!(!d.shaped());
    }

    /// Contaminated epochs are not evidence in either direction - they
    /// neither advance nor reset the quorum.
    #[test]
    fn contaminated_epochs_change_nothing() {
        let mut d = ShapeDetector::new(false);
        feed(&mut d, 12e6, 9, 1);
        for _ in 0..50 {
            assert_eq!(d.on_epoch(REF, REF, 1, false), ShapeVerdict::Hold);
        }
        // The run survived the dirty stretch: one more qualifying epoch
        // in a second stretch completes both quorums.
        let v = feed(&mut d, 12e6, 1, 2);
        assert_eq!(v, vec![ShapeVerdict::Raised]);
    }

    /// Clearing needs the same quorum, judged against the CLEAR bar:
    /// recovery to 60% of reference is not recovery.
    #[test]
    fn clears_only_on_real_recovery() {
        let mut d = ShapeDetector::new(true);
        for stretch in 1..=4u64 {
            let v = feed(&mut d, REF * 0.6, 20, stretch);
            assert!(v.iter().all(|v| *v == ShapeVerdict::Hold));
        }
        assert!(d.shaped());
        feed(&mut d, REF * 0.9, 8, 5);
        let v = feed(&mut d, REF * 0.9, 5, 6);
        assert!(v.contains(&ShapeVerdict::Cleared), "{v:?}");
        assert!(!d.shaped());
    }

    /// A restart restores a persisted flag, and a fresh ladder
    /// reference clears everything.
    #[test]
    fn restart_and_reference_reset() {
        let mut d = ShapeDetector::new(true);
        assert!(d.shaped());
        d.reset_reference();
        assert!(!d.shaped());
        // And the raise quorum starts from zero afterwards.
        let v = feed(&mut d, 12e6, 9, 1);
        assert!(v.iter().all(|v| *v == ShapeVerdict::Hold));
    }
}
