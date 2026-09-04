//! TODO 112: the live connection tuner - tracking the knee in realtime.
//!
//! The offline ladder (`sysbench::conn_ladder`) measures a knee at setup
//! time; facts change (provider load, time of day, an external party on
//! the account). This module is the slow, epoch-based controller that
//! tracks it DURING real downloads: hold the fleet for an epoch, measure
//! delivered bytes, perturb by a step the verdict can actually see
//! (>= ~3% of the fleet, +/-1 on small fleets), keep what measured
//! better. The offline knee stays the prior; the account's configured
//! `connections` is the hard ceiling and is never written by anything
//! here - the target is state, not a setting.
//!
//! Everything the offline tuner's hardening taught is baked into the
//! shape (see the conn-tuner saga: JAGGED_BAR, the test that asserted
//! the noise, CLIMB_GAIN):
//!
//! - Provider throughput swings 2-3x minute to minute, so single
//!   readings decide nothing: a probe is PAIRED A/B epochs, repeated,
//!   and judged on the median - a slow drift hits both sides of a pair
//!   where it cannot masquerade as a verdict.
//! - Asymmetric bars, both defensible against the noise floor rather
//!   than precise-looking: an up-move must EARN its socket
//!   ([`UP_GAIN`]); a down-move needs the smaller fleet to have cost
//!   nearly nothing ([`DOWN_KEEP`]).
//! - A contaminated epoch (queue ran dry, rate limiter engaged, flap
//!   clamp, capacity refusal) does not bend a verdict - it ABORTS the
//!   whole cycle. A contaminated measurement is not a slightly-wrong
//!   measurement.
//! - Never probe upward unless the last full epoch was clean: an idle
//!   queue or an engaged limiter makes "more sockets" unmeasurable, and
//!   a capacity refusal makes it hostile.
//!
//! Decisions are a pure function of the observations fed in - no I/O,
//! no clocks - so every rule here is pinned by a unit test that cannot
//! be anything else (the wave-6 lesson: the pure test was right because
//! it could not assert the noise). The wall-clock rigs in
//! `tests/integration/live_tune.rs` only ask whether the whole thing hangs together
//! against a real pool and a mock provider.

/// Minimum relative gain an up-probe must show (median over pairs) to
/// be kept. 4% sits above the paired-epoch noise floor the rigs can
/// defend; the probe step scales with the fleet ([`UP_STEP_DIV`]) so
/// the expected below-knee gain (~6%) clears this bar at any size -
/// with a fixed +1 step, past ~25 connections a single socket's honest
/// contribution was inside the noise and the walk went blind.
pub const UP_GAIN: f64 = 1.04;

/// A -1 connection is kept while the smaller fleet still delivers at
/// least this fraction of the larger one's rate: below the knee one
/// socket is worth ~1/M of the rate, so a genuine knee-or-below fleet
/// fails this immediately and the down-walk stops.
pub const DOWN_KEEP: f64 = 0.985;

/// Fast path for gross mistuning: if the FIRST up pair alone gains this
/// much, keep it without waiting for the remaining pairs. A fleet far
/// below the knee gains ~1/M per socket (25% at 4), which no honest
/// noise band needs three pairs to see; near the knee this never fires
/// and the full-median path decides. A noise spike that sneaks one
/// up-move through is walked back by the next down cycle - the
/// asymmetry is safe because down cycles never use the fast path.
pub const EARLY_UP_GAIN: f64 = 1.15;

/// A/B pairs per probe cycle (median-of-3, the offline run-off's
/// best-of-three carried over).
pub const PAIRS: u32 = 3;

/// Probe step floor as a fraction of the current target: step >=
/// target/16 (~6%). This is the DETECTABILITY limit, not a speed knob:
/// below the knee a k-socket trim loses k/m of the rate, so a step
/// near m*(1-DOWN_KEEP) is invisible to the down verdict - at one
/// socket per cycle a 100-socket fleet could walk BELOW its knee
/// losing 1% per step forever, each step individually passing the bar
/// (the ratchet leak the 10 Aug five-client re-cut motivated fixing:
/// 360 vs 40 sockets ran the same wall, and +/-1 could neither trim
/// the surplus in useful time nor stop at the knee once it mattered).
/// A 6% floor costs ~6% when the trim is wrong, a 4.5-point margin
/// over DOWN_KEEP's 1.5% bar that paired-median noise cannot bridge;
/// at 3% the margin was 1.5 points and the rigs' own +/-2% wobble
/// could sneak a below-knee trim through. Small fleets (target < 16)
/// keep today's exact +/-1 behavior.
pub const STEP_FLOOR_DIV: usize = 16;

/// Probe step ceiling as a fraction of the current target (target/4):
/// however boosted, one cycle never wagers more than a quarter of the
/// fleet on a single verdict.
pub const STEP_CAP_DIV: usize = 4;

/// Up-probe step: target/16 (~6%). An up-move must clear UP_GAIN (4%),
/// and one socket's honest below-knee contribution is 1/m - so past
/// ~25 connections a +1 can never earn its keep and a fleet seeded
/// wrongly low would be stuck there. A 6% step clears the bar with
/// margin when sockets genuinely help and still reads ~0 above the
/// knee. No acceleration: over-asking is what providers punish, so
/// the up-walk earns every step at the same size.
pub const UP_STEP_DIV: usize = 16;

/// One measured epoch: everything the controller is allowed to know
/// about it. The caller owns HOW these are measured (which gauges,
/// which clock); the controller only ever sees this.
#[derive(Debug, Clone, Copy)]
pub struct EpochObs {
    /// Delivered bytes / elapsed for THIS server over the epoch.
    pub rate_bps: f64,
    /// The queue had work the whole epoch - a dry or near-dry queue
    /// measures the queue, not the line.
    pub busy: bool,
    /// The global rate limiter was engaged (or the aggregate sat at its
    /// cap): the line is not the binding constraint, so socket-count
    /// verdicts are meaningless.
    pub rate_limited: bool,
    /// This server is flap-clamped or saw a capacity refusal this
    /// epoch: the provider is already saying "fewer".
    pub capacity_pressure: bool,
    /// The fleet actually reached the target it was asked to run
    /// (connected >= desired for the measuring stretch). An epoch that
    /// never reached its fleet measures the ramp, not the rung.
    pub fleet_met: bool,
    /// A probe cycle may START on this epoch. The caller raises this on
    /// the SAME epochs for every server (a shared metronome), which is
    /// what makes multi-server down-probes share-neutral: on a shared
    /// saturated link a SOLO -k probe loses exactly its k/m share of
    /// the line to the servers holding steady, so the verdict reads
    /// "these sockets carried rate" for sockets that were pure surplus
    /// - measured live on a 10 GbE five-provider fleet: the first
    /// (accidentally synchronized) cycle trimmed all three fast hosts,
    /// then the phases diverged on differing verdicts and every later
    /// solo probe failed, freezing 340 sockets against a knee well
    /// under a hundred. With
    /// a common gate every server shrinks ~6% in the same epochs,
    /// shares stay proportional, and per-server rate stays flat until
    /// the FLEET reaches the collective knee. A shaped host still
    /// fails its own verdict inside the shared window (its per-conn
    /// rate cannot rise to compensate) and holds - the per-server
    /// guarantee survives synchronization.
    pub cycle_gate: bool,
    /// The link itself is the binding constraint this epoch (fleet
    /// aggregate at the learned link anchor). Up-probes are suppressed
    /// while it holds: at saturation a +k probe GAINS k-proportional
    /// share from every other server - a real measured gain on this
    /// server that bought the install nothing - and with proportional
    /// steps (~6%) that grab clears UP_GAIN, so an unguarded fleet
    /// would inflate back to its ceilings one share-theft at a time.
    /// When false (link not the constraint), an up-probe's gain is
    /// genuine new throughput and the walk is free to earn it.
    pub line_saturated: bool,
}

impl EpochObs {
    fn clean(&self) -> bool {
        self.busy && !self.rate_limited && !self.capacity_pressure && self.fleet_met
    }
}

/// Which side of the current target a cycle is probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Up,
    Down,
}

impl Dir {
    fn flip(self) -> Dir {
        match self {
            Dir::Up => Dir::Down,
            Dir::Down => Dir::Up,
        }
    }
}

#[derive(Debug)]
enum Phase {
    /// Sit at the kept target for `left` clean epochs before probing
    /// again - the heavy hysteresis. `next` is the direction the next
    /// cycle will try.
    Hold { left: u32, next: Dir },
    /// Mid-cycle: epochs alternate base target and base +/- step, one
    /// pair at a time, base first (`on_probe` flips every epoch).
    /// `step` is fixed for the whole cycle so every pair measures the
    /// same rung.
    Probe {
        dir: Dir,
        step: usize,
        on_probe: bool,
        base: Vec<f64>,
        probe: Vec<f64>,
    },
}

/// Per-server live tuner. Feed it one [`EpochObs`] per epoch; read
/// [`ServerTuner::desired`] afterwards and run the fleet there for the
/// next epoch.
#[derive(Debug)]
pub struct ServerTuner {
    /// The KEPT connection count - what the controller currently
    /// believes the knee to be.
    target: usize,
    /// Hard ceiling: the account's configured `connections` (or the
    /// spawned fleet size, whichever is smaller). Never exceeded, never
    /// written here.
    ceiling: usize,
    /// Clean epochs a fresh verdict must wait out between cycles.
    hold_epochs: u32,
    /// The down-probe step in sockets, doubled after every kept down
    /// verdict and halved after a failed one, always re-clamped to
    /// [target/STEP_FLOOR_DIV, target/STEP_CAP_DIV] (min 1) when a
    /// cycle starts. This is what turns "a surplus fleet trims" from a
    /// 30-hour +/-1 walk into a geometric one: 360 sockets against a
    /// knee of 40 converges in ~13 kept cycles, every one of them an
    /// earned median-of-pairs verdict.
    down_step: usize,
    /// Consecutive FAILED down cycles. Each one doubles the hold before
    /// the next (capped), because a failed down probe is not free: its
    /// probe epochs ran the fleet below the knee, ~6% under line, and a
    /// fleet parked AT its knee re-asking every window would pay ~2% of
    /// the line forever just to keep hearing "no". Reset by any kept
    /// verdict (the facts moved) and by capacity pressure (the provider
    /// moved them for us).
    down_fails: u32,
    phase: Phase,
}

impl ServerTuner {
    /// `prior` is the starting belief (the offline knee when one is
    /// trusted, else the configured count); `ceiling` the account fact.
    pub fn new(prior: usize, ceiling: usize, hold_epochs: u32) -> Self {
        let ceiling = ceiling.max(1);
        ServerTuner {
            target: prior.clamp(1, ceiling),
            ceiling,
            hold_epochs,
            down_step: 1,
            down_fails: 0,
            // Down first: freeing sockets the line does not need is the
            // cheap direction, and a too-high prior is the harmful one
            // (over-asking is what providers punish).
            phase: Phase::Hold {
                left: hold_epochs,
                next: Dir::Down,
            },
        }
    }

    /// The connection count the fleet should run at for the NEXT epoch.
    /// During a probe cycle this alternates between the base target and
    /// the perturbed rung; between cycles it is the kept target.
    pub fn desired(&self) -> usize {
        match &self.phase {
            Phase::Hold { .. } => self.target,
            Phase::Probe {
                dir,
                step,
                on_probe,
                ..
            } => {
                if *on_probe {
                    match dir {
                        Dir::Up => (self.target + step).min(self.ceiling),
                        Dir::Down => self.target.saturating_sub(*step).max(1),
                    }
                } else {
                    self.target
                }
            }
        }
    }

    /// The step a down cycle starting NOW would probe with: the boosted
    /// state clamped to the detectability floor and the wager cap for
    /// the current target.
    fn down_step_now(&self) -> usize {
        let floor = (self.target / STEP_FLOOR_DIV).max(1);
        let cap = (self.target / STEP_CAP_DIV).max(1);
        self.down_step.clamp(floor, cap)
    }

    fn up_step_now(&self) -> usize {
        (self.target / UP_STEP_DIV).max(1)
    }

    /// The kept target (what the controller believes, ignoring any
    /// in-flight perturbation).
    pub fn target(&self) -> usize {
        self.target
    }

    pub fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// Whether this controller is still answering the question the
    /// user's CURRENT setting asks.
    ///
    /// The ceiling is fixed at construction and every later clamp only
    /// narrows, so a controller cannot follow a raised connections
    /// count - the James shape, one layer up from the stored knee it
    /// was first found in: the typed number reaches the pool build and
    /// stops there, while the live target keeps walking inside the old
    /// ceiling. A caller that re-reads the setting each epoch asks
    /// this and rebuilds the controller when it says no; `new` applies
    /// the same `max(1)` the constructor does, so a nonsense 0 is not
    /// a change.
    pub fn ceiling_matches(&self, configured: usize) -> bool {
        self.ceiling == configured.max(1)
    }

    /// Feed the epoch that just finished, measured at the count
    /// [`ServerTuner::desired`] answered when it started.
    pub fn on_epoch(&mut self, obs: EpochObs) {
        // Capacity pressure is more than contamination: the provider
        // has vetoed the CURRENT size, so probing up is off the table
        // for a while and the belief itself steps down. This is the
        // live analogue of the 481/502 capacity yield, expressed as a
        // kept verdict instead of a one-way worker exit.
        if obs.capacity_pressure {
            // Scaled like a probe step: on a 300-socket fleet a -1
            // answer to a provider veto is no answer at all.
            let step = (self.target / STEP_FLOOR_DIV).max(1);
            self.target = self.target.saturating_sub(step).max(1);
            self.down_fails = 0;
            self.phase = Phase::Hold {
                left: self.hold_epochs.max(1) * 2,
                next: Dir::Down,
            };
            return;
        }
        if !obs.clean() {
            // A contaminated epoch aborts the cycle outright - and a
            // Hold does not tick down, so probing never starts on the
            // heels of dirt (the "never probe upward when the queue is
            // near empty / limiter engaged" rule falls out of this).
            if let Phase::Probe { dir, step, .. } = &self.phase {
                let (dir, step) = (*dir, *step);
                if dir == Dir::Down {
                    // A big down-step is itself a common CAUSE of dirt:
                    // the park wave has not drained by the epoch's end,
                    // fleet_met's band flags it, and an unchanged step
                    // would abort identically forever. Halve toward a
                    // size the fleet can actually settle into.
                    self.down_step = (step / 2).max(1);
                }
                self.phase = Phase::Hold {
                    left: self.hold_epochs,
                    next: Dir::Down,
                };
            }
            return;
        }
        match &mut self.phase {
            Phase::Hold { left, next } => {
                if *left > 0 {
                    *left -= 1;
                    return;
                }
                // Cycles start only on the caller's shared metronome,
                // so every server's probe epochs line up (see
                // EpochObs::cycle_gate for why that is load-bearing).
                if !obs.cycle_gate {
                    return;
                }
                let dir = *next;
                // At link saturation an up-probe can only share-grab
                // (see EpochObs::line_saturated); probe down instead.
                let dir = if obs.line_saturated { Dir::Down } else { dir };
                // A rung with no room in the probed direction flips.
                let dir = match dir {
                    Dir::Up if self.target >= self.ceiling => Dir::Down,
                    Dir::Down if self.target <= 1 => Dir::Up,
                    d => d,
                };
                if self.target >= self.ceiling && self.target <= 1 {
                    // ceiling 1: nothing to tune.
                    return;
                }
                if dir == Dir::Up && obs.line_saturated {
                    // target 1 under saturation: nowhere to go.
                    return;
                }
                let step = match dir {
                    Dir::Up => self.up_step_now(),
                    Dir::Down => self.down_step_now(),
                };
                self.phase = Phase::Probe {
                    dir,
                    step,
                    on_probe: true, // this epoch ran at base; next runs the probe rung
                    base: vec![obs.rate_bps],
                    probe: Vec::new(),
                };
            }
            Phase::Probe {
                dir,
                step,
                on_probe,
                base,
                probe,
            } => {
                if *on_probe {
                    probe.push(obs.rate_bps);
                } else {
                    base.push(obs.rate_bps);
                }
                let dir = *dir;
                let step = *step;
                if dir == Dir::Up && obs.line_saturated {
                    // Saturation arrived mid-cycle: whatever this
                    // up-probe is reading from here on is share-grab,
                    // not throughput. Abort rather than bend.
                    self.phase = Phase::Hold {
                        left: self.hold_epochs,
                        next: Dir::Down,
                    };
                    return;
                }
                // Early keep for gross under-tuning: the first complete
                // pair alone may be unambiguous.
                let early = dir == Dir::Up
                    && base.len() == 1
                    && probe.len() == 1
                    && probe[0] >= base[0] * EARLY_UP_GAIN;
                let full = base.len() >= PAIRS as usize && probe.len() >= PAIRS as usize;
                if !(early || full) {
                    *on_probe = !*on_probe;
                    return;
                }
                let gain = median(probe) / median(base).max(1.0);
                let (kept, next) = match dir {
                    Dir::Up if gain >= UP_GAIN => (Some(self.target + step), Dir::Up),
                    Dir::Down if gain >= DOWN_KEEP => {
                        (Some(self.target.saturating_sub(step).max(1)), Dir::Down)
                    }
                    d => (None, d.flip()),
                };
                // Step bookkeeping for the NEXT down cycle: a kept trim
                // doubles the wager (a surplus fleet converges
                // geometrically), a failed one halves it back toward
                // the floor (fine steps near the knee). The clamp in
                // down_step_now re-fences either against the target it
                // will actually probe from.
                if dir == Dir::Down {
                    self.down_step = if kept.is_some() {
                        step.saturating_mul(2)
                    } else {
                        (step / 2).max(1)
                    };
                }
                if let Some(t) = kept {
                    self.target = t.clamp(1, self.ceiling);
                    self.down_fails = 0;
                    // Momentum: a kept move re-probes the same
                    // direction immediately (the next shared gate) - a
                    // grossly mistuned fleet walks to the knee in
                    // consecutive cycles instead of one step per hold
                    // window.
                    self.phase = Phase::Hold { left: 0, next };
                } else {
                    // A failed DOWN was not free (its probe epochs ran
                    // below the knee), so consecutive ones back the
                    // re-ask off exponentially; a failed UP costs
                    // nothing and keeps the ordinary hold.
                    let hold = if dir == Dir::Down {
                        self.down_fails = (self.down_fails + 1).min(4);
                        self.hold_epochs << self.down_fails
                    } else {
                        self.hold_epochs
                    };
                    self.phase = Phase::Hold { left: hold, next };
                }
            }
        }
    }
}

fn median(xs: &[f64]) -> f64 {
    let mut v: Vec<f64> = xs.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    if v.is_empty() {
        return 0.0;
    }
    let mid = v.len() / 2;
    if v.len() % 2 == 1 {
        v[mid]
    } else {
        (v[mid - 1] + v[mid]) / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A provider model in one closure: rate for a fleet of `m` on a
    /// line whose knee is `knee`, with a deterministic "noise" wobble
    /// per epoch so no verdict can lean on exact equality. The wobble
    /// (+/-2%) is BELOW both bars on purpose - these tests pin the
    /// decision rules, the rigs pin behaviour under real jitter.
    fn drive(t: &mut ServerTuner, knee: usize, epochs: usize, seed: &mut u32) {
        for _ in 0..epochs {
            let m = t.desired();
            let r = (m.min(knee)) as f64 * 1_000_000.0;
            // xorshift, deterministic: +/-2%.
            *seed ^= *seed << 13;
            *seed ^= *seed >> 17;
            *seed ^= *seed << 5;
            let wobble = 1.0 + ((*seed % 400) as f64 - 200.0) / 10_000.0;
            t.on_epoch(EpochObs {
                rate_bps: r * wobble,
                busy: true,
                rate_limited: false,
                capacity_pressure: false,
                fleet_met: true,
                cycle_gate: true,
                line_saturated: false,
            });
        }
    }

    #[test]
    fn converges_up_from_a_low_prior() {
        let mut t = ServerTuner::new(4, 30, 2);
        let mut seed = 0x1234_5678;
        drive(&mut t, 12, 400, &mut seed);
        assert!(
            (11..=13).contains(&t.target()),
            "stopped at {} against a knee of 12",
            t.target()
        );
    }

    #[test]
    fn converges_down_from_a_high_prior() {
        let mut t = ServerTuner::new(24, 30, 2);
        let mut seed = 0x0dd_ba11;
        drive(&mut t, 12, 400, &mut seed);
        assert!(
            (11..=13).contains(&t.target()),
            "stopped at {} against a knee of 12",
            t.target()
        );
    }

    /// The no-oscillation gate in pure form: a fleet already at the
    /// knee on a flat healthy line must not walk anywhere, however long
    /// it runs - the noise-chasing failure the offline tuner's history
    /// warns about.
    #[test]
    fn a_flat_line_at_the_knee_holds_steady() {
        let mut t = ServerTuner::new(12, 30, 2);
        let mut seed = 0xbeef_cafe;
        for _ in 0..10 {
            drive(&mut t, 12, 100, &mut seed);
            assert!(
                (11..=13).contains(&t.target()),
                "walked to {} on a flat line",
                t.target()
            );
        }
    }

    /// The ceiling is the account fact: however hungry the line, the
    /// controller never asks past it - and a prior above it is clamped
    /// on construction.
    #[test]
    fn the_ceiling_is_absolute() {
        let mut t = ServerTuner::new(50, 8, 2);
        assert_eq!(t.target(), 8);
        let mut seed = 0x5eed;
        drive(&mut t, 100, 300, &mut seed); // knee far above the ceiling
        assert_eq!(t.target(), 8);
        assert!(t.desired() <= 8);
    }

    /// Dirty epochs decide nothing and abort in-flight cycles: feed a
    /// mistuned fleet nothing but starved epochs and it must not move.
    #[test]
    fn starved_or_limited_epochs_never_move_the_target() {
        for (busy, limited) in [(false, false), (true, true)] {
            let mut t = ServerTuner::new(4, 30, 2);
            for _ in 0..100 {
                let m = t.desired();
                t.on_epoch(EpochObs {
                    rate_bps: m as f64 * 1_000_000.0,
                    busy,
                    rate_limited: limited,
                    capacity_pressure: false,
                    fleet_met: true,
                    cycle_gate: true,
                    line_saturated: false,
                });
            }
            assert_eq!(t.target(), 4, "moved on dirty epochs (busy={busy})");
        }
    }

    /// Capacity pressure steps the belief DOWN and parks the tuner -
    /// the provider said "fewer", which outranks any measurement.
    #[test]
    fn capacity_pressure_steps_down_and_holds() {
        let mut t = ServerTuner::new(12, 30, 2);
        t.on_epoch(EpochObs {
            rate_bps: 0.0,
            busy: true,
            rate_limited: false,
            capacity_pressure: true,
            fleet_met: false,
            cycle_gate: true,
            line_saturated: false,
        });
        assert_eq!(t.target(), 11);
        assert_eq!(t.desired(), 11);
    }

    /// Rig 2 in pure form: the line's capacity changes mid-run and the
    /// controller re-converges - the facts-on-the-ground-changed case.
    #[test]
    fn reconverges_when_the_knee_moves() {
        let mut t = ServerTuner::new(6, 30, 2);
        let mut seed = 0x00c0_ffee;
        drive(&mut t, 6, 300, &mut seed);
        assert!((5..=7).contains(&t.target()), "phase 1: {}", t.target());
        // The provider frees capacity: the knee doubles.
        drive(&mut t, 14, 500, &mut seed);
        assert!(
            (13..=15).contains(&t.target()),
            "did not follow the knee up: {}",
            t.target()
        );
        // And tightens again.
        drive(&mut t, 8, 500, &mut seed);
        assert!(
            (7..=9).contains(&t.target()),
            "did not follow the knee down: {}",
            t.target()
        );
    }

    /// The James case for the LIVE layer, in the shape the daemon's
    /// epoch loop uses it: the user raises connections mid-session.
    /// The controller's own ceiling can never grow, so the loop asks
    /// `ceiling_matches` against the freshly read setting and rebuilds
    /// when it says no. What that has to buy: the typed number runs on
    /// the very next epoch, and the fleet can then walk ABOVE the
    /// ceiling it had been living under - without the rebuild it stays
    /// pinned there forever, which is the whole complaint.
    #[test]
    fn a_raised_setting_rebuilds_the_controller_and_frees_the_walk() {
        let mut seed = 0xfeed_1234;
        let mut t = ServerTuner::new(6, 6, 2);
        drive(&mut t, 3, 200, &mut seed);
        assert!((2..=4).contains(&t.target()), "phase 1: {}", t.target());
        assert!(t.ceiling_matches(6));

        // Settings: 6 -> 24.
        assert!(!t.ceiling_matches(24), "a raised setting must be noticed");
        if !t.ceiling_matches(24) {
            t = ServerTuner::new(24, 24, 3);
        }
        assert_eq!(
            t.desired(),
            24,
            "the number the user typed runs on the next epoch"
        );

        // And the walk is no longer fenced by the old ceiling.
        drive(&mut t, 20, 400, &mut seed);
        assert!(
            t.target() > 6,
            "still fenced by the retired ceiling at {}",
            t.target()
        );
        assert!((19..=21).contains(&t.target()), "phase 2: {}", t.target());
    }

    /// The 10 Aug five-client re-cut in pure form: 360 sockets and 40
    /// sockets ran the same wall, so a fleet pinned at the published
    /// maxima is carrying ~320 sockets of pure CPU overhead. The
    /// controller must trim a large surplus fleet down to the knee in
    /// useful time - the accelerating step makes this geometric, and
    /// every step is still an earned median-of-pairs verdict.
    #[test]
    fn a_big_surplus_fleet_trims_to_the_knee_fast() {
        let mut t = ServerTuner::new(360, 360, 2);
        let mut seed = 0xa11_0c8e;
        let mut epochs_to_band = None;
        for e in 0..400 {
            drive(&mut t, 40, 1, &mut seed);
            if epochs_to_band.is_none() && t.target() <= 48 {
                epochs_to_band = Some(e + 1);
            }
        }
        assert!(
            (40..=48).contains(&t.target()),
            "settled at {} against a knee of 40",
            t.target()
        );
        let reached = epochs_to_band.expect("never reached the knee band");
        // ~10 kept cycles of 6 epochs each, plus the noise tax: near
        // the knee a genuine trim's gain sits at ~1.0 and the +/-2%
        // wobble spuriously fails ~1 in 5 of them (each fail costs a
        // hold and halves the step). Measured ~170 under this rig's
        // wobble; the bound pins the ORDER: geometric, not +/-1
        // (which would need ~1900 epochs to walk 320 sockets).
        assert!(
            reached <= 220,
            "took {reached} epochs to trim 360 -> <=48 - the walk is not geometric"
        );
    }

    /// The ratchet leak the proportional floor exists to close: on a
    /// large fleet sitting AT its knee, a -1 probe loses only 1/m of
    /// the rate - inside DOWN_KEEP's bar for m > ~67 - so the old
    /// fixed-step walk would keep every step and creep below the knee
    /// indefinitely, 1% of the line at a time. The floored step makes
    /// a below-knee trim cost ~3%, which the bar rejects.
    #[test]
    fn a_large_fleet_at_the_knee_does_not_creep_below_it() {
        let mut t = ServerTuner::new(100, 100, 2);
        let mut seed = 0xc4ee_9001;
        drive(&mut t, 100, 600, &mut seed);
        assert!(
            t.target() >= 92,
            "crept to {} on a fleet whose knee is its size",
            t.target()
        );
    }

    /// The giganews shape (nzbfast-giganews-shaping): a per-connection
    /// shaped host delivers rate proportional to sockets with no knee
    /// in reach, so every socket is genuinely needed - the trim must
    /// hold such a fleet, not bank its CPU. Modeled as a knee far above
    /// the ceiling: every down-probe loses its full share and fails.
    #[test]
    fn a_per_conn_shaped_host_keeps_its_needed_fleet() {
        let mut t = ServerTuner::new(100, 100, 2);
        let mut seed = 0x5a4e_d000;
        drive(&mut t, 1000, 400, &mut seed);
        assert_eq!(
            t.target(),
            100,
            "trimmed a fleet where every socket carries rate"
        );
    }

    /// The recovery direction after a trim, at scale: a fleet seeded
    /// far below a large knee must be able to EARN its way back up -
    /// with a fixed +1 step the 4% bar went blind past ~25 sockets and
    /// a wrongly-low seed was permanent.
    #[test]
    fn a_big_fleet_seeded_low_climbs_back_to_a_high_knee() {
        let mut t = ServerTuner::new(40, 360, 2);
        let mut seed = 0x0c11_3b12;
        drive(&mut t, 200, 600, &mut seed);
        assert!(
            t.target() >= 180,
            "stuck at {} against a knee of 200",
            t.target()
        );
    }

    /// Shared-line waterfill: each server offers m_i * percap_i;
    /// if the sum exceeds the line, per-conn-capped servers keep
    /// min(offer, fair share) and the elastic remainder splits the
    /// rest by socket count - the TCP-fairness cartoon the live
    /// shared-line stall was measured against.
    fn shared_rates(fleets: &[(usize, f64)], line: f64) -> Vec<f64> {
        let offers: Vec<f64> = fleets.iter().map(|(m, cap)| *m as f64 * cap).collect();
        let total: f64 = offers.iter().sum();
        if total <= line {
            return offers;
        }
        // One waterfill pass is enough for these tests: servers whose
        // offer is under their socket-proportional share keep it, the
        // rest split the remainder by sockets.
        let msum: f64 = fleets.iter().map(|(m, _)| *m as f64).sum();
        let mut rates = vec![0.0; fleets.len()];
        let mut spare = line;
        let mut elastic_m = 0.0;
        for (i, (m, _)) in fleets.iter().enumerate() {
            let fair = *m as f64 / msum * line;
            if offers[i] <= fair {
                rates[i] = offers[i];
                spare -= offers[i];
            } else {
                elastic_m += *m as f64;
            }
        }
        for (i, (m, _)) in fleets.iter().enumerate() {
            if rates[i] == 0.0 {
                rates[i] = *m as f64 / elastic_m * spare;
            }
        }
        rates
    }

    /// Drive N tuners against one shared line for `epochs`, with the
    /// caller's gate cadence and saturation flag computed per epoch.
    fn drive_shared(
        tuners: &mut [ServerTuner],
        percaps: &[f64],
        line: f64,
        epochs: usize,
        sync: u64,
        seed: &mut u32,
    ) {
        for e in 0..epochs {
            let fleets: Vec<(usize, f64)> = tuners
                .iter()
                .zip(percaps)
                .map(|(t, c)| (t.desired(), *c))
                .collect();
            let rates = shared_rates(&fleets, line);
            let total: f64 = rates.iter().sum();
            let saturated = total >= line * 0.85;
            for (i, t) in tuners.iter_mut().enumerate() {
                *seed ^= *seed << 13;
                *seed ^= *seed >> 17;
                *seed ^= *seed << 5;
                let wobble = 1.0 + ((*seed % 400) as f64 - 200.0) / 10_000.0;
                t.on_epoch(EpochObs {
                    rate_bps: rates[i] * wobble,
                    busy: true,
                    rate_limited: false,
                    capacity_pressure: false,
                    fleet_met: true,
                    cycle_gate: (e as u64).is_multiple_of(sync),
                    line_saturated: saturated,
                });
            }
        }
    }

    /// The measured shared-line stall, pinned: two elastic servers on a
    /// saturated shared line. WITHOUT the shared gate (every server
    /// free-running), phases diverge after the first verdicts and a
    /// solo down-probe loses its share of the line to the holder, so
    /// the fleet freezes far above the collective knee. WITH the gate,
    /// probes coincide, shares stay proportional, and the fleet trims
    /// to ~the knee. One test, both halves - the gate must MATTER.
    #[test]
    fn synchronized_gates_trim_a_shared_saturated_line() {
        // Two servers, 100 sockets each; per-conn capacity 1.0; line
        // 40: collective knee = 40 sockets total.
        let mut seed = 0x51ac_e001;
        let mut tuners = vec![ServerTuner::new(100, 100, 2), ServerTuner::new(100, 100, 2)];
        drive_shared(&mut tuners, &[1.0, 1.0], 40.0, 700, 8, &mut seed);
        let total: usize = tuners.iter().map(|t| t.target()).sum();
        assert!(
            total <= 60,
            "gated fleet kept {total} sockets against a collective knee of 40 ({} + {})",
            tuners[0].target(),
            tuners[1].target()
        );
        assert!(total >= 38, "gated fleet cut into the knee: {total}");
    }

    /// The giganews guard inside the shared window: a per-conn-shaped
    /// host on the same saturated line as an elastic one. The shaped
    /// host's rate falls with every socket it gives up (its per-conn
    /// cannot rise to compensate), so ITS verdicts fail and it keeps
    /// its fleet while the elastic host absorbs the trim.
    #[test]
    fn a_shaped_host_keeps_its_fleet_inside_the_shared_window() {
        // Server 0: shaped, 100 sockets at 0.15/conn = 15 total,
        // always under its fair share (needs every socket).
        // Server 1: elastic, 100 sockets at 1.0/conn on a line of 40.
        let mut seed = 0x9a4e_d0d0;
        let mut tuners = vec![ServerTuner::new(100, 100, 2), ServerTuner::new(100, 100, 2)];
        drive_shared(&mut tuners, &[0.15, 1.0], 40.0, 700, 8, &mut seed);
        assert!(
            tuners[0].target() >= 85,
            "trimmed a shaped host to {} - every one of its sockets carried rate",
            tuners[0].target()
        );
        assert!(
            tuners[1].target() <= 45,
            "the elastic host kept {} sockets beside a 25-socket need",
            tuners[1].target()
        );
    }

    /// The inflation guard: a fleet at the collective knee on a
    /// saturated line must not walk UP - at saturation a solo up-probe
    /// gains share, not throughput, and with proportional steps that
    /// grab clears UP_GAIN. line_saturated parks the up-walk.
    #[test]
    fn saturation_parks_the_up_walk() {
        let mut seed = 0x0bad_9a1b;
        let mut tuners = vec![ServerTuner::new(25, 100, 2), ServerTuner::new(25, 100, 2)];
        drive_shared(&mut tuners, &[1.0, 1.0], 40.0, 500, 8, &mut seed);
        for t in &tuners {
            assert!(
                t.target() <= 27,
                "walked up to {} on a saturated line - share-grab inflation",
                t.target()
            );
        }
    }

    /// A ceiling of one is not tunable and must simply sit still.
    #[test]
    fn a_single_connection_account_is_left_alone() {
        let mut t = ServerTuner::new(1, 1, 2);
        let mut seed = 3;
        drive(&mut t, 10, 100, &mut seed);
        assert_eq!(t.target(), 1);
        assert_eq!(t.desired(), 1);
    }
}
