//! How wide the create's fold runs, and what is allowed to move that
//! width once it has been chosen.
//!
//! Two rules live here and they are separate on purpose, measured apart
//! and reaching their widths by different means: the FUSED window loop's
//! feedback pacer ([`paced_width`], stepped per window against the chain
//! it just raced) and the BATCHED path's a-priori rule
//! ([`apriori_fold_width`] and [`BatchFoldPacer`], one width decided
//! before the first batch from figures the planner already has and never
//! re-estimated). Each doc comment below carries the round it came from;
//! [`create_batch_fold_pacing_enabled`]'s in particular records the two
//! feedback pacers that were built for the batched path and LOST, which
//! nobody should re-derive.
//!
//! Split out of `par2gen.rs` on 17 Sep 2026 for that file's 4,000-line
//! ceiling (claim `par2gen-size-ceiling-split-17sep`). A move and not a
//! rewrite: every function, constant, doc essay and test below is the
//! one that was in the parent, with only the visibility and path
//! qualifiers a module boundary forces.

use super::CreateControl;
use super::scan;

/// Fold pacing (13 Sep 2026), ON by default; `NZBFAST_CREATE_FOLD_PACING=0`
/// is the A/B arm. A fused create is bound by the whole-file MD5 chain
/// (one serial thread) and its fold overlaps that chain window by window;
/// wherever the fold finishes well inside the chain, its extra workers
/// buy nothing and, on a box without cores to spare, the OS shares the
/// chain's core with them. The pacer measures both per window and
/// narrows the fold to the width that still keeps pace. Measured on an
/// 8-vCPU Zen 4 VM, 8.86 GB one file at 5%: 13.26 s at eight workers
/// against 11.91 at four with everything else equal - see `paced_width`.
pub(super) fn create_fold_pacing_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NZBFAST_CREATE_FOLD_PACING").is_none_or(|v| v != "0"))
}

/// The BATCHED create's fold-width rule, ON by default since 16 Sep 2026
/// (it was off for part of that day - see below);
/// `NZBFAST_CREATE_BATCH_FOLD_PACING=0` is the A/B arm. Separate from the
/// knob above, which governs the FUSED window pacer, because the two
/// were measured apart and reach their widths by different means.
///
/// # Two feedback pacers were built here and both LOST
///
/// On an 8-vCPU Zen 4 VM, 8.86 GB single file at 5%, `-m200` (three
/// batches), three mirrored reps per arm, one binary per arm: a pacer
/// that narrowed at batch boundaries from the chain's measured rate read
/// 14.40 s median against 13.60 s with it inert, and a corrected target
/// (the fold's whole remaining wall rather than one batch's) 14.30 s.
/// Both walked all the way down to [`PACED_WIDTH_FLOOR`] (`8 -> 2` and
/// `8 -> 4 -> 2`), and the fold, not the chain, became the pole.
/// The loop is unstable for a reason its arithmetic cannot see. The
/// chain's remaining wall was extrapolated from a chain rate measured
/// WHILE the fold competed with that same chain; the rate is the starved
/// one, so the remaining wall is over-stated, so the width sheds too
/// many workers, so the chain speeds up and the next estimate is wrong
/// the same way. And the first batch - 3.1-3.8 s of a ~13.6 s create,
/// 27% - runs at full width whatever the loop learns afterwards, which
/// is precisely why `-t4` wins: it is narrow from the start. **Nobody
/// should re-derive the feedback loop.**
///
/// # What is here instead
///
/// [`apriori_fold_width`] picks ONE width before the first batch, from
/// the recovery rows and the member lengths the planner already has, and
/// nothing measured at run time moves it again. The only thing that
/// moves the cap afterwards is the chain FINISHING, which is an event
/// and not an estimate. research/PARFAST-BATCHED-CREATE-FOLD-PACER-2026-09-15.md.
fn create_batch_fold_pacing_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var_os("NZBFAST_CREATE_BATCH_FOLD_PACING").is_none_or(|v| v != "0")
    })
}

/// The fold width the next window should run at, given that this window
/// folded in `fold` on `width` workers while the chain took `chain`.
///
/// The target is a fold at ~80% of the chain: short enough that a slow
/// window does not poke past the chain and lengthen the wall, long
/// enough that the workers freed are real. The step is proportional
/// (fold time is near enough 1/width over the band this walks) so eight
/// workers reach four in one or two windows, and a fold that has crept
/// within 90% of the chain snaps back to the full width at once - the
/// asymmetry is deliberate: over-shedding costs wall, under-shedding
/// costs only the gain. Floor of [`PACED_WIDTH_FLOOR`] so the fold never
/// becomes the pole on a two-core box by this hand; ceiling `max`, the
/// published width.
pub(super) fn paced_width(
    width: usize,
    max: usize,
    fold: std::time::Duration,
    chain: std::time::Duration,
) -> usize {
    let max = max.max(1);
    if chain.is_zero() || fold.is_zero() {
        return width.clamp(1, max);
    }
    // Integer nanoseconds throughout, so the 90% and 70% edges are exact
    // (90 ms over 100 ms is 0.8999.. as an f64 and missed the snap-back
    // in the first cut of the test below).
    let (fold, chain) = (fold.as_nanos(), chain.as_nanos());
    if fold * 10 >= chain * 9 {
        return max;
    }
    if fold * 10 >= chain * 7 {
        return width.clamp(1, max);
    }
    // Under 70%: the fold has slack. Aim it at 80% of the chain -
    // ceil(width * fold / (0.8 * chain)).
    let want = (width as u128 * fold * 10).div_ceil(chain * 8) as usize;
    want.clamp(PACED_WIDTH_FLOOR.min(max), max).min(width)
}

/// The fewest fold workers [`paced_width`] ever narrows a create to. Public
/// because a queue deciding whether a box has the cores for a second create
/// (apps/parfast `parfast-session`'s `pairing`) needs the same floor rather
/// than a second literal of it.
pub const PACED_WIDTH_FLOOR: usize = 2;

/// Recovery rows ONE fold worker keeps up with while the whole-file MD5
/// chain makes ONE pass over the same bytes - the only machine constant
/// the a-priori width needs, and `None` on a fold kernel whose rate
/// against MD5 nobody here has measured.
///
/// # Where the number comes from, and why it is a ratio
///
/// A batched create's fold work is `rows * payload` bytes of GF
/// multiply-accumulate; its chain's is one MD5 pass over the payload. So
/// the width at which the fold still lands inside the chain is
/// `rows / (fold rate per worker / MD5 rate)` - **the payload cancels**,
/// and the whole a-priori decision reduces to the recovery row count
/// over this one dimensionless ratio. It therefore carries from the
/// shape it was measured on to any payload size on the same kernel,
/// which is the reason for stating it this way round rather than as two
/// byte rates.
///
/// Measured on an 8-vCPU Zen 4 VM (EPYC 9354P, the 512-bit GFNI fold),
/// 8,858,370,048 bytes, 100 recovery rows, `-m200 -t4`: the three batch
/// walls were 3.49 / 2.59 / 3.05 s on four workers, so one worker folds
/// `100 * 8.858e9 / (9.13 * 4)` = 24.3 GB/s; the same box's chain runs
/// 8.858e9 bytes in 11.37-11.71 s on the fused route, uncontended, so
/// 0.767 GB/s. The ratio is **31.6 rows per worker per chain pass**, and
/// the constant is that at the same 80% target [`paced_width`] aims at:
/// `0.8 * 31.6` = 25. On the measured shape it returns exactly the width
/// `-t4` reaches by hand.
///
/// # Why a kernel gets `None`, and what a new arm must show
///
/// MD5's single-core rate is within about 1.3x everywhere (a serial
/// 64-byte dependency chain), but the GF16 fold's is not, so a constant
/// calibrated on one kernel applied to a slower one asks for a fold too
/// narrow to keep up and the FOLD becomes the pole - the exact
/// regression the feedback pacers shipped. **That was an argument when
/// written and is a measurement now**: on a Xeon D-1531 (AVX2, no GFNI)
/// this GFNI constant's `ceil(100 / 25)` = 4 workers reads **39.43 s
/// against the unnarrowed box's 28.63** on the same fixture, a 38%
/// regression (16 Sep 2026).
///
/// **A ratio is not enough to write an arm: the per-worker fold rate
/// must also be FLAT across the band the rule picks from**, which is
/// what makes "rows per worker" a property of the worker rather than of
/// how many you started. It is free, being the same `-t` sweep the two
/// rates need anyway. NEON passes inside 5%. The nibble kernel
/// fails by 2.7x: 8.04 GB/s per worker at two workers falling to 3.03 at
/// twelve, because that fold is bandwidth-saturated at about six (its
/// AGGREGATE is flat at 35-37 GB/s from six up). The ratio you measure
/// is then a function of the width you measured at (11.8 at four
/// workers, 16.9 at two), so any constant is applied where it is false.
/// **The nibble kernel is measured and REFUSES one**, not unvisited; its
/// arm would have LOOKED harmless too, `0.8 * 11.8` = 9 giving the whole
/// box until the row count halved. The GATE has to decline, not the
/// arithmetic.
///
/// **256-bit GFNI is UNREACHED**, not estimated and not inferred from
/// the 512-bit arm: the fleet's one GFNI-without-AVX-512 part had its
/// rig lock held all day (16 Sep 2026). A forced arm
/// (`NZBFAST_GF16_FORCE`, `NZBFAST_GF16_AVX512=0`) on a faster part is a
/// ratio between two settings of one kernel, not that part's rate, so it
/// cannot stand in - `gf16.rs` says so at the knob.
///
/// # NEON (aarch64), measured 16 Sep 2026
///
/// Same method and the same fixture byte for byte, on an Apple M1 Ultra
/// (16 P + 4 E cores, 64 GB): `-m200 -t4` over three reps folds
/// `100 * 8.858e9 / (9.660 * 4)` = **22.9 GB/s** per worker, and three
/// fused legs put the chain at 13.61-13.65 s over the same bytes, so
/// **0.650 GB/s**. The ratio is **35.3 rows per worker per chain pass** -
/// HIGHER than the 512-bit GFNI box's 31.6, because this part's MD5 is
/// the slower of the two (0.650 against 0.767) while its fold is nearly
/// as fast. At the same 80% target, `0.8 * 35.3` = 28. Flatness there
/// reads 23.5 / 23.0 / 22.9 / 22.5 / 22.3 GB/s per worker at widths 2 to
/// 6, falling away only past the P-core count.
///
/// **Accepted on 12 mirrored pairs**, one binary with this knob the only
/// difference: `ceil(100 / 28)` = 4 of 20 published a priori on every
/// leg, the rule wins **9 of 12**, median **13.945 s against 14.18**
/// (-1.7%), fused control unchanged. Thinner than the GFNI arm's -3.9%
/// because a 20-core box has less contention to recover, the fold
/// already sitting well inside the chain at full width. It is also far
/// TIGHTER than the width it replaces (13.91-13.96 against 13.74-14.71);
/// the three pairs it loses are the three legs where the unnarrowed fold
/// landed in its fast mode.
///
/// Measured on ONE Apple generation (the two later parts on hand were
/// build machines above load 40 all round), so whether the ratio belongs
/// to the KERNEL or the PART is open on aarch64, and the error is safe
/// only if a later part's ratio is HIGHER - which nothing establishes.
/// research/PARFAST-BATCHED-CREATE-FOLD-PACER-2026-09-15.md.
fn fold_rows_per_worker_per_chain_pass() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::gf16::avx512_gfni_available() {
            return Some(25);
        }
        // The 256-bit GFNI and nibble kernels are NOT this and are not
        // guessed from it: one is unreached, the other measured and
        // refusing a constant. See the doc above.
        None
    }
    // NEON is baseline on aarch64 and the fold has no runtime dispatch
    // there, so the arch IS the kernel: `gf16::xor_mul_multi` has one
    // arm on this target, which every Apple, Graviton and Snapdragon
    // part takes.
    #[cfg(target_arch = "aarch64")]
    {
        Some(28)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        None
    }
}

/// The bytes of ONE whole-file MD5 chain pass a batched create actually
/// waits on.
///
/// NOT the sum of the member lengths on a many-member set: `scan_all`
/// runs one chain per MEMBER on `outer` file-level workers, so those
/// chains run BESIDE each other and the wall is the makespan of that
/// schedule. `max(largest member, total / outer)` is the standard lower
/// bound on it, and a lower bound is the conservative reading here -
/// under-stating the chain asks for a WIDER fold, which costs the gain
/// and never the wall. For the single-member set this rule was measured
/// on, both terms are the whole payload and this is an identity.
fn chain_pass_bytes(lengths: &[u64], outer: usize) -> u64 {
    let total = lengths.iter().copied().fold(0u64, u64::saturating_add);
    let largest = lengths.iter().copied().max().unwrap_or(0);
    largest.max(total / (outer.max(1) as u64))
}

/// The fold width a batched (memory-capped) create runs at, decided
/// BEFORE the first batch and never moved by anything it then measures.
///
/// `recovery_rows` rows folded over `payload_bytes`, against a chain of
/// `chain_bytes` ([`chain_pass_bytes`]), on a box offering `max`
/// workers. See [`fold_rows_per_worker_per_chain_pass`] for the
/// derivation and for the kernels this declines to narrow on, and
/// [`create_batch_fold_pacing_enabled`] for why there is no feedback
/// term. `max` (no narrowing) whenever an input is missing or zero: an
/// unknown is never an argument for shedding workers.
fn apriori_fold_width(
    recovery_rows: u64,
    payload_bytes: u64,
    chain_bytes: u64,
    max: usize,
) -> usize {
    apriori_fold_width_from(
        fold_rows_per_worker_per_chain_pass(),
        recovery_rows,
        payload_bytes,
        chain_bytes,
        max,
    )
}

/// [`apriori_fold_width`] with the KERNEL VERDICT handed in - split out
/// for the same reason [`apriori_fold_width_for`] is, and for one more:
/// `None` (a kernel nobody measured) must read as the whole box, and
/// until this split that claim could only be asserted on a box that
/// happened to BE such a part: on a measured kernel the test silently
/// exercised the other branch, where a mistake would do the damage.
fn apriori_fold_width_from(
    rows_per_worker: Option<u64>,
    recovery_rows: u64,
    payload_bytes: u64,
    chain_bytes: u64,
    max: usize,
) -> usize {
    match rows_per_worker {
        Some(rows_per_worker) => apriori_fold_width_for(
            recovery_rows,
            payload_bytes,
            chain_bytes,
            rows_per_worker,
            max,
        ),
        None => max.max(1),
    }
}

/// [`apriori_fold_width`]'s arithmetic with the machine constant handed
/// in - split out so the RULE can be pinned by a test on every box in
/// the fleet, and not only on one that dispatches to the kernel the
/// constant was measured on.
fn apriori_fold_width_for(
    recovery_rows: u64,
    payload_bytes: u64,
    chain_bytes: u64,
    rows_per_worker: u64,
    max: usize,
) -> usize {
    let max = max.max(1);
    if recovery_rows == 0 || payload_bytes == 0 || chain_bytes == 0 || rows_per_worker == 0 {
        return max;
    }
    // W >= rows * (payload / chain) / rows_per_worker, in integers so a
    // set whose fold is a hair over a worker's keep-up gets that worker.
    let want = (u128::from(recovery_rows) * u128::from(payload_bytes))
        .div_ceil(u128::from(chain_bytes) * u128::from(rows_per_worker));
    let want = want.min(max as u128) as usize;
    // The floor bounds the damage of a constant that is wrong for this
    // box in the dangerous direction, exactly as it does for the fused
    // pacer: the fold never becomes the pole by this hand.
    want.clamp(PACED_WIDTH_FLOOR.min(max), max)
}

/// The batched (memory-capped) create path's fold-width rule, split out
/// of [`super::create_body`] for the 500-line function ceiling - not
/// because it is reused anywhere else.
///
/// `fused_scan.is_none()` means the whole-file MD5 chain runs on its own
/// thread in `scan_all`, beside these batches' folds, and the fused
/// window loop's own pacer (`paced_width`, `mem::FoldWidthCap`) never
/// reaches it - there is no per-window chain join to time there. This
/// narrows the SAME cap, once, from [`apriori_fold_width`], published
/// before the first batch so that batch is paced too. **There is no
/// feedback term and there must not be one**: two were built here and
/// both walked to the floor and lost, for reasons
/// [`create_batch_fold_pacing_enabled`] records.
///
/// The one thing that moves the cap after that is the chain FINISHING,
/// which is an event and not an estimate: there is then nothing left to
/// pace against, so the remaining batches get the whole box back.
///
/// Inert (`cap` is `None`) when pacing is off, when no independent scan
/// thread is running, or when the a-priori width IS the ceiling - every
/// method is then a cheap no-op, so a caller never has to branch on
/// whether pacing is active.
pub(super) struct BatchFoldPacer {
    cap: Option<crate::mem::FoldWidthCap>,
    /// The block-digest lanes' a-priori width, handed to `scan_all` -
    /// `None` where the rule declines to narrow. It is decided HERE,
    /// in the same breath as the fold's and FROM the fold's, because
    /// the two widths are one decision about one box: see
    /// `scan::apriori_scan_lane_width_for`. Nothing moves it again
    /// either, and it has no restore: the lanes are spawned once.
    lanes: Option<usize>,
    /// Whether the RULE ran, which is not the same as whether it
    /// narrowed: a rule that chose the whole box publishes no cap and
    /// still has a reading worth printing.
    active: bool,
    max: usize,
    width: usize,
    moves: usize,
}

impl BatchFoldPacer {
    /// `chain_beside` is the caller's one fact - an independent
    /// whole-file chain is running in `scan_all`, so there is something
    /// to pace against and cores handed back reach it. Both widths are
    /// this module's, from [`apriori_fold_width`] over what the planner
    /// already knows and from `scan::apriori_scan_lane_width` over that
    /// answer. The two knobs are read here rather than by the caller so
    /// each rule can be switched off without the other: the lane rule's
    /// A/B arm has to be able to leave the fold rule exactly as it ships.
    pub(super) fn new(
        chain_beside: bool,
        recovery_rows: u64,
        lengths: &[u64],
        scan_outer: usize,
    ) -> BatchFoldPacer {
        let max = crate::mem::cpu_workers().max(1);
        let payload = lengths.iter().copied().fold(0u64, u64::saturating_add);
        let active =
            chain_beside && create_fold_pacing_enabled() && create_batch_fold_pacing_enabled();
        let width = if active {
            apriori_fold_width(
                recovery_rows,
                payload,
                chain_pass_bytes(lengths, scan_outer),
                max,
            )
        } else {
            max
        };
        BatchFoldPacer {
            // From the fold width, so the lanes are what the box has
            // left once the fold is paid - never a second narrowing
            // that thinks it is the only one.
            lanes: chain_beside
                .then(|| scan::apriori_scan_lane_width(width, scan_outer, max))
                .flatten(),
            // Nothing to publish when the rule asks for the whole box:
            // an unnarrowed cap is a cap that only costs a thread-local
            // write and a line of log saying nothing happened.
            cap: (active && width < max).then(|| crate::mem::FoldWidthCap::publish(width)),
            active,
            max,
            width,
            moves: 0,
        }
    }

    /// Before a batch's fold: the only thing that can still move the cap
    /// is the chain having finished. A no-op when inert.
    pub(super) fn before_batch(&mut self, control: &CreateControl, total: u64) {
        let Some(cap) = self.cap.as_ref() else { return };
        // The CHAIN's own counter, not `CreatePhase::Verify`. Verify is
        // stepped by the block-digest lanes, which run `threads`-way
        // parallel over the member and saturate it inside the first
        // batch or two while the sequential chain still has most of its
        // wall left - which read here as "the chain has finished"
        // (`CreateControl::chain`, and the 16 Sep round in
        // research/PARFAST-BATCHED-CREATE-FOLD-PACER-2026-09-15.md).
        if total == 0 || control.chain_done() < total || self.width == self.max {
            return;
        }
        self.width = self.max;
        self.moves += 1;
        cap.set(self.max);
    }

    /// The per-batch timing line's suffix - empty when inert.
    pub(super) fn batch_timing_suffix(&self) -> String {
        if self.active {
            format!(" (fold width {} of {})", self.width, self.max)
        } else {
            String::new()
        }
    }

    /// The whole-create timing line's suffix - empty when inert.
    pub(super) fn summary_timing_suffix(&self) -> String {
        let lanes = match self.lanes {
            Some(n) => format!("; scan lanes {n} of {} a priori", self.max),
            None => String::new(),
        };
        if self.active {
            format!(
                "; batch fold width {} of {} a priori ({} restore(s)){lanes}",
                self.width, self.max, self.moves
            )
        } else {
            lanes
        }
    }

    /// The width `scan_all`'s block-digest lanes run at, or `None` for
    /// the geometry's own.
    pub(super) fn scan_lane_cap(&self) -> Option<usize> {
        self.lanes
    }
}

#[cfg(test)]
mod fold_pacing_tests {
    use super::paced_width;
    use std::time::Duration;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_fold_with_slack_sheds_workers_toward_eighty_percent_of_the_chain() {
        // Fold at 40% of the chain on 8 workers: aim for 0.8 -> 8*0.4/0.8 = 4.
        assert_eq!(paced_width(8, 8, ms(40), ms(100)), 4);
        // On 32 workers a 20% fold aims at 8.
        assert_eq!(paced_width(32, 32, ms(20), ms(100)), 8);
        // Never below two, never above what it had.
        assert_eq!(paced_width(2, 8, ms(1), ms(100)), 2);
        assert_eq!(paced_width(4, 8, ms(1), ms(100)), 2);
    }

    #[test]
    fn a_fold_near_the_chain_holds_and_one_past_ninety_percent_snaps_back() {
        assert_eq!(paced_width(4, 8, ms(75), ms(100)), 4);
        assert_eq!(paced_width(4, 8, ms(89), ms(100)), 4);
        assert_eq!(paced_width(4, 8, ms(90), ms(100)), 8);
        assert_eq!(paced_width(4, 8, ms(130), ms(100)), 8);
    }

    #[test]
    fn degenerate_timings_leave_the_width_alone() {
        assert_eq!(paced_width(6, 8, Duration::ZERO, ms(100)), 6);
        assert_eq!(paced_width(6, 8, ms(50), Duration::ZERO), 6);
        assert_eq!(paced_width(6, 0, ms(50), ms(100)), 1);
    }
}

#[cfg(test)]
mod apriori_fold_width_tests {
    use super::{
        PACED_WIDTH_FLOOR, apriori_fold_width, apriori_fold_width_for, apriori_fold_width_from,
        chain_pass_bytes, fold_rows_per_worker_per_chain_pass,
    };

    /// The measured shape, and the whole point of the round: 100
    /// recovery rows over 8,858,370,048 bytes on eight workers, with the
    /// chain one pass over the same bytes. `-t4` reaches 12.41 s on this
    /// by hand against 13.60 s at the default width, and the rule has to
    /// reach the same four WITHOUT being told - from the row count and
    /// the member length alone, before the first batch runs.
    #[test]
    fn the_measured_shape_reaches_the_width_t4_reaches_by_hand() {
        let payload = 8_858_370_048u64;
        assert_eq!(apriori_fold_width_for(100, payload, payload, 25, 8), 4);
        // And the NEON constant on the box IT was measured on: 28 rows
        // per worker on an M1 Ultra's twenty. The rule published exactly
        // this four on every acceptance leg, and won 9 of 12 mirrored
        // pairs at -1.7% median (16 Sep 2026).
        assert_eq!(apriori_fold_width_for(100, payload, payload, 28, 20), 4);
    }

    /// **The payload cancels, and that is the reason the rule is stated
    /// as a row count over a dimensionless ratio.** The fold's work and
    /// the chain's both scale with the bytes, so a 1 GB set and a 100 GB
    /// set at the same redundancy want the same width - which is what
    /// carries this from the one shape it was measured on to every other
    /// size on the same kernel. A test that only pinned the arithmetic
    /// would not say this.
    #[test]
    fn the_payload_cancels_so_only_the_row_count_decides() {
        for payload in [1u64 << 30, 8_858_370_048, 100u64 << 30] {
            assert_eq!(
                apriori_fold_width_for(100, payload, payload, 25, 8),
                4,
                "payload {payload} moved a width it has no business moving"
            );
        }
    }

    /// More redundancy is more fold work per chain pass, so it wants
    /// more workers - and the box's own width is still the ceiling. A
    /// 10% set on this kernel is not chain-bound at all and gets
    /// everything.
    #[test]
    fn rows_drive_the_width_and_the_box_is_the_ceiling() {
        let bytes = 8_858_370_048u64;
        assert_eq!(apriori_fold_width_for(50, bytes, bytes, 25, 8), 2);
        assert_eq!(apriori_fold_width_for(100, bytes, bytes, 25, 8), 4);
        assert_eq!(apriori_fold_width_for(200, bytes, bytes, 25, 8), 8);
        assert_eq!(apriori_fold_width_for(2_000, bytes, bytes, 25, 8), 8);
    }

    /// The floor bounds the damage of a constant that is wrong for this
    /// box in the dangerous direction: however little fold work there
    /// is, the create does not end up poled by a one-worker fold that
    /// this hand chose.
    #[test]
    fn the_floor_holds_however_little_fold_work_there_is() {
        let bytes = 8_858_370_048u64;
        assert_eq!(
            apriori_fold_width_for(1, bytes, bytes, 25, 8),
            PACED_WIDTH_FLOOR
        );
        // ...and a box narrower than the floor is not widened to it.
        assert_eq!(apriori_fold_width_for(1, bytes, bytes, 25, 1), 1);
    }

    /// An unknown is never an argument for shedding workers. Every
    /// missing input reads as the whole box.
    #[test]
    fn nothing_known_is_never_an_argument_for_shedding() {
        let bytes = 8_858_370_048u64;
        assert_eq!(apriori_fold_width_for(0, bytes, bytes, 25, 8), 8);
        assert_eq!(apriori_fold_width_for(100, 0, bytes, 25, 8), 8);
        assert_eq!(apriori_fold_width_for(100, bytes, 0, 25, 8), 8);
        assert_eq!(apriori_fold_width_for(100, bytes, bytes, 0, 8), 8);
    }

    /// **A fold kernel whose rate against MD5 nobody measured never
    /// narrows** - asserted on EVERY box, not only on one that happens
    /// to be such a part. This is the gate that keeps a constant
    /// measured on one kernel off the kernels it was not.
    #[test]
    fn an_unmeasured_fold_kernel_declines_to_narrow() {
        let bytes = 8_858_370_048u64;
        // However chain-bound the shape looks, an unmeasured kernel is
        // handed the whole box. Two shapes, so this cannot pass by the
        // clamp alone.
        assert_eq!(apriori_fold_width_from(None, 1, bytes, bytes, 8), 8);
        assert_eq!(apriori_fold_width_from(None, 100, bytes, bytes, 8), 8);
        assert_eq!(apriori_fold_width_from(None, 100, bytes, bytes, 20), 20);
    }

    /// ...and the other half, in whichever direction THIS box is. The
    /// expected width is computed FROM the constant rather than written
    /// down, so a third measured kernel with a different constant cannot
    /// falsify a test about the rule.
    #[test]
    fn this_boxs_own_kernel_agrees_with_the_rule() {
        let bytes = 8_858_370_048u64;
        match fold_rows_per_worker_per_chain_pass() {
            Some(rows) => {
                assert!(
                    rows > 0,
                    "a measured ratio of zero rows is not a measurement"
                );
                let want = (100u64.div_ceil(rows) as usize).clamp(PACED_WIDTH_FLOOR, 8);
                assert_eq!(apriori_fold_width(100, bytes, bytes, 8), want);
            }
            None => assert_eq!(apriori_fold_width(1, bytes, bytes, 8), 8),
        }
    }

    /// Chains that run BESIDE each other are not summed. `scan_all`
    /// gives each member to a file-level worker, so a four-member set on
    /// four workers waits on one member's chain, not on four - and a
    /// rule that summed them would see four times the slack it has and
    /// shed four times the workers it should.
    #[test]
    fn many_members_chains_are_a_makespan_and_not_a_sum() {
        let four = [1_000u64; 4];
        assert_eq!(chain_pass_bytes(&four, 4), 1_000);
        assert_eq!(chain_pass_bytes(&four, 2), 2_000);
        assert_eq!(chain_pass_bytes(&four, 1), 4_000);
        // One big member and three small ones: the big one is the wall
        // whatever the worker count says.
        assert_eq!(chain_pass_bytes(&[9_000, 100, 100, 100], 4), 9_000);
        // The single-member set this was measured on: an identity.
        assert_eq!(chain_pass_bytes(&[8_858_370_048], 1), 8_858_370_048);
        assert_eq!(chain_pass_bytes(&[], 4), 0);
    }
}

#[cfg(test)]
mod batch_fold_pacer_tests {
    use super::super::{CreateControl, CreatePhase};
    use super::{BatchFoldPacer, apriori_fold_width};
    use crate::par2repair::PauseGate;

    /// A control whose meters exist (a gate is enough - see
    /// `CreateControl::new`), so both counters are real.
    fn watched() -> CreateControl {
        CreateControl::new(None, Some(PauseGate::new()))
    }

    const MEMBER: u64 = 8_858_370_048;

    /// The width is the RULE's, and it is in force before the first
    /// batch rather than after the first measurement.
    #[test]
    fn the_width_is_published_before_any_batch_has_run() {
        let max = crate::mem::cpu_workers().max(1);
        let pacer = BatchFoldPacer::new(true, 100, &[MEMBER], 1);
        assert_eq!(pacer.width, apriori_fold_width(100, MEMBER, MEMBER, max));
        // Published exactly when it narrows: an uncapped fold registers
        // no cap for a scheduler to read.
        assert_eq!(pacer.cap.is_some(), pacer.width < max);
        assert_eq!(pacer.moves, 0);
    }

    /// **THE REGRESSION TEST FOR THIS ROUND: there is no feedback term.**
    ///
    /// Two pacers that narrowed at batch boundaries from the chain's
    /// measured rate were built here and both walked to the floor and
    /// LOST - 14.40 s and 14.30 s against 13.60 s inert, because the
    /// rate is measured while the fold is starving the very chain it is
    /// extrapolating. This sets up the state those pacers moved on - the
    /// block-digest phase FULL and the sequential chain at 10%, which is
    /// what a mapped scan of one large member reads within its first
    /// second - and asserts the width does NOT move, batch after batch.
    #[test]
    fn a_running_chain_never_moves_the_width_again() {
        let control = watched();
        control.begin(CreatePhase::Verify, MEMBER);
        control.step(CreatePhase::Verify, MEMBER);
        control.chain_step(MEMBER / 10);

        let mut pacer = BatchFoldPacer::new(true, 100, &[MEMBER], 1);
        let chosen = pacer.width;
        for _ in 0..4 {
            pacer.before_batch(&control, MEMBER);
            assert_eq!(
                pacer.width, chosen,
                "the width moved at a batch boundary - a feedback term is back"
            );
        }
        assert_eq!(pacer.moves, 0);
    }

    /// The one event that DOES move it, and the one counter that can see
    /// that event: once the CHAIN itself is done there is nothing left
    /// to pace against, so the remaining batches get the whole box back.
    /// The block-digest phase is deliberately left at nothing here - a
    /// pacer reading `CreatePhase::Verify` for this would restore the
    /// ceiling in the test above instead, which is the defect the chain
    /// counter exists to stop.
    #[test]
    fn a_finished_chain_restores_the_ceiling() {
        let control = watched();
        control.begin(CreatePhase::Verify, MEMBER);
        control.chain_step(MEMBER);

        let mut pacer = BatchFoldPacer::new(true, 100, &[MEMBER], 1);
        let narrowed = pacer.width < pacer.max;
        pacer.before_batch(&control, MEMBER);
        assert_eq!(pacer.width, pacer.max);
        // A rule that never narrowed on this box has nothing to restore.
        assert_eq!(pacer.moves, usize::from(narrowed));
    }

    /// An inert pacer (pacing off, or a fused create) touches nothing
    /// and says nothing, whatever the counters read.
    #[test]
    fn an_inactive_pacer_is_a_no_op() {
        let control = watched();
        control.begin(CreatePhase::Verify, MEMBER);
        control.chain_step(1);
        let mut pacer = BatchFoldPacer::new(false, 100, &[MEMBER], 1);
        assert_eq!(pacer.width, pacer.max);
        assert!(pacer.cap.is_none());
        pacer.before_batch(&control, MEMBER);
        assert_eq!(pacer.moves, 0);
        assert_eq!(pacer.batch_timing_suffix(), "");
        assert_eq!(pacer.summary_timing_suffix(), "");
    }
}
