//! Forney-style back-substitution: the repair solve as two small
//! transforms instead of the m x m dense product.
//!
//! One subject per file, the way `linalg.rs` and `fastpar.rs` are: this
//! is the LAST phase of a repair, and only the last phase. It takes the
//! syndrome rows and the missing columns' base logs and returns the
//! rebuilt blocks; it never sees a file, a packet or a recovery set, and
//! the policy question of WHICH solve runs is answered by
//! [`backsub_gate`] before any arithmetic starts.
//!
//! # Why
//!
//! `Reconstructor::finish_reported` ends every repair with
//! `fold_parallel(&mut out, &syn_bytes, &|j, i| inverse[j][i])` - the
//! explicit m x m inverse times the m syndrome rows, `O(m^2 * words)` of
//! kernel work. That fold runs AT the kernel's measured peak (147.5 GB
//! in 257 ms at m = 1,500 on the M3 Ultra, audit section 3), so there is
//! nothing to win by folding it better. There is something to win by
//! folding LESS: at the `MAX_REPAIR_DIM` = 8,192 cap the same product is
//! 4.4 TB and ~7.4 s on that box, and it grows quadratically while every
//! other phase of the repair grows linearly.
//!
//! # The identity
//!
//! Both repair paths pick the SMALLEST available recovery exponents, so
//! the exponents are consecutive `e_r = e0 + r` and the matrix factors
//! `A[r][c] = g_c^{e0} * g_c^r` (`linalg::invert_vandermonde` exists for
//! the same reason). Writing `y_c = g_c^{e0} x_c`, the syndromes
//! `S_r = Σ_c y_c g_c^r` are the power sums of the unknowns at the nodes
//! `g_c`, and with `P(z) = Π_c (z + g_c)` and `Q_c = P/(z + g_c)`,
//!
//! ```text
//!     Σ_r Q_c[r] S_r = Σ_{c'} y_{c'} Q_c(g_{c'}) = d_c * y_c,
//!     d_c = Q_c(g_c) = P'(g_c)   (char 2: the odd coefficients)
//! ```
//!
//! because `Q_c` vanishes at every other node. Synthetic division gives
//! `Q_c[r] = Σ_{j>=r} p[j+1] g_c^{j-r}`, so substituting `j = r + t`
//! splits the sum into two stages that no longer mention `c` and `r`
//! together:
//!
//! ```text
//! T_t = Σ_r S_r * p[r + t + 1]                (a HANKEL product)
//!     x_c = (g_c^{-e0} / d_c) * Σ_t T_t * g_c^t   (an EVALUATION)
//! ```
//!
//! Both stages are still `O(m^2)` written that way; the point is that
//! both are now STRUCTURED, and each has a transform that does it in
//! roughly `O(m)` block folds.
//!
//! # Stage 1, the Hankel product
//!
//! `T` is a Toeplitz/Hankel matvec, so it is a convolution. Cut the
//! index into segments of [`BLK`] = 128 and every `(output segment,
//! input segment)` pair becomes one cyclic convolution of length
//! [`CONV`] = 255 - and 255 divides 65535, so GF(2^16) has a root of
//! that order and the convolution is a length-255 DFT, a pointwise
//! product and a length-255 inverse DFT. Transform each input segment
//! ONCE, accumulate in the spectral domain, transform each output
//! segment back once: `2 * m * CONV / BLK` ... in block folds,
//! `2 * CONV * m` for the transforms plus `CONV * nseg(nseg+1)/2` for
//! the spectral accumulate (only half the pairs: `p[r+t+1]` is zero past
//! `r + t = m - 1`, so the Hankel matrix is triangular).
//!
//! The first implementation did each length-255 DFT directly, as a dense
//! 255 x 128 fold. That is an exact baseline, not a lower bound: because
//! `255 = 3 * 5 * 17` with pairwise-coprime radices, a Good-Thomas network
//! factors the transform without twiddles. Putting radix 17 first lets the
//! forward transform prune the 127 padded input rows; putting it last in the
//! inverse lets that transform prune the 127 outputs the Hankel product never
//! consumes. For a full segment, each direction therefore needs 4,216
//! coefficient/source folds instead of 32,640 (7.74x fewer). Two reusable
//! 255-row stripe arenas carry the intermediate coordinates.
//!
//! # Stage 2, the evaluation
//!
//! `Σ_t T_t g_c^t = Σ_t T_t 2^{k_c t}` is one output of the 65535-point
//! DFT `par2ntt` already computes - with the roles swapped (inputs on
//! the contiguous prefix `t < m`, outputs at the scattered `k_c`), which
//! is the TRANSPOSE of the shape `FlatPlan` implements. Rather than
//! transpose that network, this stage takes the Good-Thomas split
//! `65535 = 255 * 257` straight: with `α = 2^{257*128}` (order 255) and
//! `β = 2^{255*128}` (order 257), CRT gives
//! `2^{k t} = α^{(k mod 255)(t mod 255)} * β^{(k mod 257)(t mod 257)}`,
//! so one pass over `T` per distinct `k_c mod 255` builds 257 partial
//! rows, and each column is then one 257-source fold of those.
//!
//! That costs `|K1| * m + 257 * m` block folds where `|K1|` is the
//! number of distinct `k_c mod 255`. Base logs are coprime to 65535, so
//! `k_c mod 255` is coprime to 255 and `|K1| <= φ(255) = 128` however
//! large `m` gets. The two-level form holds ONE 257-row scratch per
//! worker where the full `FlatPlan` tree would hold `needed <= 65535`
//! rows (the outputs here are scattered over the whole group, so its
//! prefix pruning does not apply) - 60-160 MB per worker at the shipped
//! stripe width, which is why the cheaper network is not the one used.
//!
//! # What it costs, and where it crosses over
//!
//! In block folds (one fused source pass through
//! `gf16::xor_mul_multi_into`, the unit audit section 18 prices
//! everything in), against the dense product's `m^2`:
//!
//! ```text
//!     stage 1: 34m + 4080*nseg + CONV*nseg(nseg+1)/2,
//!              nseg = ceil(m / BLK)
//!     stage 2: (|K1| + 257) * m
//! ```
//!
//! The first two stage-1 terms are the pruned 3x5x17 transforms; the last is
//! the unchanged triangular spectral accumulation. This is linear in `m`
//! up to the `nseg^2` term, and that term is `CONV/(2*BLK^2) = 0.0078` per
//! `m^2` - 128x under the dense product's coefficient. Fused-kernel calls
//! are fewer again because each call consumes several coefficient/source
//! pairs.
//!
//! The transform-vs-dense gate was first measured 3 Sep 2026 with
//! the original direct stage-1 DFT, 64 KiB blocks, best of three, solve only
//! (`examples/par2_fold_bench`; the tables and the method are in
//! `research/PAR2-PERF-AUDIT-2026-09-02.md` section 20). Transform
//! against dense:
//!
//! ```text
//!     m       512   1024   1500   2048   3000   6000   8192
//! M3 Ultra 32c   0.38x  0.89x  1.38x  1.90x  2.72x  5.25x  7.29x
//! Zen 4 EPYC 8t  0.43x  0.81x  1.11x  1.45x  2.04x  3.35x  4.51x
//! ```
//!
//! Those direct-DFT baseline crossovers were m ~ 1,200 on the M3 and ~1,350
//! on the Zen 4, and the mixed-radix stage only lowers the transform side.
//! The 2,048 gate they were used to justify has since been recalibrated
//! DOWN on six boxes and three kernel classes - see
//! [`backsub_min_missing`] and
//! `research/FORNEY-GATE-CROSSOVER-2026-09-10.md`; the margin those
//! numbers bought is gone deliberately, and must not be restored. At the
//! `MAX_REPAIR_DIM` cap the whole solve is 1.05 s against 7.6 s and
//! 3.7 s against 16.6 s. Setup is cheaper on this route as well (33 ms
//! against 48 ms at the cap on the M3): the tables here are `O(m)` wide
//! where the explicit inverse is `O(m^2)`.
//!
//! # What is NOT here
//!
//! Gapped exponents. When recovery packets are themselves missing the
//! exponents are not consecutive, `A` is a generalized Vandermonde with
//! no factorization, and the repair falls back to Gauss-Jordan and the
//! dense product exactly as before - untouched by any of this.

use crate::gf16::{self, MulTable};
use crate::sync::MutexExt;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

// The JOINT arm: a fused constructor-and-solver, the DEFAULT on
// aarch64 since 11 Sep 2026 and on every x86 kernel class since
// 12 Sep 2026, each admitted on its own native round. Nothing below is
// entered, and no table below is built, when the gate says no - see
// `joint::joint_gate` and `joint::joint_default_on`, plus
// `research/JOINT-FORNEY-INTEGRATION-2026-09-10.md` for the arm and
// `research/JOINT-CROSSOVER-PER-CLASS-2026-09-11.md` for the default.
mod joint;
mod locator;
mod peel;
mod poly;
mod tail;
mod whole;

pub(super) use joint::joint_gate;
#[cfg(test)]
pub(crate) use joint::seam_joint_default_on;
pub(crate) use joint::{seam_joint_arm, seam_joint_factor, seam_joint_kernel};
// The VALUES, for `par2seams`'s drift gates only - production reads the
// gates through `seam_joint_factor` / `seam_joint_kernel` and never the
// numbers, so an un-gated re-export is an unused import under `-D warnings`.
#[cfg(test)]
pub(crate) use joint::{JOINT_FACTOR_MIN_M, JOINT_KERNEL_MIN_M_X86};
pub use joint::{
    JointDecline, JointReach, joint_armed, joint_reach, reset_joint_reach, set_joint_arm,
};

/// Record that this repair took a solver the joint arm does not reach.
///
/// `reconstruct` owns that fork and this module owns the record, so the
/// crossing is one function rather than a second public enum.
pub(super) fn note_joint_not_forney() {
    joint::note_joint_declined(JointDecline::NotForney);
}

/// Segment length of the blocked Hankel product. Paired with
/// [`CONV`] = `2*BLK - 1`: the linear convolution of two length-`BLK`
/// sequences is exactly `2*BLK - 1` long, so a cyclic convolution of
/// that length carries it with no wraparound and no padding waste.
/// 128 is the largest such pairing whose length divides 65535 (255
/// does; 511 and 1023 do not), and the `nseg^2` spectral-accumulate
/// term wants `BLK` as large as the field allows.
const BLK: usize = 128;
/// The cyclic-convolution length, `2*BLK - 1`. `255 = 3*5*17` divides
/// `65535`, so `2^257` is a root of unity of exactly this order.
const CONV: usize = 2 * BLK - 1;
/// The 257 half of the Good-Thomas split `65535 = 255 * 257` used by
/// the evaluation stage.
const GT2: usize = 257;

/// `NZBFAST_BACKSUB` default: the missing-block count at or above which
/// the transform solve replaces the dense product. This is the arm
/// every fused kernel that is neither NEON nor nibble-shuffle takes -
/// in practice the GFNI ones, AVX-512 (fan-in 12) or 256-bit (6).
///
/// **1,280 since 10 Sep 2026, down from 2,048, and the value is
/// deliberately the nibble constant's.** The 2,048 came from the same
/// kind of sweep `fastpar::NTT_MIN_MISSING` rests on - both solves
/// timed at the same shapes on an M3 Ultra and a Zen 4 EPYC, audit
/// section 20, measured crossover m ~ 1,200 and ~ 1,350 - and was then
/// set ~1.5x ABOVE it, because "one constant cannot be right on every
/// box, and the dense product is the one that has run in the field for
/// a year". That margin was an argument about confidence rather than
/// performance, and the class it was applied to was the one class
/// nobody had measured it on. The six-box round of 10 Sep 2026
/// (`research/FORNEY-GATE-CROSSOVER-2026-09-10.md`) measured GFNI
/// directly: crossover ~1,400 on a Core Ultra 9 386H (bare metal) and
/// ~1,300 on an EPYC 9354P (VM), so the 2,048 gate was 46% and 57%
/// high, and AT its own gate it cost 30.3% of wall / 44.5% of CPU on
/// the bare-metal part and 22.8% / 31.6% on the VM. That band - roughly
/// 1,300 to 2,048 - is live on every AVX-512+GFNI part: Zen 4 onward,
/// Ice Lake onward.
///
/// Collapsed onto 1,280 rather than onto the measured ~1,300 on
/// purpose: the nibble figure is EXACT on the class it gates and the
/// GFNI figure is ~1,300-1,400, so one number serves both x86 classes
/// and neither class carries a number nobody measured. It is not
/// even a compromise for GFNI - at m = 1,280 Forney was ALREADY ahead
/// on both GFNI boxes, -5.0% on the Core Ultra and -4.5% on the EPYC,
/// both just inside noise. The two constants keep separate names
/// because their PROVENANCE differs, not their value, and so a
/// re-measure of either class can move one without the other.
///
/// Which way to be wrong when a part is unmeasured: see
/// [`backsub_min_missing`]. Bias DOWN. Do not restore the old margin.
pub(crate) const BACKSUB_MIN_MISSING: usize = 1280;

/// The gate on the x86 nibble-shuffle arms (AVX2 or SSSE3 without GFNI:
/// Intel before Ice Lake, AMD before Zen 4), where the dense product is
/// relatively dearer. Measured 4 Sep 2026 on an i5-10600KF desktop
/// (Windows 11, 6c/12t), both arms forced, 64 KiB blocks: dense
/// 221-251 ms against forney 479-491 at m = 512, 446-511 against
/// 550-608 at m = 768, 798 against 659-683 at m = 1,024, and 1,760-1,900
/// against 872-883 at m = 1,500 - a 2.1x loss on the published heavy
/// leg under the 2,048 gate. Crossover ~950-1,050 there; 1,280 is ~1.25x
/// past it (a margin, narrower than the others because this constant is
/// measured on the very class it gates) and puts the
/// 1,500-block leg on the fast side by ~0.9 s of a ~5.5 s repair.
/// Re-measured 6 Sep 2026 at 1 MiB blocks on the same box (10 GiB,
/// m = 900, both arms forced, mirrored): forney 26.17 / 26.25 s wall
/// against dense 24.94 / 24.98, CPU 246-248 against 198 - the
/// crossover does not move down with the block size, so the gate
/// holds at large blocks too.
///
/// **Unchanged by the 10 Sep six-box recalibration, and the only one of
/// the three that was already right.** That round re-measured this box
/// on fresh fixtures and put the crossover EXACTLY at 1,280 - the
/// finding being that each constant was right where it was measured on
/// the class it gates and wrong where it was not, which is why this one
/// held and the other two did not. It is now also the generic
/// constant's value; see [`BACKSUB_MIN_MISSING`] for why that is a
/// collapse and not a coincidence.
pub(crate) const BACKSUB_MIN_MISSING_NIBBLE: usize = 1280;

/// The gate on aarch64 (NEON), **704 since 10 Sep 2026, down from 896.**
///
/// The 896 was measured 5 Sep 2026 with the conjugate-paired transform
/// leaf in, which the transform solve is built on: the crossover the
/// 2,048 constant above was set from moved down with it. M3 Ultra, both
/// arms forced, byte-identical repairs: at m = 1,500 (the 1 GiB heavy
/// leg) the solve is 117-127 ms against the dense 275-299, the whole
/// repair 689-703 ms against 774-835; at m = 900 (10 GiB, 1 MiB blocks)
/// 1.12 s against 1.76, wall 7.67 against 8.08. The fold bench's table
/// on the same box at 64 KiB: dense 31 ms vs forney 50 at m = 512, 126
/// vs 81 at 1,024 - crossover ~700, and 896 was set 1.28x past it under
/// the margin rule that no longer applies.
///
/// The six-box round of 10 Sep 2026
/// (`research/FORNEY-GATE-CROSSOVER-2026-09-10.md`) put the crossover
/// at ~704 on an M1 Ultra, ~768 on the M3 Ultra and ~704 on an M5 Max -
/// 896 was 27% / 17% / 27% high. Localised by a 5-rep fine sweep at
/// 64-block steps with noise of 0.06-0.19 s throughout, so 704 is
/// RESOLVED rather than inferred: M1 and M5 first win beyond noise at
/// 704, M3 at 768. Taking the low end of the three follows the bias
/// rule on [`backsub_min_missing`]; on the M3 the cost of being one
/// step low is bounded by the 64-block gap and is inside that box's own
/// noise, where being high is not.
pub(crate) const BACKSUB_MIN_MISSING_NEON: usize = 704;

/// The gate this build runs under: [`BACKSUB_MIN_MISSING_NEON`] on
/// aarch64, [`BACKSUB_MIN_MISSING_NIBBLE`] on the nibble-shuffle arms,
/// [`BACKSUB_MIN_MISSING`] everywhere else. Keyed on the selected
/// kernel's fan-in exactly as the fold scheduler is
/// (`gf16::multi_fold_schedule_granule_words`): 4 is the nibble
/// kernels' width and no other arm's. The two x86 arms carry the same
/// NUMBER since 10 Sep 2026 and the branch is still written out,
/// because they are two separately measured classes and a re-measure of
/// either must be able to move one alone.
///
/// # Which way to be wrong
///
/// **Bias LOW.** The penalty is asymmetric by about 3x, measured on the
/// six-box round (`research/FORNEY-GATE-CROSSOVER-2026-09-10.md`):
///
/// ```text
/// box                worst cost too LOW   worst cost too HIGH
/// i5 (nibble)              +26.7%               71.1%
/// Core Ultra (GFNI)        +20.3%               47.2%
/// M5 Max (NEON)             +8.5%               73.2%
/// M1 Ultra (NEON)           +6.5%               67.2%
/// ```
///
/// Too low costs at most ~27% and only inside a BOUNDED band that ends
/// at the crossover. Too high costs up to 73% and keeps GROWING with
/// depth, because the dense product degrades quadratically in m where
/// the transform does not - at m = 3,072 dense burns 3.5-4.7x the CPU
/// of Forney on every box measured. So for an unmeasured part, take the
/// nearest measured class and bias down from it; the pre-10-Sep
/// convention biased UP for a stability reason, and had been paying a
/// performance price on GFNI hardware for it ever since.
///
/// # Why a constant per class, and not a predicate over (n, m)
///
/// Because the crossover does not move with `n`. An n-axis sweep over
/// n = 5,600 / 11,200 / 22,400 - a 4x range, 182 legs - found it
/// UNMOVED, m* = 768 at every n on both an M3 Ultra and an M5 Max. (A
/// coarser step than the NEON fine sweep, which is why the M5 reads 768
/// there and 704 above; the finding is the absence of movement, not the
/// value.) The cost models predicted a weak logarithmic rise
/// (`m* ~ k log n`, ~15% over a 4x range) and the measurement does not
/// resolve even that. A per-class constant is therefore the right
/// shape. Do not add a computed predicate. What DOES vary is the class - the two arms do not benefit
/// equally from kernel width, which spans 2x across the three shipped
/// classes, and is why `multi_fold_width()` is the thing to key on.
pub(crate) fn backsub_min_missing() -> usize {
    if cfg!(target_arch = "aarch64") {
        BACKSUB_MIN_MISSING_NEON
    } else if gf16::multi_fold_width() == 4 {
        BACKSUB_MIN_MISSING_NIBBLE
    } else {
        BACKSUB_MIN_MISSING
    }
}

/// Stripe-width granule, in u16 words: 32 words = 64 bytes, the widest
/// granule any shipped fused kernel takes (`gf16::xor_mul_multi_gfni512`
/// works in 64-byte chunks; the NEON and AVX2 kernels take 32). A width
/// off this granule leaves a remainder on EVERY fold, and the remainder
/// path builds a 1.2 KB `FoldTable` per source per call - measured on
/// the Zen 4 EPYC at m = 6,000, where the budget happened to land on
/// 336 words (672 bytes = ten 64-byte chunks and a 32-byte tail): the
/// whole solve ran 10.4 s against 3.7 s at m = 8,192, a shape with 33%
/// MORE work. Alignment here is not a micro-optimisation.
const STRIPE_GRAN: usize = 32;

/// Per-worker byte budget for stage 2's GROUP TILE (`gtile * GT2 * w`
/// words), which is sized to fit it. Stage 1's spectral arena is NOT
/// sized from this any more - see [`ForneyPlan::stripe_w`] and
/// [`STRIPE_W_TARGET`] for why a flat per-worker byte budget was the
/// wrong shape there.
const SPECTRA_BUDGET: usize = 8 << 20;

/// Stripe width the back-substitution asks for, in u16 words, before
/// the memory budget gets a say: 512 words = 1,024 bytes per row per
/// fold call.
///
/// **This used to be a ceiling that a deep repair never reached, and it
/// cost 2x on the whole repair.** Until 7 Sep 2026 the width was the
/// largest power of two whose stage-1 arena (`nseg * CONV * w` words)
/// fitted a flat 8 MiB per worker. `nseg = ceil(m / BLK)` grows with the
/// damage, so the stripe COLLAPSED as a repair deepened - 512 words at
/// m <= 3,277, 128 at m = 10,240, and 64 words (128 bytes a fold call)
/// at m = 16,385, which is a 1 GiB corpus at 64 KiB blocks rebuilt from
/// scratch. At 128 bytes the per-call cost dominates the call, and on
/// the x86 nibble kernels that cost is eight 16-byte `pshufb` tables
/// rebuilt per source per call - the same overhead
/// [`STRIPE_GRAN`] exists to stop the remainder path paying, measured
/// elsewhere in this engine at 33-39% of a transform.
///
/// Measured on the i5-10600KF (6c/12t, AVX2, no GFNI), full rebuild at
/// m = 16,385, mirrored arms, every leg 0/21 bad:
///
/// ```text
///     stripe   wall p1 / p2     back-substitution   stage 1   stage 2
///     64 w     27.60 / 27.87    25.19 / 25.52       12.99     11.46
///     256 w    15.57 / 15.56    13.24 / 13.25        7.23      5.39
///     512 w    14.78 / 14.61    12.43 / 12.28        7.25      4.55
///     1024 w   14.52 / 14.62    12.16 / 12.22        7.50      4.05
/// ```
///
/// -47% on the whole repair; par2cmdline-turbo 1.5.0 took 285.5 s on the
/// same leg. 512 is the knee - 1,024 buys a further 0.5% for twice the
/// arena - and it is where the ALREADY-SHIPPED shallow repairs sat, so
/// this makes one width the answer at every depth rather than raising
/// anything. The M3 Ultra is flat at the same widths (2.30 s at 64
/// against 2.26 / 2.25 at 256 / 512): a NEON `FoldCoeff` is two bytes,
/// so that arm never paid the per-call table build and never showed the
/// collapse. The floor is not arch-keyed all the same - the mechanism
/// costs nothing on NEON but does not HURT there either, and a flat
/// arch constant chosen against one round of shapes is exactly what
/// went stale here.
const STRIPE_W_TARGET: usize = 512;

/// The share of the solve budget the stripe's arenas may take even when
/// the window has left no headroom for them, as a divisor: the 512-word
/// stripe is kept whenever its arenas for every worker come to a quarter
/// of the budget or less, and when they do not, the stripe HALVES until
/// they do - it does not fall to the granule.
///
/// **Why the budget is allowed to be overspent here.** A slabbed solve's
/// window FILLS the budget by construction - `reconstruct::plan_slabs`
/// sizes the slab to it - so the headroom [`stripe_w_for_buffers`] narrows
/// against was zero on every slabbed repair, and the stripe collapsed to
/// [`STRIPE_GRAN`] for no memory at all. Measured 14 Sep 2026 on the M3
/// Ultra at `-t4`, 1 GiB / 64 KiB, m = 2,048 under a 128 MiB budget (two
/// 32 KiB slabs, a window of exactly 128 MiB): 1,024 stripe uses and a
/// 961 ms solve at 32 words, against 64 uses and 586 ms pinned at 512
/// under the SAME budget - and peak RSS 953 MB pinned against 1,048 MB
/// collapsed, so the narrow stripe did not even buy the memory it was
/// narrowing for. The arenas it refused were 20 MB for four workers. On
/// the x86 nibble kernels the same collapse is the 2x
/// [`STRIPE_W_TARGET`]'s table measured
/// (`research/PARFAST-SMALL-BUDGET-TRANSFORM-CROSSOVER-2026-09-14.md`,
/// section 3c).
///
/// **Why not reserve the arenas in the slab plan instead**, which would
/// keep the budget whole: at that shape a reservation adds a THIRD slab
/// (20 MB off 128 MiB puts the widest slab under half the block), and a
/// slab is a full sweep of the payload - 0.8-1.6 CPU-s a sweep of a
/// page-cached 1 GiB there, a full re-read on a spinning NAS - to save
/// 375 ms of solve. On the set `plan_slabs` exists for, 65 GiB whose
/// window missed a 32 GiB budget by 0.024%, any reservation that moves
/// the slab count is a sweep of 65 GiB. And a reservation that adds NO
/// slab changes nothing, because the same slab count is the same width,
/// the same window and the same headroom. So the slab plan is untouched
/// and the overspend is bounded here instead.
///
/// **A quarter, and what still narrows.** The budget is itself a quarter
/// of the OOM line (RAM/4, cgroup/4), so the most this spends past the
/// window is a sixteenth of the machine. The arenas are ~`1,020 *
/// workers / block_size` of the window, so a 32 KiB slab on four workers
/// asks ~15% of the budget and keeps the target, while many workers on
/// small blocks - 32 workers at 4 KiB ask 8x the window - still narrow,
/// down to [`STRIPE_GRAN`]. The rule does not ask whether the solve is
/// slabbed: an unslabbed window that happens to fill its budget is the
/// same shape and gets the same bound.
///
/// **Halving against the share, not collapsing (15 Sep 2026).** Until
/// then the share only decided whether the TARGET stood; a stripe that
/// missed it narrowed against the headroom alone, which under a slab is
/// zero, so it went straight to [`STRIPE_GRAN`]. Measured on the M3
/// Ultra, 1 GiB / 64 KiB, m = 4,096 under 128 MiB at `-t4`: four 16 KiB
/// slabs, 512-word arenas of 36.6 MB against a 32 MiB quarter, so 32
/// words, 1,024 stripe uses and a 1.77 s solve against 1.18 s. The width
/// ladder at that m (forced, no `-m`, one window, CPU-seconds, best of
/// two) is 13.62 at 512 words, 13.86 at 256, 14.53 at 128, 15.43 at 64
/// and 17.92 at 32 - so each halving is cheap and the granule is not.
/// Halving while the arenas exceed the quarter stops at 256 words
/// (18.3 MB), and the arenas still never exceed the quarter this guard is.
///
/// **Both bounds are kept, as a maximum.** [`stripe_w_for_buffers`] halves while
/// the arenas exceed the LARGER of the headroom and the quarter. The
/// share alone would narrow wider stripes the headroom already pays for:
/// 4 KiB blocks at m = 32,768 on 32 workers under 1 GiB leave 805 MB of
/// headroom against a 256 MiB quarter, and take 128 words on the headroom
/// where the quarter alone would drive them to the granule. Under a slab
/// the headroom is zero and the quarter is what binds; on a roomy
/// unslabbed window the headroom is. Neither bound ever narrows a stripe
/// the other admits.
const STRIPE_TARGET_BUDGET_SHARE: u64 = 4;

/// Whether this shape takes the transform solve. `NZBFAST_BACKSUB` is
/// the escape hatch in both directions (`forney` / `dense`), the way
/// `NZBFAST_NTT` is for the syndrome path; unset, the gate is the
/// measured constant alone.
///
/// Deliberately NOT tied to the fast-par setting or its trip-breaker:
/// this solve reads no untrusted geometry (the nodes are the missing
/// blocks' own base logs) and has no fallback to retry INTO - it is
/// bit-identical to the dense product or it is a bug, which is what
/// the differential harness in `inline_tests` is for.
pub(crate) fn backsub_gate(m: usize) -> bool {
    match std::env::var("NZBFAST_BACKSUB")
        .unwrap_or_default()
        .as_str()
    {
        "forney" | "1" => true,
        "dense" | "0" | "off" => false,
        // Every count above is priced in FUSED folds. Without a multi
        // kernel both solves fall back to a `FoldTable` per source, and
        // the dense product's tiled loop amortises those table builds
        // across a whole column sweep where the small per-stage folds
        // here cannot - so on a part with no fused kernel (armv7, or an
        // `NZBFAST_GF16_MULTI=0` kernel A/B) the measured ratios do not
        // transfer and the dense product keeps the shape. The forced
        // arm above still reaches it, which is what the harness needs.
        _ => gf16::multi_fold_width() > 0 && m >= backsub_min_missing(),
    }
}

/// The selection census's door onto [`backsub_gate`], so
/// `par2seams` reports the arm this build actually takes instead of
/// re-deriving it. Three lines and no logic, deliberately: a census that
/// reasons independently is a second copy of the rule.
pub(crate) fn seam_backsub(m: usize) -> bool {
    backsub_gate(m)
}

/// Stage-1 transform policy. The measured Good-Thomas network is the
/// production default; `direct` is the rollback and benchmark arm. Read this
/// while preparing the plan so each repair builds and retains only the tables
/// its selected implementation can use.
fn mixed_dft_gate() -> bool {
    !matches!(
        std::env::var("NZBFAST_BACKSUB_DFT").as_deref(),
        Ok("direct" | "0" | "off")
    )
}

/// `dst ^= Σ_s coeffs[s] * srcs[s]`, every source the same length as
/// `dst`, fused in groups of 8 with the kernel's sub-granule tail taken
/// per source. The word-slice twin of `par2ntt::fold_into` - same
/// grouping, same tail rule, different source representation (rows of
/// an arena here, caller pointers there).
fn fold_rows(dst: &mut [u16], srcs: &[&[u16]], coeffs: &[u16]) {
    debug_assert_eq!(srcs.len(), coeffs.len());
    let words = dst.len();
    let mut g = 0;
    while g < srcs.len() {
        let cnt = (srcs.len() - g).min(8);
        let mut group: [&[u8]; 8] = [&[]; 8];
        for (t, s) in srcs[g..g + cnt].iter().enumerate() {
            debug_assert_eq!(s.len(), words);
            group[t] = gf16::words_as_bytes(s);
        }
        let done = gf16::xor_mul_multi_into(dst, &group[..cnt], &coeffs[g..g + cnt]);
        if done < words {
            // The sub-32-byte tail, and the WHOLE fold on a build with
            // no fused kernel - same rule as par2ntt::fold_into.
            for (src, &c) in group[..cnt].iter().zip(&coeffs[g..g + cnt]) {
                gf16::xor_mul_single_into(&mut dst[done..], &src[done * 2..], c);
            }
        }
        g += cnt;
    }
}

// Good-Thomas coordinates for 255 = 3 * 5 * 17. The three CRT
// idempotents are 85, 51 and 120: each is one modulo its own radix and
// zero modulo the other two. Consequently
//
//   w^(k*n) = (w^85)^(k3*n3) (w^51)^(k5*n5) (w^120)^(k17*n17)
//
// with no twiddle factors between the three transforms.
#[inline]
fn gt_index(a: usize, b: usize, c: usize) -> usize {
    (a * 5 + b) * 17 + c
}

#[inline]
fn gt_natural(a: usize, b: usize, c: usize) -> usize {
    (85 * a + 51 * b + 120 * c) % CONV
}

/// Dense radix transform matrix, row-major by output then input. `idem`
/// is the radix's CRT idempotent in Z/255; negating its exponent gives
/// the inverse transform. The missing 1/255 factor is one in
/// characteristic two, exactly as for the old direct inverse table.
fn dft_matrix(wpow: &[u16], radix: usize, idem: usize, inverse: bool) -> Vec<u16> {
    let mut out = vec![0u16; radix * radix];
    for k in 0..radix {
        for n in 0..radix {
            let mut e = idem * k * n % CONV;
            if inverse && e != 0 {
                e = CONV - e;
            }
            out[k * radix + n] = wpow[e];
        }
    }
    out
}

/// First forward stage, pruned at the source: only the caller's at-most
/// 128 natural-order rows exist. Radix 17 goes first because that makes
/// each butterfly roughly half-full while eliminating the most work;
/// the later radix-5 and radix-3 stages are dense.
fn dft17_sparse(src: &[&[u16]], dst: &mut [u16], words: usize, coeff: &[u16]) {
    debug_assert_eq!(dst.len(), CONV * words);
    // A group is one fixed (n mod 3, n mod 5), which is one residue mod
    // 15, so a segment of at most BLK = 128 natural rows puts at most
    // ceil(128/15) = 9 of them in any group - which is why the three
    // scratch arrays below are nine wide and need no bounds check in the
    // loop. The caller clamps every segment to BLK; assert it here so
    // that a change to BLK fails at this line rather than as an index
    // panic inside the butterfly.
    debug_assert!(
        src.len() <= BLK,
        "dft17_sparse takes one segment, at most BLK rows"
    );
    const GROUP_MAX: usize = BLK.div_ceil(15);
    let mut rows: [&[u16]; GROUP_MAX] = [&[]; GROUP_MAX];
    let mut residues = [0usize; GROUP_MAX];
    let mut selected = [0u16; GROUP_MAX];
    for a in 0..3 {
        for b in 0..5 {
            let mut count = 0;
            for (n, &row) in src.iter().enumerate() {
                if n % 3 == a && n % 5 == b {
                    rows[count] = row;
                    residues[count] = n % 17;
                    count += 1;
                }
            }
            for k in 0..17 {
                for q in 0..count {
                    selected[q] = coeff[k * 17 + residues[q]];
                }
                let d = gt_index(a, b, k) * words;
                fold_rows(&mut dst[d..d + words], &rows[..count], &selected[..count]);
            }
        }
    }
}

/// Middle radix-5 stage, with both arenas in Good-Thomas coordinate
/// order `[mod 3][mod 5][mod 17]`.
fn dft5(src: &[u16], dst: &mut [u16], words: usize, coeff: &[u16]) {
    debug_assert_eq!(src.len(), CONV * words);
    debug_assert_eq!(dst.len(), CONV * words);
    let mut rows: [&[u16]; 5] = [&[]; 5];
    for a in 0..3 {
        for c in 0..17 {
            for b in 0..5 {
                let s = gt_index(a, b, c) * words;
                rows[b] = &src[s..s + words];
            }
            for k in 0..5 {
                let d = gt_index(a, k, c) * words;
                fold_rows(&mut dst[d..d + words], &rows, &coeff[k * 5..][..5]);
            }
        }
    }
}

/// Last forward radix-3 stage. The destination is put back in natural
/// spectral order because the pointwise product consumes `sigma`
/// contiguously.
fn dft3_to_natural(src: &[u16], dst: &mut [u16], words: usize, coeff: &[u16]) {
    debug_assert_eq!(src.len(), CONV * words);
    debug_assert_eq!(dst.len(), CONV * words);
    let mut rows: [&[u16]; 3] = [&[]; 3];
    for b in 0..5 {
        for c in 0..17 {
            for a in 0..3 {
                let s = gt_index(a, b, c) * words;
                rows[a] = &src[s..s + words];
            }
            for k in 0..3 {
                let d = gt_natural(k, b, c) * words;
                fold_rows(&mut dst[d..d + words], &rows, &coeff[k * 3..][..3]);
            }
        }
    }
}

/// First inverse radix-3 stage: natural spectral order into
/// Good-Thomas coordinate order.
fn idft3_from_natural(src: &[u16], dst: &mut [u16], words: usize, coeff: &[u16]) {
    debug_assert_eq!(src.len(), CONV * words);
    debug_assert_eq!(dst.len(), CONV * words);
    let mut rows: [&[u16]; 3] = [&[]; 3];
    for b in 0..5 {
        for c in 0..17 {
            for a in 0..3 {
                let s = gt_natural(a, b, c) * words;
                rows[a] = &src[s..s + words];
            }
            for k in 0..3 {
                let d = gt_index(k, b, c) * words;
                fold_rows(&mut dst[d..d + words], &rows, &coeff[k * 3..][..3]);
            }
        }
    }
}

/// Last inverse radix-17 stage, pruned at the destination. Stage 1
/// needs only natural indices `v = 254-t`, `t < 128`, so computing the
/// other 127 inverse outputs would be pure waste.
fn idft17_pruned(src: &[u16], dst: &mut [&mut [u16]], words: usize, coeff: &[u16]) {
    debug_assert_eq!(src.len(), CONV * words);
    let mut rows: [&[u16]; 17] = [&[]; 17];
    for (t, out) in dst.iter_mut().enumerate() {
        let v = CONV - 1 - t;
        let (a, b, c) = (v % 3, v % 5, v % 17);
        for n in 0..17 {
            let s = gt_index(a, b, n) * words;
            rows[n] = &src[s..s + words];
        }
        fold_rows(&mut out[..], &rows, &coeff[c * 17..][..17]);
    }
}

/// Per-stripe disjoint views of every row, built by repeated
/// `split_at_mut` so the borrows are provably disjoint - the shape
/// `linalg::fold_parallel` uses to own its destination cells. Returns
/// `(column offset, one slice per row)` per stripe.
fn column_stripes(rows: &mut [Vec<u16>], w: usize) -> Vec<(usize, Vec<&mut [u16]>)> {
    let words = rows.first().map_or(0, |r| r.len());
    let n = words.div_ceil(w.max(1)).max(1);
    let mut out: Vec<(usize, Vec<&mut [u16]>)> = (0..n)
        .map(|i| (i * w, Vec::with_capacity(rows.len())))
        .collect();
    for row in rows.iter_mut() {
        let mut rest: &mut [u16] = row.as_mut_slice();
        for slot in out.iter_mut() {
            let take = rest.len().min(w);
            let (head, tail) = rest.split_at_mut(take);
            slot.1.push(head);
            rest = tail;
        }
    }
    out
}

/// The width [`ForneyPlan::stripe_w`] resolves to, split out from the
/// plan so the budget arithmetic can be tested without one: `nseg` and
/// `m` describe the solve, `words` the block, `workers` the concurrency
/// [`per_stripe`] will run at, and `budget` the whole solve's byte
/// budget (`reconstruct::solve_window_budget`).
#[cfg(test)]
fn stripe_w_for(nseg: usize, m: usize, words: usize, workers: usize, budget: u64) -> usize {
    stripe_w_for_buffers(nseg, m, words, workers, budget, 2)
}

/// The production form of the test-only `stripe_w_for` above, for a solve holding `buffers` `m x block` buffers:
/// 2 as shipped, 1 for the joint arm under
/// `reconstruct::in_place_output`, whose second buffer is replaced by
/// one stripe of `T` per worker (`run_joint`) - priced here, per worker,
/// because nothing else prices it once the window no longer does.
fn stripe_w_for_buffers(
    nseg: usize,
    m: usize,
    words: usize,
    workers: usize,
    budget: u64,
    buffers: u64,
) -> usize {
    // What the solve already holds for the whole of its life: the
    // `m x block` buffers `check_repair_dim_within` admitted it on.
    // `words` is block words, so the block is `2 * words` bytes.
    let window = (m as u64)
        .saturating_mul(words as u64)
        .saturating_mul(2)
        .saturating_mul(buffers.max(1));
    let headroom = budget.saturating_sub(window);
    let workers = workers.max(1) as u64;
    let t_rows = if buffers == 1 { m as u64 } else { 0 };
    // Stage 1 per worker: the `nseg * CONV` spectral arena, the one
    // resident output spectrum, and the two mixed-radix coordinate
    // arenas - `(nseg + 3) * CONV * w` words - plus, in place, the
    // worker's `m * w` words of `T`.
    let per_worker = |w: usize| {
        (nseg as u64 + 3)
            .saturating_mul(CONV as u64)
            .saturating_add(t_rows)
            .saturating_mul(w as u64)
            .saturating_mul(2)
    };
    let mut w = STRIPE_W_TARGET;
    // The arenas may take whichever is LARGER: what the window left, or
    // the bounded overspend - a quarter of the budget, whatever the
    // window left (STRIPE_TARGET_BUDGET_SHARE says why both bounds are
    // kept and what each costs). Halving against the headroom alone sent
    // every slabbed solve whose target arenas missed the share straight
    // to the granule, because a slab's window leaves no headroom at all.
    let bound = headroom.max(budget / STRIPE_TARGET_BUDGET_SHARE);
    while w > STRIPE_GRAN && per_worker(w).saturating_mul(workers) > bound {
        w >>= 1;
    }
    w
}

/// Run `body` over the column stripes of `rows`, one worker per unit
/// until they run out. Units are popped off one mutex exactly as
/// `fold_parallel` drains its grid, so a slow core never sets the wall.
fn per_stripe<F>(rows: &mut [Vec<u16>], w: usize, body: F)
where
    F: Fn(usize, &mut Vec<&mut [u16]>) + Sync,
{
    if rows.is_empty() {
        return;
    }
    let stripes = column_stripes(rows, w);
    // Every stripe unit here runs against an ALREADY-PREPARED plan, so
    // this is the reuse the one cold construction is amortised over -
    // the half of the plan-table question that a stopwatch on the
    // constructor alone cannot answer. See `PlanPrepCounters`.
    PREP_STRIPE_USES.fetch_add(stripes.len() as u64, Ordering::Relaxed);
    let workers = crate::mem::cpu_workers().max(1).min(stripes.len().max(1));
    let units = std::sync::Mutex::new(stripes);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let unit = units.lock_ok().pop();
                    let Some((off, mut cells)) = unit else { return };
                    body(off, &mut cells);
                }
            });
        }
    });
}

/// Build one of the plan's coefficient tables across the machine:
/// `stride` words per unit, `f(unit index, unit)`, units independent.
/// The same split `invert_vandermonde` fans its columns out with, and
/// for the same reason - at the repair cap these tables are millions of
/// entries each and they are pure setup, on the wall of every repair
/// that takes this path.
fn par_build(
    out: &mut [u16],
    stride: usize,
    min_units: usize,
    f: impl Fn(usize, &mut [u16]) + Sync,
) {
    let units = out.len() / stride.max(1);
    // `min_units` is the caller's "a thread should own at least this
    // many units to be worth spawning", the same shape
    // `invert_vandermonde` splits its columns on. It is a WORK
    // threshold, not a size one: the `scales` table is m words wide and
    // O(m^2) to build, so a rule keyed on the output length alone left
    // the most expensive table in the plan single-threaded.
    let threads = crate::mem::cpu_workers()
        .min(units / min_units.max(1))
        .max(1);
    if threads < 2 {
        for (i, unit) in out.chunks_mut(stride).enumerate() {
            f(i, unit);
        }
        return;
    }
    let per = units.div_ceil(threads) * stride;
    std::thread::scope(|s| {
        for (w, slab) in out.chunks_mut(per).enumerate() {
            let f = &f;
            s.spawn(move || {
                let base = w * (per / stride);
                for (i, unit) in slab.chunks_mut(stride).enumerate() {
                    f(base + i, unit);
                }
            });
        }
    });
}

/// Exactly one implementation of the 255-point transforms used by stage 1.
/// Keeping this as a plan-time choice matters beyond the small coefficient
/// tables themselves: the direct arm must not allocate mixed scratch, and the
/// mixed arm must not retain 65,280 dead direct coefficients per repair.
enum Stage1Plan {
    Direct {
        fwd: Vec<u16>,
        inv: Vec<u16>,
    },
    Mixed {
        f3: Vec<u16>,
        f5: Vec<u16>,
        f17: Vec<u16>,
        i3: Vec<u16>,
        i5: Vec<u16>,
        i17: Vec<u16>,
    },
}

impl Stage1Plan {
    #[inline]
    fn is_mixed(&self) -> bool {
        matches!(self, Stage1Plan::Mixed { .. })
    }
}

/// Plan-preparation accounting: how long the coefficient tables cost to
/// build, and how many times a built plan is then USED.
///
/// The plan is built once per [`Reconstructor`] and reused by every
/// column stripe of both stages, so "what does one preparation cost" and
/// "how often does preparation happen" are different questions, and the
/// plan-table multiplication policy
/// (`research/par-plan-tables-2026-09-08`) turns on the second one: a
/// 16% cut of a phase nobody has sized against a whole repair is not yet
/// a 16% cut of anything a user waits for.
///
/// `cold_ns` / `cold` are the constructor - the COLD path, once per
/// repair; `stripe_uses` is how many stripe units ran against an
/// already-built plan, which is the reuse the cold cost is amortised
/// over.
///
/// Counters are process-global and MONOTONE, so a caller reads a
/// difference across the phase it cares about rather than an absolute
/// (see [`prep_counters`] and `PlanPrepCounters::since`). Two repairs
/// running at once in one daemon therefore pool into each other's
/// window; that is acceptable for a measurement driver running one
/// repair per process, and is why nothing branches on these.
static PREP_COLD_NS: AtomicU64 = AtomicU64::new(0);
static PREP_COLD: AtomicU64 = AtomicU64::new(0);
static PREP_STRIPE_USES: AtomicU64 = AtomicU64::new(0);

/// The SOLVE's counterparts, added 8 Sep 2026
/// (`research/par-solve-repair-share-2026-09-08`) for the same reason
/// and by the same argument: the joint constructor-and-solver
/// (`research/par-joint-quiet-2026-09-08`) cuts 46-48% off the solve at
/// 32,768 missing blocks, 144 of 144 paired comparisons positive, and
/// that is a reduction of an unknown until the phase is sized against a
/// whole repair - exactly the hole the prep counters above were dug to
/// fill for the constructor. Measured: the solve is 19.5-43.3% of a
/// real repair on the shapes real sets have, against preparation's
/// 0.11-0.76% on the same fixtures.
///
/// Stage 1 ([`ForneyPlan::hankel`]) and stage 2 ([`ForneyPlan::evaluate`])
/// are charged SEPARATELY because the repair driver runs them apart, with
/// the syndrome buffers dropped between them, and because only the
/// two together are the thing the joint solver replaces. `STAGE1` counts
/// stage-1 entries, which is the number of SOLVES: a repair that solves
/// once is a different economic case from one that solves many windows,
/// and `STAGE1` over `PREP_COLD` is that ratio.
///
/// Charged unconditionally, unlike the `repair-timing` lines beside
/// them: both stages already take an `Instant` at entry whatever the
/// environment says, so this adds one `elapsed` and one relaxed atomic
/// per stage per solve, against a stage that runs for hundreds of
/// milliseconds.
static SOLVE_STAGE1_NS: AtomicU64 = AtomicU64::new(0);
static SOLVE_STAGE2_NS: AtomicU64 = AtomicU64::new(0);
static SOLVE_STAGE1: AtomicU64 = AtomicU64::new(0);

/// A reading of the counters above. Differences, not absolutes: see
/// [`PlanPrepCounters::since`].
#[derive(Clone, Copy, Default)]
pub(super) struct PlanPrepCounters {
    /// Wall time inside `ForneyPlan::prepare*`, successful builds only -
    /// a `None` return means the Forney arm was abandoned and no plan
    /// was prepared.
    pub(super) cold_ns: u64,
    /// Successful plan constructions.
    pub(super) cold: u64,
    /// Stripe units run against a prepared plan, both stages.
    pub(super) stripe_uses: u64,
    /// Wall time inside [`ForneyPlan::hankel`], the blocked Hankel
    /// product - stage 1 of the solve.
    pub(super) stage1_ns: u64,
    /// Wall time inside [`ForneyPlan::evaluate`] - stage 2 of the solve.
    pub(super) stage2_ns: u64,
    /// Solves: stage-1 entries, one per back-substitution that took the
    /// transform arm.
    pub(super) solves: u64,
}

impl PlanPrepCounters {
    /// This reading minus an earlier one. Saturating, so a counter that
    /// wrapped or was read out of order reports zero rather than a
    /// nonsense share.
    pub(super) fn since(self, earlier: Self) -> Self {
        Self {
            cold_ns: self.cold_ns.saturating_sub(earlier.cold_ns),
            cold: self.cold.saturating_sub(earlier.cold),
            stripe_uses: self.stripe_uses.saturating_sub(earlier.stripe_uses),
            stage1_ns: self.stage1_ns.saturating_sub(earlier.stage1_ns),
            stage2_ns: self.stage2_ns.saturating_sub(earlier.stage2_ns),
            solves: self.solves.saturating_sub(earlier.solves),
        }
    }

    /// Both solve stages together, which is the phase the joint
    /// constructor-and-solver replaces.
    pub(super) fn solve_ns(self) -> u64 {
        self.stage1_ns.saturating_add(self.stage2_ns)
    }
}

/// Read the plan-preparation counters. Relaxed: these are a measurement
/// aid read once per phase, not a synchronisation point.
pub(super) fn prep_counters() -> PlanPrepCounters {
    PlanPrepCounters {
        cold_ns: PREP_COLD_NS.load(Ordering::Relaxed),
        cold: PREP_COLD.load(Ordering::Relaxed),
        stripe_uses: PREP_STRIPE_USES.load(Ordering::Relaxed),
        stage1_ns: SOLVE_STAGE1_NS.load(Ordering::Relaxed),
        stage2_ns: SOLVE_STAGE2_NS.load(Ordering::Relaxed),
        solves: SOLVE_STAGE1.load(Ordering::Relaxed),
    }
}

/// A repair's Forney-phase bracket: hold one for the span you want the
/// shares taken over, and it reports TWO `repair-timing` lines when it
/// drops - `plan prep:` for the constructor and `forney solve:` for the
/// two solve stages. `what` names that span, because the two repair
/// drivers start their clocks in different places.
///
/// Named for preparation because that is what it was dug for; it covers
/// the solve as well since 8 Sep 2026. The two shares are reported apart
/// and must NOT be added: they are separately measured components of one
/// repair and the campaign doc warns about summing those.
///
/// A guard rather than a pair of calls so each driver spends ONE line on
/// it: `par2repair.rs` carries the 4,000-line file ceiling with margin
/// measured in single digits, and both drivers reporting through the
/// same code is also what keeps the two lines comparable.
///
/// Silent unless `NZBFAST_REPAIR_TIMING` is set, read once at `start` so
/// the drop path does no work in a production repair.
pub(super) struct PrepSpan {
    at: PlanPrepCounters,
    t0: std::time::Instant,
    what: &'static str,
    on: bool,
}

impl PrepSpan {
    pub(super) fn start(what: &'static str) -> PrepSpan {
        PrepSpan {
            at: prep_counters(),
            t0: std::time::Instant::now(),
            what,
            on: std::env::var_os("NZBFAST_REPAIR_TIMING").is_some(),
        }
    }
}

impl Drop for PrepSpan {
    fn drop(&mut self) {
        if !self.on {
            return;
        }
        let prep = prep_counters().since(self.at);
        let total = self.t0.elapsed();
        let share = if total.as_nanos() == 0 {
            0.0
        } else {
            prep.cold_ns as f64 * 100.0 / total.as_nanos() as f64
        };
        info!(
            target: "repair-timing",
            "plan prep: {:.2?} over {} cold build(s), {} stripe use(s) - {share:.3}% of the {total:.2?} {}",
            std::time::Duration::from_nanos(prep.cold_ns),
            prep.cold,
            prep.stripe_uses,
            self.what,
        );
        // The solve's own share, on its own line so the two phases can
        // be read apart: the joint solver replaces BOTH, but the
        // constructor half is already sized at 0.11-0.76% of a repair
        // and the two are NOT added: they are separately measured
        // components of one repair, and the joint arm changes both at
        // once.
        let solve_share = if total.as_nanos() == 0 {
            0.0
        } else {
            prep.solve_ns() as f64 * 100.0 / total.as_nanos() as f64
        };
        info!(
            target: "repair-timing",
            "forney solve: {:.2?} over {} solve(s) (stage 1 {:.2?}, stage 2 {:.2?}) - {solve_share:.3}% of the {total:.2?} {}",
            std::time::Duration::from_nanos(prep.solve_ns()),
            prep.solves,
            std::time::Duration::from_nanos(prep.stage1_ns),
            std::time::Duration::from_nanos(prep.stage2_ns),
            self.what,
        );
    }
}

/// The scalar half of the solve, built once per repair from the missing
/// columns' base logs and the first recovery exponent: the master
/// polynomial that drives stage 1 and the per-column coefficients that
/// drive stage 2.
pub(super) struct ForneyPlan {
    m: usize,
    /// `ceil(m / BLK)`: input AND output segments, and (because the
    /// Hankel matrix is triangular) also the number of live kernels.
    nseg: usize,
    /// Spectra of the reversed Hankel kernels, `[s * CONV + sigma]`,
    /// `s` in `0..nseg`.
    rhat: Vec<u16>,
    /// Direct or Good-Thomas coefficient tables, selected once at prepare
    /// time. The forward mixed transform runs 17 -> 5 -> 3 (source-pruned
    /// at 17); its inverse runs 3 -> 5 -> 17 (destination-pruned at 17).
    stage1: Stage1Plan,
    /// `T` row indices in `t mod 257` order, with `t_off` the 258 group
    /// boundaries into it.
    t_order: Vec<u32>,
    t_off: Vec<usize>,
    /// Stage-2 group coefficients laid out to match `t_order`:
    /// `[g * m + idx] = α^{k1_g * (t_order[idx] mod 255)}`.
    stage_a: Vec<u16>,
    /// Stage-2 per-column coefficients, `[c * GT2 + t2]`, with the
    /// column's whole scale folded in.
    evalc: Vec<u16>,
    /// Column indices per stage-2 group, parallel to `stage_a`'s rows.
    groups: Vec<Vec<u32>>,
    /// The locator polynomial `P`'s coefficients, `p[i]` the `z^i` one.
    /// EMPTY unless the joint arm is armed: the two-stage solve reads
    /// `P` only through `rhat`, so retaining it would be a memory
    /// change on a path the switch is meant to leave untouched.
    locator: Vec<u16>,
    /// The joint arm's own plan, or `None` on the shipped path.
    joint: Option<joint::JointPlan>,
}

impl ForneyPlan {
    /// Build the plan for missing columns with base logs `ks` and first
    /// recovery exponent `e0`. `None` on a duplicate base - the same
    /// theoretically-impossible case `invert_vandermonde` returns `None`
    /// for, and the same fallback (Gauss-Jordan and the dense product).
    pub(super) fn prepare(ks: &[u32], e0: u32) -> Option<ForneyPlan> {
        Self::prepare_with_dft(ks, e0, mixed_dft_gate())
    }

    /// Constructor with an explicit stage-one implementation. Tests use
    /// this to compare both arithmetic paths in one process without mutating
    /// the process-global environment; production enters through `prepare`.
    fn prepare_with_dft(ks: &[u32], e0: u32, mixed: bool) -> Option<ForneyPlan> {
        Self::prepare_impl(ks, e0, mixed, joint_gate())
    }

    /// The constructor, with the joint arm explicit. `joint` selects
    /// BOTH halves of the joint constructor - the product tree in
    /// `locator::build` and the whole-field derivative evaluation in
    /// `poly::evaluate_field` - and retains `P` for the joint solve.
    /// With it false every line below is the one that ran before the
    /// switch existed; `locator::chain` is that same coefficient chain,
    /// moved into its own file and nothing more.
    fn prepare_impl(ks: &[u32], e0: u32, mixed: bool, joint: bool) -> Option<ForneyPlan> {
        let m = ks.len();
        if m == 0 {
            return None;
        }
        // Charged to `PREP_COLD_NS` at the `Some` below, so an abandoned
        // build (duplicate base -> Gauss-Jordan) contributes nothing:
        // no plan was prepared, so there is no preparation to size.
        let t_prep = std::time::Instant::now();
        let bases: Vec<u16> = ks.iter().map(|&k| gf16::pow2(k as u64)).collect();
        // P(z) = Π (z + g_c), degree m: p[i] is the z^i coefficient.
        // Identical to invert_vandermonde's build - the same polynomial
        // in the same order, because it is the same factorization.
        let (p, locator_stats) = locator::build(&bases, joint);
        // d_c = Π_{k≠c}(g_c + g_k) = P'(g_c), and in characteristic 2
        // the formal derivative keeps only the odd coefficients:
        // P'(z) = Σ_j p[2j+1] * (z^2)^j.
        let dodd: Vec<u16> = (0..)
            .map(|j| 2 * j + 1)
            .take_while(|&i| i <= m)
            .map(|i| p[i])
            .collect();
        // The joint arm evaluates P' at the WHOLE field once (65,536
        // entries, 128 KB, transient) and then reads each column's
        // derivative out by index, against m Horner passes over an
        // m/2-term polynomial. Same values either way, asserted by
        // `field_derivative_matches_horner` in `unit_tests`.
        let field = joint.then(|| poly::evaluate_field(&dodd));
        let mut scales = vec![0u16; m];
        par_build(&mut scales, 1, 64, |c, slot| {
            let d = match &field {
                Some((values, _)) => values[gf16::mul(bases[c], bases[c]) as usize],
                None => {
                    let z2 = MulTable::new(gf16::mul(bases[c], bases[c]));
                    let mut d = 0u16;
                    for &coef in dodd.iter().rev() {
                        d = z2.mul(d) ^ coef;
                    }
                    d
                }
            };
            // A zero here is a duplicate base, which cannot happen for
            // valid ks; it leaves the scale zero and the caller refuses
            // below rather than solving a singular system quietly.
            slot[0] = if d == 0 {
                0
            } else {
                let neg_e0 = gf16::ORDER as u64 - (ks[c] as u64 * e0 as u64) % gf16::ORDER as u64;
                gf16::mul(gf16::inv(d), gf16::pow2(neg_e0))
            };
        });
        // The whole-field table is dead the moment the scales are built,
        // and must not still be resident while the plan's own O(m) and
        // O(m * 257) tables are allocated below.
        drop(field);
        if scales.contains(&0) {
            return None; // duplicate base - Gauss-Jordan takes it from here
        }

        let nseg = m.div_ceil(BLK);
        // ω = 2^257 has order 65535/257 = 255 = CONV.
        let wpow: Vec<u16> = (0..CONV)
            .map(|i| gf16::pow2(257 * i as u64 % gf16::ORDER as u64))
            .collect();
        // The reversed Hankel kernels: R_s[w] = p[s*BLK + 2*BLK-1 - w],
        // reversed so the correlation T_t = Σ_r S_r p[r+t+1] reads off
        // the CONVOLUTION at v = 2*BLK-2-t. Zero for s >= nseg, which is
        // the triangularity the spectral accumulate exploits below.
        let mut rhat = vec![0u16; nseg * CONV];
        par_build(&mut rhat, CONV, 1, |s, out| {
            for w in 0..CONV {
                let idx = s * BLK + 2 * BLK - 1 - w;
                let rv = if idx <= m { p[idx] } else { 0 };
                if rv == 0 {
                    continue;
                }
                let t = MulTable::new(rv);
                for (sigma, slot) in out.iter_mut().enumerate() {
                    *slot ^= t.mul(wpow[sigma * w % CONV]);
                }
            }
        });
        let stage1 = if mixed {
            // Good-Thomas split 255 = 3*5*17.  85, 51 and 120 are the CRT
            // idempotents for those radices. There are no twiddle factors;
            // the inverse matrices only negate the root exponent. Since
            // 255 is odd its field representation is one in characteristic
            // two, so the inverse DFT has no additional scale.
            Stage1Plan::Mixed {
                f3: dft_matrix(&wpow, 3, 85, false),
                f5: dft_matrix(&wpow, 5, 51, false),
                f17: dft_matrix(&wpow, 17, 120, false),
                i3: dft_matrix(&wpow, 3, 85, true),
                i5: dft_matrix(&wpow, 5, 51, true),
                i17: dft_matrix(&wpow, 17, 120, true),
            }
        } else {
            let mut fwd = vec![0u16; CONV * BLK];
            for sigma in 0..CONV {
                for r in 0..BLK {
                    fwd[sigma * BLK + r] = wpow[sigma * r % CONV];
                }
            }
            // Output v = 2*BLK-2-t, the same pruned direct inverse the
            // shipped path uses.
            let mut inv = vec![0u16; BLK * CONV];
            for t in 0..BLK {
                let v = 2 * BLK - 2 - t;
                for sigma in 0..CONV {
                    inv[t * CONV + sigma] = wpow[(CONV - sigma * v % CONV) % CONV];
                }
            }
            Stage1Plan::Direct { fwd, inv }
        };

        // Stage 2. α and β are the Good-Thomas halves: CRT on the
        // exponent ring Z_65535 ≅ Z_255 x Z_257 with 257^-1 ≡ 128 (mod
        // 255) and 255^-1 ≡ 128 (mod 257).
        let apow: Vec<u16> = (0..CONV)
            .map(|i| gf16::pow2(257 * 128 * i as u64 % gf16::ORDER as u64))
            .collect();
        let bpow: Vec<u16> = (0..GT2)
            .map(|i| gf16::pow2(255 * 128 * i as u64 % gf16::ORDER as u64))
            .collect();
        let mut t_order: Vec<u32> = Vec::with_capacity(m);
        let mut t_off: Vec<usize> = Vec::with_capacity(GT2 + 1);
        for t2 in 0..GT2 {
            t_off.push(t_order.len());
            let mut t = t2;
            while t < m {
                t_order.push(t as u32);
                t += GT2;
            }
        }
        t_off.push(t_order.len());
        // Columns grouped by k1 = k_c mod 255. Base logs are coprime to
        // 65535, so k1 is coprime to 255 and at most φ(255) = 128 groups
        // ever exist, whatever m is.
        let mut seen: Vec<Option<usize>> = vec![None; CONV];
        let mut k1s: Vec<usize> = Vec::new();
        let mut groups: Vec<Vec<u32>> = Vec::new();
        for (c, &k) in ks.iter().enumerate() {
            let k1 = k as usize % CONV;
            let g = *seen[k1].get_or_insert_with(|| {
                k1s.push(k1);
                groups.push(Vec::new());
                k1s.len() - 1
            });
            groups[g].push(c as u32);
        }
        let mut stage_a = vec![0u16; k1s.len() * m];
        par_build(&mut stage_a, m, 1, |g, row| {
            let k1 = k1s[g];
            for (idx, &t) in t_order.iter().enumerate() {
                row[idx] = apow[k1 * (t as usize % CONV) % CONV];
            }
        });
        let mut evalc = vec![0u16; m * GT2];
        par_build(&mut evalc, GT2, 8, |c, row| {
            let k2 = ks[c] as usize % GT2;
            let sc = MulTable::new(scales[c]);
            for (t2, slot) in row.iter_mut().enumerate() {
                *slot = sc.mul(bpow[k2 * t2 % GT2]);
            }
        });
        let mut plan = ForneyPlan {
            m,
            nseg,
            rhat,
            stage1,
            t_order,
            t_off,
            stage_a,
            evalc,
            groups,
            locator: if joint { p } else { Vec::new() },
            joint: None,
        };
        // Built LAST because it reads the finished plan: the locator
        // polynomial for its stage-1 kernel and the column groups for
        // its factored stage-2 coefficients.
        if joint {
            plan.joint = Some(joint::JointPlan::new(&plan, ks));
        }
        PREP_COLD_NS.fetch_add(t_prep.elapsed().as_nanos() as u64, Ordering::Relaxed);
        PREP_COLD.fetch_add(1, Ordering::Relaxed);
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some()
            && let Some(j) = &plan.joint
        {
            info!(
                target: "repair-timing",
                "  forney joint plan: {} KB of kernel tables, locator tree held <= {} KB ({} KB of it cached transforms)",
                j.heap_bytes() / 1024,
                locator_stats.peak_heap_bound / 1024,
                locator_stats.cache_heap / 1024,
            );
        }
        Some(plan)
    }

    /// Stripe width: a POWER OF TWO between [`STRIPE_GRAN`] and
    /// [`STRIPE_W_TARGET`]. The target IS the answer unless the memory
    /// budget refuses, in which case the stripe narrows one halving at a
    /// time - so the fast path is the default and a narrow stripe is the
    /// low-memory concession, not the other way round.
    /// `NZBFAST_BACKSUB_W` pins the width instead (a bench knob, and the
    /// A/B arm this was measured on).
    ///
    /// **The budget is the solve's own, not a new one.** This repair was
    /// admitted by `check_repair_dim_within` against
    /// `reconstruct::solve_window_budget` - the quarter-of-the-OOM-line
    /// figure `fastpar::ntt_default_budget` derives from RAM and any
    /// cgroup limit - having priced the `2 * m * block_size` window it
    /// holds for the whole solve. The stripe arenas are the rest of that
    /// same peak, so they are spent out of what the window LEFT - or, when
    /// that is less, out of a quarter of the budget
    /// ([`STRIPE_TARGET_BUDGET_SHARE`]) - and the admission decision is
    /// untouched: a shape that repairs today still repairs, only possibly
    /// on a narrower stripe.
    ///
    /// What it costs, per worker, is `(nseg + 3) * CONV * w` words: the
    /// `nseg * CONV` spectral arena plus the output spectrum and the two
    /// mixed-radix coordinate arenas. At nseg = 129 and w = 512 that is
    /// 33.7 MB each and ~404 MB across twelve workers, against a 2.1 GB
    /// window - ~20%, inside a budget that is 16 GiB on a 64 GB box.
    ///
    /// So the concession arm is RARE by construction, and worth saying
    /// out loud rather than leaving as an unexercised branch: the window
    /// grows with `m * block_size` and the arena with `nseg * w`, i.e.
    /// with `m / BLK`, so the arena is ~`512 * 255 * 2 / (128 * 2 *
    /// block_size)` = `1,020 / block_size` of the window per worker. It
    /// takes more than `block_size / 1,020` workers for the arena to
    /// reach the window at all - 64 on a 64 KiB set - and the budget is
    /// bigger than the window to begin with. The arm therefore binds
    /// only on a many-core box repairing SMALL blocks, and the unit test
    /// `stripe_narrows_only_when_the_solve_budget_is_short` pins both
    /// sides of that.
    ///
    /// A power of two, not merely a multiple of the granule, so that
    /// the LAST stripe is aligned too: block sizes are multiples of 64
    /// bytes in every set anyone posts, so `words % w` is then a whole
    /// number of granules as well.
    fn stripe_w(&self, words: usize) -> usize {
        if let Some(w) = std::env::var("NZBFAST_BACKSUB_W")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&w| w >= 16)
        {
            return w.min(words.max(1));
        }
        // One buffer only for a plan that will run the joint arm, and
        // only under the in-place switch - the one solve that holds one.
        let buffers = if self.joint.is_some() && super::reconstruct::in_place_output() {
            1
        } else {
            2
        };
        stripe_w_for_buffers(
            self.nseg,
            self.m,
            words,
            crate::mem::cpu_workers(),
            super::reconstruct::solve_window_budget() as u64,
            buffers,
        )
        .min(words.max(1))
    }

    /// Stage 1: `T_t = Σ_r S_r * p[r + t + 1]`, the blocked Hankel
    /// product. Consumes nothing; the caller drops the syndromes as
    /// soon as this returns, so the peak stays the two `m x block`
    /// buffers the dense product also holds.
    pub(super) fn hankel(&self, syn: &[Vec<u16>], words: usize) -> Vec<Vec<u16>> {
        let t0 = std::time::Instant::now();
        let mut t: Vec<Vec<u16>> = vec![vec![0u16; words]; self.m];
        let w = self.stripe_w(words);
        let mixed = self.stage1.is_mixed();
        per_stripe(&mut t, w, |off, cells| {
            let len = cells[0].len();
            let mut shat = vec![0u16; self.nseg * CONV * len];
            let mut chat = vec![0u16; CONV * len];
            // Two transform arenas, reused by every segment. They add
            // 510 rows to the nseg*255 spectral arena but replace each
            // direct 255x128 transform with the 3x5x17 network.
            let dft_words = if mixed { CONV * len } else { 0 };
            let mut dft_a = vec![0u16; dft_words];
            let mut dft_b = vec![0u16; dft_words];
            // GAUGED, because `stripe_w` now SPENDS to this number
            // rather than capping it at a flat 8 MiB: what a worker
            // holds here is part of the repair's peak and has to appear
            // in the memory floor like the rest of it.
            let _arena = crate::memgauge::Charge::new(
                crate::memgauge::Sub::RepairWork,
                ((shat.len() + chat.len() + dft_a.len() + dft_b.len()) * 2) as u64,
            );
            let mut ssrc: Vec<&[u16]> = Vec::with_capacity(BLK);
            let mut sp: Vec<&[u16]> = Vec::with_capacity(self.nseg);
            let mut coeffs: Vec<u16> = Vec::with_capacity(self.nseg);
            // Forward: one length-CONV DFT per input segment.
            for j in 0..self.nseg {
                let r0 = j * BLK;
                let r1 = (r0 + BLK).min(self.m);
                ssrc.clear();
                ssrc.extend(syn[r0..r1].iter().map(|row| &row[off..off + len]));
                match &self.stage1 {
                    Stage1Plan::Mixed { f3, f5, f17, .. } => {
                        dft_a.fill(0);
                        dft_b.fill(0);
                        dft17_sparse(&ssrc, &mut dft_a, len, f17);
                        dft5(&dft_a, &mut dft_b, len, f5);
                        dft3_to_natural(&dft_b, &mut shat[j * CONV * len..][..CONV * len], len, f3);
                    }
                    Stage1Plan::Direct { fwd, .. } => {
                        for sigma in 0..CONV {
                            let dst = &mut shat[(j * CONV + sigma) * len..][..len];
                            fold_rows(dst, &ssrc, &fwd[sigma * BLK..][..ssrc.len()]);
                        }
                    }
                }
            }
            // One output segment at a time: accumulate its spectrum,
            // then transform it straight back into T's rows, so only
            // ONE output spectrum is ever resident.
            for i in 0..self.nseg {
                chat.fill(0);
                // Kernels past nseg-1 are zero (p[.] runs out), so the
                // pair loop is triangular: j <= nseg-1-i.
                let jn = self.nseg - i;
                for sigma in 0..CONV {
                    sp.clear();
                    coeffs.clear();
                    for j in 0..jn {
                        sp.push(&shat[(j * CONV + sigma) * len..][..len]);
                        coeffs.push(self.rhat[(i + j) * CONV + sigma]);
                    }
                    let dst = &mut chat[sigma * len..][..len];
                    fold_rows(dst, &sp, &coeffs);
                }
                let t0 = i * BLK;
                let t1 = (t0 + BLK).min(self.m);
                match &self.stage1 {
                    Stage1Plan::Mixed { i3, i5, i17, .. } => {
                        dft_a.fill(0);
                        dft_b.fill(0);
                        idft3_from_natural(&chat, &mut dft_a, len, i3);
                        dft5(&dft_a, &mut dft_b, len, i5);
                        idft17_pruned(&dft_b, &mut cells[t0..t1], len, i17);
                    }
                    Stage1Plan::Direct { inv, .. } => {
                        let cs: Vec<&[u16]> = (0..CONV).map(|s| &chat[s * len..][..len]).collect();
                        for (tp, row) in cells[t0..t1].iter_mut().enumerate() {
                            fold_rows(&mut row[..], &cs, &inv[tp * CONV..][..CONV]);
                        }
                    }
                }
            }
        });
        SOLVE_STAGE1_NS.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        SOLVE_STAGE1.fetch_add(1, Ordering::Relaxed);
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            info!(
                target: "repair-timing",
                "  forney stage 1 (hankel, nseg={}, stripe {w}w, dft={}): {:.2?}",
                self.nseg,
                if mixed { "3x5x17" } else { "direct" },
                t0.elapsed()
            );
        }
        t
    }

    /// Stage 2: `x_c = scale_c * Σ_t T_t * 2^{k_c t}`, through the
    /// Good-Thomas split of the 65535-point transform. `out` must be
    /// zeroed - every row is written by exactly one stripe unit.
    pub(super) fn evaluate(&self, t: &[Vec<u16>], out: &mut [Vec<u16>]) {
        let t0 = std::time::Instant::now();
        let words = out.first().map_or(0, |r| r.len());
        let w = self.stripe_w(words);
        // Groups are TILED, and the tile is the whole point of the loop
        // order below. Stage 2 sweeps every row of T once per group, and
        // a row's stripe is a few hundred bytes out of every block-sized
        // row - a strided gather over the whole m x block buffer, with
        // nothing but the stripe of each page used. Measured at m =
        // 8,192 / 64 KiB on the M3 Ultra, one group at a time ran the
        // stage at 240 GB/s against stage 1's 472; tiling the groups so
        // one gather feeds `gtile` destinations puts the re-reads in
        // cache and takes the stage back to the kernel's rate. The tile
        // is sized by the same per-worker budget the stripe width is.
        let gtile = (SPECTRA_BUDGET / (GT2 * w.max(1) * 2)).clamp(1, self.groups.len().max(1));
        per_stripe(out, w, |off, cells| {
            let len = cells[0].len();
            let mut b = vec![0u16; gtile * GT2 * len];
            // Gauged for the same reason stage 1's arena is: it is part
            // of the repair's peak and the memory floor has to see it.
            let _arena = crate::memgauge::Charge::new(
                crate::memgauge::Sub::RepairWork,
                (b.len() * 2) as u64,
            );
            let mut tsrc: Vec<&[u16]> = Vec::with_capacity(self.m.div_ceil(GT2).max(1));
            for (tile, gt) in self.groups.chunks(gtile).enumerate() {
                let base = tile * gtile;
                b.fill(0);
                for t2 in 0..GT2 {
                    let (a, z) = (self.t_off[t2], self.t_off[t2 + 1]);
                    if a == z {
                        continue;
                    }
                    tsrc.clear();
                    tsrc.extend(
                        self.t_order[a..z]
                            .iter()
                            .map(|&r| &t[r as usize][off..off + len]),
                    );
                    for gi in 0..gt.len() {
                        let arow = &self.stage_a[(base + gi) * self.m..][..self.m];
                        fold_rows(&mut b[(gi * GT2 + t2) * len..][..len], &tsrc, &arow[a..z]);
                    }
                }
                for (gi, cols) in gt.iter().enumerate() {
                    let bs: Vec<&[u16]> = (0..GT2)
                        .map(|s| &b[(gi * GT2 + s) * len..][..len])
                        .collect();
                    for &c in cols {
                        let c = c as usize;
                        fold_rows(&mut cells[c][..], &bs, &self.evalc[c * GT2..][..GT2]);
                    }
                }
            }
        });
        SOLVE_STAGE2_NS.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            info!(
                target: "repair-timing",
                "  forney stage 2 (evaluate, {} group(s) in tiles of {gtile}, stripe {w}w): {:.2?}",
                self.groups.len(),
                t0.elapsed()
            );
        }
    }

    /// Both stages, for the harness and the bench door. The repair
    /// driver calls the halves separately so it can drop the syndromes
    /// between them.
    pub(super) fn solve(&self, syn: &[Vec<u16>], words: usize) -> Vec<Vec<u16>> {
        let t = self.hankel(syn, words);
        let mut out: Vec<Vec<u16>> = vec![vec![0u16; words]; self.m];
        self.evaluate(&t, &mut out);
        out
    }

    /// The JOINT arm's whole solve, or `None` when this plan was not
    /// built for it. `syn` is MOVED in and comes back as the rebuilt
    /// blocks in the same allocation - see `joint::ForneyPlan::run_joint`.
    ///
    /// A `None` here is the shipped path, not a failure: the caller
    /// falls through to `hankel` / `evaluate` with the syndromes it
    /// still owns.
    pub(super) fn solve_joint(&self, syn: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, Vec<Vec<u16>>> {
        match &self.joint {
            Some(j) => Ok(self.run_joint(j, syn)),
            None => Err(syn),
        }
    }

    /// Whether this plan carries a joint arm.
    pub(super) fn has_joint(&self) -> bool {
        self.joint.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constants are load-bearing arithmetic, not tuning: the
    /// blocked convolution is exact only because `CONV = 2*BLK - 1`, and
    /// the evaluation stage is a Good-Thomas split only because
    /// `CONV * GT2 = 65535` with the two halves coprime.
    #[test]
    fn split_constants_are_the_ones_the_algebra_needs() {
        assert_eq!(CONV, 2 * BLK - 1);
        assert_eq!(CONV * GT2, gf16::ORDER as usize);
        // Coprime halves are what makes the CRT index map a bijection.
        let (mut a, mut b) = (CONV, GT2);
        while b != 0 {
            (a, b) = (b, a % b);
        }
        assert_eq!(a, 1, "the Good-Thomas halves must be coprime");
    }

    /// `2^257` must have order exactly `CONV`, or the length-255 cyclic
    /// convolution in stage 1 is not a convolution at all.
    #[test]
    fn conv_root_has_exactly_the_convolution_order() {
        let w = gf16::pow2(257);
        let mut v = 1u16;
        for i in 1..=CONV {
            v = gf16::mul(v, w);
            assert_eq!(v == 1, i == CONV, "2^257 hit 1 at {i}, wanted {CONV}");
        }
    }

    /// The Good-Thomas layout must be a permutation of natural indices,
    /// and each coordinate must really be the three advertised residues.
    /// This is also the proof that source- and destination-pruning below
    /// cannot alias or silently omit a live row.
    #[test]
    fn good_thomas_coordinates_are_a_bijection() {
        let mut seen = [false; CONV];
        for a in 0..3 {
            for b in 0..5 {
                for c in 0..17 {
                    let n = gt_natural(a, b, c);
                    assert_eq!((n % 3, n % 5, n % 17), (a, b, c));
                    assert!(!seen[n], "CRT coordinates aliased natural index {n}");
                    seen[n] = true;
                }
            }
        }
        assert!(seen.into_iter().all(|v| v));

        // Every legal partial segment: the sparse forward admits exactly
        // n=0..len, and the pruned inverse emits exactly v=254-t for the
        // same local t range. Hold the sets independently of arithmetic.
        for len in 0..=BLK {
            let mut forward = [false; CONV];
            let mut inverse = [false; CONV];
            for n in 0..len {
                let coord = gt_index(n % 3, n % 5, n % 17);
                assert!(!forward[coord]);
                forward[coord] = true;
            }
            for t in 0..len {
                let v = CONV - 1 - t;
                let coord = gt_index(v % 3, v % 5, v % 17);
                assert!(!inverse[coord]);
                inverse[coord] = true;
            }
            assert_eq!(forward.into_iter().filter(|&v| v).count(), len);
            assert_eq!(inverse.into_iter().filter(|&v| v).count(), len);
        }
    }

    /// Hold the mixed-radix network to the definition of the direct DFT
    /// at partial-segment and fused-kernel tail boundaries. This calls
    /// the real row-fold helpers; the oracle is scalar GF multiplication
    /// and shares neither the factorization nor its indexing.
    #[test]
    fn mixed_dft_matches_direct_at_segment_edges() {
        let wpow: Vec<u16> = (0..CONV)
            .map(|i| gf16::pow2(257 * i as u64 % gf16::ORDER as u64))
            .collect();
        let (f3, f5, f17) = (
            dft_matrix(&wpow, 3, 85, false),
            dft_matrix(&wpow, 5, 51, false),
            dft_matrix(&wpow, 17, 120, false),
        );
        let (i3, i5, i17) = (
            dft_matrix(&wpow, 3, 85, true),
            dft_matrix(&wpow, 5, 51, true),
            dft_matrix(&wpow, 17, 120, true),
        );
        for (rows, words) in [
            (1usize, 1usize),
            (2, 15),
            (3, 16),
            (16, 17),
            (17, 31),
            (63, 32),
            (127, 33),
            (128, 48),
        ] {
            let input: Vec<Vec<u16>> = (0..rows)
                .map(|n| {
                    (0..words)
                        .map(|w| ((n * 0x9e37 + w * 0x79b9 + 1) & 0xffff) as u16)
                        .collect()
                })
                .collect();
            let refs: Vec<&[u16]> = input.iter().map(Vec::as_slice).collect();
            let mut a = vec![0u16; CONV * words];
            let mut b = vec![0u16; CONV * words];
            let mut got = vec![0u16; CONV * words];
            dft17_sparse(&refs, &mut a, words, &f17);
            dft5(&a, &mut b, words, &f5);
            dft3_to_natural(&b, &mut got, words, &f3);
            let mut want = vec![0u16; CONV * words];
            for sigma in 0..CONV {
                for n in 0..rows {
                    let c = wpow[sigma * n % CONV];
                    for w in 0..words {
                        want[sigma * words + w] ^= gf16::mul(c, input[n][w]);
                    }
                }
            }
            assert_eq!(got, want, "forward DFT: rows={rows} words={words}");

            // Independent, fully populated spectrum: an inverse of the
            // sparse forward alone would mostly return padded zeros and
            // would under-exercise the destination-pruning coefficients.
            let spectrum: Vec<u16> = (0..CONV * words)
                .map(|i| ((i * 0xd1b5 + rows * 0x4a33 + 7) & 0xffff) as u16)
                .collect();
            a.fill(0);
            b.fill(0);
            idft3_from_natural(&spectrum, &mut a, words, &i3);
            dft5(&a, &mut b, words, &i5);
            let mut out: Vec<Vec<u16>> = vec![vec![0; words]; rows];
            let mut out_refs: Vec<&mut [u16]> = out.iter_mut().map(Vec::as_mut_slice).collect();
            idft17_pruned(&b, &mut out_refs, words, &i17);
            for (t, row) in out.iter().enumerate() {
                let v = CONV - 1 - t;
                let mut direct = vec![0u16; words];
                for sigma in 0..CONV {
                    let e = sigma * v % CONV;
                    let c = wpow[if e == 0 { 0 } else { CONV - e }];
                    for w in 0..words {
                        direct[w] ^= gf16::mul(c, spectrum[sigma * words + w]);
                    }
                }
                assert_eq!(&direct, row, "inverse DFT: t={t} rows={rows} words={words}");
            }
        }
    }

    /// Whole Hankel-stage differential against the shipped direct DFT.
    /// The row counts straddle complete and partial 128-row segments;
    /// word widths straddle the 16-word NEON/AVX2 granule as well as the
    /// 32-word AVX-512 granule. A non-zero e0 also proves that building
    /// both plans through the real constructor does not perturb its
    /// other tables.
    #[test]
    fn mixed_hankel_matches_direct_across_segment_and_stripe_edges() {
        for (m, words) in [
            (1usize, 1usize),
            (127, 15),
            (128, 16),
            (129, 17),
            (254, 31),
            (255, 32),
            (256, 33),
            (257, 48),
            (389, 16),
        ] {
            let ks = crate::par2repair::input_base_logs(m).expect("inside PAR2 block limit");
            let direct_plan =
                ForneyPlan::prepare_with_dft(&ks, 0x51, false).expect("input bases are distinct");
            let mixed_plan =
                ForneyPlan::prepare_with_dft(&ks, 0x51, true).expect("input bases are distinct");
            let syn: Vec<Vec<u16>> = (0..m)
                .map(|r| {
                    (0..words)
                        .map(|w| ((r * 0x9e37 + w * 0x79b9 + 0x243f) & 0xffff) as u16)
                        .collect()
                })
                .collect();
            let direct = direct_plan.hankel(&syn, words);
            let mixed = mixed_plan.hankel(&syn, words);
            assert_eq!(mixed, direct, "Hankel stage: m={m} words={words}");
        }
    }

    /// Selection happens before table construction: a rollback plan must not
    /// pay for mixed matrices, and the production plan must not retain the
    /// much larger direct coefficient tables.
    #[test]
    fn stage1_plan_retains_only_the_selected_transform_tables() {
        let ks = crate::par2repair::input_base_logs(3).unwrap();
        let direct = ForneyPlan::prepare_with_dft(&ks, 7, false).unwrap();
        let mixed = ForneyPlan::prepare_with_dft(&ks, 7, true).unwrap();
        match direct.stage1 {
            Stage1Plan::Direct { fwd, inv } => {
                assert_eq!(fwd.len(), CONV * BLK);
                assert_eq!(inv.len(), BLK * CONV);
            }
            Stage1Plan::Mixed { .. } => panic!("direct plan retained the mixed implementation"),
        }
        match mixed.stage1 {
            Stage1Plan::Mixed {
                f3,
                f5,
                f17,
                i3,
                i5,
                i17,
            } => {
                assert_eq!(f3.len() + i3.len(), 2 * 3 * 3);
                assert_eq!(f5.len() + i5.len(), 2 * 5 * 5);
                assert_eq!(f17.len() + i17.len(), 2 * 17 * 17);
            }
            Stage1Plan::Direct { .. } => panic!("mixed plan retained the direct implementation"),
        }
    }

    /// The mixed network adds exactly two reusable 255-row arenas;
    /// together with the already-shipped output spectrum, fixed overhead
    /// stays below 765 KiB per worker at the maximum stripe width.
    ///
    /// Swept to [`MAX_INPUT_SLICES`], not `MAX_REPAIR_DIM`: this arm has
    /// no `MAX_REPAIR_DIM` cap - that constant guards the DENSE product
    /// and the Gauss-Jordan fallback, and `check_repair_dim_within`
    /// admits the transform arm on its memory window alone. The sweep
    /// stopped at `MAX_REPAIR_DIM / BLK` = 64 until 7 Sep 2026, i.e. it
    /// covered half the nseg range production reaches and none of the
    /// depths where the stripe was collapsing.
    #[test]
    fn mixed_dft_worker_scratch_is_bounded() {
        const MAX_FIXED: usize = 3 * CONV * STRIPE_W_TARGET * 2;
        assert_eq!(MAX_FIXED, 783_360);
        for nseg in 1..=crate::par2repair::MAX_INPUT_SLICES.div_ceil(BLK) {
            let w = stripe_w_for(nseg, nseg * BLK, 1 << 15, 32, 16 << 30);
            assert!(w <= STRIPE_W_TARGET);
            assert!(3 * CONV * w * 2 <= MAX_FIXED);
        }
    }

    /// The point of the 7 Sep 2026 fix: the target width is what a
    /// repair GETS, at every depth PAR2 can express, on a box that can
    /// afford it. Before it, `nseg` alone drove the width down - 512
    /// words to 64 between m = 3,277 and m = 16,385 - and cost 2x on the
    /// whole repair on the x86 nibble kernels.
    ///
    /// The shape here is the measured one made general: 64 KiB blocks,
    /// twelve workers, and the 16 GiB budget `ntt_default_budget`
    /// derives on a 64 GB box.
    #[test]
    fn stripe_holds_the_target_width_at_every_repair_depth() {
        for nseg in 1..=crate::par2repair::MAX_INPUT_SLICES.div_ceil(BLK) {
            let m = (nseg * BLK).min(crate::par2repair::MAX_INPUT_SLICES);
            assert_eq!(
                stripe_w_for(nseg, m, 1 << 15, 12, 16 << 30),
                STRIPE_W_TARGET,
                "nseg={nseg} lost the target stripe on a box that can afford it"
            );
        }
        // ...and the depth the anomaly was found at, spelled out: a
        // 1 GiB corpus at 64 KiB blocks rebuilt from nothing.
        assert_eq!(
            stripe_w_for(16385usize.div_ceil(BLK), 16385, 1 << 15, 12, 16 << 30),
            512
        );
    }

    /// The concession arm, which the doc comment argues is rare: the
    /// stripe narrows only when the solve budget has little left after
    /// the `2 * m * block_size` window, and it narrows by halvings down
    /// to [`STRIPE_GRAN`] rather than to zero.
    ///
    /// Small blocks and many workers are what it takes - the arena is
    /// `1,020 / block_size` of the window per worker - so these are
    /// 4 KiB blocks at the input-slice ceiling.
    #[test]
    fn stripe_narrows_only_when_the_solve_budget_is_short() {
        let (nseg, m, words) = (256, 32768, 2048);
        // Roomy: the window is 268 MB of a 16 GiB budget.
        assert_eq!(stripe_w_for(nseg, m, words, 32, 16 << 30), STRIPE_W_TARGET);
        // Tight: a 1 GiB budget leaves 805 MB, and 32 workers want
        // 2.16 GB at the target. Two halvings fit.
        assert_eq!(stripe_w_for(nseg, m, words, 32, 1 << 30), 128);
        // ...on the HEADROOM, which is why that bound is kept beside the
        // quarter share: 128 words is 541 MB here, past the 256 MiB
        // quarter, so halving against the share alone would have taken
        // this repair to the granule.
        assert!(
            (nseg as u64 + 3) * CONV as u64 * 128 * 2 * 32
                > (1u64 << 30) / STRIPE_TARGET_BUDGET_SHARE
        );
        // Tighter still, and it stops at the granule rather than
        // running off the bottom - a stripe off the granule builds a
        // FoldTable per source on every remainder (see STRIPE_GRAN).
        assert_eq!(stripe_w_for(nseg, m, words, 1024, 1 << 30), STRIPE_GRAN);
        // And a budget the window has already eaten whole still yields a
        // usable width rather than zero or a panic.
        assert_eq!(stripe_w_for(nseg, m, words, 32, 1 << 20), STRIPE_GRAN);
        assert_eq!(stripe_w_for(nseg, m, words, 32, 0), STRIPE_GRAN);

        // THE BOUNDED OVERSPEND (14 Sep 2026), at the measured slab: m =
        // 2,048 at a 32 KiB slab under a 128 MiB budget, four workers.
        // The window IS the budget, so the headroom is zero - and the
        // 512-word arenas are ~20 MB, under a quarter of it, so the target
        // stands rather than collapsing to the granule (1,024 stripe uses
        // and a 961 ms solve, against 64 uses and 586 ms).
        let (s_nseg, s_m, s_words) = (2048usize.div_ceil(BLK), 2048usize, 16384usize);
        let budget = 128u64 << 20;
        assert_eq!(
            s_m as u64 * s_words as u64 * 4,
            budget,
            "the window fills the budget"
        );
        assert_eq!(
            stripe_w_for(s_nseg, s_m, s_words, 4, budget),
            STRIPE_W_TARGET
        );
        // The same unslabbed at 64 KiB and m = 1,024, whose window also
        // lands exactly on 128 MiB and collapsed the same way.
        assert_eq!(
            stripe_w_for(1024usize.div_ceil(BLK), 1024, 32768, 4, budget),
            STRIPE_W_TARGET
        );
        // One worker past a quarter's worth of arenas and it narrows as it
        // always did - which is the many-core small-block shape the rest of
        // this test holds.
        let per_worker = (s_nseg as u64 + 3) * CONV as u64 * STRIPE_W_TARGET as u64 * 2;
        let over = (budget / STRIPE_TARGET_BUDGET_SHARE / per_worker) as usize + 1;
        assert!(stripe_w_for(s_nseg, s_m, s_words, over, budget) < STRIPE_W_TARGET);

        // THE HALVING (15 Sep 2026), at the shape that still collapsed: m =
        // 4,096 under the same 128 MiB is four 16 KiB slabs (8,192 words)
        // on four workers. The window fills the budget, so the headroom is
        // zero, and the 512-word arenas are 36.6 MB - over the 32 MiB
        // quarter, so the target does not stand. Narrowing against the
        // headroom took it to the granule (1,024 stripe uses, a 1.77 s
        // solve against 1.18 s); halving against the quarter stops at 256
        // words, 18.3 MB, one step down the measured width ladder (13.62
        // CPU-s at 512, 13.86 at 256, 17.92 at 32).
        let (q_nseg, q_m, q_words) = (4096usize.div_ceil(BLK), 4096usize, 8192usize);
        assert_eq!(
            q_m as u64 * q_words as u64 * 4,
            budget,
            "the window fills the budget"
        );
        let arenas = |w: usize| (q_nseg as u64 + 3) * CONV as u64 * w as u64 * 2 * 4;
        let quarter = budget / STRIPE_TARGET_BUDGET_SHARE;
        assert!(
            arenas(STRIPE_W_TARGET) > quarter,
            "the target misses the quarter"
        );
        assert!(arenas(256) <= quarter, "one halving fits it");
        assert_eq!(stripe_w_for(q_nseg, q_m, q_words, 4, budget), 256);
        // The arenas never exceed the quarter at the width chosen, wherever
        // the halving stops - down to the granule, which is the floor.
        for workers in [1usize, 2, 4, 8, 16, 64] {
            let w = stripe_w_for(q_nseg, q_m, q_words, workers, budget);
            let spent = (q_nseg as u64 + 3) * CONV as u64 * w as u64 * 2 * workers as u64;
            assert!(
                w == STRIPE_GRAN || spent <= quarter,
                "workers={workers}: {w} words spend {spent} past a {quarter} quarter"
            );
        }
    }

    /// In place (`NZBFAST_REPAIR_OUTPUT=inplace`, joint arm) the window is
    /// ONE buffer and each worker holds its own `m * w` words of `T`
    /// instead of the second one, so the stripe is priced with that term.
    /// Shape chosen so the quarter-share rule is not what decides: 32
    /// workers at m = 4,096 on a 32 KiB slab, with a budget of exactly the
    /// one-buffer window plus the T-less arenas at the target.
    #[test]
    fn an_in_place_stripe_prices_each_workers_t() {
        let (nseg, m, words, workers) = (4096usize.div_ceil(BLK), 4096usize, 16384usize, 32usize);
        let window = m as u64 * words as u64 * 2;
        let arenas_without_t =
            (nseg as u64 + 3) * CONV as u64 * STRIPE_W_TARGET as u64 * 2 * workers as u64;
        let budget = window + arenas_without_t;
        assert!(
            arenas_without_t > budget / STRIPE_TARGET_BUDGET_SHARE,
            "the share rule must not be what keeps the target at this shape"
        );
        // Without T the target would fit the headroom exactly; with it, one
        // halving is what fits.
        assert_eq!(
            stripe_w_for_buffers(nseg, m, words, workers, budget, 1),
            STRIPE_W_TARGET / 2
        );
        // Two buffers is the shipped rule, whatever door asks.
        assert_eq!(
            stripe_w_for_buffers(nseg, m, words, workers, budget, 2),
            stripe_w_for(nseg, m, words, workers, budget)
        );
    }

    /// The identity stage 2 is built on: with `α = 2^{257·128}` and
    /// `β = 2^{255·128}`, CRT on the exponent ring `Z_65535 ≅ Z_255 ×
    /// Z_257` gives `2^e = α^{e mod 255} · β^{e mod 257}`. Checked over
    /// the whole group, since it is only 65535 values and a sampled
    /// check would not be a proof of a CRT constant.
    #[test]
    fn good_thomas_halves_reconstruct_every_power() {
        let apow: Vec<u16> = (0..CONV)
            .map(|i| gf16::pow2(257 * 128 * i as u64 % gf16::ORDER as u64))
            .collect();
        let bpow: Vec<u16> = (0..GT2)
            .map(|i| gf16::pow2(255 * 128 * i as u64 % gf16::ORDER as u64))
            .collect();
        for e in 0..gf16::ORDER as usize {
            assert_eq!(
                gf16::pow2(e as u64),
                gf16::mul(apow[e % CONV], bpow[e % GT2]),
                "CRT split disagreed at e={e}"
            );
        }
    }

    /// The default arm of the gate, pinned to the constant it documents -
    /// and, when the process is run under the escape hatch, the OVERRIDE
    /// arm instead of nothing at all.
    ///
    /// Deliberately does NOT set `NZBFAST_BACKSUB`: it is a process-wide
    /// escape hatch and this binary runs every other test beside this
    /// one (the one-process rule in CONTRIBUTING.md's build section).
    ///
    /// IT USED TO SIMPLY RETURN when the variable was set, and that made
    /// it a green tick over nothing on the one CI job that deliberately
    /// sets it: the `dense-solve-arm` job runs this whole binary under
    /// `NZBFAST_BACKSUB=dense`, so the one test that pins the threshold
    /// passed there by doing nothing, and no count-based invariant can
    /// see that - a self-returning test reports as `passed` like any
    /// other. Measured 16 Sep 2026 under claim
    /// `dense-arm-no-proof-any-test-took-it-16sep`: exactly four tests in
    /// that job's whole filter observe a different gate answer when the
    /// arm is forced (six on aarch64, whose constant is lower), so the
    /// forced run could not afford to lose one of them to a vacuum.
    ///
    /// So the forced arms are asserted here instead of skipped, and what
    /// they assert is the property a refactor quietly making
    /// `NZBFAST_BACKSUB` a no-op would break: under `dense` the gate is
    /// false at every m, under `forney` true at every m. On a part with a
    /// fused multi kernel - every runner in this fleet, and the x86 box
    /// that job runs on - the `dense` answer at the constant is a FLIP of
    /// what the default rule would have said, so the assertion is not
    /// vacuous there. On a part without one (armv7) it agrees with the
    /// default, which is harmless: armv7 never sets the variable.
    ///
    /// The name is kept across that widening on purpose - it is the name
    /// in the 4 Sep 2026 armv7 claim and in a shelf of research run logs,
    /// and a rename would make every one of those references misleading.
    ///
    /// The default arm is TWO conditions, and this pins both. It used to
    /// assert a bare `true` at the constant, which is the answer on every
    /// part that has a fused multi kernel and the WRONG one on a part that
    /// does not - `backsub_gate` says so itself, four lines above the
    /// expression: "on a part with no fused kernel (armv7, or an
    /// `NZBFAST_GF16_MULTI=0` kernel A/B) the measured ratios do not
    /// transfer and the dense product keeps the shape". So the nightly
    /// armv7-cross job failed here on a gate that was behaving exactly as
    /// documented (run 33737735769), and an `NZBFAST_GF16_MULTI=0` A/B on
    /// any box would have failed it the same way.
    ///
    /// Derived from `multi_fold_width()` rather than gated out on armv7:
    /// the constant is still pinned wherever it is observable, and where
    /// it is not, the no-kernel behaviour the gate promises is pinned
    /// instead. Both arms are checked on every part.
    #[test]
    fn gate_defaults_to_the_measured_constant() {
        // The escape hatch's own arms, which this test is the only
        // reader of. `backsub_gate`'s match is the subject: an override
        // that stopped overriding would answer the default rule here.
        match std::env::var("NZBFAST_BACKSUB")
            .unwrap_or_default()
            .as_str()
        {
            forced @ ("dense" | "0" | "off") => {
                for m in [0, 1, backsub_min_missing(), usize::MAX] {
                    assert!(
                        !backsub_gate(m),
                        "NZBFAST_BACKSUB={forced} must force the dense product at every m, and it did \
                         not at m={m} - the override is a no-op, so the job that sets it is \
                         running the arm it was already running"
                    );
                }
                return;
            }
            forced @ ("forney" | "1") => {
                for m in [0, 1, backsub_min_missing(), usize::MAX] {
                    assert!(
                        backsub_gate(m),
                        "NZBFAST_BACKSUB={forced} must force the transform solve at every m, and it \
                         did not at m={m} - the override is a no-op"
                    );
                }
                return;
            }
            // Unset, or a spelling `backsub_gate` does not recognise:
            // either way it takes the default rule, which is what the
            // rest of this test pins.
            _ => {}
        }
        let fused = gf16::multi_fold_width() > 0;
        let gate = backsub_min_missing();
        assert!(!backsub_gate(gate - 1));
        assert_eq!(
            backsub_gate(gate),
            fused,
            "at the constant the gate is the fused-multi-kernel arm alone"
        );
        // aarch64 takes its own constant, the nibble arms (fan-in 4) the
        // lower x86 one, every other arm the original; each is pinned
        // wherever it is observable.
        assert_eq!(
            gate,
            if cfg!(target_arch = "aarch64") {
                BACKSUB_MIN_MISSING_NEON
            } else if gf16::multi_fold_width() == 4 {
                BACKSUB_MIN_MISSING_NIBBLE
            } else {
                BACKSUB_MIN_MISSING
            }
        );
    }
}
