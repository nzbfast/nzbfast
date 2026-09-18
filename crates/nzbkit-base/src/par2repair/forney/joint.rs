//! The JOINT solve: one owned buffer, one fused constructor-and-solver.
//!
//! The DEFAULT on aarch64, on AVX-512 GFNI since 11 Sep 2026, and on
//! `Gfni256` and `Nibble` since 12 Sep 2026, each on its own native
//! round; `--fast` or `NZBFAST_FORNEY_JOINT=1` on any x86 class still
//! out ([`joint_default_on`] names what is in and what is not).
//! When [`joint_gate`] says no this module builds no plan, allocates
//! nothing and is never entered; the repair takes
//! [`super::ForneyPlan::hankel`] and [`super::ForneyPlan::evaluate`]
//! exactly as it has since 3 Sep 2026. [`joint_default_on`] carries the
//! measurement behind the default and the reason x86 is excluded.
//!
//! # Two independent ideas, spliced
//!
//! **Arithmetic** ([`super::whole`], [`super::peel`], [`super::tail`]).
//! Stage 1's blocked cyclic convolution becomes ONE additive-FFT
//! polynomial product, with the `nseg^2` spectral accumulate gone
//! entirely, and stage 2's per-group sweep is refactored so the part of
//! its coefficient that depends only on the row is folded once for all
//! 17 residues instead of once per group ([`FactorPlan`]).
//!
//! **Storage** (this file's [`per_stripe_bounded`]). The shipped driver
//! holds the syndromes, builds a full `m x block` T, drops the
//! syndromes, allocates a full `m x block` output and evaluates into it.
//! Here the caller hands its syndrome rows over BY VALUE and gets them
//! back as the output: each stripe builds a `m x stripe` T locally,
//! consumes the stripe's syndrome columns into it, and then overwrites
//! those same columns with the answer.
//!
//! The two are structurally disjoint - one is the stripe BODY, the other
//! the stripe SCHEDULER - which is why they compose without either being
//! weakened. `research/JOINT-FORNEY-INTEGRATION-2026-09-10.md` carries
//! the integration's own proofs and measurements, and cites the
//! component study that measured the combination against each idea
//! alone: mildly super-additive at five of six cells, 12/12 positive
//! comparisons everywhere.
//!
//! # Memory: bounded by the arm it replaces, at every shape
//!
//! Three allocations, and each is capped against what the shipped path
//! already holds:
//!
//! - The syndrome/output buffer is the CALLER'S, moved in and moved
//!   back out. One `m x block` buffer where the shipped path holds two
//!   in sequence.
//! - The local T is `m x w` per worker, and there are at most
//!   `min(cpu_workers, ceil(words / w))` workers, so the total is at
//!   most `m x words` - the full T the shipped path allocates. Pinned by
//!   `local_t_never_exceeds_the_full_t` below.
//! - The kernel arena is `n x kernel_w` per worker, and
//!   [`super::whole::admitted_width`] narrows `kernel_w` until that fits
//!   the byte allowance stage 1's `(nseg + 3) * CONV * w` spectral arena
//!   would have had. A width of zero means it cannot, and the solve
//!   falls back rather than spending more. Since 12 Sep 2026 the
//!   narrowing is stage 1's alone: it runs the stripe in sub-stripes of
//!   `kernel_w` while T and stage 2 keep the shipped `w`
//!   ([`JointStripe::kernel_w`] carries the measurement). Before that
//!   the whole stripe narrowed, and the shipped stage-2 arithmetic ran
//!   at half width on every depth just past a power of two.
//!
//! Every one of them is gauged into `memgauge::Sub::RepairWork` the way
//! the shipped arenas are, so the memory floor sees the joint arm the
//! same way it sees the arm it replaces.
//!
//! # Fallback, cancellation and errors are the shipped ones
//!
//! There is no new failure mode here. A geometry the additive kernel
//! cannot take (odd word counts, an unaligned stripe, no fused scale
//! kernel, the direct stage-1 plan) runs [`ForneyPlan::owned_hankel`]
//! instead, and a depth below [`JOINT_FACTOR_MIN_M`] runs
//! [`ForneyPlan::owned_evaluate`] - the shipped arithmetic, unchanged,
//! just inside the bounded scheduler. A plan that cannot be built at
//! all leaves `joint` as `None` and the repair takes the shipped
//! two-stage path. Neither stage has ever had a cancellation point or a
//! fallible return, and neither gains one.
//!
//! **The two fallbacks are INDEPENDENT since 11 Sep 2026**, and all
//! four combinations are reachable: stage 1 is gated on geometry (and,
//! since 12 Sep 2026, on depth on the two x86 classes where the kernel
//! was priced alone and lost below 16,384 - [`JOINT_KERNEL_MIN_M_X86`])
//! and stage 2 on depth, because stage 2's factored evaluation is a loss
//! below its crossover. [`ForneyPlan::joint_stripe`] is the one place
//! all three questions are asked; [`JOINT_FACTOR_MIN_M`] and
//! [`JOINT_KERNEL_MIN_M_X86`] carry the measurements.
use super::{
    BLK, CONV, ForneyPlan, GT2, PREP_STRIPE_USES, SOLVE_STAGE1, SOLVE_STAGE1_NS, SOLVE_STAGE2_NS,
    SPECTRA_BUDGET, Stage1Plan, dft3_to_natural, dft5, dft17_sparse, fold_rows, idft3_from_natural,
    idft17_pruned, peel, tail, whole,
};
use crate::gf16;
use crate::sync::MutexExt;
use std::sync::atomic::Ordering;
use tracing::info;

/// A caller's explicit answer, when it gave one, overriding the
/// environment for this PROCESS. `0` is unset, `1` off, `2` on.
///
/// An atomic rather than `std::env::set_var`, which is `unsafe` in
/// edition 2024 for a good reason: this engine runs scoped threads
/// throughout, and a `setenv` racing another thread's `getenv` is
/// undefined behaviour in the C library underneath, not merely a lost
/// update.
static JOINT_ARM: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Arm or disarm the joint solve for this process, whatever
/// `NZBFAST_FORNEY_JOINT` says.
///
/// The one caller is a CLI switch (`parfast --fast`). Call it BEFORE
/// the first `ForneyPlan::prepare`, because the plan is what carries
/// the joint arm and a plan built unarmed stays unarmed for its own
/// repair - which is the right shape, not a limitation: a repair does
/// not change solver half way through.
pub fn set_joint_arm(on: bool) {
    JOINT_ARM.store(if on { 2 } else { 1 }, Ordering::Relaxed);
}

/// The effective arm state, reading the same rule the solve reads.
///
/// Exists so a caller that publishes the switch can PROVE it reached
/// the engine rather than only that it parsed: a parfast switch that
/// parses and reaches nothing is this repo's own documented defect
/// (`-m` and `-t` both shipped that way).
pub fn joint_armed() -> bool {
    joint_gate()
}

/// Why a solve did NOT run the joint stage-1 kernel.
///
/// The arm is conditional on the HOST and on the SET, and until 11 Sep
/// 2026 every one of these conditions was silent: `--fast` was accepted,
/// the joint plan was built and paid for, the shipped arithmetic ran,
/// and the only trace of it was the word FALLBACK inside a
/// `repair-timing` line behind an environment variable nobody sets
/// (TODO 340). A switch that is accepted and reaches nothing has to say
/// so, which is what this exists for; the sentences a user reads are
/// parfast's, so that the engine holds the FACT and the CLI holds the
/// voice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JointDecline {
    /// The repair never reached the Forney solver at all - too few
    /// blocks missing for [`super::backsub_gate`], recovery packets
    /// lost so the exponents carry no structure to exploit, or a BUILD
    /// with no fused fold kernel (`gf16::multi_fold_width() == 0`: the
    /// armv7 tarball), where that gate answers no at every depth and
    /// the `Scalar` remedy on `ScaleKernel` is never consulted. Recorded
    /// by `par2repair::reconstruct`, which is where that fork is taken;
    /// nothing in this module can see it. parfast tells the three apart.
    NotForney,
    /// The block size is not a multiple of 32 bytes, so a stripe is not
    /// a whole number of the 16-word units every stage-1 kernel
    /// consumes. The commonest decline BY FAR on sets parfast writes
    /// itself: `create::block_size` searches in steps of four, which
    /// lands on a multiple of 32 about one time in eight.
    BlockAlignment,
    /// [`gf16::scale_available`] is false: this CPU has no vector
    /// in-place scale, so stage 1's pointwise step would build a
    /// 512-entry table per row. The x86 GFNI case, and the whole of
    /// TODO 340's second half.
    NoScaleKernel,
    /// The kernel's additive arena will not fit the memory the shipped
    /// arm was allowed, even at the narrowest stripe.
    KernelArena,
    /// Stage 1's plan is not the mixed form the joint kernel solves.
    NotMixed,
    /// HELD on the shipped arithmetic by `NZBFAST_FORNEY_STAGE1=owned`,
    /// a measurement knob and never a shipped condition: it is what a
    /// round pairs against to price the additive kernel ALONE inside
    /// the joint scheduler, the way `NZBFAST_FORNEY_FACTOR` prices
    /// stage 2 alone. Reported like the others so a leg that set it by
    /// mistake cannot read as a kernel win.
    Held,
}

/// What the last repair's solves did with the joint stage-1 kernel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JointReach {
    /// No solve made the decision - nothing to repair, or the arm was
    /// never armed.
    Untouched,
    /// At least one solve RAN the kernel, and none declined.
    Taken,
    /// At least one solve declined, for this reason.
    Declined(JointDecline),
}

/// `0` untouched, `1` taken, and one code from `2` up per
/// [`JointDecline`] - the mapping is [`decline_code`] and its inverse
/// [`reach_of`], which a test holds together. Not derived from the
/// variant's position: an enum reordering must not silently repoint a
/// reason at a different sentence.
static JOINT_REACH: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn decline_code(d: JointDecline) -> u8 {
    match d {
        JointDecline::NotForney => 2,
        JointDecline::BlockAlignment => 3,
        JointDecline::NoScaleKernel => 4,
        JointDecline::KernelArena => 5,
        JointDecline::NotMixed => 6,
        JointDecline::Held => 7,
    }
}

/// Record that a solve TOOK the joint stage-1 kernel. Never overwrites
/// a decline: a repair whose solves disagree is a repair that fell back,
/// and the report a user reads must say the weaker of the two things.
fn note_joint_taken() {
    let _ = JOINT_REACH.compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed);
}

/// Record that a solve DECLINED, keeping the first reason. Overwrites a
/// `Taken`, for the reason on [`note_joint_taken`].
pub(crate) fn note_joint_declined(d: JointDecline) {
    let want = decline_code(d);
    let mut cur = JOINT_REACH.load(Ordering::Relaxed);
    while cur < 2 {
        match JOINT_REACH.compare_exchange_weak(cur, want, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(c) => cur = c,
        }
    }
}

/// What the solves since the last [`reset_joint_reach`] did.
///
/// The one caller is a CLI that has to tell the user whether the switch
/// it accepted did anything. It reports the SOLVE's decision and not the
/// plan's, because the plan is built either way - the cost `--fast` pays
/// on a host that then declines is exactly what makes silence a defect
/// rather than a cosmetic gap.
pub fn joint_reach() -> JointReach {
    reach_of(JOINT_REACH.load(Ordering::Relaxed))
}

/// [`decline_code`]'s inverse. Separate so a test can prove the pair
/// round-trips without touching the process-global latch.
fn reach_of(code: u8) -> JointReach {
    match code {
        0 => JointReach::Untouched,
        1 => JointReach::Taken,
        2 => JointReach::Declined(JointDecline::NotForney),
        3 => JointReach::Declined(JointDecline::BlockAlignment),
        4 => JointReach::Declined(JointDecline::NoScaleKernel),
        5 => JointReach::Declined(JointDecline::KernelArena),
        6 => JointReach::Declined(JointDecline::NotMixed),
        _ => JointReach::Declined(JointDecline::Held),
    }
}

/// Clear the record, for a process that repairs more than once - the
/// daemon does, and a stale decline from the previous job would be
/// reported against this one. Call BEFORE the repair, never after.
pub fn reset_joint_reach() {
    JOINT_REACH.store(0, Ordering::Relaxed);
}

/// Whether the joint arm is armed.
///
/// Precedence, highest first: an explicit [`set_joint_arm`] - which is
/// what `parfast --fast` calls - wins over everything in BOTH
/// directions, so a CLI can disarm a box whose environment armed it;
/// then `NZBFAST_FORNEY_JOINT`, also both directions; then
/// [`joint_default_on`].
///
/// The environment arm reads `0`/`off`/`shipped` as well as the
/// affirmative spellings since the default moved. Before that, "unset"
/// and "off" were the same answer and only the affirmative needed a
/// spelling; now they are different answers and a measurement round that
/// wants the shipped solve has to be able to SAY so rather than relying
/// on a default that is exactly what it is measuring.
pub(crate) fn joint_gate() -> bool {
    match JOINT_ARM.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => match std::env::var("NZBFAST_FORNEY_JOINT").as_deref() {
            Ok("1" | "on" | "joint") => true,
            Ok("0" | "off" | "shipped") => false,
            _ => joint_default_on(),
        },
    }
}

/// Whether the joint arm runs with NOTHING set: no `--fast`, no
/// environment variable. **True on aarch64, on AVX-512 GFNI since
/// 11 Sep 2026, and on `Gfni256` AND `Nibble` since 12 Sep 2026 - the
/// Core Ultra 9 is width 6 and the i5-10600KF width 4, each a different
/// kernel from the EPYC's 12, and each admitted on its own native
/// round.** No x86 class is held out by this function any more; the
/// asymmetry the older wording described was PROVENANCE (which part had
/// run a round) rather than a judgement about the hardware, and every
/// part has now run one.
///
/// This doc said "Still off: `Nibble`" until 16 Sep 2026, four days
/// after the body below started returning true for it. That is not
/// cosmetic on this function: an A/B that sets nothing on the control
/// arm, on the strength of a stale default, races the joint arm against
/// itself - the trap `rowop.rs` warns about for the GFNI flip.
///
/// # Why there is no threshold here
///
/// The obvious shape for this - and the one the question was asked in -
/// is a per-class minimum `m`, the way [`super::BACKSUB_MIN_MISSING`]
/// and friends gate the solver above. There is no such constant here
/// because the measurement did not find a crossing to put one at. The
/// joint arm already passes through TWO depth gates before it can cost
/// anything:
///
/// - below [`super::backsub_min_missing`] (704 on NEON) the Forney
///   solver is not reached at all, so no plan is built, nothing is
///   allocated, and the two arms are the same code. Every round below
///   reads that band as an end-to-end A/A and uses it as its floor.
/// - below [`JOINT_FACTOR_MIN_M`] (8,192) stage 2 takes the shipped
///   evaluation, which is the arm that was losing shallow.
///
/// What is left between them is stage 1's additive product and the
/// owned-buffer stripe scheduler, and neither has a crossover on THIS
/// class: on NEON stage 1 measured faster at every depth and the
/// scheduler holds one `m x block` buffer where the shipped driver holds
/// two in sequence. (On the two x86 classes measured on 12 Sep 2026 the
/// kernel DOES have a crossover, at [`JOINT_KERNEL_MIN_M_X86`]; that is
/// a stage-1 gate on those classes, not a change to this default.) So "engaged all the time, but not active where it
/// does not help" is already the shape of the code, and the only thing
/// this function adds is the word ALL.
///
/// # The measurement
///
/// `research/JOINT-CROSSOVER-PER-CLASS-2026-09-11.md`. One binary
/// (`8c3da7d70d2d`), 14 rungs from 256 to 16,384, whole-arm A/B (`off`
/// against `--fast`) with a byte-identical `aa` arm at EVERY rung
/// supplying a paired per-depth noise floor. Whole-repair wall, median
/// of the paired reps, positive = `--fast` faster:
///
/// ```text
///   m        M1 Ultra   M3 Ultra   verdict
///   256        +0.48      +0.84    A/A - the arm cannot engage here
///   704        +0.83      -1.14    wash
///   1024       +0.57      +0.83    wash
///   1536       +0.21      +0.33    wash
///   2048       +2.51      +2.17    wash to small win
///   3072       +1.88      +0.76    wash to small win
///   4096       +5.37      +3.99    win
///   5120       +2.49      +5.86    win
///   6144       +4.86      +7.38    win
///   7168       +5.96     +12.03    win
///   8192       +9.86     +12.93    win   <- JOINT_FACTOR_MIN_M
///   10240      +5.61     +15.28    win
///   12288     +14.88     +19.90    win
///   16384     +20.72     +19.39    win
/// ```
///
/// **Not one rung on either box is a loss.** The worst reading anywhere
/// is -1.14% at m = 704 on the M3, against that rung's own 2.74% A/A
/// floor. The m = 256 row is what makes the rest readable: the arm
/// cannot engage below the Forney gate, the round's `stage1=no-label`
/// column proves it did not, and the row still reads +0.5% to +0.8% -
/// so that is the size of a zero on this rig, and 704 through 3,072 are
/// reported as washes rather than as small wins.
///
/// The BEFORE arm is what makes this a finding rather than a
/// reassurance. The same comparison on the pre-gate binary, same box
/// class, read -6.89% at m = 1,024 and -4.62% at m = 2,048, crossing
/// over near 4,096. The shallow band moved six to seven points and
/// changed sign, and the deep end did not move at all - which is the
/// control, because the stage-2 gate was not supposed to touch it.
///
/// Two further columns, both in the note: peak RSS is flat to the noise
/// shallow and up to 24% LOWER at depth (the owned-buffer claim, holding
/// one `m x block` buffer where the shipped driver holds two), and the
/// stage labels split the table in half - 704 to 7,168 is stage 1 and
/// the scheduler ALONE with `stage2=FALLBACK`, 8,192 up is both stages.
/// The band that used to lose is exactly the band where stage 2 now
/// declines.
///
/// Resolution, stated rather than implied: at the shallow rungs the legs
/// are 1.7-3.7 s and the paired floor is 1-5%, so that fixture can say
/// "not a loss" and cannot say "exactly zero". Do not quote those rows
/// as if it could.
///
/// Neither axis moves it, and both are now measured rather than assumed.
/// Block size: the same ladder at 1 MiB, a 4x change, agrees to about a
/// point at the deep end. SET SHAPE: swept 12 Sep 2026 over
/// n = 8,192 / 16,384 / 32,768 - a 4x range - with members held at 32 and
/// only the blocks per member moving, same box, same binary, five reps.
/// **m\* lands on the same rung at all three**
/// (`research/JOINT-CROSSOVER-N-AXIS-2026-09-11.md`). So a threshold on
/// `m` ALONE is the right shape on this class, which is what was in
/// question; the value is not what that round tested.
///
/// The gain does not stay constant over that range - it falls from
/// +8.50% to +2.47% at the crossing rung as the solve's share of a whole
/// repair shrinks - and that is the round's evidence rather than a
/// caveat to it: a rig that could not resolve an n-dependence would have
/// shown a flat gain AND a flat crossing, and the two could not be told
/// apart.
///
/// Two cautions from that round before quoting a NUMBER from either it or
/// the note above. Its absolute m\* is one rung higher than the corrected
/// value, because `jcross` alternated three arms with `reversed()`, which
/// leaves the middle one fixed, so the arm under test was never first or
/// last; the bias is common to every column and so does not reach the
/// comparison. And the n axis is measured on NEON ONLY - the Nibble class
/// has a crossing of its own in 6,144-7,168 as of 12 Sep 2026 and nobody
/// has varied `n` against it. Stage 2 folds `GT2 * 17` accumulators per
/// stripe whatever `n` is, so the structure predicts the same answer
/// there, which is a prediction and not a measurement.
///
/// # How each x86 class came in
///
/// **AVX-512 GFNI came in on 11 Sep 2026 on its own native round** (an
/// EPYC 9354P, both bands, no rung a loss) - see the body below and
/// `research/JOINT-DEFAULT-ON-X86-GFNI-2026-09-11.md`. Two classes were
/// out for one more day, and neither because it measured badly: because
/// it had not measured, each fleet part having held a rig lock.
///
/// - **`Gfni256`** - GFNI without AVX-512, fan-in 6. The EPYC round did
///   NOT cover it: that part is `Avx512Gfni` at fan-in 12, a different
///   kernel. In on 12 Sep on the Core Ultra 9 386H.
/// - **`Nibble`** - AVX2 or SSSE3, fan-in 4. In on 12 Sep on the
///   i5-10600KF, and it is the class that had LOST the 11 Sep whole-arm
///   round - nine of fourteen rungs, -12.9% at 5,120. Two changes in
///   this module between that round and the default turned it: stage 2
///   keeps the shipped stripe width, and stage 1 runs the shipped Hankel
///   below `JOINT_KERNEL_MIN_M_X86`. The body carries the ladder.
///
/// `research/JOINT-CROSSOVER-PER-CLASS-2026-09-11.md` section 8 carries
/// the command lines. The rule that admitted them stands for whatever
/// class comes next: a class moves into this function when it has its
/// OWN round, not when it seems likely to behave like a class that
/// does - the nibble ladder is the standing proof, since predicting it
/// from the GFNI rounds would have been exactly wrong before the two
/// changes above and exactly right after.
///
/// # What "class" means here is COARSER than "kernel", deliberately
///
/// `KernelClass` keys on the fold kernel's fan-in
/// (`gf16::multi_fold_width`), and `4` is returned for AVX2 and for
/// SSSE3 alike - two kernels at two vector widths, 256-bit and 128-bit,
/// reported as one `Nibble` class. So a round on an AVX2 part admits
/// SSSE3 parts as a side effect, and the census gate on the `joint-arm`
/// seam cannot tell the two apart.
///
/// That is the SHIPPED position one level down rather than something
/// this function invents: [`super::BACKSUB_MIN_MISSING_NIBBLE`] gates
/// "AVX2 or SSSE3 without GFNI" with a single number measured on an
/// i5-10600KF, which is an AVX2 part. Reproducing the granularity here
/// keeps one story rather than two.
///
/// It is worth saying out loud because it reads as finer than it is: the
/// promise above is "a class has its own round", and a reader can hear
/// "this kernel has its own round". If a vector-width difference is ever
/// shown to move one of these crossings, the fix is to split
/// `KernelClass`, not to add a special case here - and both gates would
/// need it in the same commit.
///
/// The practical consequence for the one class with NO hardware anywhere
/// on this fleet - SSSE3 without AVX2, Intel before Haswell and AMD
/// before Excavator - is that it needs no forced-kernel round and no
/// weaker tier of evidence to qualify. It is admitted by the nibble
/// round on the same terms the Forney gate already admits it. A forced
/// kernel on a modern part measures THAT part's memory system, not the
/// old one's, which is why it is not wanted here even as a supplement.
///
/// The capability side agrees since `211308b0fa`, and it did not before:
/// `gf16::scale_kernel()` gained an `Ssse3Nibble` arm that morning, so
/// such a part now HAS the in-place vector scale stage 1 requires and
/// engages rather than declining. Admitting it here is therefore
/// admitting a part that can actually take the path, not one that would
/// have fallen back anyway.
fn joint_default_on() -> bool {
    if cfg!(target_arch = "aarch64") {
        return true;
    }
    // The AVX-512 GFNI class, added 11 Sep 2026 on its own round, and
    // the 256-bit GFNI class, added 12 Sep 2026 on ITS own round (the
    // second block below). Two arms, one per class, each keyed on the
    // census's own class predicate and never on a looser ISA test.
    //
    // `avx512_gfni_available()` and NOT `gfni256_available()`, which is
    // a distinction the census draws and this nearly flattened on 11 Sep:
    // the AVX-512 round ran on an EPYC 9354P, which `KernelClass::current()`
    // reports as `Avx512Gfni` (`multi_fold_width() == 12`). A Core Ultra
    // 9 is `Gfni256` (width 6), a different kernel and a different
    // class, and on 11 Sep it had NOT been measured for this arm. `gfni`
    // + `avx2` is true on both, so the looser predicate would have turned
    // the default on for a class with no round behind it - which is the
    // thing `the_joint_default_is_only_on_for_classes_the_census_covers`
    // exists to refuse, and it would have refused it. The Gfni256 arm
    // that followed keeps the same discipline the other way round: it
    // asks `KernelClass::current()` for the class rather than `gfni` +
    // `avx2`, so a forced nibble kernel or `NZBFAST_GF16_MULTI=0` (both
    // of which move the class) moves this default with it.
    //
    // Measured on an EPYC 9354P, native AVX-512 GFNI (no forced kernel), `off`
    // against `--fast`, medians of three, SHA-256 restoration gating
    // every leg. `research/JOINT-DEFAULT-ON-X86-GFNI-2026-09-11.md`:
    //
    //     shallow   2,048 +4.4% (3/3)   4,096 +1.6% (2/3)   6,144 +3.7% (3/3)
    //     deep      8,192 +29.7%       16,384 +24.9%       24,576 +29.1%  (3/3)
    //
    // THAT BOX'S SHALLOW NUMBERS CANNOT CARRY THIS FLIP, and are kept above
    // only so this note is readable. Its A/A floor - the same arm against
    // itself, paired per rung - was later measured at 13.6-36.9%, so every
    // shallow figure there is inside its own noise. The deep half clears it
    // by 2x and always did.
    //
    // RE-VALIDATED 12 Sep 2026 ON QUOTABLE PARTS, which is what this rests on
    // now. Two bare-metal Ryzen 7 9800X3D boxes, 93 legs each, five reps, run
    // simultaneously; `research/JOINT-DEFAULT-ON-X86-GFNI-2026-09-11.md`:
    //
    //     m        2,048    3,072    4,096    6,144   12,288
    //     maxpc    +4.84%   +3.31%   +7.85%  +10.21%  +31.98%   5/5 each
    //     xander   +4.66%   +2.15%   +7.30%   +9.74%  +30.33%   5/5 each
    //
    // The two boxes agree to within 0.18-1.65 points at every rung. maxpc is
    // the quotable column (its control phase held, A/B 0.89% against A/A
    // 1.38%); xanderpc's control is marginal and corroborates rather than
    // proves. Every rung from 2,048 up clears its own paired A/A floor.
    //
    // SO THE DEFAULT IS SUPPORTED FROM m = 2,048 UP, AND NOT BELOW IT.
    // m = 1,536 - the first rung above this target's Forney gate of 1,280 -
    // does NOT clear its floor on either box (+2.33% against 4.47%, +0.95%
    // against 4.67%). Between 1,280 and 2,048 the flip is unproven in either
    // direction. The asymmetry is benign there and is why this is recorded
    // rather than acted on: the two arms converge as m falls toward the gate,
    // so the cost of being wrong shrinks to nothing instead of growing.
    //
    // THE SHALLOW BAND IS THE ONE THAT MATTERED and it is the half that
    // had never been observed on x86 by anybody. aarch64's own ladders
    // lose 6.4% and 4.2% at m = 1,024 and 2,048 on the pre-gate binary;
    // x86 does not, for two structural reasons rather than luck.
    // `BACKSUB_MIN_MISSING` is 1,280 here against NEON's 704, so m =
    // 1,024 never reaches the solver at all - the deepest aarch64 loss
    // is at a depth this arm cannot be consulted at - and below
    // `JOINT_FACTOR_MIN_M` stage 2 declines, leaving stage 1 alone,
    // which was then believed to win at every depth. (It does not on
    // the Gfni256 class once priced alone - `JOINT_KERNEL_MIN_M_X86`,
    // 12 Sep 2026 - but the whole-arm win here stands: the scheduler
    // and the factored stage 2 carried the kernel, and the gate now
    // adds the kernel's loss back to the class's gain.)
    //
    // Two further things, both a different KIND of evidence than a wall
    // clock and both stronger for a DEFAULT than any ratio: the e2e
    // suite (451/451) and the daemon suite (196/196) are green with
    // `NZBFAST_FORNEY_JOINT=1` forced, which simulates this predicate
    // exactly. That matters because `joint_gate` is in the engine, so
    // this flip moves the DAEMON's repair path and not only parfast's.
    #[cfg(target_arch = "x86_64")]
    {
        if gf16::avx512_gfni_available() {
            return true;
        }
        // THE 256-BIT GFNI CLASS, added 12 Sep 2026 on its own round:
        // `KernelClass::Gfni256`, GFNI with AVX2 and no AVX-512, which is
        // every Intel from Ice Lake and 11th gen up. Measured on a Core
        // Ultra 9 386H (16 cores, Windows 11), native kernel, `off`
        // (NZBFAST_FORNEY_JOINT=0) against `--fast` with a second `off`
        // as the A/A, 14 rungs from 256 to 16,384, three reps each,
        // SHA-256 of every member gating every leg, 129/129 restored;
        // `research/rounds/jcross-intel-fastmode-2026-09-11/jcross-coreultra9.log`:
        //
        //     m       1,536   2,048   4,096   8,192  12,288  16,384
        //     fast    +6.4%   +5.4%   +9.9%  +10.4%  +19.3%  +18.1%   3/3 each
        //     A/A      2.9%    2.3%    1.7%    1.2%    3.5%    2.6%
        //
        // Every rung from 1,536 up - the first above this class's 1,280
        // Forney gate - beats its own paired A/A floor, and the three
        // below the gate are flat, as they must be when no joint code
        // runs. Nothing like the Nibble class's losing band from 2,048
        // to 6,144 (`research/JOINT-DEFAULT-NIBBLE-X86-2026-09-11.md`)
        // appears anywhere on this ladder, which is why the two classes
        // get different answers from the same function.
        // THE NIBBLE CLASS, added 12 Sep 2026 on its own round, and it is
        // the class that lost: nine of fourteen rungs on the 11 Sep
        // whole-arm round, -12.9% at 5,120. Two things changed between
        // that round and this default, both in this module: stage 2 keeps
        // the shipped stripe width (`JointStripe::kernel_w`), and stage 1
        // runs the shipped Hankel inside the joint scheduler below
        // `JOINT_KERNEL_MIN_M_X86`, which is where this class's additive
        // kernel was costing 5-20% of the repair. Measured on the
        // i5-10600KF (6c/12t, AVX2, no GFNI), the GATED binary, `off`
        // (NZBFAST_FORNEY_JOINT=0) against `--fast`, three rotated reps,
        // SHA-256 gating every leg, an A/A at every rung
        // (`research/FAST-MODE-CROSS-CLASS-ROUNDS-2026-09-12.md`, 5.5):
        //
        //     1,536 +2.3%   2,048 +7.2%   3,072 +4.4%   4,096 +7.7%
        //     5,120 +9.6%   6,144 +11.4%  7,168 +11.0%  8,192 +14.7%
        //    10,240 +16.6% 12,288 +19.7% 16,384 +20.2%     all 3/3
        //
        // Every rung clears its own paired floor (0.6-8.5%), and the
        // 1,536 rung is the first above this class's 1,280 Forney gate.
        // The same gated binary on the Gfni256 part read +4.5% to +25.0%,
        // 3/3 throughout, so the gate improved the class that was
        // already on as well as admitting the one that was off.
        //
        // SSSE3-without-AVX2 parts are admitted with this class, as the
        // Forney gate already admits them, and that is a coarser promise
        // than it reads (see "What class means here" above): no such
        // part exists on this fleet, its butterfly is the two-pass one
        // rather than the fused AVX2 kernel, and below the kernel gate -
        // which is every depth a consumer repair reaches - the butterfly
        // is not on the path at all. Above it, the kernel is admitted on
        // the AVX2 measurement alone.
        return matches!(
            crate::par2seams::KernelClass::current(),
            crate::par2seams::KernelClass::Gfni256 | crate::par2seams::KernelClass::Nibble
        );
    }
    #[allow(unreachable_code)]
    false
}

/// The census's doors onto the two halves of [`joint_gate`]: the
/// EFFECTIVE answer, and the DEFAULT alone.
///
/// Two of them rather than one because `par2seams` asks two different
/// questions. The report wants what this process will actually do, which
/// is `joint_gate` including the switches; the provenance gate wants
/// whether the class is default-on with nothing set, which is the only
/// half a `covers` list can be checked against.
///
/// The second is `#[cfg(test)]` because only the gate reads it, and an
/// ungated one is dead code under `-D warnings`. The first is not: the
/// SEAMS table's `arm` closure calls it on every census report.
pub(crate) fn seam_joint_arm() -> bool {
    joint_gate()
}

#[cfg(test)]
pub(crate) fn seam_joint_default_on() -> bool {
    joint_default_on()
}

/// The missing-block count at or above which stage 2 takes the FACTORED
/// evaluation rather than the shipped one, **8,192, measured 11 Sep
/// 2026 on an Apple M3 Ultra.**
///
/// # What this gate is, and why stage 2 needs one when stage 1 does not
///
/// The joint arm is two independent ideas spliced (see this module's
/// header). Stage 1's additive-FFT product measured faster at every
/// depth ON NEON - +25% at m = 3,276 rising to +73% at m = 29,484 - so
/// it was gated on GEOMETRY alone; on the two x86 classes priced on
/// 12 Sep 2026 it loses to the Hankel until 16,384 and carries its own
/// depth gate there ([`JOINT_KERNEL_MIN_M_X86`]). Stage 2's factored evaluation is the only loser,
/// and it loses for a STRUCTURAL reason that a wider measurement will
/// not talk away: it folds `GT2 * 17` = 4,369 accumulators per stripe
/// WHATEVER `m` is, because the whole point of the factorization is to
/// fold each T row into one of 17 residue buckets and serve every group
/// from those 17. The saving needs `m / 257` - the number of T rows in
/// a residue class - to be large enough to pay for that fixed fold, and
/// below the crossover it is not: sixteen of every seventeen bucket
/// folds have no sources at all and the pass is largely `u.fill(0)`.
///
/// Until 11 Sep 2026 one boolean sent BOTH stages, so the shallow end
/// paid stage 2's loss to get stage 1's win and the whole arm was a
/// wash below ~8,000. Splitting the gate is what makes the switch worth
/// having at every depth the transform solve runs at.
///
/// # What was measured
///
/// `research/JOINT-STAGE2-DEPTH-GATE-2026-09-11.md`, the localising
/// round. Both arms run `parfast r` end to end with SHA-256 gates and
/// **stage 1 held on the additive kernel on both sides**
/// (`NZBFAST_FORNEY_JOINT=1` in both, `NZBFAST_FORNEY_FACTOR` forced
/// `off` / `on`), so the only thing that moves is the arm this constant
/// gates. 32 members of 512 slices at 262,144 B, 8,192 recovery blocks;
/// seven depths, five reps, arm order alternating; A/A floor first.
///
/// ```text
///   m       stage 2 %   pos    repair CPU %   pos
///   4,096     -18.75    0/5        -4.68      0/5
///   5,120     -14.30    0/5        -2.11      1/5
///   6,144      -5.26    0/5        -1.75      0/5
///   6,656      +0.98    3/5        +0.63      5/5
///   7,168      +0.00    2/5        +0.31      4/5
///   7,680      -0.86    2/5        +1.08      4/5
///   8,192      +4.03    4/5        +2.33      5/5
/// ```
///
/// Median of five paired reps, positive = the factored arm faster.
/// A/A floor 1.60% on the stage-2 mark (worst median); the control
/// phase - `verify_targets_volume_scan`, which no arm of this change
/// can reach - moved 1.39%, under both the floor and the A/A's own
/// 3.10% drift on it, which is what makes this round readable.
///
/// **The crossover is between 6,144 and 6,656**, and the whole-repair
/// CPU column is what resolves it: 0/5 and 1/5 and 0/5 positive at the
/// three depths below, then 5/5, 4/5, 4/5, 5/5 at the four above, with
/// the worst single pair at 6,656 still positive. CPU falling with the
/// mark means work removed rather than occupancy moved.
///
/// The repair WALL, which is what a user pays, turns positive later
/// still: -2.48% / -6.27% / -3.21% below the crossover, -1.67% /
/// -0.52% / -3.40% across the wash band from 6,656 to 7,680 against a
/// 1.89% A/A floor, and +1.46% (4/5) at 8,192. The wash band's CPU
/// saving is too small to reach the wall.
///
/// The whole-arm rounds of 10 Sep
/// (`research/JOINT-FORNEY-INTEGRATION-2026-09-10.md`, sections 6.5,
/// 6.7 and 6a.1) agree from the other side: they moved both stages
/// together and could only say the crossover sat between 4,096 and
/// 8,192, but their stage-2 column reads -222% at m = 256, -19% at
/// 3,276, -9% at 4,096, +7% at 8,192 and +19-20% from 16,384 up - on a
/// 750 KiB rig, a different block size on the same box. Two rigs, first
/// clear positive at 8,192 on both.
///
/// # Which way to be wrong: bias HIGH
///
/// This is the OPPOSITE of [`super::backsub_min_missing`], and the
/// asymmetry is the reason. Set too high, the cost is the factored gain
/// forgone, which is small near the crossover and PLATEAUS above it:
/// stage 2 is +19% at 16,384 and +20% at 20,480 and 29,484, so a gate
/// one rung high costs a bounded slice of one stage. Set too low, the
/// cost KEEPS GROWING as `m` falls, because the 4,369-accumulator fold
/// is fixed while the work it is amortised over shrinks: -5% at 6,144,
/// -14% at 5,120, -19% at 4,096, and -222% at 256.
///
/// 8,192 rather than the measured ~6,400 crossover is that rule spent
/// deliberately, at a stated price: over 6,656 to 8,191 the factored
/// arm would have been +0.3% to +1.1% of whole-repair CPU, so the
/// margin costs about one percent of a repair over a 1,536-block band,
/// and none of the WALL - the wall is the column that first turns
/// positive at 8,192 and not before. The margin is 1.23x past the
/// crossover, the same order as the 1.25x on
/// [`super::BACKSUB_MIN_MISSING_NIBBLE`].
///
/// So on an unmeasured part, take this number or a higher one, never a
/// lower one. A part where the factored path is dearer than it is here
/// pays only the plateau; a part where it is cheaper loses nothing this
/// gate can see.
///
/// # Which class this is, and what is NOT measured
///
/// ONE constant, not a per-class family, and aarch64 is the only class
/// measured. That is deliberate rather than lazy: both arms are
/// `fold_rows` calls and the quantity that moves is the NUMBER of folds
/// and their fan-in, which is arithmetic over `m` and the group count
/// and identical on every part. What varies by class is the kernel's
/// per-source against per-call cost, which can shift the crossover but
/// not its shape. A class that measures differently gets its own
/// constant then, the way the Forney gate grew three; until one does,
/// a second name would claim a provenance nobody has.
///
/// **REPLICATED on a second aarch64 generation, 11 Sep 2026**
/// (`research/JOINT-CROSSOVER-PER-CLASS-2026-09-11.md`). An M1 Ultra,
/// a different fixture and a different block size from the M3 Ultra
/// round above, both arms again forced through
/// `NZBFAST_FORNEY_FACTOR`, with a true A/A arm - a SECOND copy of
/// `s2off`, not the shipped solve, because pairing against the shipped
/// solve measures stage 1 and would be an A/B wearing the name of a
/// floor:
///
/// ```text
///   m        stage 2 wall %   pos
///   2,048        -8.90        0/3
///   4,096        -4.65        0/3
///   5,120        -3.65        0/2
///   6,144        -1.27        0/2
///   6,656        +0.41        1/2   <- first positive
///   7,168        +3.22        2/2
///   7,680        +4.38        2/2
///   16,384       +5.63        2/2
/// ```
///
/// **The crossover lands between 6,144 and 6,656 - the SAME 512-block
/// interval the M3 Ultra put it in**, reached from a different box, a
/// different fixture shape and a different block size. That is the
/// evidence for treating NEON as one class rather than splitting it by
/// generation, and it is what makes the 1.23x margin below a margin
/// over a measured crossing rather than over a single reading. The loss
/// also deepens as `m` falls exactly as the structural argument says it
/// must: -1.27%, -3.65%, -4.65%, -8.90% down the ladder.
///
/// **A CONSEQUENCE OF THE ARM'S DEFAULT MOVING, 11 Sep 2026.** When
/// [`joint_default_on`] turned the arm on for `Avx512Gfni`, it also made
/// THIS constant live on that class without measuring it: a default-on
/// part past 8,192 now takes the factored stage 2 under a threshold
/// measured on Apple silicon. The exposure is real but bounded, and the
/// two halves are worth separating.
///
/// What that round DID validate: it read +29.7% / +24.9% / +29.1% at
/// m = 8,192 / 16,384 / 24,576, depths where stage 2 is engaged, so the
/// factored arm is not a loss on that class at those depths. What it did
/// NOT validate is where the crossing falls there - only that 8,192 is
/// past it. Since this constant is biased HIGH on purpose, being wrong
/// costs the forgone plateau rather than a growing loss, which is the
/// cheap direction; see "Which way to be wrong" below. A stage-2 A/B on
/// that class would settle it and has not been run.
///
/// x86 was not measured here for a reason that WAS worth writing down
/// and has since expired. It read: on a GFNI part stage 1 declines until
/// `NZBFAST_GF16_ROWOP_GFNI` is armed (claim
/// `gfni-rowop-arm-evidence-11sep`), so an x86 round would have to hold
/// stage 1 on the SHIPPED arithmetic instead - a different composition
/// from the one measured above, and one whose T rows arrive with
/// different cache residency.
///
/// **That stopped being true at 08:01Z on 11 Sep 2026** (`9d91798cec`).
/// `joint_stripe` consults [`gf16::scale_available`], and `scale_kernel`
/// returns `Gfni256` on `gfni256_available()` - explicitly NOT on
/// `gfni_rowop_armed()`, an asymmetry with `butterfly` that its own
/// comment calls out. So stage 1 engages natively on an unarmed GFNI
/// part, and an x86 stage-2 round no longer has to hold it on the
/// shipped arithmetic. The obstacle this paragraph described is gone;
/// the round is simply unrun.
///
/// Found because a lane auditing `NZBFAST_GF16_ROWOP_GFNI` for a
/// DIFFERENT round discovered that variable gates two things, not one -
/// the fused butterfly and, through
/// [`gf16::inplace_scale_preferred`], `par2ntt`'s additive leaf. Anyone
/// designing an arm around it should read that function before pairing
/// against it: a single variable moving two subsystems is how a round
/// produces a number for a question it could not ask.
///
/// # Escape hatch
///
/// `NZBFAST_FORNEY_FACTOR=on|off` forces the choice in either
/// direction, the way `NZBFAST_BACKSUB` does for the solver above it.
/// It is what the localising round A/Bs through, and it is debug-only:
/// a shipped repair reads this constant.
pub(crate) const JOINT_FACTOR_MIN_M: usize = 8192;

/// Whether stage 2 takes the factored evaluation at this depth.
///
/// ONE copy of the rule, read only from [`ForneyPlan::joint_stripe`],
/// for the same reason that function is the only copy of stage 1's:
/// a second copy of a predicate like this is how a proof ends up
/// certifying the arm it was meant to exclude.
fn factor_gate(m: usize) -> bool {
    match std::env::var("NZBFAST_FORNEY_FACTOR").as_deref() {
        Ok("1" | "on" | "factor") => true,
        Ok("0" | "off" | "owned") => false,
        _ => m >= JOINT_FACTOR_MIN_M,
    }
}

/// The missing-block count at or above which stage 1 takes the ADDITIVE
/// kernel rather than the shipped Hankel product inside the joint
/// scheduler, on the two x86 classes it was measured on: **16,384,
/// measured 12 Sep 2026 on an i5-10600KF (Nibble) and a Core Ultra 9
/// 386H (Gfni256).** No gate on NEON or on AVX-512 GFNI, which have not
/// been measured for it; see [`kernel_gate`].
///
/// # Why stage 1 has a gate after all
///
/// This module's header said stage 1's additive product was "faster at
/// every depth anyone has measured", and it was - measured as a
/// COMPONENT, on NEON, against the shipped driver. The 12 Sep 2026
/// rounds (`research/FAST-MODE-CROSS-CLASS-ROUNDS-2026-09-12.md`,
/// sections 5.2 and 5.3) priced it ALONE for the first time, by holding
/// stage 1 on the shipped arithmetic inside the joint scheduler
/// (`NZBFAST_FORNEY_STAGE1=owned`) with stage 2 on its own gate, on the
/// standard ladder with an A/A at every rung. Whole-repair wall, the
/// held arm against the kernel arm, positive = the HELD arm faster:
///
/// ```text
///   m        i5 (Nibble)    Core Ultra 9 (Gfni256)
///   2048       +5.6%  3/3       +0.5%  wash
///   4096      +11.5%  3/3       +1.5%  wash
///   5120      +19.0%  3/3       +6.2%  3/3
///   6144      +17.0%  3/3       +4.2%  3/3
///   7168      +11.3%  3/3       +1.4%  3/3
///   8192      +13.5%  3/3       +7.8%  3/3
///  10240      +22.2%  3/3      +13.6%  3/3
///  12288      +13.4%  3/3       +7.3%  3/3
///  16384       -3.9%  0/3       -1.6%  0/3   <- the kernel's first win
/// ```
///
/// The stage decomposition on the i5 says why: the Hankel product runs
/// 16-27% FASTER inside the joint scheduler than in the shipped driver
/// (each stripe's T built and consumed by one worker instead of a full
/// `m x block` T re-read strided from DRAM), and the additive kernel
/// runs up to 81% slower than that Hankel until the transform's
/// `n log n` finally undercuts the Hankel's `m^2` at 16,384. What the
/// whole-arm rounds had been crediting to the kernel was the scheduler
/// and the factored stage 2 carrying it.
///
/// # Which way to be wrong: bias HIGH
///
/// 16,384 is the kernel's first measured win on either class (+3.9% of
/// the repair on the i5, +1.6% inside its floor on the Core Ultra 9) and
/// 12,288 the Hankel's last (+13.4% and +7.3%). The crossing is between
/// them and unresolved; the constant sits on the kernel's own win, so a
/// part where the crossing is lower forgoes a few percent of one stage
/// over one rung, and a part where it is higher pays nothing this gate
/// can see. On an unmeasured x86 part take this number or a higher one.
///
/// # Which classes, and which not
///
/// Nibble and Gfni256 carry it because they were measured. NEON is NOT
/// gated, and that is measured too: the same pairing on an M1 Ultra the
/// same day (`jx3`, section 5.4 of the note) read the held Hankel as a
/// wash below 7,168 and behind the kernel from there, -2.7% at 7,168 to
/// -14.6% at 16,384, 0/3 at every deep rung - the shape the 11 Sep
/// component measurement described, so every Mac keeps the kernel at
/// every depth. AVX-512
/// GFNI is not gated because it was not measured - its butterfly is the
/// same 256-bit GFNI kernel Gfni256 runs, so the same crossing is
/// likely, but "likely" is exactly what `covers` on the census seam
/// refuses to record. A class moves in when it has its own round.
pub(crate) const JOINT_KERNEL_MIN_M_X86: usize = 16384;

/// Whether stage 1 takes the additive kernel at this depth - the depth
/// half of the admission; geometry is [`ForneyPlan::joint_stripe`]'s.
///
/// `NZBFAST_FORNEY_STAGE1` forces it in either direction, the way
/// `NZBFAST_FORNEY_FACTOR` does for stage 2, and it is what the s1
/// trio of arms in the harnesses set: `owned`/`off` holds the Hankel at
/// every depth (reported through [`JointDecline::Held`]), `kernel`/`on`
/// takes the kernel wherever GEOMETRY admits it - the knob cannot force
/// a kernel past a refused stripe, only past this gate. Debug-only; a
/// shipped repair reads the constant.
///
/// ONE copy of the rule, read from `joint_stripe` and the census door
/// below, for the reason [`factor_gate`] gives.
fn kernel_gate(m: usize) -> bool {
    match stage1_env() {
        Some(forced) => forced,
        None => {
            use crate::par2seams::KernelClass;
            match KernelClass::current() {
                KernelClass::Nibble | KernelClass::Gfni256 => m >= JOINT_KERNEL_MIN_M_X86,
                KernelClass::Avx512Gfni | KernelClass::Neon | KernelClass::Scalar => true,
            }
        }
    }
}

/// `NZBFAST_FORNEY_STAGE1`, parsed: `Some(false)` holds the Hankel,
/// `Some(true)` takes the kernel past the depth gate, `None` is unset.
fn stage1_env() -> Option<bool> {
    match std::env::var("NZBFAST_FORNEY_STAGE1").as_deref() {
        Ok("0" | "off" | "owned" | "shipped") => Some(false),
        Ok("1" | "on" | "kernel") => Some(true),
        _ => None,
    }
}

/// The selection census's door onto [`kernel_gate`], three lines and no
/// logic, for the reason [`seam_joint_factor`] gives.
pub(crate) fn seam_joint_kernel(m: usize) -> bool {
    kernel_gate(m)
}

/// The selection census's door onto [`factor_gate`], so `par2seams`
/// reports the arm this build actually takes instead of re-deriving it.
/// Three lines and no logic, deliberately, for the same reason
/// [`ForneyPlan::joint_stripe`] is the only reader of both gates: a
/// census that reasons independently is a second copy of the rule, and
/// a second copy is how a proof ends up certifying the arm it was meant
/// to exclude.
pub(crate) fn seam_joint_factor(m: usize) -> bool {
    factor_gate(m)
}

/// Stage 2's coefficients, factored. Built only past
/// [`JOINT_FACTOR_MIN_M`] - below it the shipped
/// [`ForneyPlan::owned_evaluate`] runs and these tables would be dead
/// weight, which is why `JointPlan::factor` is an `Option`.
///
/// [`ForneyPlan::evaluate`] folds `stage_a[g * m + idx]` - one
/// coefficient per (group, T row) pair - so a row of T is re-folded
/// once per group. But `α^{k1 (t mod 255)}` splits along the same
/// 255 = 3 * 5 * 17 Good-Thomas coordinates stage 1 uses: the radix-17
/// half depends on `t mod 17` alone and the rest on the group. So one
/// pass folds each T row into one of 17 accumulators by its residue
/// (`first`), and every group is then 17 sources instead of `m / 257`
/// of them (`second`).
///
/// Groups are TILED by `k mod 15` so that one `first` table serves a
/// whole tile: `first` depends only on `(k mod 3, k mod 5)`.
struct FactorTile {
    groups: Vec<usize>,
    first: Vec<u16>,
    second: Vec<u16>,
}

pub(super) struct FactorPlan {
    tiles: Vec<FactorTile>,
}

/// What one solve's stripes run: the width both stages share, and the
/// arm EACH STAGE takes.
///
/// Two booleans rather than one because the two stages are gated on
/// different things - see [`ForneyPlan::joint_stripe`]. `true` means
/// that stage takes the SHIPPED arithmetic; the field names carry the
/// stage so a swapped pair cannot read as correct.
struct JointStripe {
    /// The stripe width, in u16 words: the width the local T is built
    /// at and stage 2 runs at. The SHIPPED width (`stripe_w`), never
    /// narrower - see `kernel_w`.
    w: usize,
    /// The width stage 1's additive kernel runs at, `<= w` and a
    /// divisor-or-remainder of it: when the kernel's `n x w` arena would
    /// exceed the byte allowance the shipped stage-1 arena had
    /// ([`whole::admitted_width`]), stage 1 runs the stripe in
    /// SUB-STRIPES of this width rather than narrowing the whole stripe.
    ///
    /// Until 12 Sep 2026 the one width served both stages, and it was
    /// the NARROWER of the two - so at every depth where the kernel
    /// arena did not fit (`n > (nseg + 3) * 255`: m just past a power of
    /// two, which is 8 of the 14 rungs on the standard ladder) stage 2
    /// ran the shipped arithmetic at 256 words instead of 512. On the
    /// x86 nibble class that arithmetic pays a per-call cost the other
    /// classes do not (eight `pshufb` tables rebuilt per source per call
    /// - the collapse `STRIPE_W_TARGET` documents), and halving the
    /// stripe was worth +20% to +38% of stage 2 on an i5-10600KF, which
    /// is most of why `--fast` lost at nine of fourteen depths there
    /// (`research/AVX2-NIBBLE-STRIPE-NARROWING-2026-09-12.md`). Stage 1
    /// is the only consumer of the arena, so it is the only stage that
    /// needs the narrower width.
    kernel_w: usize,
    /// Why stage 1 takes [`ForneyPlan::owned_hankel`], or `None` when it
    /// runs the kernel. The REASON rather than a bare bool, because a
    /// CLI that arms this has to be able to say which condition it
    /// tripped - the whole of TODO 340 item 1.
    stage1: Option<JointDecline>,
    /// Stage 1 is admitted by DEPTH ([`kernel_gate`]): `false` runs the
    /// shipped Hankel inside the joint scheduler below
    /// [`JOINT_KERNEL_MIN_M_X86`] on a gated class. Separate from
    /// `stage1` because it is a design choice and not a decline: the
    /// arm RAN, at the arithmetic this depth is faster with, and the CLI
    /// must not tell a user it did not.
    stage1_gate: bool,
    /// Stage 2 takes [`ForneyPlan::owned_evaluate`].
    stage2: bool,
}

/// One repair's joint plan: the stage-1 kernel selected for this `m`,
/// and stage 2's factored coefficients.
pub(super) struct JointPlan {
    /// The whole-`B` kernel. Always built: it is the fallback for every
    /// shape and the width cap for the other two.
    whole: whole::Kernel,
    /// Selected at `m = 2^k + 1`.
    peeled: Option<peel::Plan>,
    /// Selected at `m = 2^k + q`, `2 <= q <= 8`.
    tail: Option<tail::Plan>,
    /// Stage 2's factored coefficients, built only when this repair is
    /// deep enough to USE them ([`JOINT_FACTOR_MIN_M`]). `None` is the
    /// shipped evaluation, and it is the single place the depth gate is
    /// resolved: read back by [`ForneyPlan::joint_stripe`] and by
    /// nothing else, so the arm the solve runs and the tables it holds
    /// can never disagree.
    factor: Option<FactorPlan>,
    /// See [`ForneyPlan::with_kernel_forced`].
    #[cfg(test)]
    force_kernel: bool,
}

impl JointPlan {
    /// Build for a prepared [`ForneyPlan`]. `p.locator` must be
    /// populated, which [`ForneyPlan::prepare`] only does when
    /// [`joint_gate`] is set.
    pub(super) fn new(p: &ForneyPlan, ks: &[u32]) -> JointPlan {
        let m = ks.len();
        // How far past the previous power of two `m` sits. The kernel
        // size doubles at `q = 1`, so the two peeling arms exist to
        // stay on the smaller transform for the shapes just past it.
        let q = if m.is_power_of_two() {
            0
        } else {
            m - m.next_power_of_two() / 2
        };
        let b = &p.locator[1..];
        JointPlan {
            whole: whole::Kernel::new(b),
            peeled: if q == 1 { peel::Plan::new(b) } else { None },
            tail: if (2..=tail::MAX_Q).contains(&q) {
                tail::Plan::new(b)
            } else {
                None
            },
            factor: factor_gate(m).then(|| p.factor_plan(ks)),
            #[cfg(test)]
            force_kernel: false,
        }
    }

    /// Everything this plan holds, for the memory floor. The kernel
    /// dominates: `bhat` and the twiddles are one prepared coefficient
    /// per transform point, which is 130 bytes each on the x86 nibble
    /// arms and 2 everywhere else.
    pub(super) fn heap_bytes(&self) -> usize {
        self.whole.heap_bytes()
            + self.peeled.as_ref().map_or(0, peel::Plan::heap_bytes)
            + self.tail.as_ref().map_or(0, tail::Plan::heap_bytes)
            + self.factor.as_ref().map_or(0, |f| {
                f.tiles.capacity() * std::mem::size_of::<FactorTile>()
                    + f.tiles
                        .iter()
                        .map(|t| {
                            t.groups.capacity() * std::mem::size_of::<usize>()
                                + (t.first.capacity() + t.second.capacity()) * 2
                        })
                        .sum::<usize>()
            })
    }

    /// The width this plan's selected kernel may run at inside a stripe
    /// of the shipped width ([`JointStripe::kernel_w`]). The peeling
    /// arms are capped by the whole kernel's width as well as their
    /// own, so a plan can never be granted a wider arena by selecting a
    /// smaller transform.
    fn kernel_width(&self, p: &ForneyPlan, words: usize) -> usize {
        let whole = p.whole_width(&self.whole, words);
        if let Some(t) = &self.tail {
            p.whole_width(&t.kernel, words).min(whole)
        } else if let Some(k) = &self.peeled {
            p.whole_width(&k.kernel, words).min(whole)
        } else {
            whole
        }
    }
}

impl ForneyPlan {
    /// The stripe width `k` admits inside stage 1's own byte allowance.
    /// `nseg * CONV + 3 * CONV` is what a stage-1 worker holds in rows:
    /// the spectral arena, the resident output spectrum and the two
    /// mixed-radix coordinate arenas.
    fn whole_width(&self, k: &whole::Kernel, words: usize) -> usize {
        whole::admitted_width(k.n, self.nseg * CONV + 3 * CONV, self.stripe_w(words))
    }

    /// Stage 2's coefficients, factored along the Good-Thomas radix-17
    /// coordinate. Asserted against `stage_a` entry for entry by
    /// `factored_coefficients_match_stage_a` below, so the factorization
    /// is proved rather than argued.
    fn factor_plan(&self, ks: &[u32]) -> FactorPlan {
        let wp: Vec<_> = (0..CONV).map(|i| gf16::pow2(257 * i as u64)).collect();
        let ap: Vec<_> = (0..CONV)
            .map(|i| gf16::pow2(257 * 128 * i as u64))
            .collect();
        // 15 = 3 * 5: `first` depends on `k mod 3` and `k mod 5` only,
        // so every group in a bucket shares one `first` table.
        let mut buckets: Vec<Vec<usize>> = vec![vec![]; 15];
        for (gi, g) in self.groups.iter().enumerate() {
            buckets[ks[g[0] as usize] as usize % 15].push(gi);
        }
        let mut tiles = Vec::new();
        for groups in buckets.into_iter().filter(|v| !v.is_empty()) {
            let k = ks[self.groups[groups[0]][0] as usize] as usize % CONV;
            let f = (85 * (k % 3) + 51 * (k % 5)) % CONV;
            let first = (0..self.m.div_ceil(GT2))
                .map(|j| wp[f * j % CONV])
                .collect();
            let mut second = Vec::new();
            for &gi in &groups {
                let k = ks[self.groups[gi][0] as usize] as usize % CONV;
                for t2 in 0..GT2 {
                    for c in 0..17 {
                        second.push(gf16::mul(ap[k * t2 % CONV], wp[120 * (k % 17) * c % CONV]));
                    }
                }
            }
            tiles.push(FactorTile {
                groups,
                first,
                second,
            });
        }
        FactorPlan { tiles }
    }

    /// The stripe width the joint solve runs at, the width stage 1's
    /// kernel runs at inside it, and which arm EACH STAGE takes.
    ///
    /// ONE copy of the rule, because the test that proves the kernel
    /// really ran has to ask the same question the solve does. A second
    /// copy of a predicate like this is how a proof ends up certifying
    /// the fallback.
    ///
    /// The two stages are gated SEPARATELY and on different things, and
    /// that is the whole of the 11 Sep 2026 split. Stage 1's additive
    /// product is gated on GEOMETRY - the four conditions below - and,
    /// since 12 Sep 2026, on DEPTH on the classes where it was priced
    /// alone and lost ([`kernel_gate`], the `stage1_gate` field): below
    /// that gate the shipped Hankel runs inside the joint scheduler,
    /// which is the arm those depths measured faster with. Stage 2's factored evaluation is gated
    /// on DEPTH alone ([`JOINT_FACTOR_MIN_M`]): it needs none of stage
    /// 1's geometry (no fused scale kernel, no 16-word stripe, no mixed
    /// stage-1 plan - it folds through `fold_rows`, which carries a
    /// sub-granule tail), and it is a LOSS below the crossover for a
    /// structural reason that constant documents. All four combinations
    /// are reachable and all four are exact; they are pinned by
    /// `each_stage_picks_its_arm_independently`.
    ///
    /// `words.is_multiple_of(16)` means A BLOCK SIZE THAT IS A MULTIPLE
    /// OF 32 BYTES, and that is a real constraint on real sets, not a
    /// harness artefact: PAR2 only requires a multiple of four, and a
    /// creator asked for a block COUNT rather than a block size will
    /// happily land on 166,228 bytes. Such a set repairs on the shipped
    /// arithmetic inside the bounded scheduler and buys the arithmetic
    /// half of this change nothing. The alternative would be a scalar
    /// remainder path through `gf16::scale` and `gf16::butterfly`, both
    /// of which work in whole 32-byte units by construction.
    fn joint_stripe(&self, joint: &JointPlan, words: usize) -> JointStripe {
        // The stripe is the SHIPPED width, whatever the kernel's arena
        // admits: T and stage 2 run at `w`, and stage 1 runs in
        // sub-stripes of `kernel_w` inside it (`run_joint`). Until
        // 12 Sep 2026 the stripe was the narrower of the two, which
        // dragged the shipped stage-2 arithmetic down to half width at
        // every depth the arena did not fit - see `JointStripe::kernel_w`
        // for what that cost on the nibble class.
        let w = self.stripe_w(words).max(1);
        let admitted = joint.kernel_width(self, words);
        // A ZERO admitted width means the additive arena will not fit
        // the allowance the shipped arm had even at the narrowest
        // sub-stripe - so stage 1 falls back, at the shipped WIDTH, not
        // at a degenerate one-word stripe. Narrowing the solve to `w = 1`
        // because a kernel that is not going to run would not fit is
        // exactly the per-call-cost collapse `STRIPE_W_TARGET` exists
        // to prevent.
        let kernel_w = if admitted == 0 { w } else { admitted.min(w) };
        // The geometry checks the standalone joint kernels make, one
        // level lower.
        //
        // `words` IS NOT ONE OF THEM, and that is the whole of the
        // 10 Sep short-stripe fix. Stage 1's kernels work in whole
        // 32-byte units, so they need a 16-word STRIPE - but `w` is a
        // power of two between `STRIPE_GRAN` and `STRIPE_W_TARGET`, so
        // every stripe IS 16-word aligned except the last, whose length
        // is `words mod w`. Refusing the whole solve because of that one
        // short stripe threw the arm away on seven of eight sets
        // `parfast c` creates by block COUNT (its search steps by four
        // and nothing prefers 32), and at a 13.5 MB block that is one
        // stripe in 13,253. The short one is PADDED instead - see the
        // `pad` arm in `run_joint`.
        //
        // The reason is recorded as well as the verdict. `stage1` used
        // to be a bare disjunction, and the three-line trace it fed was
        // the ONLY place a declining host said so - see
        // [`JointDecline`]. The order below is the order a user can act
        // on: the set's geometry first, because they can change it, then
        // the host's kernel, then the two shapes nobody chooses.
        //
        // `kernel_w` rather than `w` on the alignment check: it is the
        // width the kernel is handed, and `w` is a power of two at or
        // above it except under a hand-set `NZBFAST_BACKSUB_W`, where
        // halving can land off the unit (48 -> 24) while `w` itself was
        // on it. A sub-stripe's length is `kernel_w` or `work mod
        // kernel_w`, and both are 16-word multiples when `kernel_w` and
        // `work` are.
        let decline = if admitted == 0 {
            Some(JointDecline::KernelArena)
        } else if !kernel_w.is_multiple_of(16) {
            Some(JointDecline::BlockAlignment)
        } else if !gf16::scale_available() {
            Some(JointDecline::NoScaleKernel)
        } else if !self.stage1.is_mixed() {
            Some(JointDecline::NotMixed)
        } else if stage1_env() == Some(false) {
            // Last, so a geometry refusal keeps its own name: the knob
            // holds a kernel that WOULD have run, it does not relabel
            // one that could not.
            Some(JointDecline::Held)
        } else {
            None
        };
        // The DEPTH half of the admission, asked only of a stripe
        // geometry admits. A test can force it (`with_kernel_forced`)
        // because the byte-identity proofs have to run the kernel on a
        // gated class at depths a unit test can afford; production
        // reads the constant.
        #[allow(unused_mut)]
        let mut stage1_gate = decline.is_some() || kernel_gate(self.m);
        #[cfg(test)]
        if joint.force_kernel && decline.is_none() {
            stage1_gate = true;
        }
        // Below the gate the arm is TAKEN, not declined: it runs, at the
        // arithmetic this depth measured faster with, and `parfast`
        // must not print "did not run" for a repair that the switch
        // just made 5-20% faster.
        match decline {
            Some(d) => note_joint_declined(d),
            None => note_joint_taken(),
        }
        JointStripe {
            w,
            kernel_w,
            stage1: decline,
            stage1_gate,
            stage2: joint.factor.is_none(),
        }
    }

    /// [`ForneyPlan::joint_stripe`]'s two widths as a pure query:
    /// `(stripe, kernel)`. `None` when this plan carries no joint arm.
    ///
    /// Test-only, so the sub-striping can be asserted to have HAPPENED
    /// on the shape a byte-identity test compares, rather than inferred
    /// from the arithmetic of `admitted_width`.
    #[cfg(test)]
    pub(super) fn joint_widths(&self, words: usize) -> Option<(usize, usize)> {
        self.joint.as_ref().map(|j| {
            let s = self.joint_stripe(j, words);
            (s.w, s.kernel_w)
        })
    }

    /// [`ForneyPlan::joint_stripe`]'s stage-1 verdict as a pure query.
    ///
    /// Test-only, and it exists so the reason can be pinned WITHOUT
    /// reading the process-global latch: `cargo test --lib` runs this
    /// whole crate in one process, so a test that reset the latch and
    /// read it back would be racing every other test that runs a joint
    /// solve. The latch's own wiring is proved end to end by parfast's
    /// integration test, in a binary where one test drives one repair.
    #[cfg(test)]
    pub(super) fn joint_decline(&self, words: usize) -> Option<Option<JointDecline>> {
        self.joint
            .as_ref()
            .map(|j| self.joint_stripe(j, words).stage1)
    }

    /// Whether a solve at this block width would run the ADDITIVE
    /// kernel rather than the shipped arithmetic. `None` when this plan
    /// carries no joint arm at all.
    ///
    /// Test-only, and it exists so a byte-identity proof can assert that
    /// the cell it just compared actually RAN the kernel. Production has
    /// no need to ask: the `repair-timing` stage line names the arm, and
    /// says FALLBACK when it took one.
    #[cfg(test)]
    pub(super) fn joint_takes_the_kernel(&self, words: usize) -> Option<bool> {
        self.joint.as_ref().map(|j| {
            let s = self.joint_stripe(j, words);
            s.stage1.is_none() && s.stage1_gate
        })
    }

    /// Take the additive kernel wherever GEOMETRY admits it, whatever
    /// [`kernel_gate`] says about the depth. Test-only, and it exists
    /// because every byte-identity proof in this module runs at depths
    /// a debug build can afford (64 to 2,048), all of which sit below
    /// [`JOINT_KERNEL_MIN_M_X86`] - so on a gated class (every x86 CI
    /// runner) the proofs would silently certify the Hankel fallback
    /// and the kernel would run nowhere in CI. A test that wants the
    /// GATE's behaviour builds its plan without this.
    #[cfg(test)]
    pub(super) fn with_kernel_forced(mut self) -> Self {
        if let Some(j) = &mut self.joint {
            j.force_kernel = true;
        }
        self
    }

    /// Whether a solve at this block width would run the FACTORED
    /// stage-2 evaluation rather than the shipped one. `None` when this
    /// plan carries no joint arm at all.
    ///
    /// Test-only, and the stage-2 twin of `joint_takes_the_kernel`: the
    /// split is only proved if a test can say which of the four arm
    /// combinations the cell it just compared actually ran. Production
    /// has no need to ask - the `repair-timing` stage-2 line names the
    /// arm, and says FALLBACK when it took the shipped one.
    #[cfg(test)]
    pub(super) fn joint_takes_the_factor(&self, words: usize) -> Option<bool> {
        self.joint
            .as_ref()
            .map(|j| !self.joint_stripe(j, words).stage2)
    }

    /// The whole solve, joint arm: `syn` in, the rebuilt blocks out, in
    /// the SAME allocation.
    ///
    /// The caller must have dropped everything it no longer needs before
    /// calling, exactly as it does before [`ForneyPlan::hankel`]: this
    /// buffer is the repair's live window for the whole call.
    pub(super) fn run_joint(&self, joint: &JointPlan, mut syn: Vec<Vec<u16>>) -> Vec<Vec<u16>> {
        assert_eq!(syn.len(), self.m);
        let words = syn.first().map_or(0, Vec::len);
        assert!(syn.iter().all(|r| r.len() == words));
        if words == 0 {
            return syn;
        }
        let t0 = std::time::Instant::now();
        // The minimum of the two components' own widths, so the stripe
        // is bounded by whichever idea alone would have chosen the
        // tighter budget. `kernel_width` is already `stripe_w` narrowed
        // by the kernel's arena, so this `min` is belt and braces for
        // the zero return.
        let JointStripe {
            w,
            kernel_w,
            stage1: s1_decline,
            stage1_gate: s1_gate,
            stage2: s2_owned,
        } = self.joint_stripe(joint, words);
        // The verdict, once, for the three sites below that only need
        // the bool. The REASON stays in `s1_decline` for the latch the
        // CLI reads (TODO 340); the depth gate is not a reason, it is
        // the arm.
        let s1_owned = s1_decline.is_some() || !s1_gate;
        // The two stages are FUSED per stripe here, so neither has a
        // wall of its own. These sum WORKER time across stripe units,
        // and the wall is split between the counters in proportion to
        // them below - an attribution, said out loud, so that the
        // `forney solve:` share stays comparable with the two-stage
        // arm's without pretending the fused arm measured two walls.
        let stage1_worker = std::sync::atomic::AtomicU64::new(0);
        let stage2_worker = std::sync::atomic::AtomicU64::new(0);
        let body = |_off: usize, cells: &mut Vec<&mut [u16]>| {
            let len = cells[0].len();
            // THE SHORT LAST STRIPE. Stage 1 refuses a width that is not
            // a whole number of 32-byte units; stage 2 does not care,
            // because it folds through `fold_rows`, which carries a
            // sub-granule tail. So a short stripe runs stage 1 at the
            // next multiple of 16 with the extra columns ZERO, and stage
            // 2 at the true width.
            //
            // Why that is exact rather than hopeful: every operation in
            // stage 1 is elementwise across the stripe - the butterflies,
            // the scale, the basis conversion's XORs, the peel and tail
            // corrections - so a column of the output depends only on
            // the same column of the input. Zero columns in give zero
            // columns out, and they cannot reach a real column. Pinned
            // by `a_short_last_stripe_is_padded_and_still_exact`.
            let pad = !s1_owned && !len.is_multiple_of(16);
            let work = if pad { len.next_multiple_of(16) } else { len };
            // One stripe's T. `m * work` words per worker, and at most
            // `ceil(words / w)` workers run at once, so the total is at
            // most the `m * words` T the shipped path allocates whole -
            // `work` exceeds `len` on at most ONE stripe of the solve
            // and by at most 15 words.
            let mut t = vec![0u16; self.m * work];
            let _t_charge = crate::memgauge::Charge::new(
                crate::memgauge::Sub::RepairWork,
                (t.len() * 2) as u64,
            );
            let a = std::time::Instant::now();
            {
                // The padded arm needs the SOURCES at the working width
                // too: the peel and tail corrections read syndrome rows
                // directly and assert they match the destination.
                let padded: Vec<u16> = if pad {
                    let mut p = vec![0u16; self.m * work];
                    for (i, row) in cells.iter().enumerate() {
                        p[i * work..i * work + len].copy_from_slice(row);
                    }
                    p
                } else {
                    Vec::new()
                };
                let _pad_charge = crate::memgauge::Charge::new(
                    crate::memgauge::Sub::RepairWork,
                    (padded.len() * 2) as u64,
                );
                let sources: Vec<&[u16]> = if pad {
                    padded.chunks_exact(work).collect()
                } else {
                    cells.iter().map(|r| &r[..]).collect()
                };
                let mut trows: Vec<&mut [u16]> = t.chunks_exact_mut(work).collect();
                if s1_owned {
                    self.owned_hankel(&sources, &mut trows);
                } else {
                    // SUB-STRIPES of the kernel's admitted width. The
                    // kernel arena is `n x len` per call, so this is
                    // what keeps it inside the shipped allowance while
                    // T and stage 2 stay at the full stripe. Exact by
                    // the same argument as the padding above: stage 1
                    // is elementwise across the stripe, so a column of
                    // T depends on that column of the syndromes alone
                    // and the cut between sub-stripes is invisible to
                    // it. One iteration when `kernel_w == work`, which
                    // is every depth where the arena fits.
                    let mut c0 = 0;
                    while c0 < work {
                        let c1 = (c0 + kernel_w).min(work);
                        let sub_src: Vec<&[u16]> = sources.iter().map(|r| &r[c0..c1]).collect();
                        let mut sub_t: Vec<&mut [u16]> =
                            trows.iter_mut().map(|r| &mut r[c0..c1]).collect();
                        self.joint_hankel_stripe(joint, &sub_src, &mut sub_t);
                        c0 = c1;
                    }
                }
            }
            let b = std::time::Instant::now();
            stage1_worker.fetch_add((b - a).as_nanos() as u64, Ordering::Relaxed);
            // The syndrome columns are dead the moment T holds them, and
            // `evaluate` accumulates into a zeroed destination.
            for cell in cells.iter_mut() {
                cell.fill(0);
            }
            // Stage 2 at the TRUE width: the padded columns of T are
            // zeros the answer does not read.
            let trows: Vec<&[u16]> = t.chunks_exact(work).map(|r| &r[..len]).collect();
            match &joint.factor {
                Some(f) if !s2_owned => self.joint_evaluate_stripe(f, &trows, cells, w),
                _ => self.owned_evaluate(&trows, cells, w),
            }
            stage2_worker.fetch_add(b.elapsed().as_nanos() as u64, Ordering::Relaxed);
        };
        per_stripe_bounded(&mut syn, w, body);
        let wall = t0.elapsed().as_nanos() as u64;
        let (s1, s2) = (
            stage1_worker.load(Ordering::Relaxed),
            stage2_worker.load(Ordering::Relaxed),
        );
        let split = |part: u64| {
            let total = s1.saturating_add(s2);
            if total == 0 {
                0
            } else {
                (u128::from(wall) * u128::from(part) / u128::from(total)) as u64
            }
        };
        SOLVE_STAGE1_NS.fetch_add(split(s1), Ordering::Relaxed);
        SOLVE_STAGE2_NS.fetch_add(split(s2), Ordering::Relaxed);
        SOLVE_STAGE1.fetch_add(1, Ordering::Relaxed);
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            // `kernel Nw` only when it differs from the stripe: both
            // harnesses key the label on the words before the first
            // comma and record the rest verbatim, so an extra clause is
            // carried, not parsed - and a line that says nothing new
            // on the depths that were never narrowed reads the same as
            // it did before this field existed.
            info!(
                target: "repair-timing",
                "  forney stage 1 (joint {}, stripe {w}w{}{}): {:.2?} of {:.2?} wall (attributed by worker share)",
                self.joint_kernel_name(joint),
                if kernel_w < w && !s1_owned {
                    format!(", kernel {kernel_w}w")
                } else {
                    String::new()
                },
                // Both harnesses key a held stage 1 on the word FALLBACK;
                // the clause after it says WHICH kind, because a gate
                // and a refusal are different facts for the reader.
                if s1_decline.is_some() {
                    ", FALLBACK arithmetic".to_string()
                } else if !s1_gate {
                    format!(
                        ", FALLBACK arithmetic below the kernel gate {JOINT_KERNEL_MIN_M_X86}"
                    )
                } else {
                    String::new()
                },
                std::time::Duration::from_nanos(split(s1)),
                std::time::Duration::from_nanos(wall),
            );
            // The two stages take their arms INDEPENDENTLY since 11 Sep
            // 2026, so this line has to name stage 2's own arm rather
            // than inherit stage 1's - a round that read the stage-1
            // label and credited both stages to it would be reading the
            // arm it did not run. `FALLBACK` is the same word stage 1
            // uses, for the same reason: it is what a harness greps.
            info!(
                target: "repair-timing",
                "  forney stage 2 ({}, stripe {w}w): {:.2?} of {:.2?} wall (attributed by worker share)",
                if s2_owned {
                    // Facts, not a cause: `NZBFAST_FORNEY_FACTOR=off`
                    // reaches here with `m` above the gate, and a line
                    // that said "m < gate" would be lying on exactly
                    // the legs a measurement round runs.
                    format!(
                        "joint scheduler, m={}, gate {JOINT_FACTOR_MIN_M}, FALLBACK arithmetic",
                        self.m
                    )
                } else {
                    format!(
                        "joint factor, {} tile(s)",
                        joint.factor.as_ref().map_or(0, |f| f.tiles.len())
                    )
                },
                std::time::Duration::from_nanos(split(s2)),
                std::time::Duration::from_nanos(wall),
            );
        }
        syn
    }

    fn joint_kernel_name(&self, joint: &JointPlan) -> &'static str {
        if joint.tail.is_some() {
            "short tail"
        } else if joint.peeled.is_some() {
            "peeled"
        } else {
            "whole/demand"
        }
    }

    /// Stage 1 over one already-column-sliced stripe: the additive-FFT
    /// product, cascaded tail -> peel -> whole exactly as the plan
    /// selected. `syn` and `cells` are both `self.m` rows of
    /// `cells[0].len()` columns.
    fn joint_hankel_stripe(&self, joint: &JointPlan, syn: &[&[u16]], cells: &mut [&mut [u16]]) {
        let len = cells[0].len();
        if let Some(p) = &joint.tail {
            let mut buf = vec![0u16; p.kernel.n * len];
            let _scratch = crate::memgauge::Charge::new(
                crate::memgauge::Sub::RepairWork,
                (buf.len() * 2 + p.kernel.n / 2) as u64,
            );
            for j in 0..p.d {
                buf[j * len..(j + 1) * len].copy_from_slice(syn[self.m - 1 - j]);
            }
            whole::linear_band(&p.kernel, &mut buf, len, p.d);
            for (t, dst) in cells.iter_mut().enumerate() {
                let r = self.m - 1 + t;
                let residual = if r < 2 * p.d - 1 {
                    Some(&buf[r * len..(r + 1) * len])
                } else {
                    None
                };
                p.finish_row_stripe(dst, syn, r, residual);
            }
        } else if let Some(p) = &joint.peeled {
            let d = self.m - 1;
            assert_eq!(p.count(), d, "the peeled kernel must carry B's low terms");
            let mut buf = vec![0u16; p.kernel.n * len];
            let _scratch = crate::memgauge::Charge::new(
                crate::memgauge::Sub::RepairWork,
                (buf.len() * 2 + p.kernel.n / 2) as u64,
            );
            for j in 0..d {
                buf[j * len..(j + 1) * len].copy_from_slice(syn[d - j]);
            }
            whole::linear_band(&p.kernel, &mut buf, len, d);
            let high = syn[0];
            for (j, dst) in cells[..d].iter_mut().enumerate() {
                let residual = if j < d - 1 {
                    Some(&buf[(d + j) * len..(d + j + 1) * len])
                } else {
                    None
                };
                p.finish_row(dst, high, syn[d - j], residual, j);
            }
            cells[d].copy_from_slice(high);
        } else {
            let k = &joint.whole;
            let mut buf = vec![0u16; k.n * len];
            let _scratch = crate::memgauge::Charge::new(
                crate::memgauge::Sub::RepairWork,
                (buf.len() * 2 + k.n / 2) as u64,
            );
            for j in 0..self.m {
                buf[j * len..(j + 1) * len].copy_from_slice(syn[self.m - 1 - j]);
            }
            whole::linear_demand(k, &mut buf, len, self.m);
            for (i, dst) in cells.iter_mut().enumerate() {
                let a = (self.m - 1 + i) * len;
                dst.copy_from_slice(&buf[a..a + len]);
            }
        }
    }

    /// Stage 2 over one stripe of the local T, through [`FactorPlan`].
    fn joint_evaluate_stripe(
        &self,
        p: &FactorPlan,
        t: &[&[u16]],
        cells: &mut [&mut [u16]],
        w: usize,
    ) {
        let len = cells[0].len();
        let cap = (SPECTRA_BUDGET / (2 * w.max(1))).saturating_sub(17) / GT2;
        if cap == 0 {
            self.owned_evaluate(t, cells, w);
            return;
        }
        let largest = p
            .tiles
            .iter()
            .map(|v| v.groups.len())
            .max()
            .unwrap_or(0)
            .min(cap);
        let mut b = vec![0u16; largest * GT2 * len];
        let mut u = vec![0u16; 17 * len];
        let _scratch = crate::memgauge::Charge::new(
            crate::memgauge::Sub::RepairWork,
            ((b.len() + u.len()) * 2) as u64,
        );
        let mut src: Vec<&[u16]> = Vec::with_capacity(self.m.div_ceil(GT2).max(1));
        let mut coeff: Vec<u16> = Vec::with_capacity(self.m.div_ceil(GT2).max(1));
        for tile in &p.tiles {
            for (chunk, groups) in tile.groups.chunks(cap).enumerate() {
                b.fill(0);
                for t2 in 0..GT2 {
                    u.fill(0);
                    let count = self.t_off[t2 + 1] - self.t_off[t2];
                    // One pass over T's rows in this 257-residue class,
                    // folded into 17 accumulators by `j mod 17`. This is
                    // the pass the shipped stage 2 repeats per GROUP.
                    for c in 0..17 {
                        src.clear();
                        coeff.clear();
                        for j in (c..count).step_by(17) {
                            src.push(t[t2 + GT2 * j]);
                            coeff.push(tile.first[j]);
                        }
                        fold_rows(&mut u[c * len..][..len], &src, &coeff);
                    }
                    let us: Vec<&[u16]> = u.chunks_exact(len).collect();
                    for gi in 0..groups.len() {
                        let base = ((chunk * cap + gi) * GT2 + t2) * 17;
                        fold_rows(
                            &mut b[(gi * GT2 + t2) * len..][..len],
                            &us,
                            &tile.second[base..base + 17],
                        );
                    }
                }
                for (gi, &g) in groups.iter().enumerate() {
                    let bs: Vec<&[u16]> =
                        b[gi * GT2 * len..][..GT2 * len].chunks_exact(len).collect();
                    for &c in &self.groups[g] {
                        fold_rows(
                            cells[c as usize],
                            &bs,
                            &self.evalc[c as usize * GT2..][..GT2],
                        );
                    }
                }
            }
        }
    }

    /// The SHIPPED stage-1 arithmetic, per stripe: byte for byte
    /// [`ForneyPlan::hankel`]'s body, reading pre-sliced rows instead of
    /// slicing `syn` by an absolute offset. The fallback arm, and the
    /// control the joint kernels are proved against.
    fn owned_hankel(&self, syn: &[&[u16]], cells: &mut [&mut [u16]]) {
        let mixed = self.stage1.is_mixed();
        let len = cells[0].len();
        let mut shat = vec![0u16; self.nseg * CONV * len];
        let mut chat = vec![0u16; CONV * len];
        let dft_words = if mixed { CONV * len } else { 0 };
        let mut dft_a = vec![0u16; dft_words];
        let mut dft_b = vec![0u16; dft_words];
        let _arena = crate::memgauge::Charge::new(
            crate::memgauge::Sub::RepairWork,
            ((shat.len() + chat.len() + dft_a.len() + dft_b.len()) * 2) as u64,
        );
        let mut ssrc: Vec<&[u16]> = Vec::with_capacity(BLK);
        let mut sp: Vec<&[u16]> = Vec::with_capacity(self.nseg);
        let mut coeffs: Vec<u16> = Vec::with_capacity(self.nseg);
        for j in 0..self.nseg {
            let r0 = j * BLK;
            let r1 = (r0 + BLK).min(self.m);
            ssrc.clear();
            ssrc.extend(syn[r0..r1].iter().map(|row| &row[..len]));
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
        for i in 0..self.nseg {
            chat.fill(0);
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
    }

    /// The SHIPPED stage-2 arithmetic, per stripe: byte for byte
    /// [`ForneyPlan::evaluate`]'s body over pre-sliced rows.
    fn owned_evaluate(&self, t: &[&[u16]], cells: &mut [&mut [u16]], w: usize) {
        let gtile = (SPECTRA_BUDGET / (GT2 * w.max(1) * 2)).clamp(1, self.groups.len().max(1));
        let len = cells[0].len();
        let mut b = vec![0u16; gtile * GT2 * len];
        let _arena =
            crate::memgauge::Charge::new(crate::memgauge::Sub::RepairWork, (b.len() * 2) as u64);
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
                tsrc.extend(self.t_order[a..z].iter().map(|&r| &t[r as usize][..len]));
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
    }
}

/// [`super::per_stripe`]'s twin for a buffer that is CONSUMED: the rows
/// are carved into column stripes lazily under one mutex, one unit per
/// worker at a time, and each unit's cells are the caller's own storage
/// rather than a separate destination.
///
/// Lazily rather than all at once because the eager
/// `column_stripes` shape builds every stripe's `Vec<&mut [u16]>` up
/// front - `m` pointers per stripe, `ceil(words / w)` stripes - which at
/// the repair cap is tens of millions of pointers held for the whole
/// solve, against a bounded one-unit-per-worker here.
fn per_stripe_bounded<F>(rows: &mut [Vec<u16>], w: usize, body: F)
where
    F: Fn(usize, &mut Vec<&mut [u16]>) + Sync,
{
    if rows.is_empty() {
        return;
    }
    let words = rows[0].len();
    assert!(rows.iter().all(|r| r.len() == words));
    let w = w.max(1);
    let n = words.div_ceil(w).max(1);
    PREP_STRIPE_USES.fetch_add(n as u64, Ordering::Relaxed);
    let workers = crate::mem::cpu_workers().max(1).min(n);
    let rest: Vec<&mut [u16]> = rows.iter_mut().map(Vec::as_mut_slice).collect();
    let cursor = std::sync::Mutex::new((rest, 0usize));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let cursor = &cursor;
            let body = &body;
            scope.spawn(move || {
                loop {
                    let unit = {
                        let mut guard = cursor.lock_ok();
                        let (rest, next) = &mut *guard;
                        if *next == n {
                            None
                        } else {
                            let off = *next * w;
                            *next += 1;
                            // Take the head of each row's remainder, so
                            // the borrows handed out are provably
                            // disjoint from the ones still held.
                            let cells = rest
                                .iter_mut()
                                .map(|r| {
                                    let remaining = std::mem::take(r);
                                    let take = remaining.len().min(w);
                                    let (head, tail) = remaining.split_at_mut(take);
                                    *r = tail;
                                    head
                                })
                                .collect();
                            Some((off, cells))
                        }
                    };
                    let Some((off, mut cells)) = unit else {
                        break;
                    };
                    body(off, &mut cells);
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::super::{ForneyPlan, locator, poly};
    use super::{
        JOINT_FACTOR_MIN_M, JointDecline, JointReach, decline_code, factor_gate, reach_of,
    };
    use crate::gf16::{self, MulTable};

    /// Base logs for `m` missing columns, spread over the group so the
    /// stage-2 grouping is exercised rather than collapsing onto one
    /// residue class. Coprime to 65,535, as real base logs are.
    fn ks(m: usize) -> Vec<u32> {
        (0..m as u32).map(|i| (i * 4051 + 7) % 65535 + 1).collect()
    }

    fn syn(m: usize, words: usize) -> Vec<Vec<u16>> {
        (0..m)
            .map(|i| {
                (0..words)
                    .map(|j| ((i * 7919 + j * 31337 + 13) ^ (i * j)) as u16)
                    .collect()
            })
            .collect()
    }

    /// The product tree is a RE-ASSOCIATION of the coefficient chain,
    /// not a different polynomial: the two must agree word for word at
    /// every shape, including the leaf boundary and the odd tail.
    #[test]
    fn locator_tree_matches_the_chain() {
        for m in [
            1, 2, 3, 7, 63, 64, 65, 127, 128, 129, 130, 255, 256, 257, 1000, 1024, 1025, 2048,
        ] {
            let bases: Vec<u16> = ks(m).iter().map(|&k| gf16::pow2(k as u64)).collect();
            let chain = locator::chain(&bases);
            let (tree, stats) = locator::build(&bases, true);
            assert_eq!(chain, tree, "m={m}");
            assert_eq!(chain.len(), m + 1, "m={m}");
            assert_eq!(chain[m], 1, "the locator polynomial is monic, m={m}");
            assert!(stats.peak_heap_bound >= tree.len() * 2, "m={m}");
        }
    }

    /// The whole-field derivative table must answer exactly what the
    /// per-column Horner pass answers, at every point the solve reads.
    #[test]
    fn field_derivative_matches_horner() {
        for m in [1, 2, 3, 64, 129, 256, 1000] {
            let bases: Vec<u16> = ks(m).iter().map(|&k| gf16::pow2(k as u64)).collect();
            let p = locator::chain(&bases);
            let dodd: Vec<u16> = (0..)
                .map(|j| 2 * j + 1)
                .take_while(|&i| i <= m)
                .map(|i| p[i])
                .collect();
            let (values, heap) = poly::evaluate_field(&dodd);
            assert!(heap >= 65536 * 2, "m={m}");
            for &g in &bases {
                let z2 = MulTable::new(gf16::mul(g, g));
                let mut want = 0u16;
                for &coef in dodd.iter().rev() {
                    want = z2.mul(want) ^ coef;
                }
                assert_eq!(values[gf16::mul(g, g) as usize], want, "m={m}");
            }
        }
    }

    /// The joint CONSTRUCTOR must produce the same plan the shipped one
    /// does: every table the two-stage solve reads, entry for entry. A
    /// plan that differs here would make the solve comparison below
    /// meaningless.
    #[test]
    fn joint_constructor_builds_the_same_plan_tables() {
        for m in [64, 128, 129, 130, 255, 256, 260] {
            let k = ks(m);
            let base = ForneyPlan::prepare_impl(&k, 3, true, false).expect("distinct bases");
            let joint = ForneyPlan::prepare_impl(&k, 3, true, true)
                .expect("distinct bases")
                .with_kernel_forced();
            assert_eq!(base.rhat, joint.rhat, "m={m}");
            assert_eq!(base.t_order, joint.t_order, "m={m}");
            assert_eq!(base.t_off, joint.t_off, "m={m}");
            assert_eq!(base.stage_a, joint.stage_a, "m={m}");
            assert_eq!(base.evalc, joint.evalc, "m={m}");
            assert_eq!(base.groups, joint.groups, "m={m}");
            assert!(base.locator.is_empty(), "the shipped arm retains no P");
            assert!(joint.has_joint(), "m={m}");
        }
    }

    /// Stage 2's factored coefficients must reproduce `stage_a` exactly:
    /// `first[j] * second[(g, t2, j mod 17)] == stage_a[g * m + a + j]`.
    /// This is the whole of the stage-2 change, checked as an identity
    /// rather than argued from the Good-Thomas split.
    #[test]
    fn factored_coefficients_match_stage_a() {
        for m in [64, 129, 257, 300] {
            let k = ks(m);
            let plan = ForneyPlan::prepare_impl(&k, 5, true, true)
                .expect("distinct bases")
                .with_kernel_forced();
            let factor = plan.factor_plan(&k);
            let mut checks = 0usize;
            for tile in &factor.tiles {
                for (gi, &g) in tile.groups.iter().enumerate() {
                    for t2 in 0..super::GT2 {
                        let (a, z) = (plan.t_off[t2], plan.t_off[t2 + 1]);
                        for j in 0..z - a {
                            assert_eq!(
                                gf16::mul(
                                    tile.first[j],
                                    tile.second[(gi * super::GT2 + t2) * 17 + j % 17]
                                ),
                                plan.stage_a[g * plan.m + a + j],
                                "m={m} g={g} t2={t2} j={j}"
                            );
                            checks += 1;
                        }
                    }
                }
            }
            assert!(checks >= m, "m={m} checked {checks}");
        }
    }

    /// THE proof this switch turns on: the joint arm's output must be
    /// BYTE-IDENTICAL to the shipped two-stage solve, at every `m` shape
    /// that selects a different stage-1 kernel and at word counts that
    /// put the last stripe on and off the stripe boundary.
    ///
    /// `m` classes: a power of two (whole/demand), a power of two plus
    /// one (peel), plus two through eight (short tail), and a long tail
    /// (back to whole/demand because `q > MAX_Q`).
    ///
    /// **This is the STAGE-1 sweep, and since the 11 Sep 2026 split
    /// every `m` in it is below [`JOINT_FACTOR_MIN_M`]**, so all of it
    /// runs the shipped stage 2 - which is exactly the pairing the
    /// split exists to make reachable, and is the arm a shallow repair
    /// takes. The factored stage 2 is proved at depth by
    /// `at_the_gate_stage_two_takes_the_factored_arm`; do not read this
    /// test as covering it.
    #[test]
    fn joint_solve_is_byte_identical_to_the_shipped_solve() {
        for m in [
            1, 2, 3, 8, 64, 65, 66, 72, 96, 128, 129, 130, 136, 200, 256, 257, 260,
        ] {
            let k = ks(m);
            let base = ForneyPlan::prepare_impl(&k, 2, true, false).expect("distinct bases");
            let joint = ForneyPlan::prepare_impl(&k, 2, true, true)
                .expect("distinct bases")
                .with_kernel_forced();
            // 48 is deliberately NOT a multiple of the 32-word stripe
            // granule, so the last stripe is short at every `m`.
            for words in [16, 48] {
                assert_eq!(
                    joint.joint_takes_the_kernel(words),
                    kernel_on_this_box(),
                    "m={m} words={words}: this cell must run the ADDITIVE kernel, \
                     or the comparison below is certifying the fallback"
                );
                let s = syn(m, words);
                let want = base.solve(&s, words);
                let got = joint.solve_joint(s).expect("the joint arm is armed");
                assert_eq!(got, want, "m={m} words={words}");
            }
        }
        // Wide blocks, where a solve runs MANY stripes and the last one
        // is short: one cell per stage-1 kernel, because a debug-build
        // sweep of every (m, words) pair costs minutes.
        for (m, words) in [(128, 1024), (129, 1024), (130, 1040), (260, 528)] {
            let k = ks(m);
            let base = ForneyPlan::prepare_impl(&k, 2, true, false).expect("distinct bases");
            let joint = ForneyPlan::prepare_impl(&k, 2, true, true)
                .expect("distinct bases")
                .with_kernel_forced();
            assert_eq!(
                joint.joint_takes_the_kernel(words),
                kernel_on_this_box(),
                "m={m} words={words}"
            );
            let s = syn(m, words);
            let want = base.solve(&s, words);
            let got = joint.solve_joint(s).expect("the joint arm is armed");
            assert_eq!(got, want, "m={m} words={words}");
        }
    }

    /// The stage-1 depth gate is a threshold on `m` alone, per class, and
    /// the environment forces it both ways. A GATED class (Nibble,
    /// Gfni256) runs the Hankel below [`JOINT_KERNEL_MIN_M_X86`] and the
    /// kernel at it; an ungated class takes the kernel at every depth.
    /// Pinned at the constant and one below it, the way the factor gate
    /// is, so a recalibration cannot move the boundary out from between
    /// the sample points.
    #[test]
    fn the_kernel_gate_is_a_threshold_on_m_alone_on_the_gated_classes() {
        if std::env::var_os("NZBFAST_FORNEY_STAGE1").is_some() {
            return;
        }
        use super::{JOINT_KERNEL_MIN_M_X86, kernel_gate};
        use crate::par2seams::KernelClass;
        let gated = matches!(
            KernelClass::current(),
            KernelClass::Nibble | KernelClass::Gfni256
        );
        assert!(kernel_gate(JOINT_KERNEL_MIN_M_X86));
        assert!(kernel_gate(usize::MAX));
        assert_eq!(kernel_gate(JOINT_KERNEL_MIN_M_X86 - 1), !gated);
        assert_eq!(kernel_gate(1), !gated);
        // And a plan built WITHOUT the test override reads the gate: on
        // a gated class a shallow plan runs the Hankel and reports the
        // arm as TAKEN, never as a decline.
        //
        // The one decline this aligned 64-word stripe CAN carry is the
        // host's: `joint_stripe` asks `scale_available` before it asks
        // the gate, so a box with no vector scale declines
        // `NoScaleKernel` at every depth. Asserting `None` flat took the
        // nightly armv7-cross job red on 00bdc3a3 - armv7 is the one
        // shipped target with no scale kernel, so no x86 or arm64 runner
        // could see it. Same two-state fact, read the same way, as
        // `a_declining_stripe_names_which_condition_it_tripped`.
        let k = ks(1024);
        let joint = ForneyPlan::prepare_impl(&k, 2, true, true).expect("distinct bases");
        let want = if gf16::scale_available() {
            None
        } else {
            Some(JointDecline::NoScaleKernel)
        };
        assert_eq!(
            joint.joint_decline(64),
            Some(want),
            "the gate is not a decline"
        );
        assert_eq!(
            joint.joint_takes_the_kernel(64),
            Some(!gated && kernel_on_this_box() == Some(true))
        );
        // 64 words, not a full block: the gate is on `m`, and a debug
        // solve at m = 1,024 costs about a millisecond a column.
        let s = syn(1024, 64);
        let base = ForneyPlan::prepare_impl(&k, 2, true, false).expect("distinct bases");
        assert_eq!(
            joint.solve_joint(s.clone()).expect("armed"),
            base.solve(&s, 64)
        );
    }

    /// When the kernel arena does not fit the shipped stage-1 allowance
    /// at the shipped stripe, the STRIPE keeps the shipped width and
    /// stage 1 runs it in sub-stripes of the admitted width - and the
    /// answer is still byte-identical to the shipped solve.
    ///
    /// The shapes are the ones the arithmetic narrows: `n`, the
    /// transform size, is the power of two at or above `2m - 1`, and
    /// the allowance is `(nseg + 3) * 255` rows, so `m` just past a
    /// power of two is where `n` doubles while `nseg` has barely
    /// grown. 1,025 selects the PEELED kernel, 1,030 the short-tail
    /// one, 1,100 the whole/demand one, so all three run sub-striped.
    /// 1,000 words is a short last stripe that is PADDED (to 496) and
    /// then sub-striped (256 + 240), the two mechanisms composed.
    ///
    /// The widths are asserted as well as the bytes, because a test
    /// that only compared bytes would pass on a build that quietly went
    /// back to narrowing the whole stripe - the exact shape this fix
    /// replaces was byte-identical too. `w` is asserted against the
    /// plan's own `stripe_w` rather than a literal so a box whose solve
    /// budget narrows the shipped stripe still runs the test honestly.
    ///
    /// NARROW BLOCKS, on purpose: the narrowing is decided by `m` alone
    /// (`n` against `(nseg + 3) * 255` rows) and sub-striping needs only
    /// a block wider than the kernel width, so 32 and 64 words exercise
    /// it fully (kernel 16 and 32) at a hundredth of the cost of the
    /// 1,024-word cells this test first shipped with - which ran over
    /// 300 s in a debug build on a 4-vCPU runner and tripped the wedge
    /// gate on linux-tests (run 34707869753, 12 Sep 2026). The one wide
    /// cell below is the PADDED short-last-stripe composition, which
    /// needs a block past the 512-word stripe, kept at the cheapest `m`.
    #[test]
    fn stage_one_sub_stripes_when_the_arena_narrows_and_stage_two_keeps_the_stripe() {
        for m in [1025usize, 1030, 1100] {
            let k = ks(m);
            let base = ForneyPlan::prepare_impl(&k, 2, true, false).expect("distinct bases");
            let joint = ForneyPlan::prepare_impl(&k, 2, true, true)
                .expect("distinct bases")
                .with_kernel_forced();
            // 520 only at the peeled shape: a 512-word stripe plus an
            // eight-word last stripe padded to 16, then sub-striped.
            let widths: &[usize] = if m == 1025 { &[32, 64, 520] } else { &[32, 64] };
            for &words in widths {
                let (w, kernel_w) = joint.joint_widths(words).expect("armed");
                assert_eq!(
                    w,
                    base.stripe_w(words),
                    "m={m} words={words}: the STRIPE is the shipped width"
                );
                assert!(
                    kernel_w < w,
                    "m={m} words={words}: this shape must narrow the kernel (w={w}, kernel_w={kernel_w}), \
                     or the comparison below is not exercising the sub-stripes"
                );
                assert!(kernel_w.is_multiple_of(16) && w.is_multiple_of(kernel_w));
                assert_eq!(
                    joint.joint_takes_the_kernel(words),
                    kernel_on_this_box(),
                    "m={m} words={words}"
                );
                let s = syn(m, words);
                let want = base.solve(&s, words);
                let got = joint.solve_joint(s).expect("the joint arm is armed");
                assert_eq!(got, want, "m={m} words={words}");
            }
        }
        // And the control: a shape whose arena FITS is not sub-striped,
        // so the depths that were never narrowed run exactly as before.
        let k = ks(1000);
        let joint = ForneyPlan::prepare_impl(&k, 2, true, true)
            .expect("distinct bases")
            .with_kernel_forced();
        let (w, kernel_w) = joint.joint_widths(1024).expect("armed");
        assert_eq!(w, kernel_w, "m=1000: n=2048 fits (8 + 3) * 255 rows");
    }

    /// A SHORT LAST STRIPE must still take the additive kernel, and
    /// still be exact.
    ///
    /// This is the 10 Sep short-stripe fix, and it is the assertion that
    /// changed sign: these word counts used to be REFUSED outright,
    /// because stage 1 will not take a width off the 32-byte unit. It
    /// will not - but the stripe width is a power of two, so only the
    /// LAST stripe is ever off it, and padding that one costs at most 15
    /// columns where refusing cost the whole solve. About seven of eight
    /// sets `parfast c` creates by block COUNT land here.
    ///
    /// Every width below is larger than one stripe, which is what makes
    /// the last stripe short rather than the only stripe odd - see
    /// `joint_falls_back_exactly_when_the_geometry_refuses` for the case
    /// that still refuses.
    ///
    /// Admission is asserted against [`kernel_on_this_box`], not a bare
    /// `Some(true)`: see that helper for the CI incident.
    #[test]
    fn a_short_last_stripe_is_padded_and_still_exact() {
        for m in [64, 129, 130, 200] {
            let k = ks(m);
            let base = ForneyPlan::prepare_impl(&k, 9, true, false).expect("distinct bases");
            let joint = ForneyPlan::prepare_impl(&k, 9, true, true)
                .expect("distinct bases")
                .with_kernel_forced();
            // Last-stripe remainders of 2, 488, 511, 1 and 1 words.
            for words in [514, 1_000, 1_023, 1_025, 4_097] {
                assert_eq!(
                    joint.joint_takes_the_kernel(words),
                    kernel_on_this_box(),
                    "m={m} words={words}: a short LAST stripe must not refuse the kernel"
                );
                let s = syn(m, words);
                let want = base.solve(&s, words);
                let got = joint.solve_joint(s).expect("the joint arm is armed");
                assert_eq!(got, want, "m={m} words={words}");
            }
        }
    }

    /// What still refuses, and must.
    ///
    /// `stripe_w` clamps the stripe to the BLOCK when the block is
    /// narrower than `STRIPE_W_TARGET`, so a block under ~1 KiB that is
    /// not itself 16-word aligned has no long stripe to be the short
    /// tail of - there is one stripe and it is odd. Those still take the
    /// shipped arithmetic, as does the direct stage-1 plan. Both still
    /// repair exactly.
    #[test]
    fn joint_falls_back_exactly_when_the_geometry_refuses() {
        for m in [64, 129, 130] {
            let k = ks(m);
            let base = ForneyPlan::prepare_impl(&k, 9, true, false).expect("distinct bases");
            let joint = ForneyPlan::prepare_impl(&k, 9, true, true)
                .expect("distinct bases")
                .with_kernel_forced();
            for words in [1, 3, 15, 17, 33, 100] {
                assert_eq!(
                    joint.joint_takes_the_kernel(words),
                    Some(false),
                    "m={m} words={words}: this cell must FALL BACK"
                );
                let s = syn(m, words);
                let want = base.solve(&s, words);
                let got = joint.solve_joint(s).expect("the joint arm is armed");
                assert_eq!(got, want, "m={m} words={words}");
            }
        }
        // And the DIRECT stage-1 plan, which the joint kernel also
        // refuses: same answer, shipped arithmetic.
        let k = ks(128);
        let base = ForneyPlan::prepare_impl(&k, 1, false, false).expect("distinct bases");
        let joint = ForneyPlan::prepare_impl(&k, 1, false, true).expect("distinct bases");
        assert_eq!(joint.joint_takes_the_kernel(64), Some(false));
        let s = syn(128, 64);
        let want = base.solve(&s, 64);
        assert_eq!(joint.solve_joint(s).expect("armed"), want);
    }

    /// Plan reuse: a repair with several windows solves through ONE
    /// plan, so the joint arm must be exact on the second and third
    /// call as well as the first. A kernel that left state in its plan
    /// would pass the single-solve test above and fail here.
    #[test]
    fn a_reused_joint_plan_is_exact_on_every_window() {
        let m = 130;
        let k = ks(m);
        let base = ForneyPlan::prepare_impl(&k, 4, true, false).expect("distinct bases");
        let joint = ForneyPlan::prepare_impl(&k, 4, true, true)
            .expect("distinct bases")
            .with_kernel_forced();
        for round in 0..3u16 {
            let mut s = syn(m, 512);
            for (i, row) in s.iter_mut().enumerate() {
                for (j, v) in row.iter_mut().enumerate() {
                    *v ^= round.wrapping_mul((i * 31 + j) as u16);
                }
            }
            let want = base.solve(&s, 512);
            assert_eq!(joint.joint_takes_the_kernel(512), kernel_on_this_box());
            assert_eq!(joint.solve_joint(s).expect("armed"), want, "round={round}");
        }
    }

    /// With the switch unset nothing is built and nothing is entered:
    /// the plan carries no joint arm and `solve_joint` hands the
    /// syndromes straight back so the caller takes the shipped path.
    #[test]
    fn an_unarmed_plan_returns_the_syndromes_untouched() {
        let k = ks(64);
        let plan = ForneyPlan::prepare_impl(&k, 1, true, false).expect("distinct bases");
        assert!(!plan.has_joint());
        assert_eq!(plan.joint_takes_the_kernel(64), None);
        let s = syn(64, 64);
        let back = plan.solve_joint(s.clone()).expect_err("no joint arm");
        assert_eq!(back, s);
    }

    /// REAL BLOCK SIZES, and the ones that matter are the ones that
    /// used to refuse.
    ///
    /// PAR2 requires only a multiple of four, and `create::block_size`
    /// searches upward in steps of FOUR with nothing preferring 32, so a
    /// set created by block COUNT - which is `parfast c`'s own default -
    /// lands on a 32-aligned width about one time in eight. Replicating
    /// that search over 42 shapes from 10 to 200 GiB gave 5 of 42, which
    /// is chance. Before the short-stripe fix every one of the other 37
    /// ran the shipped arithmetic and bought nothing; now they all run
    /// the kernel.
    #[test]
    fn real_block_sizes_run_the_kernel() {
        let k = ks(128);
        let joint = ForneyPlan::prepare_impl(&k, 1, true, true)
            .expect("distinct bases")
            .with_kernel_forced();
        for (words, what) in [
            // Widths the block-COUNT search actually picks. Not one of
            // these is 32-aligned; all of them used to refuse.
            (83_114usize, "166,228 B, a 320 MB set at -b4096"),
            (2_714_212, "5,428,424 B, 10 GiB at the default block count"),
            (6_242_686, "12,485,372 B, 23 GiB"),
            (27_142_110, "54,284,220 B, 100 GiB"),
            // And the conventional posted sizes, which always were fine.
            (32_768, "64 KiB"),
            (163_840, "327,680 B, the phase-profile fixture"),
            (192_000, "384,000 B"),
            (384_000, "768,000 B"),
        ] {
            assert_eq!(
                joint.joint_takes_the_kernel(words),
                kernel_on_this_box(),
                "words={words} ({what})"
            );
        }
        // A block narrower than one stripe that is not itself aligned
        // has no long stripe to be the short tail of, and still refuses.
        assert_eq!(joint.joint_takes_the_kernel(15), Some(false));
    }

    /// Stage 1 is gated on GEOMETRY and stage 2 on DEPTH, so the two
    /// axes are independent and ALL FOUR combinations are reachable.
    /// The four tests below are the four cells of that table, each
    /// proved byte-identical to the shipped two-stage solve with the
    /// arm EACH STAGE took asserted rather than assumed - the whole
    /// hazard of a split gate is a cell that certifies an arm it did
    /// not run, and until 11 Sep 2026 one boolean answered for both
    /// stages so no test could tell them apart.
    ///
    /// `m` pins [`JOINT_FACTOR_MIN_M`] and one below it, so these tests
    /// MOVE WHEN THE CONSTANT MOVES and a re-measure that forgets to
    /// re-read them reds here rather than quietly testing one side
    /// twice.
    ///
    /// # ONE CELL PER TEST, and that is a wall-clock rule
    ///
    /// The four cells were two tests of two cells each until 11 Sep
    /// 2026, when both of them hit nightly `armv7-cross`'s 900 s
    /// per-test ceiling (`[profile.qemu]` in `.config/nextest.toml`):
    /// `at_the_gate_stage_two_takes_the_factored_arm` timed out on both
    /// tries and its sibling PASSED at 887.727 s, thirteen seconds
    /// under the same cap, on run 34583096699. Four solves at this
    /// depth do not fit in that ceiling under emulation; two do, with
    /// room. Splitting costs one extra pair of `prepare_impl` calls per
    /// cell - 0.83 s against ~230 s, measured - and nextest runs the
    /// four concurrently, so the JOB's wall does not grow.
    ///
    /// Measured on the same binary under qemu-arm-static, the two
    /// shapes end to end: 238 s and 246 s as two tests, against 128 /
    /// 118 / 126 / 134 s as four. That rig is not the runner - scaling
    /// its one anchored point (246 s here against the 887.727 s the
    /// identical test took on run 34583096699) puts the worst of the
    /// four at ~480 s, so the margin under the 900 s cap goes from
    /// thirteen seconds to about 1.9x, and these stop being the
    /// slowest tests in the job (a rars test at 606 s is).
    ///
    /// **Do not try to buy the time back by trimming `words` instead.**
    /// That is the obvious move and it is worth nothing here, which is
    /// only visible if you measure on the target that failed. At this
    /// depth on armv7 the solve cost is INDEPENDENT of the word count,
    /// because `gf16::multi_fold_width()` is 0 there: with no fused
    /// multi-fold kernel `fold_rows` takes the per-source
    /// [`gf16::FoldTable`] path for the WHOLE fold, and on a target
    /// that is neither aarch64 nor x86_64 that constructor WAS 512 field
    /// multiplies (the nibble/affine arms build 64). It was paid once
    /// per (row, source) whatever the width, so at the widths these
    /// tests can use it swamped the per-WORD work outright - 512
    /// multiplies to set up a fold of 15 words. `gf16::split_tables`
    /// made it a subset walk on 11 Sep 2026 - section 7.1 of
    /// `research/JOINT-STAGE2-DEPTH-GATE-2026-09-11.md` - and these
    /// cells are 2.5-2.9x faster for it, but the SHAPE of
    /// the finding survives the fix and is why this rule stands: the
    /// per-(row, source) setup still dominates the per-word work at
    /// these widths, so `words` is still not the lever. Measured under
    /// qemu-arm-static, BEFORE that fix, at
    /// `m = JOINT_FACTOR_MIN_M`, `base.solve` / `solve_joint`:
    ///
    ///   words   15    62.4 s / 52.2 s
    ///   words   16    62.3 s / 52.0 s
    ///   words   32    63.3 s / 52.7 s
    ///   words  520    68.8 s / 57.6 s
    ///
    /// 505 extra words buy 10%. On a box WITH the kernel the same axis
    /// is the dominant term (on an M-series Mac, opt-level 0, the same
    /// four cells are 10.6 s / 1.4 s / 2.8 s / 28.3 s), which is why
    /// the debug-suite figures further down are no guide at all to the
    /// emulated cost. The number of SOLVES per test is the only lever
    /// these tests have on the ceiling; `words` is not one.
    ///
    /// Stage 1's admission goes through [`kernel_on_this_box`] for the
    /// CI reason documented there; stage 2's does not, because its gate
    /// is arithmetic over `m` and reads the same on every part.
    #[test]
    fn at_the_gate_stage_two_takes_the_factored_arm() {
        // The `words` axis is stage 1's admission at this `m`, which is
        // a memory-allowance question and not a round number - at these
        // depths the additive kernel's arena fits and the stripe's
        // 32-BYTE unit is what decides, so 15 is refused (the cell
        // below) and 16 admitted. 520 is admitted AND leaves an
        // eight-word last stripe, so the PADDED stage-1 arm composes
        // with the factored stage 2 in this one cell - which is the
        // pairing a real deep repair actually takes, since about seven
        // of eight block sizes `parfast c` picks by block COUNT are off
        // the 32-byte unit (`real_block_sizes_run_the_kernel`).
        //
        // It is the expensive line in this crate's DEBUG suite (~26 s
        // against ~1.4 s for the admitted cell below the gate, because
        // a debug solve at these `m` runs about 44 ms per column and
        // this cell buys 520 of them) and it is the ONLY executed proof
        // anywhere that a padded stage 1 composes with the factored
        // stage 2. Cheaper widths were looked for and do not exist:
        // past the gate the stripe cap is 512 at every `m`, so a
        // `words` of 512 or under is a single stripe and cannot be
        // short. Under emulation it is not the expensive line at all -
        // see the width table above.
        stage_split_cell(JOINT_FACTOR_MIN_M, true, 520, kernel_on_this_box());
    }

    /// The same depth with stage 1 REFUSED, which is the other half of
    /// the at-gate row: a geometry the additive kernel cannot take must
    /// still send stage 2 down the FACTORED arm, because the two gates
    /// are independent. 15 words is a stripe that is not a whole number
    /// of 32-byte units, the commonest decline
    /// (`a_declining_stripe_names_which_condition_it_tripped` names the
    /// four reasons).
    #[test]
    fn at_the_gate_a_refused_stage_one_still_takes_the_factored_arm() {
        stage_split_cell(JOINT_FACTOR_MIN_M, true, 15, Some(false));
    }

    /// The other row: one missing block below the gate, where stage 2
    /// must take the SHIPPED evaluation whatever stage 1 chose. This is
    /// the arm the 11 Sep split exists to reach - the additive stage 1
    /// with the shipped stage 2 - and before the split it was
    /// unreachable, because one boolean sent both stages the same way.
    #[test]
    fn stage_two_takes_the_shipped_arm_below_the_gate() {
        stage_split_cell(JOINT_FACTOR_MIN_M - 1, false, 16, kernel_on_this_box());
    }

    /// And its refused half: below the gate with stage 1 declining too,
    /// the cell where NEITHER stage takes its new arm. It is the one
    /// combination that reads like a no-op and is not - it is the only
    /// place the two fallbacks are proved to compose.
    #[test]
    fn below_the_gate_a_refused_stage_one_takes_the_shipped_arm() {
        stage_split_cell(JOINT_FACTOR_MIN_M - 1, false, 15, Some(false));
    }

    /// One CELL of the stage-split table: one `m` and one width, with
    /// both stages' chosen arms asserted and the result byte-identical
    /// to the shipped solve. One cell per test is deliberate - see the
    /// wall-clock rule on `at_the_gate_stage_two_takes_the_factored_arm`
    /// before folding these back into a loop.
    fn stage_split_cell(m: usize, want_factor: bool, words: usize, want_kernel: Option<bool>) {
        let k = ks(m);
        let base = ForneyPlan::prepare_impl(&k, 2, true, false).expect("distinct bases");
        let joint = ForneyPlan::prepare_impl(&k, 2, true, true)
            .expect("distinct bases")
            .with_kernel_forced();
        assert_eq!(
            joint.joint_takes_the_kernel(words),
            want_kernel,
            "m={m} words={words}: stage 1 took the wrong arm"
        );
        assert_eq!(
            joint.joint_takes_the_factor(words),
            Some(want_factor),
            "m={m} words={words}: stage 2's arm must follow the DEPTH gate \
             ({JOINT_FACTOR_MIN_M}) and nothing stage 1 decided"
        );
        let s = syn(m, words);
        let want = base.solve(&s, words);
        let got = joint.solve_joint(s).expect("the joint arm is armed");
        assert_eq!(got, want, "m={m} words={words}");
    }

    /// The gate itself, as arithmetic: it is a threshold on `m` and
    /// nothing else, so one missing block decides it and nothing about
    /// the block width or the stage-1 geometry can move it.
    ///
    /// Cheap, and deliberately separate from the four exactness cells
    /// above: those cost seconds each on a box with the fold kernel and
    /// MINUTES each without one, so between them they can afford two
    /// points on this axis, where this one can walk the whole
    /// neighbourhood.
    #[test]
    fn the_factor_gate_is_a_threshold_on_m_alone() {
        assert!(!factor_gate(JOINT_FACTOR_MIN_M - 1));
        assert!(factor_gate(JOINT_FACTOR_MIN_M));
        assert!(factor_gate(JOINT_FACTOR_MIN_M + 1));
        assert!(!factor_gate(0));
        assert!(factor_gate(usize::MAX));
        // And it sits ABOVE the Forney gate on every class, which is
        // what makes the -222% at m = 256 unreachable rather than
        // merely unlikely: below `backsub_min_missing` there is no
        // transform solve to take a stage-2 arm at all.
        assert!(
            JOINT_FACTOR_MIN_M >= super::super::backsub_min_missing(),
            "the stage-2 gate must not sit below the Forney gate"
        );
    }

    /// What `joint_takes_the_kernel` answers for an admissible geometry
    /// ON THE BOX RUNNING THE TEST. It is not a constant: on x86 the
    /// fused scale kernel `joint_stripe` requires (`gf16::scale_available`)
    /// is present on the nibble-shuffle arms, i.e. AVX2 WITHOUT GFNI, and
    /// aarch64 always has it. **A GFNI part needed
    /// `NZBFAST_GF16_ROWOP_GFNI=1` when the incident below happened and
    /// does NOT any more** - `scale` stopped waiting on that gate on
    /// 11 Sep 2026 and the gate itself then shipped on - so a GFNI
    /// runner now answers the same `Some(true)` an Apple box does. The
    /// relaxation below is still right and still load-bearing: it is
    /// what makes these tests read the box rather than a constant, and
    /// an x86 part with neither GFNI nor AVX2 still answers no. Five
    /// admission sites in four tests asserted a bare `Some(true)`, which held on every
    /// dev box (Apple, and the i5 with no GFNI) and failed on
    /// `linux-tests` shard 2/4 and three `windows-unit` shards on
    /// 10 Sep 2026 (runs 34528779701 and 34543810022) whenever nextest's
    /// hash partition put the test on a GFNI runner - GitHub's fleet
    /// mixes Zen 3 (no GFNI) with Ice Lake (GFNI), so the same shard
    /// flapped red and green between pushes with no code change, and
    /// the two docs-only runs in between skipped the suite entirely and
    /// read as green. The exactness assertions in those tests stay
    /// unconditional on purpose: where the kernel is refused they prove
    /// the fallback arm instead, which is the arm a GFNI user runs.
    fn kernel_on_this_box() -> Option<bool> {
        Some(gf16::scale_available())
    }

    /// The stage-1 verdict now carries its REASON, and the reason is
    /// what `parfast --fast` prints (TODO 340). A bare "it fell back"
    /// is what shipped for weeks and told nobody anything.
    ///
    /// Read as a pure query rather than through the process-global
    /// latch: `cargo test --lib` puts this whole crate in one process,
    /// so a test that reset the latch and read it back would race every
    /// other test here that runs a joint solve. The latch's own wiring
    /// is proved end to end in parfast's `fast_switch` integration
    /// test, where one test drives one repair in one binary.
    #[test]
    fn a_declining_stripe_names_which_condition_it_tripped() {
        let k = ks(1024);
        let joint = ForneyPlan::prepare_impl(&k, 2, true, true)
            .expect("distinct bases")
            .with_kernel_forced();

        // A block whose STRIPE is not a whole number of 16-word units.
        // THE COMMONEST DECLINE, and it is the SET's fault rather than
        // the host's: PAR2 allows any multiple of 4 and
        // `create::block_size` searches in steps of four, so about seven
        // sets in eight that parfast writes itself land here. 130 words
        // is a 260-byte block, which is what parfast's own integration
        // test writes for exactly this reason.
        //
        // These are BLOCK widths narrow enough that the stripe is the
        // whole block: a wide block takes a 16-aligned stripe and only
        // its short LAST stripe is ragged, which `run_joint` pads rather
        // than declining (`a_short_last_stripe_is_padded_and_still_exact`).
        for words in [130usize, 258, 66] {
            assert_eq!(
                joint.joint_decline(words),
                Some(Some(JointDecline::BlockAlignment)),
                "words={words}"
            );
        }

        // A width that IS aligned declines only for a host reason, and
        // on this box there is exactly one candidate - so the two
        // answers are the two states `gf16::scale_available` can be in,
        // and the test says which it expects rather than accepting
        // either.
        let want = if gf16::scale_available() {
            None
        } else {
            Some(JointDecline::NoScaleKernel)
        };
        assert_eq!(joint.joint_decline(512), Some(want));

        // The DIRECT (non-mixed) stage-1 plan is the fourth reason, and
        // it is neither the set's fault nor the host's.
        //
        // THE ORDER DECIDES THIS CELL, and asserting `NotMixed` flat
        // took main red on 34563445: `joint_stripe` asks the HOST's
        // question (`scale_available`) before the plan's SHAPE, so on a
        // box with no vector scale both conditions hold and
        // `NoScaleKernel` wins. This assertion therefore has to read the
        // same two-state fact the aligned-width one above does. It
        // passed on the dev Mac and on half the GitHub runners: the
        // x86-64 pool mixes Zen 3 (no GFNI) with Ice Lake (GFNI), so an
        // assertion keyed on the host flaps by luck of the draw - the
        // exact class `gf16::gfni_rowop_armed`'s docstring records for
        // 10 Sep, walked into again here. Never assert an arm this
        // module chooses without saying which host you are on.
        let direct = ForneyPlan::prepare_impl(&ks(128), 1, false, true).expect("distinct bases");
        let got = direct
            .joint_decline(64)
            .expect("the plan carries a joint arm")
            .expect("a direct stage-1 plan must decline");
        // The two GEOMETRY reasons are excluded on every host, and
        // separately, so a budget or alignment surprise reports itself
        // instead of arriving disguised as the host question below.
        assert_ne!(
            got,
            JointDecline::BlockAlignment,
            "64 words is 16-aligned; this cell is not about geometry"
        );
        assert_ne!(
            got,
            JointDecline::KernelArena,
            "the kernel's arena fits at m=128, words=64; if this ever fires the \
             budget moved and the rest of this assertion is meaningless"
        );
        // What is left is the host's question and then the plan's shape,
        // in that order.
        if gf16::scale_available() {
            assert_eq!(
                got,
                JointDecline::NotMixed,
                "with a vector scale kernel present, a direct plan declines on its SHAPE"
            );
        } else {
            assert_eq!(
                got,
                JointDecline::NoScaleKernel,
                "with no vector scale kernel the HOST's question is reached first, \
                 and both conditions being true is exactly why the order matters"
            );
        }

        // And an unarmed plan has no decision to report at all, which is
        // not the same thing as a decline - a CLI that conflated them
        // would print a reason for a repair that never asked.
        let unarmed = ForneyPlan::prepare_impl(&ks(64), 1, true, false).expect("distinct bases");
        assert_eq!(unarmed.joint_decline(512), None);
    }

    /// The latch keeps the WEAKER answer: a repair whose solves
    /// disagree fell back, and the line a user reads must say so. And
    /// the first decline wins over a later one, so the reason reported
    /// is the one the repair actually hit first.
    ///
    /// Drives the recording functions directly. It does NOT read the
    /// global back afterwards - see the note above - so what it proves
    /// is the ORDERING rule, over a local copy of the same state
    /// machine the functions implement.
    #[test]
    fn a_decline_outranks_a_take_and_the_first_decline_wins() {
        // The rule, stated once, as `note_joint_taken` and
        // `note_joint_declined` implement it against `JOINT_REACH`.
        fn step(cur: u8, ev: Option<JointDecline>) -> u8 {
            match ev {
                None if cur == 0 => 1,
                None => cur,
                Some(d) if cur < 2 => decline_code(d),
                Some(_) => cur,
            }
        }
        let b = decline_code(JointDecline::BlockAlignment);
        let n = decline_code(JointDecline::NoScaleKernel);
        assert_ne!(b, n, "the five reasons must have distinct codes");
        // take, then decline: the decline wins.
        assert_eq!(step(step(0, None), Some(JointDecline::BlockAlignment)), b);
        // decline, then take: the decline stands.
        assert_eq!(step(step(0, Some(JointDecline::BlockAlignment)), None), b);
        // two declines: the FIRST stands.
        assert_eq!(
            step(
                step(0, Some(JointDecline::BlockAlignment)),
                Some(JointDecline::NoScaleKernel)
            ),
            b
        );
        // and every code round-trips through the public reader.
        for d in [
            JointDecline::NotForney,
            JointDecline::BlockAlignment,
            JointDecline::NoScaleKernel,
            JointDecline::KernelArena,
            JointDecline::NotMixed,
            JointDecline::Held,
        ] {
            assert_eq!(reach_of(decline_code(d)), JointReach::Declined(d));
        }
        assert_eq!(reach_of(0), JointReach::Untouched);
        assert_eq!(reach_of(1), JointReach::Taken);
    }

    /// The local per-stripe T buffers together can never exceed the ONE
    /// full `m x block` T the shipped arm allocates, because the number
    /// of concurrent workers is capped by the number of stripes.
    /// Arithmetic, so it holds on a box with any core count.
    #[test]
    fn local_t_never_exceeds_the_full_t() {
        for m in [1usize, 1000, 8192, 32768] {
            for words in [16usize, 512, 2048, 32768] {
                for w in [16usize, 32, 128, 512] {
                    let w = w.min(words);
                    let stripes = words.div_ceil(w).max(1);
                    for cpus in [1usize, 4, 12, 32, 128] {
                        let workers = cpus.min(stripes);
                        assert!(
                            m * w * workers <= m * words,
                            "m={m} words={words} w={w} cpus={cpus}"
                        );
                    }
                }
            }
        }
    }
}
