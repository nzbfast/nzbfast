//! The whole inherent impl of [`Reconstructor`] - construction, the feed
//! and fold paths, and both finish flavours - moved out of par2repair.rs
//! bodily under the size gate (TODO 106). A child module of the defining
//! module, so the struct's private fields and par2repair.rs's private
//! helpers and `use` bindings stay in scope exactly as they were inline.
//! The struct itself, [`Feeder`], and the report types stay in the parent
//! beside their docs.

use super::linalg::{ArenaPool, fold_batches, invert_vandermonde};
use super::*;

/// The one place the repair's dimension is spelled as a refusal, so the
/// two callers cannot drift in wording or in which side of the boundary
/// they admit. [`Reconstructor::new_with_path`] is the backstop every
/// route funnels through; `repair_dir_set_inner` calls it EARLIER, once
/// its missing set is final, because the backstop sits behind
/// `load_selected_recovery`, which pins one `block_size` buffer per
/// missing block - `m x block_size` bytes read and held only to be
/// dropped when the backstop refuses.
///
/// THE DIMENSION CAP IS PER-ARM, because the two solves have different
/// costs and only one of them is what [`MAX_REPAIR_DIM`] was sized
/// against. THE MEMORY CAP IS NOT: see below.
///
/// - The DENSE product keeps it. Its doc comment prices exactly that
///   arm - `~4*m^2` bytes of matrix and inverse, `O(m^3)` scalar setup -
///   and at `m = 32,768` that really is hours and gigabytes, so a
///   crafted set must not reach it.
/// - FORNEY does not build an `m x m` inverse at all: its plan is
///   `O(m * GT2)` tables (tens of MB at these sizes) and its solve is
///   an evaluation, not a cubic. Capping it at 8,192 refused an
///   ORDINARY workflow: deleting every data file and repairing from
///   over-100% parity makes `m` EVERY input block of the set, so a
///   10 GiB set at 1 MiB blocks (10,240) was refused outright while
///   par2cmdline-turbo completed it. Measured 6 Sep 2026 on an M3 Ultra
///   over 1.1 GB at 110% redundancy with every data file deleted:
///   m = 6,554 repaired in 1.69 s against turbo's 11.88 s (21/21 files
///   byte-identical), and m = 16,385 was refused here where turbo took
///   42.9 s - it repairs in 2.3 s now.
///
/// So Forney's ceiling is MEMORY, which is the honest bound for an arm
/// whose time is linear in `m`: the back-substitution's peak window is
/// the rebuilt output plus one other `m x block_size` buffer (the
/// syndrome rows, or the Hankel product `T`), as
/// [`Reconstructor::finish_blocks_reported`] documents where it charges
/// them. A set that would need more than the budget is refused with a
/// message about MEMORY rather than about a matrix, because that is
/// what actually stops it.
///
/// THAT WINDOW IS ARM-INDEPENDENT, and until 8 Sep 2026 only Forney was
/// charged for it. The dense arm returned `Ok(())` off its matrix cap
/// alone and then allocated the SAME two `m x block_size` buffers, plus
/// its `~4*m^2` matrix on top - so the cheaper-in-memory arm was the
/// only one priced. The cliff was one block wide: on a GFNI x86 box
/// with 8 GiB (budget 2 GiB) at 1 MiB blocks, `m = 2,048` reached
/// Forney and was refused at 4 GiB of window while `m = 2,047` took the
/// dense arm and allocated the same 4 GiB unchecked. Full erasure of a
/// real 948-block set at 5.376 MB slices asks for a 10.19 GB window: an
/// aarch64 build refused it under 38 GiB of RAM and an x86 build
/// allocated it on an 8 GiB NAS - the same shape, refused on one arch
/// and OOM-killed on the other. The window test now runs for BOTH arms.
///
/// ORDER MATTERS, and it is dimension-first on purpose - but the only
/// dimension left here is [`MAX_INPUT_SLICES`], the PAR2 format's own
/// ceiling. This block used to say that a set over [`MAX_REPAIR_DIM`]
/// on the dense arm keeps reporting the matrix cap; `454141ce0f`
/// removed that refusal the same day, on the measurement above, and the
/// sentence outlived it. Past the old flat cap the dense arm is now
/// admitted when its footprint fits and refused with `SolveBudget` when
/// it does not, which is the whole point of bounding it by memory:
/// raising the budget DOES admit it, so `SolveBudget`'s advice to retry
/// with a bigger one is true. `MAX_REPAIR_DIM` itself is still live as
/// the `is_long()` forecast threshold in `survey.rs`, which is a
/// different question - how long a repair will take, not whether it is
/// allowed.
pub(super) fn check_repair_dim(m: usize, block_size: usize) -> Result<(), RepairError> {
    check_repair_dim_within(m, block_size, solve_window_budget() as u64)
}

/// [`check_repair_dim`] with the budget handed in, so the tests can
/// drive both sides of the memory boundary without touching a
/// process-global environment - the same seam `ntt_default_budget` and
/// `ForneyPlan::prepare_with_dft` use, and for the same reason.
pub(super) fn check_repair_dim_within(
    m: usize,
    block_size: usize,
    budget: u64,
) -> Result<(), RepairError> {
    // No arm survives a set declaring more missing blocks than PAR2
    // permits inputs, whatever the memory. This is the outer guard the
    // DoS argument really rests on.
    if m > MAX_INPUT_SLICES {
        return Err(RepairError::Malformed(format!(
            "{m} missing blocks exceeds the PAR2 input-slice ceiling ({MAX_INPUT_SLICES})"
        )));
    }
    // BOTH ARMS. Each holds the syndrome rows and the rebuilt output at
    // once - `2 * m * block_size` - and the DENSE arm pays its `~4*m^2`
    // matrix and inverse on top, which is why its bound is its own.
    //
    // THE DENSE ARM WAS BOUNDED BY A FLAT DIMENSION UNTIL 8 SEP 2026 and
    // is bounded by MEMORY now, which is the change `2ff1ceb436` already
    // made for Forney and declined to make here. Three of the four
    // premises behind the flat 8,192 turned out to be false when the arm
    // was finally timed from ABOVE it (the cap was what had prevented
    // that measurement; `NZBFAST_REPAIR_DIM` is the knob that took it):
    //
    //  - it prices `O(m^3)` SINGLE-THREADED ops, but `linalg::invert`
    //    dispatches to `invert_parallel` at `m >= PAR_INVERT_MIN` (128);
    //  - it predicts "hours", and the measurement is 67.8 s at
    //    m = 10,000 and 224 s at m = 16,384 on an M1 Ultra;
    //  - it offers par2cmdline as the fallback, and at m = 10,000
    //    par2cmdline-turbo 1.5.0 takes 84.9 s - SLOWER than the arm we
    //    were refusing to run. The refusal sent the user to a worse tool.
    //
    // The DoS premise is weak too: `have` counts only recovery slices
    // that pass their packet MD5, so a crafted set cannot DECLARE a large
    // m - it must supply that much VALID parity. Reaching the ceiling
    // costs an attacker ~4.3 GB of genuine recovery data to buy ~30
    // minutes of CPU, which is a poor amplification ratio.
    //
    // Memory is the premise that held, so memory is the bound. What this
    // admits at the top end is honest and worth stating: the largest
    // UNSTRUCTURED m that can exist is ~32,766 (repairing m blocks needs
    // m usable recovery slices, and if all 32,768 survive the exponents
    // are consecutive and the set is not unstructured at all), which is
    // ~4.3 GB of matrix plus ~4.3 GB of window and about half an hour.
    // par2cmdline-turbo takes about the same, being cubic as well. Slow
    // is not the same as refused.
    let window = (m as u64)
        .saturating_mul(block_size as u64)
        .saturating_mul(2);
    let need = if super::forney::backsub_gate(m) {
        window
    } else {
        window.saturating_add(dense_matrix_bytes(m))
    };
    if need > budget {
        return Err(RepairError::SolveBudget {
            m,
            block_size,
            needed_mb: need / (1 << 20),
            budget_mb: budget / (1 << 20),
        });
    }
    Ok(())
}

/// How a solve too big for the memory budget is CUT UP rather than
/// refused.
///
/// Every operation in PAR2 reconstruction is elementwise along the byte
/// axis inside a block: word offset `k` of an output block depends only
/// on word offset `k` of the syndromes, which depend only on word offset
/// `k` of the sources. `forney::evaluate` already leans on this - it
/// runs `per_stripe` over disjoint column stripes on separate threads
/// with no cross-talk. So a repair over a byte range `[c0, c1)` of every
/// block IS a repair at `block_size = c1 - c0`, and the whole solve
/// decomposes along that axis with NO redundant arithmetic: the same GF
/// operations happen, in a different order.
///
/// What a slab costs is I/O. The sources have to be swept once per
/// slab, because a pass can only accumulate the syndrome bytes it has
/// room to hold. What it does NOT cost is the expensive per-`m` work -
/// the dense inverse (`O(m^3)`, 260 MB at m = 8,064), the Forney plan
/// tables, the exponent logs - all of which depend on `m` and the
/// exponents and not on the block width, so they are built once and
/// reused across every slab.
///
/// THE PLAN IS ALWAYS THE FEWEST SLABS THAT FIT, because every slab past
/// the first is another sweep of the payload. One slab is the ordinary
/// case and is the untouched fast path: `slabs == 1` reproduces the
/// pre-slab code exactly, byte for byte and read for read.
///
/// WHY THIS REPLACES A REFUSAL. Until 9 Sep 2026 a solve whose window
/// was over budget returned `SolveBudget` and repaired NOTHING, which on
/// the 65 GiB / 50% publication set was an exit-5 refusal that a harness
/// discarding stderr published as a 12.3 s win against
/// par2cmdline-turbo's 1413.6 s repair OF THE SAME SET. The set was fine
/// and the machine had 128 GiB; the window was 32.0076 GiB against a
/// budget of exactly 32 GiB, missed by 0.024%. A downloader that hands
/// back "this machine cannot" while the reference tool completes is
/// wrong whatever the number is, so the number stopped being a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlabPlan {
    /// Sweeps of the payload this solve will take. 1 is the fast path.
    pub slabs: usize,
    /// Bytes of each block one sweep carries. Always even (the solve
    /// works in `u16` words) and never zero.
    pub width: usize,
}

impl SlabPlan {
    /// The byte range slab `i` covers, clamped to the block.
    pub fn range(&self, i: usize, block_size: usize) -> std::ops::Range<usize> {
        let c0 = (i * self.width).min(block_size);
        let c1 = (c0 + self.width).min(block_size);
        c0..c1
    }
}

/// The fewest slabs whose peak window fits `budget`.
///
/// The window a slab of width `w` needs is `2 * m * w` - the same two
/// `m x block_size` buffers [`check_repair_dim_within`] prices, measured
/// at the slab's width instead of the block's. The dense arm's `~4*m^2`
/// matrix is NOT divided by slabbing (it depends on `m` alone) so it is
/// charged once, off the top, before the width is chosen.
///
/// This function does not fail. It cannot usefully: at the narrowest
/// legal width - one `u16` word, 2 bytes - the window is `4 * m`, which
/// is 128 KB at the PAR2 ceiling of 32,768 inputs and fits any budget a
/// process can be given. A caller that wants to know whether a repair
/// will be SLOW asks how many slabs came back, and that is a fact to
/// report, not a door to close.
pub(crate) fn plan_slabs(m: usize, block_size: usize, budget: u64) -> SlabPlan {
    // A degenerate solve has no window to cut; one slab, and the callers'
    // `m == 0` arms never look at the width.
    if m == 0 || block_size == 0 {
        return SlabPlan {
            slabs: 1,
            width: block_size.max(2),
        };
    }
    // The per-`m` term the slab cannot shrink. Taken off the budget
    // first so the width is chosen against what is actually left; on
    // the Forney arm it is zero.
    let fixed = if super::forney::backsub_gate(m) {
        0
    } else {
        dense_matrix_bytes(m)
    };
    let spendable = budget.saturating_sub(fixed);
    // `2 * m * w <= spendable`, the widest even `w`, never wider than
    // the block and never narrower than one word.
    let per_slab = |w: u64| w.saturating_mul(2).saturating_mul(m as u64);
    let widest = {
        let w = (spendable / (2 * m as u64).max(1)).min(block_size as u64) & !1;
        (w as usize).max(2)
    };
    // The pass COUNT is what costs a sweep of the payload, so it is
    // settled first - and then the width is spread back out evenly over
    // that many passes. Taking `widest` directly would leave the last
    // slab holding the remainder, and the remainder can be tiny: at
    // m = 8,064 and a 32 GiB budget the widest legal slab is 504 bytes
    // short of the whole 2,130,944-byte block, so the greedy cut buys a
    // SECOND FULL SWEEP of a 65 GiB payload to carry 504 bytes. Two
    // balanced slabs of 1,065,472 read the same bytes in the same two
    // passes with half the working set each.
    let mut slabs = block_size.div_ceil(widest).max(1);
    let width = loop {
        let w = round_up_even(block_size.div_ceil(slabs));
        // Rounding up to a whole word can push a balanced slab back over
        // the budget by one word. Widening the cut by one pass always
        // resolves it, and cannot loop: `slabs` reaches `block_size / 2`
        // at the latest, where `w` is 2 and `per_slab` is `4 * m`.
        if per_slab(w as u64) <= spendable || w <= 2 {
            break w;
        }
        slabs += 1;
    };
    SlabPlan {
        slabs: block_size.div_ceil(width),
        width,
    }
}

fn round_up_even(n: usize) -> usize {
    n.saturating_add(n & 1)
}

/// The plan a DRIVER runs under: [`plan_slabs`] against this process's
/// real budget, unless a test is forcing one.
///
/// The forcing seam is thread-local and test-only, and exists for the
/// same reason [`check_repair_dim_within`] takes its budget as an
/// argument: the differential that proves a slabbed repair is
/// byte-identical to a whole-width one has to drive BOTH over the same
/// small fixture, and moving the process-wide budget to do that would
/// be visible to every other test sharing the process (`cargo test`
/// puts a whole crate in one).
pub(crate) fn plan_slabs_for(m: usize, block_size: usize) -> SlabPlan {
    #[cfg(test)]
    if let Some(width) = forced_slab_width() {
        // Even, always: the solve works in u16 words and the
        // Reconstructor refuses an odd block size outright.
        let width = (width.min(round_up_even(block_size)) & !1).max(2);
        return SlabPlan {
            slabs: block_size.div_ceil(width).max(1),
            width,
        };
    }
    plan_slabs(m, block_size, solve_window_budget() as u64)
}

/// Where a driver that must hold the whole rebuilt output should keep
/// it - see `RebuiltStore`, which is the thing being chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Staging {
    /// One slab: the solve's buffers are the output, nothing is copied.
    Whole,
    /// Slabbed, output assembled in memory. No I/O.
    Assembled,
    /// Slabbed, output staged on disk. One extra write and read of the
    /// rebuilt payload.
    Spill,
}

/// A slab plan together with where the output will live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SolvePlan {
    pub slabs: SlabPlan,
    pub staging: Staging,
}

/// Plan a solve for a driver that consumes the WHOLE rebuilt output
/// (the disk driver's patch phase does; the mapped driver writes each
/// slab straight out and uses [`plan_slabs`] alone).
///
/// The tiers are tried in order of speed, and the first that fits wins:
///
/// 1. `Whole` - the window fits, one slab, nothing changes. The
///    overwhelming majority of repairs land here and pay nothing for
///    any of this.
/// 2. `Assembled` - the output fits beside a slabbed window. Costs the
///    extra sweeps of the payload the slabs imply and NO I/O beyond
///    them, so it is preferred over spilling whenever it fits.
/// 3. `Spill` - the output does not fit at all. The window alone is
///    slabbed to the budget and the output is staged on disk.
///
/// Tier 3 is what makes the whole thing unconditional: it needs only
/// `4 * m` bytes of window at the narrowest slab, so there is no set
/// this can fail to plan, and a repair is never refused for memory.
pub(crate) fn plan_solve(m: usize, block_size: usize, budget: u64) -> SolvePlan {
    let whole = plan_slabs(m, block_size, budget);
    if whole.slabs == 1 {
        return SolvePlan {
            slabs: whole,
            staging: Staging::Whole,
        };
    }
    // Room for the assembled output beside its window? `plan_slabs` is
    // asked against what is left AFTER the output, and is only taken if
    // that left enough to be worth having - a plan whose slabs are
    // narrower than the spilled one's is a plan that buys memory it does
    // not need with sweeps it cannot afford.
    let resident = (m as u64).saturating_mul(block_size as u64);
    let left = budget.saturating_sub(resident);
    if left > 0 {
        let assembled = plan_slabs(m, block_size, left);
        if assembled.slabs <= whole.slabs {
            return SolvePlan {
                slabs: assembled,
                staging: Staging::Assembled,
            };
        }
    }
    SolvePlan {
        slabs: whole,
        staging: Staging::Spill,
    }
}

/// [`plan_solve`] against this process's real budget, with the same
/// test-forcing seam [`plan_slabs_for`] honours.
pub(crate) fn plan_solve_for(m: usize, block_size: usize) -> SolvePlan {
    #[cfg(test)]
    if forced_slab_width().is_some() {
        let slabs = plan_slabs_for(m, block_size);
        let staging = if slabs.slabs == 1 {
            Staging::Whole
        } else if forced_spill() {
            Staging::Spill
        } else {
            Staging::Assembled
        };
        return SolvePlan { slabs, staging };
    }
    plan_solve(m, block_size, solve_window_budget() as u64)
}

#[cfg(test)]
thread_local! {
    static FORCED_SPILL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn forced_spill() -> bool {
    FORCED_SPILL.with(|f| f.get())
}

/// Force a slabbed solve on THIS THREAD to stage its output on disk,
/// so the spill arm is exercised without a fixture too big for memory.
#[cfg(test)]
pub(crate) struct ForcedSpill(bool);

#[cfg(test)]
impl ForcedSpill {
    pub(crate) fn on() -> Self {
        Self(FORCED_SPILL.with(|f| f.replace(true)))
    }
}

#[cfg(test)]
impl Drop for ForcedSpill {
    fn drop(&mut self) {
        FORCED_SPILL.with(|f| f.set(self.0));
    }
}

#[cfg(test)]
thread_local! {
    static FORCED_SLAB_WIDTH: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn forced_slab_width() -> Option<usize> {
    FORCED_SLAB_WIDTH.with(|f| f.get())
}

/// Force every driver on THIS THREAD to cut its solve into slabs of
/// `width` bytes until the guard drops. Test-only.
#[cfg(test)]
pub(crate) struct ForcedSlabWidth(Option<usize>);

#[cfg(test)]
impl ForcedSlabWidth {
    pub(crate) fn set(width: usize) -> Self {
        Self(FORCED_SLAB_WIDTH.with(|f| f.replace(Some(width))))
    }
}

#[cfg(test)]
impl Drop for ForcedSlabWidth {
    fn drop(&mut self) {
        FORCED_SLAB_WIDTH.with(|f| f.set(self.0));
    }
}

/// The dense arm's matrix and its inverse, in bytes: two `m x m`
/// `Vec<Vec<u16>>`, so `2 * m^2 * 2`. This is the term that makes the
/// dense arm's memory bound its own rather than the window both arms
/// share, and it is what `MAX_REPAIR_DIM`'s doc block prices as
/// `~4*m^2`.
fn dense_matrix_bytes(m: usize) -> u64 {
    (m as u64).saturating_mul(m as u64).saturating_mul(4)
}

/// The DENSE arm's bound, asked again once the arm is known.
///
/// [`check_repair_dim`] runs before the recovery exponents are examined,
/// so it cannot tell a set that will find structure from one that will
/// fall through to Gauss-Jordan; it charges the Forney bound whenever
/// `backsub_gate` says Forney. This is the same check for a set that
/// turned out to be unstructured after all, and it is the only place the
/// `~4*m^2` matrix is charged against a real block size.
pub(super) fn check_repair_dim_dense(
    m: usize,
    block_size: usize,
    control: &control::RepairControl,
) -> Result<(), RepairError> {
    // The UNATTENDED ceiling comes first, because it is a policy about
    // who is watching and not a statement about what fits. See
    // [`set_unattended_unstructured_ceiling`].
    //
    // A CALLER THAT IS WATCHING IS EXEMPT, since 12 Sep 2026. The
    // ceiling's own doc named the day in-fold progress and a cancel the
    // fold honours arrived as the day to raise it; this is that, asked
    // per REPAIR rather than set per process, because "unattended" was
    // never really a property of the process - it was a property of
    // whether anyone could see this repair and stop it, and now that is
    // a thing a caller can answer for itself. `RepairControl::
    // is_attended` carries the argument for needing both halves.
    //
    // THE DAEMON NOW TAKES THIS DOOR, since 12 Sep 2026
    // (`daemon-infold-progress-cancel`, and the nested extraction
    // ladder the same day under `nested-repair-infold-control`): its
    // download repair, its late-set pass and each nested layer's PAR2
    // pass all pass a control built from the job's own `SideCancel`, so
    // they arrive here attended and the ceiling it sets in
    // `serve/mod.rs` does not apply to them. That ceiling is still set,
    // and still right, for the two daemon paths that pass nothing -
    // `get::settle::noset`'s obfuscated arm and the MAPPED in-stream
    // driver - and for whatever is written next without looking. The
    // census is on `set_unattended_unstructured_ceiling`. Raising the
    // NUMBER instead would have uncapped those too, for nothing.
    unattended_refusal_for(m, super::linalg::unattended_unstructured_ceiling(), control)?;
    check_repair_dim_dense_within(m, block_size, solve_window_budget() as u64)
}

/// The ceiling arm of [`check_repair_dim_dense`], as a pure function of
/// its three inputs.
///
/// THE SEAM EXISTS SO THE EXEMPTION CAN BE TESTED AT ALL. The ceiling
/// itself is a process-global policy and `cargo test` puts a whole crate
/// in one process, so a test that stored to it would be visible to every
/// test after it - which is exactly why [`unattended_refusal`] below is
/// already a pure function rather than a reader of the global. This is
/// the same trick one level up, because the CONTROL is the half that
/// decides and neither the global nor `unattended_refusal` knows about
/// it. Pinned by
/// `a_controlled_caller_is_exempt_from_the_unattended_ceiling`.
pub(super) fn unattended_refusal_for(
    m: usize,
    ceiling: usize,
    control: &control::RepairControl,
) -> Result<(), RepairError> {
    // BOTH HALVES OR NEITHER: progress with no cancel leaves a watcher
    // who cannot act, and a cancel with no progress leaves one who does
    // not know when to. `RepairControl::is_attended` carries the
    // argument.
    if control.is_attended() {
        return Ok(());
    }
    unattended_refusal(m, ceiling)
}

/// The unattended ceiling as a pure function of `m`, so a test can drive
/// both sides of it WITHOUT storing to the process-wide policy - a
/// `cargo test` run puts a whole crate in one process, and a test that
/// mutated the ceiling would be visible to every test after it.
/// Zero is "no ceiling", the default.
pub(super) fn unattended_refusal(m: usize, ceiling: usize) -> Result<(), RepairError> {
    if ceiling != 0 && m > ceiling {
        return Err(RepairError::Malformed(format!(
            "{m} missing blocks with unstructured recovery exponents is past this \
             process's unattended ceiling ({ceiling}) - the repair is possible but slow \
             (roughly cubic in the missing count) and this caller passes no progress or \
             cancel control, so nobody could see it run or stop it. It is left to a \
             foreground tool, or to a caller that supplies a `RepairControl`"
        )));
    }
    Ok(())
}

/// [`check_repair_dim_dense`] with the budget handed in, the same seam
/// [`check_repair_dim_within`] is and for the same reason: the tests
/// drive both sides of the boundary without touching a process-global
/// environment.
pub(super) fn check_repair_dim_dense_within(
    m: usize,
    block_size: usize,
    budget: u64,
) -> Result<(), RepairError> {
    if m > MAX_INPUT_SLICES {
        return Err(RepairError::Malformed(format!(
            "{m} missing blocks exceeds the PAR2 input-slice ceiling ({MAX_INPUT_SLICES})"
        )));
    }
    let need = (m as u64)
        .saturating_mul(block_size as u64)
        .saturating_mul(2)
        .saturating_add(dense_matrix_bytes(m));
    if need > budget {
        return Err(RepairError::SolveBudget {
            m,
            block_size,
            needed_mb: need / (1 << 20),
            budget_mb: budget / (1 << 20),
        });
    }
    Ok(())
}

/// What the back-substitution's peak window may occupy: the same
/// quarter-of-the-OOM-line derivation the NTT retention budget uses
/// (`fastpar::ntt_default_budget` - a flat ceiling, then a quarter of
/// physical RAM and of any cgroup limit), because it answers the same
/// question about the same process. `NZBFAST_REPAIR_SOLVE_BUDGET`
/// overrides it absolutely - a raw byte count (unchanged, so the
/// published research sweep's numeric values still work) or a
/// KiB/MiB/GiB (or bare K/M/G, KB/MB/GB) suffixed value. Absolutely
/// over the DERIVATION, that is: the one bound an override cannot lift
/// is the address space, so a figure past it is clamped by
/// [`fit_addressable`] rather than honoured into a guaranteed OOM. On
/// every 64-bit target that clamp is a no-op and "absolutely" is
/// literal.
///
/// A value that parses as neither form is loud, never silent: a bare
/// `.parse().ok()` here once swallowed `16GiB` outright and ran the
/// DEFAULT budget with
/// no sign anything was wrong, which cost a measurement its own
/// disproof - the published repro for that finding used a raw byte
/// count for exactly this reason, and still does.
pub(super) fn solve_window_budget() -> usize {
    match std::env::var("NZBFAST_REPAIR_SOLVE_BUDGET") {
        Ok(v) => match parse_budget_bytes(&v) {
            Some(bytes) => bytes,
            None => {
                warn!(
                    target: "repair-timing",
                    "NZBFAST_REPAIR_SOLVE_BUDGET={v:?} is not a byte count (use a raw integer, \
                     or a K/M/G or KiB/MiB/GiB suffixed value) - falling back to the default \
                     budget rather than silently misreading it"
                );
                default_solve_window_budget()
            }
        },
        Err(_) => default_solve_window_budget(),
    }
}

fn default_solve_window_budget() -> usize {
    // Clamped to the PUBLISHED process budget for the same reason
    // `ntt_budget_within_published` is: a host-derived window is the
    // wrong bound for a process that was handed a smaller limit, and
    // until 8 Sep 2026 only the creator honoured it.
    //
    // Nothing about `NZBFAST_REPAIR_SOLVE_BUDGET` is consulted here, and
    // that is the fix rather than an omission. Every route into this
    // function is one where that variable produced NO usable number -
    // unset, or set to something `parse_budget_bytes` refused and
    // `solve_window_budget` warned about - so what is being clamped is
    // always the host default, never a value the user chose. The first
    // spelling asked `var_os` inside the clamp, which made a typo count
    // as an override and wave the whole host budget through unclamped:
    // exactly the misreading the warning above promises not to do.
    super::fastpar::clamp_to_published(super::fastpar::ntt_default_budget(
        crate::mem::physical_ram(),
        crate::mem::cgroup_mem_limit(),
    ))
}

/// The largest budget this target can hold, whatever the string asked
/// for. Asked of [`crate::mem::MemBudget::max_total`] rather than
/// spelled here,
/// because that is where the ceiling is decided and a second copy
/// cannot follow it: `u64::MAX` on a 64-bit target, so every clamp
/// below is a no-op there, and the 32-bit address-space ceiling
/// otherwise.
///
/// A budget past the address space is neither a typo nor a wrap. It is
/// a figure written for a bigger machine - one config file is routinely
/// deployed to a workstation and to a 32-bit NAS - and the honest
/// reading of it is "as much as this target allows". The two answers it
/// used to get were both wrong and were not even the same wrong:
///
/// - the raw spelling was REFUSED, because `str::parse::<usize>` fails
///   out of range and no suffix then matches, so a well-formed byte
///   count reached the caller as `None` and was warned about as though
///   it were a typo;
/// - the suffixed spelling of the same size SATURATED to `usize::MAX`
///   through the `as` cast below, which as a budget means no bound at
///   all - so a value asking for MORE memory turned the repair's memory
///   guard OFF, on the one target that guard exists for.
///
/// Clamping answers both, identically, and never unbinds the guard.
///
/// It also brings the two routes into [`solve_window_budget`] to the
/// same ceiling. The default route already had one - `ntt_default_budget`
/// holds its flat ceiling to what a 32-bit process can actually spend,
/// for the reason spelled out there - and the override route, the only
/// one a person can reach, had none at all.
fn fit_addressable(bytes: u64) -> usize {
    usize::try_from(bytes.min(crate::mem::MemBudget::max_total())).unwrap_or(usize::MAX)
}

/// Parse a byte count: a bare integer (raw bytes, the form every rig and
/// the published research sweep already uses), or a number followed by
/// `K`/`M`/`G` or `KiB`/`MiB`/`GiB` (also `KB`/`MB`/`GB`, same binary
/// multiplier - this is a memory ceiling sized against RAM, not a
/// network rate, and every other budget in this family is already
/// binary). Case-insensitive; a space between the number and the suffix
/// is allowed. `None` means the string is neither, and the caller must
/// not treat that as zero or as "unset".
///
/// Every well-formed byte count returns `Some`, on every target: what
/// the string said, [`fit_addressable`]-clamped to what this one can
/// hold. That is what keeps `None` meaning what the warning in
/// [`solve_window_budget`] tells the user it means.
fn parse_budget_bytes(raw: &str) -> Option<usize> {
    let s = raw.trim();
    if let Ok(bytes) = s.parse::<u64>() {
        return Some(fit_addressable(bytes));
    }
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        // A decimal integer too long for even a `u64` is still a byte
        // count, and still one no target can hold. Reading it as a
        // rejection would put a well-formed value down the "not a byte
        // count" path on EVERY target, which is the misdiagnosis above
        // with the width argument removed.
        return Some(fit_addressable(u64::MAX));
    }
    let lower = s.to_ascii_lowercase();
    let (num, mult) = [
        ("gib", 1u64 << 30),
        ("mib", 1 << 20),
        ("kib", 1 << 10),
        ("gb", 1 << 30),
        ("mb", 1 << 20),
        ("kb", 1 << 10),
        ("g", 1 << 30),
        ("m", 1 << 20),
        ("k", 1 << 10),
    ]
    .into_iter()
    .find_map(|(suffix, mult)| lower.strip_suffix(suffix).map(|n| (n, mult)))?;
    let n: f64 = num.trim().parse().ok()?;
    // `as` from `f64` saturates rather than wrapping, so the product is
    // a ceiling and never a small number; the clamp then brings it to
    // what this target can hold, exactly as the raw arm above.
    (n >= 0.0).then(|| fit_addressable((n * mult as f64) as u64))
}

// Experimental internal result owner: keep the original allocation and its
// alignment until drop. Borrowing its byte view never transfers ownership.
pub(super) enum RebuiltBlock {
    Words(Vec<u16>),
    Bytes(Vec<u8>),
}
impl std::ops::Deref for RebuiltBlock {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Words(w) => gf16::words_as_bytes(w),
            Self::Bytes(b) => b,
        }
    }
}

impl Reconstructor {
    /// `recovery` payloads are only READ here (widened into the u16
    /// syndrome rows before the fold worker spawns), so borrowed slices
    /// into a caller's corpus are as good as owned buffers - the mapped
    /// repair path selects `(u32, &[u8])` pairs to avoid cloning ~m x
    /// block_size of payload it would immediately discard.
    pub fn new<D: AsRef<[u8]>>(
        block_size: usize,
        n_inputs: usize,
        missing: &[usize],
        recovery: &[(u32, D)],
    ) -> Result<Reconstructor, RepairError> {
        Self::new_with_path(block_size, n_inputs, missing, recovery, SyndromePath::Auto)
    }

    #[doc(hidden)]
    pub fn new_with_path<D: AsRef<[u8]>>(
        block_size: usize,
        n_inputs: usize,
        missing: &[usize],
        recovery: &[(u32, D)],
        path: SyndromePath,
    ) -> Result<Reconstructor, RepairError> {
        Reconstructor::new_controlled(
            block_size,
            n_inputs,
            missing,
            recovery,
            path,
            &control::RepairControl::default(),
        )
    }

    /// [`new_with_path`](Self::new_with_path) that reports the SOLVE's
    /// progress and can be called off inside it.
    ///
    /// Two of a repair's slowest stretches are behind this constructor
    /// and neither is reachable from the driver: the Gauss-Jordan
    /// inverse built below (`O(m^3)`, and the whole of the unstructured
    /// arm's setup), and the dense back-substitution in
    /// [`finish_blocks_reported`](Self::finish_blocks_reported). Both
    /// take the control from here. See `par2repair::control`.
    ///
    /// The FOLD WORKER does not: it is spawned below and outlives this
    /// call, and the fold's own progress is reported by the FEEDERS,
    /// which is both the earlier fact and the one a user is waiting on
    /// (bytes read off disk, not bytes XORed after they arrived).
    pub fn new_controlled<D: AsRef<[u8]>>(
        block_size: usize,
        n_inputs: usize,
        missing: &[usize],
        recovery: &[(u32, D)],
        path: SyndromePath,
        control: &control::RepairControl,
    ) -> Result<Reconstructor, RepairError> {
        if block_size == 0 || !block_size.is_multiple_of(2) {
            return Err(RepairError::Malformed(format!(
                "block size {block_size} not a positive multiple of 2"
            )));
        }
        if recovery.len() != missing.len() {
            return Err(RepairError::Malformed(format!(
                "{} recovery slices for {} missing blocks - caller must pass exactly one per",
                recovery.len(),
                missing.len()
            )));
        }
        // The backstop every repair route funnels through - the mapped
        // driver, the disk driver and any direct caller. The disk driver
        // ALSO checks it earlier (see `check_repair_dim`); this one is
        // what makes the cap a property of the engine rather than of
        // whoever remembered to ask.
        check_repair_dim(missing.len(), block_size)?;
        let base_logs = input_base_logs(n_inputs)?;
        if let Some(&j) = missing.iter().find(|&&j| j >= n_inputs) {
            return Err(RepairError::Malformed(format!(
                "missing index {j} out of range ({n_inputs} inputs)"
            )));
        }
        let t_inv = std::time::Instant::now();
        // Consecutive exponents (both repair paths pick the SMALLEST
        // available, so this is the norm - gaps mean recovery packets
        // were themselves lost) make A a Vandermonde in the bases times
        // a diagonal, whose explicit inverse costs O(m²) instead of
        // Gauss-Jordan's O(m³).
        //
        // Past `forney::backsub_gate` the same factorization is used a
        // second way: the solve runs through two transforms and the
        // explicit inverse is never built at all (m² entries - 134 MB
        // and 62 ms at the repair cap), so this is a fork, not a stage.
        let consecutive = !recovery.is_empty() && recovery.windows(2).all(|w| w[1].0 == w[0].0 + 1);
        let ks: Vec<u32> = missing.iter().map(|&j| base_logs[j]).collect();
        let progression = if !consecutive
            && std::env::var("NZBFAST_RS_PROGRESSIONS").ok().as_deref() != Some("0")
        {
            progression_parameters(&ks, &recovery.iter().map(|r| r.0).collect::<Vec<_>>())
        } else {
            None
        };
        let (solve_ks, solve_e0) = progression
            .as_ref()
            .map(|(k, e)| (k.as_slice(), *e))
            .unwrap_or((&ks, recovery.first().map_or(0, |r| r.0)));
        let structured = if consecutive || progression.is_some() {
            if forney::backsub_gate(missing.len()) {
                ForneyPlan::prepare(solve_ks, solve_e0).map(BackSub::Forney)
            } else {
                invert_vandermonde(solve_ks, solve_e0).map(BackSub::Dense)
            }
        } else {
            None
        };
        let (label, solve) = match structured {
            Some(s @ BackSub::Forney(_)) => ("forney", s),
            Some(s) => {
                // `--fast` arms the joint solve INSIDE the Forney
                // route; a repair that takes any other route never
                // offers it a decision to make, and a CLI that only
                // watched `joint_stripe` would report nothing at all.
                // Recorded here because this is the one place the fork
                // is taken (TODO 340).
                forney::note_joint_not_forney();
                ("vandermonde", s)
            }
            None => {
                // NO STRUCTURE TO EXPLOIT, so this is Gauss-Jordan on an
                // explicit m x m: the `O(m^3)` setup and `~4*m^2` bytes.
                // `check_repair_dim` admitted this m against the FORNEY
                // arm's bound - it runs before the exponents are examined
                // and cannot know the set would land here - so the DENSE
                // arm's own bound is re-asserted at the point the arm is
                // actually chosen. Reached when the recovery exponents
                // are neither consecutive nor a relabelable progression,
                // which means recovery packets were themselves lost.
                //
                // Since 8 Sep 2026 that bound is MEMORY rather than a
                // flat dimension, so this re-assert changed with it: the
                // check is the same one `check_repair_dim_within` makes,
                // asked again now that the arm is known. A set that fits
                // is repaired, slowly if it must be; only one that does
                // not fit is refused, and it is refused naming memory.
                // See the block on `check_repair_dim` for the four
                // premises the old flat cap rested on and which of them
                // survived being measured.
                forney::note_joint_not_forney();
                check_repair_dim_dense(missing.len(), block_size, control)?;
                // The `O(m^3)` elimination below is minutes at the sizes
                // that make the unstructured arm worth warning about, so
                // it reports per matrix COLUMN and is cancellable there.
                control.begin(control::RepairPhase::Solve, missing.len() as u64);
                // A[r][c] = g_{missing[c]}^{e_r} = 2^{k·e mod 65535}
                let a: Vec<Vec<u16>> = recovery
                    .iter()
                    .map(|(e, _)| {
                        missing
                            .iter()
                            .map(|&j| gf16::pow2(base_logs[j] as u64 * *e as u64))
                            .collect()
                    })
                    .collect();
                let inv = invert_controlled(a, control)?;
                control.finish(control::RepairPhase::Solve);
                ("gauss-jordan", BackSub::Dense(inv))
            }
        };
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            info!(
                target: "repair-timing",
                "back-substitution setup ({}x{0}, {label}): {:.2?}",
                missing.len(),
                t_inv.elapsed()
            );
        }
        let words = block_size / 2;
        // Memory-floor gauge: the syndrome rows are the repair's one
        // whole-run allocation - m x block_size, live from here to the
        // back-substitution (610 MB on the first leg that motivated
        // this: 165 recovery blocks x 3.7 MB).
        let syn_charge = crate::memgauge::Charge::new(
            crate::memgauge::Sub::RepairWork,
            (recovery.len() * block_size) as u64,
        );
        let mut exponents = Vec::with_capacity(recovery.len());
        let mut syndromes = Vec::with_capacity(recovery.len());
        for (e, data) in recovery {
            let data = data.as_ref();
            if data.len() != block_size {
                return Err(RepairError::Malformed(format!(
                    "recovery slice (exponent {e}) is {} bytes, block size is {block_size}",
                    data.len()
                )));
            }
            let mut w = vec![0u16; words];
            for (dw, s) in w.iter_mut().zip(data.as_chunks::<2>().0) {
                *dw = u16::from_le_bytes(*s);
            }
            exponents.push(*e);
            syndromes.push(w);
        }
        // EXPERIMENTAL NTT dispatch (merged NTT plan Stage 2): when the
        // repair shape clears the measured gates, the worker RETAINS the
        // fed batches - the batch arenas ARE the resident source corpus -
        // and finish() runs the output-pruned NTT instead of having
        // folded along the way. Filling the retention budget does NOT
        // revert to the fold (it did until 2 Sep 2026): the worker
        // transforms what it holds as one WINDOW, releases it and starts
        // over, which is what lets a corpus bigger than the budget take
        // the transform at all - and, since 5 Sep 2026, what the
        // dispatcher admits such a corpus ON (`ntt_retention_admits`).
        // The fold remains the unconditional fallback, per window: a
        // window whose plan cannot be built folds instead.
        let ntt_budget =
            resolve_syndrome_path(path, block_size, n_inputs, missing.len(), &exponents);
        let worker_exponents = exponents.clone();
        // Capacity 8 (was 1, then 4 - aa3fb30fd deepened it alongside
        // BATCH_BYTES 32 -> 64 MiB): with M2c.2's parallel readers each
        // sender carries a BATCH_BYTES/N-sized batch, so a slightly deeper
        // queue keeps disks busy while a batch folds without growing
        // worst-case in-flight memory beyond the old single-feeder cap.
        let (tx, rx) = std::sync::mpsc::sync_channel::<FeedBatch>(8);
        // Arenas in circulation at steady state: up to eight feeders'
        // assembly batches plus the channel's eight, and the fold
        // worker's merged set is those same batches - so 16 keeps every
        // arena of a streaming repair alive from first fold to finish.
        let pool = ArenaPool::new(if ArenaPool::enabled() { 16 } else { 0 });
        let worker_pool = pool.clone();
        let fold_trace = std::env::var_os("NZBFAST_FOLD_TRACE").is_some();
        // The one thing the worker takes from the control: the cancel.
        // It reports nothing - the FEEDERS report the fold, because
        // bytes read off disk is both the earlier fact and the one a
        // user is waiting on - but it must stop DOING the work, or a
        // cancelled repair still pays for every XOR that was already
        // queued.
        let worker_control = control.clone();
        let worker = std::thread::spawn(move || {
            let exponents = worker_exponents;
            let pool = worker_pool;
            let mut syndromes = syndromes;
            let mut retained: Vec<FeedBatch> = Vec::new();
            let mut retained_bytes = 0usize;
            let ntt_budget = ntt_budget;
            let mut ntt_windows = 0usize;
            let mut ntt_window_used = false;
            let mut ntt_window_present = 0usize;
            let mut waited = std::time::Duration::ZERO;
            let mut folded = std::time::Duration::ZERO;
            let mut calls = 0usize;
            let mut bytes = 0usize;
            loop {
                let t_w = std::time::Instant::now();
                let Ok(first) = rx.recv() else { break };
                waited += t_w.elapsed();
                if worker_control.cancelled() {
                    // DRAIN, never break: a feeder blocked on the full
                    // channel would wait for a receiver that had gone,
                    // and the reader scope would never join. The
                    // syndromes this abandons are read by nobody - the
                    // driver refuses before `finish` and again before
                    // the patch.
                    pool.put(first);
                    continue;
                }
                if let Some(budget) = ntt_budget {
                    // Charge the pad the NTT will need for this batch as
                    // well as the batch itself: every SHORT slice (a file
                    // tail) is copied into a zero-padded whole block in
                    // `ntt_syndromes`, so a set of many small files - all
                    // tails - costs up to a second copy of the corpus
                    // that the fed bytes alone never show.
                    let pad = first
                        .slices
                        .iter()
                        .filter(|&&(_, _, len)| len != 0 && len != block_size)
                        .count()
                        * block_size;
                    retained_bytes += first.arena.len() + pad;
                    retained.push(first);
                    if retained_bytes > budget {
                        // Budget full: this window of the corpus is
                        // transformed NOW and released, and retention
                        // starts over. The transform is linear in its
                        // inputs, so windows XOR into the same syndrome
                        // rows exactly as one transform over the whole
                        // corpus would - which is what admits a set
                        // larger than the budget (a 23 GB member) to the
                        // NTT at all; until 2 Sep 2026 an overflow folded
                        // what it held and streamed the rest on the fold.
                        // A window the plan cannot build (duplicate feeds,
                        // out-of-range logs) folds instead, per window.
                        let t_w = std::time::Instant::now();
                        let (used, n) = ntt_syndromes_into(
                            block_size,
                            &exponents,
                            &mut syndromes,
                            &retained,
                            NttFault::None,
                        );
                        ntt_window_present += n;
                        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                            info!(
                                target: "repair-timing",
                                "ntt window ({retained_bytes} bytes, {} slices, {}): {:.2?}",
                                retained.iter().map(|b| b.slices.len()).sum::<usize>(),
                                if used { "transformed" } else { "folded" },
                                t_w.elapsed()
                            );
                        }
                        ntt_windows += 1;
                        ntt_window_used |= used;
                        retained.clear();
                        retained_bytes = 0;
                    }
                    continue;
                }
                let mut merged = vec![first];
                // Coalesce whatever the feeders have already queued: the
                // tiled fold walks EVERY syndrome row once per call, so N
                // small batches cost N row sweeps where one merged batch
                // costs one. Parallel feeders split BATCH_BYTES across
                // handles for memory control (M2c.2), which shrank fold
                // units 8x - measured as a repair regression on
                // small-L3 parts.
                //
                // The bound is channel capacity PLUS live senders, not
                // capacity alone: each try_recv that frees a buffered slot
                // immediately unblocks a sender, whose message lands in the
                // buffer and is drained on the next iteration. With
                // sync_channel(8) and up to 8 feeders that is up to 16
                // batches merged, not 9. Harmless at typical block sizes
                // (~128 MB vs the 64 MB BATCH_BYTES design cap), but a feeder
                // batch is one whole block when block_size is large - a set
                // with 16 MB blocks holds ~256 MB in the merged batch. The
                // fold is XOR accumulation, so merging and reordering are
                // exact; this is a memory bound, not a correctness one.
                while let Ok(more) = rx.try_recv() {
                    merged.push(more);
                }
                let t_f = std::time::Instant::now();
                fold_batches(&exponents, &mut syndromes, &merged);
                folded += t_f.elapsed();
                calls += 1;
                let mb: usize = merged.iter().map(|b| b.arena.len()).sum();
                bytes += mb;
                if fold_trace {
                    warn!(
                        target: "fold-trace",
                        "call {calls}: {} srcs, {:.1} MB, {:.2?}",
                        merged.iter().map(|b| b.slices.len()).sum::<usize>(),
                        mb as f64 / 1e6,
                        t_f.elapsed()
                    );
                }
                for b in merged {
                    pool.put(b);
                }
            }
            if fold_trace {
                info!(
                    target: "fold-trace",
                    "total: {calls} calls, {:.1} MB, fold {:.2?}, recv-wait {:.2?}",
                    bytes as f64 / 1e6,
                    folded,
                    waited
                );
            }
            (
                syndromes,
                retained,
                ntt_windows,
                ntt_window_used,
                ntt_window_present,
            )
        });
        Ok(Reconstructor {
            control: control.clone(),
            block_size,
            base_logs: std::sync::Arc::new(base_logs),
            missing: missing.to_vec(),
            exponents,
            solve,
            tx: Some(tx),
            worker: Some(worker),
            batch: pool.take(BATCH_BYTES),
            batch_capacity: BATCH_BYTES,
            pool,
            backsub_arm: label,
            ntt_selected: ntt_budget.is_some(),
            syn_charge,
            ntt_fault: match path {
                SyndromePath::NttForceCorrupt(_) => NttFault::Corrupt,
                SyndromePath::NttForcePanic(_) => NttFault::Panic,
                _ => NttFault::None,
            },
        })
    }

    /// Which back-substitution arm this construction chose:
    /// `"forney"`, `"vandermonde"` or `"gauss-jordan"`. The first two
    /// need the recovery exponents to be consecutive (or a relabelable
    /// arithmetic progression); the third is the `O(m^3)` setup and the
    /// dense product a gapped set falls onto, and is the one arm
    /// `MAX_REPAIR_DIM` still refuses past. Not part of the supported
    /// API surface - it exists so a test can assert which arm a given
    /// exponent set reaches, which no other observable reports.
    #[doc(hidden)]
    pub fn backsub_arm(&self) -> &'static str {
        self.backsub_arm
    }

    /// Whether the dispatcher selected the NTT path at construction.
    /// Not part of the supported API surface.
    #[doc(hidden)]
    pub fn ntt_selected(&self) -> bool {
        self.ntt_selected
    }

    /// Accumulate one present input slice (borrowed - it is packed into
    /// the batch arena, so callers can reuse one read buffer instead of
    /// allocating per slice). `data` may be shorter than the block size
    /// (file tail) - the zero padding contributes nothing.
    pub fn feed(&mut self, input_index: usize, data: &[u8]) {
        debug_assert!(
            !self.missing.contains(&input_index),
            "fed a slice declared missing"
        );
        debug_assert!(data.len() <= self.block_size);
        if self.batch.arena.len() + data.len() > self.batch_capacity {
            self.flush();
        }
        self.batch.push(self.base_logs[input_index], data);
        if self.batch.arena.len() >= self.batch_capacity {
            self.flush();
        }
    }

    /// Hand the pending batch to the fold worker. Blocks only when a
    /// batch is already queued behind the one being folded.
    fn flush(&mut self) {
        if self.batch.slices.is_empty() {
            return;
        }
        let batch = std::mem::replace(&mut self.batch, self.pool.take(self.batch_capacity));
        // The worker outlives every sender; send can't fail.
        let _ = self
            .tx
            .as_ref()
            .expect("finish() not yet called")
            .send(batch);
    }

    /// A shareable feed handle for parallel producers (M2c.2). Each
    /// reader thread takes its own Feeder; batches from every handle
    /// funnel into the same fold worker, so slices may arrive in any
    /// interleaving (the syndrome fold is order-free XOR accumulation).
    /// `max_batch` bounds the handle's assembly buffer - callers split
    /// [`BATCH_BYTES`] across handles so total in-flight memory stays
    /// what the single-feeder design used. Drop every Feeder (they
    /// flush on drop) BEFORE calling [`Self::finish`], or finish blocks
    /// on the channel.
    pub fn feeder(&self, max_batch: usize) -> Feeder {
        let max_batch = max_batch.max(1 << 20);
        Feeder {
            tx: self.tx.as_ref().expect("finish() not yet called").clone(),
            base_logs: self.base_logs.clone(),
            batch: self.pool.take(max_batch),
            pool: self.pool.clone(),
            max_batch,
        }
    }

    /// Hand a batch assembled elsewhere (the verify pass's retained
    /// blocks, `retain::RetainedCorpus`) to the fold worker as it is:
    /// its slices carry their base logs already. Blocks like a feeder's
    /// flush when the channel is full.
    pub(super) fn send_batch(&self, batch: FeedBatch) {
        if batch.slices.is_empty() {
            return;
        }
        let _ = self
            .tx
            .as_ref()
            .expect("finish() not yet called")
            .send(batch);
    }

    /// Solve: returns the reconstructed slices (full `block_size` bytes
    /// each, zero-padded past any file tail) in `missing` order.
    pub fn finish(self) -> Vec<Vec<u8>> {
        self.finish_reported().0
    }

    /// [`finish`](Self::finish), also reporting what the syndrome pass
    /// did - the repair drivers' verify-failure fallback needs to know
    /// whether the NTT actually computed the syndromes. Not part of the
    /// supported API surface.
    #[doc(hidden)]
    pub fn finish_reported(self) -> (Vec<Vec<u8>>, SyndromeReport) {
        let (out, report) = self.finish_blocks_reported(false);
        (
            out.into_iter()
                .map(|b| match b {
                    RebuiltBlock::Bytes(v) => v,
                    RebuiltBlock::Words(w) => gf16::words_as_bytes(&w).to_vec(),
                })
                .collect(),
            report,
        )
    }

    pub(super) fn finish_owned_reported(self) -> (Vec<RebuiltBlock>, SyndromeReport) {
        // Keep the solved rows as words and write their byte views, ON by
        // default since 5 Sep 2026 (the review's lead): it removes the consuming
        // full-output copy, byte-identical, and measures i5-10600KF repair
        // 101 1.60-1.64 -> 1.55-1.63 s, heavy 2.88-2.96 -> 2.87-2.94, M1
        // heavy -3.3..-3.9% (review), M3 Ultra flat. `NZBFAST_REPAIR_KEEP_WORDS=0`
        // is the copying arm, the A/B.
        let keep_words = !std::env::var_os("NZBFAST_REPAIR_KEEP_WORDS").is_some_and(|v| v == "0");
        self.finish_blocks_reported(keep_words)
    }

    fn finish_blocks_reported(mut self, keep_words: bool) -> (Vec<RebuiltBlock>, SyndromeReport) {
        self.flush();
        drop(self.tx.take());
        let (mut syndromes, retained, ntt_windows, ntt_window_used, ntt_window_present) = self
            .worker
            .take()
            .expect("finish() called once")
            .join()
            .expect("syndrome fold worker panicked");
        let mut report = SyndromeReport {
            ntt_used: ntt_window_used,
            // Every window's slices, not the tail's - see the field's
            // docs. The windows the worker closed mid-flight are already
            // counted; the tail below is the last of them.
            n_present: ntt_window_present,
            windows: ntt_windows,
        };
        if !retained.is_empty() {
            let (used, n) = self.ntt_syndromes(&mut syndromes, &retained);
            report.ntt_used |= used;
            report.n_present += n;
            report.windows += 1;
        }
        if ntt_windows > 0 && std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            info!(
                target: "repair-timing",
                "ntt: {ntt_windows} window(s) transformed before the tail, tail {}",
                if retained.is_empty() { "empty" } else { "transformed above" }
            );
        }
        // The retained corpus is dead the moment the syndromes are
        // computed, and it is the single biggest live allocation on the
        // NTT path - it must not still be resident while the m x
        // block_size output below is allocated and then copied out. The
        // worker arenas are already gone (dropped when the scoped
        // threads exited), so this window is the real NTT peak.
        drop(retained);
        let m = self.missing.len();
        let words = self.block_size / 2;
        // Memory-floor gauge: the rebuilt output blocks coexist with one
        // other m x block buffer through the back-substitution - the
        // syndrome rows on the dense path, the Hankel product T on the
        // transform one - and together they are the repair's true peak
        // window. Charged inside each arm rather than before the match
        // because the two arms allocate in a different ORDER, and a
        // gauge that charged `out` up front would read the transform
        // path as holding three buffers where it holds two. Released at
        // return (the caller writes the blocks out and drops them).
        let charge =
            |n: usize| crate::memgauge::Charge::new(crate::memgauge::Sub::RepairWork, n as u64);
        let t_bs = std::time::Instant::now();
        // The solve's own phase. The dense arm below re-sizes it from
        // the fold's unit grid, which is finer; the transform arms never
        // do, so for them this pair is the whole report - a bar that
        // moves to the solve and lands, over a stretch measured in
        // seconds. Honest either way, and better than the bar that sat
        // still through all of it before 12 Sep 2026.
        self.control
            .begin(control::RepairPhase::Solve, m.max(1) as u64);
        let (label, out, _out_charge) = match &self.solve {
            _ if m == 0 => ("empty", Vec::new(), charge(0)),
            BackSub::Dense(inverse) => {
                // Same tiled multi-accumulate as the syndrome fold: the
                // m x m back-substitution re-reads every syndrome row per
                // output row, so untiled it costs m x the syndrome set in
                // RAM sweeps (and used to run scalar on top). Shares the
                // row x column scheduler too - with one missing block this
                // solve is a single row, so rows alone would run it on one
                // thread.
                let mut out: Vec<Vec<u16>> = vec![vec![0u16; words]; m];
                let out_charge = charge(m * words * 2);
                let syn_bytes: Vec<&[u8]> =
                    syndromes.iter().map(|s| gf16::words_as_bytes(s)).collect();
                // The one arm of the four that is worth watching: the
                // m x m product is the unstructured repair's second
                // multi-minute stretch, after the inverse. The Forney
                // arms below are seconds at every size the format
                // allows - `RepairForecast::est_secs` declines to
                // estimate them for exactly that reason - so they are
                // bracketed rather than instrumented, and instrumenting
                // them would mean editing `forney.rs`, which a
                // measurement round holds.
                fold_parallel_controlled(
                    &mut out,
                    &syn_bytes,
                    &|j, i| inverse[j][i],
                    Some(crate::memgauge::Sub::RepairWork),
                    &self.control,
                );
                ("dense", out, out_charge)
            }
            // The JOINT arm (`joint_gate`: the default on aarch64,
            // `--fast` or `NZBFAST_FORNEY_JOINT=1` elsewhere).
            // The syndromes are MOVED into the solve and come back as
            // the rebuilt blocks in the same allocation, so this arm
            // holds ONE m x block buffer where the two below hold two.
            // `has_joint` is false unless the switch armed the plan, so
            // with it unset this arm never matches and the code below
            // is reached exactly as before.
            BackSub::Forney(plan) if plan.has_joint() => {
                let syn = std::mem::take(&mut syndromes);
                let Ok(out) = plan.solve_joint(syn) else {
                    unreachable!("the arm guard is `has_joint()`")
                };
                // The syndrome charge and the output charge are the SAME
                // BYTES here - the same allocation, renamed. The
                // syndrome charge is therefore held across the whole
                // solve (which is this arm's peak) and handed over only
                // now, so the floor never reads the peak window as
                // empty. Taking the output charge before releasing the
                // syndrome one over-states by one buffer for the length
                // of two atomic adds, which is the safe direction for a
                // floor.
                let out_charge = charge(m * words * 2);
                self.syn_charge.release_all();
                ("forney-joint", out, out_charge)
            }
            BackSub::Forney(plan) => {
                // Ordered so the peak is the SAME two m x block buffers
                // the dense product holds: T is built while the
                // syndromes are live, the syndromes go, and only then
                // does the output exist.
                let t = plan.hankel(&syndromes, words);
                let mut t_charge = charge(m * words * 2);
                syndromes.clear();
                syndromes.shrink_to_fit();
                self.syn_charge.release_all();
                let mut out: Vec<Vec<u16>> = vec![vec![0u16; words]; m];
                let out_charge = charge(m * words * 2);
                plan.evaluate(&t, &mut out);
                drop(t);
                t_charge.release_all();
                ("forney", out, out_charge)
            }
        };
        self.control.finish(control::RepairPhase::Solve);
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            info!(target: "repair-timing", "back-substitution ({label}): {:.2?}", t_bs.elapsed());
        }
        // Same reason as the retained corpus above: the syndrome rows
        // are consumed by the back-substitution and nothing past it
        // reads them, so they must not stay live across the byte
        // conversion below.
        //
        // TWO COPIES OF ONE BLOCK, not of the output. The conversion is
        // `out.into_iter()`, which CONSUMES each `Vec<u16>` as it builds
        // that block's `Vec<u8>`, so the live total stays around
        // `m * block` throughout and only one block is ever doubled. It
        // churns `m * block` of allocation against `m * block` of frees;
        // it does not hold the whole output twice.
        //
        // The distinction is not pedantry. This comment previously said
        // "which briefly holds two copies of the output", and on
        // 10 Sep 2026 that sentence was read as the explanation for a
        // repair's peak RSS - a 19.3 GB claim that went into a research
        // document and was relayed to two other lanes before anyone
        // checked the ownership against the words
        // (`research/JOINT-FORNEY-INTEGRATION-2026-09-10.md` section
        // 6.8). What actually sets the peak is still open.
        drop(syndromes);
        self.syn_charge.release_all();
        // On little-endian a word slice already IS its PAR2 byte view,
        // so this is a memcpy per block rather than a per-byte iterator
        // chain over the whole repaired payload.
        let out = out
            .into_iter()
            .map(|w| {
                if keep_words {
                    RebuiltBlock::Words(w)
                } else {
                    RebuiltBlock::Bytes(gf16::words_as_bytes(&w).to_vec())
                }
            })
            .collect();
        (out, report)
    }

    /// EXPERIMENTAL NTT syndrome pass over the retained source corpus
    /// (merged NTT plan Stage 2). XORs each present slice's contribution
    /// into the recovery-initialized syndrome rows via the output-pruned
    /// transform; any shape the plan cannot represent (duplicate feeds,
    /// out-of-range logs) falls back to folding the retained batches -
    /// bit-identical semantics either way, since the fold is pure XOR
    /// accumulation. Returns (ntt actually ran, present slices fed).
    fn ntt_syndromes(&self, syndromes: &mut [Vec<u16>], retained: &[FeedBatch]) -> (bool, usize) {
        ntt_syndromes_into(
            self.block_size,
            &self.exponents,
            syndromes,
            retained,
            self.ntt_fault,
        )
    }
}

/// The transform over one RETAINED WINDOW of the corpus, XORed into the
/// syndrome rows - the body of [`Reconstructor::ntt_syndromes`], as a
/// free function so the fold worker can run it per window as the
/// retention budget fills (see the worker loop). Linear in its inputs,
/// so windows compose by XOR. Returns (transform ran, slices fed).
fn ntt_syndromes_into(
    block_size: usize,
    exponents: &[u32],
    syndromes: &mut [Vec<u16>],
    retained: &[FeedBatch],
    fault: NttFault,
) -> (bool, usize) {
    {
        let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
        let t0 = std::time::Instant::now();
        let words = block_size / 2;
        // Slice table: full-length slices point into the batch arenas
        // (the resident corpus); short tails are copied once into a
        // zero-padded side arena so every stripe pointer is readable.
        let mut table: Vec<*const u8> = Vec::new();
        let mut present: Vec<(u32, crate::par2ntt::SrcId)> = Vec::new();
        // Counted up front rather than grown block by block: a set of
        // many small files is nearly all tails, so the doubling Vec
        // would hold up to twice the final pad during a reallocation -
        // and that transient is exactly what the retention backstop's
        // pad charge is trying to bound.
        let n_short = retained
            .iter()
            .flat_map(|b| b.slices.iter())
            .filter(|&&(_, _, len)| len != 0 && len != block_size)
            .count();
        let mut pad_arena: Vec<u8> = Vec::new();
        pad_arena.reserve_exact(n_short * block_size);
        // Memory-floor gauge: the zero-padded tail arena - up to a
        // second copy of the corpus on a many-small-files set (the same
        // transient the retention backstop's pad term prices).
        let _pad_charge = crate::memgauge::Charge::new(
            crate::memgauge::Sub::RepairWork,
            (n_short * block_size) as u64,
        );
        let mut pads: Vec<(usize, usize, usize)> = Vec::new(); // (table idx, pad off, len)
        pads.reserve_exact(n_short);
        for b in retained {
            for &(log, off, len) in &b.slices {
                if len == 0 {
                    continue;
                }
                let id = table.len() as crate::par2ntt::SrcId;
                if len == block_size {
                    table.push(b.arena[off..off + len].as_ptr());
                } else {
                    let poff = pad_arena.len();
                    pad_arena.resize(poff + block_size, 0);
                    pads.push((table.len(), poff, len));
                    table.push(std::ptr::null()); // patched below
                }
                present.push((log, id));
            }
        }
        // Second pass for the tail copies: pad_arena has its final size
        // now, so pointers taken from it below are stable.
        {
            let mut pi = 0usize;
            let mut ti = 0usize;
            for b in retained {
                for &(_, off, len) in &b.slices {
                    if len == 0 {
                        continue;
                    }
                    if len != block_size {
                        let (idx, poff, plen) = pads[pi];
                        debug_assert_eq!(idx, ti);
                        pad_arena[poff..poff + plen].copy_from_slice(&b.arena[off..off + len]);
                        table[ti] = pad_arena[poff..poff + block_size].as_ptr();
                        pi += 1;
                    }
                    ti += 1;
                }
            }
            debug_assert_eq!(pi, pads.len());
        }
        let needed = exponents.iter().copied().max().unwrap_or(0) as usize + 1;
        // Private range experiment. Keep the original dispatcher and its
        // conservative prefix memory admission; compact only the actual plan.
        // The range plan (outputs from the smallest selected exponent, not
        // from 0) is the default since 5 Sep 2026: for consecutive sets
        // from 0 it IS the prefix plan, and for a set that starts high it
        // computes only the rows asked for (i5-10600KF, 1,500 rows at
        // exponents 8,192+: compact 1.20 s against the forced prefix
        // plan's 1.44 and the fold's 2.97; the review's range validation).
        // `NZBFAST_REPAIR_NTT_RANGE=0` keeps the prefix plan (the A/B arm).
        let first = if std::env::var("NZBFAST_REPAIR_NTT_RANGE").ok().as_deref() != Some("0") {
            exponents.iter().copied().min().unwrap_or(0) as usize
        } else {
            0
        };
        // A unit-stride progression e0+d*r becomes consecutive in bases
        // k*d and offset e0/d modulo 65535. Relabel, never rescale bytes.
        // Same for the progression relabel: default on, `=0` off.
        let compact = if std::env::var("NZBFAST_REPAIR_NTT_PROGRESSION")
            .ok()
            .as_deref()
            != Some("0")
        {
            let keys: Vec<u32> = present.iter().map(|p| p.0).collect();
            progression_parameters(&keys, exponents).filter(|(_, e)| {
                (*e as usize)
                    .checked_add(exponents.len())
                    .is_some_and(|end| end <= crate::par2ntt::N)
            })
        } else {
            None
        };
        let relabeled: Vec<_> = compact
            .as_ref()
            .map(|(keys, _)| present.iter().zip(keys).map(|(p, &k)| (k, p.1)).collect())
            .unwrap_or_default();
        let (plan_input, plan_first, plan_count) = if let Some((_, offset)) = &compact {
            (relabeled.as_slice(), *offset as usize, exponents.len())
        } else {
            (present.as_slice(), first, needed - first)
        };
        let plan = match crate::par2ntt::FlatPlan::build_range(plan_input, plan_first, plan_count) {
            Ok(p) => p,
            Err(why) => {
                if timing {
                    info!(target: "repair-timing", "ntt plan unbuildable ({why}) - fold fallback");
                }
                fold_batches(exponents, syndromes, retained);
                return (false, 0);
            }
        };
        // Stripe width and worker count: W=512 (1 KiB stripes) holds the
        // measured wall inside the scratch budget (Stage 1 doc); workers
        // pull stripes from a shared queue and XOR their rows into
        // disjoint column ranges of the shared syndrome rows. ONE rule,
        // `fastpar::ntt_stripe_geometry`: this site carried its own copy
        // until 5 Sep 2026, so the thread rule the creator ran was not
        // the one the repair ran (the i5-10600KF's heavy repair stayed on
        // six threads after the shared rule went to twelve; round K).
        let (w, threads) = super::fastpar::ntt_stripe_geometry(block_size);
        let stripes = words.div_ceil(w);
        struct SynPtrs(Vec<*mut u16>, Vec<usize>);
        // SAFETY: raw pointers into the syndrome rows; workers XOR
        // into disjoint column ranges only (one stripe per atomic
        // fetch_add claim, per the stripe/worker comment above), so
        // sharing them across the scope's threads races nothing.
        unsafe impl Send for SynPtrs {}
        // SAFETY: as above, writes are confined to the claiming
        // worker's stripe columns.
        unsafe impl Sync for SynPtrs {}
        let syn = SynPtrs(
            syndromes.iter_mut().map(|s| s.as_mut_ptr()).collect(),
            if compact.is_some() {
                (0..exponents.len()).collect()
            } else {
                exponents.iter().map(|&e| e as usize - first).collect()
            },
        );
        struct SrcTable(Vec<*const u8>);
        // SAFETY: read-only pointers into the retained batch arenas
        // and the finalized pad arena (stable per the second-pass
        // comment above); neither is mutated while the scope's
        // workers read them.
        unsafe impl Send for SrcTable {}
        // SAFETY: as above, all access through these pointers is
        // read-only.
        unsafe impl Sync for SrcTable {}
        let table = SrcTable(table);
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            let plan = &plan;
            let syn = &syn;
            let table = &table;
            let next = &next;
            for _ in 0..threads {
                s.spawn(move || {
                    let mut scratch = plan.new_scratch(w);
                    let mut out = vec![0u16; plan.needed * w];
                    loop {
                        let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if c >= stripes {
                            break;
                        }
                        let len = w.min(words - c * w);
                        // SAFETY: every table entry is readable for
                        // block_size bytes (full slices point into the
                        // batch arenas, tails into the zero-padded
                        // side arena, per the slice-table comment
                        // above), and c*w*2 + 2*len <= block_size
                        // because len = w.min(words - c*w), satisfying
                        // transform's src_of contract.
                        let src_of = |id: crate::par2ntt::SrcId| unsafe {
                            table.0[id as usize].add(c * w * 2)
                        };
                        plan.transform(&src_of, len, &mut scratch, &mut out);
                        for (j, &e) in syn.1.iter().enumerate() {
                            // SAFETY: syndrome row j is words long and
                            // c*w + len <= words, so the range is in
                            // bounds; stripe c belongs to this worker
                            // alone (claimed via the atomic queue), so
                            // no other thread touches these columns.
                            let row =
                                unsafe { std::slice::from_raw_parts_mut(syn.0[j].add(c * w), len) };
                            for (d, s) in row.iter_mut().zip(&out[e * len..(e + 1) * len]) {
                                *d ^= *s;
                            }
                        }
                    }
                });
            }
        });
        if std::env::var_os("NZBFAST_NTT_PROFILE").is_some() {
            let r = crate::par2ntt::FlatPlan::profile_report();
            info!(
                target: "repair-timing",
                "ntt profile (inclusive thread-seconds): depth0 {:.2} depth1 {:.2} depth2 {:.2} leaves {:.2}",
                r[0], r[1], r[2], r[3]
            );
        }
        if timing {
            info!(
                target: "repair-timing",
                "ntt syndromes (m={}, needed={}, n={}, W={w}, threads={threads}): {:.2?}",
                exponents.len(),
                plan.needed,
                present.len(),
                t0.elapsed()
            );
        }
        match fault {
            NttFault::None => {}
            // TEST ONLY (NttForceCorrupt): a single flipped word models
            // an NTT correctness bug; whole-file verification must catch
            // it and the fold retry must rescue the repair.
            NttFault::Corrupt => syndromes[0][0] ^= 1,
            // TEST ONLY (NttForcePanic): the retry must survive a panic
            // on the NTT path.
            NttFault::Panic => panic!("injected NTT panic (NttForcePanic test path)"),
        }
        (true, present.len())
    }
}

/// An arithmetic progression e_r=e0+d*r gives the same Vandermonde
/// matrix in transformed bases h_c=g_c^d. If d is a unit modulo 65535,
/// e0'=e0/d modulo 65535 preserves the original diagonal g_c^e0.
/// Non-unit strides and irregular/duplicate exponents keep the old fallback.
pub(super) fn progression_parameters(ks: &[u32], exps: &[u32]) -> Option<(Vec<u32>, u32)> {
    if exps.len() < 2 {
        return None;
    }
    let step = exps[1].checked_sub(exps[0])?;
    if step == 0
        || !exps
            .windows(2)
            .all(|w| w[1].checked_sub(w[0]) == Some(step))
    {
        return None;
    }
    let modulus = gf16::ORDER as i64;
    let (mut a, mut b) = (step as i64 % modulus, modulus);
    let (mut x, mut y) = (1i64, 0i64);
    while b != 0 {
        let q = a / b;
        (a, b) = (b, a - q * b);
        (x, y) = (y, x - q * y);
    }
    if a != 1 {
        return None;
    }
    let inverse = x.rem_euclid(modulus) as u64;
    let transformed = ks
        .iter()
        .map(|&k| (k as u64 * step as u64 % gf16::ORDER as u64) as u32)
        .collect();
    let offset = (exps[0] as u64 * inverse % gf16::ORDER as u64) as u32;
    Some((transformed, offset))
}

#[cfg(test)]
mod progression_tests {
    use super::*;
    #[test]
    fn progression_inverse_matches_general_inverse() {
        for n in [2usize, 5, 17, 64] {
            for step in [2u32, 4, 7, 8, 16, 31, 65536] {
                for start in [0u32, 3, 65530, 1000000] {
                    let logs = input_base_logs(n * 3).unwrap();
                    let ks: Vec<_> = (0..n).map(|i| logs[i * 3 + 1]).collect();
                    let exps: Vec<_> = (0..n).map(|i| start + step * i as u32).collect();
                    let (transformed, e0) = progression_parameters(&ks, &exps).unwrap();
                    let matrix: Vec<Vec<_>> = exps
                        .iter()
                        .map(|&e| {
                            ks.iter()
                                .map(|&k| gf16::pow2(k as u64 * e as u64))
                                .collect()
                        })
                        .collect();
                    assert_eq!(
                        invert_vandermonde(&transformed, e0).unwrap(),
                        linalg::invert(matrix).unwrap(),
                        "n={n} step={step} start={start}"
                    );
                }
            }
        }
    }
    #[test]
    fn progression_refuses_nonunits_and_irregular_exponents() {
        for step in [0u32, 3, 5, 17, 257, 65535] {
            assert!(progression_parameters(&[1, 2, 4], &[1, 1 + step, 1 + 2 * step]).is_none());
        }
        for e in [vec![], vec![1], vec![2, 1], vec![0, 2, 5]] {
            assert!(progression_parameters(&[1, 2, 4], &e).is_none());
        }
    }
    #[test]
    fn progression_forney_matches_general_inverse_solution() {
        let n = 37usize;
        let words = 17usize;
        let logs = input_base_logs(n * 3).unwrap();
        let ks: Vec<_> = (0..n).map(|i| logs[i * 3 + 1]).collect();
        for step in [2u32, 7, 16] {
            let exps: Vec<_> = (0..n).map(|i| 11 + step * i as u32).collect();
            let (kk, e0) = progression_parameters(&ks, &exps).unwrap();
            let matrix: Vec<Vec<_>> = exps
                .iter()
                .map(|&e| {
                    ks.iter()
                        .map(|&k| gf16::pow2(k as u64 * e as u64))
                        .collect()
                })
                .collect();
            let inv = linalg::invert(matrix).unwrap();
            let syn: Vec<Vec<u16>> = (0..n)
                .map(|r| {
                    (0..words)
                        .map(|w| ((r * 7919 + w * 619 + 17) % 65536) as u16)
                        .collect()
                })
                .collect();
            let mut expected = vec![vec![0u16; words]; n];
            for r in 0..n {
                for c in 0..n {
                    for w in 0..words {
                        expected[r][w] ^= gf16::mul(inv[r][c], syn[c][w]);
                    }
                }
            }
            let actual = ForneyPlan::prepare(&kk, e0).unwrap().solve(&syn, words);
            assert_eq!(actual, expected);
        }
    }
}

#[cfg(test)]
mod solve_budget_tests {
    use super::*;
    use crate::mem::MemBudget;

    /// `n` GiB as this target's `usize`, clamped where the address
    /// space cannot hold it. The ceiling is ASKED of
    /// [`MemBudget::max_total`] rather than written out, because a
    /// copied ceiling cannot follow a change to the real one and this
    /// file has no way to see a 32-bit answer otherwise. Also the
    /// reason these are not literals: `16 * (1 << 30)` as a `usize`
    /// literal is a const-eval overflow at 32-bit pointer width and
    /// does not COMPILE, in dead code as much as in live, which is what
    /// took the armv7 nightly red on 8 Sep 2026.
    fn gib(n: u64) -> usize {
        usize::try_from((n << 30).min(MemBudget::max_total())).unwrap_or(usize::MAX)
    }

    /// The published research sweep and every rig pass a raw byte count
    /// (e.g. `25769803776`), so that form must keep working unchanged.
    ///
    /// 24 GiB is past what a 32-bit `usize` can hold, and there this
    /// spelling is CLAMPED to the address-space ceiling. Until 8 Sep
    /// 2026 it was refused instead: `str::parse::<usize>` failed out of
    /// range, no suffix matched, and `solve_window_budget` warned that a
    /// perfectly well-formed byte count was "not a byte count" before
    /// falling back to the host default.
    #[test]
    fn a_raw_byte_count_still_parses() {
        assert_eq!(parse_budget_bytes("25769803776"), Some(gib(24)));
        assert_eq!(parse_budget_bytes("0"), Some(0));
    }

    /// THE INVARIANT THE 8 Sep 2026 armv7 RED WAS HIDING, and the one
    /// assertion here that is live at BOTH widths: one size, two
    /// spellings, one answer. It held on a 64-bit host by arithmetic
    /// accident - neither path clamps anything there - and failed on a
    /// 32-bit one in two different directions at once, the raw form
    /// reading as a typo and the suffixed form as no limit at all.
    #[test]
    fn the_same_size_parses_the_same_however_it_is_spelled() {
        assert_eq!(
            parse_budget_bytes("25769803776"),
            parse_budget_bytes("24GiB")
        );
        assert_eq!(
            parse_budget_bytes("17179869184"),
            parse_budget_bytes("16GiB")
        );
    }

    /// A budget past the address space is a request the platform cannot
    /// grant, not a parse error and not an unbounded one.
    ///
    /// The second half is the safety property, and it is the one that
    /// was actually lost: `check_repair_dim_within` refuses when the
    /// peak window is over the budget, so a budget of `usize::MAX` -
    /// what `16GiB` used to parse to at 32-bit pointer width - admits
    /// every window there is. A 32-bit NAS asking for a BIGGER repair
    /// budget was silently switching off the guard that keeps a large
    /// set from being OOM-killed there, which is the exact failure that
    /// guard was added for.
    #[test]
    fn an_over_large_budget_is_clamped_rather_than_refused_or_unbounded() {
        for spelling in ["16GiB", "17179869184", "1024GiB", "99999999999999999999999"] {
            let Some(budget) = parse_budget_bytes(spelling) else {
                panic!("{spelling} is a well-formed byte count and must not read as a typo");
            };
            assert!(
                u64::try_from(budget).is_ok_and(|b| b <= MemBudget::max_total()),
                "{spelling} parsed to {budget}, past what this target can hold"
            );
        }
        // ...and the clamped budget still BINDS. `MAX_INPUT_SLICES` is
        // admitted by the slice ceiling and reaches the window check on
        // either arm, so a block size just over `budget / (2 * m)` puts
        // the peak window over the budget by construction, at whatever
        // value the budget clamped to on this target.
        let budget = parse_budget_bytes("16GiB").expect("well-formed");
        let bs = budget / (2 * MAX_INPUT_SLICES) + 1;
        assert!(
            matches!(
                check_repair_dim_within(MAX_INPUT_SLICES, bs, budget as u64),
                Err(RepairError::SolveBudget { .. })
            ),
            "a window over the clamped budget must still be a capacity refusal"
        );
    }

    /// The defect: `NZBFAST_REPAIR_SOLVE_BUDGET=16GiB` (or any suffixed
    /// form) used to parse as nothing, and `.ok()` swallowed the failure
    /// silently - the run used the default budget and looked like a clean
    /// disproof of the capacity refusal it was meant to demonstrate.
    ///
    /// The 16 and 24 GiB rows carry a second statement on a 32-bit
    /// target, where neither value fits a `usize`: both are clamped to
    /// the address-space ceiling, the same answer the raw spelling of
    /// the same size gets. That agreement is asserted on its own in
    /// [`the_same_size_parses_the_same_however_it_is_spelled`]; here it
    /// is pinned to a number, so the 32-bit answer is stated rather
    /// than gated out of the suite that only a 64-bit box ever runs.
    ///
    /// The rows below 1 GiB are unclamped at either width and say the
    /// same thing on both.
    #[test]
    fn suffixed_values_parse_as_binary_bytes() {
        const GIB: usize = 1 << 30;
        const MIB: usize = 1 << 20;
        const KIB: usize = 1 << 10;
        assert_eq!(parse_budget_bytes("16GiB"), Some(gib(16)));
        assert_eq!(parse_budget_bytes("16 GiB"), Some(gib(16)));
        assert_eq!(parse_budget_bytes("16gib"), Some(gib(16)));
        assert_eq!(parse_budget_bytes("24GB"), Some(gib(24)));
        assert_eq!(parse_budget_bytes("24G"), Some(gib(24)));
        assert_eq!(parse_budget_bytes("512MiB"), Some(512 * MIB));
        assert_eq!(parse_budget_bytes("512MB"), Some(512 * MIB));
        assert_eq!(parse_budget_bytes("512M"), Some(512 * MIB));
        assert_eq!(parse_budget_bytes("4KiB"), Some(4 * KIB));
        assert_eq!(parse_budget_bytes("4KB"), Some(4 * KIB));
        assert_eq!(parse_budget_bytes("4K"), Some(4 * KIB));
        // A fractional multiplier, and the one row where the 32-bit
        // ceiling lands BELOW the asked-for size without the size being
        // anywhere near `usize::MAX` - 1.5 GiB fits a 32-bit `usize`
        // perfectly well and is still more than the address space may
        // spend, so the clamp here is the memory policy binding rather
        // than an arithmetic limit.
        assert_eq!(
            parse_budget_bytes("1.5GiB"),
            Some(usize::try_from(((1.5 * GIB as f64) as u64).min(MemBudget::max_total())).unwrap())
        );
    }

    /// Neither a bare number nor a recognised suffix - the caller must
    /// treat this as "reject loudly", never as zero or as "unset".
    #[test]
    fn unparseable_values_are_rejected_not_swallowed() {
        for bad in ["", "GiB", "16 gigs", "-5", "16XB", "sixteen", "16GiBB"] {
            assert_eq!(parse_budget_bytes(bad), None, "must reject {bad:?}");
        }
    }
}
