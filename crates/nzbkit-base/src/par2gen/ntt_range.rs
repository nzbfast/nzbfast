//! The creator's transform plan for recovery exponents `first..first +
//! count`: a SELECTED-RANGE plan when `first > 0`, the prefix plan when
//! `first == 0` (identical to what the creator always built).
//!
//! Why: the creator planned `first + count` rows and wrote `count` of
//! them, so a create whose first exponent is not zero - `parfast c -f`,
//! or every batch after the first of a memory-limited big create,
//! where the accumulator budget splits the rows into passes - computed
//! the whole prefix and threw most of it away, the waste growing with
//! each batch. the review's sparse-NTT pass (5 Sep 2026): 10 x 1 GiB /
//! 4 MiB / 256 rows at first exponent 4,096 on an M1, 19.4 s over
//! 4,352 plan rows against 8.4 s over 256 (-57% wall, -55% CPU). The
//! repair grew `FlatPlan::build_range` for exactly this shape the same
//! day (the range/progression lane); the creator now uses it.
//! `NZBFAST_CREATE_NTT_RANGE=0` keeps the prefix plan (the A/B arm).

use crate::par2ntt::{FlatPlan, SrcId};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// How much of a real create is spent CONSTRUCTING the transform plan.
///
/// The NTT's own profile knob charges node EVALUATION at four tree
/// depths and never wraps `FlatPlan::build*`, so every queued setup
/// experiment - the cached additive kernel, shared coefficient and
/// order work, the sparse builder, the inverse Rader rank table - was
/// aimed at a phase with no measured denominator. These counters are
/// that denominator, and they are the create-side twin of the repair
/// path's plan-preparation counters, deliberately reported in the same
/// words so the two sides are read the same way.
///
/// `cold_ns` / `cold` are the constructor; `stripe_uses` is how many
/// column stripes then ran against an already-built plan, which is the
/// reuse the cold cost is amortised over. Cold and reuse are separated
/// because the create builds ONE plan PER RESIDENT WINDOW on the copied
/// path and one per create on the mapped and stripe-first paths, and
/// which of those a shape takes is exactly what decides whether a
/// constructor saving is worth anything.
///
/// Counters are process-global and MONOTONE, so a caller reads a
/// difference across the span it cares about (see [`PrepCounters::since`]).
/// Two creates at once in one daemon pool into each other's window;
/// that is acceptable for a measurement driver running one create per
/// process, and is why nothing branches on them.
static PREP_COLD_NS: AtomicU64 = AtomicU64::new(0);
static PREP_COLD: AtomicU64 = AtomicU64::new(0);
static PREP_STRIPE_USES: AtomicU64 = AtomicU64::new(0);

/// A reading of the counters above. Differences, not absolutes.
#[derive(Clone, Copy, Default)]
struct PrepCounters {
    cold_ns: u64,
    cold: u64,
    stripe_uses: u64,
}

impl PrepCounters {
    fn read() -> PrepCounters {
        PrepCounters {
            cold_ns: PREP_COLD_NS.load(Ordering::Relaxed),
            cold: PREP_COLD.load(Ordering::Relaxed),
            stripe_uses: PREP_STRIPE_USES.load(Ordering::Relaxed),
        }
    }

    /// This reading minus an earlier one. Saturating, so a counter read
    /// out of order reports zero rather than a nonsense share.
    fn since(self, earlier: Self) -> Self {
        Self {
            cold_ns: self.cold_ns.saturating_sub(earlier.cold_ns),
            cold: self.cold.saturating_sub(earlier.cold),
            stripe_uses: self.stripe_uses.saturating_sub(earlier.stripe_uses),
        }
    }
}

/// Charge column stripes run against an already-built plan. One call per
/// plan USE, beside the stripe count the workers claim from.
pub(super) fn note_stripes(stripes: usize) {
    PREP_STRIPE_USES.fetch_add(stripes as u64, Ordering::Relaxed);
}

/// Test doors, in one place: the counter a suite reads to prove a create
/// really took the transform, the two arms it flips to build the SAME
/// set both ways, and the shipped admission shapes so a fixture can be
/// sized from the gates rather than from a copy of their numbers.
///
/// Why doors rather than the environment knobs the bench arms use
/// (`NZBFAST_NTT`, `NZBFAST_PAR2GEN_MAP`): `std::env::set_var` is sound
/// only where nothing else in the process is reading the environment,
/// which a test in a SHARED binary cannot promise - and
/// `NZBFAST_PAR2GEN_MAP` is latched in a `OnceLock` besides, so the
/// first create in the process would decide the mapping arm for every
/// test after it. These are atomics, so one test can build both arms
/// back to back under its own serializer. Same shape and same reason as
/// `par2gen::pin_accum_budget_for_tests`. Not part of the supported API.
///
/// The counter is process-global and monotone, so a caller reads a
/// DIFFERENCE across its own create; two creates at once in one process
/// pool into each other's window, which is what the caller's serializer
/// is for.
#[doc(hidden)]
pub fn cold_builds_for_tests() -> u64 {
    PREP_COLD.load(Ordering::Relaxed)
}

/// Test door: force every create in this process onto the FOLD (`true`),
/// or back to the shipped dispatch (`false`). See [`cold_builds_for_tests`].
#[doc(hidden)]
pub fn pin_transform_off_for_tests(off: bool) {
    TRANSFORM_OFF.store(off, Ordering::Relaxed);
}

/// Test door: force this process's TRANSFORM off the mapped input path
/// (`true`) and onto the copied resident windows, or back to the shipped
/// dispatch (`false`). Read by `par2gen::map_inputs_enabled`, ahead of
/// the `NZBFAST_PAR2GEN_MAP` knob it latches - narrower than that knob,
/// which also unmaps the scan and the direct fold, because the branch
/// this exists to reach is the creator's copied-window loop. See
/// [`cold_builds_for_tests`].
#[doc(hidden)]
pub fn pin_map_off_for_tests(off: bool) {
    MAP_OFF.store(off, Ordering::Relaxed);
}

/// The shipped floor clause's shape on this build: the input count and
/// the recovery-row count that [`rows_and_present_admitted`] admits.
/// A fixture built from this crosses the gates at their measured value
/// on whatever arch it runs on, instead of restating numbers that are
/// per-arch and fold-denominated.
#[doc(hidden)]
pub fn floor_shape_for_tests() -> (usize, usize) {
    (create_ntt_min_present(), create_ntt_min_rows())
}

/// The high-redundancy subfloor clause's shape on this build - the
/// few-source, many-row corner of [`rows_and_present_admitted`], which
/// the floor above refuses. See [`floor_shape_for_tests`].
#[doc(hidden)]
pub fn subfloor_shape_for_tests() -> (usize, usize) {
    (SUBFLOOR_MIN_PRESENT, SUBFLOOR_MIN_ROWS)
}

static TRANSFORM_OFF: AtomicBool = AtomicBool::new(false);
static MAP_OFF: AtomicBool = AtomicBool::new(false);

/// Whether [`pin_map_off_for_tests`] is holding the mapped input path
/// shut. Production reads this once per recovery batch through
/// `map_inputs_enabled`.
pub(super) fn map_off_pinned() -> bool {
    MAP_OFF.load(Ordering::Relaxed)
}

/// A create's plan-construction bracket: hold one for the span the share
/// should be taken over and it reports on `repair-timing` when it drops,
/// beside the create's other phase lines.
///
/// A guard rather than a pair of calls so the creator spends ONE line on
/// it: `par2gen.rs` and its `create_into_inner` both carry the size
/// gate's ceilings with margin in single digits.
///
/// Silent unless `NZBFAST_REPAIR_TIMING` is set, read once at `start` so
/// the drop path does no work in a production create.
pub(super) struct PrepSpan {
    at: PrepCounters,
    t0: std::time::Instant,
    what: &'static str,
    on: bool,
}

impl PrepSpan {
    pub(super) fn start(what: &'static str) -> PrepSpan {
        PrepSpan {
            at: PrepCounters::read(),
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
        let prep = PrepCounters::read().since(self.at);
        let total = self.t0.elapsed();
        let share = if total.as_nanos() == 0 {
            0.0
        } else {
            prep.cold_ns as f64 * 100.0 / total.as_nanos() as f64
        };
        tracing::info!(
            target: "repair-timing",
            "plan prep: {:.2?} over {} cold build(s), {} stripe use(s) - {share:.3}% of the {total:.2?} {}",
            std::time::Duration::from_nanos(prep.cold_ns),
            prep.cold,
            prep.stripe_uses,
            self.what,
        );
    }
}

fn range_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_CREATE_NTT_RANGE").as_deref() != Ok("0"))
}

/// The plan's worker-arena cost for admission: priced on the rows the
/// plan will actually hold.
pub(super) fn worker_arenas(block_size: usize, first: usize, count: usize) -> usize {
    let rows = if first > 0 && range_enabled() {
        count
    } else {
        first + count
    };
    crate::par2repair::ntt_worker_arenas(block_size, rows)
}

/// The plan, and the plan-output index of exponent `first`: 0 for a
/// range plan (its outputs are the selected rows, compact), `first` for
/// the prefix plan.
///
/// Every create-side plan construction goes through here, which is what
/// makes this the one place the constructor has to be timed (see
/// [`PREP_COLD_NS`]). A failed build charges nothing: no plan was built,
/// so there is no construction to size, and the caller falls to the fold.
pub(super) fn plan(
    present: &[(u32, SrcId)],
    first: usize,
    count: usize,
) -> Result<(FlatPlan, usize), String> {
    let t0 = std::time::Instant::now();
    let built = if first > 0 && range_enabled() {
        (FlatPlan::build_range(present, first, count)?, 0)
    } else {
        (FlatPlan::build(present, first + count)?, first)
    };
    PREP_COLD_NS.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    PREP_COLD.fetch_add(1, Ordering::Relaxed);
    Ok(built)
}

/// Whether the transform is even a candidate for this recovery batch:
/// the plan fits the field, and the batch clears the create's row and
/// input-count gates (the parent's `create_ntt_min_rows` /
/// `create_ntt_min_present`).
pub(super) fn shape_possible(
    block_size: usize,
    n_slices: usize,
    needed: usize,
    count: usize,
) -> bool {
    block_size > 0 && needed <= crate::par2ntt::N && rows_and_present_admitted(n_slices, count)
}

/// The create's row and input-count gates as ONE predicate - the
/// transform's admission and the fused single-member scan's refusal
/// ask the same question, and a shape admitted here must never be
/// captured by that scan.
///
/// Two clauses. The floor (`create_ntt_min_rows` / `create_ntt_min_present`,
/// measured at ordinary redundancy) and, below the input floor, the
/// HIGH-REDUNDANCY clause: the transform's cost does not depend on the
/// row count and the fold's does, so a set with few sources and many
/// rows crosses over well under the floor. the review's candidate 55 on an
/// M5 Max (7 Sep 2026): 512 sources x 512 rows at 2 MiB, 2.38 s on the
/// fold against 1.46 on the transform; then measured here, same
/// binary, forced arm against the fold, x2 mirrored, identical
/// outputs: M3 Ultra, 512 sources at 2 MiB, 384 rows 1.59-1.67 s
/// against 1.81-1.95, 512 rows 1.62-1.86 against 2.01-2.09; 768
/// sources at 384 rows 1.65-1.69 against 2.05-2.27; 256 rows a small
/// win here and a 6% loss on the M5, so the clause starts at 384.
/// i5-10600KF (nibble arm), 1,024 sources at 1 MiB: 256 rows 3.94-3.99
/// against the fold's 2.65-2.75, 384 rows 4.15-4.20 against 3.84-3.95,
/// 512 rows 4.47-4.54 against 5.16-5.21, 768 rows 5.05-5.09 against
/// 7.68-7.85; 1,536 sources at 384 rows 4.64-4.69 against 5.39-5.55;
/// 512 sources at 512 rows 8.05-8.19 against 5.31-5.49 - so on x86 the
/// clause is 1,024 sources and 512 rows, and nothing below 1,024.
/// `NZBFAST_CREATE_NTT_SUBFLOOR=0` drops the clause (the A/B arm).
pub(super) fn rows_and_present_admitted(n_slices: usize, count: usize) -> bool {
    let (floor_present, floor_rows) = (create_ntt_min_present(), create_ntt_min_rows());
    if count >= floor_rows && n_slices >= floor_present {
        return true;
    }
    // Between the clause's point and the floor's the row line is
    // LINEAR in the source count - measured on the i5 (round BA, 6 Sep
    // 2026, forced arm against the fold, x2 mirrored): ON the line
    // between (1,024, 512) and (2,048, 256), 1,280 sources x 448 rows
    // 4.61-4.78 s against 5.44-5.57, 1,536 x 384 4.66-4.75 against
    // 5.45-5.50, 1,792 x 323 4.73-4.90 against 5.22-5.29; one step BELOW
    // it, 1,280 x 384 4.44-4.50 against 4.63-4.76, 1,536 x 323 equal,
    // 1,792 x 269 4.64-4.69 against 4.42-4.49. The same form on aarch64
    // between (512, 384) and (1,024, 192) is bracketed rather than
    // measured (768 x 256 a small win on the M3 and a 6% loss on the M5,
    // 768 x 384 a win on both; the line puts 768 at 288).
    subfloor_enabled()
        && n_slices >= SUBFLOOR_MIN_PRESENT
        && floor_present > SUBFLOOR_MIN_PRESENT
        && count >= subfloor_rows_at(n_slices, floor_present, floor_rows)
}

/// The clause's row line at `n_slices` sources: [`SUBFLOOR_MIN_ROWS`] at
/// [`SUBFLOOR_MIN_PRESENT`], falling linearly to the floor's row gate
/// at the floor's source count (see [`rows_and_present_admitted`]).
fn subfloor_rows_at(n_slices: usize, floor_present: usize, floor_rows: usize) -> usize {
    if n_slices >= floor_present || SUBFLOOR_MIN_ROWS <= floor_rows {
        return floor_rows.min(SUBFLOOR_MIN_ROWS);
    }
    let over = n_slices.saturating_sub(SUBFLOOR_MIN_PRESENT);
    let span = floor_present - SUBFLOOR_MIN_PRESENT;
    SUBFLOOR_MIN_ROWS - (SUBFLOOR_MIN_ROWS - floor_rows) * over / span
}

/// The high-redundancy clause's floors (see [`rows_and_present_admitted`]).
const SUBFLOOR_MIN_PRESENT: usize = if cfg!(target_arch = "aarch64") {
    512
} else {
    1024
};
const SUBFLOOR_MIN_ROWS: usize = if cfg!(target_arch = "aarch64") {
    384
} else {
    512
};

fn subfloor_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_CREATE_NTT_SUBFLOOR").as_deref() != Ok("0"))
}

/// Smallest resident window the creator will hand to the transform, in
/// slices: below this the per-window structural cost outweighs what the
/// transform saves over the fold (measured, audit record section 13).
pub(super) const NTT_WINDOW_MIN: usize = 1024;

/// Resident input window when the create-side NTT is admissible for this
/// exact recovery batch. The single-member source-fusion dispatcher asks this
/// same function before choosing the fold: sharing the predicate keeps a
/// newly admitted NTT shape from being silently captured by the fused path,
/// which cannot feed the transform from its sequential hash pass.
pub(super) fn create_ntt_window(
    block_size: usize,
    n_slices: usize,
    first: usize,
    count: usize,
) -> Option<usize> {
    if TRANSFORM_OFF.load(Ordering::Relaxed)
        || matches!(std::env::var("NZBFAST_NTT").as_deref(), Ok("0") | Ok("off"))
    {
        return None;
    }
    let needed = first.checked_add(count)?;
    if !shape_possible(block_size, n_slices, needed, count) {
        return None;
    }
    let budget = crate::par2repair::ntt_budget_within_published().saturating_sub(worker_arenas(
        block_size,
        needed - count,
        count,
    ));
    create_ntt_window_with_budget(block_size, n_slices, needed, count, budget)
}

/// The create's row gate: `NZBFAST_CREATE_NTT_MIN_ROWS` (a bench knob for
/// crossover sweeps), else the repair's row gate (`ntt_min_missing`: the
/// create and repair crossovers measured together on the M3, 5 Sep 2026).
pub(super) fn create_ntt_min_rows() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("NZBFAST_CREATE_NTT_MIN_ROWS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(crate::par2repair::ntt_min_missing)
    })
}

/// The create's input-count floor for the transform. NOT the repair's
/// 8,192: the create's transform wins at ~1,075 inputs from 192 rows
/// (M3 Ultra, 1 MiB blocks: 0.79-0.81 s vs the fold's 0.90-0.92 at 256
/// rows, 0.82-0.84 vs 1.03-1.06 at 320; 512 KiB / ~2,150 inputs the
/// same way), where the repair's transform at the same input count LOSES
/// to the fold at every row count (0.68-0.72 vs 0.42-0.53: its plan and
/// retention costs are not amortised there). 1,024 is the smallest count
/// measured winning on NEON; nothing below it is measured.
///
/// **The fold's cost is this constant's denominator**, the same way it
/// is the repair gates' (`crate::par2repair::fastpar`'s
/// `NTT_MIN_PRESENT` carries that rule in full): this is the same
/// crossover on the create path, so a fold that gets faster RAISES it
/// and both floors here have to be re-derived. The fold lives in
/// `crates/nzbkit-base/src/par2repair/linalg.rs` - the creator folds
/// through the repairer's routine - and carries the pointer back.
/// Nothing asserts either floor; a stale one costs only wall.
const CREATE_NTT_MIN_PRESENT_NEON: usize = 1024;

/// The same floor on x86 (i5-10600KF, AVX2 nibble arm): at ~1,075 inputs
/// the create's transform LOSES at every row count (1 MiB blocks: 3.95-3.99
/// vs 3.18 at 256 rows, 4.20-4.28 vs 3.74 at 320), and wins from 256 rows
/// at ~2,150 (512 KiB: 2.79-2.83 vs 3.43-3.49), so the floor sits at the
/// smaller winning count. Fold-denominated, and re-derived with its
/// NEON twin above.
const CREATE_NTT_MIN_PRESENT_X86: usize = 2048;

/// The create's input-count gate: `NZBFAST_CREATE_NTT_MIN_PRESENT` (the same
/// bench knob's other half), else the arch's measured floor.
pub(super) fn create_ntt_min_present() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("NZBFAST_CREATE_NTT_MIN_PRESENT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(if cfg!(target_arch = "aarch64") {
                CREATE_NTT_MIN_PRESENT_NEON
            } else {
                CREATE_NTT_MIN_PRESENT_X86
            })
    })
}

/// Pure half of [`create_ntt_window`], kept separate so boundary tests can pin
/// the transform's memory gate without mutating the process environment.
pub(super) fn create_ntt_window_with_budget(
    block_size: usize,
    n_slices: usize,
    needed: usize,
    count: usize,
    budget: usize,
) -> Option<usize> {
    if !shape_possible(block_size, n_slices, needed, count) {
        return None;
    }
    let window = (budget / block_size).min(n_slices);
    (window >= NTT_WINDOW_MIN.min(n_slices)).then_some(window)
}

#[cfg(test)]
mod subfloor_tests {
    /// The high-redundancy clause admits few-source, many-row shapes
    /// below the input floor, per arch, along a line falling to the
    /// floor's own row gate; nothing below the line, nothing below the
    /// clause's source floor; the ordinary floor unchanged by it.
    #[test]
    fn the_high_redundancy_clause_admits_below_the_input_floor_only_with_the_rows() {
        if std::env::var_os("NZBFAST_CREATE_NTT_SUBFLOOR").is_some()
            || std::env::var_os("NZBFAST_CREATE_NTT_MIN_ROWS").is_some()
            || std::env::var_os("NZBFAST_CREATE_NTT_MIN_PRESENT").is_some()
        {
            return;
        }
        let (present, rows) = (super::SUBFLOOR_MIN_PRESENT, super::SUBFLOOR_MIN_ROWS);
        let (floor, floor_rows) = (
            super::create_ntt_min_present(),
            super::create_ntt_min_rows(),
        );
        assert!(present < floor, "the clause sits below the input floor");
        assert!(super::rows_and_present_admitted(present, rows));
        assert!(super::rows_and_present_admitted(present + 1, rows + 100));
        assert!(!super::rows_and_present_admitted(present - 1, rows));
        assert!(!super::rows_and_present_admitted(present, rows - 1));
        // The line: halfway to the floor the row gate is halfway down,
        // one row under it refuses, and at the floor it is the floor's.
        let mid = present + (floor - present) / 2;
        let mid_rows = rows - (rows - floor_rows) / 2;
        assert_eq!(super::subfloor_rows_at(mid, floor, floor_rows), mid_rows);
        assert!(super::rows_and_present_admitted(mid, mid_rows));
        assert!(!super::rows_and_present_admitted(mid, mid_rows - 1));
        assert_eq!(
            super::subfloor_rows_at(floor, floor, floor_rows),
            floor_rows
        );
        // The ordinary floor still admits at its own row gate.
        assert!(super::rows_and_present_admitted(floor, floor_rows));
        assert!(!super::rows_and_present_admitted(floor, floor_rows - 1));
    }
}
