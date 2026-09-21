//! What a DAEMON repair is doing, while it does it.
//!
//! The companion of [`crate::unpackprog`] one stage earlier in the
//! tail, and it exists for the identical reason. The disk unpack ladder
//! used to publish one static word for however many minutes it ran,
//! which reads as a hang; so did the repair, and the daemon's own
//! source said so out loud. `serve/mod.rs` capped what a daemon would
//! even START at `MAX_REPAIR_DIM` because "the queue row has read
//! `Repairing, 100%, timeleft 0:00:00` through exactly that kind of
//! stall before", and `par2repair.rs`'s forecast warn ended "and
//! nothing reports progress while it runs".
//!
//! The engine grew the channel on 12 Sep 2026
//! (`nzbkit::par2repair::control`, whose module doc carries the whole
//! design). This is the daemon's end of it: a `ProgressSink` that
//! publishes into a value the queue payload reads on every poll, plus
//! the band decision the engine deliberately refuses to make.
//!
//! # Where the CANCEL half lives, and why it is not here
//!
//! On [`crate::streamhub::SideCancel`], which is the one per-owner
//! handle every daemon repair site already receives and the daemon
//! already publishes per nzo_id. A repair gate of its own here would be
//! a SECOND cancel bit for one button - the host presses Cancel, one of
//! them is set, and whether the fold stops depends on which. That is
//! the mistake `parfast_session::runner::Control` was rewritten to
//! remove on the very day the engine's gate landed, and it is not worth
//! re-making one crate over. `SideCancel::repair_control` is where the
//! two halves are put together.
//!
//! # Why the fraction is stored and not recomputed
//!
//! The engine reports four phases in four different UNITS and refuses
//! to weigh them (`par2repair::RepairPhase`), because only a caller
//! knows what its user is waiting on. The queue payload is polled far
//! more often than the sink is called, so the weighing happens once per
//! sink call - at most 256 times a phase - rather than once per poll,
//! and a `fetch_max` makes it monotone across phases without a lock.
//! A bar that went back to 85% because a slabbed solve re-entered its
//! phase would read as a restart.
//!
//! # Cost
//!
//! Nothing in this module is on a hot path and no hook of its own is
//! added to one. The engine's rate limit is what makes that true: two
//! relaxed stores and a `fetch_max` per sink call (it was four stores
//! and a `fetch_max` until the phase and the per-mille became one
//! word - see [`RepairProgress::bar`]), and the sink is
//! reached at most `control::STEPS` times per phase however many
//! batches there were (pinned by
//! `a_million_steps_reach_the_sink_at_most_steps_times`). The per-batch
//! cost is the engine's own and was measured when the hooks landed: on
//! a real 1 GiB set with 200 blocks of damage, mirrored A B B A x 4,
//! +0.82% of CPU-seconds against an A/A floor of +0.59% measured on the
//! same box in the same round - inside the floor, with the ranges
//! overlapping almost entirely. The CONTROLLED path has no A/B of its
//! own yet: per site it is one relaxed `fetch_add`, one relaxed load
//! and a compare per fed block and per fold unit, which is a bound
//! rather than a measurement.

use std::sync::atomic::{AtomicU64, Ordering};

/// The four phases, as the token the dashboard maps to a sentence.
///
/// Zero is "no repair in flight", which is a state the payload needs a
/// shape for: `hub.activity` says `repairing` for the whole repair
/// SECTION - the recovery-volume side-fetches included - and only part
/// of that section is inside the engine.
const PHASE_NONE: u8 = 0;

/// [`RepairProgress::route`] values - see [`band`].
const ROUTE_DISK: u64 = 0;
const ROUTE_MAPPED: u64 = 1;

/// [`RepairProgress::arm`] values - see [`band`] and
/// `par2repair::SolveArm`.
///
/// Three states for a two-variant announcement, because what [`band`]
/// needs is not "which arm" but "is this sweep's solve SPLIT, and if so
/// which half is reporting". A back-substitution that heard no inverse
/// before it is the ordinary repair, and it must read exactly the band
/// it always had.
const ARM_NONE: u64 = 0;
/// The Gauss-Jordan inverse is reporting: this sweep IS split, and this
/// is its first half, which runs BEFORE the fold.
const ARM_INVERSE: u64 = 1;
/// The back-substitution is reporting AFTER an inverse in this sweep:
/// still split, second half. A back-substitution with no inverse behind
/// it leaves the state at [`ARM_NONE`].
const ARM_SPLIT_BACKSUB: u64 = 2;

/// One job's live repair progress, as both the sink the engine writes
/// to and the value the queue payload reads.
///
/// One type rather than a publisher and a snapshot, because there is
/// nothing to snapshot: every field is an atomic the payload can read
/// at any instant, so the engine advances it in place and nobody has to
/// remember to publish.
#[derive(Default, Debug)]
pub struct RepairProgress {
    /// THE BAR: the phase code in the high 32 bits, the whole repair's
    /// per-mille in the low 32, as ONE value. `0` is `PHASE_NONE` and
    /// no repair inside the engine.
    ///
    /// ONE WORD RATHER THAN TWO BECAUSE A READER READS BOTH. Every
    /// caller that draws this draws the pair - the queue payload's
    /// `{"phase": .., "pct": ..}` is one object - and two atomics
    /// cannot be read as a pair: a reader descheduled between the two
    /// loads gets a phase from before a boundary and a percentage from
    /// after it. The boundary that matters is [`clear`](Self::clear),
    /// which is `RepairRun`'s drop and `restart`'s whole job, so the
    /// torn pair is `("write", 0.0%)` - a bar that says the last phase
    /// of a repair at nought per cent, which is the "reads as a
    /// restart" this module exists to refuse. Measured 15 Sep 2026 on
    /// a reader polling the two-atomic version across 2,000 runs:
    /// 3 torn reads in 576,051 samples idle, and 1 in 12,782 under 36
    /// spinners on 18 cores - ~15x the per-sample rate, which is why
    /// it was a LOADED sweep that caught it.
    ///
    /// A packed `fetch_max` is also what makes the LABEL monotone: the
    /// sink is called from worker threads (`control::ProgressSink`),
    /// and a straggler from earlier in the repair publishes a smaller
    /// word, so it cannot pull the label back.
    ///
    /// THE FIGURE IS MAJOR AND THE PHASE IS MINOR, and until 16 Sep
    /// 2026 it was the other way round. Phase-major worked only while
    /// ordering the word by phase and ordering it by per-mille were the
    /// same order, which held because the four bands were contiguous
    /// and rising. Per-SWEEP bands break that (see [`band`]): sweep 2's
    /// fold sits above sweep 1's solve, so a phase-major word would
    /// hold at the earlier phase's higher code and swallow every later
    /// sweep - which is the very freeze the split exists to remove.
    /// Ordering by the figure a reader DRAWS is the rule that survives
    /// both layouts.
    ///
    /// The sweep index sits between them so that two publishes at the
    /// same per-mille still resolve in the order the engine made them:
    /// a sweep boundary is exactly such a tie (sweep `i`'s solve ends
    /// on the per-mille sweep `i+1`'s fold opens at), and without it
    /// the label would read `solve` until the new fold's first bucket
    /// crossed - up to 1/256th of a sweep, which on the repairs that
    /// slab is not a moment.
    bar: AtomicU64,
    /// Which sweep of the payload the engine is in: `(index << 32) | of`.
    ///
    /// NOT part of the bar, because it is not drawn: it is the FRAME
    /// the phases are weighed in, read by [`band`] on the sink's own
    /// thread and never by a poller. Zero - the default, and what
    /// [`clear`](Self::clear) restores - is `of == 0`, which [`band`]
    /// reads as the one-sweep repair; that is the correct reading both
    /// before any sweep is announced and for a repair with no blocks to
    /// rebuild, which announces none.
    ///
    /// Written by the driver thread alone, once per sweep, before that
    /// sweep's first `progress` and never concurrently with one
    /// (`par2repair::control::ProgressSink::slab` states the contract),
    /// so a relaxed store is enough.
    slab: AtomicU64,
    /// Which route announced itself through [`ProgressSink::route`] -
    /// [`ROUTE_DISK`] or [`ROUTE_MAPPED`]. Read by [`band`] on the
    /// sink's own thread, same as `slab`, and for the same reason not
    /// part of the bar: it is the FRAME the phases are placed in, not a
    /// thing a poller draws. [`ROUTE_DISK`] is the default and what
    /// [`RepairProgress::clear`] restores, so a driver that never calls
    /// `route` - every disk call site there is - gets the table it
    /// always had.
    route: AtomicU64,
    /// Which arm of the solve announced itself through
    /// [`ProgressSink::solve_arm`] - [`ARM_NONE`], [`ARM_INVERSE`] or
    /// [`ARM_SPLIT_BACKSUB`]. Read by [`band`] on the sink's own
    /// thread, and not part of the bar, for the same reason `slab` and
    /// `route` are not: it is the FRAME the `Solve` phase is placed in,
    /// never a thing a poller draws.
    ///
    /// PER SWEEP, so [`ProgressSink::slab`] clears it: on a slabbed
    /// unstructured repair the inverse is recomputed inside every
    /// sweep, and a state left set from the previous one would put
    /// sweep N's fold-opening publish above the base of the inverse
    /// that is about to run - which a monotone bar swallows, the exact
    /// defect this field exists to remove.
    arm: AtomicU64,
    /// The current phase's own `(done, total)`, in ITS units - bytes for
    /// Verify, Fold and Write, fold units or matrix columns for Solve
    /// (see `par2repair::RepairPhase`). Published for a caller that
    /// wants to say more than a percentage, and for the tests.
    ///
    /// NOT part of the bar and not read with it: these are about the
    /// PHASE, in units that change with it, and a caller draws them as
    /// a detail line beside the percentage rather than as the bar. A
    /// poll that catches them a phase out of step shows one stale
    /// number for one frame; the pair above is what must never be torn.
    done: AtomicU64,
    total: AtomicU64,
    /// Every published `(phase code, permille)`, as a reader would see
    /// it the instant after each sink call. Test builds only.
    ///
    /// A watcher thread sampling the atomics sees only what the
    /// scheduler lets it see, and on a loaded box that is NOTHING: at
    /// load ~70 on 32 cores the four-phases test's watcher caught `[]`
    /// in four runs of ten, because the whole repair ran inside one of
    /// its timeslices (15 Sep 2026). The control carries this value as
    /// its one sink, so the record has to live on the value itself.
    #[cfg(test)]
    trace: std::sync::Mutex<Vec<(u8, u64)>>,
    /// A one-shot park at the first Fold publish, so a test's watcher
    /// presses Cancel while the fold is DEFINITELY running rather than
    /// whenever the scheduler lets it look. Test builds only; unarmed
    /// it does nothing. See [`RepairProgress::hold_at_first_fold`].
    #[cfg(test)]
    fold_hold: FoldHold,
}

/// The states of [`RepairProgress::fold_hold`], in the order they go.
#[cfg(test)]
const HOLD_UNARMED: u8 = 0;
#[cfg(test)]
const HOLD_ARMED: u8 = 1;
#[cfg(test)]
const HOLD_PARKED: u8 = 2;
#[cfg(test)]
const HOLD_RELEASED: u8 = 3;

/// How long either side of the fold hold waits for the other. Bounded,
/// so a side that never arrives ends the test with a readable
/// assertion rather than hanging a shard (the wedge-that-exits-0 shape
/// CLAUDE.md warns about); the repair it holds is milliseconds.
#[cfg(test)]
const HOLD_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(test)]
#[derive(Default, Debug)]
struct FoldHold {
    state: std::sync::Mutex<u8>,
    wake: std::sync::Condvar,
}

/// `(bar offset, bar span)` for a phase, inside sweep `slab` of `of`.
///
/// THE SAME WEIGHTS `parfast_session::runner::RepairProgress` TOOK, and
/// deliberately so: the engine refuses to weigh its four phases, so
/// each caller decides - and two products of the same repair engine
/// disagreeing about what 60% means is a worse outcome than either
/// choice. The verify half is the first 45% of a repair's bar, the fold
/// the next 40%, the solve 10% and the write the last 5%. That is the
/// shape of an ordinary damaged repair on the measured corpus, and it
/// is a LABELLING choice rather than a prediction: a bar honest about
/// which phase is running and monotone within it beats one that lies
/// smoothly.
///
/// # THE SLAB SPLIT IS BY SWEEP, NOT BY PHASE, and that is the whole
/// subtlety
///
/// A repair whose solve window does not fit the memory budget sweeps
/// the payload once per slab, so the engine runs Fold, Solve, Fold,
/// Solve, ... `of` times (`par2repair::control::ProgressSink::slab`).
/// The obvious split - give phase Fold the `i`th slice of `[0.45,
/// 0.85)` and phase Solve the `i`th slice of `[0.85, 0.95)` - is WRONG,
/// and wrong in the exact way that leaves the defect in place: sweep
/// 1's solve would end above sweep 2's fold, so a monotone bar would
/// swallow every later fold just as it does today.
///
/// So the whole of `[0.45, 0.95)` is cut into `of` equal SWEEP
/// segments, and the 40/10 weighting lives INSIDE each segment. The
/// bands then run contiguously in the order the engine actually enters
/// them - fold, solve, fold, solve - and nothing is ever published
/// below something published before it. At `of == 1` the arithmetic is
/// the pre-slab split exactly, to the per-mille, which is what keeps
/// the ordinary repair's bar unchanged.
///
/// Measured before the split, on a real slabbed repair: the bar froze
/// at the literal pair `("solve", 950)` for 41.5% / 70.3% / 64.2% of
/// the wall at 2 / 4 / 8 slabs
/// (`research/REPAIR-SLABBED-BAR-2026-09-16.md`).
///
/// # Why `route` moves `Verify` rather than adding a phase
///
/// The mapped in-stream driver has no pre-fold verify pass - its
/// present-block ledger was earned off the wire - so its only proof of
/// the patch is the self-prove reread AFTER `Write`
/// (`nzbkit::par2repair::RepairRoute`). Published at the disk driver's
/// `[0.0, 0.45)` that reading arrives behind a `Write` that already
/// reached 1,000, and [`RepairProgress::bar`]'s `fetch_max` simply
/// discards it - the exact `Repairing, 100%, timeleft 0:00:00` freeze
/// this whole module exists to remove. So [`RepairRoute::Mapped`] gets
/// the SAME four weights (45/40/10/5), reordered to the sequence that
/// route actually runs: `Fold`, `Solve`, `Write`, then `Verify` last,
/// carrying the 45% a pre-fold pass would have spent. `Verify`'s own
/// band is simply never reached on this route's OTHER phases, and the
/// disk route's table - the one every pinned band-value test in this
/// file was written against - is untouched.
///
/// # AND THE SOLVE IS TWO ARMS, NOT ONE
///
/// `Solve` is entered TWICE within one sweep on the unstructured route
/// (`par2repair::SolveArm`): the Gauss-Jordan inverse before the fold,
/// the back-substitution after it. Given one band between them the
/// first walked it to the top and the monotone bar swallowed the
/// second - the queue row read `95%` unchanged for 19.0 s of a 63.7 s
/// repair, measured 18 Sep 2026 on the m = 10,000 gapped fixture
/// (`research/REPAIR-ROW-ACCEPTANCE-2026-09-18.md`, TODO 352).
///
/// So when `arm` says this sweep is split, the inverse takes the FIRST
/// HALF OF THE FOLD'S BAND and the fold keeps the second: within a
/// sweep segment the cut goes `0.20 / 0.20 / 0.10` instead of
/// `0.40 / 0.10`. Two things fall out of choosing that shape over any
/// other:
///
/// - **The back-substitution keeps the band it always had**, to the
///   per-mille, on both routes and at every slab count. Nothing below
///   the fold moves, so `Write` and both routes' `Verify` are untouched
///   and the pinned pre-slab table still reads 450 / 850 / 950 / 1000
///   for a repair that announces no arm.
/// - **The inverse is placed where it RUNS**, ahead of the fold rather
///   than behind it. That half is not cosmetic: `new_controlled` builds
///   the inverse before a block is read, so an inverse banded after the
///   fold publishes above the whole feed and a monotone bar then
///   discards every fold reading of an unstructured repair. The gapped
///   fixture hid it - a gapped set's fold is trivial - and a dense
///   repair with a real fold would not have.
///
/// The `0.20 / 0.10` split of what the two arms share between them is
/// the measured proportion and is a LABELLING choice like the 45/40/10/5
/// above, not a prediction: the same run spent 39.6 s in the inverse
/// against 20.3 s in the back-substitution, which is the 2:1 this gives
/// them. On that fixture it takes the worst plateau from 19.0 s to about
/// two seconds - the width of one drawn percentage point - and no region
/// of the bar is reserved for an arm that does not run.
fn band(
    phase: nzbkit::par2repair::RepairPhase,
    slab: u32,
    of: u32,
    route: nzbkit::par2repair::RepairRoute,
    arm: u64,
) -> (f64, f64) {
    use nzbkit::par2repair::RepairPhase as P;
    use nzbkit::par2repair::RepairRoute as R;
    // Never zero and never past the end: the pair is read from an
    // atomic a worker thread may see mid-update, and a division here is
    // not the place to find out.
    let of = f64::from(of.max(1));
    let i = f64::from(slab).min(of - 1.0);
    // One sweep's share of the fold+solve region, and where this one
    // starts - `[0.45, 0.95)` on the disk route, `[0.0, 0.50)` on the
    // mapped one, which is the same width shifted to make room for a
    // pre-fold `Verify` that this route does not have.
    let seg = 0.50 / of;
    // Is this sweep's solve SPLIT, and is the inverse the half that is
    // reporting? Both halves of the split state answer the first
    // question yes: the fold of a sweep that computed an inverse sits
    // in the upper half of its band whichever arm last announced
    // itself, so a straggling fold publish cannot fall back into the
    // inverse's region.
    let split = arm != ARM_NONE;
    let inverse = arm == ARM_INVERSE;
    // The fold's own base and width inside the segment. Unsplit it is
    // the whole 0.40; split, the inverse has the first half of it.
    let (fold_at, fold_span) = if split {
        (0.20 / of, 0.20 / of)
    } else {
        (0.0, 0.40 / of)
    };
    match route {
        R::Disk => {
            let at = 0.45 + seg * i;
            match phase {
                P::Verify => (0.0, 0.45),
                P::Fold => (at + fold_at, fold_span),
                P::Solve if inverse => (at, 0.20 / of),
                P::Solve => (at + 0.40 / of, 0.10 / of),
                P::Write => (0.95, 0.05),
            }
        }
        R::Mapped => {
            let at = seg * i;
            match phase {
                // The self-prove: AFTER `Write`, not before `Fold`, and
                // carrying the 45% a pre-fold pass would have spent.
                // Neither re-enters nor slabs, so unlike the other three
                // this reading does not depend on `slab`/`of` at all.
                P::Verify => (0.55, 0.45),
                P::Fold => (at + fold_at, fold_span),
                P::Solve if inverse => (at, 0.20 / of),
                P::Solve => (at + 0.40 / of, 0.10 / of),
                P::Write => (0.50, 0.05),
            }
        }
    }
}

/// The packed word's low byte: NOT just the phase, because the word's
/// tie-break at a shared per-mille is "the larger code wins"
/// ([`pack`]'s own doc), which only resolves FORWARD in time when the
/// codes rise in the order the phases actually run. On the disk route
/// that is true of `RepairPhase` as written (Verify < Fold < Solve <
/// Write, its own chronology) and needed no thought; on the mapped
/// route `Verify` runs LAST, so encoding it as `1` made the tie at the
/// Write/Verify boundary - both publish 550 exactly, `Write`'s `finish`
/// and `Verify`'s opening `(0, total)` - resolve BACKWARD: `("write",
/// 550)`, the very freeze this route-aware band table exists to
/// remove, caught by
/// `the_mapped_route_reports_verify_after_write_and_lands_on_full`. So
/// the mapped route's self-prove gets a code of its own, past every
/// other phase's, and [`token`] maps it back to the same label.
fn code(phase: nzbkit::par2repair::RepairPhase, route: nzbkit::par2repair::RepairRoute) -> u8 {
    use nzbkit::par2repair::RepairPhase as P;
    use nzbkit::par2repair::RepairRoute as R;
    match (route, phase) {
        (R::Mapped, P::Verify) => 5,
        (_, P::Verify) => 1,
        (_, P::Fold) => 2,
        (_, P::Solve) => 3,
        (_, P::Write) => 4,
    }
}

/// How many slabs the published word can order by. 24 bits, which is
/// four orders past any plan a real budget produces: the narrowest
/// legal slab is one `u16` word, so `plan.slabs` tops out at
/// `block_size / 2` and a 16 MiB block - four times the largest any
/// poster uses - is 8.4 million. Clamped rather than masked, so a
/// figure past it degrades to "the last sweep" instead of wrapping to
/// the first.
const SLAB_CEILING: u64 = 0xFF_FFFF;

/// The published word: per-mille major, then the sweep, then the phase.
/// See [`RepairProgress::bar`].
fn pack(code: u8, slab: u32, permille: u64) -> u64 {
    (permille << 32) | (u64::from(slab).min(SLAB_CEILING) << 8) | u64::from(code)
}

/// The token for a phase code, or None for `PHASE_NONE`.
///
/// Two codes read as `"verify"` - see [`code`] for why the mapped
/// route's self-prove needs a code of its own that still means the same
/// phase to a reader.
fn token(code: u8) -> Option<&'static str> {
    match code {
        1 | 5 => Some("verify"),
        2 => Some("fold"),
        3 => Some("solve"),
        4 => Some("write"),
        _ => None,
    }
}

impl RepairProgress {
    /// Which phase is running, as the token the dashboard maps to a
    /// translated sentence, or None when no repair is inside the engine
    /// right now.
    ///
    /// `None` is not "nothing is happening": the recovery-volume
    /// side-fetches run under the same `repairing` activity word and
    /// are not a phase of the engine's repair. The page keeps saying
    /// the bare word for those, which is what it said before any of
    /// this existed.
    pub fn phase(&self) -> Option<&'static str> {
        self.bar().map(|(ph, _)| ph)
    }

    /// THE PAIR A CALLER DRAWS, from one load: the phase token and the
    /// whole repair's per-mille, or None when no repair is inside the
    /// engine.
    ///
    /// Use this and not [`phase`](Self::phase) with
    /// [`permille`](Self::permille) whenever both go into the same
    /// frame - which is every drawing caller there is. The two
    /// accessors are each one load of the same word, so reading them
    /// separately is two loads of a value that moves between them; see
    /// the field's own note for the torn pair that produces and how
    /// often.
    pub fn bar(&self) -> Option<(&'static str, u64)> {
        let w = self.bar.load(Ordering::Relaxed);
        token((w & 0xFF) as u8).map(|ph| (ph, w >> 32))
    }

    /// The current phase's `done`, in that phase's own units.
    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    /// The current phase's `total`, in that phase's own units.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// The whole repair, 0-1000. Monotone for one [`RepairRun`].
    pub fn permille(&self) -> u64 {
        self.bar.load(Ordering::Relaxed) >> 32
    }

    /// Arm reporting for one repair call, and disarm it when the guard
    /// drops.
    ///
    /// A job makes SEVERAL engine repair calls - the adoption probe,
    /// the pass after the recovery fetch, and the escalation's second
    /// go - and each is its own bar: the probe's verify pass is not
    /// 45% of the repair that follows it. So the counters go back to
    /// zero here rather than accumulating, and the guard is what says
    /// "no repair is inside the engine" for the stretches in between,
    /// which is most of a slow tail's wall.
    pub fn enter(&self) -> RepairRun<'_> {
        self.clear();
        RepairRun(self)
    }

    /// Put the bar back for the NEXT set of a multi-set pass, without
    /// closing the window.
    ///
    /// [`enter`](Self::enter) is the same clear WITH a guard, and it is
    /// what a caller that owns its own loop uses per set (`get::
    /// latesets` does). The nested extraction ladder cannot: its pass
    /// repairs EVERY present set in the directory and the loop is the
    /// ENGINE's, so the only set boundary it has is the control supplier
    /// `par2repair::repair_present_sets_controlled_as` calls once per
    /// set - a `Fn`, which cannot hold a guard. This is that boundary's
    /// opening half; the directory's single [`RepairRun`] is what closes
    /// the window when the ladder leaves the level.
    ///
    /// Without it the bar would read 100% for every set after the
    /// first: `permille` is monotone by `fetch_max` (a slabbed solve
    /// re-entering its phase must not read as a restart), which is the
    /// right rule inside one repair and the wrong one across two.
    pub fn restart(&self) {
        self.clear();
    }

    fn clear(&self) {
        self.done.store(0, Ordering::Relaxed);
        self.total.store(0, Ordering::Relaxed);
        // Back to the one-sweep reading: the next engine call's verify
        // pass runs before it announces a sweep of its own, and a call
        // that rebuilds nothing never announces one at all.
        self.slab.store(0, Ordering::Relaxed);
        // Back to the disk table: a mapped attempt that self-proves and
        // then falls back to the disk driver must not leave the NEXT
        // engine call reading its `Verify` off the mapped route's band.
        self.route.store(ROUTE_DISK, Ordering::Relaxed);
        // Back to the unsplit solve: the next engine call may take a
        // structured arm that computes no inverse at all, and it must
        // not inherit this one's split band.
        self.arm.store(ARM_NONE, Ordering::Relaxed);
        // LAST, and ONE store: the bar going back to `PHASE_NONE` and
        // the percentage going back to nought are the same write, so
        // there is no instant at which a poller can read a phase with a
        // cleared percentage beside it.
        self.bar.store(pack(PHASE_NONE, 0, 0), Ordering::Relaxed);
    }
}

/// One engine repair call's reporting window. See
/// [`RepairProgress::enter`].
pub struct RepairRun<'a>(&'a RepairProgress);

impl Drop for RepairRun<'_> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

#[cfg(test)]
impl RepairProgress {
    /// Arm a one-shot park: the next Fold publish waits, with the
    /// published phase reading `fold`, until
    /// [`release_fold`](Self::release_fold) or [`HOLD_LIMIT`].
    ///
    /// WHY IT IS SAFE TO PARK THERE. The first Fold publish is
    /// `RepairControl::begin`, on the repair's DRIVER thread and before
    /// any fold worker exists, holding only that phase meter's own
    /// `reported` lock - which nothing else can want until the workers
    /// it is about to start. So the park holds no work another thread
    /// could take, and the one thing the watcher does meanwhile,
    /// `SideCancel::cancel`, takes the pause gate's lock and the pool
    /// queue's, neither of which the fold holds (memory topic
    /// `nzbfast-rayon-scope-owner-must-not-park` is the rule).
    pub(crate) fn hold_at_first_fold(&self) {
        *self.fold_hold.state.lock().unwrap() = HOLD_ARMED;
    }

    /// Wait, bounded, for the repair to park at the fold. True if it
    /// did.
    pub(crate) fn wait_parked_at_fold(&self) -> bool {
        let g = self.fold_hold.state.lock().unwrap();
        let (g, _) = self
            .fold_hold
            .wake
            .wait_timeout_while(g, HOLD_LIMIT, |s| *s != HOLD_PARKED)
            .unwrap();
        *g == HOLD_PARKED
    }

    /// Let a parked repair go on, and disarm a hold nobody reached.
    pub(crate) fn release_fold(&self) {
        *self.fold_hold.state.lock().unwrap() = HOLD_RELEASED;
        self.fold_hold.wake.notify_all();
    }

    fn park_if_held(&self, phase: nzbkit::par2repair::RepairPhase) {
        if phase != nzbkit::par2repair::RepairPhase::Fold {
            return;
        }
        let mut g = self.fold_hold.state.lock().unwrap();
        if *g != HOLD_ARMED {
            debug_assert!(*g == HOLD_UNARMED || *g == HOLD_RELEASED);
            return;
        }
        *g = HOLD_PARKED;
        self.fold_hold.wake.notify_all();
        let _ = self
            .fold_hold
            .wake
            .wait_timeout_while(g, HOLD_LIMIT, |s| *s == HOLD_PARKED)
            .unwrap();
    }
}

impl nzbkit::par2repair::ProgressSink for RepairProgress {
    /// Which route is reporting. One relaxed store on the driver thread,
    /// once, before its first phase; the weighing is `band`'s. See
    /// `RepairProgress::clear` for why the default reading is `Disk`.
    fn route(&self, route: nzbkit::par2repair::RepairRoute) {
        let r = match route {
            nzbkit::par2repair::RepairRoute::Disk => ROUTE_DISK,
            nzbkit::par2repair::RepairRoute::Mapped => ROUTE_MAPPED,
        };
        self.route.store(r, Ordering::Relaxed);
    }

    /// Which sweep of the payload is starting. One relaxed store on the
    /// driver thread, once per sweep; the weighing is `band`'s.
    fn slab(&self, index: usize, of: usize) {
        let pair = ((index as u64) << 32) | (of as u64).max(1) & 0xFFFF_FFFF;
        self.slab.store(pair, Ordering::Relaxed);
        // A NEW SWEEP IS A NEW SOLVE, so the arm goes back to unsplit
        // here and this sweep's inverse announces itself again. See
        // [`RepairProgress::arm`] for what a state carried across the
        // boundary would swallow.
        self.arm.store(ARM_NONE, Ordering::Relaxed);
    }

    /// Which arm of the solve is reporting. One relaxed store on the
    /// driver thread, before that arm's first publish; the weighing is
    /// `band`'s.
    ///
    /// The transition is where the three states come from: an inverse
    /// says "split", and a back-substitution says "split" only if an
    /// inverse announced itself in this sweep first. A route that
    /// computes no inverse therefore leaves the state at `ARM_NONE`
    /// and reads the band it always had, which is what keeps the fix
    /// from trading one dead region for another.
    fn solve_arm(&self, arm: nzbkit::par2repair::SolveArm) {
        use nzbkit::par2repair::SolveArm as A;
        let next = match arm {
            A::Inverse => ARM_INVERSE,
            A::BackSub if self.arm.load(Ordering::Relaxed) == ARM_INVERSE => ARM_SPLIT_BACKSUB,
            A::BackSub => ARM_NONE,
        };
        self.arm.store(next, Ordering::Relaxed);
    }

    fn progress(&self, phase: nzbkit::par2repair::RepairPhase, done: u64, total: u64) {
        // The sweep this phase belongs to, read once. Published by the
        // driver before this sweep's first `progress` and not touched
        // again until the next sweep's, so every worker in a sweep
        // weighs against the same frame.
        let sw = self.slab.load(Ordering::Relaxed);
        let (slab, of) = ((sw >> 32) as u32, (sw & 0xFFFF_FFFF) as u32);
        let route = match self.route.load(Ordering::Relaxed) {
            ROUTE_MAPPED => nzbkit::par2repair::RepairRoute::Mapped,
            _ => nzbkit::par2repair::RepairRoute::Disk,
        };
        // The arm this sweep's solve is in, read once and on the same
        // terms as the sweep above: published by the driver before the
        // arm's first `progress` and not touched again until the next
        // arm's.
        let arm = self.arm.load(Ordering::Relaxed);
        let (base, span) = band(phase, slab, of, route, arm);
        let frac = if total == 0 {
            0.0
        } else {
            (done as f64 / total as f64).clamp(0.0, 1.0)
        };
        // The phase pair is stored plainly: it is ABOUT the phase, so a
        // later phase's smaller `done` is correct rather than a step
        // backwards. BEFORE the bar, so a poller that has just seen a
        // new phase finds that phase's own numbers beside it rather
        // than the previous one's.
        self.done.store(done, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
        // One `fetch_max` publishes the phase AND the figure: monotone
        // without the lock the engine has already taken for ordering,
        // and atomic as a pair because that is what a reader reads.
        let pm = ((base + span * frac) * 1000.0).round() as u64;
        let mine = pack(code(phase, route), slab, pm.min(1000));
        // Underscored because only the test build reads it back: the
        // word AFTER this call, which is this call's own unless a later
        // phase had already got there.
        let _published = self.bar.fetch_max(mine, Ordering::Relaxed).max(mine);
        #[cfg(test)]
        self.trace
            .lock()
            .unwrap()
            .push((((_published & 0xFF) as u8), _published >> 32));
        // After the stores, so a reader of the published value sees
        // `fold` for the whole of the park.
        #[cfg(test)]
        self.park_if_held(phase);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nzbkit::par2repair::{ProgressSink, RepairPhase, RepairRoute, SolveArm};

    #[test]
    fn nothing_is_reported_until_a_phase_arrives() {
        let p = RepairProgress::default();
        assert_eq!(
            (p.phase(), p.done(), p.total(), p.permille()),
            (None, 0, 0, 0)
        );
    }

    /// The four phases each land in their own band and the whole-repair
    /// figure climbs through all of them - which is the thing the queue
    /// row could not do and the whole point of this module.
    #[test]
    fn the_four_phases_each_move_their_own_band_of_one_rising_bar() {
        let p = RepairProgress::default();
        let _run = p.enter();
        let mut last = 0;
        for (phase, tok, top) in [
            (RepairPhase::Verify, "verify", 450),
            (RepairPhase::Fold, "fold", 850),
            (RepairPhase::Solve, "solve", 950),
            (RepairPhase::Write, "write", 1000),
        ] {
            p.progress(phase, 0, 100);
            assert_eq!(p.phase(), Some(tok));
            for done in [25u64, 50, 75, 100] {
                p.progress(phase, done, 100);
                assert!(
                    p.permille() >= last,
                    "{tok} at {done}: {} went below {last}",
                    p.permille()
                );
                last = p.permille();
            }
            assert_eq!(p.permille(), top, "{tok} lands on the top of its band");
        }
    }

    /// A slabbed solve re-enters `Solve` from zero. The phase pair goes
    /// back with it - it is about the phase - and the whole-repair bar
    /// must NOT, because a bar that fell from 95% to 85% reads as a
    /// restart.
    #[test]
    fn a_re_entered_phase_does_not_take_the_whole_repair_bar_backwards() {
        let p = RepairProgress::default();
        let _run = p.enter();
        p.progress(RepairPhase::Solve, 50, 50);
        assert_eq!(p.permille(), 950);
        p.progress(RepairPhase::Solve, 0, 50);
        assert_eq!(p.done(), 0, "the phase pair is about the phase");
        assert_eq!(p.permille(), 950, "the whole-repair bar is monotone");
    }

    /// The probe pass and the real pass are separate bars, and the
    /// stretch between two engine calls - the recovery-volume fetch,
    /// which runs under the same `repairing` word - reports no phase at
    /// all rather than the last one it saw.
    #[test]
    fn each_engine_call_is_its_own_bar_and_the_gap_between_them_is_silent() {
        let p = RepairProgress::default();
        {
            let _probe = p.enter();
            p.progress(RepairPhase::Verify, 100, 100);
            assert_eq!(p.permille(), 450);
        }
        assert_eq!(p.phase(), None, "no repair is inside the engine");
        assert_eq!(p.permille(), 0);
        {
            let _real = p.enter();
            p.progress(RepairPhase::Verify, 10, 100);
            assert_eq!(p.phase(), Some("verify"));
            assert_eq!(p.permille(), 45, "not 450 carried over from the probe");
        }
    }

    /// EVERY READING OF THE BAR IS A PAIR THAT WAS PUBLISHED TOGETHER,
    /// while a repair enters, runs and leaves under a reader.
    ///
    /// The property is checked WITHOUT history, on each sample alone:
    /// a per-mille always lies inside its own phase's band (see
    /// [`band`]), so a pair assembled from two moments shows up as a
    /// percentage its phase cannot produce - `("write", 0)`, the end of
    /// an engine call read across [`RepairProgress::clear`], being the
    /// one that a poller draws as a bar that fell to nought while still
    /// naming the last phase. That is what a reader taking two loads
    /// does, and it is why this hammers rather than arranges: the
    /// window is the distance between two instructions. Against the
    /// two-atomic version it trips in milliseconds (4,369 torn samples
    /// in 19,018 over 20,000 runs, 15 Sep 2026); against one word it
    /// cannot trip at all, which is the point.
    ///
    /// # THE READER'S PARTICIPATION IS A PRECONDITION, NOT A HOPE
    ///
    /// A sample only exists while a repair is inside the window, and
    /// the whole hammer is a few milliseconds of relaxed stores, so
    /// "spawn a reader and run the loop" asks the scheduler for a
    /// favour. On the 4 vCPU Windows runner it refused: shard 2/6 of
    /// `windows-unit` failed this test's `samples > 0` guard on
    /// 426505e8 with `the reader never caught the bar at all`,
    /// deterministically, on both nextest attempts (run 35047098102,
    /// 16 Sep 2026) - the reader thread had not been scheduled once
    /// before the writer finished all 20,000 runs and set `stop`. That
    /// is the same starvation the `trace` field and
    /// [`RepairProgress::hold_at_first_fold`] were added for a day
    /// earlier, and it cannot be answered the same way: tearing is a
    /// property of a READ, so a record of what was published cannot
    /// stand in for a reader that looked.
    ///
    /// So both halves are arranged rather than timed, and neither is a
    /// widened tolerance:
    ///
    /// 1. A [`std::sync::Barrier`] holds the writer until the reader
    ///    thread has RUN. Spawn latency can no longer swallow the
    ///    window.
    /// 2. The reader counts its samples into a shared word, and the
    ///    writer keeps the window open past its 20,000 runs until that
    ///    count reaches [`MIN_SAMPLES`] - so the run ends when the
    ///    reader has proved it looked, not when the writer got bored.
    ///
    /// The surviving assertion is therefore `samples >= MIN_SAMPLES`,
    /// which is strictly stronger than the `samples > 0` it replaces:
    /// at the measured 23% per-sample tear rate of the two-atomic
    /// version (4,369 in 19,018), 1,000 samples is a floor that
    /// version cannot clear, where a single sample had a three in four
    /// chance of missing it. The extension is bounded by
    /// [`READER_LIMIT`] so a reader that never runs at all ends the
    /// test with a readable assertion rather than a hung shard, and on
    /// a box where the reader keeps up it runs zero extra iterations,
    /// so the hammer is the same 20,000 it was.
    ///
    /// BOTH HALVES ARE LOAD-BEARING, against different starvations.
    /// Measured on the dev Mac by injecting the latency the runner had,
    /// as a sleep in the reader - the CI red reproduces here as
    /// `caught 0` once the sleep outlasts the hammer (~300 ms in this
    /// debug build, ~40 ms in the archive build that failed):
    ///
    /// ```text
    ///                     reader delayed    reader delayed
    ///                     BEFORE the gate   AFTER the gate
    ///   old shape         FAIL, 0 samples   FAIL, 0 samples
    ///   barrier only      pass              FAIL, 0 samples
    ///   extension only    pass              pass
    ///   SHIPPED (both)    pass              pass
    /// ```
    ///
    /// And the surviving band assertion still has its teeth: pointed at
    /// a mutant `bar()` that takes two loads and recombines them - the
    /// two-atomic reader this module replaced - it trips with 16,954 of
    /// 18,999 readings outside their band, `("write", 0)` among them.
    #[test]
    fn the_published_bar_is_one_value_and_never_a_pair_of_moments() {
        /// Readings the reader must take INSIDE the window before the
        /// run may end. See the note above for why 1,000.
        const MIN_SAMPLES: u64 = 1_000;
        /// The measured hammer, unchanged.
        const RUNS: u32 = 20_000;
        /// How long the writer will hold the window open waiting for a
        /// reader that is not being scheduled. Only ever reached on the
        /// way to a failure.
        const READER_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

        let p = std::sync::Arc::new(RepairProgress::default());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = std::sync::Arc::new(AtomicU64::new(0));
        let bad = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, u64)>::new()));
        // Two parties: the writer does not publish until the reader is
        // past this, so the reader thread has demonstrably run.
        let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
        let reader = {
            let (p, stop, seen, bad, gate) = (
                p.clone(),
                stop.clone(),
                seen.clone(),
                bad.clone(),
                gate.clone(),
            );
            std::thread::spawn(move || {
                gate.wait();
                while !stop.load(Ordering::Relaxed) {
                    if let Some((ph, pm)) = p.bar() {
                        seen.fetch_add(1, Ordering::Relaxed);
                        // One sweep: this hammer publishes phases
                        // directly and announces no slab, so the bands
                        // are the pre-slab ones and the reading must
                        // lie in the phase's own.
                        let disk = nzbkit::par2repair::RepairRoute::Disk;
                        let (base, span) = match ph {
                            "verify" => band(RepairPhase::Verify, 0, 1, disk, ARM_NONE),
                            "fold" => band(RepairPhase::Fold, 0, 1, disk, ARM_NONE),
                            "solve" => band(RepairPhase::Solve, 0, 1, disk, ARM_NONE),
                            "write" => band(RepairPhase::Write, 0, 1, disk, ARM_NONE),
                            other => panic!("unknown phase {other}"),
                        };
                        let (lo, hi) = ((base * 1000.0) as u64, ((base + span) * 1000.0) as u64);
                        if pm < lo || pm > hi {
                            bad.lock().unwrap().push((ph.to_string(), pm));
                        }
                    }
                    std::thread::yield_now();
                }
            })
        };
        let one_run = || {
            let run = p.enter();
            for phase in [
                RepairPhase::Verify,
                RepairPhase::Fold,
                RepairPhase::Solve,
                RepairPhase::Write,
            ] {
                p.progress(phase, 0, 4);
                p.progress(phase, 4, 4);
            }
            drop(run);
            // The record is per REPAIR CALL here, not per test: 20,000
            // runs of eight publishes is 160,000 entries otherwise, for
            // a test that never reads it.
            p.trace.lock().unwrap().clear();
        };
        gate.wait();
        for _ in 0..RUNS {
            one_run();
        }
        // The window stays open until the reader has proved it looked.
        // Zero iterations whenever it kept up, which is every box that
        // schedules it at all; the clock is only consulted here, off
        // the measured hammer, and only bounds a failure.
        let deadline = std::time::Instant::now() + READER_LIMIT;
        while seen.load(Ordering::Relaxed) < MIN_SAMPLES && std::time::Instant::now() < deadline {
            one_run();
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().expect("reader");
        let samples = seen.load(Ordering::Relaxed);
        let bad = bad.lock().unwrap();
        // Failing to find is failing: a reader starved off the box
        // proves nothing, and the assertion below would pass on zero.
        assert!(
            samples >= MIN_SAMPLES,
            "the reader caught {samples} of the {MIN_SAMPLES} readings this \
             property needs, in {READER_LIMIT:?} past {RUNS} runs - it was not \
             being scheduled, so nothing below was actually tested"
        );
        assert!(
            bad.is_empty(),
            "{} of {samples} readings carried a per-mille from outside their own \
             phase's band - the bar was assembled from two moments: {:?}",
            bad.len(),
            &bad[..bad.len().min(8)]
        );
    }

    /// A damaged recovery set in a scratch dir, and the id of the set
    /// in it. Four members over 8 KiB blocks with 25% parity, damaged
    /// one block per member, which is enough fold for the engine to
    /// cross several buckets and free enough to run anywhere.
    fn damaged_set(
        tag: &str,
    ) -> (
        crate::testscratch::ScratchDir,
        [u8; 16],
        Vec<(String, Vec<u8>)>,
    ) {
        let dir = crate::testscratch::ScratchDir::attach(
            &std::env::temp_dir().join(format!("nzbfast-repairprog-{tag}-{}", std::process::id())),
        );
        let files: Vec<(String, Vec<u8>)> = (0..4u8)
            .map(|i| {
                // A deterministic, incompressible-enough payload: the
                // repair reads every byte either way, so what matters
                // is only that two members differ.
                let mut v = vec![0u8; 8_192 * 24];
                let mut x = 0x9E37_79B9u32.wrapping_add(i as u32);
                for b in &mut v {
                    x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    *b = (x >> 24) as u8;
                }
                (format!("member{i}.bin"), v)
            })
            .collect();
        let members: Vec<nzbkit::par2gen::Member> = files
            .iter()
            .map(|(n, d)| {
                std::fs::write(dir.join(n), d).unwrap();
                nzbkit::par2gen::Member {
                    name: n.clone(),
                    path: dir.join(n),
                }
            })
            .collect();
        nzbkit::par2gen::create_into(
            &dir,
            &members,
            "set",
            &nzbkit::par2gen::Par2Spec {
                redundancy_pct: 25,
                block_size: Some(8_192),
            },
        )
        .expect("par2 set written");
        for (n, _) in &files {
            let p = dir.join(n);
            let mut bytes = std::fs::read(&p).unwrap();
            for b in &mut bytes[8_192 * 3..8_192 * 4] {
                *b ^= 0xFF;
            }
            std::fs::write(&p, bytes).unwrap();
        }
        let id = *nzbkit::par2repair::disk_set_ids(&dir)
            .expect("the set is readable")
            .first()
            .expect("one set");
        (dir, id, files)
    }

    fn intact(dir: &std::path::Path, files: &[(String, Vec<u8>)]) -> bool {
        files
            .iter()
            .all(|(n, d)| std::fs::read(dir.join(n)).is_ok_and(|got| got == *d))
    }

    /// THE HEADLINE, end to end from the daemon's own side: the handle
    /// the daemon registers per job, the control it builds from it, the
    /// real engine, a real damaged set - and a queue row that moves
    /// through four phases where it used to read `Repairing, 100%,
    /// timeleft 0:00:00` for the whole fold.
    ///
    /// It goes through `SideCancel` rather than building a
    /// `RepairControl` by hand on purpose. That handle is the one wire
    /// between the delete path and the fold, and a test that assembled
    /// the control itself would pass with the daemon wired to nothing.
    #[test]
    fn a_daemon_repair_moves_a_bar_through_four_phases() {
        let (dir, id, files) = damaged_set("phases");
        let sc = crate::streamhub::SideCancel::new();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, u64)>::new()));
        // Sampled from the sink's own thread through a second sink is
        // not available - the control carries one. So the phases are
        // read the way the QUEUE PAYLOAD reads them, off the published
        // value, from a watcher thread: that is the surface this whole
        // change exists to fill, so it is the surface asserted - for the
        // properties any sample of it must keep. What a sample cannot
        // promise to contain is asserted on the value's own record.
        let watch = {
            let seen = seen.clone();
            let prog = sc.repair_progress().clone();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop2 = stop.clone();
            let h = std::thread::spawn(move || {
                while !stop2.load(Ordering::Relaxed) {
                    // ONE load, through `bar()`. Read as `phase()` and
                    // then `permille()` this samples a value that moves
                    // between the two loads, and the reading it invents
                    // at the end of the run is `("write", 0)` - the
                    // `RepairRun` guard's clear caught in the middle.
                    // That is a fall, so the ordering assertion below
                    // was a coin the box tossed under load rather than
                    // a property of the bar (15 Sep 2026; see the
                    // `bar` field).
                    if let Some((ph, pm)) = prog.bar() {
                        let mut g = seen.lock().unwrap();
                        if g.last().map(|l| (l.0.as_str(), l.1)) != Some((ph, pm)) {
                            g.push((ph.to_string(), pm));
                        }
                    }
                    std::thread::yield_now();
                }
            });
            (stop, h)
        };
        // Read INSIDE the run's scope: `permille` is a high-water mark
        // for the life of the `RepairRun`, and the guard clears it.
        let (status, landed) = {
            let _run = sc.repair_progress().enter();
            let st = nzbkit::par2repair::repair_dir_set_with_donors_controlled_as(
                &dir,
                &id,
                &[],
                nzbkit::par2repair::RetentionCaller::default(),
                sc.repair_control(),
            )
            .expect("the repair runs");
            (st, sc.repair_progress().permille())
        };
        watch.0.store(true, Ordering::Relaxed);
        watch.1.join().expect("watcher");
        assert!(
            matches!(status, nzbkit::par2repair::RepairStatus::Repaired(_)),
            "{status:?}"
        );
        assert!(intact(&dir, &files), "the repair is byte-exact");

        // THE BAR LANDED ON FULL, which only the Write band's own
        // `finish` can reach (see [`band`]) - so the repair went
        // through all four phases and the last of them completed.
        // Asserted from the high-water mark rather than from the
        // poller, because WHICH phases a poller happens to catch is a
        // property of the poller: the write half of a four-block repair
        // is microseconds, and the dashboard polls once a second. That
        // the four phases each report and each land is the engine door's
        // own test (`the_controlled_entry_carries_progress_and_a_cancel_
        // of_its_own`), and that each lands at the top of its band is
        // `the_four_phases_each_move_their_own_band_of_one_rising_bar`
        // above. This test is the third link: the real handle carries
        // them.
        assert_eq!(
            landed, 1000,
            "the bar did not land on full - a fraction that never reaches one reads as \
             a wedge, which is the complaint this whole change answers"
        );

        // IT NEVER WENT BACKWARDS AND THE PHASES ONLY ADVANCED, on two
        // readers: the watcher, which reads the published value the way
        // the queue payload does, and the value's own record of every
        // publish. Both properties hold for ANY subset of the readings,
        // so they are asserted on whatever the watcher caught.
        let order = ["verify", "fold", "solve", "write"];
        let ordered = |who: &str, readings: &[(String, u64)]| {
            let mut last = 0u64;
            let mut at = 0usize;
            for (ph, pm) in readings {
                assert!(
                    *pm >= last,
                    "{who}: the bar fell: {last} -> {pm} in {ph}, {readings:?}"
                );
                last = *pm;
                let Some(i) = order.iter().position(|o| o == ph) else {
                    panic!("{who}: unknown phase {ph} in {readings:?}");
                };
                assert!(
                    i >= at,
                    "{who}: phase {ph} came after {} in {readings:?} - the four only ever advance",
                    order[at]
                );
                at = i;
            }
        };
        let seen = seen.lock().unwrap().clone();
        ordered("watcher", &seen);

        // IT MOVED, and the FOLD was on the bar - the dominant phase of
        // a real repair and the one the queue row could not see at all.
        // Asserted on the COMPLETE record of publishes rather than on
        // the watcher: which readings a sampling thread catches is a
        // property of the scheduler, and on a loaded box it caught none
        // (`RepairProgress::trace`). The record is every value a reader
        // could have read, so this is the watcher's question with the
        // sampling taken out, and all four phases can be demanded of it.
        let mut published: Vec<(String, u64)> = Vec::new();
        for &(code, pm) in sc.repair_progress().trace.lock().unwrap().iter() {
            let ph = order
                .get(usize::from(code).wrapping_sub(1))
                .unwrap_or_else(|| panic!("phase code {code} published"))
                .to_string();
            if published.last() != Some(&(ph.clone(), pm)) {
                published.push((ph, pm));
            }
        }
        ordered("published", &published);
        for ph in order {
            assert!(
                published.iter().any(|(p, _)| p == ph),
                "the {ph} phase was never published: {published:?}"
            );
        }
        assert!(
            published.len() >= 4,
            "{} distinct readings is not a bar that moves: {published:?}",
            published.len()
        );
        // And it is CLEARED when the engine leaves, so the recovery
        // fetches between two passes do not keep showing a stale phase.
        assert_eq!(sc.repair_progress().phase(), None);
        assert_eq!(sc.repair_progress().permille(), 0);
    }

    /// THE OTHER HEADLINE: the Cancel the daemon's delete path presses
    /// ends a running repair.
    ///
    /// `SideCancel::cancel` is what `postproc::cancel_tail_fetches`
    /// calls, so this is the real button on the real handle. Before
    /// 12 Sep 2026 it stopped the recovery fetches and nothing else -
    /// that function's own doc said "A repair already patching bytes
    /// runs to its end and parks".
    ///
    /// WHAT THIS DOES AND DOES NOT PROVE. It presses the button while
    /// the published phase says `fold`, which is the earliest moment a
    /// watcher on the daemon's own side can know the engine is folding,
    /// and the repair is held at the fold's first publish until it has
    /// (`RepairProgress::hold_at_first_fold`), so the press lands before
    /// the first fold batch on any box at any load. That is the fold's
    /// DOOR, not block-by-block inside it - and that is fine here,
    /// because the
    /// DISCRIMINATING test for the in-fold check is the engine's
    /// (`control_tests::a_cancel_raised_mid_fold_ends_the_repair_
    /// before_it_writes`, which trips from inside the sink and asserts
    /// the fold's counter never reached its total). What this one is
    /// for is the wire: that the daemon's handle carries the cancel at
    /// all, that the verdict is `Cancelled` and not a broken set, and
    /// that the directory is re-runnable afterwards.
    #[test]
    fn the_delete_paths_cancel_ends_a_running_repair() {
        let (dir, id, files) = damaged_set("cancel");
        let before: Vec<Vec<u8>> = files
            .iter()
            .map(|(n, _)| std::fs::read(dir.join(n)).unwrap())
            .collect();
        let sc = std::sync::Arc::new(crate::streamhub::SideCancel::new());
        // Pressed from a watcher while the FOLD is running, which is
        // where a timer would be a race on a box of another speed. The
        // repair PARKS at its first Fold publish until the watcher has
        // pressed: a watcher that merely polled for `fold` lost the
        // whole repair to one timeslice on a loaded box and saw it come
        // back `Repaired` (4 of 15 at load ~70 on 32 cores, 15 Sep
        // 2026).
        let pressed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        sc.repair_progress().hold_at_first_fold();
        let h = {
            let sc = sc.clone();
            let pressed = pressed.clone();
            std::thread::spawn(move || {
                // BOUNDED (see `HOLD_LIMIT`), and released on every
                // path, so a fold that never arrives ends the test with
                // a readable assertion rather than a hung shard. The
                // button is pressed on what the daemon can SEE - the
                // published phase - not on the hold's word alone.
                if sc.repair_progress().wait_parked_at_fold()
                    && sc.repair_progress().phase() == Some("fold")
                {
                    sc.cancel();
                    pressed.store(true, Ordering::Relaxed);
                }
                sc.repair_progress().release_fold();
            })
        };
        let err = {
            let _run = sc.repair_progress().enter();
            nzbkit::par2repair::repair_dir_set_with_donors_controlled_as(
                &dir,
                &id,
                &[],
                nzbkit::par2repair::RetentionCaller::default(),
                sc.repair_control(),
            )
            .expect_err("a cancelled repair is not a verdict")
        };
        h.join().expect("watcher");
        assert!(pressed.load(Ordering::Relaxed), "the cancel never fired");
        assert!(
            matches!(err, nzbkit::par2repair::RepairError::Cancelled),
            "a user's Cancel must not be reported as a broken set: {err:?}"
        );
        assert!(sc.repair_cancelled(), "the gate stayed up");
        // Nothing was renamed in and no member is worse than it was -
        // the contract on `RepairError::Cancelled`. Cancelled in the
        // fold, nothing is written at all.
        for ((name, _), was) in files.iter().zip(&before) {
            assert_eq!(&std::fs::read(dir.join(name)).unwrap(), was, "{name}");
        }
        // AND IT IS RE-RUNNABLE, which is the whole of what a cancel
        // owes a user who changes their mind - through a FRESH handle,
        // because the cancelled one is sticky by design.
        let sc2 = crate::streamhub::SideCancel::new();
        let again = nzbkit::par2repair::repair_dir_set_with_donors_controlled_as(
            &dir,
            &id,
            &[],
            nzbkit::par2repair::RetentionCaller::default(),
            sc2.repair_control(),
        )
        .expect("the re-run repairs");
        assert!(
            matches!(again, nzbkit::par2repair::RepairStatus::Repaired(_)),
            "{again:?}"
        );
        assert!(intact(&dir, &files), "the re-run is byte-exact");
    }

    /// A cancelled handle refuses a LATER repair too, without running
    /// it: the latch is sticky, which is what stops a deleted job's
    /// second set from being folded after the first was called off.
    #[test]
    fn a_cancelled_handle_refuses_the_next_set_as_well() {
        let (dir, id, _files) = damaged_set("sticky");
        let sc = crate::streamhub::SideCancel::new();
        sc.cancel();
        let err = nzbkit::par2repair::repair_dir_set_with_donors_controlled_as(
            &dir,
            &id,
            &[],
            nzbkit::par2repair::RetentionCaller::default(),
            sc.repair_control(),
        )
        .expect_err("a cancelled handle does not repair");
        assert!(
            matches!(err, nzbkit::par2repair::RepairError::Cancelled),
            "{err:?}"
        );
    }

    /// The control the daemon hands over is ATTENDED, which is what
    /// lifts the unattended unstructured ceiling for it
    /// (`reconstruct::check_repair_dim_dense`). A half-wired handle
    /// would still repair and would silently stay capped, so this is
    /// pinned rather than left to the engine's own test of the
    /// predicate.
    #[test]
    fn the_handle_the_daemon_registers_builds_an_attended_control() {
        let sc = crate::streamhub::SideCancel::new();
        assert!(sc.repair_control().is_attended());
        assert!(sc.repair_control().is_active());
    }

    /// ONE SWEEP IS THE PRE-SLAB SPLIT, TO THE PER-MILLE. The slab
    /// split is only allowed to change what a SLABBED repair draws, and
    /// almost no repair slabs - so the ordinary DISK-route bar is pinned
    /// against the four figures it had before 16 Sep 2026 rather than
    /// left to be re-derived from [`band`]'s new arithmetic. The route
    /// split (16 Sep 2026, for the mapped self-prove) must leave this
    /// table exactly where it was too, which is what passing
    /// `RepairRoute::Disk` explicitly - rather than a new default -
    /// pins.
    #[test]
    fn a_repair_that_does_not_slab_keeps_the_bar_it_always_had() {
        let disk = nzbkit::par2repair::RepairRoute::Disk;
        for of in [0u32, 1] {
            // `0` is the value before any sweep is announced, and a
            // repair with no blocks to rebuild announces none at all.
            for (phase, top) in [
                (RepairPhase::Verify, 450.0),
                (RepairPhase::Fold, 850.0),
                (RepairPhase::Solve, 950.0),
                (RepairPhase::Write, 1000.0),
            ] {
                let (base, span) = band(phase, 0, of, disk, ARM_NONE);
                assert_eq!(
                    ((base + span) * 1000.0).round(),
                    top,
                    "{phase:?} at of={of} no longer tops out where it did"
                );
            }
        }
    }

    /// THE MAPPED ROUTE'S HEADLINE: `Verify` runs LAST, after `Write`,
    /// carries the 45% a pre-fold pass would have spent, and lands the
    /// bar on full. Until 16 Sep 2026 this route's post-patch self-prove
    /// reported nothing at all - `nzbkit::par2repair::RepairRoute`'s own
    /// doc has the incident this answers.
    #[test]
    fn the_mapped_route_reports_verify_after_write_and_lands_on_full() {
        let p = RepairProgress::default();
        let _run = p.enter();
        p.route(RepairRoute::Mapped);
        let mut last = 0;
        for (phase, tok, top) in [
            (RepairPhase::Fold, "fold", 400),
            (RepairPhase::Solve, "solve", 500),
            (RepairPhase::Write, "write", 550),
            (RepairPhase::Verify, "verify", 1000),
        ] {
            p.progress(phase, 0, 100);
            assert_eq!(p.phase(), Some(tok));
            for done in [25u64, 50, 75, 100] {
                p.progress(phase, done, 100);
                assert!(
                    p.permille() >= last,
                    "{tok} at {done}: {} went below {last}",
                    p.permille()
                );
                last = p.permille();
            }
            assert_eq!(p.permille(), top, "{tok} lands on the top of its band");
        }
    }

    /// A repair that never calls [`ProgressSink::route`] - every disk
    /// call site, and this daemon's own default - reads the disk table,
    /// unchanged by the mapped route existing at all. This is the other
    /// half of the pin above: the DEFAULT must still be `Disk`.
    #[test]
    fn a_repair_that_never_announces_a_route_reads_the_disk_table() {
        let p = RepairProgress::default();
        let _run = p.enter();
        p.progress(RepairPhase::Verify, 100, 100);
        assert_eq!(
            p.permille(),
            450,
            "verify still tops out where the disk route always put it"
        );
    }

    /// ROUTE RESETS WHEN THE ENGINE LEAVES, exactly as `slab` does: a
    /// mapped attempt whose self-prove fails falls back to the disk
    /// driver through a FRESH [`RepairProgress::enter`], and that call
    /// must not read the previous attempt's mapped table.
    #[test]
    fn route_resets_to_disk_when_the_engine_leaves() {
        let p = RepairProgress::default();
        {
            let _run = p.enter();
            p.route(RepairRoute::Mapped);
            p.progress(RepairPhase::Write, 100, 100);
            assert_eq!(
                p.permille(),
                550,
                "write topped out inside the mapped table"
            );
        }
        let _run = p.enter();
        p.progress(RepairPhase::Verify, 100, 100);
        assert_eq!(
            p.permille(),
            450,
            "a fresh engine call read the previous call's mapped table instead of resetting to disk"
        );
    }

    /// THE HEADLINE OF THE SLAB SPLIT. The sequence a 4-slab engine
    /// repair really publishes - recorded from `nzbkit-base`'s own
    /// control tests under `ForcedSlabWidth`, and replayed here through
    /// the daemon's value exactly as the engine makes it - must move the
    /// bar through EVERY sweep.
    ///
    /// Until 16 Sep 2026 it did not: the bands were per repair, so
    /// sweep 1's solve reached 950 and every later sweep was swallowed
    /// by the `fetch_max`. A poller read the literal pair
    /// `("solve", 950)` for 41.5% to 70.3% of the repair's wall
    /// (`research/REPAIR-SLABBED-BAR-2026-09-16.md`), which is the
    /// `Repairing, 100%, timeleft 0:00:00` shape this module exists to
    /// remove.
    ///
    /// The discriminating assertion is the per-sweep one: a bar that
    /// merely rose and landed would pass on the old bands too, because
    /// the verify half and the write half moved it either way.
    #[test]
    fn every_sweep_of_a_slabbed_repair_moves_the_bar() {
        const SLABS: usize = 4;
        let p = RepairProgress::default();
        let _run = p.enter();
        let mut last = 0u64;
        let check = |p: &RepairProgress, last: &mut u64, what: &str| {
            let (_, pm) = p.bar().expect("a repair is inside the engine");
            assert!(pm >= *last, "the bar fell at {what}: {last} -> {pm}");
            *last = pm;
            pm
        };
        p.progress(RepairPhase::Verify, 10_240, 10_240);
        assert_eq!(check(&p, &mut last, "verify"), 450);
        for si in 0..SLABS {
            p.slab(si, SLABS);
            let opened = {
                p.progress(RepairPhase::Fold, 0, 2496);
                check(&p, &mut last, &format!("sweep {si} fold begin"))
            };
            assert_eq!(
                p.phase(),
                Some("fold"),
                "sweep {si} opened its fold and the label did not follow"
            );
            p.progress(RepairPhase::Fold, 2496, 2496);
            let folded = check(&p, &mut last, &format!("sweep {si} fold end"));
            p.progress(RepairPhase::Solve, 0, 4);
            p.progress(RepairPhase::Solve, 4, 4);
            let solved = check(&p, &mut last, &format!("sweep {si} solve end"));
            // THE DISCRIMINATING PAIR: this sweep's fold moved the bar,
            // and so did its solve. On the pre-split bands both were
            // flat for every `si > 0`.
            assert!(
                folded > opened,
                "sweep {si}'s fold did not move the bar: {opened} -> {folded}"
            );
            assert!(
                solved > folded,
                "sweep {si}'s solve did not move the bar: {folded} -> {solved}"
            );
        }
        // The last sweep hands over exactly where the write band starts,
        // so the four sweeps between them spent the whole of [450, 950).
        assert_eq!(last, 950, "the sweeps did not fill their span");
        p.progress(RepairPhase::Write, 256, 256);
        assert_eq!(p.permille(), 1000);
        assert_eq!(p.phase(), Some("write"));
    }

    /// A SWEEP BOUNDARY IS A TIE ON THE PER-MILLE - sweep `i`'s solve
    /// ends on the figure sweep `i+1`'s fold opens at - and the label
    /// must resolve it forwards.
    ///
    /// This is what the sweep index in the packed word buys, and it is
    /// asserted apart from the test above because the cost of getting
    /// it wrong is invisible in a bar that is only read for its number:
    /// the row would say `solve` until the new fold crossed its first
    /// bucket, which is up to 1/256th of a sweep, and on a repair that
    /// slabs a sweep is not a moment.
    #[test]
    fn the_label_crosses_a_sweep_boundary_without_waiting_for_a_bucket() {
        let p = RepairProgress::default();
        let _run = p.enter();
        p.slab(0, 2);
        p.progress(RepairPhase::Solve, 4, 4);
        let (ph, at) = p.bar().unwrap();
        assert_eq!(ph, "solve");
        p.slab(1, 2);
        // The opening publish of the next sweep, and nothing else: no
        // batch has been folded, so the per-mille has not moved.
        p.progress(RepairPhase::Fold, 0, 2496);
        assert_eq!(
            p.bar(),
            Some(("fold", at)),
            "the label did not cross the sweep boundary on the tie"
        );
    }

    /// THE HEADLINE OF THE SOLVE SPLIT (TODO 352). The sequence an
    /// unstructured repair actually makes - inverse, fold,
    /// back-substitution - moves the bar through all three, and the
    /// back-substitution is not swallowed by the arm ahead of it.
    ///
    /// Before this, both arms shared `[0.85, 0.95)`: the inverse walked
    /// it to 950 and every one of the back-substitution's readings lost
    /// the `fetch_max`, so the queue row read `95%` unchanged for
    /// 19.0 s of a 63.7 s repair on the m = 10,000 gapped fixture
    /// (`research/REPAIR-ROW-ACCEPTANCE-2026-09-18.md`).
    ///
    /// Asserted as READINGS THAT MOVE rather than as figures, plus the
    /// three landings, so the split's proportions stay a labelling
    /// choice a later round may re-measure without rewriting the test.
    #[test]
    fn both_solve_arms_move_the_bar_and_the_second_is_not_swallowed() {
        let p = RepairProgress::default();
        let _run = p.enter();
        let mut seen: Vec<(String, u64)> = Vec::new();
        let mut note = |p: &RepairProgress| {
            if let Some((ph, pm)) = p.bar() {
                let now = (ph.to_string(), pm);
                if seen.last() != Some(&now) {
                    seen.push(now);
                }
            }
        };
        p.slab(0, 1);
        p.progress(RepairPhase::Verify, 100, 100);
        note(&p);
        // The fold is SIZED before the inverse announces itself, which
        // is the drivers' real order (`par2repair.rs`: `begin(Fold, ..)`
        // then `Reconstructor::new_controlled`), so the split has to
        // survive one fold reading arriving unsplit.
        p.progress(RepairPhase::Fold, 0, 1000);
        note(&p);

        // ARM 1: the inverse, per matrix column, BEFORE a byte is
        // folded.
        p.solve_arm(SolveArm::Inverse);
        for done in [0u64, 250, 500, 750, 1000] {
            p.progress(RepairPhase::Solve, done, 1000);
            note(&p);
        }
        let after_inverse = p.permille();

        // THE FOLD, between the two arms.
        for done in [250u64, 500, 750, 1000] {
            p.progress(RepairPhase::Fold, done, 1000);
            note(&p);
        }
        let after_fold = p.permille();
        assert!(
            after_fold > after_inverse,
            "the fold did not move the bar past the inverse ({after_fold} vs              {after_inverse}) - an inverse banded ABOVE the feed swallows the whole              fold of an unstructured repair"
        );

        // ARM 2: the back-substitution, in fold units, after the feed.
        p.solve_arm(SolveArm::BackSub);
        let mut moves = 0;
        for done in [0u64, 40, 80, 120, 160] {
            p.progress(RepairPhase::Solve, done, 160);
            if p.permille() > after_fold {
                moves += 1;
            }
            note(&p);
        }
        assert!(
            moves >= 3,
            "the back-substitution moved the bar {moves} time(s) past where the fold              left it - this is the arm that used to be swallowed whole"
        );
        assert_eq!(
            p.permille(),
            950,
            "the back-substitution still lands exactly where `Solve` always landed"
        );
        p.progress(RepairPhase::Write, 100, 100);
        note(&p);
        assert_eq!(p.permille(), 1000);

        // MONOTONE THROUGHOUT. Not STRICTLY: a band boundary is a tie
        // by construction - the phase below lands on the per-mille the
        // phase above opens at, so `(fold, 850)` is followed by
        // `(solve, 850)` and only the LABEL changes. What the freeze
        // broke is a bar that stands still while the work goes on, and
        // the stretches below are where that is asserted.
        for w in seen.windows(2) {
            assert!(w[1].1 >= w[0].1, "the bar went backwards: {seen:?}");
        }
        // A DRAWN PERCENTAGE FOR EVERY STRETCH. The dashboard draws
        // `Math.round(pct)` and the phase word alone, so a stretch of
        // the repair that publishes inside one whole percent is a
        // stretch the row cannot show at all. Both arms and the fold
        // must each cross several.
        let drawn = |lo: u64, hi: u64| hi / 10 - lo / 10;
        assert!(
            drawn(450, after_inverse) >= 5
                && drawn(after_inverse, after_fold) >= 5
                && drawn(after_fold, 950) >= 5,
            "one of the three stretches is too narrow to draw: 450 -> {after_inverse}              -> {after_fold} -> 950"
        );
    }

    /// AND THE OTHER HALF OF IT: a solve that announces only the
    /// back-substitution - every structured route, which computes no
    /// inverse at all - reads exactly the band it always had.
    ///
    /// This is what keeps the fix from trading one dead region for
    /// another. A split reserved unconditionally would hand the
    /// inverse's share of the bar to an arm that never runs on the
    /// common route, and the fold would then jump over it.
    #[test]
    fn a_solve_with_no_inverse_behind_it_keeps_the_band_it_always_had() {
        let p = RepairProgress::default();
        let _run = p.enter();
        p.slab(0, 1);
        p.solve_arm(SolveArm::BackSub);
        p.progress(RepairPhase::Fold, 100, 100);
        assert_eq!(p.permille(), 850, "the fold still tops out at 850");
        p.progress(RepairPhase::Solve, 0, 160);
        assert_eq!(p.permille(), 850, "and the solve still opens there");
        p.progress(RepairPhase::Solve, 160, 160);
        assert_eq!(p.permille(), 950);
    }

    /// THE ARM IS PER SWEEP. A slabbed unstructured repair recomputes
    /// its inverse inside every sweep, so the state must go back to
    /// unsplit at the sweep boundary: carried over, sweep 2's
    /// fold-opening publish would sit at the TOP of the band its own
    /// inverse is about to report from, and the monotone bar would
    /// swallow that inverse exactly as it used to swallow the
    /// back-substitution.
    #[test]
    fn a_new_sweep_starts_unsplit_so_its_own_inverse_is_not_swallowed() {
        let p = RepairProgress::default();
        let _run = p.enter();
        let sweep = |i: usize| {
            p.slab(i, 2);
            p.progress(RepairPhase::Fold, 0, 100);
            let opened = p.permille();
            p.solve_arm(SolveArm::Inverse);
            p.progress(RepairPhase::Solve, 0, 100);
            let inverse_at = p.permille();
            p.progress(RepairPhase::Solve, 100, 100);
            let inverse_top = p.permille();
            p.progress(RepairPhase::Fold, 100, 100);
            p.solve_arm(SolveArm::BackSub);
            p.progress(RepairPhase::Solve, 100, 100);
            (opened, inverse_at, inverse_top)
        };
        for i in 0..2 {
            let (opened, inverse_at, inverse_top) = sweep(i);
            assert_eq!(
                opened, inverse_at,
                "sweep {i}'s inverse opened above the fold's own opening, so the readings                  below its top are swallowed"
            );
            assert!(
                inverse_top > inverse_at,
                "sweep {i}'s inverse did not move the bar at all"
            );
        }
        assert_eq!(p.permille(), 950, "the last sweep still lands on 950");
    }

    /// A phase whose total was an estimate must not report over 100%.
    #[test]
    fn an_overrunning_phase_clamps_at_its_band() {
        let p = RepairProgress::default();
        let _run = p.enter();
        p.progress(RepairPhase::Write, 500, 100);
        assert_eq!(p.permille(), 1000);
        p.progress(RepairPhase::Verify, 0, 0);
        assert_eq!(p.permille(), 1000, "and a zero total is not a division");
    }
}
