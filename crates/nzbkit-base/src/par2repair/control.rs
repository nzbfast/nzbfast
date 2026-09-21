//! What a repair tells a caller WHILE it runs, and how a caller stops it.
//!
//! One subject per file, the way `survey` is the pre-fold handshake's:
//! this is the half of a repair that happens AFTER the caller has said
//! `Repair` and before the verdict comes back - the half that used to be
//! silent. Until 12 Sep 2026 there was no counter, no channel and no
//! token anywhere under `par2*` past [`AfterSurvey`](super::AfterSurvey):
//! a progress bar stopped moving when the verify half ended and sat
//! there for the whole fold, a Cancel pressed mid-fold waited for the
//! repair, and the daemon's own warn line said so out loud ("nothing
//! reports progress while it runs").
//!
//! # The three things this carries, and why they are shaped differently
//!
//! **Progress is a COUNTER, not an event.** The fold is the hot path of
//! this product: a sink call per row would be a store per row at
//! millions of rows, which is exactly the kind of instrumentation that
//! shows up as a benchmark regression and gets ripped out again. So a
//! worker bumps a relaxed [`AtomicU64`] per BATCH - a fold unit, a
//! block, a member - and `RepairControl::step` calls the sink only
//! when the count crosses one of `STEPS` buckets. Over a whole phase
//! the sink is called at most `STEPS` times however many batches there
//! were, and the per-batch cost is one relaxed add plus two multiplies.
//!
//! **Cancel is an ATOMIC, polled at the same sites.** It has to be free
//! to read from inside a worker, and it is read far more often than it
//! is written, so it is its own `AtomicBool` and every poll is a relaxed
//! load. Sticky: nothing clears it.
//!
//! **Pause PARKS, and parks OUTSIDE any scope the engine owns.** A
//! condvar, because a paused repair must cost nothing. The rule about
//! WHERE it may park is the load-bearing half - see [`PauseGate`].
//!
//! # Nothing here is reached unless a caller asks for it
//!
//! A [`RepairControl::default()`] has no sink, no gate and a cancel flag
//! that no one can set, and every hook is `if let Some(..)` over those.
//! The twelve call sites that reach the repair driver without an
//! observer take that value and pay a predictable branch per batch. The
//! control is fetched from the observer ONCE, at the top of the repair,
//! through [`SurveyObserver::control`](super::SurveyObserver::control) -
//! which is defaulted, so `crates/parfast`, the daemon and every impl
//! written before this module existed are unchanged and opt in when they
//! want it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// How many times a sink hears about one phase, at most.
///
/// 256 is a bar wide enough to look continuous at any window size and
/// small enough that the sink's own cost - a lock, a snapshot write, a
/// host wake - cannot matter beside a fold. A caller that wants finer
/// granularity wants a different progress model, not a bigger number:
/// the bump is per BATCH, and batches are what the engine actually has.
const STEPS: u64 = 256;

/// Which part of a repair is running.
///
/// The four are distinguished because their COSTS are unrelated and a
/// single bar over all of them would move at four different speeds
/// without saying why. Each phase reports its own `(done, total)` in its
/// own units, named on the variant; a caller that wants one bar decides
/// the weights, because only a caller knows what its user is waiting on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RepairPhase {
    /// Hashing the members off disk, in BYTES of declared member length.
    /// This is the half a survey already reports per member; the counter
    /// is here so a caller that never surveys (the daemon) still has it.
    Verify,
    /// Feeding present and adopted blocks into the syndrome fold, in
    /// BYTES fed. The dominant phase of an ordinary repair, and the one
    /// the whole of this module exists for.
    Fold,
    /// The back-substitution, in fold UNITS (cache-sized cells of the
    /// destination grid) for the dense arm and matrix COLUMNS for the
    /// Gauss-Jordan inverse ahead of it. Not bytes: what the solve
    /// sweeps is a matrix, and pretending otherwise would make the bar
    /// disagree with itself between the two arms.
    Solve,
    /// Writing repaired bytes to the targets, in BYTES written.
    Write,
}

impl RepairPhase {
    /// A short lowercase name, for a caller that logs rather than draws.
    pub fn as_str(self) -> &'static str {
        match self {
            RepairPhase::Verify => "verify",
            RepairPhase::Fold => "fold",
            RepairPhase::Solve => "solve",
            RepairPhase::Write => "write",
        }
    }
}

/// Which repair route is reporting - see `nzbfast_core::repairprog::band`.
///
/// The two drivers earn their proof of a member's bytes at different
/// points in the call: the disk driver hashes from disk BEFORE the fold
/// (`RepairPhase::Verify`), the mapped in-stream driver has no such pass
/// - its present-block ledger was earned off the wire - so its only
/// proof is the self-prove AFTER the patch, reported under the same
/// `RepairPhase::Verify` code because it is the same kind of claim ("these
/// bytes check out"), just made at the opposite end of the call. A band
/// table that draws one bar has to know which end it is, or a mapped
/// self-prove publishes a per-mille sized for a phase that runs first and
/// a monotone bar discards it - see the `self_prove_set` call in
/// `super::repair_mapped_inner` for the incident this answers.
///
/// Announced from the driver thread ONCE, before any phase begins - the
/// same contract as [`ProgressSink::slab`]. DEFAULTED to [`Disk`](Self::Disk):
/// a sink that is never told otherwise - every disk-driver call site,
/// and every sink written before this existed - keeps exactly the
/// reading it always had.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RepairRoute {
    /// The disk driver: a pre-fold `Verify`, then `Fold`, `Solve`, `Write`.
    #[default]
    Disk,
    /// The mapped in-stream driver: `Fold`, `Solve`, `Write`, then a
    /// post-patch `Verify` - the self-prove.
    Mapped,
}

/// Which arm of [`RepairPhase::Solve`] is reporting.
///
/// The phase is entered TWICE within one sweep on the unstructured
/// (Gauss-Jordan) route, in two different units and on opposite sides
/// of the fold: the m x m inverse reports per matrix COLUMN before a
/// block is read, and the back-substitution reports in fold UNITS after
/// the feed is in. A caller weighing the phases into one bar cannot
/// tell them apart from the `progress` calls alone - both say `Solve` -
/// so it gave them one band, the first arm walked it to the top and the
/// monotone bar swallowed the second whole. Measured 18 Sep 2026 on the
/// m = 10,000 gapped fixture: the queue row read `95%` unchanged for
/// 19.0 s of a 63.7 s repair
/// (`research/REPAIR-ROW-ACCEPTANCE-2026-09-18.md`, TODO 352).
///
/// Announced from the DRIVER thread, before that arm's own
/// `RepairControl::begin` and never concurrently with a `progress`
/// call - the same contract as [`ProgressSink::slab`] and
/// [`ProgressSink::route`]. A route that has no inverse to compute
/// (every structured selection: Forney, the progression arms) announces
/// [`BackSub`](Self::BackSub) alone, and a sink that hears only that one
/// must keep exactly the single band it always had, or the arm that
/// never runs leaves a dead region where the freeze used to be.
///
/// # Why this is not a fifth `RepairPhase`
///
/// "Rebuilding the missing blocks" is the honest sentence for both
/// arms, and a user waiting on a repair does not care which matrix
/// operation is running. A phase of its own would cost a new word in
/// 16 locales to say something nobody asked. What the caller needs is
/// not a new name, it is the FRAME - which is what this is, the same
/// way `slab` is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolveArm {
    /// The Gauss-Jordan inverse of the explicit m x m, per matrix
    /// COLUMN. Runs BEFORE the fold - `Reconstructor::new_controlled`
    /// builds the back-substitution the feed will pour into - so a band
    /// table that places it after the fold puts the whole feed below
    /// something already published and a monotone bar discards it.
    Inverse,
    /// The back-substitution, in fold UNITS. Runs after the feed, where
    /// `RepairPhase::Solve` has always been placed.
    BackSub,
}

/// Where a repair's progress goes.
///
/// `Send + Sync` and `&self`, because it is called from worker threads -
/// the fold's readers, the solve's unit drain - and never from one
/// place. An implementation must be CHEAP and must not block: it runs
/// on a thread that is doing the repair, and `STEPS` bounds how often
/// it is called but not what it does when it is. Publishing into a
/// mutex-guarded snapshot and waking a host is the shape this was built
/// for.
///
/// `total` is the phase's whole, known when the phase starts; `done` is
/// monotone within a phase and both are in that phase's units (see
/// [`RepairPhase`]). A phase may be entered more than once - a slabbed
/// solve folds once per slab - and the counter is reset at each entry,
/// so a caller must not assume `done` never goes backwards ACROSS calls
/// with the same phase.
pub trait ProgressSink: Send + Sync {
    /// `done` of `total` units of `phase`, called from a repair
    /// thread. The only required method. Do cheap work here and hand
    /// the numbers to a host - see the type doc for what the counters
    /// do and do not promise.
    fn progress(&self, phase: RepairPhase, done: u64, total: u64);

    /// WHICH ROUTE IS REPORTING - see [`RepairRoute`].
    ///
    /// DEFAULTED, like [`slab`](Self::slab) - but NOT for the same
    /// reason, since 17 Sep 2026 narrowed that one: a sink that draws
    /// one bar per phase and does not place `Verify` differently by
    /// route (`parfast`'s `Meter`, every test sink here) is correct
    /// ignoring THIS one. Implement it only if a band table needs to
    /// tell a pre-fold `Verify` from a post-patch one.
    fn route(&self, _route: RepairRoute) {}

    /// WHICH SWEEP OF THE PAYLOAD IS STARTING, `index` of `of`.
    ///
    /// A solve whose window does not fit the memory budget is cut along
    /// the block's byte axis and the payload is swept once per slab
    /// (`reconstruct::plan_slabs`), so Fold and Solve are each entered
    /// `of` times. Announced from the DRIVER thread at the top of each
    /// sweep, before that sweep's [`RepairPhase::Fold`] `progress`, and
    /// never concurrently with one. A repair that does not slab
    /// announces `(0, 1)` once; one with no blocks to rebuild announces
    /// nothing, and `(0, 1)` is the right reading of that too.
    ///
    /// DEFAULTED, so this is not a break: a sink that RECORDS the calls
    /// (every test sink here) is correct ignoring it.
    ///
    /// It named `parfast`'s `Meter` as the other such case - "a sink
    /// that draws one bar per phase ... is correct ignoring it" - and
    /// that was WRONG, corrected 17 Sep 2026. Drawing one bar per phase
    /// does not excuse a caller from the frame; it only changes how the
    /// frame is spent. Starting a phase's bar over at each sweep is not
    /// a neutral simplification of a slabbed repair, because the
    /// REFERENCE spans its own memory passes with one bar: par2cmdline
    /// at `-m1` prints `Repairing:` once, 0.1% to 100.0%, strictly
    /// monotone, over a payload it demonstrably re-read per pass
    /// (measured, and the figures are on `parfast`'s `Meter`). A
    /// drop-in that resets per sweep therefore reports something the
    /// tool it replaces never reports, on fragments a queue scraper
    /// reads. `Meter` implements this now, banding each phase's own bar
    /// into the frame.
    ///
    /// So ignore it only if your caller neither DRAWS nor DERIVES a
    /// fraction from these calls. If it does either, a slab is
    /// something your bar has to be able to say.
    ///
    /// # Why a caller that weighs the phases NEEDS this
    ///
    /// It cannot be inferred. A sink can count re-entries and so knows
    /// the INDEX, but not `of` - and a weighted bar has to reserve the
    /// headroom for sweeps 2..N before sweep 1 has used it up, or it
    /// must take the bar backwards to make room, which is the fall this
    /// whole channel's callers refuse. Until 16 Sep 2026 the daemon's
    /// bar froze at the literal pair `("solve", 950)` for 41.5% to 70.3%
    /// of a slabbed repair's wall for exactly that reason
    /// (`research/REPAIR-SLABBED-BAR-2026-09-16.md`).
    fn slab(&self, _index: usize, _of: usize) {}

    /// WHICH ARM OF THE SOLVE IS REPORTING - see [`SolveArm`].
    ///
    /// DEFAULTED, for the narrow reason [`route`](Self::route) is and
    /// not the wider one [`slab`](Self::slab) had: a sink that draws
    /// one bar per phase sees the two arms as one phase entered twice,
    /// which is what they are, and is correct ignoring this. Implement
    /// it only if a band table weighs `Solve` into a shared bar, where
    /// giving both arms one band means the second is swallowed whole.
    fn solve_arm(&self, _arm: SolveArm) {}
}

/// A `Fn` is a sink, so a caller that only wants a closure stays one.
/// It hears `progress` and takes the default `slab`, which is the whole
/// point of that method being defaulted.
impl<F: Fn(RepairPhase, u64, u64) + Send + Sync> ProgressSink for F {
    fn progress(&self, phase: RepairPhase, done: u64, total: u64) {
        self(phase, done, total)
    }
}

/// The two bits [`PauseGate`] is.
#[derive(Debug, Default, Clone, Copy)]
struct GateState {
    /// STICKY: nothing clears it. A cancelled repair stays cancelled.
    cancelled: bool,
    paused: bool,
}

/// Park a repair while a caller holds it, and let a caller call it off.
///
/// # Where it may park, which is the whole of the design
///
/// THE RULE: never park while holding work another thread could take,
/// and never while holding a lock. That is the general form of memory
/// topic `nzbfast-rayon-scope-owner-must-not-park` - parking a thread
/// that owns pool work starves the pool it is holding, and a 32-core
/// box does not show it. The engine's fold pool is
/// `std::thread::scope` rather than rayon, but the failure is the same.
///
/// Applied, that admits exactly two kinds of site and refuses a third.
///
/// **The driver's own boundaries** - between the verify pass and the
/// fold, between two slabs of a slabbed solve, before the patch opens
/// its first destination. Nothing is held at any of them.
///
/// **The feed's reader loop**, between two blocks. A reader owns a
/// STATIC, DISJOINT chunk of the work list (`work.chunks(chunk)`), so
/// there is no other thread that could have taken the block it is
/// holding; its Feeder is its own; it holds no lock; and the fold
/// worker keeps draining the channel while it sleeps. A parked reader
/// stalls its own chunk and nothing else, which is what pause means.
/// This is the site that matters, because the feed is most of an
/// ordinary repair's wall.
///
/// **NOT the solve's unit drain** (`linalg::fold_parallel`). Those
/// units are a SHARED work-stealing queue: a worker that parked holding
/// a popped unit would hold a piece of work every other worker is
/// looking for, and on a grid sized to the core count that is the whole
/// fold stopped behind one sleeper with nothing gained - the driver's
/// boundary either side of the solve already holds the repair. The unit
/// drain polls CANCEL, which costs a relaxed load and never blocks.
///
/// So a pause pressed during the SOLVE takes effect at the end of it
/// rather than inside it. Cancel has no such delay anywhere.
///
/// # A pool worker CAN park before it claims, and a create's does
///
/// The refusal above is about a worker HOLDING a popped unit, not about
/// pool workers as a class. `par2gen`'s transform workers claim stripes
/// off a shared counter exactly as the solve claims units, and they
/// park - at the top of the loop, BEFORE the `fetch_add`, where a
/// worker has finished its last stripe and taken no next one and so
/// holds nothing at all. Read against this rule that site is admitted,
/// and the solve's still is not.
///
/// The reason `par2gen` needed it and the solve does not is stated in
/// full in `par2gen::control`: a repair's solve is a stage between
/// other stages that the driver's boundaries already bound, where a
/// create's transform IS the create - 10.73 s of a measured 12.85 s
/// run - so "at the end of it" left a create with no park point
/// anywhere in its arithmetic and a Pause that did nothing at all.
/// Before applying this rule to a new pool, ask which of the two shapes
/// the site is: does the poll happen while the worker holds work, or
/// between two pieces of it?
///
/// # Why the state is under the MUTEX and `cancelled` is ALSO an atomic
///
/// The condvar needs the mutex anyway, and the wait loop must open on a
/// terminating check that reads the GUARD - a loop whose opening check
/// reads something the guard does not name is the shape
/// `tools/wait-recheck-gate.py` refuses to classify, and it is right to:
/// a reader cannot tell what ends such a loop. So `cancelled` is a field
/// of `GateState` and [`gate`](Self::gate) opens on it, exactly as
/// `parfast_session::runner::Control::gate` does.
///
/// `hot` is a WRITE-THROUGH MIRROR of that field and
/// nothing else. It is written only under the lock, by the one function
/// that writes the field; it is read only by [`RepairControl::cancelled`],
/// which is polled per fold unit and per written block by every worker
/// at once, where taking a mutex would put every one of them on one
/// cache line for no reason. The wait loop never reads it. That is the
/// whole of the contract, and it is why this is not the second copy of a
/// truth the `Control` doc warns against: there is one writer, under one
/// lock, and the mirror is never the thing anybody decides on.
#[derive(Debug, Default)]
pub struct PauseGate {
    state: Mutex<GateState>,
    wake: Condvar,
    /// See the type doc: a read-only mirror of `GateState::cancelled`
    /// for the hot polls.
    hot: AtomicBool,
    /// The same mirror for `cancelled || paused` - "a hot loop must stop
    /// and ask". It exists so a site that honours BOTH controls still
    /// costs one relaxed load in the common case, where taking the
    /// mutex per block across eight reader threads would not be free.
    held: AtomicBool,
}

impl PauseGate {
    /// An open gate: not paused, not cancelled. Shared, because both
    /// the repair threads and whoever drives the controls hold it.
    pub fn new() -> Arc<PauseGate> {
        Arc::new(PauseGate::default())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Call the repair off. Sticky, and it wakes a parked repair: a
    /// cancel while paused must take effect now, not at the resume
    /// nobody is going to press.
    pub fn cancel(&self) {
        let mut st = self.lock();
        st.cancelled = true;
        // Under the lock, and this is the ONLY writer - see the type doc.
        self.hot.store(true, Ordering::Relaxed);
        self.held.store(true, Ordering::Relaxed);
        drop(st);
        self.wake.notify_all();
    }

    /// Park the repair at the next gate point, or release it. NOT
    /// sticky, unlike [`Self::cancel`], and it cannot un-cancel: a
    /// cancelled gate stays cancelled whatever is set here.
    pub fn set_paused(&self, paused: bool) {
        let mut st = self.lock();
        st.paused = paused;
        self.held
            .store(st.paused || st.cancelled, Ordering::Relaxed);
        drop(st);
        self.wake.notify_all();
    }

    /// Has [`Self::cancel`] been called? One relaxed load off the hot
    /// mirror, so a per-block loop can afford to ask.
    pub fn is_cancelled(&self) -> bool {
        self.hot.load(Ordering::Relaxed)
    }

    /// `cancelled || paused`, from the mirror - the one relaxed load a
    /// hot loop pays to honour both controls.
    fn held(&self) -> bool {
        self.held.load(Ordering::Relaxed)
    }

    /// Is the repair parked? `false` once cancelled, because a
    /// cancelled repair is not waiting for a resume - a caller drawing
    /// a "Paused" badge off this must not keep drawing it after
    /// Cancel.
    pub fn is_paused(&self) -> bool {
        let st = *self.lock();
        st.paused && !st.cancelled
    }

    /// Block while paused; answer `false` once cancelled.
    ///
    /// See the type doc for where this may be called from.
    pub fn gate(&self) -> bool {
        let mut guard = self.lock();
        loop {
            if guard.cancelled {
                return false;
            }
            if !guard.paused {
                return true;
            }
            guard = self.wake.wait(guard).unwrap_or_else(|p| p.into_inner());
        }
    }
}

/// One phase's counter: the `(done, total)` a [`ProgressSink`] is told
/// about, and how often it is told.
///
/// # Why the sink call is under a lock and the counter is not
///
/// `done` is bumped by every worker and must stay lock-free - that is
/// the whole cost argument. But a bar that goes BACKWARDS is a defect
/// the contract must not have, and the two halves of a report (bump the
/// counter, tell the sink) cannot be made atomic by an atomic: two
/// workers that bump to 3,520 and 4,032 can reach the sink in the other
/// order, and the host draws 4,032 and then 3,520. That is not
/// hypothetical - it is what this test fixture did on its first run,
/// every time.
///
/// So `reported` is a MUTEX holding the last bucket announced, the sink
/// is called while it is held, and the value announced is `done` read
/// FRESH under that lock. `done` only ever grows, so reports taken in
/// lock order are in value order. The lock is reached at most [`STEPS`]
/// times per phase, which is what makes it free: a fold unit's bump
/// touches only `hint`.
///
/// `hint` is the lock-free pre-filter - the last announced bucket
/// again, relaxed - so the common step is one `fetch_add`, one load and
/// a compare, and never a lock.
#[derive(Debug, Default)]
struct Meter {
    done: AtomicU64,
    total: AtomicU64,
    hint: AtomicU64,
    reported: Mutex<u64>,
}

/// A caller's standing veto on a LONG repair, and what it saw when it
/// used it.
///
/// TODO 332. The engine already works out, at the survey point, that a
/// repair is the shape worth warning about
/// ([`RepairForecast::is_long`](super::RepairForecast::is_long)) and
/// says so in the log before a byte is written. A DAEMON needs to be
/// able to act on that rather than only print it: the ruling of 8 Sep
/// 2026 is that it must never block on a question nobody may be there
/// to answer, but that it may push the job to the back of the queue
/// ONCE so the person has a chance to see the notice and back out.
///
/// # Why it rides on the control rather than on the observer
///
/// The observer handshake ([`SurveyObserver`](super::SurveyObserver))
/// can already refuse a repair, and it is the right door for a CLI: a
/// `parfast` run is a person at a terminal, and `AfterSurvey::Stop`
/// means "this process is done with this set". It is the wrong door for
/// the daemon for two reasons. A stop is spelled `NoDamage` on every
/// entry but the surveying one, which would tell the tail the set
/// verifies when it does not; and the daemon's repair sites reach the
/// driver through four different entry points, three of which pass the
/// trivial always-`Repair` observer the controlled doors build for
/// them, so there is no observer of the daemon's own to hang anything
/// on. The control is the one value every entry already takes.
///
/// WHICH SITES OPT IN IS THE CALLER'S BUSINESS, not this type's: a gate
/// reaches the driver only where a caller puts one on the control it
/// passes. Today that is exactly one site (`nzbfast`'s download disk
/// repair), and the four others are unchanged - the argument for the
/// narrowness is at that call, because it is an argument about jobs and
/// queues rather than about repairs.
///
/// The verdict is `RepairError::Deferred`(super::RepairError::
/// Deferred) and NOT a status, for the same reason
/// [`RepairError::Cancelled`](super::RepairError::Cancelled) is an
/// error: the set was not repaired and the caller must not read the
/// return as a set that was fine.
///
/// # ARMED, then FIRED, and never armed again by the engine
///
/// `arm` is the caller saying "the setting is on AND this job has not
/// been deferred yet" - the engine holds no policy and cannot work out
/// either half. Firing DISARMS, so one armed gate can stop at most one
/// repair however many recovery sets a run walks. The once-only
/// property across RUNS is the caller's: it is the caller that decides
/// not to arm the gate the second time round, from a mark it kept on
/// the job. The engine's half is deliberately the smaller one.
#[derive(Debug, Default)]
pub struct DeferGate {
    armed: AtomicBool,
    fired: AtomicBool,
    /// The forecast it fired on, so the caller can say WHY in the
    /// notice it shows. Only meaningful once `fired` is set.
    blocks: AtomicU64,
    est_secs: AtomicU64,
}

/// What a fired [`DeferGate`] saw - the forecast the repair would have
/// run, for the caller's notice. An order of magnitude, never a
/// countdown: see `RepairForecast::est_secs`(super::RepairForecast::
/// est_secs), which is fitted to two points on one box.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeferredRepair {
    /// Blocks the survey found missing - the figure a notice should
    /// quote, since it is measured rather than fitted.
    pub missing_blocks: u64,
    /// `0` where the shape is one nobody has measured.
    pub est_secs: u64,
}

impl DeferGate {
    /// An armed gate. There is no disarmed constructor on purpose: a
    /// caller that does not want the veto passes no gate at all, and
    /// the inert control is then byte-for-byte the one it had before.
    pub fn armed() -> Arc<DeferGate> {
        let g = DeferGate::default();
        g.armed.store(true, Ordering::Relaxed);
        Arc::new(g)
    }

    /// What this gate stopped, or `None` if it never fired.
    pub fn fired(&self) -> Option<DeferredRepair> {
        self.fired.load(Ordering::Acquire).then(|| DeferredRepair {
            missing_blocks: self.blocks.load(Ordering::Relaxed),
            est_secs: self.est_secs.load(Ordering::Relaxed),
        })
    }

    /// The engine's half: is THIS forecast one the caller wants to
    /// stand back from? Fires (and disarms) when it is.
    fn consider(&self, f: &super::RepairForecast) -> bool {
        if !f.is_long() || !self.armed.swap(false, Ordering::AcqRel) {
            return false;
        }
        self.blocks
            .store(f.missing_blocks as u64, Ordering::Relaxed);
        self.est_secs
            .store(f.est_secs.unwrap_or(0), Ordering::Relaxed);
        // Release LAST: `fired()` reads the two fields above after an
        // acquire load of this one, so a reader that sees the flag sees
        // the forecast that set it.
        self.fired.store(true, Ordering::Release);
        true
    }
}

/// Progress out, cancel in, pause parked - as one cheap, clonable value.
///
/// Cloning is two `Arc` bumps at most; a default one is three `None`s
/// and costs nothing to carry. See the module doc.
#[derive(Clone, Default)]
pub struct RepairControl {
    sink: Option<Arc<dyn ProgressSink>>,
    gate: Option<Arc<PauseGate>>,
    /// One meter per phase, in `RepairPhase` order. `Arc` because the
    /// control is cloned into worker closures and they all count into
    /// the same totals.
    meters: Option<Arc<[Meter; 4]>>,
    /// THE ONE PHASE THIS VIEW MAY REPORT, if it is a narrowed one -
    /// see [`RepairControl::reporting_only`]. `None` is a full control
    /// and the default.
    only: Option<RepairPhase>,
    /// The caller's standing veto on a long repair - see [`DeferGate`].
    /// `None` on every control that has not asked for one, which is
    /// every control there was before TODO 332 and every CLI control
    /// still.
    defer: Option<Arc<DeferGate>>,
}

impl std::fmt::Debug for RepairControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepairControl")
            .field("sink", &self.sink.is_some())
            .field("gate", &self.gate.is_some())
            .finish()
    }
}

impl RepairControl {
    /// A control that reports to `sink` and is stopped through `gate`.
    /// Either half may be left out: `None` for the sink is a cancel-only
    /// control, `None` for the gate is a report-only one.
    pub fn new(sink: Option<Arc<dyn ProgressSink>>, gate: Option<Arc<PauseGate>>) -> RepairControl {
        let any = sink.is_some() || gate.is_some();
        RepairControl {
            sink,
            gate,
            meters: any.then(|| Arc::new(std::array::from_fn(|_| Meter::default()))),
            only: None,
            defer: None,
        }
    }

    /// This control with a long-repair veto on it - see [`DeferGate`].
    ///
    /// A builder rather than a third argument to [`new`](Self::new),
    /// because the veto is orthogonal to both halves of the attended
    /// pair and every existing caller would otherwise have to type
    /// `None` to say nothing. It does NOT make a control active: a
    /// caller holding a gate and nothing else can still stop a repair
    /// before it starts, and `is_active`/`is_attended` go on meaning
    /// exactly what they meant.
    #[must_use]
    pub fn with_defer(mut self, defer: Option<Arc<DeferGate>>) -> RepairControl {
        self.defer = defer;
        self
    }

    /// Does the caller want to stand back from THIS repair? Asked once
    /// per attempt, at the survey point, before anything is written.
    pub(crate) fn defer_long(&self, f: &super::RepairForecast) -> bool {
        self.defer.as_ref().is_some_and(|d| d.consider(f))
    }

    /// The error a fired veto unwinds with, carrying the forecast it
    /// stood back from - what the driver returns the instant
    /// [`defer_long`](Self::defer_long) has answered true.
    ///
    /// Reads the gate back rather than being handed the forecast,
    /// because the gate is the thing the CALLER will read too (it holds
    /// the same two numbers for the notice it shows), so there is one
    /// place those numbers come from. `defer_long` answering true is
    /// the only thing that sets them, so the default is unreachable.
    pub(crate) fn deferred_error(&self) -> super::RepairError {
        let d = self
            .defer
            .as_ref()
            .and_then(|g| g.fired())
            .unwrap_or_default();
        super::RepairError::Deferred {
            missing_blocks: d.missing_blocks,
            est_secs: d.est_secs,
        }
    }

    /// Whether anything is listening or holding. `false` is the default
    /// control, and every hook short-circuits on it.
    pub fn is_active(&self) -> bool {
        self.meters.is_some()
    }

    /// Is somebody WATCHING this repair - both able to see how far it
    /// has got and able to stop it?
    ///
    /// This is the predicate `linalg::set_unattended_unstructured_ceiling`
    /// was a stand-in for. That ceiling exists because an unstructured
    /// solve can run for half an hour and, until 12 Sep 2026, "this
    /// engine emits no progress inside a fold and polls nothing that
    /// could stop one" - so an unattended process had no way to tell a
    /// long repair from a wedged one. A caller that supplies BOTH halves
    /// has removed exactly that reason, and only both: progress with no
    /// cancel leaves a watcher who cannot act, and a cancel with no
    /// progress leaves one who does not know when to.
    pub fn is_attended(&self) -> bool {
        self.sink.is_some() && self.gate.is_some()
    }

    /// Has the repair been called off? A relaxed load, safe to poll per
    /// fold unit and per written block - see [`PauseGate`].
    pub fn cancelled(&self) -> bool {
        self.gate.as_ref().is_some_and(|g| g.is_cancelled())
    }

    /// [`Self::cancelled`] as the error the repair unwinds with, so a
    /// hook site is one `?`.
    pub(crate) fn check(&self) -> Result<(), super::RepairError> {
        if self.cancelled() {
            return Err(super::RepairError::Cancelled);
        }
        Ok(())
    }

    /// This control NARROWED TO ONE PHASE: the same sink, the same gate
    /// and the SAME METERS, so the phase named here keeps counting into
    /// the host's bar and every other phase's `begin`/`step`/`finish` is
    /// a no-op on this view.
    ///
    /// For the syndrome pass - the fold worker's folds and the NTT's
    /// stripes - which must stop when the repair is called off AND is
    /// the stretch [`RepairPhase::Fold`] is a fraction of. It took no
    /// control at all until 15 Sep 2026, so a cancel that landed after
    /// the feed's last check waited out the whole transform with the
    /// driver parked on its join: 53 s of a 54 s run locally, and a
    /// `parfast` cancel test killed at CI's 600 s ceiling
    /// (`research/CLAIMS.jsonl`,
    /// `single-file-followups-linux-tests-cancel-wedge`). A pass it cuts
    /// short leaves syndromes nobody may act on, which is legal for the
    /// same reason the dense back-substitution's is: the check before
    /// the patch refuses first.
    ///
    /// Then it took the CANCEL ALONE (`cancel_only`, a gate and meters
    /// of its own) on the reasoning that the syndrome pass "is not a
    /// phase anybody watches". That was the accounting defect this
    /// narrowing replaces: the pass IS the fold, and while it reported
    /// nothing the `Fold` bar was filled by the hand-over instead -
    /// measured 17 Sep 2026 at 1.96 s of a 3.45 s fold running after
    /// the bar read 100%
    /// (`research/SAB-PARFAST-METER-DROPIN-2026-09-17.md`).
    ///
    /// The MASK is what makes that safe rather than a second bar. The
    /// tiled fold the syndrome pass runs re-sizes and counts
    /// [`RepairPhase::Solve`] as it drains its unit grid, because that
    /// grid IS the solve for the dense back-substitution that shares
    /// the code; reached from the fold worker with a full control it
    /// would drive the host's solve bar through the fold. On this view
    /// it cannot.
    pub(crate) fn reporting_only(&self, phase: RepairPhase) -> RepairControl {
        RepairControl {
            sink: self.sink.clone(),
            gate: self.gate.clone(),
            meters: self.meters.clone(),
            only: Some(phase),
            // NOT carried. The veto is answered ONCE, at the survey
            // point, on the full control the driver holds; a narrowed
            // view exists for a worker inside a phase, which is long
            // past the last moment a repair could be stood back from.
            defer: None,
        }
    }

    /// Park while paused; `Err(Cancelled)` once cancelled.
    ///
    /// See [`PauseGate`] for the rule about where this may be called
    /// from. The short form: never while holding work another thread
    /// could take, and never while holding a lock.
    pub(crate) fn gate(&self) -> Result<(), super::RepairError> {
        match self.gate.as_ref() {
            Some(g) if !g.gate() => Err(super::RepairError::Cancelled),
            _ => Ok(()),
        }
    }

    /// [`gate`](Self::gate) for a HOT loop: one relaxed load unless
    /// something is actually holding the repair, and only then the
    /// mutex. This is what a per-block site calls - it honours the
    /// cancel and the pause at the same price the cancel alone used to
    /// cost.
    pub(crate) fn gate_if_held(&self) -> Result<(), super::RepairError> {
        match self.gate.as_ref() {
            Some(g) if g.held() => self.gate(),
            _ => Ok(()),
        }
    }

    fn meter(&self, phase: RepairPhase) -> Option<&Meter> {
        // A narrowed view answers for its own phase and nothing else -
        // see `reporting_only`. One compare, on the same branch the
        // inert control already costs.
        if self.only.is_some_and(|only| only != phase) {
            return None;
        }
        let i = match phase {
            RepairPhase::Verify => 0,
            RepairPhase::Fold => 1,
            RepairPhase::Solve => 2,
            RepairPhase::Write => 3,
        };
        self.meters.as_ref().map(|m| &m[i])
    }

    /// Start a phase: `total` is its whole, `done` goes back to zero,
    /// and the sink hears `(0, total)` so a bar can size itself before
    /// the first batch lands.
    ///
    /// Called from the driver thread only, before the workers that will
    /// [`step`](Self::step) into it exist.
    pub(crate) fn begin(&self, phase: RepairPhase, total: u64) {
        let Some(m) = self.meter(phase) else { return };
        let mut reported = m.reported.lock().unwrap_or_else(|p| p.into_inner());
        m.done.store(0, Ordering::Relaxed);
        m.total.store(total.max(1), Ordering::Relaxed);
        m.hint.store(0, Ordering::Relaxed);
        *reported = 0;
        if let Some(s) = self.sink.as_ref() {
            s.progress(phase, 0, total);
        }
    }

    /// Announce the sweep that is about to start - see
    /// [`ProgressSink::slab`].
    ///
    /// Driver thread only, once per slab, before that slab's
    /// [`Self::begin`]. No meter of its own: a slab is not a phase and
    /// has no `(done, total)`; it is the frame the phases that follow
    /// are read in.
    pub(crate) fn slab(&self, index: usize, of: usize) {
        if self.only.is_some() {
            return;
        }
        if let Some(s) = self.sink.as_ref() {
            s.slab(index, of.max(1));
        }
    }

    /// Announce which route is reporting - see [`RepairRoute`].
    ///
    /// Driver thread only, once, before that driver's first phase
    /// begins. A no-op on a control with no sink, exactly like every
    /// other hook here.
    pub(crate) fn route(&self, route: RepairRoute) {
        if self.only.is_some() {
            return;
        }
        if let Some(s) = self.sink.as_ref() {
            s.route(route);
        }
    }

    /// Announce which arm of the solve is reporting - see [`SolveArm`].
    ///
    /// Driver thread only, before that arm's own [`Self::begin`]. No
    /// meter of its own for the same reason [`Self::slab`] has none: an
    /// arm is not a phase and has no `(done, total)` - the phase it
    /// belongs to carries those - it is the frame that phase is read
    /// in. Masked on a narrowed view (`reporting_only`), exactly as the
    /// other two frame hooks are: the tiled fold's grid drain re-sizes
    /// `Solve` from inside the fold and must not move the host's frame
    /// with it.
    pub(crate) fn solve_arm(&self, arm: SolveArm) {
        if self.only.is_some() {
            return;
        }
        if let Some(s) = self.sink.as_ref() {
            s.solve_arm(arm);
        }
    }

    /// One batch of `add` units done.
    ///
    /// SAFE IN A HOT LOOP, which is the whole point: a relaxed
    /// `fetch_add`, two multiplies and a compare, and the sink is
    /// reached only on a bucket crossing (see [`STEPS`]). Callable from
    /// any thread.
    pub(crate) fn step(&self, phase: RepairPhase, add: u64) {
        let Some(m) = self.meter(phase) else { return };
        let done = m.done.fetch_add(add, Ordering::Relaxed) + add;
        let total = m.total.load(Ordering::Relaxed).max(1);
        let bucket = done.min(total).saturating_mul(STEPS) / total;
        // The lock-free common case: below the next boundary, nothing
        // to say, and no lock taken.
        if bucket <= m.hint.load(Ordering::Relaxed) {
            return;
        }
        self.announce(phase, m, total);
    }

    /// Tell the sink where the phase is NOW, at most once per bucket and
    /// always in order. See [`Meter`] for why this is a lock.
    ///
    /// A CONCURRENT WORKER'S REPORT IS SWALLOWED WHOLE, not merely
    /// deferred, and a caller counting samples has to expect it: two
    /// workers that finish close together both cross a bucket, the first
    /// to take the lock reads the pair's COMBINED `done` and reports it,
    /// and the second finds its own bucket already covered and says
    /// nothing. So the sink can hear ONE update from a grid of many
    /// units. Measured 20 Sep 2026 on a 16-core Windows box, the PAR2
    /// fold over a two-unit grid with the process oversubscribed on four
    /// CPUs: 50 cold runs, 14 of them lost at least one report this way
    /// and 4 came down to the announcement and the landing - which is
    /// what reddened a loaded Windows CI shard on 18 Sep 2026 against a
    /// test that read a sample count as a grid width. This is the rate
    /// limit working, not a lost update: the value the first worker
    /// published is the FRESHER one.
    fn announce(&self, phase: RepairPhase, m: &Meter, total: u64) {
        let mut reported = m.reported.lock().unwrap_or_else(|p| p.into_inner());
        // Read FRESH under the lock: another worker may have got here
        // first with a larger count, and announcing this thread's stale
        // one is exactly the step backwards this lock exists to stop.
        let done = m.done.load(Ordering::Relaxed).min(total);
        let bucket = done.saturating_mul(STEPS) / total;
        if bucket <= *reported {
            return;
        }
        *reported = bucket;
        m.hint.store(bucket, Ordering::Relaxed);
        if let Some(s) = self.sink.as_ref() {
            s.progress(phase, done, total);
        }
    }

    /// A phase is over: the sink hears `(total, total)` exactly once, so
    /// a bar lands on full rather than stopping at whatever bucket the
    /// last batch happened to cross.
    pub(crate) fn finish(&self, phase: RepairPhase) {
        let Some(m) = self.meter(phase) else { return };
        let total = m.total.load(Ordering::Relaxed);
        let mut reported = m.reported.lock().unwrap_or_else(|p| p.into_inner());
        if *reported >= STEPS {
            return;
        }
        *reported = STEPS;
        m.hint.store(STEPS, Ordering::Relaxed);
        if let Some(s) = self.sink.as_ref() {
            s.progress(phase, total, total);
        }
    }

    /// [`finish`](Self::finish) for a phase THIS call may not have
    /// opened: a no-op unless somebody called [`begin`](Self::begin) on
    /// it first.
    ///
    /// The fold's landing needs this because it is no longer the
    /// driver's to make. The fold is not over when the last block has
    /// been HANDED to the syndrome worker, it is over when that worker
    /// has been joined - and the join is inside
    /// `Reconstructor::finish_blocks_reported`, which is also the
    /// public `Reconstructor::finish` that direct callers reach with a
    /// control that never opened a `Fold` phase at all. `begin` stores
    /// `total.max(1)`, so a zero total is exactly "never begun".
    pub(crate) fn finish_begun(&self, phase: RepairPhase) {
        let Some(m) = self.meter(phase) else { return };
        if m.total.load(Ordering::Relaxed) == 0 {
            return;
        }
        self.finish(phase);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a test sink records: every call, in order.
    #[derive(Default)]
    struct Rec(Mutex<Vec<(RepairPhase, u64, u64)>>);
    impl ProgressSink for Rec {
        fn progress(&self, phase: RepairPhase, done: u64, total: u64) {
            self.0.lock().unwrap().push((phase, done, total));
        }
    }

    fn rigged() -> (RepairControl, Arc<Rec>) {
        let rec = Arc::new(Rec::default());
        (
            RepairControl::new(Some(rec.clone()), Some(PauseGate::new())),
            rec,
        )
    }

    /// THE COST ARGUMENT, as a test rather than a claim: a million
    /// single-unit steps must not be a million sink calls. `STEPS`
    /// bounds it, plus the opening `begin` and the closing `finish`.
    #[test]
    fn a_million_steps_reach_the_sink_at_most_steps_times() {
        let (c, rec) = rigged();
        c.begin(RepairPhase::Fold, 1_000_000);
        for _ in 0..1_000_000 {
            c.step(RepairPhase::Fold, 1);
        }
        c.finish(RepairPhase::Fold);
        let n = rec.0.lock().unwrap().len() as u64;
        assert!(
            n <= STEPS + 2,
            "{n} sink calls for 1,000,000 steps - the bucket rate limit is not working, and a \
             sink call per batch is the regression this whole design is shaped to avoid"
        );
        assert!(n > 8, "{n} sink calls is not a moving bar");
    }

    /// A bar has to RISE and it has to LAND. Both halves have been got
    /// wrong by progress code before: a fraction that never reaches 1
    /// reads as a wedge, which is the exact complaint this module
    /// answers.
    #[test]
    fn the_fraction_rises_monotonically_and_ends_at_one() {
        let (c, rec) = rigged();
        c.begin(RepairPhase::Fold, 4096);
        for _ in 0..4096 {
            c.step(RepairPhase::Fold, 1);
        }
        c.finish(RepairPhase::Fold);
        let calls = rec.0.lock().unwrap().clone();
        let mut last = 0u64;
        for (phase, done, total) in &calls {
            assert_eq!(*phase, RepairPhase::Fold);
            assert_eq!(*total, 4096);
            assert!(*done >= last, "progress went backwards: {last} -> {done}");
            last = *done;
        }
        assert_eq!(
            calls.first().map(|c| c.1),
            Some(0),
            "a bar sizes itself first"
        );
        assert_eq!(last, 4096, "a finished phase lands on full");
    }

    /// `finish` after a phase that already crossed every bucket must not
    /// produce a second full call - a host that wakes on every call
    /// would redraw for nothing.
    #[test]
    fn finish_is_idempotent_and_does_not_double_report_full() {
        let (c, rec) = rigged();
        c.begin(RepairPhase::Write, 10);
        c.step(RepairPhase::Write, 10);
        c.finish(RepairPhase::Write);
        c.finish(RepairPhase::Write);
        let calls = rec.0.lock().unwrap().clone();
        let full = calls.iter().filter(|c| c.1 == 10).count();
        assert_eq!(full, 1, "{calls:?}");
    }

    /// Concurrent steppers are what the CAS in `step` is for: the total
    /// must be exact however the adds interleave, and no bucket may be
    /// announced twice.
    #[test]
    fn concurrent_steppers_count_exactly_and_announce_each_bucket_once() {
        let (c, rec) = rigged();
        c.begin(RepairPhase::Solve, 8192);
        std::thread::scope(|s| {
            for _ in 0..8 {
                let c = c.clone();
                s.spawn(move || {
                    for _ in 0..1024 {
                        c.step(RepairPhase::Solve, 1);
                    }
                });
            }
        });
        c.finish(RepairPhase::Solve);
        let calls = rec.0.lock().unwrap().clone();
        assert_eq!(calls.last().map(|c| c.1), Some(8192));
        // STRICTLY increasing, which is the property the lock in
        // `announce` buys: two workers that bump to 3,520 and 4,032 can
        // reach an unlocked sink in the other order, and a host then
        // draws the bar going backwards. This assertion is the one that
        // found it.
        let mut prev = 0u64;
        for &(_, done, _) in &calls[1..] {
            assert!(done > prev, "not strictly increasing: {calls:?}");
            prev = done;
        }
    }

    /// The default control is the twelve call sites that never asked for
    /// any of this, and it must reach nothing at all.
    #[test]
    fn a_default_control_is_inert_and_never_cancels() {
        let c = RepairControl::default();
        assert!(!c.is_active());
        c.begin(RepairPhase::Fold, 100);
        c.step(RepairPhase::Fold, 100);
        c.finish(RepairPhase::Fold);
        assert!(!c.cancelled());
        assert!(c.check().is_ok());
        assert!(c.gate().is_ok());
    }

    /// Cancel is STICKY and it is visible through both doors - the hot
    /// mirror the workers poll and the guard the wait loop opens on.
    /// A mirror that could disagree with the field is the one way this
    /// design fails, so it is pinned rather than argued.
    #[test]
    fn cancel_is_sticky_and_the_hot_mirror_agrees_with_the_guard() {
        let gate = PauseGate::new();
        let c = RepairControl::new(None, Some(gate.clone()));
        assert!(!c.cancelled());
        gate.cancel();
        assert!(c.cancelled(), "the hot mirror");
        assert!(!gate.gate(), "the guard the wait loop reads");
        assert!(gate.is_cancelled());
        assert!(!gate.is_paused(), "a cancelled gate is not a paused one");
        assert!(matches!(
            c.check(),
            Err(super::super::RepairError::Cancelled)
        ));
        assert!(matches!(
            c.gate(),
            Err(super::super::RepairError::Cancelled)
        ));
    }

    /// A cancel raised WHILE a repair is parked must take effect at
    /// once - at the resume nobody is going to press is not an answer.
    #[test]
    fn a_cancel_while_paused_wakes_the_parked_repair() {
        let gate = PauseGate::new();
        gate.set_paused(true);
        let g2 = gate.clone();
        let h = std::thread::spawn(move || g2.gate());
        // The worker is either parked or about to be; cancel either way.
        std::thread::sleep(std::time::Duration::from_millis(20));
        gate.cancel();
        assert!(
            !h.join().expect("gate thread"),
            "a cancelled gate answers false"
        );
    }

    /// Pause parks and resume releases, which is the other half of the
    /// same promise.
    #[test]
    fn a_paused_gate_parks_until_it_is_resumed() {
        let gate = PauseGate::new();
        gate.set_paused(true);
        assert!(gate.is_paused());
        let g2 = gate.clone();
        let h = std::thread::spawn(move || g2.gate());
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(!h.is_finished(), "a paused gate must not fall through");
        gate.set_paused(false);
        assert!(
            h.join().expect("gate thread"),
            "a resumed gate answers true"
        );
        assert!(!gate.is_paused());
    }

    /// Phases are independent counters. A slabbed solve re-enters
    /// `Solve` while `Fold` has already finished, and the two must not
    /// share a bucket.
    #[test]
    fn phases_count_independently_and_a_phase_may_be_re_entered() {
        let (c, rec) = rigged();
        c.begin(RepairPhase::Fold, 100);
        c.step(RepairPhase::Fold, 100);
        c.finish(RepairPhase::Fold);
        c.begin(RepairPhase::Solve, 50);
        c.step(RepairPhase::Solve, 50);
        c.finish(RepairPhase::Solve);
        // Second slab: Solve again, from zero.
        c.begin(RepairPhase::Solve, 50);
        c.step(RepairPhase::Solve, 25);
        let calls = rec.0.lock().unwrap().clone();
        assert!(calls.contains(&(RepairPhase::Fold, 100, 100)));
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.0 == RepairPhase::Solve && c.1 == 0)
                .count(),
            2,
            "each slab re-sizes the bar: {calls:?}"
        );
    }

    /// A closure is a sink. The trait is the contract, but nobody should
    /// have to write a struct to watch a repair from a test.
    #[test]
    fn a_closure_is_a_progress_sink() {
        let hits = Arc::new(AtomicU64::new(0));
        let h = hits.clone();
        let c = RepairControl::new(
            Some(Arc::new(move |_: RepairPhase, _: u64, _: u64| {
                h.fetch_add(1, Ordering::Relaxed);
            })),
            None,
        );
        c.begin(RepairPhase::Verify, 10);
        c.step(RepairPhase::Verify, 10);
        c.finish(RepairPhase::Verify);
        assert!(hits.load(Ordering::Relaxed) >= 2);
    }

    /// `step` past `total` (a phase whose total was an estimate) must
    /// clamp rather than report a fraction over one.
    #[test]
    fn a_phase_that_overruns_its_total_clamps_rather_than_exceeding_it() {
        let (c, rec) = rigged();
        c.begin(RepairPhase::Write, 100);
        c.step(RepairPhase::Write, 250);
        let calls = rec.0.lock().unwrap().clone();
        assert!(
            calls.iter().all(|&(_, done, total)| done <= total),
            "{calls:?}"
        );
    }

    /// TODO 332's engine half, and the whole of what the engine knows
    /// about deferring: a gate fires on the LONG shape and only on it,
    /// and firing DISARMS it.
    ///
    /// The disarm is what bounds a single run: a job may walk several
    /// recovery sets (the disk repair per declined set, then the
    /// late-set round over the directory), and a gate that stayed armed
    /// would answer "not now" to every one of them from one armed bit.
    /// The ACROSS-RUNS half is not here and cannot be - it is the
    /// caller's mark on the job, which is why the engine's half is
    /// deliberately the smaller one.
    #[test]
    fn a_defer_gate_fires_on_the_long_shape_once_and_then_stands_aside() {
        let long = super::super::RepairForecast {
            missing_blocks: super::super::MAX_REPAIR_DIM + 1,
            block_size: 65536,
            solve: super::super::SolveKind::Unstructured,
            est_secs: Some(1800),
        };
        let gate = DeferGate::armed();
        assert_eq!(gate.fired(), None, "an armed gate has seen nothing yet");
        assert!(gate.consider(&long), "the long shape is what it is for");
        assert_eq!(
            gate.fired(),
            Some(DeferredRepair {
                missing_blocks: (super::super::MAX_REPAIR_DIM + 1) as u64,
                est_secs: 1800,
            }),
            "it carries the forecast it fired on, so the caller can say WHY"
        );
        assert!(
            !gate.consider(&long),
            "ONCE. A second set in the same run repairs - a gate that \
             stayed armed would stand back from every set a job walks"
        );
    }

    /// The same gate says nothing at all about the shapes the warn does
    /// not warn about: a structured solve is seconds at every size the
    /// format allows, and a small unstructured one is not worth a trip
    /// round the queue. `is_long` is the ONE switch, shared with the
    /// log line - so a caller cannot be deferred over something it was
    /// never told about.
    #[test]
    fn a_defer_gate_stays_armed_for_a_repair_nobody_warns_about() {
        let gate = DeferGate::armed();
        let structured = super::super::RepairForecast {
            missing_blocks: super::super::MAX_REPAIR_DIM + 1,
            block_size: 65536,
            solve: super::super::SolveKind::Structured,
            est_secs: None,
        };
        let small = super::super::RepairForecast {
            missing_blocks: 12,
            block_size: 65536,
            solve: super::super::SolveKind::Unstructured,
            est_secs: Some(1),
        };
        assert!(!gate.consider(&structured));
        assert!(!gate.consider(&small));
        assert_eq!(
            gate.fired(),
            None,
            "neither shape is one the engine warns about, so neither may \
             spend the job's one deferral"
        );
        let long = super::super::RepairForecast {
            solve: super::super::SolveKind::Unstructured,
            ..structured
        };
        assert!(
            gate.consider(&long),
            "and refusing those two must not have disarmed it"
        );
    }

    /// A control with no gate is the control every caller had before
    /// TODO 332, answer for answer - and a NARROWED view never carries
    /// one, because it exists for a worker inside a phase, long past the
    /// last moment a repair could be stood back from.
    #[test]
    fn only_a_control_that_was_given_a_gate_can_defer() {
        let long = super::super::RepairForecast {
            missing_blocks: super::super::MAX_REPAIR_DIM + 1,
            block_size: 65536,
            solve: super::super::SolveKind::Unstructured,
            est_secs: Some(1800),
        };
        assert!(!RepairControl::default().defer_long(&long));
        let armed = RepairControl::default().with_defer(Some(DeferGate::armed()));
        assert!(
            !armed.is_active() && !armed.is_attended(),
            "a veto is not a sink and not a gate: it must not make an \
             inert control report as watched, which is what lifts the \
             unattended unstructured ceiling"
        );
        assert!(
            !armed.reporting_only(RepairPhase::Fold).defer_long(&long),
            "a narrowed view may not answer the veto"
        );
        assert!(armed.defer_long(&long), "the full control still does");
    }
}
