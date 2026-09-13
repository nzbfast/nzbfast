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
//! block, a member - and [`RepairControl::step`] calls the sink only
//! when the count crosses one of [`STEPS`] buckets. Over a whole phase
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

/// Where a repair's progress goes.
///
/// `Send + Sync` and `&self`, because it is called from worker threads -
/// the fold's readers, the solve's unit drain - and never from one
/// place. An implementation must be CHEAP and must not block: it runs
/// on a thread that is doing the repair, and [`STEPS`] bounds how often
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
    fn progress(&self, phase: RepairPhase, done: u64, total: u64);
}

/// A `Fn` is a sink, so a caller that only wants a closure stays one.
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
/// of [`GateState`] and [`gate`](Self::gate) opens on it, exactly as
/// `parfast_session::runner::Control::gate` does.
///
/// [`hot`](Self::hot) is a WRITE-THROUGH MIRROR of that field and
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

    pub fn set_paused(&self, paused: bool) {
        let mut st = self.lock();
        st.paused = paused;
        self.held
            .store(st.paused || st.cancelled, Ordering::Relaxed);
        drop(st);
        self.wake.notify_all();
    }

    pub fn is_cancelled(&self) -> bool {
        self.hot.load(Ordering::Relaxed)
    }

    /// `cancelled || paused`, from the mirror - the one relaxed load a
    /// hot loop pays to honour both controls.
    fn held(&self) -> bool {
        self.held.load(Ordering::Relaxed)
    }

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
}
