//! What a CREATE tells a caller while it runs, and how a caller stops
//! it.
//!
//! The repair side grew this on 12 Sep 2026
//! ([`crate::par2repair::control`]); create had none of it - no
//! counter, no gate, no token anywhere under `par2gen` - so a 50 GB
//! set was minutes of silence with nothing able to stop it, and the
//! parfast session crate said so in its own module doc ("a CREATE is
//! cancellable before it starts and not during"). This is the same two
//! things for the third direction.
//!
//! # It is the repair's machinery, not a second copy of it
//!
//! [`CreateControl`] is a thin face over
//! [`RepairControl`](crate::par2repair::RepairControl): the bucket rate
//! limiter, the per-phase meters, the `hint`/`reported` pair that keeps
//! a bar from going backwards, the [`PauseGate`] and the
//! [`ProgressSink`] trait are all THAT module's, reached through it.
//! Nothing here reimplements any of them, deliberately - a second copy
//! of a progress model is a second set of bugs, and a sink written for
//! a repair must not need rewriting to watch a create. The only thing
//! this type adds is the error mapping: a create unwinds with
//! [`Par2GenError::Cancelled`] and a repair with `RepairError::
//! Cancelled`, and a call site should be one `?` either way.
//!
//! # The three phases, and which of the repair's four they are
//!
//! A create reuses the repair's [`RepairPhase`] rather than declaring a
//! fourth enum, for the same reason it reuses the sink: the CLI's meter
//! and the GUI's publisher already switch on it. The mapping is exact
//! and it is the whole of the contract:
//!
//! * [`RepairPhase::Verify`] - HASHING the members off disk, in bytes
//!   of member length. Every byte of every member, counted once, by
//!   whichever of the scan's four arms ran.
//! * [`RepairPhase::Fold`] - the recovery arithmetic, in bytes of input
//!   block fed (the direct fold and the copied-window transform) or in
//!   stripes drained (the stripe-first transform, which has no window
//!   loop to count bytes in). Re-entered once per fold BATCH of a
//!   multi-pass create, which re-sizes the phase - that is the
//!   documented re-entry [`RepairPhase`] already allows for a slabbed
//!   solve.
//! * [`RepairPhase::Write`] - the recovery volumes, in bytes of
//!   recovery-slice payload written. Sized ONCE for the whole create
//!   (`n_recovery * block_size`), so a multi-pass create's write bar
//!   walks up across its passes rather than restarting at each.
//!
//! [`RepairPhase::Solve`] is never reported by a create: there is
//! nothing to solve when every row is known from the start.
//!
//! # The hash and the fold OVERLAP, and a caller has to know
//!
//! A create hashes the members on one thread while the fold reads the
//! same payload on another (that overlap is what the creator's whole
//! pipeline is shaped around), so the two phases report AT THE SAME
//! TIME rather than one after the other - and on the fused arm, where
//! the fold's own reader does the hashing, `Verify` never reports at
//! all. A caller that draws one bar should treat both as one span over
//! the payload and take the larger fraction, which is what the parfast
//! session crate does.
//!
//! # Where a create may PARK, and where it may only be CANCELLED
//!
//! [`PauseGate`]'s rule - never park while holding work another thread
//! could take, and never while holding a lock - admits exactly the
//! sites the repair's does:
//!
//! * the batch loop's own boundary and the fold's window loop, both on
//!   the driver thread with nothing held;
//! * a member scan's block lanes, which own a static disjoint range of
//!   one file's blocks, exactly as the repair's feed readers own a
//!   static chunk of the work list;
//! * a transform worker BETWEEN two stripes, and the stripe-first
//!   driver between two chunks - see the next section, which is the one
//!   thing a create does not simply inherit from the repair.
//!
//! It still refuses the volume writers. Those poll CANCEL, which is one
//! relaxed load and never blocks.
//!
//! # Why the transform parks here where the repair's SOLVE does not
//!
//! Until 12 Sep 2026 this said a create's transform was cancel-only for
//! the reason the repair's solve is, and that a pause pressed during a
//! transform "takes effect at the end of it". Both halves were true of
//! the code and the conclusion was wrong for a create, because of one
//! difference between the two directions: a repair's solve is a stage
//! BETWEEN other stages, with driver boundaries either side that hold
//! the repair within a bounded slice of its wall. **A create's
//! transform is the create.** Measured on the shape the first parfast
//! mac-app run used - 27 GiB over 36 members, one batch, the mapped arm
//! - it was 10.73 s of a 12.85 s run, and the only other park sites
//! were the batch boundary BEFORE it and a window loop that arm does
//! not have. So "at the end of the transform" meant "when the job is
//! finished", and a create could not be paused at all: the job read
//! Paused, some threads stalled, and it then wrote its complete set
//! with Resume never pressed.
//!
//! The rule did not have to bend to fix it, only to be applied one line
//! further up. A stripe worker parks BEFORE its `fetch_add`, not after:
//! at that point it has finished its last stripe and claimed no next
//! one, so it holds nothing another worker could take and nothing
//! another worker is waiting on. The stripe-first arm's driver parks
//! between two chunks, where every worker is already blocked on the
//! start barrier having claimed nothing. Both are the rule, not an
//! exception to it - which is why the solve next door still may not
//! park: its workers hold a POPPED unit when they poll.
//!
//! It cost nothing to add. `gate` is `gate_if_held`: one relaxed load
//! of the `paused || cancelled` mirror, the same single load the bare
//! cancel poll at those sites already was, and the mutex only when
//! somebody is really holding the create.
//!
//! # What the grain actually is, measured
//!
//! One stripe. The count is `(block_size / 2) / W` and so is set by the
//! BLOCK SIZE rather than by the payload: measured on the dev Mac over
//! 2 GiB of 36 members, a 1 MiB block gives 1,043 stripes over a 788 ms
//! transform (24 ms of thread time each) and a 64 KiB block gives 64
//! over 423 ms (211 ms each) at 32,256 input slices, which is within a
//! few hundred of the PAR2 slice ceiling and so is about as coarse as
//! the grain gets before the transform itself is short. Sub-second at
//! both ends, against a pause that previously never arrived.
//!
//! # What it costs, which is the condition this shipped under
//!
//! A cancel is worth having only if watching costs nothing, so this
//! landed on a measurement rather than on an argument: one binary, two
//! arms selected by the env knob below, interleaved reps over four
//! cells picked to reach each of the engine's create paths. CPU-second
//! medians identical on three of them and 0.27% the instrumented arm's
//! way on the fourth; every wall delta inside the within-arm spread.
//! The record is `research/PAR2GEN-CREATE-CONTROL-AB-2026-09-12.md`
//! (private tree).

use std::path::Path;
use std::sync::{Arc, Mutex};

use super::Par2GenError;
use crate::par2repair::{PauseGate, ProgressSink, RepairControl, RepairPhase};

/// A create's phase, which IS the repair's - the same type, under the
/// name a create's call sites read better under. See the module doc for
/// which three of the four a create uses and what each counts; the
/// alias exists so nothing has to convert, and so a [`ProgressSink`]
/// written for one direction watches the other unchanged.
pub use crate::par2repair::RepairPhase as CreatePhase;

/// Progress out, cancel in, pause parked - for a create.
///
/// A [`CreateControl::default()`] is inert: no sink, no gate, and every
/// hook below short-circuits on one `Option` branch, which is what the
/// engine's own callers (postfast, the daemon's posting path, the
/// creator's own tests) keep paying and nothing more.
#[derive(Clone, Default)]
pub struct CreateControl {
    /// The repair's control, holding this create's sink AND its gate -
    /// so the meters, the bucket limiter and the `gate_if_held` mirror
    /// are all the ones that module already measured.
    inner: RepairControl,
}

impl std::fmt::Debug for CreateControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateControl")
            .field("active", &self.is_active())
            .finish()
    }
}

impl CreateControl {
    /// A control that reports to `sink` and is stopped through `gate`.
    /// Either half may be left out: `None` for the sink is the
    /// cancel-only control the command line wants (Ctrl-C, no meter),
    /// `None` for the gate is a report-only one.
    pub fn new(sink: Option<Arc<dyn ProgressSink>>, gate: Option<Arc<PauseGate>>) -> CreateControl {
        CreateControl {
            inner: RepairControl::new(sink, gate),
        }
    }

    /// Whether anything is listening or holding.
    pub fn is_active(&self) -> bool {
        self.inner.is_active()
    }

    /// Has the create been called off? A relaxed load, safe to poll in
    /// any loop that is already chunked.
    pub fn cancelled(&self) -> bool {
        self.inner.cancelled()
    }

    /// [`Self::cancelled`] as the error a create unwinds with, so a
    /// hook site inside a worker is one `?`.
    pub(super) fn check(&self) -> Result<(), Par2GenError> {
        if self.inner.cancelled() {
            return Err(Par2GenError::Cancelled);
        }
        Ok(())
    }

    /// Park while paused, `Err(Cancelled)` once cancelled - for a site
    /// that holds nothing (see the module doc). One relaxed load unless
    /// something is actually holding the create.
    pub(super) fn gate(&self) -> Result<(), Par2GenError> {
        self.inner
            .gate_if_held()
            .map_err(|_| Par2GenError::Cancelled)
    }

    /// Start a phase: `total` is its whole and `done` goes back to
    /// zero. Driver thread only, before the workers that step into it
    /// exist.
    pub(super) fn begin(&self, phase: RepairPhase, total: u64) {
        self.inner.begin(phase, total);
    }

    /// One batch of `add` units done. Safe in any loop the engine
    /// already chunks: a relaxed `fetch_add`, two multiplies and a
    /// compare, and the sink is reached at most 256 times per phase.
    pub(super) fn step(&self, phase: RepairPhase, add: u64) {
        self.inner.step(phase, add);
    }

    /// A phase is over: the sink lands on full exactly once.
    pub(super) fn finish(&self, phase: RepairPhase) {
        self.inner.finish(phase);
    }

    /// The A/B ARM. `NZBFAST_CREATE_CONTROL=on` installs a silent
    /// control - a sink that does nothing and a gate nobody can trip -
    /// where the caller supplied none, so one release binary measures
    /// both arms of "what does polling cost" on any box.
    ///
    /// Inverted against this file's neighbours (`NZBFAST_CREATE_
    /// STRIPE_FIRST=0`, `NZBFAST_CREATE_EARLY_METADATA=0`,
    /// `NZBFAST_NTT=0`), which turn a shipped default OFF, because the
    /// thing being priced here is not a default: whether a create is
    /// watched is the CALLER's choice, and the arm exists to put a
    /// watched create under a caller that never asks for one. `off`,
    /// anything else and unset all mean "the caller's own control",
    /// which is how every shipped path runs.
    pub(super) fn or_env_arm(&self) -> CreateControl {
        if self.is_active() || std::env::var("NZBFAST_CREATE_CONTROL").as_deref() != Ok("on") {
            return self.clone();
        }
        CreateControl::new(
            Some(Arc::new(|_: RepairPhase, _: u64, _: u64| {})),
            Some(PauseGate::new()),
        )
    }
}

/// Every file THIS create has created, so a cancelled one can leave
/// nothing.
///
/// # Why a partial set is worse than no set
///
/// The volumes are written to their FINAL names with no temp file, and
/// the critical packets are patched into them LAST (see
/// [`super::volwrite::backfill_critical`]), so a create killed in the
/// middle leaves files that carry a placeholder critical block: they
/// name no member, they verify against nothing, and the next tool to
/// look at the directory finds a recovery set that is real enough to
/// try and broken enough to fail. That is the promise stated on
/// [`Par2GenError::Cancelled`], and this is what keeps it.
///
/// # Only what this run wrote
///
/// An EXTEND (`-f`, a first exponent onto an existing set) writes new
/// volume names beside the ones already there, and a cancel must take
/// its own and not the set it was extending. So the trail is a record
/// of creation, noted by the code that calls `File::create`, rather
/// than a glob over the directory afterwards - a glob cannot tell the
/// two apart. A create RE-RUN over the same names is the one case
/// where the unlink removes a file that existed before: `File::create`
/// truncated it the moment the run started, so there was nothing left
/// to keep.
#[derive(Default)]
pub(super) struct CreateTrail {
    names: Mutex<Vec<String>>,
}

impl CreateTrail {
    /// Note a file this create has just created, by its name in the
    /// output directory. Called from the volume writers' threads, so
    /// this is a lock - once per FILE, which is nothing beside writing
    /// one.
    pub(super) fn note(&self, name: &str) {
        self.names
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(name.to_string());
    }

    /// Remove every file this create created. Best effort by design:
    /// one that cannot be removed leaves the directory no worse than
    /// stopping without trying, and there is nobody to report an error
    /// to - the cancel is the outcome.
    pub(super) fn unlink_all(&self, dir: &Path) {
        for name in self.names.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            let _ = std::fs::remove_file(dir.join(name));
        }
    }

    #[cfg(test)]
    pub(super) fn noted(&self) -> Vec<String> {
        self.names.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The default control is every engine caller that never asked for
    /// any of this, and it must reach nothing at all.
    #[test]
    fn a_default_control_is_inert_and_never_cancels() {
        let c = CreateControl::default();
        assert!(!c.is_active());
        assert!(!c.cancelled());
        c.begin(RepairPhase::Fold, 100);
        c.step(RepairPhase::Fold, 100);
        c.finish(RepairPhase::Fold);
        assert!(c.check().is_ok());
        assert!(c.gate().is_ok());
    }

    /// Cancel is the repair gate's, so it is sticky and it arrives as
    /// THIS module's error - which is the only thing this type adds.
    #[test]
    fn a_cancelled_gate_unwinds_as_the_create_error() {
        let gate = PauseGate::new();
        let c = CreateControl::new(None, Some(gate.clone()));
        assert!(c.check().is_ok());
        assert!(c.gate().is_ok());
        gate.cancel();
        assert!(c.cancelled());
        assert!(matches!(c.check(), Err(Par2GenError::Cancelled)));
        assert!(matches!(c.gate(), Err(Par2GenError::Cancelled)));
        // Sticky: nothing clears it.
        assert!(matches!(c.check(), Err(Par2GenError::Cancelled)));
    }

    /// A pause parks a create at a site that holds nothing, and a
    /// cancel raised while it is parked releases it - the gate's own
    /// promise, pinned here because this is the door the creator uses.
    #[test]
    fn a_paused_create_parks_and_a_cancel_releases_it() {
        let gate = PauseGate::new();
        let c = CreateControl::new(None, Some(gate.clone()));
        gate.set_paused(true);
        let c2 = c.clone();
        let h = std::thread::spawn(move || c2.gate());
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(!h.is_finished(), "a paused create must not fall through");
        gate.cancel();
        assert!(matches!(
            h.join().expect("gate thread"),
            Err(Par2GenError::Cancelled)
        ));
    }

    /// The rate limit is the repair's, and this is the cost argument
    /// for every site below: a million steps is not a million calls.
    #[test]
    fn the_sink_hears_a_bounded_number_of_calls_for_a_million_steps() {
        let hits = Arc::new(AtomicU64::new(0));
        let h = hits.clone();
        let c = CreateControl::new(
            Some(Arc::new(move |_: RepairPhase, _: u64, _: u64| {
                h.fetch_add(1, Ordering::Relaxed);
            })),
            None,
        );
        c.begin(RepairPhase::Verify, 1_000_000);
        for _ in 0..1_000_000 {
            c.step(RepairPhase::Verify, 1);
        }
        c.finish(RepairPhase::Verify);
        let n = hits.load(Ordering::Relaxed);
        assert!(n > 8 && n <= 258, "{n} sink calls");
    }

    /// The env arm is for the A/B and nothing else: it must never
    /// override a caller that brought its own control, and it must be
    /// absent unless it is asked for by name.
    #[test]
    fn the_env_arm_only_fills_in_for_a_caller_with_no_control() {
        let gate = PauseGate::new();
        let mine = CreateControl::new(None, Some(gate.clone()));
        // Whatever the environment says, a supplied control is returned
        // as itself - the same gate, so a cancel still reaches it.
        let kept = mine.or_env_arm();
        gate.cancel();
        assert!(kept.cancelled());
        // And with no variable set, an inert control stays inert.
        if std::env::var_os("NZBFAST_CREATE_CONTROL").is_none() {
            assert!(!CreateControl::default().or_env_arm().is_active());
        }
    }

    /// The trail is the cancel promise: what it noted is what goes,
    /// and a file it never noted stays - which is the extend case.
    #[test]
    fn the_trail_removes_what_it_noted_and_leaves_what_it_did_not() {
        // The crate has no dev-dep on tempfile, so the creator's own
        // tests build a three-line `Tmp` rather than acquire one; this
        // needs one directory and does it inline.
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-par2gen-trail-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        for n in ["set.par2", "set.vol000+01.par2", "old.vol100+01.par2"] {
            std::fs::write(dir.join(n), b"x").expect("write");
        }
        let trail = CreateTrail::default();
        trail.note("set.par2");
        trail.note("set.vol000+01.par2");
        // A name that is not there at all must not stop the rest.
        trail.note("set.vol999+01.par2");
        assert_eq!(trail.noted().len(), 3);
        trail.unlink_all(&dir);
        assert!(!dir.join("set.par2").exists());
        assert!(!dir.join("set.vol000+01.par2").exists());
        assert!(
            dir.join("old.vol100+01.par2").exists(),
            "an extend's existing volumes are not this run's to remove"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
