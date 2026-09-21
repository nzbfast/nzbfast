//! What a CREATE tells a caller while it runs, and how a caller stops
//! it: the create's progress sink, cancel gate and the trail a cancel
//! unlinks. Added 12 Sep 2026 (claim `par2gen-create-control`).
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
//! [`CreateControl`] is a thin face over [`RepairControl`]: the bucket
//! rate limiter, the per-phase meters, the `hint`/`reported` pair that
//! keeps a bar from going backwards, the [`PauseGate`] and the
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
    /// The validated digest cache this create consults
    /// (`crate::digest_cache`), resolved ONCE on the entry point's own
    /// thread by [`Self::with_active_digest_cache`] and carried from there,
    /// because the scan runs on threads the entry point spawns and a store
    /// read on one of those is not necessarily the store the caller made
    /// active (a unit test's is thread-local by design).
    digest_cache: Option<Arc<crate::digest_cache::DigestCache>>,
    /// Bytes the whole-file MD5 CHAIN lane has accounted for, across
    /// every member scanned so far - the counter the batched create's
    /// fold pacer paces against, and NOT a phase.
    ///
    /// # Why this is not a [`CreatePhase`]
    ///
    /// The chain is a SECOND pass over bytes [`CreatePhase::Verify`]
    /// already counts once (see [`RepairPhase::Verify`]'s own doc: "in
    /// BYTES of declared member length"), so a phase for it would make
    /// every sink in the fleet - the daemon's bar, the CLI's, an
    /// embedder's - report a create as two hundred percent of itself.
    /// A pacer needs a RATE from one lane; a sink needs the member's
    /// bytes counted once. Those are different readers, so they get
    /// different counters.
    ///
    /// # Why it is not `CreatePhase::Verify`, which is what shipped
    ///
    /// It WAS `Verify` until 16 Sep 2026, and that made the batched
    /// pacer a measured no-op: on the route a large single member
    /// actually takes (`scan::scan_mapped`, and `scan::
    /// scan_parallel_positional` the same way) `Verify` is stepped by
    /// the BLOCK-DIGEST lanes, which are `threads`-way parallel over
    /// the member, while the whole-file chain is a separate sequential
    /// lane that deliberately steps nothing. The counter therefore
    /// saturated inside the first batch or two with most of the chain's
    /// wall still to run, and the pacer read that as "the chain has
    /// finished" and restored the ceiling: `8 -> 8 workers, 0 move(s)`
    /// in all nine batched legs of the acceptance round
    /// (research/PARFAST-BATCHED-CREATE-FOLD-PACER-2026-09-15.md).
    ///
    /// An `Arc` rather than a bare atomic because [`CreateControl`] is
    /// `Clone` and a clone must SHARE this - the scan thread and the
    /// batch driver are handed the same control, and a per-clone
    /// counter would silently read zero on either side of that.
    chain: Arc<std::sync::atomic::AtomicU64>,
    /// Bytes the BLOCK-DIGEST lanes have stepped into
    /// [`CreatePhase::Verify`] - the raw lane count, kept apart from
    /// what the sink has been told. See [`Self::verify_sync`].
    verify_blocks: Arc<std::sync::atomic::AtomicU64>,
    /// Bytes of `Verify` the sink HAS been told, so the two lanes'
    /// lesser can be forwarded to an add-only meter as increments.
    verify_forwarded: Arc<std::sync::atomic::AtomicU64>,
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
            digest_cache: None,
            chain: Arc::default(),
            verify_blocks: Arc::default(),
            verify_forwarded: Arc::default(),
        }
    }

    /// This control with the digest cache the calling thread's entry point
    /// made active. Called on that thread, before any worker exists.
    pub(super) fn with_active_digest_cache(mut self) -> CreateControl {
        self.digest_cache = crate::digest_cache::active();
        self
    }

    /// The store this create consults, if any.
    pub(super) fn digest_cache(&self) -> Option<&Arc<crate::digest_cache::DigestCache>> {
        self.digest_cache.as_ref()
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
        if phase == RepairPhase::Verify {
            self.verify_blocks
                .store(0, std::sync::atomic::Ordering::Relaxed);
            self.verify_forwarded
                .store(0, std::sync::atomic::Ordering::Relaxed);
        }
        self.inner.begin(phase, total);
    }

    /// The fold BATCH about to start, and how many there will be -
    /// the create's reading of [`ProgressSink::slab`], which is the
    /// repair's channel for exactly this and not a second one.
    ///
    /// A memory-capped create folds the set a batch of volumes at a
    /// time, and [`CreatePhase::Fold`] is re-sized at each
    /// (`par2gen::recovery_slices`), so its `(done, total)` alone says
    /// where THIS batch is and nothing about where the create is. A bar
    /// that is told `(index, of)` first can band the fold across the
    /// batches and stay monotone; one that is not can only draw 0 to
    /// 100 once per batch. `of` cannot be inferred from the re-entries
    /// - a sink counting them knows the index and never the whole -
    /// which is the argument [`ProgressSink::slab`] already makes for
    /// the repair.
    ///
    /// Driver thread only, once per batch, BEFORE that batch's
    /// `begin(Fold, ..)`. A create that folds in one pass announces
    /// `(0, 1)`; the stripe-first transform announces nothing, and
    /// `(0, 1)` is the right reading of that too.
    pub(super) fn batch(&self, index: usize, of: usize) {
        self.inner.slab(index, of);
    }

    /// One batch of `add` units done. Safe in any loop the engine
    /// already chunks: a relaxed `fetch_add`, two multiplies and a
    /// compare, and the sink is reached at most 256 times per phase.
    pub(super) fn step(&self, phase: RepairPhase, add: u64) {
        if phase == RepairPhase::Verify {
            self.verify_blocks
                .fetch_add(add, std::sync::atomic::Ordering::Relaxed);
            self.verify_sync();
            return;
        }
        self.inner.step(phase, add);
    }

    /// Forward to the sink the LESSER of `Verify`'s two lanes.
    ///
    /// The scan hashes a member on two lanes at once: the block digests,
    /// `threads`-way parallel and stepping [`CreatePhase::Verify`], and
    /// the whole-file MD5 chain, one sequential pass stepping
    /// [`Self::chain`]. The phase is over when BOTH are, and from page
    /// cache the block lanes finish several times sooner - measured
    /// 20 Sep 2026 on a 4 GiB single member, `parfast c -r10`: the
    /// block lanes stepped `Verify` to full in 0.44 s, the chain ran
    /// 6.09 s, and every bar over the phase sat on 100 for the last
    /// 5.6 s of it (GH #88's "gets to 100 and then waits"). So the sink
    /// hears `min(blocks, chain)`: each lane's step recomputes the
    /// lesser and forwards only what is NEW beyond what the sink already
    /// has, through a `fetch_max` so two lanes racing here never
    /// forward the same bytes twice. The chain takes part once it has
    /// stepped at all; an arm that hashes without a chain (none today,
    /// but the gate costs one load) reports its block lanes as before.
    ///
    /// The chain counter itself is unchanged and still not a phase -
    /// [`Self::chain`] says why - so the pacer that reads it for a rate
    /// reads what it always did.
    fn verify_sync(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        let blocks = self.verify_blocks.load(Relaxed);
        let chain = self.chain.load(Relaxed);
        let lesser = if chain == 0 {
            blocks
        } else {
            blocks.min(chain)
        };
        let told = self.verify_forwarded.fetch_max(lesser, Relaxed);
        if lesser > told {
            self.inner.step(RepairPhase::Verify, lesser - told);
        }
    }

    /// A phase is over: the sink lands on full exactly once.
    pub(super) fn finish(&self, phase: RepairPhase) {
        self.inner.finish(phase);
    }

    /// `add` more bytes accounted for by the whole-file MD5 chain - see
    /// the [`Self::chain`] field. Called from whichever lane of
    /// `scan::scan_at_length`'s arms actually RUNS that chain, which on
    /// the mapped and positional arms is not the lane that steps
    /// [`CreatePhase::Verify`]. One relaxed `fetch_add`, no sink, no
    /// bucket filter: the only reader is a pacer asking for a rate.
    ///
    /// A member whose chain is ABANDONED part-way (a validated digest
    /// record answers for it, `crate::digest_cache`) credits the rest of
    /// its length here as it leaves, because the chain's WORK for that
    /// member is then over - which is the question the pacer is asking.
    ///
    /// Since 20 Sep 2026 it also re-syncs the `Verify` phase: the sink
    /// hears the lesser of this lane and the block lanes, so a chain
    /// running behind them holds the bar back rather than being
    /// invisible to it. It still adds nothing of its own to the phase -
    /// the bytes stay counted once. See [`Self::verify_sync`].
    pub(super) fn chain_step(&self, add: u64) {
        self.chain
            .fetch_add(add, std::sync::atomic::Ordering::Relaxed);
        self.verify_sync();
    }

    /// What the chain has accounted for so far, in the same units and
    /// against the same whole as [`CreatePhase::Verify`]'s total (the
    /// sum of the members' declared lengths), so a caller can compare
    /// the two directly.
    pub(super) fn chain_done(&self) -> u64 {
        self.chain.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Back to zero, before a create's scan starts. A control outlives
    /// one create at some call sites (the session crate reuses one
    /// across a pairing), and a carried-over count would read as a
    /// chain that finished before it began.
    pub(super) fn chain_reset(&self) {
        self.chain.store(0, std::sync::atomic::Ordering::Relaxed);
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
/// of creation, written by [`CreateTrail::create`] as it opens each
/// file, rather than a glob over the directory afterwards - a glob
/// cannot tell the two apart. An OVERWRITING create re-run over the
/// same names is the one case where the unlink removes a file that
/// existed before: the open truncated it the moment the run started,
/// so there was nothing left to keep. A no-clobber run has no such
/// case, because it never opens a file it did not create.
///
/// # Which is why the trail OPENS the files
///
/// [`CreateTrail::create`] is the ONE door every set member is created
/// through, and it notes the name only once the open has succeeded.
/// The two used to be separate calls with the note going FIRST, which
/// was right while every open truncated - the note had to cover the
/// window between `File::create` returning and the first byte landing.
/// It stops being right the moment an open can be REFUSED: a
/// no-clobber create that declines to touch somebody else's file would
/// have noted that file as its own, and a cancel taken any time
/// afterwards would then delete the very file the refusal was
/// protecting. Opening and noting in one place is what makes "noted
/// means this run created it" true by construction rather than by
/// every call site remembering the order.
///
/// # `no_clobber`
///
/// Set from [`super::CreatePlan::no_clobber`]. `false` is every caller
/// this engine has ever had and is `File::create`'s truncating open;
/// `true` opens with `O_EXCL`, so an existing file is
/// [`std::io::ErrorKind::AlreadyExists`] and this run neither writes it
/// nor owns it. That is the only door below the CLI that can refuse the
/// overwrite ATOMICALLY - a caller's own look-before-you-write is a
/// preflight, and two creates started together on one base race straight
/// through it.
pub(super) struct CreateTrail {
    names: Mutex<Vec<String>>,
    no_clobber: bool,
}

impl Default for CreateTrail {
    /// Overwriting, which is what every engine caller and
    /// par2cmdline's own default do.
    fn default() -> Self {
        CreateTrail {
            names: Mutex::new(Vec::new()),
            no_clobber: false,
        }
    }
}

impl CreateTrail {
    /// A trail that refuses to write over a file that is already there
    /// when `no_clobber`, and truncates as it always has when not.
    pub(super) fn new(no_clobber: bool) -> Self {
        CreateTrail {
            names: Mutex::new(Vec::new()),
            no_clobber,
        }
    }

    /// Create `name` in `dir` as a member of this run's set, and note
    /// it. THE ONE DOOR: see the type's own doc for why creating and
    /// noting are a single call and not two.
    ///
    /// Called from the volume writers' threads, so the note is a lock -
    /// once per FILE, which is nothing beside writing one.
    ///
    /// It returns a [`SetMember`] and not a `std::fs::File`, which is
    /// what makes this the one door in the LANGUAGE rather than only in
    /// the gate: `SetMember`'s field is private to this module, so no
    /// other function anywhere can produce one. See that type's doc.
    pub(super) fn create(&self, dir: &Path, name: &str) -> std::io::Result<SetMember> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(self.no_clobber)
            // `create(true).truncate(true)` is `File::create`, spelled
            // the long way so the one flag that differs between the two
            // modes is the one flag that moves.
            .create(!self.no_clobber)
            .truncate(!self.no_clobber)
            .open(dir.join(name))?;
        // AFTER the open, and only on success. A refused open is
        // somebody else's file and was never this run's to remove.
        self.note(name);
        // The ONE construction of a `SetMember` in the crate, and the
        // reason the write paths can only be fed by this function.
        Ok(SetMember { file })
    }

    /// Note a file this create has just created, by its name in the
    /// output directory.
    fn note(&self, name: &str) {
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

/// An open handle on a file of THIS run's recovery set, which only
/// [`CreateTrail::create`] can mint.
///
/// # Why this is a type and not a `std::fs::File`
///
/// The door above is the one place a set member comes into existence,
/// and until 20 Sep 2026 that was held by a GATE
/// (`tools/par2-create-door-gate.py`) and by nothing in the language: a
/// fourth write path spelled `std::fs::File::create` type-checked
/// perfectly, wrote a real volume, and lost both of the door's
/// properties - the no-clobber refusal and the note-after-open
/// ordering - with every test still green.
///
/// The field is PRIVATE TO THIS MODULE, so `control` is the only place
/// a `SetMember` can be built and `create` is the only function in
/// `control` that builds one. `par2gen` is this module's PARENT and
/// reaches the field no more than a stranger does. Everything that
/// writes a set member - the index (`super::write_member`), the batched
/// volume writer (`super::volwrite`), the stripe-first layout
/// (`super::stripe_first`) - now names this type in its own signature,
/// so a bare `File` cannot be threaded into any of them and the handle
/// those paths write to is, by construction, the handle the door
/// opened. That last is the CONVERSE of what the gate can prove: the
/// gate shows the door is CALLED, never that its return value is what
/// gets written.
///
/// # What it deliberately does NOT have
///
/// There is no `as_file`, no `into_inner` and no `From<File>`, and that
/// absence is the whole point rather than an omission to be tidied up.
/// One accessor handing out a `&File` would put every method on
/// `std::fs::File` and every free helper in [`crate::disk`] back within
/// reach of a bare create, which is the hole this type closes. The four
/// operations the three write paths actually need are forwarded below;
/// a fifth is added HERE, deliberately, and not bought with an
/// accessor.
///
/// # What it does NOT prove, so a build is read for what it is
///
/// Rust cannot ban a call. A new par2gen function is still free to
/// write `std::fs::File::create(path)` and drive the result with
/// `std::io::Write` directly, never touching this type - it simply
/// cannot reach any of par2gen's OWN write machinery that way. That
/// residue is arm D of `tools/par2-create-door-gate.py`, which is why
/// arm D stays: the plan that commissioned this type ruled that the type
/// would subsume that arm, and building it is what showed the ruling does
/// not hold. That gate's own docstring states it at the arm.
///
/// # `Debug`
///
/// Derived because a test asserting the door REFUSED an open reaches the
/// refusal through `Result::expect_err`, which needs the ok side
/// printable. It hands out no handle: the derive prints the descriptor
/// and path the way `std::fs::File`'s own does.
#[derive(Debug)]
pub(super) struct SetMember {
    /// Private to `control`. See the type's own doc: this field, and
    /// the absence of any accessor for it, IS the invariant.
    file: std::fs::File,
}

impl SetMember {
    /// Write `buf` at `at`, leaving the file's cursor alone
    /// ([`crate::disk::write_all_at`]). The stripe-first layout's
    /// grain: every volume is sized up front and filled by offset.
    pub(super) fn write_all_at(&self, buf: &[u8], at: u64) -> std::io::Result<()> {
        crate::disk::write_all_at(&self.file, buf, at)
    }

    /// Size the file before the first positional write
    /// ([`crate::disk::preallocate_output`]), which on NTFS is what
    /// keeps a write past the valid data length from zero-filling up
    /// to it.
    pub(super) fn preallocate(&self, size: u64, cap: u64) -> std::io::Result<()> {
        crate::disk::preallocate_output(&self.file, size, cap)
    }

    /// The data of this member on the platter, without the metadata
    /// flush a full `sync_all` also pays.
    pub(super) fn sync_data(&self) -> std::io::Result<()> {
        self.file.sync_data()
    }
}

/// So a member can be handed to a [`std::io::BufWriter`] and filled in
/// stream order, which is the batched volume writer's whole shape.
impl std::io::Write for SetMember {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.file, buf)
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        std::io::Write::write_vectored(&mut self.file, bufs)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// THE DOOR'S RETURN TYPE, asserted at COMPILE TIME rather than by
    /// running anything - this item is the test.
    ///
    /// `SetMember`'s field is private to `control`, so this signature is
    /// what makes a bare `std::fs::File::create` unusable in every one
    /// of par2gen's write paths: they name `SetMember` and only this
    /// function produces one. Widening `create` back to `-> Result<
    /// std::fs::File>` is the one edit that would restore the hole
    /// wholesale and would be invisible at every call site (`let file =
    /// trail.create(..)?` compiles either way), so it is pinned here.
    ///
    /// WHAT THIS DOES NOT SAY: Rust cannot ban a call, so a brand-new
    /// par2gen function writing `File::create` and driving the handle
    /// with `std::io::Write` directly still compiles. That residue is
    /// arm D of `tools/par2-create-door-gate.py`, which is why arm D
    /// was NOT retired when this type landed.
    const _DOOR_RETURNS_A_SET_MEMBER: fn(&CreateTrail, &Path, &str) -> std::io::Result<SetMember> =
        CreateTrail::create;

    /// A member writes through the three forwarded shapes the real write
    /// paths use, and the bytes land where each one says they do.
    ///
    /// The point is not that `std::fs::File` works - it is that these
    /// are the ONLY four operations a set member has, so the next path
    /// that needs a fifth adds it here deliberately rather than reaching
    /// a raw handle through an accessor.
    #[test]
    fn a_set_member_writes_in_stream_order_and_by_offset() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-setmember-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        let trail = CreateTrail::default();
        let mut m = trail.create(&dir, "set.par2").expect("the door opens");
        // Stream order, which is what `BufWriter` drives in `volwrite`.
        std::io::Write::write_all(&mut m, b"HEADER..").expect("write_all");
        std::io::Write::flush(&mut m).expect("flush");
        // Sized and then filled by offset, which is `stripe_first`'s
        // whole shape.
        m.preallocate(16, u64::MAX).expect("preallocate");
        m.write_all_at(b"TAIL", 8).expect("write_all_at");
        m.sync_data().expect("sync_data");
        drop(m);

        let got = std::fs::read(dir.join("set.par2")).expect("read back");
        assert_eq!(&got[..8], b"HEADER..", "the stream write landed at 0");
        assert_eq!(&got[8..12], b"TAIL", "the positional write landed at 8");
        assert_eq!(
            trail.noted(),
            vec!["set.par2".to_string()],
            "the door noted the member it opened"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

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

    /// The chain counter and the phase meters are DIFFERENT QUESTIONS
    /// and must not alias: one asks how far a single sequential lane has
    /// got (a rate, for the fold pacer), the other how much of the
    /// member has been accounted for at all (a bar, for a sink). They
    /// were the same counter until 16 Sep 2026 and the pacer built on
    /// that read a finished chain before the chain had started.
    ///
    /// Pinned in BOTH directions, and the sink is the instrument for it:
    /// a phase step must not move the chain counter, and a chain step
    /// must not reach a sink at all - the chain is a second pass over
    /// bytes `Verify` already counted, so a sink that heard it would
    /// report the create as twice itself.
    #[test]
    fn the_chain_counter_is_its_own_and_never_adds_to_the_phase() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let rec = Arc::clone(&calls);
        let c = CreateControl::new(
            Some(Arc::new(move |p: RepairPhase, done: u64, _t: u64| {
                rec.lock().unwrap().push((p, done));
            })),
            None,
        );
        assert_eq!(c.chain_done(), 0);
        c.begin(RepairPhase::Verify, 100);
        c.step(RepairPhase::Verify, 100);
        c.finish(RepairPhase::Verify);
        assert!(
            !calls.lock().unwrap().is_empty(),
            "the phase step reached no sink - this test is measuring nothing"
        );
        assert_eq!(
            c.chain_done(),
            0,
            "a phase step moved the chain counter - they are the same counter again"
        );

        let heard = calls.lock().unwrap().len();
        c.chain_step(30);
        assert_eq!(c.chain_done(), 30);
        c.chain_step(70);
        assert_eq!(c.chain_done(), 100);
        assert_eq!(
            calls.lock().unwrap().len(),
            heard,
            "the chain reached the progress sink past a phase already full - a bar would \
             double-count the member"
        );

        c.chain_reset();
        assert_eq!(c.chain_done(), 0);
    }

    /// The phase reports the LESSER of its two lanes (see
    /// `verify_sync`): block lanes that race ahead cannot put the bar
    /// on 100 while the chain is still hashing, and the chain catching
    /// up is what moves it - without ever counting a byte twice.
    #[test]
    fn verify_reports_the_slower_of_the_block_lanes_and_the_chain() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let rec = Arc::clone(&calls);
        let c = CreateControl::new(
            Some(Arc::new(move |p: RepairPhase, done: u64, _t: u64| {
                if p == RepairPhase::Verify {
                    rec.lock().unwrap().push(done);
                }
            })),
            None,
        );
        let last = || *calls.lock().unwrap().last().unwrap();
        c.begin(RepairPhase::Verify, 1000);
        // The chain has started; the block lanes then finish the whole
        // member at once, as they do from page cache.
        c.chain_step(10);
        c.step(RepairPhase::Verify, 1000);
        assert_eq!(last(), 10, "the block lanes may not outrun the chain");
        c.chain_step(490);
        assert_eq!(last(), 500, "the chain moves the bar");
        // The chain overtaking the blocks would be held by them in turn.
        let held = c.clone();
        held.begin(RepairPhase::Verify, 1000);
        held.step(RepairPhase::Verify, 300);
        held.chain_step(1000);
        assert_eq!(last(), 300);
        held.step(RepairPhase::Verify, 700);
        assert_eq!(last(), 1000);
        // Finish still lands on full whatever the lanes said.
        c.begin(RepairPhase::Verify, 1000);
        c.step(RepairPhase::Verify, 100);
        c.finish(RepairPhase::Verify);
        assert_eq!(last(), 1000);
    }

    /// A clone SHARES the chain counter, because the scan thread and the
    /// batch driver are handed the same control and a per-clone counter
    /// would read zero on one side of that. An inert control has one
    /// too - it is not gated on a sink or a gate the way the meters are.
    #[test]
    fn a_cloned_control_shares_the_chain_counter() {
        let c = CreateControl::new(None, Some(PauseGate::new()));
        let twin = c.clone();
        c.chain_step(7);
        assert_eq!(twin.chain_done(), 7);
        twin.chain_step(5);
        assert_eq!(c.chain_done(), 12);
        let inert = CreateControl::default();
        inert.chain_step(3);
        assert_eq!(inert.chain_done(), 3);
        // ...and a SEPARATE control is separate.
        assert_eq!(CreateControl::default().chain_done(), 0);
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

    /// THE TRAP a no-clobber create sets, pinned at the one place it can
    /// be pinned deterministically.
    ///
    /// The refusal and the cancel are two features that are each fine
    /// alone and destroy a user's file together: a create that declines
    /// to touch a file it does not own, having NOTED that file first,
    /// hands the cancel path a name to `remove_file`. The refusal would
    /// then delete exactly the file it refused to overwrite - a worse
    /// outcome than the overwrite it was added to prevent.
    ///
    /// `CreateTrail::create` is what makes it impossible: the note is
    /// after the open and only on success, so "noted" means "this run
    /// created it". This test is that sentence, both ways round.
    #[test]
    fn a_refused_no_clobber_open_is_never_noted_and_so_never_unlinked() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-trail-noclobber-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let theirs = b"somebody else's recovery volume".to_vec();
        std::fs::write(dir.join("set.vol000+01.par2"), &theirs).expect("write");

        let trail = CreateTrail::new(true);
        // Ours: created here, so the trail owns it.
        trail.create(&dir, "set.par2").expect("a free name opens");
        // Theirs: refused, and refused in the ONE way a caller can act
        // on - `AlreadyExists`, not a generic write failure.
        let e = trail
            .create(&dir, "set.vol000+01.par2")
            .expect_err("no-clobber must refuse a file that is already there");
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "{e:?}");
        assert_eq!(
            trail.noted(),
            vec!["set.par2".to_string()],
            "a file this run did not create must not be on its trail"
        );
        assert_eq!(
            std::fs::read(dir.join("set.vol000+01.par2")).expect("still there"),
            theirs,
            "the refusal itself must not have touched the file"
        );

        trail.unlink_all(&dir);
        assert!(!dir.join("set.par2").exists(), "this run's own file goes");
        assert_eq!(
            std::fs::read(dir.join("set.vol000+01.par2")).expect("still there"),
            theirs,
            "the cancel deleted the very file the refusal was protecting"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The control arm of the test above: the DEFAULT trail truncates,
    /// which is what every engine caller and par2cmdline itself do, and
    /// a file it truncated is this run's to take back on a cancel.
    #[test]
    fn a_default_trail_still_truncates_and_owns_what_it_truncated() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-trail-clobber-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("set.par2"), b"the previous run's index").expect("write");

        let trail = CreateTrail::default();
        trail
            .create(&dir, "set.par2")
            .expect("the default trail writes over what is there");
        assert_eq!(
            std::fs::read(dir.join("set.par2"))
                .expect("still there")
                .len(),
            0,
            "the open must have truncated"
        );
        assert_eq!(trail.noted(), vec!["set.par2".to_string()]);
        trail.unlink_all(&dir);
        assert!(!dir.join("set.par2").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
