//! TODO 313 items 3, 4, 5 and 10: when the head cannot use the fleet it
//! holds, lend the unused part of it to the QUEUE.
//!
//! **The regime this is for, and the three it must decline.** A head
//! whose articles are behind DEAD AIR is the one shape on the tree
//! where a job cannot use its own fleet: its sockets are parked on
//! silence, its wall improves only 2.0x for 4x the sockets, and no
//! demotion arm can reach it because bytes are still trickling
//! (`research/SECOND-JOB-OVERLAP-2026-08.md` sections 1 and 4). A head
//! that is merely on a SLOW PROVIDER, one clearing REFUSALS, and one
//! that is simply LINE-BOUND all look slow and are all using their
//! fleet perfectly well; lending their sockets makes the queue slower,
//! not faster. Every rule below exists to tell those four apart.
//!
//! **The trigger is delivered bytes per DIALLING socket, over that
//! link's own trained per-socket carry** - never the refusal ratio and
//! never an achieved rate. `pool/steer.rs`'s header already forbids
//! refusal-derived state ("a 430 storm is legitimate for old posts"),
//! the study measures a high refusal ratio as predicting a job that
//! finishes SOONER, and the dead-air regime produces no refusals at
//! all: a refusal trigger would fire on the case that needs nothing and
//! miss the only one worth serving. An achieved rate on its own is the
//! `nzbfast-linecap-achieved-rate-is-not-a-line` trap - a slow provider
//! is slow for that provider too, so the RATIO is what separates the
//! populations and the level never can.
//!
//! **The denominator is TODO 275 item 1 part 2's**, the per-socket
//! carry that outlives a job (`serve::linecarry`, landed 28 Aug 2026).
//! With no reading banked yet there is no denominator, and this module
//! says nothing at all rather than guessing - a job that starts badly
//! would otherwise be measured against its own bad start.
//!
//! **And it is SNAPSHOT at the head's pool build, not read live**
//! (item 12, 2 Sep 2026). `linecarry` banks during a run by design, so
//! reading it each tick let the head being judged overwrite the bank
//! with its own crippled figure within four seconds and be measured
//! against itself from then on - which ended every episode after about
//! fifteen seconds whatever the head was doing. `Governor::carry`
//! carries the full account; `note_pool_build` is where it is frozen.
//!
//! **What it does when it fires** is walk the head's `ConnTarget` down
//! to a floor and let a job started behind it build on the freed slice
//! of the SAME `HostLease`, so the account never sees a socket it did
//! not license. The head keeps its own counters, its own progress and
//! its own defer supervision - `tasks::stall::watched()` already judges
//! the drainer in preference to the hub owner - so the hazard that
//! lending a fleet also removes a job's escalation does not exist.
//!
//! **Sizing is by ABSORPTION and not by share** (item 10, and it is the
//! largest measured finding in the study). A small job is
//! ARTICLE-bound, not socket-bound: twelve articles cannot hold
//! thirty-two sockets however many they are offered. So a successor is
//! given `min(its remaining articles, what is left of the slice)` and
//! the residue passes on rather than being wasted on it. Measured, the
//! arm that gave the successors the FEWEST sockets was the best one by
//! a distance: eight sockets as four lanes of two finished all eight
//! queued jobs inside the head's own window while the head paid 17%,
//! where sixteen sockets to one lane cost the head 44% and finished
//! them no sooner.
//!
//! **RECLAIM outranks the spill.** The head is ahead of the lane in the
//! user's queue, so when its articles come unstuck its claim on a freed
//! permit must outrank every spilled lane's or the spill inverts queue
//! priority. That rule lives at the lease
//! (`nzbkit::pool::handoff::LeaseClass::Spill`); what lives here is
//! deciding WHEN to ask for the sockets back.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use nzbkit::pool::handoff::SpillGate;

use crate::MutexExt;

/// Samples in the trigger's window.
///
/// The same shape `whyslow` uses for the same reason: a verdict about a
/// job is worth nothing on one reading. This window is not shared with
/// it deliberately - whyslow answers "what is holding this job back"
/// for a human, and reuses its answer for the stand-down below; this
/// answers "can these sockets be used by something else", which is a
/// different question and must be able to say no while whyslow is still
/// saying `unknown`.
///
/// **TWENTY TICKS, and NOT twenty seconds - this comment said seconds
/// until 2 Sep 2026 and a CI failure disproved it the same day.** The
/// samples come from the shared one-second ticker in `linkpeak::spawn`,
/// and that cadence is a best effort rather than a guarantee: on a
/// 4-vCPU runner sharing a shard with three other daemon tests, the
/// e2e rig's head sat on dead air for its whole 36 s and the governor
/// still never reached twelve agreeing samples, because the ticker did
/// not deliver them (run 33612016239; the fix was to give that test
/// nextest's isolated group, not to move any threshold).
///
/// What that means for the FEATURE is mild and arguably right: a box
/// too loaded to tick reliably is a box where a second download is less
/// welcome, so firing late there is the conservative direction and
/// every stand-down still reads current state. What it means for a
/// READER is that this is a count of observations, so "how long before
/// a spill starts" has no fixed answer and must not be quoted as one.
///
/// Making it time-based instead - carry each sample's instant and ask
/// for twelve agreeing seconds of REAL time - was considered and not
/// built: it would change when the mechanism fires on exactly the boxes
/// nobody has measured it on, and the switch is off. Whoever turns it
/// on should decide this with a measurement rather than inherit it.
const WINDOW: usize = 20;

/// Samples that must agree before a spill starts: 60% of the window,
/// `whyslow`'s majority rule.
const MAJORITY: usize = 12;

/// And the count it must fall BACK to before the sockets are reclaimed.
/// A separate, much lower number rather than the same one, because a
/// mechanism that starts and stops on one threshold chatters: every
/// start moves the very quantity the threshold reads (the head has
/// fewer sockets, so its delivered-per-socket RISES), which would walk
/// the fleet up and down for the whole of a dead-air episode and pay a
/// dial for each turn.
const CLEAR: usize = 6;

/// Delivered bytes per dialling socket, as a fraction of the link's own
/// trained per-socket carry, under which a socket is judged not to be
/// carrying.
///
/// **Chosen, not measured, and the arms that pin it are the tests and
/// the e2e rather than a bench round.** The study measures the REGIME
/// (dead air is latency-bound and sub-linear in sockets; a slow
/// provider and a refusal storm are neither) and leaves the bar to the
/// build. Half is the defensible reading of "not carrying": a head
/// delivering less than half what a socket on this link is known to
/// hold, for twelve of the last twenty readings, is not a head having a
/// bad second. A slow provider reads ~1 here however slow it is, which is
/// the whole point of dividing by a trained carry rather than comparing
/// to a rate.
const CARRY_BAR: f64 = 0.5;

/// Concurrent download phases, including the head.
///
/// **Two, and the study's own range is 2-4** (`postproc_jobs` is the
/// precedent at exactly that clamp, and the measurement says four buys
/// nothing over two - the dominant variable is how many sockets the
/// HEAD keeps, not the fan-out). Two is also what this daemon can
/// actually run today and that is a structural bound rather than a
/// preference: `Daemon::active_dl` and `Daemon::drain_dl` are two
/// slots, `wire_counters` reads exactly those two under one lock, and
/// `stall::watched()` judges one owner against one drainer. A third
/// phase is a change to all three and to every reader that assumes
/// them.
///
/// The queue is still drained by more than one job: a lane that
/// finishes takes the NEXT queued job while the head is still going
/// (`tasks::worker`'s chaining loop), which is where item 10's win
/// comes from. What is capped is how many run AT ONCE.
///
/// One cost that WAS on this list is not any more: item 1 landed on
/// 2 Sep 2026, so `inflight_cap` is a shared charge and N phases admit
/// one wire-side body ceiling between them rather than N.
pub const MAX_DOWNLOAD_PHASES: usize = 2;

/// What fraction of the fleet may be lent at most: a quarter.
///
/// From the best measured arm rather than from taste. At a lease cap of
/// 32 the arm that won left the head 24 and lent 8, finishing all eight
/// queued jobs inside the head's window for a 17% cost to the head;
/// every arm that lent half cost the head 43-50% and finished the same
/// jobs no sooner. Absorption then usually takes less than this - a
/// twelve-article job is given twelve sockets, not eight - so this is a
/// ceiling on the ceiling.
const LEND_DIVISOR: usize = 4;

/// One second of evidence about the job on the wire.
///
/// Every field is a reading somebody else already publishes. Nothing
/// here opens a detector of its own, which is `slowstore.rs`'s standing
/// warning (a stall watchdog once aborted a job on a wrong reading) and
/// the discipline TODO 306's answer took.
#[derive(Clone, Copy, Debug, Default)]
pub struct Tick {
    /// Delivered bytes/s across the head's servers, from the pool's own
    /// windowed EWMA (`ServerLive::srv_rate_bps`), which is fed only by
    /// real bodies and never by probes.
    pub delivered_bps: f64,
    /// Sockets those bytes are divided by: sessions this run currently
    /// holds. Dialling, not spawned - a parked worker delivers nothing,
    /// so it must not divide a delivered rate.
    pub sockets: usize,
    /// The link's trained per-socket carry in bytes/s (TODO 275 item 1
    /// part 2). 0 = nothing banked yet, and this module then has no
    /// opinion at all.
    pub carry_bps: u64,
    /// `whyslow`'s standing verdict is `client` - our own pipeline is
    /// the bottleneck. A downstream bottleneck is SHARED, so a second
    /// job makes it worse.
    pub client_verdict: bool,
    /// The output volume is suspect or the queue is paused for it. Same
    /// argument, one layer down.
    pub storage_suspect: bool,
    /// The output volume ROTATES. `get::plan::clamp_concurrency` picks
    /// ONE decoder there "so the article lanes stop being seek lanes",
    /// and that rule is per-JOB: two concurrent downloads writing two
    /// jobs' articles to one spinning volume reinstate exactly the seek
    /// pattern it removes, and neither job can see the other's decoder.
    pub rotational: bool,
    /// The run's own hand-over signal has latched - a primary worker
    /// found itself idle with the queue dry, and the shipped cross-job
    /// hand-over is already starting the next job on the sockets this
    /// one is shedding. Nothing to add: item 5's fourth stand-down.
    ///
    /// **The latch and not queue-dry itself**, and the difference is
    /// the whole feature. A deep pipeline runs out of ARTICLES TO HAND
    /// OUT long before it runs out of work - the study measures a
    /// 360-connection fleet dry at 11% of its run with every connection
    /// still holding four articles - so a stand-down on queue-dry would
    /// switch this mechanism off for the last 89% of every job,
    /// including the whole of the dead-air regime it exists for. The
    /// latch fires on an IDLE worker after dry, which is precisely when
    /// the sockets are spare for the shipped reason and this mechanism
    /// has nothing left to lend.
    pub handover_latched: bool,
    /// A job is startable behind this one. Without one there is nothing
    /// to lend TO, and latching the hand-over signal would leave the
    /// runner polling for a successor for the rest of the head's run.
    pub queue_waiting: bool,
}

impl Tick {
    /// Delivered bytes per dialling socket over the trained carry.
    /// `None` when the question cannot be asked: no trained carry, or
    /// no socket to divide by.
    pub fn useful_fraction(&self) -> Option<f64> {
        (self.carry_bps > 0 && self.sockets > 0)
            .then(|| self.delivered_bps / (self.sockets as f64 * self.carry_bps as f64))
    }

    /// Any of the mandatory stand-downs (item 5). Checked before the
    /// trigger and again on every tick of a live episode, so a volume
    /// that goes suspect mid-spill takes the sockets back.
    pub fn stood_down(&self) -> bool {
        self.client_verdict || self.storage_suspect || self.rotational || self.handover_latched
    }

    /// Is this second's reading "the fleet is not carrying"? A
    /// stand-down votes NO rather than abstaining: an episode must not
    /// be able to start on a window half of which was collected while a
    /// stand-down held.
    fn not_carrying(&self) -> bool {
        !self.stood_down() && self.useful_fraction().is_some_and(|f| f < CARRY_BAR)
    }
}

/// What the governor wants done this second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing to do.
    Idle,
    /// Start an episode: lend the head's fleet to the queue.
    Spill,
    /// Take the sockets back - the head recovered, or a stand-down
    /// fired.
    Reclaim,
}

#[derive(Default)]
pub struct Core {
    votes: VecDeque<bool>,
    live: bool,
}

impl Core {
    fn step(&mut self, t: &Tick) -> Verdict {
        self.votes.push_back(t.not_carrying());
        while self.votes.len() > WINDOW {
            self.votes.pop_front();
        }
        let agree = self.votes.iter().filter(|v| **v).count();
        // A stand-down reclaims IMMEDIATELY and does not wait out the
        // window: the reasons are all "a second job would make this
        // worse", and they are true from the tick they are seen.
        if self.live && (t.stood_down() || agree <= CLEAR) {
            self.live = false;
            return Verdict::Reclaim;
        }
        if !self.live && agree >= MAJORITY && t.queue_waiting && !t.stood_down() {
            self.live = true;
            return Verdict::Spill;
        }
        Verdict::Idle
    }
}

/// The daemon's spill governor: one per daemon, ticked once a second
/// off the loop `linkpeak::spawn` already runs.
#[derive(Default)]
pub struct Governor {
    core: std::sync::Mutex<Core>,
    /// The gate every pool built while the switch is on carries a seat
    /// on. ONE per daemon and not one per episode, because a head's
    /// pools are built long before an episode starts and cannot be
    /// handed a gate afterwards: the seat goes in at fleet build, and
    /// what moves later is only whether this is open.
    gate: std::sync::OnceLock<Arc<SpillGate>>,
    /// The per-socket carry this run's HEAD is judged against, frozen
    /// at the moment that head's pool is built (item 12). 0 = nothing
    /// was banked before this job started, and the governor then has no
    /// opinion at all.
    ///
    /// **A SNAPSHOT and not a reading, and that is the whole of item
    /// 12.** `serve::linecarry` banks DURING a run, by design and off
    /// this very ticker, so reading it live let a head stuck on dead
    /// air overwrite the banked carry with its own crippled figure
    /// within four seconds and be measured against itself from then on:
    /// measured 2 Sep 2026, a seed of 2,000,000 B/s replaced by 42,905
    /// at t=4 s and settling at 54,358, after which the head's own
    /// delivery over its remaining sockets read 1.12-1.17 of that same
    /// number and walked the window down to `CLEAR` - so every episode
    /// ended after about fifteen seconds while the head was still
    /// stuck. Freezing it here rather than making `linecarry` stop
    /// learning is deliberate: that module's in-run learning is TODO
    /// 275 item 1 part 2's whole purpose and the fleet-sizing caller
    /// wants the newest number.
    carry: std::sync::atomic::AtomicU64,
    /// What the live episode walked down, `None` between episodes.
    episode: std::sync::Mutex<Option<Episode>>,
    /// The output volume's storage class, cached by path. Probing it is
    /// real IO (`disk::detect_storage` reads the device), and this is
    /// asked once a second - so it is asked once per output directory
    /// instead.
    rot: std::sync::Mutex<Option<(std::path::PathBuf, bool)>>,
}

/// One live spill episode.
pub struct Episode {
    /// `(the head's target, what it read before the walk-down)`, so
    /// reclaim restores the head to exactly what the line-cap governor
    /// and the TODO 112 walker had agreed on rather than to a number
    /// this module invented.
    ///
    /// The targets themselves and not their row keys: the map a key
    /// would be looked up in is the TUNER's, which a default install
    /// never populates, and holding the `Arc` cannot go stale or miss.
    pub restore: Vec<(Arc<nzbkit::pool::ConnTarget>, usize)>,
    /// Sockets lent, for the diagnostics surface.
    pub lent: usize,
    pub since: Instant,
}

impl Governor {
    /// One second of evidence in, one decision out. Pure apart from the
    /// window it keeps; the caller does the acting.
    pub fn tick(&self, t: &Tick) -> Verdict {
        self.core.lock_ok().step(t)
    }

    /// The daemon's one gate. Minted on first use so `Default` stays
    /// trivial and every construction of `Daemon` gets one without
    /// saying so.
    pub fn gate(&self) -> Arc<SpillGate> {
        self.gate.get_or_init(SpillGate::new).clone()
    }

    /// Is the output volume rotational? Cached by path - see `rot`.
    pub fn rotational(&self, out: &std::path::Path) -> bool {
        {
            let seen = self.rot.lock_ok();
            if let Some((p, v)) = seen.as_ref()
                && p == out
            {
                return *v;
            }
        }
        // Both halves of the probe, for the same reason
        // `disk::decoders_for_storage` reads both: this stand-down and
        // that clamp are the SAME sentence about write order reaching a
        // platter, so the anonymous-device fallback (btrfs, ZFS) must
        // not widen one of them without the other. TODO 325.
        let probe = nzbkit::disk::probe_storage(out);
        let v = probe.class == nzbkit::disk::Storage::Rotational && probe.direct_dev;
        *self.rot.lock_ok() = Some((out.to_path_buf(), v));
        v
    }

    /// The frozen denominator: what one socket on this link carried
    /// before the current head started. 0 = no opinion.
    pub fn carry_bps(&self) -> u64 {
        self.carry.load(Ordering::Relaxed)
    }

    /// Freeze it, at the moment a HEAD's pool is built. See `carry`.
    fn freeze_carry(&self, carry_bps: u64) {
        self.carry.store(carry_bps, Ordering::Relaxed);
    }

    /// Is an episode live right now? Read by the diagnostics surface
    /// and by the runner's chaining loop.
    pub fn is_live(&self) -> bool {
        self.episode.lock_ok().is_some()
    }

    /// Sockets lent by the live episode, 0 when none is.
    pub fn lent(&self) -> usize {
        self.episode.lock_ok().as_ref().map_or(0, |e| e.lent)
    }

    pub fn open(&self, e: Episode) {
        *self.episode.lock_ok() = Some(e);
        self.gate().open();
    }

    /// End the episode and hand back what has to be undone. The gate is
    /// SHUT here, so no pool takes another spill decision, and the
    /// caller walks the targets back up.
    pub fn close(&self) -> Option<Episode> {
        let taken = self.episode.lock_ok().take();
        self.gate().close();
        // A close that comes from the outside (the head ended, the
        // queue drained) must not leave the window claiming an episode
        // is live, or the next start is refused for the length of it.
        self.core.lock_ok().live = false;
        taken
    }
}

/// How many sockets a successor is given: what it can ABSORB, bounded
/// by what is left of the slice.
///
/// Both halves matter. A job with three articles left cannot use eight
/// sockets on any link, so offering them wastes seven and the residue
/// belongs to the next job down the queue (or, with none, back to the
/// head - which is where the measurement says the head's own cost is
/// decided). And a job with a thousand articles may not have the whole
/// fleet: the slice is what the head could spare.
pub fn absorb(remaining_articles: usize, slice_left: usize) -> usize {
    remaining_articles.min(slice_left)
}

/// The most of a fleet of `cap` that may be lent at once.
///
/// A quarter, floored at one so a small account can still lend
/// something, and never so much that the head is left under
/// `MIN_DOWNLOAD_FLEET` - below two sockets a pool stops being a fleet
/// at all (`handoff::MIN_DOWNLOAD_FLEET` carries that argument).
pub fn lendable(cap: usize) -> usize {
    let floor = nzbkit::pool::handoff::MIN_DOWNLOAD_FLEET;
    let head_keeps = cap.saturating_sub(cap / LEND_DIVISOR).max(floor);
    cap.saturating_sub(head_keeps)
}

/// Download phases live on the wire right now: the job that owns the
/// hub, plus the one in the drain slot if there is one.
///
/// The two slots ARE the count - `wire_counters` reads exactly those
/// two under one lock, and nothing else in this daemon can hold a
/// pipeline - so this is a reading rather than a tally somebody has to
/// remember to keep in step.
pub fn phases_live(d: &crate::daemon::Daemon) -> usize {
    usize::from(d.active_dl.lock_ok().is_some()) + usize::from(d.drain_dl.lock_ok().is_some())
}

/// May another download phase start right now? The enforcement half of
/// [`MAX_DOWNLOAD_PHASES`].
///
/// Asked before each link of the spill chain rather than trusted to the
/// shape of the loop: the loop finishes a lane before it starts the
/// next one today, so this is false only if that ever stops being
/// true - which is exactly the change that would quietly turn a
/// two-phase daemon into an N-phase one, with N `BufPool`s and N output
/// file sets, and no reader the wiser. (The wire-side body ceiling is
/// no longer one of those costs: TODO 313 item 1 made `inflight_cap` a
/// shared ledger on 2 Sep 2026. The rest still scale with N.)
pub fn phase_available(d: &crate::daemon::Daemon) -> bool {
    phases_live(d) < MAX_DOWNLOAD_PHASES
}

/// Is the spill mechanism switched on for this daemon? The whole
/// feature is behind it and it is OFF until measured.
pub fn enabled(d: &crate::daemon::Daemon) -> bool {
    d.queue_spill.load(Ordering::Relaxed)
}

/// A download phase is starting: freeze the trigger's denominator if
/// this is the HEAD (TODO 313 item 12).
///
/// **Called with the same role the pool's `SpillSeat` is built from,
/// and from the same statement**, so there is one rule about which job
/// is the head rather than two that can disagree. A LANE start must
/// leave the snapshot alone: while an episode is live the head has
/// moved to the drain slot and the lane owns the hub, so a lane that
/// re-snapshotted would hand the governor a fresh denominator in the
/// middle of the very episode it is judging - which is the defect this
/// function exists to remove, arriving through the other door.
///
/// It runs whether or not the switch is on. The read side already
/// short-circuits on `enabled`, and taking it unconditionally is what
/// makes a switch flipped ON mid-run read this head's own pre-job
/// carry instead of whatever was frozen for some earlier job.
pub fn note_pool_build(d: &crate::daemon::Daemon, role: nzbkit::pool::handoff::SpillRole) {
    if role == nzbkit::pool::handoff::SpillRole::Head {
        d.spill.freeze_carry(d.line_carry.carry_bps());
    }
}

/// Articles a job of `bytes` probably holds, for the absorption sizing.
///
/// **An ESTIMATE, and the tree has nothing better to offer here.** The
/// queue row records `total_bytes` and not a segment count - the NZB is
/// parsed at enqueue for the bytes and the parse is not kept - so the
/// alternative is re-parsing an NZB in the runner's own path, moments
/// before the pipeline parses it again for real.
///
/// 384 KB is the article size the study measured on and a common yEnc
/// segment; real posts run from there to about 800 KB. So this errs
/// HIGH on the article count, and that direction is the safe one: the
/// count only ever has to beat the slice, which is a quarter of the
/// fleet, so over-estimating a big job simply hands it the whole slice
/// (which is right) and over-estimating a small one costs a socket or
/// two that do nothing. Under-estimating would starve exactly the small
/// jobs this mechanism exists to clear.
pub fn articles_for(bytes: u64) -> usize {
    const ARTICLE_BYTES: u64 = 384_000;
    usize::try_from(bytes.div_ceil(ARTICLE_BYTES)).unwrap_or(usize::MAX)
}

/// One second of observation and, when it says so, one action. Rides
/// the ticker `linkpeak::spawn` already runs, for the reason
/// `linecarry::feed` beside it does: nothing here is worth a task of
/// its own, and reading the same job's state a second apart is what
/// keeps two learners from disagreeing about what the link did.
pub fn feed(d: &Arc<crate::daemon::Daemon>) {
    if !enabled(d) {
        return;
    }
    let t = sample(d);
    // One line a second at DEBUG, off in production and the only way to
    // see WHY a spill did not fire: every input the decision reads,
    // named, in the order the rules ask them.
    tracing::debug!(
        target: "queue",
        "spill tick: bps={:.0} sockets={} carry={} frac={:?} client={} storage={} rot={}          handover={} waiting={} live={}",
        t.delivered_bps,
        t.sockets,
        t.carry_bps,
        t.useful_fraction(),
        t.client_verdict,
        t.storage_suspect,
        t.rotational,
        t.handover_latched,
        t.queue_waiting,
        d.spill.is_live(),
    );
    // And the two numbers that say whether a live episode is actually
    // MOVING sockets, which is a different question from whether it
    // fired: permits held across the account, and the head's targets.
    // Both were the difference between "the mechanism is wired" and
    // "the mechanism works" twice on 2 Sep 2026 - a lane that took no
    // permit for twenty-nine seconds looked identical from the verdict
    // side.
    tracing::debug!(
        target: "queue",
        "spill lease: held={:?} targets={:?}",
        d.hub.conn_budget.get().map(|b| b.held_total()),
        d.hub
            .job_targets
            .lock_ok()
            .iter()
            .map(|t| t.get())
            .collect::<Vec<_>>(),
    );

    match d.spill.tick(&t) {
        Verdict::Idle => {}
        Verdict::Spill => start(d),
        Verdict::Reclaim => reclaim(d, "the head is using its fleet again"),
    }
}

/// Read this second's evidence off the daemon.
///
/// The head's own gauges, wherever the head currently is: its pool is
/// on the hub until a lane starts and in the DRAIN SLOT afterwards, and
/// this has to keep watching the same job across that move or an
/// episode would judge its own lane and reclaim on the spot.
pub fn sample(d: &Arc<crate::daemon::Daemon>) -> Tick {
    let live_now = d.spill.is_live();
    let live = match live_now {
        true => d
            .drain_dl
            .lock_ok()
            .as_ref()
            .and_then(|s| s.pool_live.clone()),
        false => d.hub.pool_live.lock_ok().clone(),
    };
    let (delivered_bps, sockets) = live.as_ref().map_or((0.0, 0), |l| {
        l.servers.iter().fold((0.0, 0), |(bps, n), s| {
            (
                bps + s.srv_rate_bps().unwrap_or(0.0),
                n + s.connected.load(Ordering::Relaxed),
            )
        })
    });
    // Bound to a local FIRST: written as one chain, the `active_dl`
    // guard is a temporary that lives to the end of the statement, so
    // the queue lock would be taken while it is still held. Nothing on
    // the tree takes those two in that order today and a once-a-second
    // diagnostic is not the place to be the first.
    let active = d.active_dl.lock_ok().clone();
    let out = active.and_then(|id| {
        let q = d.queue.lock_ok();
        q.iter().find_map(|j| {
            let g = j.lock_ok();
            (g.nzo_id == id).then(|| g.out_dir.clone())
        })
    });
    Tick {
        delivered_bps,
        sockets,
        // FROZEN at this head's pool build and not read live off
        // `linecarry`, which banks during the run - see `Governor::
        // carry` for what reading it live did to every episode.
        carry_bps: d.spill.carry_bps(),
        client_verdict: d.whyslow.blames_client(),
        storage_suspect: d.slow_storage.suspect(nzbkit::pool::now_ms()) || d.slow_storage.paused(),
        rotational: out.as_deref().is_some_and(|p| d.spill.rotational(p)),
        // Past queue-dry the existing hand-over owns the endgame, and
        // the latch IS that moment: it fires when a primary worker
        // first finds itself idle with the queue dry.
        //
        // NOT read once an episode is live, and that is not a
        // convenience. Starting a spill latches this very signal - it
        // is how the runner is told to start a lane - so a live episode
        // reading it would stand itself down on its own first tick,
        // reclaim, and leave a lane running on sockets the head had
        // just taken back. While an episode is live the four stand-downs
        // that still apply are the three above, which are all about
        // whether a second job would make things worse.
        handover_latched: !live_now
            && d.hub
                .handoff
                .lock_ok()
                .as_ref()
                .is_some_and(|h| h.is_latched()),
        queue_waiting: live_now || waiting_behind(d),
    }
}

/// Is there a job that could be spilled onto? A cheap read of the queue
/// rather than a `pick_job`, which the runner will do properly a moment
/// later - this only has to answer "is it worth latching the hand-over
/// signal", and latching it with nothing to start would leave the
/// runner polling for a successor for the rest of the head's run.
fn waiting_behind(d: &crate::daemon::Daemon) -> bool {
    let active = d.active_dl.lock_ok().clone();
    d.queue.lock_ok().iter().any(|j| {
        let g = j.lock_ok();
        g.state == crate::job::JobState::Queued
            && !g.paused
            && !g.tombstone
            && Some(&g.nzo_id) != active.as_ref()
    })
}

/// Open an episode: walk the head's live targets down and latch its
/// hand-over signal, which is the runner's cue to start a job behind
/// it.
///
/// **No live target, no spill**, and that is a stand-down as real as
/// the four in `Tick`. A pinned account, a single-connection server and
/// an install with the fleet cap off all run without a `ConnTarget`
/// (`get::fleet`), and lending needs one: it is the only way a running
/// fleet gives a socket back without retiring the worker that held it.
pub fn start(d: &Arc<crate::daemon::Daemon>) {
    let mut restore = Vec::new();
    let mut lent = 0usize;
    for target in d.hub.job_targets.lock_ok().iter() {
        let was = target.get();
        let give = lendable(was);
        if give == 0 {
            continue;
        }
        target.set(was - give);
        restore.push((target.clone(), was));
        lent = lent.max(give);
    }
    if restore.is_empty() {
        // Nothing to walk down. Put the window back so the next second
        // can ask again rather than latching a live episode that lent
        // nothing.
        //
        // SAYS SO, since 2 Sep 2026. This is the one way the governor
        // can decide to spill and then do nothing, and it used to be
        // completely silent - no log at any level - which is the worst
        // possible shape for the investigation that finds it. A pinned
        // account, a single-connection server and an install with the
        // fleet cap off all run without a `ConnTarget`, and lending
        // needs one.
        tracing::debug!(
            target: "queue",
            "spill wanted but this fleet has no live connection target to walk \
             down - nothing was lent"
        );
        d.spill.close();
        return;
    }
    d.spill.open(Episode {
        restore,
        lent,
        since: Instant::now(),
    });
    tracing::info!(
        target: "queue",
        "this download is not using {lent} of its connections - lending them to the \
         jobs behind it while it waits"
    );
    d.note_event(
        "spill",
        format!(
            "the download at the head of the queue is waiting on articles, so {lent} of \
             its connections are working on the jobs behind it"
        ),
    );
    // The runner is parked on exactly this: it starts the next job the
    // moment the signal latches.
    if let Some(h) = d.hub.handoff.lock_ok().as_ref() {
        h.latch();
    }
}

/// End the episode: shut the gate and walk the head's targets back to
/// what they were.
///
/// The order matters. The gate goes first, so no pool takes a fresh
/// spill decision while the targets move; then the head's workers are
/// re-admitted and take their permits back as `Download`-class waiters,
/// which is what a spilled lane's `LeaseClass::Spill` acquire stands
/// behind. Nothing has to be told to give a socket up: a lane's idle
/// worker reads the head parked on the lease and hands one over on its
/// next idle turn.
pub fn reclaim(d: &Arc<crate::daemon::Daemon>, why: &str) {
    let Some(e) = d.spill.close() else {
        return;
    };
    for (t, was) in &e.restore {
        // Never LOWER on the way back: the line-cap governor and the
        // TODO 112 walker may have moved this target during the
        // episode, and their answer is newer than ours.
        t.update(|now| (now < *was).then_some(*was));
    }
    tracing::info!(
        target: "queue",
        "taking the lent connections back for the job at the head of the queue - {why} \
         (spill held {} s)",
        e.since.elapsed().as_secs()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tick in the regime this mechanism is FOR: sockets held, bytes
    /// trickling far under what a socket on this link is known to
    /// carry, nothing downstream to blame, a job waiting behind.
    fn dead_air() -> Tick {
        Tick {
            delivered_bps: 8.0 * 100_000.0,
            sockets: 8,
            carry_bps: 2_000_000,
            queue_waiting: true,
            ..Tick::default()
        }
    }

    /// And the one it must decline: a slow provider. The absolute rate
    /// is just as low, and the trained carry is just as low with it, so
    /// the ratio is ~1 and the fleet is being used perfectly well.
    fn slow_provider() -> Tick {
        Tick {
            delivered_bps: 8.0 * 95_000.0,
            sockets: 8,
            carry_bps: 100_000,
            queue_waiting: true,
            ..Tick::default()
        }
    }

    fn run(g: &Governor, t: &Tick, secs: usize) -> Vec<Verdict> {
        (0..secs).map(|_| g.tick(t)).collect()
    }

    #[test]
    fn the_trigger_fires_on_a_sustained_low_per_socket_carry() {
        let g = Governor::default();
        let t = dead_air();
        assert!(t.useful_fraction().is_some_and(|f| f < CARRY_BAR));
        let v = run(&g, &t, MAJORITY - 1);
        assert!(
            v.iter().all(|v| *v == Verdict::Idle),
            "a verdict about a job is worth nothing on a short window"
        );
        assert_eq!(g.tick(&t), Verdict::Spill, "the majority tick fires it");
        assert_eq!(g.tick(&t), Verdict::Idle, "and it fires ONCE");
    }

    /// The row a naive "low rate" trigger gets catastrophically wrong.
    #[test]
    fn a_slow_provider_never_triggers_a_spill() {
        let g = Governor::default();
        let t = slow_provider();
        assert!(
            t.useful_fraction().is_some_and(|f| f > CARRY_BAR),
            "a slow provider is slow FOR THAT PROVIDER TOO - the ratio is \
             what separates the populations, and the level never can"
        );
        assert!(run(&g, &t, WINDOW * 2).iter().all(|v| *v == Verdict::Idle));
    }

    /// Refusals are not evidence here at all, which is the house rule
    /// `pool/steer.rs` states and section 3 of the study measures: a
    /// high refusal ratio predicts a job that finishes SOONER. This
    /// module has no field for one, so the pin is that a fleet clearing
    /// refusals at a healthy per-socket carry is invisible to it.
    #[test]
    fn a_refusal_storm_is_invisible_to_the_trigger() {
        let g = Governor::default();
        let t = Tick {
            delivered_bps: 8.0 * 1_900_000.0,
            sockets: 8,
            carry_bps: 2_000_000,
            queue_waiting: true,
            ..Tick::default()
        };
        assert!(run(&g, &t, WINDOW * 2).iter().all(|v| *v == Verdict::Idle));
    }

    /// With no trained carry banked there is no denominator, so the
    /// question cannot be asked and the answer is silence - never a
    /// guess against the job's own bad start.
    #[test]
    fn no_trained_carry_means_no_opinion() {
        let g = Governor::default();
        let t = Tick {
            carry_bps: 0,
            ..dead_air()
        };
        assert!(t.useful_fraction().is_none());
        assert!(run(&g, &t, WINDOW * 2).iter().all(|v| *v == Verdict::Idle));
    }

    #[test]
    fn every_stand_down_refuses_a_spill_and_ends_a_live_one() {
        let marks: [(&str, fn(&mut Tick)); 4] = [
            ("whyslow says client", |t| t.client_verdict = true),
            ("storage suspect", |t| t.storage_suspect = true),
            ("rotational output", |t| t.rotational = true),
            ("the hand-over has latched", |t| t.handover_latched = true),
        ];
        for (name, mark) in marks {
            // It refuses to start.
            let g = Governor::default();
            let mut t = dead_air();
            mark(&mut t);
            assert!(t.stood_down(), "{name} is a stand-down");
            assert!(
                run(&g, &t, WINDOW * 2).iter().all(|v| *v == Verdict::Idle),
                "{name} must refuse to start a spill"
            );

            // And it ends one that is already live, on the tick it is
            // seen rather than after another window.
            let g = Governor::default();
            let healthy = dead_air();
            run(&g, &healthy, MAJORITY);
            assert!(g.tick(&healthy) == Verdict::Idle);
            let mut t = dead_air();
            mark(&mut t);
            assert_eq!(g.tick(&t), Verdict::Reclaim, "{name} reclaims at once");
        }
    }

    /// Nothing to lend TO is not a reason to lend. Without this the
    /// runner is left polling for a successor for the rest of the
    /// head's run, because the hand-over signal latches once.
    #[test]
    fn an_empty_queue_never_starts_a_spill() {
        let g = Governor::default();
        let t = Tick {
            queue_waiting: false,
            ..dead_air()
        };
        assert!(run(&g, &t, WINDOW * 2).iter().all(|v| *v == Verdict::Idle));
    }

    /// The head comes unstuck: the sockets go back. On a LOWER bar than
    /// the one that started it, because starting moves the very
    /// quantity the bar reads - the head has fewer sockets, so its
    /// delivered-per-socket rises - and one threshold for both
    /// directions would walk the fleet up and down all episode.
    #[test]
    fn a_recovering_head_reclaims_and_the_bar_has_hysteresis() {
        let g = Governor::default();
        let stuck = dead_air();
        run(&g, &stuck, MAJORITY);
        let healthy = Tick {
            delivered_bps: 8.0 * 1_800_000.0,
            ..dead_air()
        };
        // Enough healthy seconds to fall under MAJORITY, but not yet to
        // CLEAR: still spilling.
        let v = run(&g, &healthy, WINDOW - MAJORITY + 1);
        assert!(
            v.iter().all(|x| *x == Verdict::Idle),
            "one good second is not a recovery"
        );
        let v = run(&g, &healthy, WINDOW);
        assert!(
            v.contains(&Verdict::Reclaim),
            "a sustained recovery takes the sockets back"
        );
        assert!(
            v.iter().filter(|x| **x == Verdict::Reclaim).count() == 1,
            "and reclaims once, not on every tick after"
        );
    }

    /// Item 10's sizing rule: what the successor can absorb, bounded by
    /// what is left of the slice, with the residue passing on.
    #[test]
    fn a_successor_is_sized_by_absorption_and_the_residue_passes_on() {
        // The measured shape: a lease at 32, a slice of 8, and small
        // jobs of 12 articles behind.
        let slice = lendable(32);
        assert_eq!(slice, 8, "a quarter of the fleet, so the head keeps 24");
        // The first job takes what it can hold, and it is the SLICE
        // that binds here, not the articles.
        let first = absorb(12, slice);
        assert_eq!(first, 8);
        // A job with three articles left takes three, and five pass on.
        assert_eq!(absorb(3, slice), 3);
        assert_eq!(
            slice - absorb(3, slice),
            5,
            "the residue is not spent on it"
        );
        // Nothing to absorb, nothing given.
        assert_eq!(absorb(0, slice), 0);
    }

    /// A fleet cannot be lent down to nothing: below two sockets a pool
    /// stops being a fleet at all.
    #[test]
    fn the_head_keeps_a_floor_whatever_the_cap() {
        assert_eq!(lendable(0), 0);
        assert_eq!(lendable(1), 0, "a one-socket account lends nothing");
        assert_eq!(lendable(2), 0);
        assert_eq!(
            lendable(3),
            0,
            "and neither does one that would be left short"
        );
        assert_eq!(lendable(8), 2);
        assert_eq!(lendable(50), 12);
        for cap in 0..200usize {
            assert!(
                cap.saturating_sub(lendable(cap))
                    >= nzbkit::pool::handoff::MIN_DOWNLOAD_FLEET.min(cap),
                "cap {cap} left the head under the floor"
            );
        }
    }

    /// The phase cap is the count of concurrent DOWNLOAD phases, head
    /// included, and it is two.
    #[test]
    fn the_concurrent_phase_cap_is_two() {
        assert_eq!(MAX_DOWNLOAD_PHASES, 2);
        assert!(
            (1..=4).contains(&MAX_DOWNLOAD_PHASES),
            "and it stays inside the study's own 2-4 range and \
             postproc_jobs' 1..=4 precedent"
        );
    }

    /// A scratch daemon of this test's own - the house idiom in
    /// `serve`, keyed on the pid and the case so ~1750 tests sharing a
    /// process stay out of each other's spool files.
    fn daemon(tag: &str) -> (crate::testscratch::ScratchDir, Arc<crate::daemon::Daemon>) {
        let dir = std::env::temp_dir().join(format!("nzbfast-spill-{tag}-{}", std::process::id()));
        let dir = crate::testscratch::ScratchDir::attach(&dir);
        let d = crate::testutil::test_daemon(&dir);
        (dir, d)
    }

    /// **ITEM 12, and it is the defect this file was reopened for.**
    /// The denominator is frozen when the head's pool is built, so a
    /// carry the head itself re-trains mid-run cannot move what the
    /// governor divides by.
    ///
    /// The numbers are the ones measured off `RUST_LOG=queue=debug` on
    /// 2 Sep 2026: a link banked at 2,000,000 B/s, and a head stuck on
    /// dead air that re-trained it to 54,358 within a few seconds and
    /// was then measured against itself for the rest of the run.
    #[test]
    fn a_carry_the_head_retrains_mid_run_does_not_move_the_denominator() {
        let (_dir, d) = daemon("frozen-carry");
        // What the link carried BEFORE this job - the bank a real
        // install brings to a job's start.
        assert!(d.line_carry.observe(2_000_000));
        note_pool_build(&d, nzbkit::pool::handoff::SpillRole::Head);
        assert_eq!(d.spill.carry_bps(), 2_000_000);
        assert_eq!(sample(&d).carry_bps, 2_000_000);

        // Now the head trains it down on its own dead air, which is
        // exactly what the one-second ticker does to a stuck head.
        assert!(d.line_carry.observe(54_358));
        assert_eq!(
            d.line_carry.carry_bps(),
            54_358,
            "linecarry still learns in-run - item 12 does not stop it,              because TODO 275 item 1 part 2's fleet-sizing caller wants              the newest number"
        );
        assert_eq!(
            sample(&d).carry_bps,
            2_000_000,
            "but the governor still divides by what the link carried              BEFORE this job started"
        );
    }

    /// And the other door: a spilled LANE start must not re-freeze it.
    /// While an episode is live the head has moved to the drain slot
    /// and the lane owns the hub, so a lane that re-snapshotted would
    /// hand the governor a fresh denominator in the middle of the very
    /// episode it is judging.
    #[test]
    fn a_spilled_lane_start_leaves_the_frozen_denominator_alone() {
        let (_dir, d) = daemon("lane-carry");
        assert!(d.line_carry.observe(2_000_000));
        note_pool_build(&d, nzbkit::pool::handoff::SpillRole::Head);
        assert!(d.line_carry.observe(54_358));
        note_pool_build(&d, nzbkit::pool::handoff::SpillRole::Lane);
        assert_eq!(
            d.spill.carry_bps(),
            2_000_000,
            "a lane start is not a head start"
        );
    }

    /// **A fresh install still has NO OPINION AT ALL** (item 4), and
    /// the snapshot must not quietly give it one: the whole point is
    /// that a job which starts badly is never measured against its own
    /// bad start.
    #[test]
    fn nothing_banked_before_the_job_is_no_opinion_for_the_whole_job() {
        let (_dir, d) = daemon("fresh-carry");
        assert_eq!(d.line_carry.carry_bps(), 0, "a fresh install banks nothing");
        note_pool_build(&d, nzbkit::pool::handoff::SpillRole::Head);
        // The job then trains a carry of its own, as any running job
        // does. Before item 12 that reading became the denominator.
        assert!(d.line_carry.observe(54_358));
        let t = sample(&d);
        assert_eq!(t.carry_bps, 0);
        assert_eq!(
            t.useful_fraction(),
            None,
            "no bank before the job, no question to ask"
        );
    }

    /// The cap is a READING of the two wire slots, not a tally.
    #[test]
    fn a_phase_is_available_only_while_a_slot_is_free() {
        let dir = std::env::temp_dir().join(format!("nzbfast-spill-phases-{}", std::process::id()));
        let dir = crate::testscratch::ScratchDir::attach(&dir);
        let d = crate::testutil::test_daemon(&dir);
        assert_eq!(phases_live(&d), 0);
        assert!(phase_available(&d));
        *d.active_dl.lock_ok() = Some("a".into());
        assert_eq!(phases_live(&d), 1);
        assert!(phase_available(&d), "the head alone leaves room for a lane");
        *d.drain_dl.lock_ok() = Some(crate::wire::DrainSlot {
            nzo_id: "b".into(),
            t_start: Instant::now(),
            progress: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            counters: d.hub.fetch_counters(),
            total: 0,
            resume_seeded: 0,
            pool_live: None,
            abort: None,
            queue_ctl: None,
        });
        assert_eq!(phases_live(&d), 2);
        assert!(
            !phase_available(&d),
            "and two is the cap - a third phase is another BufPool, \
             another inflight_cap charge and one more job that \
             assumes-one-job code has never seen"
        );
    }
}
