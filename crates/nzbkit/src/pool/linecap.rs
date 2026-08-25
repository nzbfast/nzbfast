//! TODO 208 item 1: the fleet cap.
//!
//! `--connections` is a PER-SERVER ceiling, so a five-server config
//! dials 360 sockets into whatever pipe it finds. Measured 21-22 Aug
//! 2026 on a 99 Mbit line (TODO.md §208): fleet 50 walls 546 s against
//! fleet 360's 585 s, with stall-deadline kills 0 against 299-491, dup
//! spend 23 MB against 312 MB, RSS 172 MB against 800 MB and the
//! queue-dry drain 18 s against 94 s - every column monotone, no knee
//! inside the ladder, and the line LESS full at 360 (66-71% saturated)
//! than at 50 (84%), because each socket was a 35 KB/s trickle that
//! stalled, re-dialled and raced. A single provider knees at ~20.
//!
//! The rule: a small fleet ([`LINE_CAP_DEFAULT_FLEET`]), split equally
//! across the servers, each share still subject to the account's own
//! `connections` and to a pin.
//!
//! **TODO 277: the fleet SIZE is a function of the line again, and this
//! time it can only ever grow.** Between 23 and 24 Aug 2026 it was a
//! flat constant at every rate, and the 24 Aug mummy round (BENCHMARKS
//! 749aa76ff, 87 GB of steady state at 10 GbE) measured what that costs
//! where the line is bigger than 25 sockets can carry: 25 sockets top
//! out ~6.9 Gbps of a ~9 Gbps line and wall 90 s against the uncapped
//! arm's 71 s - 21%. The knee is measured too, and it is nowhere near
//! the account maxima: the 24 Aug knee sweep (34c842be9) and its 3-rep
//! re-cut have wall FLAT at 69-71 s from 50 total sockets all the way
//! to 360, with cpu_s rising 2.3x across that flat. So the curve is
//! [`fleet_for_line`]: the measured constant as its FLOOR, the measured
//! knee ([`LINE_CAP_MAX_FLEET`]) as its ceiling, and nothing outside
//! that window at any rate.
//!
//! Two properties do the safety work, and both are worth stating before
//! the arithmetic:
//!
//! * **It is monotone in the reading and floored at the old constant**,
//!   so no line reading - absent, misread low, misread high - can put
//!   the fleet below what shipped as the flat default. A box that reads
//!   its line as nothing gets exactly the 23 Aug behaviour.
//! * **Every reading it takes is an ACHIEVED rate, which is a LOWER
//!   bound on the line** (`min(line, supply)`), and this curve only
//!   ever sizes UP from it. That is the same fact that makes DIVIDING
//!   by such a reading unsafe - see [`Shared::line_cap_tick`] for the
//!   download that rule cost - and it points the other way here: a
//!   fleet that has been observed to move 7 Gbps is proof the line
//!   carries 7 Gbps, whatever the supply was doing.
//!
//! **What a reading that is WRONG THE OTHER WAY can cost**, which is
//! the one direction those two properties do not cover. The daemon's
//! anchor is `linkpeak.effective`, and that prefers a measured peak but
//! falls back to the line speed a user TYPED - so an install that typed
//! 10 Gbps on a 100 Mbit line can hand this curve its ceiling. The
//! bound on the damage is measured and it is why the ceiling is where
//! it is: §208 Round A ran that exact fleet on that exact line, and at
//! 99 Mbit fleet 50 / 35 / 25 all wall 544-547 s. The columns that
//! separated in that round separated at 360, not at 50. So the WORST a
//! wrong reading can do is put the fleet on a rung the slow-line ladder
//! already cleared, which is why no measured-only plumbing is bolted
//! under this and why the ceiling must not be raised past the rung that
//! round measured.
//!
//! **The line rate used to BE the rule** - `fleet = line Mbit x 0.5`,
//! standing down entirely from 720 Mbit up - **and the floor rounds
//! retired it** (§208 Rounds A and B, 22 Aug 2026). They went looking
//! for the rung where too few sockets start to cost wall and did not
//! find one: at 99 Mbit fleet 50 / 35 / 25 all wall 544-547 s, and at
//! 247 Mbit fleet 25 beat the per-Mbit rule's own prediction for that
//! line (125) on every column - wall 218 against 223 s, RSS 136-139
//! against 276-396 MB, cpu -13%, duplicate wire 7.6-17.3 against
//! 86.6-102.8 MB, the drain 4.5 against 20.2 s, per-article latency 7
//! against 50 s. On an unshaped 1 GbE A/B, where the old rule stood
//! down and dialled everything, fleet 20 finished a second ahead of
//! fleet 360 at the same saturation. Up to a gigabit the best fleet
//! measured does not scale with the line, and the 720 Mbit stand-down
//! protected nothing. **Read that as the statement about ITS RANGE that
//! it is**: it was written as "the best fleet does not scale with the
//! line" flat, the anchor was retired from the seed on the strength of
//! it, and the mummy round found the range's far edge two days later.
//! The anchor is load-bearing for the seed again (TODO 277 above), on a
//! curve that is flat across every rate those rounds covered.
//!
//! **What is NOT measured, because a constant cuts both ways.** Nothing
//! has run this fleet on a line slower than it: at 10 Mbit, 25 sockets
//! are 50 KB/s each, which is the trickle regime the rule exists to
//! prevent, and the one low-line round measured a fleet of EIGHT (§208,
//! a bench line shaped to 10 Mbit with 250 ms of added round trip:
//! capped 304 s against uncapped 352 s, its own ladder flat from fleet
//! 1 to 8, and the gauge reading that line as 2 Mbit at shed time - 5x
//! low, which is why the old rule needed a floor bolted under it). 25
//! is also an upper bound on the floor rather than the floor: it is the
//! lowest rung either ladder ran and it won at both rates. The sub-25
//! rungs (§208 owed item 2) place it, and a slow-line rung is owed with
//! them.
//!
//! The SEED (`nzbfast::get::fleet`) sizes the fleet at job build, which
//! is where the damage is front-loaded - the backlog is dialled in the
//! first seconds - and it caps whether or not the install knows its
//! line, because the curve's floor needs no line to divide. What it
//! SPAWNS is a second number: see the next section. That is new
//! behaviour on a CLI run and on a daemon's first job, both of which
//! the per-Mbit rule left alone for want of an anchor. A bench leg that
//! wants a fleet bigger than the cap must say so
//! (`NZBFAST_LINE_CAP=0`, as the A/B arms already do), where before an
//! anchorless CLI leg was uncapped by construction.
//!
//! **WHICH HALF SEES THE LINE FIRST, and it is the seed.** The reading
//! the seed sizes from is the daemon's persisted link anchor
//! (`PoolConfig::line_anchor_bps`, `linkpeak.effective`), so a 10 GbE
//! install is on the measured knee from its SECOND job on - the first
//! job is what teaches the anchor. A run with no anchor at all - a CLI
//! `get`, a prefetch sidecar, a daemon that has never finished a job -
//! reads 0, and 0 is the floor, which is exactly the fleet that
//! shipped. On such a run it is the GOVERNOR below that finds the line,
//! off the run's own trained peak.
//!
//! **For the first hours of this curve's life it could not, and the
//! reason was structural rather than a missing feature.** A
//! `ConnTarget` above the SPAWNED fleet has no slots to wake
//! ([`ConnTarget::set`]) - the raise returns exactly as a raise inside
//! the fleet does, and nothing dials - and every shape this pool was
//! built in spawned at the capped number. So a `nzbfast get` on a 10
//! GbE line was pinned at 25 sockets for ever, whatever the governor
//! decided, and `bench2.sh`'s shipped-defaults arm could not show this
//! rule working at all.
//!
//! The seed therefore SPAWNS [`LINE_CAP_MAX_FLEET`]'s share and RUNS at
//! [`fleet_for_line`]'s, parking the difference - the shape TODO 112's
//! `live_tune` walker already used. A parked worker holds no connection
//! and admission is a COUNT rather than a slot ordinal (`pool::admit`),
//! so the surplus costs a provider nothing until a raise wakes it, and
//! a slot that has NEVER dialled wakes exactly like one that has
//! (`a_raise_wakes_slots_that_were_parked_before_they_ever_dialled`).
//! The ceiling and never the raw `--connections` dial: that is 500
//! sockets on a five-provider box, and this rule exists because §208
//! measured what a fleet that size does. A leg that TYPED a fleet size
//! gets no headroom either - it pinned the governor too, so there is
//! nothing to make room for.
//!
//! That moves `workers_live` and `alive`, which four shipped quantities
//! divide by - the §208.2 stall bound and the tail taper the first,
//! `rate_per_worker` and `srv_rate_per_worker` the second. All four are
//! held at the count they were MEASURED with by
//! `Shared::workers_dialling`, which subtracts the parked ones; read
//! its doc before changing any of them.
//!
//! The in-run GOVERNOR and SHED ([`Shared::line_cap_tick`]) hold the
//! live targets inside a cap that may itself grow during the run.
//! [`fleet_step`] is the growth rule and it is deliberately sticky: a
//! reading has to hold for [`LINE_CAP_RAISE_TICKS`] consecutive seconds
//! before the fleet follows it, the curve is quantised to
//! [`LINE_CAP_RUNG`]-socket rungs so a gauge wobbling inside a rung
//! moves nothing at all, and the cap NEVER falls within a run. The shed
//! half still stands down without the daemon's persisted link anchor,
//! and that requirement is left exactly where the download that bought
//! it put it - see [`Shared::line_cap_tick`] for the measurement. What
//! it says is that a run with no independent estimate of its line dials
//! what it was told and is not resized DOWN mid-flight; a raise is not
//! covered by it, because a raise cannot be the arithmetic mistake that
//! rule exists to refuse.
//! The §112 `live_tune` walker is deliberately NOT the owner: it is
//! per-provider, sheds one socket per ~7 epochs by design and has no
//! fleet view; it walks inside the cap.
//!
//! The curve is a parameter (`NZBFAST_LINE_CAP=<fleet connections>`,
//! `0` disables) so the bench drivers can A/B it and so the sub-25
//! rungs can move it without a code change. **An explicit number is
//! still a FIXED fleet at every rate** - it pins both halves, the
//! governor included, because a leg that typed a fleet size is asking
//! for that fleet and not for a starting point. **The knob's UNIT
//! changed with the rule** on 23 Aug 2026: it used to be connections
//! per Mbit, so a stale `NZBFAST_LINE_CAP=0.5` in a box's environment
//! no longer parses and reads as OFF - the old control arm, and visible
//! as an empty `line cap` field in the `[pool]` line rather than as a
//! fleet of one.

use super::*;

/// The FLOOR of the fleet curve, in sockets, and the fleet a run with
/// no line evidence gets: the small constant that beat every larger
/// fleet at 99, 247 and ~1000 Mbit (module doc), split equally across
/// the servers, so five providers get 5 each. It is an upper bound on
/// the floor rather than the floor itself - 25 is the lowest rung §208
/// ran, and it won at both rates - so the sub-25 rungs may lower it.
/// There is deliberately no separate minimum under it: the old
/// `LINE_CAP_FLOOR` of 8 existed to stop a MISREAD line dividing the
/// fleet away (a 10 Mbit line read as 2 Mbit gave one connection), and
/// this curve never divides - it only ever adds sockets to this number.
pub const LINE_CAP_DEFAULT_FLEET: usize = 25;

/// The CEILING of the fleet curve, in sockets: the measured knee at
/// 10 GbE and the most this rule will ever ask for at any rate.
///
/// It is the CHEAP end of a measured flat, which is the whole reason it
/// is 50 and not the 360 the accounts would allow. The 24 Aug 2026 knee
/// sweep (BENCHMARKS 34c842be9) and the 3-rep knee50 re-cut put an
/// 87 GB job's wall at 69-71 s for every fleet from 50 to 360 on a
/// ~9 Gbps line, while cpu_s rises 2.3x (144 to 332) and RSS with it
/// across that same flat. Every socket past this one is measured to buy
/// nothing but cost.
pub const LINE_CAP_MAX_FLEET: usize = 50;

/// The line rate one socket is PLANNED to carry, in bytes/s (150 Mbit),
/// which is what turns a reading into a fleet size in
/// [`fleet_for_line`].
///
/// Deliberately about half the carry actually measured: the 24 Aug
/// mummy round had 25 sockets holding ~6.9 Gbps, which is ~276 Mbit
/// each. Planning at half of that asks for roughly twice the sockets
/// the measurement strictly needs, and that is the safe direction HERE
/// and only here - the curve is clamped into
/// [`LINE_CAP_DEFAULT_FLEET`]..=[`LINE_CAP_MAX_FLEET`], and inside that
/// window the knee sweep says wall is flat and only cost moves. Outside
/// it, where §208 measured that too many sockets is what costs wall,
/// the clamp is what protects us and not this figure.
const LINE_CAP_SOCKET_BPS: u64 = 18_750_000;

/// The granularity of the curve, in sockets. The fleet is only ever a
/// multiple of this, which is the cheap half of the hysteresis: a rung
/// is ~940 Mbit of line reading, so a gauge that wobbles by less than a
/// rung produces the same fleet and nothing moves at all.
pub const LINE_CAP_RUNG: usize = 5;

/// How many consecutive [`LINE_CAP_TICK_MS`] ticks a bigger reading has
/// to hold before the in-run governor follows it. The other half of the
/// hysteresis, and the half that covers a genuine burst: the provisional
/// gauge reading is a windowed rate, so a single fast second is exactly
/// what it is built to show.
pub const LINE_CAP_RAISE_TICKS: u32 = 3;

/// How often the in-run shed re-reads its targets.
const LINE_CAP_TICK_MS: u64 = 1_000;

/// TODO 277: the fleet size for a line reading of `line_bps` bytes/s,
/// 0 = no evidence.
///
/// Monotone non-decreasing, floored at [`LINE_CAP_DEFAULT_FLEET`] and
/// ceilinged at [`LINE_CAP_MAX_FLEET`], quantised to [`LINE_CAP_RUNG`]
/// sockets. No reading can make this smaller than the flat default that
/// shipped, and none can make it bigger than the measured knee.
///
/// Where it leaves the floor: at [`LINE_CAP_SOCKET_BPS`] per socket, 25
/// sockets plan for 3.75 Gbit, so a line has to read ABOVE that before
/// the fleet grows at all, and it reaches the ceiling at 7.5 Gbit. That
/// floor is far above the ~1.5 Gbit the TODO paragraph names as the
/// measured edge, deliberately: between 1 GbE (where §208 measured the
/// small fleet free-to-faster) and the ~9 Gbps mummy round (where it
/// measured it 21% expensive) nothing is measured at all, and the safe
/// thing to do in an unmeasured band is the thing that was measured on
/// both sides of it.
pub fn fleet_for_line(line_bps: u64) -> usize {
    if line_bps == 0 {
        return LINE_CAP_DEFAULT_FLEET;
    }
    let needed = line_bps.div_ceil(LINE_CAP_SOCKET_BPS) as usize;
    // Up to the rung, never down to it: a line that needs 26 sockets is
    // a line 25 does not carry.
    let rung = needed.div_ceil(LINE_CAP_RUNG) * LINE_CAP_RUNG;
    rung.clamp(LINE_CAP_DEFAULT_FLEET, LINE_CAP_MAX_FLEET)
}

/// One tick of the in-run fleet governor: the fleet in force, how many
/// consecutive ticks have already agreed that it should be bigger, and
/// the line reading this tick. Returns the pair for the next tick.
///
/// Pure, and the whole hysteresis rule lives here:
///
/// * the fleet NEVER falls - a reading is an achieved rate and so a
///   lower bound on the line (module doc), which makes it evidence for
///   growing and no evidence at all for shrinking. It also means a
///   fleet handed out mid-run is never taken back, so nothing can
///   oscillate;
/// * a bigger reading has to hold [`LINE_CAP_RAISE_TICKS`] ticks in a
///   row, and ONE smaller reading resets the count to zero;
/// * the curve is quantised, so a reading that moves inside a rung asks
///   for the fleet that is already in force and starts no count.
///
/// A reading that jumps two rungs at once applies both once the count
/// is served: the count is about the reading being real, not about
/// walking the fleet up one socket at a time, and the ceiling is three
/// rungs above the floor in total.
pub fn fleet_step(fleet: usize, streak: u32, line_bps: u64) -> (usize, u32) {
    let want = fleet_for_line(line_bps);
    if want <= fleet {
        return (fleet, 0);
    }
    match streak + 1 {
        s if s >= LINE_CAP_RAISE_TICKS => (want, 0),
        s => (fleet, s),
    }
}

/// The fleet-wide connection budget under a cap of `fleet` sockets.
/// `None` = no cap, i.e. the rule is off.
///
/// The line rate is no longer an argument (module doc: three rounds
/// took it out), so all this decides is what `0` means - in the one
/// place both halves of the rule read it from.
pub fn fleet_cap(fleet: usize) -> Option<usize> {
    (fleet > 0).then_some(fleet)
}

/// One server's equal share of a fleet budget. Rounds UP so the fleet
/// never lands under the budget through truncation (50 over 3 servers
/// is 17 each, not 16), and never below one connection.
pub fn server_share(fleet: usize, n_servers: usize) -> usize {
    fleet.div_ceil(n_servers.max(1)).max(1)
}

/// The in-run governor and shed's state on `Shared`: the SEED fleet cap
/// (0 = off) and whether it is the curve's own number rather than a
/// typed one, the anchor that arms the shed, the per-server live
/// targets it may move with their spawn ceilings (None = pinned or no
/// target), the last value IT set per server (usize::MAX = never - a
/// target holding another value was moved by someone else and is only
/// ever lowered), the ms stamp of the last tick, the cap in force now
/// and the consecutive-agreement count behind it (TODO 277), the fleet
/// cap it last applied (0 = none yet) and the shed and raise tallies
/// for the `[pool]` line.
pub(super) struct LineCap {
    cap: usize,
    auto: bool,
    pub(super) anchor_bps: u64,
    targets: Vec<Option<(Arc<ConnTarget>, usize)>>,
    set: Vec<AtomicUsize>,
    at: AtomicU64,
    cur: AtomicUsize,
    streak: AtomicUsize,
    fleet: AtomicUsize,
    sheds: AtomicU64,
    raises: AtomicU64,
}

impl LineCap {
    /// Cap and anchor MAX-fold across the fleet, like the gauge's
    /// `pct`; a server contributes a target only if its config carries
    /// one (a pinned server never does).
    ///
    /// `auto` folds the OTHER way, with `all`: one server carrying a
    /// typed fleet size is a leg that pinned its fleet, and a governor
    /// that grew the cap out from under it would make the arm mean
    /// something else.
    pub(super) fn new(servers: &[(ServerConfig, PoolConfig)]) -> Self {
        let cap = servers
            .iter()
            .map(|(_, c)| c.line_cap_fleet)
            .max()
            .unwrap_or(0);
        LineCap {
            cap,
            auto: !servers.is_empty() && servers.iter().all(|(_, c)| c.line_cap_auto),
            anchor_bps: servers
                .iter()
                .map(|(_, c)| c.line_anchor_bps)
                .max()
                .unwrap_or(0),
            targets: servers
                .iter()
                .map(|(_, c)| c.live_target.clone().map(|t| (t, c.connections)))
                .collect(),
            set: servers
                .iter()
                .map(|_| AtomicUsize::new(usize::MAX))
                .collect(),
            at: AtomicU64::new(0),
            cur: AtomicUsize::new(cap),
            streak: AtomicUsize::new(0),
            fleet: AtomicUsize::new(0),
            sheds: AtomicU64::new(0),
            raises: AtomicU64::new(0),
        }
    }
}

impl Shared {
    /// The in-run half of the cap: walk every server's live target to
    /// its share of the fleet cap. Called from the delivered-bytes
    /// fold, so it costs one atomic load per article and does real work
    /// once a second.
    ///
    /// A target the pool lowered is raised again if the cap loosens
    /// (the knob is per job, so in practice it does not), but only
    /// while it still holds the value the pool set - a target somebody
    /// else moved since (the §112 walker) is theirs, and the pool will
    /// only ever LOWER it.
    ///
    /// **Why the shed still requires the daemon's link anchor, even
    /// though the cap is now a constant** (the rule bought on 22 Aug
    /// 2026, when the cap was still divided out of a measured line; it
    /// halved a live download). A trained peak is an ACHIEVED rate, and
    /// an achieved rate is `min(line, supply)` - a LOWER bound on the
    /// line, never an upper one. A fleet that is supply-bound - a slow
    /// or far provider, small articles, TLS on a weak core, anything
    /// under ~250 KB/s per socket - read as a slow LINE, and the cap
    /// divided it away. Worse, the reading latched: the peak is
    /// monotone, so the smaller fleet's lower rate could never raise it
    /// back. Measured on the daemon suite's
    /// `prefetch_borrows_from_the_busy_server_when_no_healthy_idle`: a
    /// 4-connection fleet on a 250 ms/article server moved 0.3 MB/s,
    /// read as a 3 Mbit line, shed 4 -> 1 at 8 s and finished in 24.6 s
    /// against a 12.5 s connection-bound ideal - 2x, unrecoverable.
    /// The curve removes that arithmetic - it never divides a reading,
    /// it only ever adds sockets to a floor - so the gate now carries a
    /// narrower rule: a run with no independent estimate of its line -
    /// a CLI run, or the daemon's first job - dials what it was told
    /// and is not resized DOWN mid-flight. Its seed is capped either
    /// way.
    ///
    /// **The GOVERNOR (TODO 277) is not behind that gate, and the same
    /// paragraph is why.** The hazard above is a reading that is too
    /// LOW being divided into a fleet; the governor multiplies, and the
    /// worst a too-low reading can do to it is leave the fleet exactly
    /// where the seed put it. Its evidence is `max(anchor, trained
    /// peak)` - both achieved rates, so both lower bounds on the line -
    /// and its rule ([`fleet_step`]) never lowers the cap. So it runs
    /// on an anchorless run too, which is the only kind of run whose
    /// seed could not see the line at all.
    ///
    /// What it needs in order to do anything is documented at length in
    /// the module doc and belongs beside the code: raising a
    /// `ConnTarget` above the SPAWNED fleet wakes nothing, because
    /// those slots were never born. The seed spawns
    /// [`LINE_CAP_MAX_FLEET`]'s share and parks the surplus so that
    /// this raise always has somewhere to land; a fleet built any other
    /// way (a rig, a caller that sets `connections` itself) still binds
    /// only up to its own spawn count, which is the natural and
    /// harmless ceiling.
    pub(super) fn line_cap_tick(&self, now: u64) {
        let lc = &self.line_cap;
        if lc.cap == 0 || lc.targets.iter().all(Option::is_none) {
            return;
        }
        let last = lc.at.load(Ordering::Relaxed);
        if now.saturating_sub(last) < LINE_CAP_TICK_MS
            || lc
                .at
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        // The CAS above is what serializes this: exactly one caller a
        // second gets past it, so the governor's two atomics are read
        // and written by one thread at a time.
        let mut cap = lc.cur.load(Ordering::Relaxed);
        if lc.auto {
            // A trained peak is what the fleet has been SEEN to move;
            // the anchor is what a previous job saw. Both are lower
            // bounds on the line, so the better evidence is whichever
            // is larger.
            let line = lc.anchor_bps.max(self.sat.peak_bps());
            let (want, streak) = fleet_step(cap, lc.streak.load(Ordering::Relaxed) as u32, line);
            lc.streak.store(streak as usize, Ordering::Relaxed);
            if want != cap {
                lc.cur.store(want, Ordering::Relaxed);
                lc.raises.fetch_add(1, Ordering::Relaxed);
                info!(
                    "line cap: fleet {cap} -> {want} ({:.0} Mbit line seen; seed fleet {})",
                    line as f64 * 8.0 / 1e6,
                    lc.cap,
                );
                cap = want;
            }
        }
        // No independent line estimate = no mid-run SHED; see the doc
        // above for the download that bought this. A raise the governor
        // has already made still gets handed to the targets, which is
        // the one thing an anchorless run may resize.
        let allow_shed = lc.anchor_bps > 0;
        if !allow_shed && cap <= lc.cap {
            return;
        }
        lc.fleet.store(cap, Ordering::Relaxed);
        let share = server_share(cap, lc.targets.len());
        // The value the SEED left on this target, which is the share of
        // the seed cap: a target still holding it is one the fleet
        // build set and nobody has moved since, so the governor may
        // raise it. Anything else is somebody's (the §112 walker's) and
        // the pool will only ever LOWER it.
        let seeded = server_share(lc.cap, lc.targets.len());
        for (si, slot) in lc.targets.iter().enumerate() {
            let Some((target, ceiling)) = slot else {
                continue;
            };
            let want = share.min(*ceiling);
            let mine = lc.set[si].load(Ordering::Relaxed);
            // One atomic decide-and-set (F-24): the read, the rule and
            // the write run under the watch's lock, so a §112 walker
            // moving the target between them can neither be clobbered
            // nor mistaken for our own value.
            let seen = std::cell::Cell::new(0usize);
            let shed = std::cell::Cell::new(false);
            let moved = target.update(|cur| {
                seen.set(cur);
                let ours = cur == mine || (mine == usize::MAX && cur == seeded.min(*ceiling));
                if cur > want {
                    if !allow_shed {
                        return None;
                    }
                    shed.set(true);
                    Some(want)
                } else if cur < want && ours {
                    Some(want)
                } else {
                    None
                }
            });
            if !moved {
                continue;
            }
            let cur = seen.get();
            if shed.get() {
                lc.sheds.fetch_add(1, Ordering::Relaxed);
            }
            lc.set[si].store(want, Ordering::Relaxed);
            if let Some(l) = &self.live
                && let Some(sl) = l.servers.get(si)
            {
                sl.budget.store(want, Ordering::Relaxed);
            }
            info!(
                "line cap: {} using {want} of {ceiling} (was {cur}; fleet cap {cap})",
                self.live
                    .as_ref()
                    .and_then(|l| l.servers.get(si))
                    .map_or_else(|| format!("s{si}"), |s| s.host.clone()),
            );
        }
    }

    /// The ledger's fragment for the `[pool]` line: empty unless the
    /// rule was armed AND the shed or the governor ran, so short runs,
    /// anchorless runs that never grew and capped-off A/B arms keep
    /// their exact log shape.
    ///
    /// **The shipped head is `line cap <fleet> (<n> sheds)` and it does
    /// not move.** The bench round tables anchor on exactly that,
    /// parentheses included, so TODO 277's dynamic fleet is reported by
    /// APPENDING after the closing bracket - the head still carries the
    /// fleet in force, which is the number those readers want.
    pub(super) fn line_cap_summary(&self) -> String {
        if self.line_cap.cap == 0 {
            return String::new();
        }
        match self.line_cap.fleet.load(Ordering::Relaxed) {
            0 => String::new(),
            f => {
                let grown = match self.line_cap.raises.load(Ordering::Relaxed) {
                    0 => String::new(),
                    _ => format!(" raised from {}", self.line_cap.cap),
                };
                format!(
                    " · line cap {f} ({} sheds){grown}",
                    self.line_cap.sheds.load(Ordering::Relaxed)
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mbit/s as the bytes/s a gauge actually reports, so the cases
    /// below read as line rates and not as nine-digit constants.
    fn mbit(m: u64) -> u64 {
        m * 1_000_000 / 8
    }

    #[test]
    fn a_fleet_is_still_whatever_number_it_is_handed() {
        // `fleet_cap` decides one thing and it is what `0` means; the
        // curve above it is what decides the number.
        assert_eq!(fleet_cap(LINE_CAP_DEFAULT_FLEET), Some(25));
        assert_eq!(fleet_cap(4), Some(4));
    }

    #[test]
    fn no_line_reading_can_shrink_the_fleet_below_what_shipped() {
        // The property the whole curve is built on: a box that reads
        // its line as nothing, or slowly, or wrongly, gets exactly the
        // flat constant that shipped on 23 Aug 2026.
        assert_eq!(fleet_for_line(0), LINE_CAP_DEFAULT_FLEET);
        assert_eq!(fleet_for_line(1), LINE_CAP_DEFAULT_FLEET);
        assert_eq!(fleet_for_line(mbit(10)), LINE_CAP_DEFAULT_FLEET);
        assert_eq!(fleet_for_line(mbit(99)), LINE_CAP_DEFAULT_FLEET);
        assert_eq!(fleet_for_line(mbit(247)), LINE_CAP_DEFAULT_FLEET);
        // A gigabit, where §208's A/B measured fleet 20 a second ahead
        // of fleet 360.
        assert_eq!(fleet_for_line(mbit(1_000)), LINE_CAP_DEFAULT_FLEET);
        // And the ~1.5 Gbit the TODO paragraph names as the edge of the
        // measurement: still the floor, because the band above it is
        // not measured either and the floor is what was.
        assert_eq!(fleet_for_line(mbit(1_500)), LINE_CAP_DEFAULT_FLEET);
        assert_eq!(fleet_for_line(mbit(3_750)), LINE_CAP_DEFAULT_FLEET);
    }

    #[test]
    fn a_multi_gig_line_reaches_the_measured_knee_and_stops_there() {
        // The 24 Aug 2026 mummy round: ~9 Gbps of line, where 25
        // sockets walled 90 s against the uncapped arm's 71 - and the
        // knee sweep, where 50 sockets wall the same 69-71 s as 360.
        assert_eq!(fleet_for_line(mbit(9_000)), LINE_CAP_MAX_FLEET);
        assert_eq!(fleet_for_line(mbit(10_000)), LINE_CAP_MAX_FLEET);
        // Nothing above it, ever: every socket past the knee is
        // measured to buy wall nothing and cost 2.3x the cpu.
        assert_eq!(fleet_for_line(mbit(40_000)), LINE_CAP_MAX_FLEET);
        assert_eq!(fleet_for_line(u64::MAX), LINE_CAP_MAX_FLEET);
    }

    #[test]
    fn the_curve_climbs_in_rungs_and_never_dips() {
        // Monotone at every Mbit from nothing to well past the ceiling,
        // and only ever on a rung: those two together are what make a
        // wobbling gauge unable to move the fleet inside a rung.
        let mut prev = 0;
        for m in (0..12_000).step_by(25) {
            let f = fleet_for_line(mbit(m));
            assert!(f >= prev, "fell at {m} Mbit: {prev} -> {f}");
            assert_eq!(f % LINE_CAP_RUNG, 0, "{f} is not on a rung at {m} Mbit");
            assert!((LINE_CAP_DEFAULT_FLEET..=LINE_CAP_MAX_FLEET).contains(&f));
            prev = f;
        }
        // The band between the floor and the ceiling is real rather
        // than a step: a 6 Gbit line asks for more than 25 and less
        // than 50.
        let mid = fleet_for_line(mbit(6_000));
        assert!(
            mid > LINE_CAP_DEFAULT_FLEET && mid < LINE_CAP_MAX_FLEET,
            "{mid}"
        );
    }

    #[test]
    fn one_fast_second_does_not_move_the_fleet() {
        // The hysteresis: a burst has to hold LINE_CAP_RAISE_TICKS
        // consecutive ticks, and one slower reading puts the count back
        // to nothing.
        let fast = mbit(9_000);
        let (f, s) = fleet_step(LINE_CAP_DEFAULT_FLEET, 0, fast);
        assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 1));
        let (f, s) = fleet_step(f, s, fast);
        assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 2));
        // The burst stops one tick short and the count is lost.
        let (f, s) = fleet_step(f, s, mbit(400));
        assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 0));
        // So it has to start again from the beginning.
        let (f, s) = fleet_step(f, s, fast);
        assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 1));
    }

    #[test]
    fn a_reading_that_holds_moves_the_fleet_once_and_stays() {
        let fast = mbit(9_000);
        let mut st = (LINE_CAP_DEFAULT_FLEET, 0);
        for _ in 0..LINE_CAP_RAISE_TICKS {
            st = fleet_step(st.0, st.1, fast);
        }
        assert_eq!(st, (LINE_CAP_MAX_FLEET, 0));
        // At the ceiling nothing further can accumulate, so a fleet
        // that has arrived cannot keep re-announcing itself.
        for _ in 0..10 {
            st = fleet_step(st.0, st.1, fast);
            assert_eq!(st, (LINE_CAP_MAX_FLEET, 0));
        }
    }

    #[test]
    fn the_fleet_never_falls_within_a_run() {
        // An achieved rate is a LOWER bound on the line, so a reading
        // that drops is evidence about the SUPPLY and none at all about
        // the line: sockets already handed out are never taken back,
        // which is also what stops the governor oscillating.
        let mut st = (LINE_CAP_DEFAULT_FLEET, 0);
        for _ in 0..LINE_CAP_RAISE_TICKS {
            st = fleet_step(st.0, st.1, mbit(9_000));
        }
        assert_eq!(st.0, LINE_CAP_MAX_FLEET);
        for r in [mbit(500), 0, mbit(20), mbit(3_000)] {
            st = fleet_step(st.0, st.1, r);
            assert_eq!(st, (LINE_CAP_MAX_FLEET, 0), "a {r} B/s reading moved it");
        }
    }

    #[test]
    fn a_gauge_wobbling_inside_a_rung_moves_nothing_at_all() {
        // The cheap half of the hysteresis, and the half that runs on
        // every tick: two readings either side of the same rung ask for
        // the same fleet, so no count ever starts.
        // 5,250 to 6,000 Mbit is one rung (40 sockets at 150 Mbit
        // each), which is the width the quantisation buys: three
        // quarters of a gigabit of gauge noise, for nothing.
        let base = fleet_for_line(mbit(6_000));
        assert_eq!(base, fleet_for_line(mbit(5_300)));
        let mut st = (base, 0);
        for m in [5_300, 5_990, 5_500, 5_900, 6_000] {
            st = fleet_step(st.0, st.1, mbit(m));
            assert_eq!(st, (base, 0), "{m} Mbit started a raise");
        }
    }

    #[test]
    fn a_two_rung_jump_applies_whole_once_the_count_is_served() {
        // The count is about the reading being real, not about walking
        // one socket at a time - the whole window is three rungs wide.
        let mut st = (LINE_CAP_DEFAULT_FLEET, 0);
        for _ in 0..LINE_CAP_RAISE_TICKS {
            st = fleet_step(st.0, st.1, mbit(10_000));
        }
        assert_eq!(st.0, LINE_CAP_MAX_FLEET);
    }

    /// A two-server fleet as `get::fleet` seeds it on an ANCHORLESS
    /// run: `spawn` slots born per server, the live target at the
    /// curve's floor share, the governor armed.
    fn seeded_fleet(spawn: usize) -> (Arc<Shared>, Vec<Arc<ConnTarget>>) {
        let targets: Vec<_> = (0..2)
            .map(|_| ConnTarget::new(server_share(LINE_CAP_DEFAULT_FLEET, 2)))
            .collect();
        let servers: Vec<(ServerConfig, PoolConfig)> = targets
            .iter()
            .enumerate()
            .map(|(i, t)| {
                (
                    ServerConfig {
                        host: format!("s{i}.example"),
                        port: 119,
                        tls: false,
                        username: None,
                        password: None,
                        connections: spawn as u32,
                        pin_connections: false,
                        rcvbuf: None,
                        level: 0,
                        group: None,
                        retention_days: 0,
                        block_bytes: None,
                        block_account: false,
                        bind_ip: None,
                        socks5: None,
                        enabled: true,
                        warm_pool: false,
                        idle_release_secs: None,
                        idle_keep: None,
                        max_source_ips: None,
                    },
                    PoolConfig {
                        connections: spawn,
                        live_target: Some(t.clone()),
                        line_cap_fleet: LINE_CAP_DEFAULT_FLEET,
                        line_cap_auto: true,
                        // An anchorless run: a CLI `get`, a sidecar, a
                        // daemon that has never finished a job.
                        line_anchor_bps: 0,
                        ..PoolConfig::default()
                    },
                )
            })
            .collect();
        (
            Shared::new(vec![ArticleReq::fresh("<a@x>")], &servers).0,
            targets,
        )
    }

    /// TODO 277 end to end, and the reason the seed spawns wide: three
    /// agreeing ticks of a 10 GbE reading must actually put more
    /// sockets on the wire, on a run whose seed saw no line at all.
    ///
    /// The second half is the whole point. A fleet spawned at the
    /// number it dials - every shape this pool was built in until 24
    /// Aug 2026 - takes the identical three ticks, moves its cap to the
    /// ceiling exactly the same way, and changes NOTHING about the
    /// targets, because `want` is `min`ed into the spawn count and
    /// there is nothing above it to wake.
    #[test]
    fn a_governor_raise_only_reaches_the_wire_on_a_fleet_spawned_wide() {
        let floor = server_share(LINE_CAP_DEFAULT_FLEET, 2);
        let ceiling = server_share(LINE_CAP_MAX_FLEET, 2);
        for (spawn, want) in [(ceiling, ceiling), (floor, floor)] {
            let (sh, targets) = seeded_fleet(spawn);
            sh.sat.set_peak_bps(1_250_000_000); // 10 Gbit
            assert!(targets.iter().all(|t| t.get() == floor));
            // One tick a second, which is what the CAS inside admits.
            for i in 1..=LINE_CAP_RAISE_TICKS as u64 {
                sh.line_cap_tick(i * LINE_CAP_TICK_MS);
            }
            assert!(
                targets.iter().all(|t| t.get() == want),
                "spawned {spawn}: wanted {want}, got {:?}",
                targets.iter().map(|t| t.get()).collect::<Vec<_>>()
            );
        }
        assert_ne!(floor, ceiling, "or the two arms above prove nothing");
    }

    #[test]
    fn off_means_no_cap() {
        assert_eq!(fleet_cap(0), None);
    }

    #[test]
    fn the_default_puts_five_connections_on_each_of_five_providers() {
        let fleet = fleet_cap(LINE_CAP_DEFAULT_FLEET).unwrap();
        assert_eq!(server_share(fleet, 5), 5);
        assert_eq!(server_share(fleet, 1), 25);
        assert_eq!(server_share(fleet, 3), 9);
    }

    #[test]
    fn shares_round_up_and_never_go_below_one() {
        assert_eq!(server_share(50, 5), 10);
        assert_eq!(server_share(125, 5), 25);
        assert_eq!(server_share(50, 3), 17);
        assert_eq!(server_share(2, 5), 1);
        assert_eq!(server_share(50, 0), 50);
    }
}
