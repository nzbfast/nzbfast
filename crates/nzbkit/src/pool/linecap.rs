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
///
/// `pub` since 26 Aug 2026 (TODO 312 item 3): the "why is this slow?"
/// surface asks the same question this constant answers - is a socket
/// carrying what the plan assumed - and a second copy of the number
/// over there would be the drift this repo keeps paying for.
pub const LINE_CAP_SOCKET_BPS: u64 = 18_750_000;

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

/// How much of the line a fleet has to be moving before it counts as
/// LINE-bound, in percent, for [`fleet_for_supply`].
///
/// Under this, the line has headroom the fleet is demonstrably not
/// using, which is the only condition that arm fires on. It is a
/// PROPORTION rather than a rate because both sides are achieved rates
/// off the same gauge, so the ratio survives whatever the absolute
/// numbers are.
pub const LINE_CAP_SUPPLY_PCT: u64 = 75;

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

/// TODO 275 item 1 (GH #62): the fleet size when the sockets, not the
/// line, are what is short - `0` inputs or a fleet that is already big
/// enough all read as NO OPINION and hand `fleet` straight back.
///
/// `now_bps` is what the fleet is moving and `dialling` is how many
/// sockets are moving it, which is NOT `fleet`: the seed spawns a
/// surplus and parks it (TODO 277), and dividing by the parked count
/// would under-read the carry and then ask for sockets to replace ones
/// that never held a connection. `fleet` is the cap in force and is
/// only ever the FLOOR of the answer.
///
/// [`fleet_for_line`] answers "how many sockets does this line need",
/// and it answers it by PLANNING [`LINE_CAP_SOCKET_BPS`] per socket.
/// That constant is the carry measured on a 10 GbE box against
/// providers that could fill it (module doc), and where a provider
/// cannot, the plan is optimistic by exactly the ratio it is wrong by
/// and the fleet comes out that many times too small. Worse, the
/// governor could not rescue it: its only candidate was that same
/// curve, so below 3.75 Gbit `want <= fleet` on every tick and the
/// raise arm was unreachable BY CONSTRUCTION at every rate a home line
/// runs at.
///
/// Reported 27 Aug 2026 by a user on a 1 Gbit line with five servers
/// against AU-routed providers: the curve returned its floor (a 1 Gbit
/// line plans for 7 sockets and the floor is 25), `server_share(25, 5)`
/// gave 5 connections each of an allowed 50, and the only escape that
/// worked was turning the rule off. It is the same regime §275 watched
/// on a giganews-only box, where 25 sockets at ~10-13 Mbps each WERE
/// the ~0.35 Gbps rate on a line that had recorded 2.5 Gbps in the same
/// half hour.
///
/// So this arm asks the other question - "are these sockets carrying
/// what the plan assumed" - and sizes off the carry it MEASURES instead
/// of the one it assumes. Four properties keep it safe, and none of
/// them is optional:
///
/// * **It only fires with the line proven under-used.** `now_bps` below
///   [`LINE_CAP_SUPPLY_PCT`]% of `line_bps` is the gate. A fleet that is
///   filling its line is LINE-bound, the regime §208 measured, and this
///   arm has no opinion about it - which is what keeps it away from
///   every rung those rounds cleared.
/// * **It only fires when the sockets are under the plan.** At or above
///   [`LINE_CAP_SOCKET_BPS`] per socket the curve's own assumption is
///   holding and the curve owns the answer.
/// * **It is self-limiting.** It asks for `line / measured carry`, the
///   number that fills the line and not one socket more, so as the
///   fleet grows the achieved rate rises, the gate closes and it stops.
///   It cannot walk away to §208's measured-bad 360 on a slow line,
///   because on such a line the gate shuts long before.
/// * **It is clamped into the SAME window as the curve**, so it is
///   monotone, never falls, and the worst a wrong reading can do is put
///   the fleet on [`LINE_CAP_MAX_FLEET`] - the rung §208 Round A ran at
///   99 Mbit, where fleet 50 / 35 / 25 all walled 544-547 s. That bound
///   is what makes plumbing measured-vs-typed anchor provenance
///   unnecessary here: an install that TYPED 10 Gbps on a 100 Mbit line
///   holds this gate open for ever and still only ever reaches a rung
///   that was measured free.
///
/// **The ceiling is the half of this that is still owed a leg**, and it
/// is why the reporter above is improved rather than finished: 25 -> 50
/// doubles their fleet, and `line / measured carry` wanted ~77.
///
/// **What holds it at 50 is NOT the cost**, and this comment said it
/// was until 27 Aug 2026. Measured that day
/// (`research/LINECAP-SLOW-CARRY-2026-08-27.md`): a parked slot is a
/// tokio TASK, not an OS thread - the only threads here are the I/O
/// shards, and `get::shard_count` clamps those to 4 whatever the fleet
/// - and it costs ~6.3 KB of RSS and no socket at all, so moving this
/// constant 50 -> 100 is ~0.3 MB a job and at most one extra shard.
///
/// What holds it is the fourth property above: this ceiling IS the
/// bound on a line reading that was TYPED rather than measured, which
/// is the only thing making it safe to run this arm on an anchor whose
/// provenance the pool never sees. An install that typed 10 Gbps on a
/// 100 Mbit line holds the supply gate open for ever and reaches
/// whatever this constant is, and §208 measured that regime's far end
/// as 299-491 stall kills, 312 MB of duplicate wire and 800 MB of RSS.
/// So this is a PROVENANCE question, and since 28 Aug 2026 the word IS
/// carried down here - `PoolConfig::line_anchor_measured`, folded onto
/// `LineCap::anchor_measured` (§275 item 1 part 1). That closes the
/// PREREQUISITE and nothing else: raising this constant for a measured
/// anchor is part 3, it is a judgement about what every install spends,
/// and it is deliberately not taken here. §275 item 1 has the proposal
/// and the ladder that would size the second ceiling.
pub fn fleet_for_supply(line_bps: u64, now_bps: u64, dialling: usize, fleet: usize) -> usize {
    if line_bps == 0 || now_bps == 0 || dialling == 0 || fleet == 0 {
        return fleet;
    }
    // The line is being used: this is the regime the curve measured.
    if now_bps.saturating_mul(100) >= line_bps.saturating_mul(LINE_CAP_SUPPLY_PCT) {
        return fleet;
    }
    let per_socket = now_bps / dialling as u64;
    // The plan is holding, or there is not enough rate to divide.
    if per_socket == 0 || per_socket >= LINE_CAP_SOCKET_BPS {
        return fleet;
    }
    sockets_for_carry(line_bps, per_socket).clamp(fleet, LINE_CAP_MAX_FLEET)
}

/// TODO 312 item 3: how many sockets this line needs at a MEASURED
/// per-socket carry, rung-quantised and DELIBERATELY UNCLAMPED. 0 if
/// either input is 0.
///
/// [`fleet_for_supply`] is this function plus the two gates and the
/// clamp, and that split is the point rather than tidiness. A surface
/// that has to say what the cap is COSTING - "your sockets carry this
/// much, so this line wants that many, and you are allowed this many" -
/// cannot say it with a number already clamped into the window. The
/// reporter on GH #62 is the case: their carry implies ~77 and the
/// ceiling is 50, and a verdict that printed 50 for both would be
/// describing the cap with the cap's own number.
///
/// NOT [`fleet_for_carry`], which is the SEED helper next door and is
/// this same arm with the gates and the clamp on: that one answers "how
/// big may the next job start", this one answers "how big does the line
/// want to be", and the two are different questions on purpose. NOR
/// [`fleet_implied_by_carry`], which is this function plus a single
/// gate that reports nothing once the carry meets the plan - a panel's
/// question, and the only caller that wants to be silent rather than
/// truthful when there is nothing wrong. All three call this one arm;
/// none of them restates it. Never a
/// fleet SIZE by itself - nothing may seed or grow a pool from this
/// without going through [`fleet_for_supply`]'s gates, which keep the
/// arm away from a line-bound fleet, and its clamp, which is what bounds
/// a TYPED line reading (see that function's fourth property).
pub fn sockets_for_carry(line_bps: u64, per_socket_bps: u64) -> usize {
    if line_bps == 0 || per_socket_bps == 0 {
        return 0;
    }
    let needed = line_bps.div_ceil(per_socket_bps) as usize;
    needed.div_ceil(LINE_CAP_RUNG) * LINE_CAP_RUNG
}

/// TODO 275 item 1 part 2: the SEED half of [`fleet_for_supply`] - the
/// fleet to start a job at when a previous job on this link measured
/// what one socket actually carries.
///
/// `carry_bps` is that measurement, bytes/s per socket, `0` = none,
/// which hands `fleet` straight back and is exactly the behaviour that
/// shipped. `fleet` is what the curve asked for and is only ever the
/// FLOOR of the answer.
///
/// **Why the seed wants this at all.** [`fleet_for_supply`] is an
/// in-run governor and nothing carries its verdict across a job
/// boundary, so GH #62's reporter starts every job at the curve's floor
/// and walks to the same answer over [`LINE_CAP_RAISE_TICKS`] ticks
/// plus the dial, for ever. The climb is not free - it is paid at the
/// front of every job, which is where a job's backlog is - and it is
/// re-paid identically each time because the evidence was thrown away.
///
/// **It is the same arm, called with a planned rate instead of an
/// observed one**, which is deliberate and is what makes this need no
/// new safety argument: `carry x fleet` is what this fleet would move
/// at the carry last measured, so all four of that function's
/// properties apply here word for word. In particular it still stands
/// down on a line that reading says would be full (the regime TODO 208
/// measured), it still has no opinion at or above
/// [`LINE_CAP_SOCKET_BPS`], and it still clamps into
/// `fleet..=`[`LINE_CAP_MAX_FLEET`] - so a seed can no more exceed
/// today's ceiling than a raise can.
///
/// **The ceiling is emphatically NOT raised here.** That is TODO 275
/// item 1 part 3, it needs the provenance now carried by
/// `PoolConfig::line_anchor_measured`, and it is a decision about what
/// every install spends rather than a consequence of this function.
pub fn fleet_for_carry(line_bps: u64, carry_bps: u64, fleet: usize) -> usize {
    if carry_bps == 0 || fleet == 0 {
        return fleet;
    }
    // What this fleet would be moving at the carry last measured. The
    // divisor and the multiplier are the same number on purpose: the
    // arm divides `now_bps` by `dialling` to recover the carry, so
    // handing it `carry x fleet` over `fleet` recovers exactly
    // `carry_bps` whatever `fleet` is, and the arithmetic cannot drift
    // from what a live tick would have concluded at this fleet.
    fleet_for_supply(
        line_bps,
        carry_bps.saturating_mul(fleet as u64),
        fleet,
        fleet,
    )
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
pub fn fleet_step(
    fleet: usize,
    streak: u32,
    line_bps: u64,
    now_bps: u64,
    dialling: usize,
) -> (usize, u32) {
    // TODO 275 item 1: two candidates, and the bigger wins. The curve
    // asks what the LINE needs assuming a planned carry; the supply arm
    // asks what it needs at the carry actually MEASURED, and has no
    // opinion at all unless the line is provably under-used. Both are
    // monotone and both clamp into the same window, so the max of them
    // is too - `now_bps == 0` is exactly the old behaviour.
    let want = fleet_for_line(line_bps).max(fleet_for_supply(line_bps, now_bps, dialling, fleet));
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

/// TODO 312 item 2: the fleet a MEASURED per-socket carry implies for
/// this line - **for REPORT ONLY, and nothing in this module calls it**.
///
/// [`fleet_for_supply`] asks the same question of a carry it inferred
/// from a running pool, and [`fleet_for_carry`] of one a previous job
/// banked; both then clamp the answer into the window the knee sweep
/// measured, because both SPEND it. This one asks it of a carry a user
/// deliberately went and measured with the per-server carry probe
/// (`serve/api/servers.rs`), and does NOT clamp - which is the whole
/// difference between the three and the only reason a third exists.
/// A user on a slow-per-connection route needs to see how far past
/// [`LINE_CAP_MAX_FLEET`] their line would want to go, and a clamped
/// answer hides exactly that by construction. GH #62's reporter is the
/// case: 1 Gbit over ~7 Mbit a socket wants 145 against a ceiling of
/// 50, and being shown 50 would answer a question nobody asked.
///
/// It lives here, beside the arm whose arithmetic it mirrors, for the
/// reason this file keeps re-learning: written out in the API handler
/// it would be a SECOND spelling of `line / carry`, and the second is
/// the one nobody holds to the rule when [`LINE_CAP_RUNG`] moves.
///
/// **Report only** is a property of the CALLERS and cannot be enforced
/// here, so it is stated at both ends: no fleet, cap, share or ceiling
/// may be derived from this. Wiring a measured carry into what the pool
/// SPENDS is TODO 275 item 1 part 3 - a judgement about what every
/// install spends, and not a consequence of this function - so see
/// [`fleet_for_supply`]'s own closing note on why the ceiling is a
/// provenance question rather than a cost one.
///
/// **The one thing it adds over [`sockets_for_carry`]**, which is
/// otherwise the same rung and is where the arithmetic actually lives:
/// a carry at or above [`LINE_CAP_SOCKET_BPS`] reports `0`, because the
/// plan the curve already makes is holding and the curve owns the
/// answer. That is a decision about what a PANEL should say - a line
/// whose sockets are meeting the plan has nothing to report, and a
/// number there reads as a complaint - and it is the whole reason this
/// name exists beside that one. `whyslow`'s own fleet verdict wants the
/// ungated rung and calls [`sockets_for_carry`] directly.
///
/// `0` out is therefore "no opinion" at every door: either input at
/// zero is no evidence, and a carry meeting the plan is not this
/// function's question.
pub fn fleet_implied_by_carry(line_bps: u64, carry_bps: u64) -> usize {
    // The ARITHMETIC is [`sockets_for_carry`]'s and is called, never
    // restated. This function is that rung plus ONE gate, and the two
    // landed the same day from the two halves of TODO 312 without
    // either lane being able to see the other: for a few hours main
    // carried the same `line / carry` division, and the same
    // [`LINE_CAP_RUNG`] quantisation, written out twice. That is the
    // defect item 2's own instruction names - "two spellings of one
    // quantity and the second is the one nobody holds to the rule" -
    // and the day the rung moves is the day it would have bitten.
    if carry_bps >= LINE_CAP_SOCKET_BPS {
        return 0;
    }
    sockets_for_carry(line_bps, carry_bps)
}

/// The in-run governor and shed's state on `Shared`: the SEED fleet cap
/// (0 = off) and whether it is the curve's own number rather than a
/// typed one, the anchor that arms the shed and whether that anchor was
/// MEASURED rather than typed (TODO 275 item 1 part 1), the per-server
/// live targets it may move with their spawn ceilings (None = pinned or
/// no target), the last value IT set per server (usize::MAX = never - a
/// target holding another value was moved by someone else and is only
/// ever lowered), the ms stamp of the last tick, the cap in force now
/// and the consecutive-agreement count behind it (TODO 277), the fleet
/// cap it last applied (0 = none yet) and the shed and raise tallies for
/// the `[pool]` line. The best per-socket carry the run has held (TODO
/// 275 item 1 part 2) is NOT kept here: it is published straight to
/// `LiveStats`, which is the Arc the daemon already shares with the
/// pool and the only reader that has anywhere to persist it.
pub(super) struct LineCap {
    cap: usize,
    auto: bool,
    pub(super) anchor_bps: u64,
    pub(super) anchor_measured: bool,
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
    ///
    /// `anchor_measured` folds with `all` too (TODO 275 item 1 part 1),
    /// for a different reason: it is a claim about the LINE, one link
    /// carries the whole fleet, and a claim about evidence is worth
    /// what its weakest member is worth. An empty fleet is not
    /// measured - `all` over nothing is vacuously true, which would
    /// make "no servers at all" the strongest evidence in the system.
    pub(super) fn new(servers: &[(ServerConfig, PoolConfig)]) -> Self {
        let cap = seed_cap(servers);
        LineCap {
            cap,
            auto: seed_auto(servers),
            anchor_bps: servers
                .iter()
                .map(|(_, c)| c.line_anchor_bps)
                .max()
                .unwrap_or(0),
            anchor_measured: !servers.is_empty()
                && servers.iter().all(|(_, c)| c.line_anchor_measured),
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

/// The SEED fleet cap this pool was built with, 0 = the rule is off.
///
/// MAX-folded across the fleet, like the gauge's `pct`. Split out of
/// [`LineCap::new`] on 26 Aug 2026 so that the gauge TODO 312 item 3
/// publishes for the dashboard cannot fold it a second way: two
/// spellings of one quantity is this repo's most repeated defect, and
/// the one that would matter here is a surface saying the cap is 25
/// while the governor is walking 50.
pub(super) fn seed_cap(servers: &[(ServerConfig, PoolConfig)]) -> usize {
    servers
        .iter()
        .map(|(_, c)| c.line_cap_fleet)
        .max()
        .unwrap_or(0)
}

/// Whether the seed cap is the curve's own number rather than one
/// somebody typed. ALL-folded, and the other direction from
/// [`seed_cap`] on purpose: one server carrying a typed fleet size is a
/// leg that pinned its fleet, and a governor that grew the cap out from
/// under it would make the arm mean something else.
pub(super) fn seed_auto(servers: &[(ServerConfig, PoolConfig)]) -> bool {
    !servers.is_empty() && servers.iter().all(|(_, c)| c.line_cap_auto)
}

/// What the fleet would dial with the cap taking nothing out: every
/// server's own ceilings summed. 0 = the builder said nothing, which
/// reads as "no claim" and never as "no sockets".
///
/// The denominator of TODO 312 item 3's question. It is a SUM where the
/// two folds above are max/all, because it is a fleet quantity in the
/// same currency as the cap itself - the cap is a whole-fleet socket
/// budget, and what it is being compared against is the whole fleet's
/// own allowance.
pub(super) fn seed_uncapped(servers: &[(ServerConfig, PoolConfig)]) -> usize {
    servers.iter().map(|(_, c)| c.line_cap_uncapped).sum()
}

/// TODO 312 item 7: a STALE auto-tune knee holding ONE server under its
/// own ceiling, as [`crate::pool::PoolConfig::line_cap_knee`] carries
/// it.
///
/// THE JUDGEMENT IS THE PRODUCER'S AND NEVER THIS CRATE'S, which is the
/// one thing to read before touching either of the two folds below.
/// `conntune` owns what a knee is, when one applies, and when it has
/// gone stale (`crates/nzbfast/src/conntune.rs`); nothing in nzbkit has
/// a view of any of it. What arrives here is already the answer - a
/// knee that applies, that is past its re-probe appointment, and that
/// is really lowering what this server would otherwise dial - so
/// [`seed_knee`] only ever adds numbers up. Putting the staleness test
/// in here would be a second spelling of a rule that already exists,
/// which is this repo's most repeated defect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerKnee {
    /// The knee itself: the connection count the measurement settled
    /// on, which is what a reader recognises from the Providers card.
    pub at: usize,
    /// Sockets the knee takes off what this server would OTHERWISE
    /// dial, the fleet cap's share included - never the account's raw
    /// number. That is not a detail: with a cap of 35 on an account of
    /// 40 and a knee of 32, lifting the knee buys 3 sockets and not 8,
    /// and the larger figure is a promise the setting cannot keep.
    ///
    /// Never 0. A knee taking nothing is not one worth reporting, and
    /// `conntune::stale_knee` hands back `None` for it - which is also
    /// what makes this field decide the whole ordering question on its
    /// own: `takes > 0` IS "the knee, not the fleet cap, is the lower
    /// of the two", with no second comparison to disagree with it.
    pub takes: usize,
    /// How long ago the knee was measured, in seconds.
    pub age_secs: u64,
}

/// The same thing folded over a whole fleet: how many sockets our own
/// stale measurements are holding back in total, and WHICH server to
/// send the reader to. `None` when no server carries one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetKnee {
    /// The stalest knee'd server; see [`seed_knee`] for why that one.
    pub host: String,
    /// That server's knee, as [`ServerKnee::at`].
    pub at: usize,
    /// Summed over every server carrying a stale knee.
    pub takes: usize,
    /// The named server's own age, never a fleet average: an average of
    /// two measurements is a measurement of nothing.
    pub age_secs: u64,
}

/// Fold the per-server stale knees into the fleet's answer.
///
/// `takes` is a SUM, for [`seed_uncapped`]'s reason exactly: it is a
/// whole-fleet socket quantity in the same currency as the cap, and
/// what a reader is owed is how many sockets our own measurements are
/// costing them across the fleet, not how many one of them costs.
///
/// `host`, `at` and `age_secs` come from the STALEST entry, which is a
/// different kind of fold and deliberately so. Neither a sum nor a max
/// means anything as an AGE, and a fleet has to name ONE server or the
/// reader has nowhere to go. The stalest is the right one because
/// staleness is the verdict's own bar (`serve/whyslow.rs`'s
/// `knee_bound`): the server it names must be the one that most clearly
/// fails that bar, and a costlier but FRESHER knee is a measurement we
/// still stand by. Ties keep the first in fleet order, so the answer is
/// stable from tick to tick rather than flipping between two servers
/// probed in the same minute.
pub(super) fn seed_knee(servers: &[(ServerConfig, PoolConfig)]) -> Option<FleetKnee> {
    let mut takes = 0usize;
    let mut named: Option<(&str, usize, u64)> = None;
    for (s, c) in servers {
        let Some(k) = c.line_cap_knee.as_ref() else {
            continue;
        };
        takes += k.takes;
        if named.is_none_or(|(_, _, age)| k.age_secs > age) {
            named = Some((s.host.as_str(), k.at, k.age_secs));
        }
    }
    let (host, at, age_secs) = named?;
    Some(FleetKnee {
        host: host.to_string(),
        at,
        takes,
        age_secs,
    })
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
    /// `tail` is the queue-dry latch, passed in by the one production
    /// caller (`note_srv_bytes`, which computes it beside this call)
    /// rather than re-read here - see the supply-arm gate below for
    /// what it guards.
    pub(super) fn line_cap_tick(&self, now: u64, tail: bool) {
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
            // TODO 275 item 1: what the fleet is moving RIGHT NOW,
            // divided by the sockets actually dialling for it. The
            // parked surplus is excluded on purpose (`workers_dialling`
            // is TODO 277's own correction) - dividing by the SPAWNED
            // count would under-read the carry and ask for sockets to
            // replace ones that were never holding a connection.
            //
            // Past queue-dry the arm sits out (F6, 27 Aug sweep): a
            // tail's fleet rate sags because the QUEUE is short, not
            // the line - a handful of last articles on slow sockets
            // reads as under-supply, and three such ticks woke the
            // parked surplus to dial into an empty queue and join the
            // endgame duplicate racing. No reading taken in the tail
            // is supply evidence; `now_bps == 0` is `fleet_for_supply`'s
            // own "no opinion", so the curve arm is untouched.
            let now_bps = if tail {
                0
            } else {
                self.sat.now_rate(now).unwrap_or(0.0).max(0.0) as u64
            };
            let dialling = self.workers_dialling();
            // TODO 275 item 1 part 2: bank the carry this tick just
            // measured, so the NEXT job can seed from it rather than
            // re-walking this climb from the curve's assumption. Same
            // reading and same divisor the arm above sizes off - taking
            // it anywhere else would let the seed and the governor
            // disagree about what a socket carries - and MAX over the
            // run, which is the conservative direction (a high carry
            // asks for fewer sockets). The tail gate has already zeroed
            // `now_bps`, so a queue-dry sag is no more evidence here
            // than it is there.
            if now_bps > 0
                && dialling > 0
                && let Some(l) = &self.live
            {
                l.line_carry_bps
                    .fetch_max(now_bps / dialling as u64, Ordering::Relaxed);
            }
            let (want, streak) = fleet_step(
                cap,
                lc.streak.load(Ordering::Relaxed) as u32,
                line,
                now_bps,
                dialling,
            );
            lc.streak.store(streak as usize, Ordering::Relaxed);
            if want != cap {
                lc.cur.store(want, Ordering::Relaxed);
                lc.raises.fetch_add(1, Ordering::Relaxed);
                // TODO 312 item 3: the gauge follows the cap in FORCE,
                // not the seed. Published HERE and not below the shed
                // loop, because the shed's own early return
                // (`!allow_shed && cap <= lc.cap`) is reachable on an
                // anchorless run - and a governor that grew the cap
                // while the gauge still read the seed is exactly the
                // second spelling `seed_cap` exists to prevent.
                if let Some(l) = &self.live {
                    l.line_cap_fleet.store(want, Ordering::Relaxed);
                }
                // TODO 275 item 1 part 1: the anchor's provenance is on
                // the record here, and this is the one place a person
                // reading a log can see WHICH of the two regimes a
                // raise happened in. It is reported and nothing more:
                // no rule branches on it, because the decision it
                // exists for (a higher ceiling a measured anchor alone
                // may reach) is not this lane's to take. Appended after
                // the existing parenthetical on purpose - the rig's
                // fleet guard parses the SEED line's head positionally
                // and this line not at all, and the head of this one
                // still opens exactly as it did.
                info!(
                    "line cap: fleet {cap} -> {want} ({:.0} Mbit line seen; seed fleet {}; {} anchor)",
                    line as f64 * 8.0 / 1e6,
                    lc.cap,
                    if lc.anchor_measured {
                        "measured"
                    } else {
                        "typed"
                    },
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
        let (f, s) = fleet_step(LINE_CAP_DEFAULT_FLEET, 0, fast, 0, 0);
        assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 1));
        let (f, s) = fleet_step(f, s, fast, 0, 0);
        assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 2));
        // The burst stops one tick short and the count is lost.
        let (f, s) = fleet_step(f, s, mbit(400), 0, 0);
        assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 0));
        // So it has to start again from the beginning.
        let (f, s) = fleet_step(f, s, fast, 0, 0);
        assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 1));
    }

    #[test]
    fn a_reading_that_holds_moves_the_fleet_once_and_stays() {
        let fast = mbit(9_000);
        let mut st = (LINE_CAP_DEFAULT_FLEET, 0);
        for _ in 0..LINE_CAP_RAISE_TICKS {
            st = fleet_step(st.0, st.1, fast, 0, 0);
        }
        assert_eq!(st, (LINE_CAP_MAX_FLEET, 0));
        // At the ceiling nothing further can accumulate, so a fleet
        // that has arrived cannot keep re-announcing itself.
        for _ in 0..10 {
            st = fleet_step(st.0, st.1, fast, 0, 0);
            assert_eq!(st, (LINE_CAP_MAX_FLEET, 0));
        }
    }

    /// TODO 312 item 2: the reported number is GH #62's own arithmetic,
    /// and it is deliberately NOT clamped where `fleet_for_supply` is.
    ///
    /// Their line reads 1 Gbit and their sockets carry ~6.4-7.6 Mbit
    /// each against AU-routed providers. The supply arm can only ever
    /// hand them `LINE_CAP_MAX_FLEET`; the honest answer to "what would
    /// fill this line at that carry" is three times that, and hiding it
    /// behind the ceiling is what leaves the user unable to see what the
    /// ceiling is costing them. That gap is the whole reason the probe
    /// reports rather than spends.
    #[test]
    fn an_implied_fleet_is_reported_past_the_ceiling_the_pool_would_clamp_to() {
        let line = mbit(1_000);
        let carry = mbit(7);
        let implied = fleet_implied_by_carry(line, carry);
        assert_eq!(implied, 145, "1 Gbit over a 7 Mbit carry, up to the rung");
        assert!(
            implied > LINE_CAP_MAX_FLEET,
            "clamping here would hide exactly what the user pressed the button to find out"
        );
        // The arm that SPENDS still clamps, and that is the half this
        // number must never be plumbed into.
        assert_eq!(
            fleet_for_supply(line, mbit(35), 5, LINE_CAP_DEFAULT_FLEET),
            LINE_CAP_MAX_FLEET
        );
    }

    /// Both roundings go UP and both are the same two `fleet_for_supply`
    /// applies, so the two numbers a user is shown side by side are
    /// comparable. A carry that leaves a fleet one socket short of a
    /// rung is a fleet that rung does not carry.
    #[test]
    fn an_implied_fleet_rounds_up_to_the_rung_the_supply_arm_uses() {
        // 26 sockets' worth of line: up to the rung, never down to it.
        let carry = LINE_CAP_SOCKET_BPS / 2;
        let line = carry * 26;
        assert_eq!(fleet_implied_by_carry(line, carry), 30);
        assert_eq!(fleet_implied_by_carry(carry * 25, carry), 25);
        // The remainder is a whole socket, not a rounding artefact.
        assert_eq!(fleet_implied_by_carry(carry * 25 + 1, carry), 30);
    }

    /// The panel rung and the verdict rung are ONE arithmetic, and this
    /// is what holds them to it.
    ///
    /// They arrived the same day from the two halves of TODO 312, in
    /// the same file, neither lane able to see the other, and for a few
    /// hours main carried `line / carry` and its [`LINE_CAP_RUNG`]
    /// quantisation written out twice. Below the plan the two must
    /// agree exactly; at or above it they part company for one stated
    /// reason and one only, which is the gate the panel wants.
    #[test]
    fn the_reported_rung_and_the_verdict_rung_are_the_same_arithmetic() {
        let line = mbit(1_000);
        for m in [1, 3, 7, 20, 60, 120, 149] {
            let carry = mbit(m);
            assert!(carry < LINE_CAP_SOCKET_BPS, "{m} Mbit is under the plan");
            assert_eq!(
                fleet_implied_by_carry(line, carry),
                sockets_for_carry(line, carry),
                "the two rungs disagree at {m} Mbit a socket"
            );
        }
        // The ONE difference, and it is the panel's gate rather than a
        // second opinion about the arithmetic: at the plan the report
        // falls silent while the verdict still answers.
        assert_eq!(fleet_implied_by_carry(line, LINE_CAP_SOCKET_BPS), 0);
        assert!(sockets_for_carry(line, LINE_CAP_SOCKET_BPS) > 0);
    }

    /// Zero is NO OPINION at every door, and a carry that is meeting the
    /// plan is the curve's business rather than this function's - the
    /// same two gates `fleet_for_supply` opens with, so a reader cannot
    /// find a regime where one of them answers and the other does not.
    #[test]
    fn a_carry_meeting_the_plan_and_a_missing_input_both_report_nothing() {
        assert_eq!(fleet_implied_by_carry(0, mbit(7)), 0, "no line reading");
        assert_eq!(fleet_implied_by_carry(mbit(1_000), 0), 0, "no carry");
        assert_eq!(
            fleet_implied_by_carry(mbit(1_000), LINE_CAP_SOCKET_BPS),
            0,
            "the plan is holding, so the curve owns the answer"
        );
        assert_eq!(
            fleet_implied_by_carry(mbit(9_000), LINE_CAP_SOCKET_BPS * 4),
            0,
            "a carry ABOVE the plan is the regime the knee sweep measured"
        );
        // One byte under the plan is an opinion again - the gate is the
        // same `>=` on both sides.
        assert!(fleet_implied_by_carry(mbit(1_000), LINE_CAP_SOCKET_BPS - 1) > 0);
    }

    #[test]
    fn the_fleet_never_falls_within_a_run() {
        // An achieved rate is a LOWER bound on the line, so a reading
        // that drops is evidence about the SUPPLY and none at all about
        // the line: sockets already handed out are never taken back,
        // which is also what stops the governor oscillating.
        let mut st = (LINE_CAP_DEFAULT_FLEET, 0);
        for _ in 0..LINE_CAP_RAISE_TICKS {
            st = fleet_step(st.0, st.1, mbit(9_000), 0, 0);
        }
        assert_eq!(st.0, LINE_CAP_MAX_FLEET);
        for r in [mbit(500), 0, mbit(20), mbit(3_000)] {
            st = fleet_step(st.0, st.1, r, 0, 0);
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
            st = fleet_step(st.0, st.1, mbit(m), 0, 0);
            assert_eq!(st, (base, 0), "{m} Mbit started a raise");
        }
    }

    #[test]
    fn a_two_rung_jump_applies_whole_once_the_count_is_served() {
        // The count is about the reading being real, not about walking
        // one socket at a time - the whole window is three rungs wide.
        let mut st = (LINE_CAP_DEFAULT_FLEET, 0);
        for _ in 0..LINE_CAP_RAISE_TICKS {
            st = fleet_step(st.0, st.1, mbit(10_000), 0, 0);
        }
        assert_eq!(st.0, LINE_CAP_MAX_FLEET);
    }

    /// A two-server fleet as `get::fleet` seeds it on an ANCHORLESS
    /// run: `spawn` slots born per server, the live target at the
    /// curve's floor share, the governor armed.
    fn seeded_fleet(spawn: usize) -> (Arc<Shared>, Vec<Arc<ConnTarget>>) {
        seeded_fleet_n(&[spawn; 2], LINE_CAP_DEFAULT_FLEET, 0)
    }

    /// The same seed for one server per entry of `spawns` - each
    /// entry that server's own `connections`, which is the ceiling the
    /// share walk mins into - under a cap of `cap`, with the install's
    /// persisted link anchor at `anchor_bps` (0 = the anchorless run
    /// above).
    ///
    /// GH #62 is a FIVE-server config, and the number its reporter
    /// actually sees is `server_share(cap, 5)` rather than the fleet -
    /// so the share walk is the half of the rule that has to be
    /// asserted on, and it is per-target rather than a single number.
    /// The per-server ceilings are a slice rather than one number for
    /// the same reason: a real config's providers do not all grant the
    /// same account size, and what the walk does with the odd one out
    /// is a property nothing had ever asserted.
    fn seeded_fleet_n(
        spawns: &[usize],
        cap: usize,
        anchor_bps: u64,
    ) -> (Arc<Shared>, Vec<Arc<ConnTarget>>) {
        let n = spawns.len();
        let targets: Vec<_> = (0..n)
            .map(|_| ConnTarget::new(server_share(cap, n)))
            .collect();
        let servers: Vec<(ServerConfig, PoolConfig)> = targets
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let spawn = spawns[i];
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
                        address_family: Default::default(),
                        tls_hostname: None,
                    },
                    PoolConfig {
                        connections: spawn,
                        live_target: Some(t.clone()),
                        line_cap_fleet: cap,
                        line_cap_auto: true,
                        // `0` is an anchorless run: a CLI `get`, a
                        // sidecar, a daemon that has never finished a
                        // job. Anything else is the daemon's persisted
                        // `linkpeak.effective`.
                        line_anchor_bps: anchor_bps,
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
                sh.line_cap_tick(i * LINE_CAP_TICK_MS, false);
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

    /// GH #62 / TODO 275 item 1: the reported configuration, as
    /// arithmetic. A 1 Gbit line, five servers granting 50 connections
    /// each, and providers that carry ~13 Mbit a socket rather than the
    /// 150 the curve plans for.
    ///
    /// The curve alone returns its FLOOR at this rate and the governor
    /// could never move off it - that is the defect, and the first two
    /// assertions are what the reporter saw.
    #[test]
    fn the_supply_arm_grows_a_fleet_whose_sockets_cannot_fill_the_line() {
        let line = mbit(1_000);
        assert_eq!(
            fleet_for_line(line),
            LINE_CAP_DEFAULT_FLEET,
            "a 1 Gbit line is the curve's floor"
        );
        assert_eq!(
            server_share(LINE_CAP_DEFAULT_FLEET, 5),
            5,
            "which is the reporter's 5 connections a server"
        );
        // 25 sockets at ~13 Mbit each: ~325 Mbit of a 1 Gbit line.
        let now = mbit(325);
        let got = fleet_for_supply(line, now, 25, LINE_CAP_DEFAULT_FLEET);
        assert!(
            got > LINE_CAP_DEFAULT_FLEET,
            "the line is a third used and the sockets are under the plan: {got}"
        );
        assert_eq!(got, LINE_CAP_MAX_FLEET, "and it is held at the ceiling");
        // The old rule could not move: same inputs, no rate.
        assert_eq!(
            fleet_step(LINE_CAP_DEFAULT_FLEET, 2, line, 0, 0).0,
            LINE_CAP_DEFAULT_FLEET,
            "the curve alone is stuck at the floor, which is the bug"
        );
        assert_eq!(
            fleet_step(LINE_CAP_DEFAULT_FLEET, 2, line, now, 25).0,
            LINE_CAP_MAX_FLEET,
            "and the supply arm carries it through the same streak rule"
        );
    }

    /// The gates, each shown to be the thing that holds. Every case
    /// here MUST return the fleet unchanged, and each fails for its own
    /// reason - so a gate that stops working shows up as one named
    /// assertion rather than as a silently wider rule.
    #[test]
    fn the_supply_arm_has_no_opinion_outside_its_regime() {
        let line = mbit(1_000);
        let f = LINE_CAP_DEFAULT_FLEET;
        assert_eq!(
            fleet_for_supply(line, mbit(800), 25, f),
            f,
            "80% of the line is LINE-bound - the regime the curve measured"
        );
        assert_eq!(
            fleet_for_supply(line, mbit(750), 25, f),
            f,
            "the gate is inclusive at exactly LINE_CAP_SUPPLY_PCT"
        );
        assert_eq!(
            fleet_for_supply(mbit(10_000), mbit(4_000), 25, f),
            f,
            "160 Mbit a socket is ABOVE the planned carry, so the curve owns this \
             one however little of the line is used - the arm is about sockets \
             that under-deliver, not about headroom on its own"
        );
        assert_eq!(
            fleet_for_supply(0, mbit(100), 25, f),
            f,
            "no line reading, no opinion"
        );
        assert_eq!(fleet_for_supply(line, 0, 25, f), f, "no rate, no opinion");
        assert_eq!(
            fleet_for_supply(line, mbit(100), 0, f),
            f,
            "nothing dialling, no divisor, no opinion"
        );
        assert_eq!(
            fleet_for_supply(line, mbit(100), 25, 0),
            0,
            "the rule off stays off"
        );
    }

    /// The safety properties, which are the reason this arm is allowed
    /// to run on a reading it cannot prove is measured rather than
    /// typed.
    #[test]
    fn the_supply_arm_is_monotone_clamped_and_self_limiting() {
        // A wildly wrong (typed) line on a slow pipe reaches the
        // ceiling and stops there - the rung §208 Round A cleared.
        assert_eq!(
            fleet_for_supply(mbit(10_000), mbit(90), 25, LINE_CAP_DEFAULT_FLEET),
            LINE_CAP_MAX_FLEET,
            "the worst a wrong reading can do is a measured-free rung"
        );
        // Self-limiting: once the bigger fleet fills the line, the gate
        // shuts and the fleet stops growing.
        let line = mbit(1_000);
        let grown = fleet_for_supply(line, mbit(325), 25, LINE_CAP_DEFAULT_FLEET);
        assert_eq!(
            fleet_for_supply(line, mbit(950), grown, grown),
            grown,
            "a fleet that now fills its line asks for nothing more"
        );
        // Never falls, whatever it is handed.
        for now in [1, mbit(1), mbit(10), mbit(999)] {
            for dialling in [1, 7, 25, 50, 500] {
                let got = fleet_for_supply(line, now, dialling, LINE_CAP_MAX_FLEET);
                assert!(
                    got >= LINE_CAP_MAX_FLEET,
                    "fell from the ceiling at now={now} dialling={dialling}: {got}"
                );
                assert!(got <= LINE_CAP_MAX_FLEET, "left the window: {got}");
            }
        }
    }

    /// The divisor is the DIALLING count and not the cap, which is the
    /// one input a reader is most likely to wire wrong: TODO 277's seed
    /// spawns a surplus and parks it, so dividing by the spawned or
    /// capped number under-reads the carry and over-asks.
    #[test]
    fn the_supply_arm_divides_by_what_is_dialling_not_by_the_cap() {
        let line = mbit(1_000);
        // 10 sockets holding 300 Mbit is 30 Mbit each - under the plan,
        // so it grows.
        assert!(fleet_for_supply(line, mbit(300), 10, 25) > 25);
        // The SAME rate carried by 1 socket is 300 Mbit - at twice the
        // plan, so the curve owns it and this arm stands down.
        assert_eq!(
            fleet_for_supply(line, mbit(300), 1, 25),
            25,
            "a socket above the planned carry is not this arm's business"
        );
    }

    /// Drive the fleet gauge at a constant `bps` and run the
    /// governor's once-a-second tick over `secs` seconds of synthetic
    /// clock, from a cold pool. Returns the clock it stopped at.
    ///
    /// It samples every 10 ms because the EWMA's warm-up correction is
    /// EXACT for a constant input - `val(t)` is `steady x fill` and
    /// `corrected_rate` divides by exactly that `fill` - so the reading
    /// is the imposed rate from the FIRST tick rather than after a
    /// warm-up. That is what makes these deterministic instead of
    /// timing-dependent, and it is why the carry can be asserted to
    /// within a percent below rather than to an order of magnitude.
    fn feed_and_tick(sh: &Arc<Shared>, secs: u64, bps: u64, tail: bool) -> u64 {
        let step = 10u64;
        let per = bps * step / 1000;
        let mut now = 0u64;
        while now < secs * 1000 {
            now += step;
            sh.sat.note_bytes(now, per, tail);
            if now.is_multiple_of(LINE_CAP_TICK_MS) {
                sh.line_cap_tick(now, tail);
            }
        }
        now
    }

    /// GH #62 / TODO 275 item 1: the supply arm sizes off the carry it
    /// MEASURES, and this pins the number rather than the direction.
    ///
    /// Every other test of this arm asserts that the fleet GREW, and a
    /// version that grew it for the wrong reason passes all of them -
    /// most of them land on [`LINE_CAP_MAX_FLEET`], where the clamp
    /// hides whatever arithmetic produced it. So the case here is
    /// deliberately INTERIOR: a 1 Gbit line whose sockets carry 3.624
    /// MB/s each wants 35 sockets, which is neither the floor nor the
    /// ceiling, so the exact answer is visible.
    ///
    /// That is also the sharpest available check of the DIVISOR, which
    /// is the input a reader is most likely to wire wrong (TODO 277's
    /// seed spawns a surplus and parks it). The same fleet rate divided
    /// by the SPAWNED 50 rather than the DIALLING 25 halves the carry,
    /// doubles the ask and lands on the ceiling - so at an interior
    /// answer the two are separable, where at the ceiling they are not.
    #[test]
    fn the_supply_arm_sizes_off_the_carry_it_measures() {
        let line = mbit(1_000);
        let dialling = 25;
        let carry = 3_624_000u64; // ~29 Mbit a socket
        let now = carry * dialling as u64;
        // The imposed carry, as arithmetic: what the line needs at it,
        // rounded up to a rung and clamped into the curve's window.
        let want = line.div_ceil(carry) as usize;
        assert_eq!(want, 35, "the case is only interesting off the clamps");
        assert_eq!(
            fleet_for_supply(line, now, dialling, LINE_CAP_DEFAULT_FLEET),
            35,
            "the arm must return the carry's own answer, not merely a bigger one"
        );
        // Wired to the spawned count instead, the same rate reads as
        // half the carry and runs into the ceiling.
        assert_eq!(
            fleet_for_supply(line, now, 50, LINE_CAP_DEFAULT_FLEET),
            LINE_CAP_MAX_FLEET,
            "or this case does not separate the divisor from the clamp"
        );
        // And across the band, the answer is exactly the rounded-up
        // rung of `line / carry` wherever that lands inside the window.
        for c in [3_000_000u64, 4_000_000, 5_000_000, 6_000_000, 8_000_000] {
            let n = c * dialling as u64;
            if n.saturating_mul(100) >= line.saturating_mul(LINE_CAP_SUPPLY_PCT) {
                continue; // line-bound: the arm has no opinion there
            }
            let ideal = line.div_ceil(c) as usize;
            let expect = ideal
                .div_ceil(LINE_CAP_RUNG)
                .saturating_mul(LINE_CAP_RUNG)
                .clamp(LINE_CAP_DEFAULT_FLEET, LINE_CAP_MAX_FLEET);
            assert_eq!(
                fleet_for_supply(line, n, dialling, LINE_CAP_DEFAULT_FLEET),
                expect,
                "carry {c} B/s a socket wants {ideal} sockets"
            );
        }
    }

    /// GH #62 end to end through the real tick, in the reporter's own
    /// shape: FIVE servers, a 1 Gbit anchor, and sockets carrying far
    /// under the plan.
    ///
    /// Three things are asserted that nothing else asserts. The GAUGE
    /// reads back the carry the fixture imposed, so the arm is sizing
    /// off a measurement and not off an artefact of the fold. The
    /// DIVISOR is the dialling count: 50 workers are live and 25 of
    /// them parked, which is exactly the seed's shape, and dividing by
    /// the live count instead would land on the ceiling rather than on
    /// the interior rung this asserts. And the SHARE WALK hands every
    /// one of the five targets its new share - the reporter's visible
    /// number is `server_share`, not the fleet, so 25 -> 35 is 5 -> 7
    /// connections a server.
    #[test]
    fn the_governor_measures_the_carry_across_a_five_server_fleet() {
        let line = mbit(1_000);
        let per_server_ceiling = server_share(LINE_CAP_MAX_FLEET, 5);
        let (sh, targets) = seeded_fleet_n(&[per_server_ceiling; 5], LINE_CAP_DEFAULT_FLEET, line);
        assert!(
            targets.iter().all(|t| t.get() == 5),
            "the reporter's seed is 5 connections on each of 5 servers"
        );
        // The seed's own shape: the ceiling's share spawned, the
        // curve's share admitted, the rest parked.
        sh.workers_live
            .store(per_server_ceiling * 5, Ordering::Release);
        sh.parked_total.store(
            per_server_ceiling * 5 - LINE_CAP_DEFAULT_FLEET,
            Ordering::Release,
        );
        assert_eq!(sh.workers_dialling(), LINE_CAP_DEFAULT_FLEET);
        // 25 sockets at 3.624 MB/s each - ~29 Mbit, the long-haul
        // regime - is 72% of a gigabit, under the supply gate.
        let carry = 3_624_000u64;
        let at = feed_and_tick(&sh, 8, carry * LINE_CAP_DEFAULT_FLEET as u64, false);
        // The measurement itself, before anything derived from it.
        let read = sh.sat.now_rate(at).expect("the gauge never trained");
        let measured = read / sh.workers_dialling() as f64;
        assert!(
            (measured - carry as f64).abs() / carry as f64 <= 0.01,
            "the gauge read {measured:.0} B/s a socket against an imposed {carry}"
        );
        assert!(
            targets.iter().all(|t| t.get() == 7),
            "every server should hold its share of 35: {:?}",
            targets.iter().map(|t| t.get()).collect::<Vec<_>>()
        );
        assert_eq!(server_share(35, 5), 7);
    }

    /// TODO 275 item 1 part 2, the other end of the same tick: the
    /// carry the arm just sized off is PUBLISHED, so the daemon can
    /// persist it and the next job can seed from it. Until it is on
    /// `LiveStats` it dies with the pool, which is the whole defect.
    ///
    /// Three properties, and each is a way the memory could be wrong
    /// rather than merely absent. It is the SAME number the arm sized
    /// off - a carry taken anywhere else would let the seed and the
    /// governor disagree about one link. It is the MAXIMUM over the
    /// run, which is the conservative direction because a high carry
    /// asks for FEWER sockets. And a queue-dry tail publishes nothing,
    /// for the reason the F6 guard exists: a short queue is not a slow
    /// socket, and banking a tail's sag would seed the NEXT job at the
    /// ceiling on the strength of this one's last few articles.
    #[test]
    fn the_tick_publishes_the_carry_it_measured() {
        let line = mbit(1_000);
        let (sh, _targets, live) = seeded_fleet_live(LINE_CAP_DEFAULT_FLEET, line);
        sh.workers_live.store(LINE_CAP_MAX_FLEET, Ordering::Release);
        sh.parked_total.store(
            LINE_CAP_MAX_FLEET - LINE_CAP_DEFAULT_FLEET,
            Ordering::Release,
        );
        assert_eq!(sh.workers_dialling(), LINE_CAP_DEFAULT_FLEET);
        assert_eq!(
            live.line_carry_bps.load(Ordering::Relaxed),
            0,
            "nothing measured is nothing published"
        );
        let carry = 3_624_000u64;
        feed_and_tick(&sh, 8, carry * LINE_CAP_DEFAULT_FLEET as u64, false);
        let banked = live.line_carry_bps.load(Ordering::Relaxed);
        // 2% and not the 1% the five-server test above holds the gauge
        // to: this is the same windowed reading through one more
        // rounding (an integer divide by the dialling count), so the
        // slack is the arithmetic and not a weaker claim about it.
        assert!(
            (banked as f64 - carry as f64).abs() / carry as f64 <= 0.02,
            "published {banked} B/s a socket against an imposed {carry}"
        );
        // A slower stretch does not un-teach it: the run's summary is
        // its best, exactly as `linkpeak`'s is for a link.
        feed_and_tick(&sh, 4, carry * 4, false);
        assert_eq!(
            live.line_carry_bps.load(Ordering::Relaxed),
            banked,
            "the maximum stands, so a mid-run sag cannot inflate the next seed"
        );
        // And the tail publishes nothing at all, at any rate.
        let (sh2, _t2, live2) = seeded_fleet_live(LINE_CAP_DEFAULT_FLEET, line);
        sh2.workers_live
            .store(LINE_CAP_MAX_FLEET, Ordering::Release);
        sh2.parked_total.store(
            LINE_CAP_MAX_FLEET - LINE_CAP_DEFAULT_FLEET,
            Ordering::Release,
        );
        feed_and_tick(&sh2, 8, carry * LINE_CAP_DEFAULT_FLEET as u64, true);
        assert_eq!(
            live2.line_carry_bps.load(Ordering::Relaxed),
            0,
            "a queue-dry tail is not evidence about a socket"
        );
    }

    /// [`seeded_fleet_n`]'s two-server shape with a real `LiveStats`
    /// attached, which is the channel the daemon reads the carry back
    /// through. Kept separate rather than folded into that helper: a
    /// dozen tests use it to assert the SHARE WALK, and none of them
    /// should have to care that a gauge is hanging off the side.
    fn seeded_fleet_live(
        cap: usize,
        anchor_bps: u64,
    ) -> (Arc<Shared>, Vec<Arc<ConnTarget>>, Arc<LiveStats>) {
        let per = server_share(LINE_CAP_MAX_FLEET, 2);
        let targets: Vec<_> = (0..2)
            .map(|_| ConnTarget::new(server_share(cap, 2)))
            .collect();
        let mut servers = anchor_cfgs(&[true, true], anchor_bps);
        for (i, (sc, pc)) in servers.iter_mut().enumerate() {
            sc.connections = per as u32;
            pc.connections = per;
            pc.live_target = Some(targets[i].clone());
            pc.line_cap_fleet = cap;
        }
        let live = LiveStats::for_servers(&servers);
        for (_, pc) in servers.iter_mut() {
            pc.live = Some(live.clone());
        }
        let sh = Shared::new(vec![ArticleReq::fresh("<a@x>")], &servers).0;
        (sh, targets, live)
    }

    /// TODO 275 item 1, F6 (27 Aug sweep): no reading taken past
    /// queue-dry is supply evidence, and until this test nothing held
    /// the guard.
    ///
    /// A tail's fleet rate sags because the QUEUE is short, not because
    /// the sockets are slow - a handful of last articles spread over a
    /// full fleet reads exactly like under-supply - and three such
    /// ticks would wake the parked surplus to dial into an empty queue
    /// and join the endgame duplicate racing. The fixture is the rig
    /// above with one bit flipped, so a guard that stopped working
    /// shows up here and nowhere else.
    #[test]
    fn a_queue_dry_tail_is_never_supply_evidence() {
        let line = mbit(1_000);
        let ceiling = server_share(LINE_CAP_MAX_FLEET, 5);
        let carry = 3_624_000u64;
        let bps = carry * LINE_CAP_DEFAULT_FLEET as u64;
        let (sh, targets) = seeded_fleet_n(&[ceiling; 5], LINE_CAP_DEFAULT_FLEET, line);
        sh.workers_live.store(ceiling * 5, Ordering::Release);
        sh.parked_total
            .store(ceiling * 5 - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
        // Eight ticks of exactly the reading that raises the fleet in
        // the test above, every one of them inside the tail.
        feed_and_tick(&sh, 8, bps, true);
        assert!(
            targets.iter().all(|t| t.get() == 5),
            "a queue-dry tail woke the parked surplus: {:?}",
            targets.iter().map(|t| t.get()).collect::<Vec<_>>()
        );
        // The same reading outside the tail does raise it, so this is
        // not passing because the fixture cannot raise at all.
        let (sh, targets) = seeded_fleet_n(&[ceiling; 5], LINE_CAP_DEFAULT_FLEET, line);
        sh.workers_live.store(ceiling * 5, Ordering::Release);
        sh.parked_total
            .store(ceiling * 5 - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
        feed_and_tick(&sh, 8, bps, false);
        assert!(
            targets.iter().all(|t| t.get() == 7),
            "control did not raise"
        );
    }

    /// The half of GH #62's fix that is about everybody ELSE: an
    /// install whose fleet is filling its line must not be grown.
    ///
    /// This is the regime TODO 208 measured - where more sockets bought
    /// nothing and cost wall, RSS and duplicate wire - so the supply
    /// arm standing down here is what keeps the fix away from every
    /// rung those rounds cleared. Same five-server fixture, same
    /// under-the-plan per-socket carry, and the ONLY difference is that
    /// the fleet is moving 80% of its line instead of 72%.
    #[test]
    fn a_five_server_fleet_that_is_filling_its_line_is_left_alone() {
        let line = mbit(1_000);
        let ceiling = server_share(LINE_CAP_MAX_FLEET, 5);
        let (sh, targets) = seeded_fleet_n(&[ceiling; 5], LINE_CAP_DEFAULT_FLEET, line);
        sh.workers_live.store(ceiling * 5, Ordering::Release);
        sh.parked_total
            .store(ceiling * 5 - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
        // 80% of the line, still only 4 MB/s a socket - well under the
        // 18.75 MB/s the curve plans for, so it is the LINE gate and
        // not the carry gate that has to hold here.
        let bps = line * 80 / 100;
        assert!(
            bps / (LINE_CAP_DEFAULT_FLEET as u64) < LINE_CAP_SOCKET_BPS,
            "the per-socket carry must still be under the plan, or this \
             test passes for the other gate's reason"
        );
        feed_and_tick(&sh, 12, bps, false);
        assert!(
            targets.iter().all(|t| t.get() == 5),
            "a line-bound fleet was grown: {:?}",
            targets.iter().map(|t| t.get()).collect::<Vec<_>>()
        );
    }

    /// What the arm concludes when the providers are NOT uniform,
    /// which is GH #62's realistic shape: two AU-routed providers and
    /// three ordinary ones, not five identical ones.
    ///
    /// The arm divides an AGGREGATE rate by an AGGREGATE socket count,
    /// so what it sizes off is the fleet's MEAN carry. Stated as the
    /// property it is: the fleet it asks for is the one that would fill
    /// the line if every socket carried the mean, which is the right
    /// answer for the fleet as a whole and is NOT the same as sizing
    /// each server off its own carry. Per-server sizing would put more
    /// sockets on the slow providers and fewer on the fast ones; the
    /// fleet-wide arm spreads the increase evenly through
    /// [`server_share`] and lets the §112 walker and the steering
    /// gates do the per-server part, which is their job and not this
    /// rule's.
    ///
    /// The two answers are close here rather than equal, and the
    /// direction is the safe one: the mean is dragged DOWN by the slow
    /// providers, so the fleet-wide arm asks for MORE sockets than a
    /// fast-server-only reading would - the same direction the clamp
    /// bounds.
    #[test]
    fn the_supply_arm_reads_a_mixed_speed_fleet_as_its_mean_carry() {
        let line = mbit(1_000);
        // Two providers at ~10 Mbit a socket, three at ~40, five
        // sockets each: the reporter's config with realistic routing.
        let slow = 1_250_000u64;
        let fast = 5_000_000u64;
        let per_server = 5usize;
        let dialling = per_server * 5;
        let now = (2 * per_server as u64) * slow + (3 * per_server as u64) * fast;
        let mean = now / dialling as u64;
        assert_eq!(mean, 3_500_000, "the fleet's mean carry");
        let got = fleet_for_supply(line, now, dialling, LINE_CAP_DEFAULT_FLEET);
        let by_mean = line.div_ceil(mean) as usize;
        assert_eq!(
            got,
            by_mean
                .div_ceil(LINE_CAP_RUNG)
                .saturating_mul(LINE_CAP_RUNG)
                .clamp(LINE_CAP_DEFAULT_FLEET, LINE_CAP_MAX_FLEET),
            "the arm sizes the fleet off its mean carry"
        );
        // A fleet of only the FAST three would read a higher carry and
        // ask for fewer sockets, which is what "the mean is dragged
        // down" means in numbers.
        let fast_only = fleet_for_supply(
            line,
            (3 * per_server as u64) * fast,
            3 * per_server,
            LINE_CAP_DEFAULT_FLEET,
        );
        assert!(
            fast_only <= got,
            "mixed {got} should ask for at least the fast-only {fast_only}"
        );
    }

    /// A server whose ACCOUNT is smaller than its share keeps its
    /// account, and the shortfall is not handed to anybody else.
    ///
    /// Recorded because it is the one way this rule can deliver fewer
    /// sockets than the fleet it decided on, and nothing said so: the
    /// walk is `share.min(ceiling)` per server with no second pass. A
    /// fleet of 35 across five providers is 7 each, but a provider
    /// granting 3 contributes 3, so the fleet on the wire is 31. That
    /// is the conservative direction - it can only ever under-dial an
    /// account, never over-dial one - and redistributing would mean
    /// deciding which provider deserves the surplus, which is the
    /// steering gates' question and not this rule's.
    #[test]
    fn a_small_account_caps_its_own_share_and_is_not_redistributed() {
        let line = mbit(1_000);
        let big = server_share(LINE_CAP_MAX_FLEET, 5);
        let (sh, targets) = seeded_fleet_n(&[big, big, big, big, 3], LINE_CAP_DEFAULT_FLEET, line);
        sh.workers_live.store(big * 4 + 3, Ordering::Release);
        sh.parked_total
            .store(big * 4 + 3 - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
        let carry = 3_624_000u64;
        feed_and_tick(&sh, 8, carry * sh.workers_dialling() as u64, false);
        let got: Vec<usize> = targets.iter().map(|t| t.get()).collect();
        assert_eq!(
            got,
            vec![7, 7, 7, 7, 3],
            "the small account kept its own size"
        );
        assert_eq!(
            got.iter().sum::<usize>(),
            31,
            "so the fleet on the wire is under the 35 the rule decided"
        );
    }

    /// GH #62's remaining gap, as arithmetic, so the ladder that
    /// prices it has a number to move: what the reporter's measured
    /// carry actually asks for, against what the ceiling allows.
    ///
    /// The reporter's own figures - a 1 Gbit line and providers
    /// carrying ~13 Mbit a socket - want 77 sockets. The supply arm
    /// takes them from 25 to 50, which is a real doubling and is not
    /// the whole answer, and the reason it stops there is
    /// [`LINE_CAP_MAX_FLEET`] rather than any property of their line.
    /// Pinned here so that a future raise of that constant is a
    /// deliberate edit with a measurement behind it, and so the shape
    /// of what is still owed does not have to be re-derived.
    #[test]
    fn the_reported_config_still_wants_more_than_the_ceiling_allows() {
        let line = mbit(1_000);
        let carry = mbit(13); // ~1.625 MB/s a socket
        let ideal = line.div_ceil(carry) as usize;
        assert_eq!(ideal, 77, "the reporter's measured arithmetic");
        assert_eq!(
            fleet_for_supply(line, carry * 25, 25, LINE_CAP_DEFAULT_FLEET),
            LINE_CAP_MAX_FLEET,
            "and the arm is held at the ceiling, not at 77"
        );
        assert_eq!(server_share(LINE_CAP_DEFAULT_FLEET, 5), 5, "what they saw");
        assert_eq!(server_share(LINE_CAP_MAX_FLEET, 5), 10, "what they now get");
        assert_eq!(server_share(ideal, 5), 16, "what the measurement wants");
    }

    /// TODO 275 item 1 part 2: the second job starts where the first
    /// one ENDED, and this is what "ended" means in arithmetic.
    ///
    /// GH #62's reporter again. Job one seeds at the curve's floor
    /// because a 1 Gbit line plans for 7 sockets, runs, and the in-run
    /// arm measures ~13 Mbit a socket on the way to walking the fleet
    /// up. Without a memory job two starts at that same floor and
    /// re-walks the identical climb - which is paid at the FRONT of the
    /// job, where the backlog is. With one, the seed asks the same
    /// question of the same number and gets the same answer, at once.
    #[test]
    fn the_next_job_seeds_from_the_carry_the_last_one_measured() {
        let line = mbit(1_000);
        let carry = mbit(13);
        // Job one: no memory, so the curve's floor and nothing else.
        assert_eq!(
            fleet_for_carry(line, 0, fleet_for_line(line)),
            LINE_CAP_DEFAULT_FLEET,
            "a fresh install is exactly the behaviour that shipped"
        );
        // Job two, seeded from what job one measured.
        let seeded = fleet_for_carry(line, carry, fleet_for_line(line));
        assert_eq!(
            seeded, LINE_CAP_MAX_FLEET,
            "and it starts where the in-run arm finished"
        );
        // The seed and the governor must agree about the same link, or
        // one of them is walking somewhere the other would undo. Same
        // carry, same line, same answer.
        assert_eq!(
            seeded,
            fleet_for_supply(line, carry * 25, 25, LINE_CAP_DEFAULT_FLEET),
            "the seed asks the in-run arm's own question"
        );
        assert_eq!(server_share(seeded, 5), 10, "10 a server, not 5");
    }

    /// The seed inherits every one of the in-run arm's gates, so each
    /// is shown here to be the thing that holds. Every case MUST return
    /// the fleet unchanged and each fails for its own reason.
    #[test]
    fn the_seed_stands_down_wherever_the_in_run_arm_does() {
        let f = LINE_CAP_DEFAULT_FLEET;
        // LINE-BOUND, which is the regime TODO 208 measured and the one
        // this arm must never touch: 25 sockets at 40 Mbit would be
        // filling the line, so there is nothing to grow for.
        assert_eq!(
            fleet_for_carry(mbit(1_000), mbit(40), f),
            f,
            "a fleet that would fill its line is not short of sockets"
        );
        // The PLAN is holding: at or above LINE_CAP_SOCKET_BPS the
        // curve owns the answer and this arm has no opinion.
        assert_eq!(
            fleet_for_carry(mbit(100_000), LINE_CAP_SOCKET_BPS, f),
            f,
            "a socket carrying what the curve planned needs no help"
        );
        // No evidence, in each of the three ways there is none.
        assert_eq!(fleet_for_carry(mbit(1_000), 0, f), f, "no carry banked");
        assert_eq!(
            fleet_for_carry(0, mbit(13), f),
            f,
            "no line to divide - an anchorless run seeds at the floor"
        );
        assert_eq!(fleet_for_carry(mbit(1_000), mbit(13), 0), 0, "rule off");
    }

    /// The acceptance property of part 2, stated as the only thing that
    /// could make it unsafe: no carry, however small or however wrong,
    /// may seed a fleet past today's ceiling. That ceiling is what
    /// `fleet_for_supply`'s safety case rests on - it is the rung TODO
    /// 208 Round A cleared at 99 Mbit - and part 2 deliberately does
    /// not move it. Part 3 is where that decision lives.
    #[test]
    fn no_banked_carry_can_seed_past_todays_ceiling() {
        for line in [
            0,
            mbit(10),
            mbit(99),
            mbit(1_000),
            mbit(10_000),
            u64::MAX / 2,
            u64::MAX,
        ] {
            for carry in [1, 1_024, mbit(1), mbit(13), mbit(150), u64::MAX] {
                for fleet in [0, 1, LINE_CAP_DEFAULT_FLEET, LINE_CAP_MAX_FLEET] {
                    let got = fleet_for_carry(line, carry, fleet);
                    assert!(
                        got <= LINE_CAP_MAX_FLEET.max(fleet),
                        "line {line} carry {carry} fleet {fleet} seeded {got}"
                    );
                    assert!(
                        got >= fleet,
                        "and it is monotone: {fleet} -> {got} at line {line} carry {carry}"
                    );
                }
            }
        }
    }

    /// TODO 275 item 1 part 1: the pool can now tell a line reading it
    /// MEASURED from one a user typed into Settings.
    ///
    /// The two are the SAME NUMBER here on purpose. That is exactly the
    /// configuration the fleet rules cannot distinguish today and the
    /// one the whole provenance question is about: an install that
    /// typed 10 Gbps on a 100 Mbit line presents to `fleet_for_supply`
    /// identically to a slow-carry link, and only this word separates
    /// them.
    ///
    /// It asserts availability and NOT behaviour, deliberately. Nothing
    /// in the shipped rules branches on it - raising the ceiling for a
    /// measured anchor is part 3 and is a judgement about what every
    /// install spends. If a future edit makes a rule read this, that
    /// edit is where the measurement has to be.
    #[test]
    fn a_typed_anchor_and_a_measured_one_are_distinguishable_in_the_pool() {
        let anchor = mbit(10_000);
        for (measured, want) in [(true, true), (false, false)] {
            let servers = anchor_cfgs(&[measured, measured], anchor);
            let lc = LineCap::new(&servers);
            assert_eq!(lc.anchor_bps, anchor, "the number is unchanged");
            assert_eq!(
                lc.anchor_measured, want,
                "and the word survives the fold ({measured})"
            );
        }
        // ALL-folded: one typed anchor makes the fleet's reading typed,
        // because it is a claim about the LINE and one link carries the
        // whole fleet. MAX-folding it would let the strongest evidence
        // in the config speak for the weakest.
        let mixed = anchor_cfgs(&[true, false], anchor);
        assert!(
            !LineCap::new(&mixed).anchor_measured,
            "the weakest evidence is what the claim is worth"
        );
        assert!(
            !LineCap::new(&[]).anchor_measured,
            "and no servers at all is not the strongest evidence in the system"
        );
    }

    /// Two server configs carrying the same anchor with the provenance
    /// asked for. Deliberately not `seeded_fleet_n`: this is about
    /// `LineCap::new`'s fold and wants no pool, no targets and no
    /// spawn counts in the way of reading it.
    fn anchor_cfgs(measured: &[bool], anchor_bps: u64) -> Vec<(ServerConfig, PoolConfig)> {
        measured
            .iter()
            .enumerate()
            .map(|(i, m)| {
                (
                    ServerConfig {
                        host: format!("s{i}.example"),
                        port: 119,
                        tls: false,
                        username: None,
                        password: None,
                        connections: 10,
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
                        address_family: Default::default(),
                        tls_hostname: None,
                    },
                    PoolConfig {
                        line_cap_fleet: LINE_CAP_DEFAULT_FLEET,
                        line_cap_auto: true,
                        line_anchor_bps: anchor_bps,
                        line_anchor_measured: *m,
                        ..PoolConfig::default()
                    },
                )
            })
            .collect()
    }
}
