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
//! already cleared - **for an install whose line reading might be a
//! lie, which is the only kind this paragraph was ever about.**
//!
//! **That is why the ceiling is now TWO numbers** (TODO 275 item 7,
//! decided 2 Sep 2026). The bound above holds a TYPED or absent anchor
//! at [`LINE_CAP_MAX_FLEET`] exactly as it always did, and nothing
//! about such an install moves. An anchor the daemon MEASURED is not a
//! claim but a rate this link was seen to carry, so the argument does
//! not apply to it: [`supply_ceiling`] lets that fleet reach
//! [`LINE_CAP_SUPPLY_MAX_FLEET`], bounded by the account's own grant,
//! and only through the in-run governor. The sentence this replaces
//! read "the ceiling must not be raised past the rung that round
//! measured", which was true of what could be told apart at the time it
//! was written and became answerable when the provenance arrived (item
//! 1 part 1, 28 Aug 2026).
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

/// TODO 275 item 7: the SECOND ceiling, in sockets - the most the
/// supply arm may ever ask for, and only ever on an anchor the daemon
/// MEASURED rather than one a user typed. Decided 2 Sep 2026.
///
/// **[`LINE_CAP_MAX_FLEET`] does not move.** It stays the ceiling for
/// every install with a typed line, an absent line, or sockets carrying
/// what the curve plans for, which is every install any TODO 208 round
/// measured. This one is reachable only through [`supply_ceiling`], and
/// only by the in-run governor: the SEED still clamps at 50
/// ([`fleet_for_carry`]), so a job opens where it always did and the
/// governor walks it up under its own hysteresis.
///
/// **It is a BACKSTOP and not the operative ceiling.** What normally
/// binds first is the account's own grant, which [`supply_ceiling`]
/// takes the `min` with - the fleet can never ask a provider for more
/// than it sells, and that needed no new constant. This number bounds
/// the band above the grant, where nothing has been measured at all.
///
/// **Why 100 and not the arithmetic.** `line / measured carry` is 77
/// for GH #62's reporter and 145 for the same line at the carry
/// whyslow's probe reads, and neither is evidence about an engine.
/// What IS measured is three published rounds. A 27 Aug 2026 ladder on
/// a 10 GbE line against ONE cold provider, over five DISJOINT slices of
/// one release so no rung could warm another's articles: per-socket
/// carry 9.95 / 10.32 / 9.97 / 9.54 Mbps at fleets 25 / 50 / 77 / 100 -
/// flat over a 4x range - with peak throughput linear to 77 and 96% of
/// linear at 100. A 28 Aug replication over a SECOND long-haul route
/// from another continent: 20.5 / 22.1 / 21.8 / 22.3 Mbps at 25 / 32 /
/// 50 / 77. And a 28 Aug SHAPED rung that measures THIS ENGINE rather
/// than any provider, every socket held at 5 Mbit by a per-flow pipe:
/// throughput is 99.7% of linear to 100 sockets, so nothing in here
/// bottlenecks before the sockets do.
/// 100 is the TOP of that measured band on both routes, and it is where
/// both routes met the account itself: the first took one `481 ...
/// exceeded maximum number of connections per user` at its grant of
/// 100, and the second route's 100 rung bounced off the same limit and
/// fell to 18.6 Mbps a socket at 55% saturation against 88% at 77. That is a fact about
/// an account, which is why the grant is what binds and this is only
/// the edge of the evidence. Above it §208's 360-socket rung is the
/// only measurement there is and it is bad (299-491 stall kills, 312 MB
/// of duplicate wire, 800 MB of RSS), so nothing may walk into that
/// band on arithmetic.
///
/// The cost of the extra parked slots is measured too and is why this
/// was affordable at all: a parked slot is a tokio task holding no
/// socket at ~6.3 KB of RSS, so 50 -> 100 is ~0.3 MB a job and at most
/// one extra I/O shard (`research/LINECAP-SLOW-CARRY-2026-08-27.md`
/// section 2).
pub const LINE_CAP_SUPPLY_MAX_FLEET: usize = 100;

/// TODO 275 item 7: the ceiling the supply arm may clamp to on THIS
/// fleet - [`LINE_CAP_MAX_FLEET`] unless the line anchor was MEASURED,
/// and never more than the fleet's own `grant`.
///
/// `anchor_measured` is `PoolConfig::line_anchor_measured` ALL-folded
/// (`LineCap::anchor_measured`, TODO 275 item 1 part 1), and it is the
/// whole safety case. [`fleet_for_supply`]'s fourth property is that
/// the worst a wrong line reading can do is put the fleet on a rung
/// §208 Round A measured as free at 99 Mbit; that property is what
/// licenses running the arm on a number a user typed into Settings, and
/// it stops being true the moment the ceiling moves. So the ceiling
/// moves only where the reading is not a claim: a MEASURED anchor is a
/// rate this link was SEEN to carry, so `line / carry` cannot ask for
/// sockets to fill a line that was never there. A typed 10 Gbps on a
/// 100 Mbit line - the configuration the rules cannot otherwise
/// distinguish - keeps today's ceiling exactly.
///
/// `grant` is [`seed_uncapped`]: what this fleet would dial with the
/// cap taking nothing out, each account's own `connections` and any
/// host cap already applied, and a PINNED server contributing 0 because
/// the cap takes nothing from one. **0 means "no claim" and never "no
/// sockets"** - a rig, a CLI pool, an all-pinned fleet - and it holds
/// the ceiling at exactly [`LINE_CAP_MAX_FLEET`], which is today's
/// behaviour and the right answer for a fleet that never said what it
/// was allowed.
///
/// Monotone in both arguments and never below [`LINE_CAP_MAX_FLEET`],
/// so no reading and no configuration can make this stricter than what
/// shipped.
///
/// **The stated limit, and it is the population this reaches.**
/// `linkpeak::Core::effective` says "measured" only when the measured
/// peak is at least the typed line speed (or no line was typed at all),
/// and a peak is an achieved rate - so a fleet the cap is holding down
/// measures its own cap and reads back as "line". The installs this
/// ceiling reaches are therefore the ones that have BEEN faster than
/// they are now: a box with no line speed typed, or one whose peak
/// beat what its owner typed. That is exactly the regime §275 was filed
/// from - a daemon recording `line peak 314.8 MB/s` in the same half
/// hour as a sole-provider job walled at ~0.35 Gbps - and it is NOT
/// GH #62's five-server reporter, whose anchor reads "line". That
/// install keeps 50, which is what item 7 decided.
pub fn supply_ceiling(anchor_measured: bool, grant: usize) -> usize {
    if !anchor_measured {
        return LINE_CAP_MAX_FLEET;
    }
    LINE_CAP_SUPPLY_MAX_FLEET.min(grant).max(LINE_CAP_MAX_FLEET)
}

/// TODO 275 item 10: how full the extractor's held-span ledger may be,
/// in percent of its cap, before the fleet stops growing PAST
/// [`LINE_CAP_MAX_FLEET`].
///
/// **The measurement this exists for** (2 Sep 2026, a 10 GbE line
/// against one cold provider, both fleet-100 legs of item 7's round).
/// A fleet buys a REORDER WINDOW, and a sequential consumer has to hold
/// everything that arrives out of order until the piece in front of it
/// lands. Cold per-article latency variance is what fills that window,
/// and doubling the fleet roughly squares the spread between the
/// fastest and slowest article in flight - so the buffer grows much
/// faster than the fleet does. At 100 sockets the ledger PINS at its
/// cap, the run is saturated 6-7% of the time, and the job takes 3.31x
/// longer per GB than the same job at 50, whose holds reach a quarter
/// of the cap and whose rate is flat for 40 GB. The same slice at 100
/// sockets on WARM content fills the whole line with 43 MB of holds, so
/// this is a property of the ROUTE and not of the fleet size alone.
///
/// **Why the ceiling is not simply lower.** That same round measured
/// fixed fleet 100 beating fixed fleet 50 by 21% on short cold jobs, so
/// the sockets are worth having; what was missing is the arm noticing
/// when they have stopped being worth having. And the population item 7
/// was decided for - GH #62's ~10 Mbps a socket - would want ~1 Gbps at
/// 100 sockets and would very likely never fill this buffer at all, so
/// a blanket lowering would take the win away from the install the
/// ceiling was built for in order to fix a regime it was not.
///
/// **Why 50 and not a measured number.** There is no ladder here, only
/// two points: a quarter of the cap at a fleet that was healthy, and
/// the whole cap at one that was not. This sits between them, nearer
/// the healthy one. Both error directions are bounded and they are not
/// symmetric, which is what makes an unmeasured midpoint acceptable:
/// too STRICT costs an install the item 7 win and returns it to exactly
/// the behaviour that shipped before, while too LOOSE costs 3.31x. The
/// gate is also re-asked every tick rather than latched, so strictness
/// is never permanent - when the ledger drains, the ceiling comes back.
pub const LINE_CAP_HOLDS_PCT: u64 = 50;

/// TODO 275 item 10: may this fleet grow past [`LINE_CAP_MAX_FLEET`]
/// right now, given how full the consumer's held-span ledger is?
///
/// `holds_bytes` is the live gauge and `holds_cap` the ceiling
/// (`PoolConfig::holds_cap`). A cap of 0 is NO CLAIM - a rig, a caller
/// that stamped no budget - and reads as "yes", which is the behaviour
/// that shipped with item 7 and the only answer that cannot invent a
/// constraint out of a missing number.
///
/// It is a whole-PROCESS question on both sides, deliberately: the
/// ledger and its cap are process-wide, so two concurrent jobs share
/// the pressure, and a fleet that grew on the strength of its own share
/// alone would be sizing against a budget it does not have to itself.
pub fn holds_allow_growth(holds_bytes: u64, holds_cap: u64) -> bool {
    if holds_cap == 0 {
        return true;
    }
    holds_bytes.saturating_mul(100) < holds_cap.saturating_mul(LINE_CAP_HOLDS_PCT)
}

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
///   the fleet on `ceiling` - which for every install whose anchor was
///   not MEASURED is [`LINE_CAP_MAX_FLEET`], the rung §208 Round A ran
///   at 99 Mbit, where fleet 50 / 35 / 25 all walled 544-547 s. That
///   bound is what makes plumbing measured-vs-typed anchor provenance
///   unnecessary FOR A TYPED ANCHOR: an install that TYPED 10 Gbps on a
///   100 Mbit line holds this gate open for ever and still only ever
///   reaches a rung that was measured free.
///
/// `ceiling` is [`supply_ceiling`] and must come from there rather than
/// from any caller's own arithmetic - it is the one place the measured
/// anchor and the account's grant are read together, and a second
/// spelling of it is how the second ceiling would reach an install that
/// never proved its line (TODO 275 item 7).
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
/// What held it was the fourth property above: that ceiling IS the
/// bound on a line reading that was TYPED rather than measured, which
/// is the only thing making it safe to run this arm on an anchor whose
/// provenance the pool never sees. An install that typed 10 Gbps on a
/// 100 Mbit line holds the supply gate open for ever and reaches
/// whatever the ceiling is, and §208 measured that regime's far end as
/// 299-491 stall kills, 312 MB of duplicate wire and 800 MB of RSS.
/// So it is a PROVENANCE question, the word has been carried down here
/// since 28 Aug 2026 (`PoolConfig::line_anchor_measured`, folded onto
/// `LineCap::anchor_measured`, §275 item 1 part 1), and on 2 Sep 2026
/// the decision that rests on it was taken: [`supply_ceiling`] hands
/// this arm a SECOND ceiling when the anchor was measured, bounded by
/// the account's own grant. `LINE_CAP_MAX_FLEET` did not move and is
/// still what a typed or absent anchor gets.
pub fn fleet_for_supply(
    line_bps: u64,
    now_bps: u64,
    dialling: usize,
    fleet: usize,
    ceiling: usize,
) -> usize {
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
    // `ceiling.max(fleet)` and not a bare `clamp(fleet, ceiling)`: a
    // caller already above the ceiling - a rig, a typed fleet - must
    // read as NO OPINION and get its own number back, where `clamp`
    // with min > max panics. The arm never lowers a fleet anywhere else
    // and must not acquire the ability here.
    sockets_for_carry(line_bps, per_socket).clamp(fleet, ceiling.max(fleet))
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
/// **The ceiling is emphatically NOT raised here**, and that stayed
/// true when the second ceiling shipped on 2 Sep 2026 (TODO 275 item
/// 7). A SEED reaching it would open a job at 100 sockets on the
/// strength of a carry banked by a job that may have run against a
/// different provider set - `linecarry.rs`'s module doc records
/// that the banked value has no ageing and is fleet-wide, which is
/// bounded and self-correcting inside this window and would not be at
/// the wider one. The governor walks there instead, one hysteresis
/// streak at a time, off THIS run's own gauge.
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
        // TODO 275 item 7: the SEED keeps the first ceiling, and that is
        // a decision rather than a plumbing gap. The second ceiling is
        // reachable only by the in-run governor, so a raise past 50 is
        // always gradual (`LINE_CAP_RAISE_TICKS` of agreement per rung)
        // and always backed by THIS run's own gauge - where a seed would
        // open at 100 on the strength of a number banked by a job that
        // ran against a different provider set. `linecarry.rs`'s
        // module doc records that the banked carry has no ageing and is
        // fleet-wide, which is bounded and self-correcting inside
        // today's window and would not be at the wider one.
        LINE_CAP_MAX_FLEET,
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
/// walking the fleet up one socket at a time, and the first ceiling is
/// three rungs above the floor in total.
///
/// `ceiling` is [`supply_ceiling`] - [`LINE_CAP_MAX_FLEET`] for every
/// install whose anchor was typed or absent, and TODO 275 item 7's
/// second ceiling for one that measured its line. It bounds the SUPPLY
/// candidate only; [`fleet_for_line`] has its own clamp and is
/// untouched by it, so a raise past the first ceiling can only ever be
/// one this run's own gauge asked for.
pub fn fleet_step(
    fleet: usize,
    streak: u32,
    line_bps: u64,
    now_bps: u64,
    dialling: usize,
    ceiling: usize,
) -> (usize, u32) {
    // TODO 275 item 1: two candidates, and the bigger wins. The curve
    // asks what the LINE needs assuming a planned carry; the supply arm
    // asks what it needs at the carry actually MEASURED, and has no
    // opinion at all unless the line is provably under-used. Both are
    // monotone and both clamp into the same window, so the max of them
    // is too - `now_bps == 0` is exactly the old behaviour.
    let want = fleet_for_line(line_bps).max(fleet_for_supply(
        line_bps, now_bps, dialling, fleet, ceiling,
    ));
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

/// TODO 313 item 7: one server's target with a temporary surge loan on
/// top of it, held to the same spawn ceiling.
///
/// The ONE spelling of that sum. Both writers to a `ConnTarget` - the
/// in-run governor's apply loop and [`Shared::surge_apply`] - call it,
/// so a surged target reads as each one's own value to the other. Two
/// spellings of it would be exactly the "two writers, two numbers"
/// fight that made a raise outside `ConnTarget` unsafe in the first
/// place.
///
/// The clamp is applied AFTER the addition and to the sum, never to the
/// base alone: `min(base, ceiling) + lent` would hand back
/// `ceiling + lent` on a server whose share already exceeds its spawn
/// count, and a target above the spawned fleet wakes nothing - so the
/// number would be a fiction the shed arms then read as real.
pub(super) fn surge_want(base: usize, lent: usize, ceiling: usize) -> usize {
    (base + lent).min(ceiling)
}

/// TODO 312 item 2: the fleet a MEASURED per-socket carry implies for
/// this line - **for REPORT ONLY, and nothing in this module calls it**.
///
/// [`fleet_for_supply`] asks the same question of a carry it inferred
/// from a running pool, and [`fleet_for_carry`] of one a previous job
/// banked; both then clamp the answer into the window the knee sweep
/// measured, because both SPEND it. This one asks it of a carry a user
/// deliberately went and measured with the per-server carry probe
/// (`api/servers.rs`), and does NOT clamp - which is the whole
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
/// may be derived from this. What the pool SPENDS goes through
/// [`fleet_for_supply`]'s gates and [`supply_ceiling`]'s clamp, which
/// is where TODO 275 item 7's decision lives; this function is the
/// UNCLAMPED rung a panel needs and is deliberately not that.
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
/// MEASURED rather than typed (TODO 275 item 1 part 1) with the account
/// grant that bounds the ceiling that word unlocks (item 7), the
/// per-server
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
    /// What this fleet would dial with the cap taking nothing out
    /// ([`seed_uncapped`]), which is the account grant TODO 275 item 7's
    /// second ceiling is bounded by. 0 = no claim, which holds the
    /// ceiling at [`LINE_CAP_MAX_FLEET`].
    grant: usize,
    /// TODO 275 item 10: the consumer's held-span ceiling in bytes
    /// (`PoolConfig::holds_cap`), against which the live gauge is read
    /// each tick. 0 = no claim, and the growth gate is inert.
    holds_cap: u64,
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
            anchor_measured: seed_anchor_measured(servers),
            grant: seed_uncapped(servers),
            // MAX-folded like the cap and the anchor: it is a
            // whole-process budget, so every server carries the same
            // number and a fleet that stamped none contributes no
            // claim rather than a zero that would gate everyone.
            holds_cap: servers.iter().map(|(_, c)| c.holds_cap).max().unwrap_or(0),
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

/// Whether the line anchor this fleet sized from was MEASURED rather
/// than typed into Settings (TODO 275 item 1 part 1).
///
/// ALL-folded: it is a claim about the LINE, one link carries the whole
/// fleet, and a claim about evidence is worth what its weakest member is
/// worth. An empty fleet is not measured - `all` over nothing is
/// vacuously true, which would make "no servers at all" the strongest
/// evidence in the system.
///
/// Split out of [`LineCap::new`] on 2 Sep 2026 for [`seed_cap`]'s exact
/// reason: TODO 275 item 7 made this word decide a CEILING, and
/// `LiveStats` has to publish the same ceiling the governor is walking
/// under or the "why is this slow?" surface convicts a cap that is three
/// ticks from raising itself. Two spellings of one fold is this repo's
/// most repeated defect.
pub(super) fn seed_anchor_measured(servers: &[(ServerConfig, PoolConfig)]) -> bool {
    !servers.is_empty() && servers.iter().all(|(_, c)| c.line_anchor_measured)
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
/// gone stale (`crates/nzbfast-core/src/conntune.rs`); nothing in nzbkit has
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
/// staleness is the verdict's own bar (`whyslow.rs`'s
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
        // TODO 275 item 7, the residue handoff's OWED 4: has any account
        // on this fleet refused us for capacity this run? Read ONCE and
        // ABOVE the auto arm, because it is two things at once. It is
        // the ceiling arm's input below, and it is a receipt the "why is
        // this slow?" panel needs on a TYPED cap as well - there no
        // ceiling arm runs at all, and the panel still convicts the
        // budget and still offers to raise it, on an account that has
        // already said no.
        //
        // `swap` rather than a plain store, because the return is the
        // EDGE: the stand-down's one log line is emitted once rather
        // than once a second. A fleet with no `LiveStats` keeps the arm
        // and loses both, which is the trade every gauge on this path
        // makes. Nothing publishes on a run with the cap rule off,
        // either - this whole function returned above.
        let refused = self.auth.iter().any(|a| a.capacity_refused());
        let first_refusal = match &self.live {
            Some(l) => refused && !l.line_cap_refused.swap(true, Ordering::Relaxed),
            None => false,
        };
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
            // TODO 275 item 7: the ceiling this fleet may walk to.
            // `LINE_CAP_MAX_FLEET` for every install whose anchor was
            // typed or absent - which is every install any TODO 208
            // round measured - and the second ceiling, bounded by the
            // account's own grant, for one that measured its line.
            // Recomputed each tick rather than banked: it is two fields
            // that never move, so this costs nothing, and a banked copy
            // is a second place for the ceiling to be wrong.
            // TODO 275 item 7: and a provider that has REFUSED us for
            // capacity this run takes the second ceiling back off the
            // table. A raise past the first ceiling is the one this
            // engine has no measurement above, and an account that has
            // said in words that it will not grant more has already
            // answered the question the arm is about to re-ask with
            // twenty more sockets. It stops the CLIMB and never shrinks
            // the fleet: the cap never falls within a run (`fleet_step`),
            // because a reading is a lower bound on the line and so is
            // evidence for growing and none at all for shrinking, and a
            // ceiling that could shrink a fleet would let one refusal
            // oscillate it for the rest of the job. Cheap - one relaxed
            // load per server, once a second - and it is fleet-wide
            // because the cap is: one refusing account is enough,
            // because the arm sizes a whole-fleet budget it cannot aim
            // at the servers that are not refusing.
            //
            // TODO 275 item 10 is the third condition on the same line,
            // and it is the one that is asked EVERY TICK rather than
            // latched. The fleet buys a reorder window and the
            // sequential consumer has to buffer it; on a cold route
            // that window fills the held-span ledger long before the
            // sockets stop being useful, and past its cap the consumer
            // head-of-line blocks (3.31x per GB, measured). So a fleet
            // may not GROW past the first ceiling while the ledger is
            // full - the same reasoning as the F6 queue-dry guard
            // above, one layer further down the pipeline: a reading
            // taken while the CONSUMER is the bottleneck is not supply
            // evidence about the line. Unlatched on purpose, unlike the
            // refusal: a full ledger is a passing condition and the
            // ceiling comes back when it drains, where a provider's
            // refusal is a durable fact about an account.
            //
            // THE TWO ARMS ARE SPLIT rather than folded into one
            // condition, and the split is what the gauge below needs.
            // `durable` is the ceiling this run is going to keep - the
            // refusal arm's answer holds for the rest of it - while
            // `ceiling` is the one in force THIS TICK, which the holds
            // arm may be lowering for a few seconds. The governor wants
            // the second; a surface asking "can this cap still fix
            // itself" wants the first, and handing it the second would
            // have it convict a cap that is three ticks from raising
            // itself.
            let durable = match refused {
                true => LINE_CAP_MAX_FLEET,
                false => supply_ceiling(lc.anchor_measured, lc.grant),
            };
            let ceiling = match holds_allow_growth(
                crate::memgauge::cur(crate::memgauge::Sub::Holds),
                lc.holds_cap,
            ) {
                true => durable,
                false => LINE_CAP_MAX_FLEET,
            };
            // TODO 275 item 7, the residue handoff's OWED 4: PUBLISH the
            // stand-down. `LiveStats::line_cap_ceiling` was seeded at
            // fleet build and never written again, which was right for
            // the whole day the ceiling was two fixed inputs and wrong
            // from the moment this arm made it a per-tick quantity - a
            // gauge reading 100 over a governor pinned at 50 tells
            // `whyslow::fleet_bound` the cap is about to fix itself,
            // and it is not.
            //
            // Written EVERY tick and not only on a move, because the
            // whole failure this repairs is a stand-down that PREVENTS
            // a raise: there is no move to hang it off. One relaxed
            // store a second, on a path that already does exactly this
            // for `line_carry_bps`.
            //
            // The DURABLE ceiling and never `ceiling`, for the reason
            // the split above states. The latch that explains it was
            // published above, where a typed cap can reach it too.
            if let Some(l) = &self.live {
                l.line_cap_ceiling.store(durable, Ordering::Relaxed);
            }
            // And SAY it once, here rather than at the latch, because
            // this sentence is about the ceiling and a typed cap has no
            // ceiling for a refusal to take away.
            if first_refusal {
                info!(
                    "line cap: a provider refused this account for capacity; \
                     holding the fleet ceiling at {LINE_CAP_MAX_FLEET} \
                     (the account's grant of {} is off the table for this run)",
                    lc.grant
                );
            }
            let (want, streak) = fleet_step(
                cap,
                lc.streak.load(Ordering::Relaxed) as u32,
                line,
                now_bps,
                dialling,
                ceiling,
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
                // raise happened in. It was reported and nothing more
                // until 2 Sep 2026, when the decision it exists for was
                // taken twenty lines above: `supply_ceiling` hands this
                // arm a SECOND ceiling on a measured anchor (TODO 275
                // item 7). So the word is what explains the ceiling
                // this same line goes on to report, and a reader who
                // took it for decoration would have the rule backwards.
                // Appended after
                // the existing parenthetical on purpose - the rig's
                // fleet guard parses the SEED line's head positionally
                // and this line not at all, and the head of this one
                // still opens exactly as it did.
                info!(
                    "line cap: fleet {cap} -> {want} ({:.0} Mbit line seen; seed fleet {}; \
                     {} anchor{})",
                    line as f64 * 8.0 / 1e6,
                    lc.cap,
                    if lc.anchor_measured {
                        "measured"
                    } else {
                        "typed"
                    },
                    // TODO 275 item 7: say when the raise is running
                    // under the SECOND ceiling, and say what bounded it.
                    // A reader diagnosing this regime needs to know
                    // whether 100 or the account's own grant is the
                    // number in the way, because only one of the two is
                    // theirs to change. Silent at the first ceiling, so
                    // every install that is not in this regime keeps the
                    // line it had.
                    match ceiling > LINE_CAP_MAX_FLEET {
                        false => String::new(),
                        true => format!("; ceiling {ceiling} of the account's {}", lc.grant),
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
            // TODO 313 item 7: the surge's loan is part of the number
            // this governor puts on the wire, not a raise made behind
            // its back. Adding it HERE is the whole of why two writers
            // can share one `ConnTarget` without fighting: the shed arm
            // below sees `cur == want` on a surged target and leaves it,
            // where a raise made outside would read as somebody else's
            // value and be shed within the second.
            let want = surge_want(share.min(*ceiling), self.surge.lent_on(si), *ceiling);
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

    /// TODO 313 item 7: re-apply ONE server's live target with the
    /// surge's current loan folded in, and answer with the number now
    /// in force (`None` = nothing moved).
    ///
    /// This is the surge's only way to the wire, and it is deliberately
    /// the SAME apply the governor above makes rather than a second
    /// one: `want` comes from [`surge_want`] in both places, and the
    /// value written is recorded in `lc.set[si]` exactly as the
    /// governor records its own, so the next `line_cap_tick` reads a
    /// surged target as OURS and neither raises past it nor sheds it
    /// away. A raise made around `ConnTarget` would be invisible to the
    /// §208/§277 shed arms - §9d constraint 3, and the memory topic
    /// `nzbfast-linecap-achieved-rate-is-not-a-line` is what that
    /// invisibility costs.
    ///
    /// **Three stand-downs, and each one is a refusal to guess.**
    ///
    /// * **No target, no surge.** A pinned server, a single-connection
    ///   server and an install with the fleet cap off all run without
    ///   one, and a target is the only thing that can hand a socket
    ///   back without retiring the worker holding it. Item 5's fifth
    ///   stand-down for the queue spill is the same rule for the same
    ///   reason.
    /// * **The rule off (`cap == 0`), no surge.** With no seed cap
    ///   there is no per-server share to add a loan to:
    ///   `server_share(0, n)` is 1 by its own floor, so a surge that
    ///   used it as a base would COLLAPSE a live-tuned fleet to one
    ///   socket plus the loan. The only other owner of such a target is
    ///   the §112 walker, whose number is not ours to build on.
    /// * **A target somebody else is driving, no surge.** The `ours`
    ///   test is the governor's own, and it is what stops a surge
    ///   laundering the walker's value into the governor's bookkeeping
    ///   - which would let the next tick raise from a number the
    ///   governor never chose.
    pub(super) fn surge_apply(&self, si: usize) -> Option<usize> {
        let lc = &self.line_cap;
        if lc.cap == 0 {
            return None;
        }
        let (target, ceiling) = lc.targets.get(si)?.as_ref()?;
        // The cap in FORCE - `fleet` once the governor has applied one,
        // the seed until then - so the surge and the governor divide
        // the same number across the same servers.
        let cap = match lc.fleet.load(Ordering::Relaxed) {
            0 => lc.cap,
            f => f,
        };
        let base = server_share(cap, lc.targets.len()).min(*ceiling);
        let want = surge_want(base, self.surge.lent_on(si), *ceiling);
        let mine = lc.set[si].load(Ordering::Relaxed);
        let seeded = server_share(lc.cap, lc.targets.len()).min(*ceiling);
        let moved = target.update(|cur| {
            let ours = cur == mine || (mine == usize::MAX && cur == seeded);
            (ours && cur != want).then_some(want)
        });
        if !moved {
            return None;
        }
        lc.set[si].store(want, Ordering::Relaxed);
        if let Some(l) = &self.live
            && let Some(sl) = l.servers.get(si)
        {
            sl.budget.store(want, Ordering::Relaxed);
        }
        Some(want)
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

// Child module file, not inline: this file's cases outgrew the
// production code they cover (1,908 test lines against 1,509), and an
// inline `mod tests` is scored against the production file's 4,000-line
// ceiling while a `#[cfg(test)] mod x;` target gets the 12,000-line test
// one. Same pattern as postfast/src/container/tests.rs.
#[cfg(test)]
mod tests;
