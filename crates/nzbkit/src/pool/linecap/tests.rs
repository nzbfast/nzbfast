//! The line-cap curve's own test suite: the rate -> fleet ladder and its
//! rungs, the supply arm that grows a fleet whose sockets cannot fill
//! the line, the holds ledger's stand-down, and the seeding that carries
//! one job's measured carry into the next.
//!
//! Its own file rather than an inline `mod tests`, which had taken
//! `linecap.rs` to 3,418 of the size gate's 4,000-line file ceiling on
//! 7 Sep 2026 (claim `debt-split-hot-files-7sep`) with production code
//! accounting for only 1,509 of them. Same move, and for the same
//! reason, as `postfast/src/container/tests.rs` and the six test
//! children of `nzbfast-unpack/src/repair.rs`: a `#[cfg(test)] mod x;`
//! target is whole-file test code, so it is scored against the 12,000-
//! line test ceiling and the production file gets its own back.
//!
//! Verbatim move - every case, helper and comment is the one that was
//! inline, dedented by one level and nothing else.

use super::*;

/// Mbit/s as the bytes/s a gauge actually reports, so the cases
/// below read as line rates and not as nine-digit constants.
fn mbit(m: u64) -> u64 {
    m * 1_000_000 / 8
}

/// The per-socket carry the TODO 275 ladders measured on a cold
/// giganews route, in bytes/s: ~10 Mbps, flat from fleet 25 to 100
/// on a 10 GbE line (27 Aug 2026) and reproduced at 18-22 Mbps over
/// a second long-haul route the next day. On a gigabit line it implies exactly
/// 100 sockets, which is what makes it the right fixture for the
/// second ceiling: the arm is self-limiting, so a faster carry
/// stops the fleet below 50 for reasons that have nothing to do
/// with any ceiling.
const COLD_CARRY_BPS: u64 = 1_250_000;

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
    let (f, s) = fleet_step(LINE_CAP_DEFAULT_FLEET, 0, fast, 0, 0, LINE_CAP_MAX_FLEET);
    assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 1));
    let (f, s) = fleet_step(f, s, fast, 0, 0, LINE_CAP_MAX_FLEET);
    assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 2));
    // The burst stops one tick short and the count is lost.
    let (f, s) = fleet_step(f, s, mbit(400), 0, 0, LINE_CAP_MAX_FLEET);
    assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 0));
    // So it has to start again from the beginning.
    let (f, s) = fleet_step(f, s, fast, 0, 0, LINE_CAP_MAX_FLEET);
    assert_eq!((f, s), (LINE_CAP_DEFAULT_FLEET, 1));
}

#[test]
fn a_reading_that_holds_moves_the_fleet_once_and_stays() {
    let fast = mbit(9_000);
    let mut st = (LINE_CAP_DEFAULT_FLEET, 0);
    for _ in 0..LINE_CAP_RAISE_TICKS {
        st = fleet_step(st.0, st.1, fast, 0, 0, LINE_CAP_MAX_FLEET);
    }
    assert_eq!(st, (LINE_CAP_MAX_FLEET, 0));
    // At the ceiling nothing further can accumulate, so a fleet
    // that has arrived cannot keep re-announcing itself.
    for _ in 0..10 {
        st = fleet_step(st.0, st.1, fast, 0, 0, LINE_CAP_MAX_FLEET);
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
        fleet_for_supply(
            line,
            mbit(35),
            5,
            LINE_CAP_DEFAULT_FLEET,
            LINE_CAP_MAX_FLEET
        ),
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
        st = fleet_step(st.0, st.1, mbit(9_000), 0, 0, LINE_CAP_MAX_FLEET);
    }
    assert_eq!(st.0, LINE_CAP_MAX_FLEET);
    for r in [mbit(500), 0, mbit(20), mbit(3_000)] {
        st = fleet_step(st.0, st.1, r, 0, 0, LINE_CAP_MAX_FLEET);
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
        st = fleet_step(st.0, st.1, mbit(m), 0, 0, LINE_CAP_MAX_FLEET);
        assert_eq!(st, (base, 0), "{m} Mbit started a raise");
    }
}

#[test]
fn a_two_rung_jump_applies_whole_once_the_count_is_served() {
    // The count is about the reading being real, not about walking
    // one socket at a time - the whole window is three rungs wide.
    let mut st = (LINE_CAP_DEFAULT_FLEET, 0);
    for _ in 0..LINE_CAP_RAISE_TICKS {
        st = fleet_step(st.0, st.1, mbit(10_000), 0, 0, LINE_CAP_MAX_FLEET);
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
    // A TYPED anchor, which is what every test written before TODO
    // 275 item 7 assumed and what keeps them all asserting about
    // the first ceiling.
    seeded_fleet_full(spawns, cap, anchor_bps, false)
}

/// [`seeded_fleet_n`] with the line anchor's PROVENANCE said out
/// loud (TODO 275 item 7).
///
/// `measured` becomes `PoolConfig::line_anchor_measured` on every
/// server, which is what `LineCap::new` ALL-folds, and each
/// server's `line_cap_uncapped` is its own `spawns` entry - the
/// grant the second ceiling is bounded by, exactly as
/// `get::fleet::cap_exposed` stamps it for a server the cap may
/// cut.
fn seeded_fleet_full(
    spawns: &[usize],
    cap: usize,
    anchor_bps: u64,
    measured: bool,
) -> (Arc<Shared>, Vec<Arc<ConnTarget>>) {
    // A fixture stamps NO holds ceiling, so TODO 275 item 10's
    // growth gate is inert for every test but the ones about it.
    // That is the point rather than a convenience: the gate reads a
    // PROCESS-WIDE gauge, and a fixture carrying a cap would make
    // every fleet test in this file depend on what an unrelated
    // test left in that gauge.
    seeded_fleet_holds(spawns, cap, anchor_bps, measured, 0)
}

/// [`seeded_fleet_full`] with the consumer's held-span ceiling set,
/// which is what arms TODO 275 item 10's growth gate.
fn seeded_fleet_holds(
    spawns: &[usize],
    cap: usize,
    anchor_bps: u64,
    measured: bool,
    holds_cap: u64,
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
                    warm_reserve: None,
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
                    line_anchor_measured: measured,
                    line_cap_uncapped: spawn,
                    holds_cap,
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
    let got = fleet_for_supply(line, now, 25, LINE_CAP_DEFAULT_FLEET, LINE_CAP_MAX_FLEET);
    assert!(
        got > LINE_CAP_DEFAULT_FLEET,
        "the line is a third used and the sockets are under the plan: {got}"
    );
    assert_eq!(got, LINE_CAP_MAX_FLEET, "and it is held at the ceiling");
    // The old rule could not move: same inputs, no rate.
    assert_eq!(
        fleet_step(LINE_CAP_DEFAULT_FLEET, 2, line, 0, 0, LINE_CAP_MAX_FLEET).0,
        LINE_CAP_DEFAULT_FLEET,
        "the curve alone is stuck at the floor, which is the bug"
    );
    assert_eq!(
        fleet_step(LINE_CAP_DEFAULT_FLEET, 2, line, now, 25, LINE_CAP_MAX_FLEET).0,
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
        fleet_for_supply(line, mbit(800), 25, f, LINE_CAP_MAX_FLEET),
        f,
        "80% of the line is LINE-bound - the regime the curve measured"
    );
    assert_eq!(
        fleet_for_supply(line, mbit(750), 25, f, LINE_CAP_MAX_FLEET),
        f,
        "the gate is inclusive at exactly LINE_CAP_SUPPLY_PCT"
    );
    assert_eq!(
        fleet_for_supply(mbit(10_000), mbit(4_000), 25, f, LINE_CAP_MAX_FLEET),
        f,
        "160 Mbit a socket is ABOVE the planned carry, so the curve owns this \
         one however little of the line is used - the arm is about sockets \
         that under-deliver, not about headroom on its own"
    );
    assert_eq!(
        fleet_for_supply(0, mbit(100), 25, f, LINE_CAP_MAX_FLEET),
        f,
        "no line reading, no opinion"
    );
    assert_eq!(
        fleet_for_supply(line, 0, 25, f, LINE_CAP_MAX_FLEET),
        f,
        "no rate, no opinion"
    );
    assert_eq!(
        fleet_for_supply(line, mbit(100), 0, f, LINE_CAP_MAX_FLEET),
        f,
        "nothing dialling, no divisor, no opinion"
    );
    assert_eq!(
        fleet_for_supply(line, mbit(100), 25, 0, LINE_CAP_MAX_FLEET),
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
        fleet_for_supply(
            mbit(10_000),
            mbit(90),
            25,
            LINE_CAP_DEFAULT_FLEET,
            LINE_CAP_MAX_FLEET
        ),
        LINE_CAP_MAX_FLEET,
        "the worst a wrong reading can do is a measured-free rung"
    );
    // Self-limiting: once the bigger fleet fills the line, the gate
    // shuts and the fleet stops growing.
    let line = mbit(1_000);
    let grown = fleet_for_supply(
        line,
        mbit(325),
        25,
        LINE_CAP_DEFAULT_FLEET,
        LINE_CAP_MAX_FLEET,
    );
    assert_eq!(
        fleet_for_supply(line, mbit(950), grown, grown, LINE_CAP_MAX_FLEET),
        grown,
        "a fleet that now fills its line asks for nothing more"
    );
    // Never falls, whatever it is handed.
    for now in [1, mbit(1), mbit(10), mbit(999)] {
        for dialling in [1, 7, 25, 50, 500] {
            let got = fleet_for_supply(line, now, dialling, LINE_CAP_MAX_FLEET, LINE_CAP_MAX_FLEET);
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
    assert!(fleet_for_supply(line, mbit(300), 10, 25, LINE_CAP_MAX_FLEET) > 25);
    // The SAME rate carried by 1 socket is 300 Mbit - at twice the
    // plan, so the curve owns it and this arm stands down.
    assert_eq!(
        fleet_for_supply(line, mbit(300), 1, 25, LINE_CAP_MAX_FLEET),
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
    feed_and_tick_from(sh, 0, secs, bps, tail)
}

/// [`feed_and_tick`] CONTINUING from a clock this fleet has already
/// seen, returning the new one.
///
/// A second `feed_and_tick` on the same pool does almost nothing
/// and does it silently: it restarts at zero, so the governor's own
/// interval guard (`now - lc.at < LINE_CAP_TICK_MS`) drops every
/// tick in it and the saturation window is fed timestamps behind
/// the ones it holds. Any test that wants a SECOND stretch of run -
/// a condition that lifts, a latch that does not - has to move the
/// clock forward instead. `from` is left a multiple of
/// [`LINE_CAP_TICK_MS`] by every caller, so the tick alignment
/// carries across the join.
fn feed_and_tick_from(sh: &Arc<Shared>, from: u64, secs: u64, bps: u64, tail: bool) -> u64 {
    let step = 10u64;
    let per = bps * step / 1000;
    let mut now = from;
    let end = from + secs * 1000;
    while now < end {
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
        fleet_for_supply(
            line,
            now,
            dialling,
            LINE_CAP_DEFAULT_FLEET,
            LINE_CAP_MAX_FLEET
        ),
        35,
        "the arm must return the carry's own answer, not merely a bigger one"
    );
    // Wired to the spawned count instead, the same rate reads as
    // half the carry and runs into the ceiling.
    assert_eq!(
        fleet_for_supply(line, now, 50, LINE_CAP_DEFAULT_FLEET, LINE_CAP_MAX_FLEET),
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
            fleet_for_supply(
                line,
                n,
                dialling,
                LINE_CAP_DEFAULT_FLEET,
                LINE_CAP_MAX_FLEET
            ),
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

/// TODO 275 item 7, acceptance (a): an install whose line reading
/// is TYPED, or absent, tops out exactly where it always did.
///
/// This is the half of item 7 that is a promise about EVERY
/// install rather than about the regime the ladders measured, and
/// it is what makes the second ceiling safe at all
/// (`supply_ceiling`'s doc has the argument): the typed 10 Gbps on
/// a 100 Mbit line holds the supply gate open for ever, so the only
/// thing between it and §208's measured-bad far end is where this
/// clamp lands.
///
/// The grants swept here go far past the second ceiling on purpose.
/// A fleet's ACCOUNT allowance says nothing about whether its line
/// reading is worth believing, and a rule that read the two
/// together would let a big account buy provenance.
#[test]
fn a_typed_or_absent_anchor_tops_out_where_it_always_did() {
    for grant in [0, 1, 25, 50, 77, 100, 500, usize::MAX] {
        assert_eq!(
            supply_ceiling(false, grant),
            LINE_CAP_MAX_FLEET,
            "a typed anchor with a grant of {grant} moved the ceiling"
        );
    }
    // And through the arm itself, in the shape that most nearly
    // reaches for the second ceiling: a wildly over-stated line, a
    // carry far under the plan, and every tick agreeing for long
    // enough that the hysteresis is not what is holding it.
    let ceiling = supply_ceiling(false, 500);
    let mut st = (LINE_CAP_DEFAULT_FLEET, 0);
    for _ in 0..(LINE_CAP_RAISE_TICKS * 10) {
        st = fleet_step(st.0, st.1, mbit(10_000), mbit(90), 25, ceiling);
        assert!(
            st.0 <= LINE_CAP_MAX_FLEET,
            "a typed anchor reached {} sockets",
            st.0
        );
    }
    assert_eq!(st.0, LINE_CAP_MAX_FLEET, "and it still reaches the first");
}

/// TODO 275 item 7, acceptance (b): a MEASURED anchor may walk past
/// the first ceiling, and never past the account's own grant.
///
/// The grant is the operative bound and the constant is the
/// backstop, which is the whole shape of the decision taken on
/// 2 Sep 2026: `conntune::line_cap_spawn_slots` already held the
/// fleet to what each account sells, so the second ceiling needed
/// no new number to be safe - only one to bound the band above the
/// grant, where nothing has been measured on any route.
#[test]
fn a_measured_anchor_may_walk_up_to_the_account_grant() {
    // Never below the first ceiling, whatever the grant says. A
    // small account is already held by its own share walk, and a
    // ceiling that dipped under 50 would take sockets off an
    // install that had them before this existed.
    for grant in [0, 1, 25, 49, 50] {
        assert_eq!(
            supply_ceiling(true, grant),
            LINE_CAP_MAX_FLEET,
            "a grant of {grant} lowered the ceiling"
        );
    }
    // Between the two it IS the grant: the fleet can never ask a
    // provider for more than it sells.
    for grant in [51, 60, 77, 99] {
        assert_eq!(supply_ceiling(true, grant), grant, "grant {grant}");
    }
    // And above it the constant is what bounds the unmeasured band.
    for grant in [100, 250, 500, usize::MAX] {
        assert_eq!(
            supply_ceiling(true, grant),
            LINE_CAP_SUPPLY_MAX_FLEET,
            "grant {grant} walked past the measured band"
        );
    }
    // Monotone in the grant, so no account size is a cliff.
    let mut last = 0;
    for grant in 0..=200 {
        let got = supply_ceiling(true, grant);
        assert!(got >= last, "ceiling fell at grant {grant}");
        last = got;
    }
}

/// The same, through the governor's own step: the second ceiling
/// changes WHERE the walk stops and nothing about HOW it walks.
///
/// Every property the first ceiling had is asserted again here
/// rather than assumed, because the ceiling is the one argument
/// `fleet_step` gained and an arm that reached it by any other
/// route would pass a test that only looked at the destination: a
/// raise still needs `LINE_CAP_RAISE_TICKS` consecutive ticks, the
/// fleet still never falls, and a tick with no supply reading
/// (`now_bps == 0`) still leaves the curve to answer alone - which
/// on this line is the floor.
#[test]
fn the_second_ceiling_moves_the_destination_and_not_the_walk() {
    let line = mbit(1_000);
    // 25 sockets at 10 Mbps each - the carry the 27 Aug ladder
    // MEASURED against a cold provider, flat across a 4x fleet
    // range - which is 25% of a gigabit and implies 100 sockets.
    let now = COLD_CARRY_BPS * LINE_CAP_DEFAULT_FLEET as u64;
    let ceiling = supply_ceiling(true, 100);
    assert_eq!(ceiling, LINE_CAP_SUPPLY_MAX_FLEET);

    // A raise still costs a full agreement streak, at every rung.
    let mut st = (LINE_CAP_DEFAULT_FLEET, 0);
    let mut raises = 0;
    for _ in 0..(LINE_CAP_RAISE_TICKS * 12) {
        let before = st.0;
        st = fleet_step(st.0, st.1, line, now, LINE_CAP_DEFAULT_FLEET, ceiling);
        if st.0 > before {
            raises += 1;
            assert_eq!(st.1, 0, "a raise clears the count");
        }
    }
    assert!(raises >= 1, "the fleet never moved at all");
    assert!(
        st.0 > LINE_CAP_MAX_FLEET,
        "a measured anchor stopped at the first ceiling: {}",
        st.0
    );
    assert!(st.0 <= ceiling, "it left the window: {}", st.0);

    // It never falls, and a tick carrying no supply reading is the
    // curve alone - which at 1 Gbit is the floor, so the fleet
    // simply stays where it is.
    let held = st.0;
    for r in [0, mbit(10), mbit(999)] {
        st = fleet_step(st.0, st.1, line, r, LINE_CAP_DEFAULT_FLEET, ceiling);
        assert!(st.0 >= held, "a {r} B/s reading shrank the fleet");
    }
}

/// TODO 275 item 7 end to end through the real tick, and the pair
/// that says the provenance is what does it: two fleets identical
/// in every number - same line, same carry, same grant, same seed -
/// and only the anchor's PROVENANCE different.
///
/// That is the configuration `a_typed_anchor_and_a_measured_one_are_distinguishable_in_the_pool`
/// pinned as merely VISIBLE on 28 Aug 2026, with a note saying that
/// the edit which made a rule read it is where the measurement has
/// to be. This is that edit, and the measurement is in
/// `LINE_CAP_SUPPLY_MAX_FLEET`'s own doc: three published rounds,
/// two routes, carry flat to 100 sockets.
#[test]
fn only_a_measured_anchor_puts_the_extra_sockets_on_the_wire() {
    let line = mbit(1_000);
    // Grant each of the five servers 20, so the fleet's own
    // allowance is 100 - the second ceiling - and the share walk
    // has somewhere to go.
    let per_server = 20usize;
    let mut reached = Vec::new();
    for measured in [false, true] {
        let (sh, targets) =
            seeded_fleet_full(&[per_server; 5], LINE_CAP_DEFAULT_FLEET, line, measured);
        // The seed's own shape: the headroom's share spawned, the
        // curve's share admitted, the rest parked.
        sh.workers_live.store(per_server * 5, Ordering::Release);
        sh.parked_total
            .store(per_server * 5 - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
        assert_eq!(sh.workers_dialling(), LINE_CAP_DEFAULT_FLEET);
        // The ladder's own measured cold carry: 10 Mbps a socket,
        // so this line wants 100 of them and the gate is open the
        // whole way.
        let carry = COLD_CARRY_BPS;
        feed_and_tick(&sh, 30, carry * LINE_CAP_DEFAULT_FLEET as u64, false);
        let cap = sh.line_cap.cur.load(Ordering::Relaxed);
        let widest = targets.iter().map(|t| t.get()).max().unwrap_or(0);
        assert_eq!(
            widest,
            server_share(cap, 5).min(per_server),
            "every target should hold its share of {cap} (measured {measured})"
        );
        reached.push(cap);
    }
    assert_eq!(
        reached[0], LINE_CAP_MAX_FLEET,
        "a typed anchor must stop at the first ceiling"
    );
    assert!(
        reached[1] > reached[0],
        "a measured anchor bought nothing: {} against {}",
        reached[1],
        reached[0]
    );
    assert!(
        reached[1] <= LINE_CAP_SUPPLY_MAX_FLEET,
        "and it left the measured band: {}",
        reached[1]
    );
}

/// TODO 275 item 10: the ledger question, on its own and with no
/// pool in the way.
///
/// A cap of 0 is NO CLAIM and must read as "yes". That is the arm
/// most likely to be got wrong by a later edit, because a missing
/// number and a full ledger are both falsy-looking and only one of
/// them is a constraint - a fixture, a rig, or any caller that
/// stamped no budget would otherwise have its fleet gated by a
/// ceiling nobody set.
#[test]
fn a_ledger_with_no_ceiling_constrains_nothing() {
    for bytes in [0, 1, 1 << 30, u64::MAX] {
        assert!(
            holds_allow_growth(bytes, 0),
            "a cap of 0 gated growth at {bytes} bytes"
        );
    }
    let cap = 1_000_000_000u64;
    assert!(holds_allow_growth(0, cap), "an empty ledger");
    assert!(
        holds_allow_growth(cap / 4, cap),
        "the quarter measured healthy"
    );
    assert!(
        holds_allow_growth(cap * LINE_CAP_HOLDS_PCT / 100 - 1, cap),
        "one byte under the bar"
    );
    assert!(
        !holds_allow_growth(cap * LINE_CAP_HOLDS_PCT / 100, cap),
        "the bar itself is inclusive, like the supply gate"
    );
    assert!(!holds_allow_growth(cap, cap), "the ledger measured pinned");
    // Neither side may overflow into the wrong answer.
    assert!(!holds_allow_growth(u64::MAX, cap));
    assert!(holds_allow_growth(0, u64::MAX));
}

/// TODO 275 item 10 through the real tick, as a control pair: the
/// SAME fleet, the same line, the same carry, and only the
/// consumer's ledger different.
///
/// This is the defect the 2 Sep 2026 round found in item 7 as
/// shipped. The fleet buys a reorder window, a cold route fills it,
/// and past the ledger's cap the sequential consumer head-of-line
/// blocks - 3.31x longer per GB at 100 sockets than at 50. The arm
/// could not see it, and worse, it feeds itself: a blocked consumer
/// drops the achieved rate, which makes the LINE look even more
/// under-used, which is the arm's own signal to ask for more
/// sockets.
///
/// It holds the gauge lock because the ledger is a PROCESS-wide
/// atomic, and it puts back exactly what it added rather than
/// resetting, so a test running beside it in the same process keeps
/// whatever it was counting.
#[test]
fn a_full_holds_ledger_stops_the_fleet_at_the_first_ceiling() {
    let _guard = crate::memgauge::one_gauge_test_at_a_time();
    let line = mbit(1_000);
    let per_server = 20usize;
    let holds_cap = 1_000_000_000u64;
    let carry = COLD_CARRY_BPS;
    let mut reached = Vec::new();
    // Full first, then empty: the second arm is the control and it
    // must reach the second ceiling, or the first proves nothing.
    for full in [true, false] {
        let charged = match full {
            true => holds_cap,
            false => 0,
        };
        crate::memgauge::add(crate::memgauge::Sub::Holds, charged);
        let (sh, _t) = seeded_fleet_holds(
            &[per_server; 5],
            LINE_CAP_DEFAULT_FLEET,
            line,
            true,
            holds_cap,
        );
        sh.workers_live.store(per_server * 5, Ordering::Release);
        sh.parked_total
            .store(per_server * 5 - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
        feed_and_tick(&sh, 30, carry * LINE_CAP_DEFAULT_FLEET as u64, false);
        reached.push(sh.line_cap.cur.load(Ordering::Relaxed));
        crate::memgauge::sub(crate::memgauge::Sub::Holds, charged);
    }
    assert_eq!(
        reached[0], LINE_CAP_MAX_FLEET,
        "a fleet whose consumer is already blocked climbed to {}",
        reached[0]
    );
    assert!(
        reached[1] > LINE_CAP_MAX_FLEET,
        "the control never reached the second ceiling, so this test proves nothing: {}",
        reached[1]
    );
}

/// The gate must NOT fire below the first ceiling, which is the
/// constraint that keeps it away from every TODO 208 round.
///
/// Those rounds measured the 25-to-50 window on lines this rule
/// still governs, and a consumer-pressure gate reaching into it
/// would change what they measured for every install, including
/// every one that never goes near the second ceiling.
#[test]
fn a_full_holds_ledger_still_lets_a_fleet_reach_the_first_ceiling() {
    let _guard = crate::memgauge::one_gauge_test_at_a_time();
    let holds_cap = 1_000_000_000u64;
    crate::memgauge::add(crate::memgauge::Sub::Holds, holds_cap);
    let (sh, targets) = seeded_fleet_holds(
        &[20; 5],
        LINE_CAP_DEFAULT_FLEET,
        mbit(1_000),
        true,
        holds_cap,
    );
    sh.workers_live.store(100, Ordering::Release);
    sh.parked_total
        .store(100 - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
    feed_and_tick(
        &sh,
        30,
        COLD_CARRY_BPS * LINE_CAP_DEFAULT_FLEET as u64,
        false,
    );
    let cap = sh.line_cap.cur.load(Ordering::Relaxed);
    crate::memgauge::sub(crate::memgauge::Sub::Holds, holds_cap);
    assert_eq!(
        cap, LINE_CAP_MAX_FLEET,
        "the fleet must still climb to the first ceiling under a full ledger"
    );
    assert!(
        targets.iter().all(|t| t.get() == server_share(cap, 5)),
        "and the share walk must have handed it out: {:?}",
        targets.iter().map(|t| t.get()).collect::<Vec<_>>()
    );
}

/// The gate stops GROWTH and never takes sockets back.
///
/// The cap may not fall within a run - a reading is an achieved
/// rate and so a lower bound on the line, which is evidence for
/// growing and none at all for shrinking - and a ceiling that could
/// shrink a fleet would let a ledger crossing its bar oscillate the
/// whole fleet for the rest of the job. So a fleet already past the
/// first ceiling when the ledger fills STAYS there.
#[test]
fn a_ledger_that_fills_after_the_fleet_grew_takes_nothing_back() {
    let _guard = crate::memgauge::one_gauge_test_at_a_time();
    let holds_cap = 1_000_000_000u64;
    let (sh, _t) = seeded_fleet_holds(
        &[20; 5],
        LINE_CAP_DEFAULT_FLEET,
        mbit(1_000),
        true,
        holds_cap,
    );
    sh.workers_live.store(100, Ordering::Release);
    sh.parked_total
        .store(100 - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
    // Grow with the ledger empty.
    let at = feed_and_tick(
        &sh,
        30,
        COLD_CARRY_BPS * LINE_CAP_DEFAULT_FLEET as u64,
        false,
    );
    let grown = sh.line_cap.cur.load(Ordering::Relaxed);
    assert!(grown > LINE_CAP_MAX_FLEET, "the fleet never grew: {grown}");
    // Now fill it and keep ticking.
    crate::memgauge::add(crate::memgauge::Sub::Holds, holds_cap);
    for _ in 0..LINE_CAP_RAISE_TICKS * 4 {
        sh.line_cap.at.store(0, Ordering::Relaxed);
        sh.line_cap_tick(at + 1_000, false);
    }
    let after = sh.line_cap.cur.load(Ordering::Relaxed);
    crate::memgauge::sub(crate::memgauge::Sub::Holds, holds_cap);
    assert_eq!(after, grown, "a full ledger shrank the fleet from {grown}");
}

/// TODO 275 item 7, acceptance (c): a provider that REFUSES for
/// capacity takes the second ceiling back off the table.
///
/// The walk-back is a stand-down and NOT a shrink, which is the one
/// thing to read before changing it. The cap never falls within a
/// run - a reading is a lower bound on the line, so it is evidence
/// for growing and none at all for shrinking - and a ceiling that
/// could shrink a fleet would let one refusal from one server
/// oscillate the whole fleet for the rest of the job. What this
/// buys is that a fleet cannot keep climbing into an account that
/// has already said no; the surplus workers that meet the refusal
/// are parked by `park_or_probe`, which is the machinery that
/// shipped and is untouched here.
#[test]
fn a_capacity_refusal_stands_the_second_ceiling_down() {
    let line = mbit(1_000);
    let per_server = 20usize;
    let (sh, _targets) = seeded_fleet_full(&[per_server; 5], LINE_CAP_DEFAULT_FLEET, line, true);
    sh.workers_live.store(per_server * 5, Ordering::Release);
    sh.parked_total
        .store(per_server * 5 - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
    // ONE server of five, in the provider's own words. The ceiling
    // is a whole-fleet budget, so one refusing account is enough:
    // the arm cannot aim its extra sockets at the four that are
    // not refusing.
    sh.auth[3].note(
        crate::nntp::AuthRefusal::Capacity,
        "481 exceeded maximum number of connections per user",
    );
    assert!(sh.auth[3].capacity_refused());
    let carry = COLD_CARRY_BPS;
    feed_and_tick(&sh, 30, carry * LINE_CAP_DEFAULT_FLEET as u64, false);
    let cap = sh.line_cap.cur.load(Ordering::Relaxed);
    assert_eq!(
        cap, LINE_CAP_MAX_FLEET,
        "a refused fleet climbed past the first ceiling to {cap}"
    );
    // And it is the REFUSAL doing it: the identical fleet without
    // one is the control, and it walks past.
    let (ok, _t) = seeded_fleet_full(&[per_server; 5], LINE_CAP_DEFAULT_FLEET, line, true);
    ok.workers_live.store(per_server * 5, Ordering::Release);
    ok.parked_total
        .store(per_server * 5 - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
    feed_and_tick(&ok, 30, carry * LINE_CAP_DEFAULT_FLEET as u64, false);
    assert!(
        ok.line_cap.cur.load(Ordering::Relaxed) > LINE_CAP_MAX_FLEET,
        "the control never reached the second ceiling, so the test proves nothing"
    );
}

/// TODO 275 item 7, the residue handoff's OWED 4: the stand-down
/// this arm applies REACHES A SURFACE.
///
/// `LiveStats::line_cap_ceiling` was seeded at fleet build and
/// never written again, which was right for one day and wrong from
/// the moment this arm made the ceiling a per-tick quantity. On the
/// install the second ceiling was built for - a measured anchor
/// over an account granting more than the first ceiling - the gauge
/// went on reading the grant while the governor was pinned at
/// `LINE_CAP_MAX_FLEET` for the rest of the run, and
/// `whyslow::fleet_bound` reads exactly that gauge to decide
/// whether a cap can still fix itself. So the one thing pinning the
/// fleet was the one thing the "why is this slow?" panel could not
/// say.
///
/// The cap DOES NOT MOVE in either arm here and that is deliberate:
/// the failure being repaired is a stand-down that PREVENTS a
/// raise, so a test that waited for a move would be waiting for the
/// thing this case does not have.
///
/// The control is the identical fleet with no refusal, which is
/// what says the refusal and not the seeding did it.
#[test]
fn the_tick_publishes_the_stand_down_it_applied() {
    let line = mbit(1_000);
    let grant = LINE_CAP_SUPPLY_MAX_FLEET;
    // The fixture's own guard: without a grant past the first
    // ceiling there is no second ceiling to stand down from, and
    // both arms below would read 50 whatever the code did.
    assert_eq!(
        supply_ceiling(true, grant),
        grant,
        "a measured anchor must reach past the first ceiling here"
    );
    assert!(grant > LINE_CAP_MAX_FLEET);
    let (sh, _t, live) = seeded_fleet_live_full(LINE_CAP_DEFAULT_FLEET, line, grant, 0, true);
    assert_eq!(
        live.line_cap_ceiling.load(Ordering::Relaxed),
        grant,
        "the fleet was built with the whole grant available to it"
    );
    assert!(
        !live.line_cap_refused.load(Ordering::Relaxed),
        "nothing has refused anything yet"
    );
    // One server of two, in the provider's own words. The arm is
    // fleet-wide because the cap is, so the gauge is too.
    sh.auth[1].note(
        crate::nntp::AuthRefusal::Capacity,
        "481 max simultaneous IP addresses reached",
    );
    let carry = COLD_CARRY_BPS * LINE_CAP_DEFAULT_FLEET as u64;
    let at = feed_and_tick(&sh, 5, carry, false);
    assert_eq!(
        live.line_cap_ceiling.load(Ordering::Relaxed),
        LINE_CAP_MAX_FLEET,
        "the gauge went on offering a ceiling the governor had taken away"
    );
    assert!(
        live.line_cap_refused.load(Ordering::Relaxed),
        "the number alone cannot say a refusal is why it fell"
    );
    // And it LATCHES with the arm it mirrors: five more seconds of
    // an account serving normally do not put the ceiling back,
    // because the question the arm asks is whether this account has
    // said no AT ANY POINT.
    feed_and_tick_from(&sh, at, 5, carry, false);
    assert_eq!(
        live.line_cap_ceiling.load(Ordering::Relaxed),
        LINE_CAP_MAX_FLEET,
        "a run the account went back to serving got its second ceiling back"
    );
    assert!(live.line_cap_refused.load(Ordering::Relaxed));
    // The control: the same fleet, the same ticks, no refusal.
    let (ok, _t2, live2) = seeded_fleet_live_full(LINE_CAP_DEFAULT_FLEET, line, grant, 0, true);
    feed_and_tick(
        &ok,
        5,
        COLD_CARRY_BPS * LINE_CAP_DEFAULT_FLEET as u64,
        false,
    );
    assert_eq!(
        live2.line_cap_ceiling.load(Ordering::Relaxed),
        grant,
        "the control lost its ceiling with nothing refusing it"
    );
    assert!(!live2.line_cap_refused.load(Ordering::Relaxed));
}

/// The refusal receipt is published on a TYPED cap too, where there
/// is no ceiling for the refusal to take away.
///
/// The governor does not run on a typed cap, so nothing lowers a
/// ceiling and `line_cap_ceiling` keeps the number it was seeded
/// with. But `whyslow::fleet_bound` convicts a typed cap on evidence
/// that never asks about a ceiling at all - a typed cap never grows,
/// so it binds at whatever number it holds - and the panel then
/// offers to raise the connection budget. That offer is the one this
/// receipt exists to withhold, and it is made here as readily as in
/// the automatic regime.
#[test]
fn a_typed_cap_publishes_the_refusal_even_though_no_ceiling_moved() {
    let line = mbit(1_000);
    let grant = LINE_CAP_SUPPLY_MAX_FLEET;
    let (sh, _t, live) = seeded_fleet_live_full(LINE_CAP_DEFAULT_FLEET, line, grant, 0, false);
    let seeded = live.line_cap_ceiling.load(Ordering::Relaxed);
    sh.auth[0].note(
        crate::nntp::AuthRefusal::Capacity,
        "481 exceeded maximum number of connections per user",
    );
    feed_and_tick(
        &sh,
        5,
        COLD_CARRY_BPS * LINE_CAP_DEFAULT_FLEET as u64,
        false,
    );
    assert!(
        live.line_cap_refused.load(Ordering::Relaxed),
        "a typed cap met a refusal and published nothing a surface could read"
    );
    assert_eq!(
        live.line_cap_ceiling.load(Ordering::Relaxed),
        seeded,
        "a typed cap has no ceiling arm, so nothing may move the ceiling gauge"
    );
    assert_eq!(
        sh.line_cap.cur.load(Ordering::Relaxed),
        LINE_CAP_DEFAULT_FLEET,
        "the governor ran on a typed cap, so this fixture is not the regime it claims"
    );
}

/// The DESIGN CALL at the centre of OWED 4, made testable: the
/// gauge carries the LATCHED half of the ceiling and not the
/// passing one.
///
/// Two arms lower the tick's ceiling and they are not the same kind
/// of fact. A capacity refusal is a durable statement about an
/// account and never cleared; item 10's held-span gate is a
/// condition that passes, and its own comment says the ceiling
/// comes back when the ledger drains. `fleet_bound` reads this
/// gauge to ask whether a cap can still fix itself, so a gauge that
/// simply mirrored the tick's ceiling would flap with the holds arm
/// and convict a cap that really is three ticks from raising
/// itself - which is the defect OWED 4 repairs, wearing the other
/// hat.
///
/// So: a full ledger holds the GOVERNOR at the first ceiling, and
/// leaves the gauge alone. Both halves are asserted, because a
/// gauge that stayed put on a fleet whose governor was never gated
/// would prove nothing.
#[test]
fn a_full_holds_ledger_gates_the_governor_and_not_the_gauge() {
    let _guard = crate::memgauge::one_gauge_test_at_a_time();
    let line = mbit(1_000);
    let grant = LINE_CAP_SUPPLY_MAX_FLEET;
    let holds_cap = 1_000_000_000u64;
    let (sh, _t, live) =
        seeded_fleet_live_full(LINE_CAP_DEFAULT_FLEET, line, grant, holds_cap, true);
    // Wide enough that a raise has somewhere to land, so a cap that
    // stops at the first ceiling stopped because it was gated.
    sh.workers_live.store(grant, Ordering::Release);
    sh.parked_total
        .store(grant - LINE_CAP_DEFAULT_FLEET, Ordering::Release);
    crate::memgauge::add(crate::memgauge::Sub::Holds, holds_cap);
    let carry = COLD_CARRY_BPS * LINE_CAP_DEFAULT_FLEET as u64;
    let at = feed_and_tick(&sh, 30, carry, false);
    let gated = sh.line_cap.cur.load(Ordering::Relaxed);
    let ceiling = live.line_cap_ceiling.load(Ordering::Relaxed);
    let refused = live.line_cap_refused.load(Ordering::Relaxed);
    crate::memgauge::sub(crate::memgauge::Sub::Holds, holds_cap);
    assert_eq!(
        gated, LINE_CAP_MAX_FLEET,
        "the governor was not gated by the ledger, so the gauge half proves nothing"
    );
    assert_eq!(
        ceiling, grant,
        "a passing condition took the durable ceiling off the gauge"
    );
    assert!(
        !refused,
        "a full ledger is not an account refusing anything"
    );
    // Drained - the `sub` above - the governor walks past the first
    // ceiling again, which is the property that makes this cap one
    // that CAN fix itself and so the one a verdict must not
    // convict. The clock CONTINUES: a second run from zero would be
    // dropped by the governor's own interval guard and would read
    // as a gate that never lifted.
    feed_and_tick_from(&sh, at, 30, carry, false);
    assert!(
        sh.line_cap.cur.load(Ordering::Relaxed) > LINE_CAP_MAX_FLEET,
        "the ledger drained and the fleet stayed put, so it was never the ledger"
    );
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
    // A grant of 0 leaves `supply_ceiling` at the FIRST ceiling for
    // every one of this helper's older callers, which is what they
    // were written against.
    seeded_fleet_live_full(cap, anchor_bps, 0, 0, true)
}

/// [`seeded_fleet_live`] with the two inputs the second ceiling and
/// its two stand-down arms are made of: the account `grant` the
/// ceiling is bounded by ([`seed_uncapped`], split evenly over the
/// two servers) and the consumer's `holds_cap`.
///
/// `auto` is the cap's own provenance: `true` is the curve's number
/// and the governor may walk it, `false` is one somebody typed and
/// the governor never runs at all - which is the regime that has a
/// refusal receipt to publish and no ceiling to take away.
///
/// A grant of 0 and a holds cap of 0 are both "inert", not "zero":
/// the first leaves `supply_ceiling` at [`LINE_CAP_MAX_FLEET`] and
/// the second leaves item 10's growth gate unarmed, which is what
/// keeps a fixture from making every test in this file depend on
/// what an unrelated one left in a process-wide gauge.
fn seeded_fleet_live_full(
    cap: usize,
    anchor_bps: u64,
    grant: usize,
    holds_cap: u64,
    auto: bool,
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
        pc.line_cap_uncapped = grant / 2;
        pc.holds_cap = holds_cap;
        pc.line_cap_auto = auto;
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
    let got = fleet_for_supply(
        line,
        now,
        dialling,
        LINE_CAP_DEFAULT_FLEET,
        LINE_CAP_MAX_FLEET,
    );
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
        LINE_CAP_MAX_FLEET,
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
        fleet_for_supply(
            line,
            carry * 25,
            25,
            LINE_CAP_DEFAULT_FLEET,
            LINE_CAP_MAX_FLEET
        ),
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
        fleet_for_supply(
            line,
            carry * 25,
            25,
            LINE_CAP_DEFAULT_FLEET,
            LINE_CAP_MAX_FLEET
        ),
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
                    warm_reserve: None,
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
