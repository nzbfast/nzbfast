//! TODO 313 item 7: the temporary surge dial, arm by arm.
//!
//! **WHAT THESE TESTS PIN, AND IT IS THE STAND-DOWNS AS MUCH AS THE
//! DIAL.** A mechanism whose feature-ON arm is indistinguishable from
//! feature-OFF is the shape that cost two lanes four hours on the
//! queue-spill rig (`research/NOTE-2026-09-02-QSPILL-E2E-RED-
//! DIAGNOSIS.md`): a stand-down the test never pinned was correctly
//! declining on one platform and correctly firing on the other, and the
//! failure was deterministic, identical on retry and left every one of
//! the feature's own timings unchanged. So every stand-down here gets
//! its own arm AND a control arm proving the same fixture surges once
//! the stand-down is lifted - a green suite in which nothing ever
//! dialled would look exactly the same otherwise.
//!
//! **The environment these tests have to pin is the CLOCK and not the
//! platform.** Nothing in this mechanism reads a filesystem, a device
//! class or an OS capability - the queue-spill trap's own subject - so
//! there is no `rotational`-shaped fact for a cloud VM to answer
//! differently from a Mac. What there IS is a bound derived from a
//! trained EWMA and an age measured against it, so every fixture below
//! sets `art_ms` explicitly and BACK-DATES its in-flight entries rather
//! than sleeping: a rig that slept would be measuring the test box's
//! scheduler, and under a loaded CI shard that is the same
//! deterministic-and-identical-on-retry failure wearing different
//! clothes.

use super::*;
use crate::pool::linecap::{LINE_CAP_DEFAULT_FLEET, server_share};

/// A two-server fleet seeded exactly as `get::fleet` seeds an
/// anchorless run, with the surge armed at `max`.
///
/// `spawn` is each server's own `connections` - the count `get::fleet`
/// SPAWNS from `conntune::line_cap_spawn_slots`, which is the ceiling
/// the surge inherits both provider bounds from (§9d.1). The live
/// target starts at the curve's floor share, so `spawn - share` is the
/// parked headroom a surge has to wake into.
///
/// `blocked` flags server 0 as a metered account, which is the §9d.2
/// stand-down's fixture.
fn fleet(spawn: usize, max: usize, blocked: bool) -> (Arc<Shared>, Vec<Arc<ConnTarget>>) {
    fleet_anchored(spawn, max, blocked, 0)
}

/// [`fleet`] with the install's persisted link anchor set, which is
/// what ARMS the fleet cap's mid-run shed (`allow_shed`). Needed by the
/// one test that has to prove the governor leaves a surged target
/// alone: with no anchor there is no shed to survive.
fn fleet_anchored(
    spawn: usize,
    max: usize,
    blocked: bool,
    anchor_bps: u64,
) -> (Arc<Shared>, Vec<Arc<ConnTarget>>) {
    let cap = LINE_CAP_DEFAULT_FLEET;
    // The seed's own shape: the target starts at what this server
    // DIALS, which is its share of the cap held to its own ceiling, and
    // `spawn` slots are born - the surplus parked. A fixture that
    // seeded the target above the spawn count would be testing a fleet
    // this pool cannot build.
    let targets: Vec<_> = (0..2)
        .map(|_| ConnTarget::new(server_share(cap, 2).min(spawn)))
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
                    block_account: blocked && i == 0,
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
                    line_cap_uncapped: spawn,
                    line_anchor_bps: anchor_bps,
                    block_account: blocked && i == 0,
                    surge_max: max,
                    // The bound the surge shares is `hedge`'s, and the
                    // shipped profile sets this; without it the bound
                    // is the flat 8 s, which the last test asserts on
                    // deliberately.
                    hedge: true,
                    ..PoolConfig::default()
                },
            )
        })
        .collect();
    let reqs: Vec<ArticleReq> = (0..64)
        .map(|i| ArticleReq::fresh(format!("<a{i}@x>")))
        .collect();
    (Shared::new(reqs, &servers).0, targets)
}

/// Put an in-flight entry on `si`, dispatched `age` ago.
///
/// BACK-DATED rather than slept for - see the module doc. `Instant`
/// arithmetic can saturate near process start on some platforms, so the
/// subtraction is checked and falls back to the run's own start, which
/// is older than any bound these tests use.
fn stale_entry(sh: &Arc<Shared>, id: &str, si: usize, age: Duration) {
    let dispatched = Instant::now().checked_sub(age).unwrap_or(sh.start);
    sh.inflight.lock_ok().insert(
        Arc::from(id),
        Inflight {
            server: si,
            dispatched,
            dups: 0,
            tried_430: 0,
            dup_servers: 0,
            found: 0,
            tried_fail: 0,
            suspect: false,
            age_days: 0,
            part: 0,
            file: 0,
            ord: 0,
        },
    );
    sh.bump_inflight_gen();
}

/// The staleness bound in force, so a test never writes a number the
/// mechanism derives.
fn bound(sh: &Shared) -> Duration {
    sh.hedge_stale_bound()
}

/// Tick past the fleet-wide rate limit `n` times, returning the ms
/// stamp reached. Ticks are spaced [`SURGE_TICK_MS`] apart because that
/// is what the CAS admits - a test that ticked faster would be
/// asserting on the rate limit and calling it the mechanism.
fn tick_n(sh: &Arc<Shared>, from: u64, n: usize) -> u64 {
    let mut now = from;
    for _ in 0..n {
        now += SURGE_TICK_MS;
        sh.surge_tick(now);
    }
    now
}

/// THE MECHANISM: a stale article with no idle connection dials one
/// extra socket, through `ConnTarget::set`, and the fleet cap's own
/// bookkeeping agrees with the number that landed.
#[test]
fn a_stale_article_with_nothing_idle_dials_one_extra_socket() {
    let (sh, targets) = fleet(20, 2, false);
    let base = targets[0].get();
    stale_entry(&sh, "<a0@x>", 0, bound(&sh) + Duration::from_millis(50));
    tick_n(&sh, 0, 1);
    assert_eq!(
        targets[0].get(),
        base + 1,
        "the surge did not reach the wire"
    );
    assert_eq!(sh.surge.lent_on(0), 1);
    assert_eq!(sh.surge.out.load(Ordering::Relaxed), 1);
    // The OTHER server holds no stale article, so it is untouched: the
    // loan is aimed at the server that is stuck, not spread over the
    // fleet.
    assert_eq!(targets[1].get(), base, "an unstuck server was surged");
}

/// §9d.3: it went THROUGH `ConnTarget::set`, and the proof that this
/// matters is that the fleet cap's own in-run SHED then leaves it
/// alone.
///
/// A raise made around `ConnTarget` would be invisible to the
/// §208/§277 shed arms; a raise made through it but not recorded would
/// read to the next tick as somebody else's value and be shed within
/// the second. The governor runs here with its shed armed (a real link
/// anchor) and the surged socket survives it, because the loan is part
/// of the number the governor itself computes.
#[test]
fn the_fleet_caps_own_shed_leaves_a_surged_target_alone() {
    let (sh, targets) = fleet_anchored(20, 2, false, 12_500_000);
    let base = targets[0].get();
    stale_entry(&sh, "<a0@x>", 0, bound(&sh) + Duration::from_millis(50));
    let now = tick_n(&sh, 0, 1);
    assert_eq!(targets[0].get(), base + 1);
    // The governor's own tick, with the shed armed. Its CAS admits one
    // caller per LINE_CAP_TICK_MS, so this is a real tick and not a
    // no-op return.
    // 1_000 ms is `linecap::LINE_CAP_TICK_MS`, which is private to
    // that module - spelled out rather than widened for a test.
    for i in 1..=3u64 {
        sh.line_cap_tick(now + i * 1_000, false);
    }
    assert_eq!(targets[0].get(), base + 1, "the governor shed the surge");
    assert_eq!(sh.surge.lent_on(0), 1);
    // And when the loan comes back, the governor's own number is what
    // is left - not one socket under it.
    sh.inflight.lock_ok().clear();
    tick_n(&sh, now + 4_000, 1);
    assert_eq!(targets[0].get(), base, "the give-back overshot");
}

/// The defining gate: with an idle connection available the shipped
/// hedge can race the stale article for free, so this arm stands down.
///
/// The control arm is the test above, on the identical fixture - the
/// ONLY difference between them is the gauge, which is what makes this
/// a stand-down rather than a mechanism that never fires.
#[test]
fn an_idle_connection_stands_the_surge_down() {
    let (sh, targets) = fleet(20, 2, false);
    let base = targets[0].get();
    stale_entry(&sh, "<a0@x>", 0, bound(&sh) + Duration::from_millis(50));
    let idle = IdleConn::hold(&sh);
    tick_n(&sh, 0, 4);
    assert_eq!(targets[0].get(), base, "surged with a connection idle");
    assert_eq!(sh.surge.out.load(Ordering::Relaxed), 0);
    // And the moment that connection takes work, the same fixture
    // surges - the guard's Drop is the whole difference.
    drop(idle);
    tick_n(&sh, 4 * SURGE_TICK_MS, 1);
    assert_eq!(targets[0].get(), base + 1);
}

/// It shares [`Shared::hedge_stale_bound`] rather than growing a bound
/// of its own: an article one tick YOUNGER than the bound is not stale,
/// the same article is stale once the bound moves under it, and nothing
/// here reads a number the hedge does not.
#[test]
fn the_surge_shares_the_hedge_bound_and_never_its_own() {
    let (sh, targets) = fleet(20, 2, false);
    let base = targets[0].get();
    // Train the EWMA so the bound is the derived 3x rather than the
    // flat maximum: 400 ms trains to 1200 ms.
    sh.art_ms.store(400, Ordering::Relaxed);
    assert_eq!(bound(&sh), Duration::from_millis(1_200));
    // Just inside the bound: not stale, no surge.
    stale_entry(&sh, "<a0@x>", 0, Duration::from_millis(1_100));
    let now = tick_n(&sh, 0, 4);
    assert_eq!(targets[0].get(), base, "surged inside the shared bound");
    // The ARTICLE has not moved - the BOUND has. A faster-training
    // fleet has a tighter bound, and the same 1100 ms article is stale
    // against it. That is the whole claim: one threshold, and the surge
    // is downstream of it.
    sh.art_ms.store(100, Ordering::Relaxed);
    assert_eq!(bound(&sh), Duration::from_millis(500));
    tick_n(&sh, now, 1);
    assert_eq!(targets[0].get(), base + 1);
    // And it is the number the dashboard reads. `hedge_bound_ms` is
    // published from the same call, so a reader diagnosing a surge and
    // a reader diagnosing a hedge cannot be looking at two thresholds.
    assert_eq!(sh.hedge_stale_bound(), Duration::from_millis(500));
}

/// §9d.1: the surge never dials past the server's SPAWNED count, which
/// is `conntune::line_cap_spawn_slots`'s `min(headroom_share,
/// uncapped)` with any measured knee already applied.
///
/// Pinned on a server spawned at exactly its share, so there is no
/// parked slot at all: the loan is refused rather than recorded, because
/// a loan that moved no target is a socket we never got and would sit
/// against the fleet allowance for nothing.
#[test]
fn the_surge_never_dials_past_the_spawn_ceiling() {
    let share = server_share(LINE_CAP_DEFAULT_FLEET, 2);
    let (sh, targets) = fleet(share, 2, false);
    assert_eq!(targets[0].get(), share, "the fixture has no parked slot");
    stale_entry(&sh, "<a0@x>", 0, bound(&sh) + Duration::from_millis(50));
    tick_n(&sh, 0, 6);
    assert_eq!(targets[0].get(), share, "dialled past the spawn ceiling");
    assert_eq!(sh.surge.out.load(Ordering::Relaxed), 0, "a phantom loan");
    // Control: the identical fixture with ONE parked slot surges once
    // and then stops at the ceiling, so the refusal above is the
    // ceiling and not the mechanism being dead.
    let (sh, targets) = fleet(share + 1, 2, false);
    stale_entry(&sh, "<a0@x>", 0, bound(&sh) + Duration::from_millis(50));
    tick_n(&sh, 0, 6);
    assert_eq!(targets[0].get(), share + 1);
    assert_eq!(
        sh.surge.out.load(Ordering::Relaxed),
        1,
        "took a second slot"
    );
}

/// §9d.2: a metered account is excluded, the same question every other
/// speculative dup picker asks (`Shared::speculative_blocked`).
///
/// The 27 Aug 2026 defect this refuses - a Block account racing for
/// duplicate BODIES at per-gigabyte rates - is what an unguarded surge
/// reintroduces, and the control arm is the unstuck server beside it
/// surging on the identical fixture.
#[test]
fn a_block_account_never_surges() {
    let (sh, targets) = fleet(20, 2, true);
    let base = targets[0].get();
    stale_entry(&sh, "<a0@x>", 0, bound(&sh) + Duration::from_millis(50));
    tick_n(&sh, 0, 4);
    assert_eq!(targets[0].get(), base, "surged a metered account");
    assert_eq!(sh.surge.out.load(Ordering::Relaxed), 0);
    // Control: server 1 is the same fixture without the flag, and the
    // same stall on IT dials.
    stale_entry(&sh, "<a1@x>", 1, bound(&sh) + Duration::from_millis(50));
    tick_n(&sh, 4 * SURGE_TICK_MS, 1);
    assert_eq!(targets[1].get(), base + 1);
    assert_eq!(targets[0].get(), base, "the metered server moved after all");
}

/// The socket is GIVEN BACK when the stall clears - the ordinary
/// return, and the one the module doc's requirement describes.
#[test]
fn the_extra_socket_comes_back_when_the_article_lands() {
    let (sh, targets) = fleet(20, 2, false);
    let base = targets[0].get();
    stale_entry(&sh, "<a0@x>", 0, bound(&sh) + Duration::from_millis(50));
    let now = tick_n(&sh, 0, 1);
    assert_eq!(targets[0].get(), base + 1);
    // The article lands: its entry leaves the map, exactly as
    // `deregister_inflight_done` does it.
    sh.inflight.lock_ok().clear();
    sh.bump_inflight_gen();
    tick_n(&sh, now, 1);
    assert_eq!(targets[0].get(), base, "the fleet stayed wide");
    assert_eq!(sh.surge.out.load(Ordering::Relaxed), 0);
    assert_eq!(sh.surge.lent_on(0), 0);
}

/// AND IT COMES BACK IN THE FAILURE CASE TOO: a stuck article that
/// never arrives must not leave the fleet permanently wide.
///
/// This is the arm the mechanism's whole "temporary" claim rests on.
/// The stall never clears - the entry stays in the map, stale, for the
/// length of the test - and the loan still comes back, because the
/// deadline stamped when it was taken is absolute.
#[test]
fn a_stall_that_never_clears_still_gives_the_socket_back() {
    // An allowance of ONE, so the episode is exactly one socket and
    // the arithmetic below is about the deadline rather than about how
    // many more the fleet was still entitled to take.
    let (sh, targets) = fleet(20, 1, false);
    let base = targets[0].get();
    // A trained bound, so the derived hold is the arithmetic and not
    // the clamp: 400 ms trains to 1200 ms, x4 is 4800 ms, inside
    // [SURGE_HOLD_MIN, SURGE_HOLD_MAX].
    sh.art_ms.store(400, Ordering::Relaxed);
    let hold = bound(&sh) * SURGE_HOLD_BOUNDS;
    assert!(hold > SURGE_HOLD_MIN && hold < SURGE_HOLD_MAX);
    stale_entry(&sh, "<a0@x>", 0, Duration::from_secs(30));
    let mut now = tick_n(&sh, 0, 1);
    assert_eq!(targets[0].get(), base + 1, "the fixture never surged");
    // Tick right up to the deadline: the article is still there, still
    // stale, and the loan is still out - so this arm is measuring the
    // deadline rather than the stall clearing behind its back.
    while now + SURGE_TICK_MS < hold.as_millis() as u64 {
        now = tick_n(&sh, now, 1);
        assert_eq!(targets[0].get(), base + 1, "gave back early at {now} ms");
    }
    assert_eq!(sh.inflight.lock_ok().len(), 1, "the stall cleared itself");
    // And past it, back to base - with the article still stuck.
    now = tick_n(&sh, hold.as_millis() as u64, 1);
    assert_eq!(targets[0].get(), base, "the fleet stayed permanently wide");
    assert_eq!(sh.surge.out.load(Ordering::Relaxed), 0);
    // AND IT STAYS BACK. This is the half the deadline alone does not
    // buy and the half this test found: the stall is still on and
    // nothing is still idle, so without the cooldown the very next
    // decision re-takes the loan and the fleet is permanently wide with
    // a ledger churning an episode a second underneath it.
    let cool = bound(&sh) * SURGE_COOL_BOUNDS;
    // The window's END, captured before the walk: `now` moves inside
    // it, so a bound recomputed from the current stamp would never be
    // reached.
    let cool_ends = now + cool.as_millis() as u64;
    while now + SURGE_TICK_MS < cool_ends {
        now = tick_n(&sh, now, 1);
        assert_eq!(targets[0].get(), base, "re-took the loan at {now} ms");
    }
    // Past the cooldown a fresh episode may open - the stand-down is a
    // window, not a retirement - and it gets its OWN deadline, so a
    // second episode cannot inherit or extend the first one's.
    now = tick_n(&sh, cool_ends, 1);
    assert_eq!(targets[0].get(), base + 1, "a fresh episode never opened");
    let end = tick_n(&sh, now + hold.as_millis() as u64, 1);
    assert_eq!(targets[0].get(), base, "the fresh episode never closed");
    assert!(end > now, "the second episode never advanced the clock");
}

/// The fleet-wide allowance is a ceiling and the loan is small by
/// construction: §9b's first two sockets are the efficient point, so a
/// whole fleet of stuck reads still takes two.
#[test]
fn the_allowance_is_a_fleet_ceiling_and_a_stuck_fleet_cannot_pass_it() {
    let (sh, targets) = fleet(20, SURGE_MAX_DEFAULT, false);
    let base = targets[0].get();
    stale_entry(&sh, "<a0@x>", 0, bound(&sh) + Duration::from_millis(50));
    stale_entry(&sh, "<a1@x>", 1, bound(&sh) + Duration::from_millis(50));
    tick_n(&sh, 0, 20);
    let over = (targets[0].get() - base) + (targets[1].get() - base);
    assert_eq!(over, SURGE_MAX_DEFAULT, "the fleet allowance was passed");
    assert_eq!(sh.surge.out.load(Ordering::Relaxed), SURGE_MAX_DEFAULT);
    // A settings value past the measured efficient point is clamped at
    // the fold, so a hand-edited file cannot buy sockets §9b says are
    // worth nothing.
    let (wide, _) = fleet(64, 40, false);
    assert_eq!(wide.surge.max, SURGE_MAX_CLAMP);
}

/// OFF is off, and it is the default: nothing arms, nothing dials, and
/// the run's `[pool]` line is byte-identical to a run without the code.
#[test]
fn the_surge_is_off_by_default_and_off_means_nothing_moves() {
    assert_eq!(PoolConfig::default().surge_max, 0, "the default is not off");
    assert_eq!(
        PoolConfig::shipped().surge_max,
        0,
        "the shipped profile switched it on"
    );
    let (sh, targets) = fleet(20, 0, false);
    let base = targets[0].get();
    assert!(!sh.surge_armed(), "a read would arm its timer");
    stale_entry(&sh, "<a0@x>", 0, Duration::from_secs(30));
    tick_n(&sh, 0, 20);
    assert_eq!(targets[0].get(), base);
    assert_eq!(sh.surge_summary(), "", "the [pool] line grew a fragment");
}

/// Two stand-downs that are the run ending rather than the stall
/// clearing, and the books close either way.
#[test]
fn a_draining_run_returns_its_loan_and_takes_no_more() {
    let (sh, targets) = fleet(20, 2, false);
    let base = targets[0].get();
    stale_entry(&sh, "<a0@x>", 0, bound(&sh) + Duration::from_millis(50));
    let now = tick_n(&sh, 0, 1);
    assert_eq!(targets[0].get(), base + 1);
    sh.draining.store(true, Ordering::Release);
    tick_n(&sh, now, 2);
    assert_eq!(targets[0].get(), base, "a draining run kept its surge");
    assert_eq!(sh.surge.out.load(Ordering::Relaxed), 0);
}

/// The pool going away closes the books even when the target does not.
///
/// Under `live_tune` the `ConnTarget` lives on the daemon hub and
/// outlives the job (`streamhub::job_targets`), so a ledger left
/// non-zero here would follow the run out and make `surge_summary` lie
/// about how many episodes closed.
#[test]
fn dropping_the_pool_closes_the_surge_books() {
    let (sh, targets) = fleet(20, 2, false);
    let base = targets[0].get();
    stale_entry(&sh, "<a0@x>", 0, bound(&sh) + Duration::from_millis(50));
    tick_n(&sh, 0, 1);
    assert_eq!(targets[0].get(), base + 1);
    sh.surge_close_books();
    assert_eq!(sh.surge.out.load(Ordering::Relaxed), 0);
    assert_eq!(sh.surge.lent_on(0), 0);
    assert_eq!(sh.surge.episodes.load(Ordering::Relaxed), 1);
}

/// The pure arithmetic both writers to a `ConnTarget` share, including
/// the case that made it worth naming: a share already past the spawn
/// ceiling must clamp to the ceiling and never to `ceiling + lent`.
#[test]
fn the_loan_is_added_before_the_ceiling_is_applied() {
    use crate::pool::linecap::surge_want;
    assert_eq!(surge_want(5, 0, 8), 5, "no loan, no change");
    assert_eq!(surge_want(5, 2, 8), 7);
    assert_eq!(surge_want(7, 2, 8), 8, "clamped at the spawn ceiling");
    // The wrong order - `min(base, ceiling) + lent` - answers 10 here,
    // and a target above the spawned fleet wakes nothing, so that would
    // be a number the shed arms then read as real.
    assert_eq!(surge_want(10, 2, 8), 8);
}
