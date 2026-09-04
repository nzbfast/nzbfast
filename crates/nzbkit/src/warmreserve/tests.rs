//! TODO 313 item 8 - the standing warm reserve.
//!
//! The acceptance set the item asks for, in the order it asks for it:
//! the floor is MAINTAINED (not merely permitted), the reserve holds
//! permits, an account at its cap gets an effective reserve of zero,
//! active work outranks a parked spare for the same permit,
//! `block_account` servers get none, and the default of zero changes
//! nothing at all. Plus the invariant under a fleet that GROWS mid-run,
//! which is the case that shrinks the reserve, and the diagnostics that
//! keep a quietly-different-from-configured number from costing somebody
//! an evening.

use super::*;
use crate::mock::{Chaos, MockServer};
use crate::pool::handoff::LeaseClass;
use crate::warmpool::{DEFAULT_MAX_IDLE, MAX_PER_SERVER};

async fn provider() -> MockServer {
    MockServer::start(Default::default(), Chaos::default()).await
}

/// A server pointed at `mock`, with pooling on (which the reserve
/// requires - see [`ReserveNote::PoolOffForServer`]) and `reserve` spare
/// lanes asked for.
fn cfg(mock: &MockServer, connections: u32, reserve: u32) -> ServerConfig {
    ServerConfig {
        connections,
        warm_pool: true,
        warm_reserve: Some(reserve),
        ..mock.server_config()
    }
}

fn pool() -> Arc<WarmPool> {
    WarmPool::new(DEFAULT_MAX_IDLE, MAX_PER_SERVER)
}

/// The headline: the dialler MAINTAINS the floor. Nothing has
/// downloaded, no job has parked anything, and the sessions are there
/// anyway - which is the one word that separates this from
/// `WarmPool::per_server`, a ceiling on what may be parked.
#[tokio::test(flavor = "multi_thread")]
async fn the_dialler_maintains_the_floor() {
    let mock = provider().await;
    let sc = cfg(&mock, 8, 2);
    let warm = pool();
    let budget = ConnBudget::new();
    let reserve = WarmReserve::new(warm.clone(), budget.clone());
    reserve.set_servers(std::slice::from_ref(&sc));

    reserve.tick().await;

    assert_eq!(
        warm.parked_for(&sc).await,
        2,
        "the reserve dials its floor rather than waiting for a job to park one"
    );
    assert_eq!(reserve.counts(), (2, 0));
    // And they are sessions, not bookkeeping: a floor that cannot be
    // checked out has kept nothing.
    let mut got = warm.take(&sc).await.expect("a parked session");
    got.date().await.expect("a reserve session speaks NNTP");

    // A second turn does not dial on top of a pool that is already full.
    // The floor is measured against the POOL, not against a private set,
    // which is what stops the reserve stacking sessions a finished job
    // already parked.
    warm.give(&sc, got).await;
    reserve.tick().await;
    assert_eq!(warm.parked_for(&sc).await, 2, "still the floor, not four");
    assert_eq!(
        reserve.counts(),
        (2, 0),
        "the second turn dialled nothing at all"
    );
}

/// The correctness constraint, and it is not memory. A proactive dialler
/// that does not hold `HostLease` permits makes `handoff`'s invariant
/// false silently, and the failure mode is `warmpool`'s own header: the
/// 25-26 Aug 2026 incident, "502 connection limit (40) reached", for
/// hours, across a restart.
#[tokio::test(flavor = "multi_thread")]
async fn the_reserve_holds_permits_on_the_account() {
    let mock = provider().await;
    let sc = cfg(&mock, 8, 3);
    let warm = pool();
    let budget = ConnBudget::new();
    let reserve = WarmReserve::new(warm.clone(), budget.clone());
    reserve.set_servers(std::slice::from_ref(&sc));

    reserve.tick().await;

    let lease = budget
        .lease_borrowed(&ConnBudget::key(&sc))
        .expect("the reserve states a cap for an account no job has reached");
    assert_eq!(lease.spares(), 3, "three sockets, three slots");
    let (held, cap) = lease.snapshot();
    assert_eq!(held, 0, "no worker is holding anything yet");
    assert!(
        held + lease.spares() <= cap,
        "active + spares must never exceed the account's cap"
    );
}

/// "The configured count is a REQUEST bounded by the available gap, not
/// a guarantee. On a server whose fleet already runs at max the gap is
/// zero and the effective reserve there is zero, which is correct."
#[tokio::test(flavor = "multi_thread")]
async fn an_account_at_its_cap_gets_an_effective_reserve_of_zero() {
    let mock = provider().await;
    let sc = cfg(&mock, 2, 2);
    let warm = pool();
    let budget = ConnBudget::new();
    // A job got here first and took the whole account: cap 2, one
    // download permit and one post-processing one, nothing left over.
    let lease = budget.lease(&ConnBudget::key(&sc), 2);
    let _a = lease.acquire_as(LeaseClass::Download).await;
    let _b = lease.acquire_as(LeaseClass::PostProcess).await;
    assert_eq!(lease.snapshot(), (2, 2));

    let reserve = WarmReserve::new(warm.clone(), budget.clone());
    reserve.set_servers(std::slice::from_ref(&sc));
    reserve.tick().await;

    assert_eq!(lease.spares(), 0);
    assert_eq!(
        warm.parked_for(&sc).await,
        0,
        "an account with no gap must not be dialled into"
    );
    assert_eq!(reserve.counts(), (0, 0));
}

/// The second sizing invariant: "active work outranks a parked spare for the
/// same permit. If the cap logic ever raises the active fleet into the
/// gap, the RESERVE SHRINKS to make room. The fleet is never denied a
/// permit a spare is sitting on."
///
/// Asserted as a NON-BLOCK: every acquire below completes, and it
/// completes because the spare gave way rather than because the account
/// had room to spare. The `timeout` is what makes that an assertion -
/// without it a reserve that wrongly held its slots would hang the test
/// rather than fail it.
#[tokio::test(flavor = "multi_thread")]
async fn active_work_outranks_a_parked_spare_for_the_same_permit() {
    let budget = ConnBudget::new();
    let lease = budget.lease("acct", 4);
    assert_eq!(lease.set_spares(4), 4, "an idle account can spare all four");

    let mut held = Vec::new();
    // `download_cap` is 3 of the 4 (one is the post-processing reserve),
    // so three download workers, then the side-fetch takes the fourth.
    for i in 0..3 {
        let p = tokio::time::timeout(Duration::from_secs(5), lease.acquire())
            .await
            .unwrap_or_else(|_| panic!("worker {i} blocked behind a parked spare"));
        held.push(p);
        assert!(
            lease.snapshot().0 + lease.spares() <= 4,
            "active + spares over the cap after worker {i}"
        );
    }
    assert_eq!(
        lease.spares(),
        1,
        "the fleet took three, the spare kept one"
    );
    let _side = tokio::time::timeout(
        Duration::from_secs(5),
        lease.acquire_as(LeaseClass::PostProcess),
    )
    .await
    .expect("the post-processing reserve blocked behind a parked spare");
    assert_eq!(lease.spares(), 0, "the last spare gave way to real work");
    assert_eq!(lease.snapshot(), (4, 4));

    // And it comes back when the work does not need it any more, which
    // is what makes this a reserve rather than a one-shot.
    held.clear();
    assert_eq!(
        lease.set_spares(4),
        3,
        "the three download workers retired, so their slots come back to          the reserve; the side-fetch still holds the fourth"
    );
}

/// "`0` on any `block_account` server" - a warm spare on a metered
/// account is paid-for headroom doing nothing, and the reserve asks the
/// same question every other speculative picker on the tree asks.
#[tokio::test(flavor = "multi_thread")]
async fn a_block_account_server_is_never_held_warm() {
    let mock = provider().await;
    let sc = ServerConfig {
        block_account: true,
        ..cfg(&mock, 8, 4)
    };
    assert_eq!(request_for(&sc), (0, ReserveNote::Metered));

    let warm = pool();
    let budget = ConnBudget::new();
    let reserve = WarmReserve::new(warm.clone(), budget.clone());
    reserve.set_servers(std::slice::from_ref(&sc));
    reserve.tick().await;

    assert_eq!(reserve.counts(), (0, 0));
    assert_eq!(warm.parked_for(&sc).await, 0);
    let st = reserve.status_for(&sc).expect("reported, not omitted");
    assert_eq!(st.effective, 0);
    assert_eq!(st.note, ReserveNote::Metered);
}

/// The default is zero and zero changes NOTHING: no dial, no permit, and
/// not even a lease minted for an account no job has touched.
#[tokio::test(flavor = "multi_thread")]
async fn the_default_of_zero_changes_nothing_at_all() {
    let mock = provider().await;
    let plain = mock.server_config();
    assert_eq!(plain.warm_reserve, None, "off unless asked for");
    assert_eq!(request_for(&plain), (0, ReserveNote::Off));

    let warm = pool();
    let budget = ConnBudget::new();
    let reserve = WarmReserve::new(warm.clone(), budget.clone());
    reserve.set_servers(std::slice::from_ref(&plain));
    reserve.tick().await;

    assert_eq!(reserve.counts(), (0, 0));
    assert_eq!(warm.parked_for(&plain).await, 0);
    assert_eq!(mock.accepted.load(Ordering::Relaxed), 0, "nothing dialled");
    assert!(
        budget.lease_borrowed(&ConnBudget::key(&plain)).is_none(),
        "with the feature off the reserve must leave the daemon's \
         connection accounting exactly where it found it"
    );
    assert_eq!(budget.held_total(), 0);
}

/// The invariant under a fleet that GROWS MID-RUN, which is the case the
/// item names: the line-cap governor raising the target is what shrinks
/// the reserve.
///
/// Both halves are asserted at every step - the sum never exceeds the
/// cap, and no worker is ever refused - because a reserve that satisfied
/// only the first by blocking the fleet would be the priority inversion
/// this rule exists to prevent.
#[tokio::test(flavor = "multi_thread")]
async fn the_reserve_shrinks_as_a_growing_fleet_takes_the_gap() {
    const CAP: usize = 8;
    let budget = ConnBudget::new();
    let lease = budget.lease("acct", CAP);
    assert_eq!(lease.set_spares(3), 3);

    let mut fleet = Vec::new();
    // `download_cap` is CAP - 1: the post-processing reserve is not a
    // download's to take, and neither is it a spare's to block.
    for i in 1..=CAP - 1 {
        let p = tokio::time::timeout(Duration::from_secs(5), lease.acquire())
            .await
            .unwrap_or_else(|_| panic!("the fleet's {i}th worker was refused"));
        fleet.push(p);
        let (held, cap) = lease.snapshot();
        assert_eq!(held, i);
        assert!(
            held + lease.spares() <= cap,
            "step {i}: active {held} + spares {} over the cap {cap}",
            lease.spares()
        );
    }
    assert_eq!(
        lease.spares(),
        1,
        "seven of eight are working, so one slot is all that is left to spare"
    );

    // And a cap turned DOWN between jobs takes the rest of it: a held
    // permit is never revoked, but a standing spare is exactly the
    // holder that is doing no work.
    lease.set_cap(4);
    assert_eq!(lease.spares(), 0);
    assert!(lease.snapshot().0 + lease.spares() <= lease.snapshot().0.max(4));
}

/// "It must be visible in diagnostics rather than silently absent" - the
/// precedent being `nzbfast-redeploy-resets-server-enables`, where a
/// setting quietly different from what the user configured cost somebody
/// an evening.
#[tokio::test(flavor = "multi_thread")]
async fn a_reserve_smaller_than_the_one_configured_says_so() {
    let mock = provider().await;
    let sc = cfg(&mock, 6, 4);
    let warm = pool();
    let budget = ConnBudget::new();
    // A job is running and holding five of the six.
    let lease = budget.lease(&ConnBudget::key(&sc), 6);
    let mut fleet = Vec::new();
    for _ in 0..5 {
        fleet.push(lease.acquire().await);
    }

    let reserve = WarmReserve::new(warm.clone(), budget.clone());
    reserve.set_servers(std::slice::from_ref(&sc));
    reserve.tick().await;

    let st = reserve.status_for(&sc).expect("every server is reported");
    assert_eq!(st.configured, 4, "what the user asked for, unchanged");
    assert_eq!(st.effective, 1, "what the account can actually spare");
    assert!(st.shortfall(), "and it is flagged as a shortfall");
    assert_eq!(st.note, ReserveNote::AccountAtCap);
    assert!(
        !st.note.as_str().is_empty(),
        "the shortfall carries a sentence a user can act on"
    );
}

/// A server that has not opted into pooling gets no reserve, because its
/// fleet never checks a parked session out (`get::fleet` hands it no
/// pool) - so a reserve there is sessions on the account that nobody may
/// take. Reported rather than silently skipped, for the same reason as
/// every other shortfall here.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_with_pooling_off_gets_no_reserve() {
    let mock = provider().await;
    let sc = ServerConfig {
        warm_pool: false,
        ..cfg(&mock, 8, 2)
    };
    assert_eq!(request_for(&sc), (0, ReserveNote::PoolOffForServer));

    let warm = pool();
    let reserve = WarmReserve::new(warm.clone(), ConnBudget::new());
    reserve.set_servers(std::slice::from_ref(&sc));
    reserve.tick().await;

    assert_eq!(reserve.counts(), (0, 0));
    assert_eq!(
        reserve.status_for(&sc).map(|s| s.note),
        Some(ReserveNote::PoolOffForServer)
    );
}

/// The reserve stands DOWN with the idle release rather than fighting
/// it. `release_if_idle` hands the account back when no job has touched
/// the pool for that server's timeout; a dialler that refilled the floor
/// on the next turn would make that release mean nothing, and the two
/// would trade sockets for as long as the daemon ran.
///
/// This is also the sharpest statement of what this floor is NOT: the
/// release's own `keep` floor survives here untouched, because it is a
/// floor on what a release KEEPS and not a level anybody maintains.
#[tokio::test(flavor = "multi_thread")]
async fn the_reserve_stands_down_while_the_pool_is_released() {
    let mock = provider().await;
    let sc = cfg(&mock, 8, 2);
    let warm = pool();
    let budget = ConnBudget::new();
    let reserve = WarmReserve::new(warm.clone(), budget.clone());
    reserve.set_servers(std::slice::from_ref(&sc));
    reserve.tick().await;
    assert_eq!(warm.parked_for(&sc).await, 2);
    let dialled = reserve.counts().0;

    // Past this server's release timeout with nothing downloading.
    let after = sc.idle_release_policy().after.expect("a derived timeout");
    warm.set_release_policies(std::slice::from_ref(&sc));
    warm.rewind_activity(after + Duration::from_secs(1));

    reserve.tick().await;
    let st = reserve.status_for(&sc).expect("reported");
    assert_eq!(st.effective, 0);
    assert_eq!(st.note, ReserveNote::Released);
    assert_eq!(
        budget
            .lease_borrowed(&ConnBudget::key(&sc))
            .expect("the lease outlives the stand-down")
            .spares(),
        0,
        "the slots go back to the account with the sockets"
    );
    assert_eq!(
        reserve.counts().0,
        dialled,
        "and nothing was redialled to replace what the release let go"
    );
}

/// A closed pool (the daemon going offline) is not a shortfall to be
/// dialled through. `set_accepting(false)` is how "give the account
/// back" is said, and a reserve that kept dialling would be the one
/// thing on the tree still holding it.
#[tokio::test(flavor = "multi_thread")]
async fn an_offline_daemon_holds_no_reserve() {
    let mock = provider().await;
    let sc = cfg(&mock, 8, 2);
    let warm = pool();
    let budget = ConnBudget::new();
    warm.set_accepting(false);
    let reserve = WarmReserve::new(warm.clone(), budget.clone());
    reserve.set_servers(std::slice::from_ref(&sc));
    reserve.tick().await;

    assert_eq!(reserve.counts(), (0, 0));
    assert_eq!(mock.accepted.load(Ordering::Relaxed), 0);
    assert_eq!(
        reserve.status_for(&sc).map(|s| s.note),
        Some(ReserveNote::PoolClosed)
    );
}

/// A server that leaves the config gives its slots back on the next
/// turn, not when the daemon restarts. The lease is per ACCOUNT and
/// lives for the daemon's life, so a count left behind would pin those
/// connections with nothing able to release them.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_removed_from_the_config_gives_its_slots_back() {
    let mock = provider().await;
    let sc = cfg(&mock, 8, 2);
    let warm = pool();
    let budget = ConnBudget::new();
    let reserve = WarmReserve::new(warm.clone(), budget.clone());
    reserve.set_servers(std::slice::from_ref(&sc));
    reserve.tick().await;
    let lease = budget
        .lease_borrowed(&ConnBudget::key(&sc))
        .expect("a lease");
    assert_eq!(lease.spares(), 2);

    reserve.set_servers(&[]);
    reserve.tick().await;
    assert_eq!(lease.spares(), 0);
    assert!(reserve.status().is_empty());

    // And dropping the reserve outright is the same promise, since the
    // lease outlives it.
    reserve.set_servers(std::slice::from_ref(&sc));
    reserve.tick().await;
    assert_eq!(lease.spares(), 2);
    drop(reserve);
    assert_eq!(lease.spares(), 0);
}

/// The ask is clamped to the account's own connection count: a reserve
/// wider than the whole account is not a number anybody can mean, and
/// clamping it here rather than at the lease keeps the CONFIGURED figure
/// in the report a number the user could actually have had.
#[test]
fn the_ask_is_clamped_to_the_accounts_own_width() {
    let base = ServerConfig {
        warm_pool: true,
        connections: 4,
        warm_reserve: Some(99),
        ..bare()
    };
    assert_eq!(request_for(&base), (4, ReserveNote::Held));
    assert_eq!(
        request_for(&ServerConfig {
            warm_reserve: Some(2),
            ..base.clone()
        }),
        (2, ReserveNote::Held)
    );
    assert_eq!(
        request_for(&ServerConfig {
            enabled: false,
            ..base.clone()
        }),
        (0, ReserveNote::Disabled)
    );
    assert_eq!(
        request_for(&ServerConfig {
            warm_reserve: Some(0),
            ..base
        }),
        (0, ReserveNote::Off)
    );
}

fn bare() -> ServerConfig {
    ServerConfig {
        host: "127.0.0.1".into(),
        port: 119,
        tls: false,
        username: None,
        password: None,
        connections: 8,
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
    }
}
