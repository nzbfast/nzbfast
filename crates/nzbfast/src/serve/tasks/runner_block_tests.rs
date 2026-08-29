//! §96.5 when TWO CONFIG ROWS SHARE ONE HOSTNAME: what
//! [`super::reset_hub_for_job`] publishes for the pool build, and what
//! [`super::settle_job_tail`] bills at the end of the run.
//!
//! A child module of `runner.rs` rather than a sibling of it, so both
//! functions stay `pub(super)` - the alternative was widening two items
//! for a test - and so the private `DetachedTail::usage_flushed` stays
//! readable from here.
//!
//! TWO ROWS ON ONE HOST IS A SUPPORTED SHAPE, not a misconfiguration: a
//! prepaid block account beside the main account on the same backbone,
//! which the config never dedupes. `daemon_usage.rs`'s crossing latch
//! says so in its own words and
//! `block_threshold_tests::duplicate_host_entries_edge_trigger_independently`
//! pins it. Every case below is a defect that was live until 28 Aug
//! 2026 because the pool-build rules were decided per ROW while every
//! reader of them is keyed by HOST.
//!
//! Nothing here touches a socket or a config FILE: `reset_hub_for_job`
//! takes the server list as a snapshot (Codex sweep H - the read it used
//! to do inline was on the runner and could hang the queue), so a test
//! hands it one directly.

use super::*;

fn tmp(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-rbt-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// The server list as `reset_hub_for_job` receives it - a parsed
/// snapshot, exactly what `ServerProbe::config` hands the pick.
fn snapshot(servers: &str) -> Option<Arc<nzbkit::config::Config>> {
    let cfg: nzbkit::config::Config =
        serde_json::from_str(&format!(r#"{{"servers":{servers}}}"#)).expect("parse config");
    Some(Arc::new(cfg))
}

/// Run the real hand-over and read back the two slots the pool build
/// consumes: `get::plan` drops servers whose host is in the first, and
/// `get::fleet` seeds each server's mid-run byte budget from the second.
fn published(
    d: &Arc<Daemon>,
    servers: &str,
) -> (Vec<String>, std::collections::HashMap<String, u64>) {
    reset_hub_for_job(d, snapshot(servers), "nzo_rbt", String::new());
    (
        d.hub.excluded_hosts.lock_ok().clone(),
        d.hub.host_byte_budgets.lock_ok().clone(),
    )
}

/// The control, and the reason this change is safe to land: an install
/// whose hosts are all distinct gets byte-for-byte what it always got.
#[test]
fn distinct_hosts_are_scored_exactly_as_before() {
    let dir = tmp("distinct");
    let d = crate::serve::testutil::test_daemon(&dir);
    d.add_usage(&[("spent.example".into(), 1_200)]);
    let (excluded, budgets) = published(
        &d,
        r#"[{"host":"spent.example","block_bytes":1000},
            {"host":"live.example","block_bytes":1000},
            {"host":"flat.example"}]"#,
    );
    assert_eq!(excluded, vec!["spent.example".to_string()]);
    assert_eq!(budgets.get("live.example"), Some(&1000));
    assert_eq!(
        budgets.get("flat.example"),
        None,
        "a server with no block has nothing to count down"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// One exhausted row must not take its funded sibling out of the pool.
///
/// The old loop pushed `s.host` onto the exclusion list the moment ANY
/// row on it was spent, and `get::plan` drops by HOST - so a user whose
/// only provider carried a spent block account beside a funded one got
/// "no usable servers" while the Settings list still showed the funded
/// account healthy with bytes left.
#[test]
fn an_exhausted_row_does_not_exclude_its_funded_sibling() {
    let dir = tmp("funded");
    let d = crate::serve::testutil::test_daemon(&dir);
    // Spend is HOST-aggregated by design, so both rows read 1,200: the
    // 1,000 block is spent, the 5,000 one has 3,800 left.
    d.add_usage(&[("blk.example".into(), 1_200)]);
    let (excluded, budgets) = published(
        &d,
        r#"[{"host":"blk.example","block_bytes":1000},
            {"host":"blk.example","block_bytes":5000}]"#,
    );
    assert!(
        excluded.is_empty(),
        "the host still has an account with allowance: {excluded:?}"
    );
    assert_eq!(
        budgets.get("blk.example"),
        Some(&3_800),
        "and it is handed what that account has left"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An unlimited account sharing the hostname must not be dropped, and
/// must not be capped either.
///
/// Both halves were live. The exclusion took the flat-rate row out of
/// the pool with its spent sibling, and `budgets.insert` put a cap under
/// the host that `get::fleet` then copied onto EVERY row on it - so the
/// pool would release an unlimited account at a limit the user never
/// configured.
#[test]
fn a_flat_rate_sibling_is_never_excluded_and_never_capped() {
    let dir = tmp("flatsib");
    let d = crate::serve::testutil::test_daemon(&dir);
    d.add_usage(&[("mix.example".into(), 1_200)]);
    let (excluded, budgets) = published(
        &d,
        r#"[{"host":"mix.example","block_bytes":1000},
            {"host":"mix.example"}]"#,
    );
    assert!(
        excluded.is_empty(),
        "an unlimited account on the host keeps it in the pool: {excluded:?}"
    );
    assert_eq!(
        budgets.get("mix.example"),
        None,
        "and nothing may cap an account the user set no limit on"
    );

    // The same with the block row still FUNDED: the cap is what is
    // being refused here, not the exclusion.
    let (excluded, budgets) = published(
        &d,
        r#"[{"host":"mix2.example"},
            {"host":"mix2.example","block_bytes":9000}]"#,
    );
    assert!(excluded.is_empty());
    assert_eq!(budgets.get("mix2.example"), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The answer may not depend on which order the user's rows happen to
/// be listed in.
///
/// `budgets.insert` was last-write-wins, so with two funded rows on one
/// host the config's ORDER picked the cap: 1,500 one way and 4,500 the
/// other, for the same two accounts. The maximum remaining is the only
/// order-independent answer, and it is also the right one - spend is
/// host-aggregated, so the host can keep serving while any account on it
/// still has allowance.
#[test]
fn the_budget_is_order_independent_and_takes_the_largest_remaining() {
    let dir = tmp("order");
    let d = crate::serve::testutil::test_daemon(&dir);
    d.add_usage(&[("two.example".into(), 500)]);
    let forwards = published(
        &d,
        r#"[{"host":"two.example","block_bytes":2000},
            {"host":"two.example","block_bytes":5000}]"#,
    );
    let backwards = published(
        &d,
        r#"[{"host":"two.example","block_bytes":5000},
            {"host":"two.example","block_bytes":2000}]"#,
    );
    assert_eq!(forwards, backwards, "the config's order decides nothing");
    assert_eq!(forwards.1.get("two.example"), Some(&4_500));
    assert!(forwards.0.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The exclusion still fires when there is genuinely nothing left on the
/// host - and names it ONCE, where the old per-row loop pushed it as
/// many times as the host had spent rows.
#[test]
fn a_host_whose_every_account_is_spent_is_still_excluded() {
    let dir = tmp("allspent");
    let d = crate::serve::testutil::test_daemon(&dir);
    d.add_usage(&[("done.example".into(), 2_000)]);
    let (excluded, budgets) = published(
        &d,
        r#"[{"host":"done.example","block_bytes":1000},
            {"host":"done.example","block_bytes":2000}]"#,
    );
    assert_eq!(excluded, vec!["done.example".to_string()]);
    assert!(
        budgets.is_empty(),
        "an excluded host has no budget to hand out: {budgets:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A switched-off row decides nothing at all.
///
/// This is the per-entry block latch's defect one door over, and it was
/// fixed there and left live here: the snapshot is not filtered on
/// `enabled` while `get::plan` drops disabled servers BEFORE it applies
/// the exclusion, so a switched-off exhausted block row deleted its
/// ENABLED sibling from the pool.
#[test]
fn a_disabled_exhausted_row_does_not_exclude_its_enabled_sibling() {
    let dir = tmp("disabled");
    let d = crate::serve::testutil::test_daemon(&dir);
    d.add_usage(&[("off.example".into(), 1_200)]);
    let (excluded, budgets) = published(
        &d,
        r#"[{"host":"off.example","block_bytes":1000,"enabled":false},
            {"host":"off.example","block_bytes":5000}]"#,
    );
    assert!(
        excluded.is_empty(),
        "a server the user switched off cannot rule one out: {excluded:?}"
    );
    assert_eq!(budgets.get("off.example"), Some(&3_800));

    // ...and the same against a flat-rate sibling, which has no budget
    // of its own to fall back on.
    let (excluded, budgets) = published(
        &d,
        r#"[{"host":"off2.example","block_bytes":1,"enabled":false},
            {"host":"off2.example"}]"#,
    );
    assert!(excluded.is_empty());
    assert_eq!(budgets.get("off2.example"), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The settle-side half of the usage fold, which MUST move with
/// `Daemon::flush_run_usage`'s (see `Daemon::fold_bytes_by_host`).
///
/// `DetachedTail::usage_flushed` is keyed by HOST and holds the SUM of
/// every pool row on that host, while `pool_live.servers` is one row per
/// configured ACCOUNT. Comparing an unfolded row counter against that
/// sum under-bills exactly the way the flush did; folding here and not
/// there would bill the run twice. Both are asserted in one run below:
/// the detach bills the pair's first 300 bytes, and the settle bills the
/// 100 the pool moved after it and not a byte more.
#[test]
fn settle_bills_the_residual_of_two_rows_on_one_host_once() {
    let dir = tmp("settle");
    let d = crate::serve::testutil::test_daemon(&dir);
    let row = || -> nzbkit::config::ServerConfig {
        serde_json::from_str(r#"{"host":"blk.example","port":119}"#).expect("server config")
    };
    let live = nzbkit::pool::LiveStats::for_servers(&[
        (row(), nzbkit::pool::PoolConfig::default()),
        (row(), nzbkit::pool::PoolConfig::default()),
    ]);
    live.servers[0].bytes.store(100, Ordering::Relaxed);
    live.servers[1].bytes.store(200, Ordering::Relaxed);
    *d.hub.pool_live.lock_ok() = Some(live.clone());

    let detached = detach_job_tail(&d, "nzo_rbt");
    assert_eq!(
        d.usage_lifetime("blk.example"),
        300,
        "the detach bills both rows"
    );
    assert_eq!(
        detached.usage_flushed.get("blk.example"),
        Some(&300),
        "and the high-water mark is the host's TOTAL, not one row's"
    );

    // The drain moves another 100 across the pair.
    live.servers[0].bytes.store(150, Ordering::Relaxed);
    live.servers[1].bytes.store(250, Ordering::Relaxed);
    let progress = AtomicU64::new(0);
    let mut ledger: Option<QuotaLedger> = None;
    settle_job_tail(&d, "nzo_rbt", &mut ledger, &progress, Some(detached));
    assert_eq!(
        d.usage_lifetime("blk.example"),
        400,
        "the residual is the HOST's, so none of the drain's paid bytes is lost"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
