//! The prepaid-block READOUT arithmetic, and the 85%/100% crossings that
//! ride the usage flush.
//!
//! Stage 2 of research/BLOCK-ACCOUNT-ECONOMICS-2026-08-27.md. Stage 1's
//! `sabcompat/block_warning_tests.rs` pins the exhaustion CONDITION - a
//! state, in the warnings pane, true for as long as it is true. These
//! pin the MOMENTS beside it: a crossing fires once, does not repeat
//! itself every 30 s, and re-arms when the user tops the account up.
//!
//! Every figure here comes from our own accounting and nothing else.
//! There is no provider-reported input to assert against and the design
//! rules one out: a figure a provider stops emitting would make a silent
//! account look like a full block.

use super::*;

/// Write a server list at the daemon's OWN config path, which is what
/// `block_threshold_tick` reads.
///
/// A test that leaves that path alone is testing the BOX: `Config::load`
/// answers a missing file by going and finding a SABnzbd install's ini
/// under `$HOME`, which this fleet has from the competitive benchmarking
/// and a CI runner does not. `test_daemon` seeds a flat-rate list there,
/// which has no block in it at all, so a block test must write its own.
fn write_cfg(d: &Arc<Daemon>, servers: &str) {
    std::fs::write(&d.cfg_path, format!(r#"{{"servers":{servers}}}"#)).expect("write config");
}

/// The ledger key a row spelled `{"host": h}` bills to.
///
/// The §96.5 block meter is per ACCOUNT rather than per host (see
/// `ServerConfig::account_key`), so a test that bills by hand has to
/// bill the same key `block_threshold_tick` reads back - a bare
/// hostname is a real key, just not that row's, and asserting against
/// it would pass on a ledger nothing in production writes.
fn acct(host: &str) -> String {
    let s: nzbkit::config::ServerConfig =
        serde_json::from_str(&format!(r#"{{"host":"{host}"}}"#)).expect("server config");
    s.account_key()
}

fn kinds(d: &Arc<Daemon>) -> Vec<String> {
    d.life_events
        .lock_ok()
        .iter()
        .filter_map(|e| e["kind"].as_str().map(str::to_string))
        .filter(|k| k.starts_with("server.block"))
        .collect()
}

pub fn tmp(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// The readout itself: what is left, what percentage that is, and which
/// band the account is in at each edge of the two thresholds.
///
/// The zero-block row is the one that matters most and is easiest to get
/// wrong. `block_bytes: 0` is how every layer here spells "no block
/// configured", so a naive `spent >= total` calls every flat-rate server
/// on the install exhausted - which is the shape the API payload would
/// have carried into the dashboard's colouring.
#[test]
fn a_block_standing_reads_left_and_the_band_off_our_own_ledger() {
    let dir = tmp("blockstand");
    let d = crate::testutil::test_daemon(&dir);
    let cfg: nzbkit::config::Config = serde_json::from_str(
        r#"{"servers":[{"host":"flat.example"},
                       {"host":"blk.example","block_bytes":1000},
                       {"host":"off.example","block_bytes":1000,"enabled":false}]}"#,
    )
    .expect("parse config");

    // Nothing spent yet.
    let st = d.block_standings(&cfg);
    assert_eq!(
        st.iter().map(|b| b.host.as_str()).collect::<Vec<_>>(),
        vec!["blk.example", "off.example"],
        "a server with no block has no standing to report"
    );
    assert_eq!((st[0].spent, st[0].left, st[0].band()), (0, 1000, 0));
    assert!(
        st[1].total == 1000 && !st[1].enabled,
        "reported, not filtered"
    );

    // Just under the low mark, then exactly on it.
    d.add_usage(&[(acct("blk.example"), 849)]);
    assert_eq!(
        d.block_standings(&cfg)[0].band(),
        0,
        "849 of 1000 is not low"
    );
    d.add_usage(&[(acct("blk.example"), 1)]);
    let b = d.block_standings(&cfg)[0].clone();
    assert_eq!(
        (b.spent, b.left, b.band()),
        (850, 150, 1),
        "85% is the mark"
    );
    assert!((b.pct() - 85.0).abs() < 1e-9, "{}", b.pct());

    // Overspent: left saturates to zero rather than wrapping, and the
    // percentage caps at 100 rather than reading 120% of a block.
    d.add_usage(&[(acct("blk.example"), 350)]);
    let b = d.block_standings(&cfg)[0].clone();
    assert_eq!((b.spent, b.left, b.band()), (1200, 0, 2));
    assert!((b.pct() - 100.0).abs() < 1e-9, "{}", b.pct());

    // A refill rewinds the standing, because it reads `block_spent` and
    // not the never-pruned lifetime bucket.
    d.block_refilled(&acct("blk.example"));
    assert_eq!(d.block_standings(&cfg)[0].band(), 0, "a refill re-arms it");

    // The PER-SERVER door, which is what the servers payload calls for
    // every row including the ones with no block at all. A flat-rate
    // server has spent bytes and a total of zero, and it must read "ok":
    // a naive `spent >= total` makes it "spent", which is the colour and
    // the word the Settings list would then put on every unlimited
    // account on the install. Nothing else on this tree reaches band()
    // with a zero total, so this assertion is the only thing holding
    // that guard up.
    d.add_usage(&[(acct("flat.example"), 9_000_000_000)]);
    let flat = d.block_standing(&cfg.servers[0]);
    assert_eq!(
        (flat.total, flat.left, flat.band_word()),
        (0, 0, "ok"),
        "an unlimited plan has nothing to run out of"
    );
    let blk = d.block_standing(&cfg.servers[1]);
    assert_eq!(blk.band_word(), "ok", "and the words track the bands");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The crossing is a MOMENT: it fires once, does not repeat on the next
/// tick, escalates to `server.block_spent` when the block runs out, and
/// comes back after a refill.
///
/// The first tick seeding SILENTLY is the half worth reading twice. A
/// daemon that starts up against an already-spent block has not watched
/// it cross anything, and re-announcing a state as a moment on every
/// restart is what would make a webhook subscriber stop trusting the
/// kind. The state at exhaustion is `sab_warnings`' job, and stage 1
/// pins it there.
#[test]
fn a_block_crossing_fires_once_and_re_arms_on_a_refill() {
    let dir = tmp("blockcross");
    let d = crate::testutil::test_daemon(&dir);
    write_cfg(&d, r#"[{"host":"blk.example","block_bytes":1000}]"#);

    // Already past the low mark before the daemon ever looked: seeded,
    // silently.
    d.add_usage(&[(acct("blk.example"), 900)]);
    d.block_threshold_tick();
    assert!(
        kinds(&d).is_empty(),
        "the first tick seeds, it does not fire"
    );

    // Still low, still nothing: a state does not re-announce itself.
    d.add_usage(&[(acct("blk.example"), 50)]);
    d.block_threshold_tick();
    assert!(
        kinds(&d).is_empty(),
        "no crossing, no event: {:?}",
        kinds(&d)
    );

    // Over the top.
    d.add_usage(&[(acct("blk.example"), 60)]);
    d.block_threshold_tick();
    assert_eq!(kinds(&d), vec!["server.block_spent"], "the 100% crossing");
    d.block_threshold_tick();
    assert_eq!(kinds(&d).len(), 1, "and only once");

    // What a subscriber acts on rides in the payload, not only in the
    // sentence: the account, and our own three figures.
    {
        let ring = d.life_events.lock_ok();
        let e = ring
            .iter()
            .find(|e| e["kind"] == "server.block_spent")
            .expect("the event is on the ring");
        assert_eq!(e["host"], json!("blk.example"), "{e}");
        assert_eq!(e["block_bytes"], json!(1000u64), "{e}");
        assert_eq!(e["spent_bytes"], json!(1010u64), "{e}");
        assert_eq!(e["left_bytes"], json!(0u64), "{e}");
        assert!(
            e["message"]
                .as_str()
                .unwrap_or_default()
                .contains("Block refilled"),
            "the remedy is named, the same one the warnings pane names: {e}"
        );
    }

    // Topped up: the band drops, so the NEXT crossing is a crossing
    // again - the low mark first this time, in order.
    d.block_refilled(&acct("blk.example"));
    d.block_threshold_tick();
    d.add_usage(&[(acct("blk.example"), 900)]);
    d.block_threshold_tick();
    assert_eq!(
        kinds(&d),
        vec!["server.block_spent", "server.block_low"],
        "a refill re-arms both marks"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Two shapes that must never fire, and both are shapes a real config
/// reaches - the same pair stage 1's warning is pinned against.
///
/// A DISABLED server is downloading nothing whatever its ledger says.
/// `block_bytes: 0` is an unlimited plan, so there is nothing to run out
/// of; section 5.4 records that silence as correct rather than as a bug
/// to "fix" by warning on lifetime spend, which never stops rising.
#[test]
fn a_disabled_server_and_a_zero_block_cross_nothing() {
    let dir = tmp("blockcross2");
    let d = crate::testutil::test_daemon(&dir);
    write_cfg(
        &d,
        r#"[{"host":"off.example","block_bytes":1000,"enabled":false},
            {"host":"flat.example","block_bytes":0}]"#,
    );

    d.block_threshold_tick();
    d.add_usage(&[
        (acct("off.example"), 5000),
        (acct("flat.example"), 5_000_000),
    ]);
    d.block_threshold_tick();
    assert!(
        kinds(&d).is_empty(),
        "neither shape crosses: {:?}",
        kinds(&d)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An unreadable config emits nothing AND latches nothing, so the
/// crossing still fires from the first tick that can read the file.
///
/// The other way round is the trap: a tick that latched on a config it
/// could not read would seed the band it never saw, and the crossing
/// would be swallowed for good. This is not a spend decision, so the
/// design's fail-closed rule has nothing to bite on here - what it does
/// have is this, which is the same instinct one door over.
#[test]
fn an_unreadable_config_swallows_no_crossing() {
    let dir = tmp("blockcross3");
    let d = crate::testutil::test_daemon(&dir);
    write_cfg(&d, r#"[{"host":"blk.example","block_bytes":1000}]"#);
    d.block_threshold_tick();

    std::fs::write(&d.cfg_path, "{ this is not json").expect("write config");
    d.add_usage(&[(acct("blk.example"), 900)]);
    d.block_threshold_tick();
    assert!(
        kinds(&d).is_empty(),
        "nothing to say about a file we cannot read"
    );

    write_cfg(&d, r#"[{"host":"blk.example","block_bytes":1000}]"#);
    d.block_threshold_tick();
    assert_eq!(
        kinds(&d),
        vec!["server.block_low"],
        "and the crossing survived"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Two config entries sharing one HOST are two accounts with two
/// standings, so the crossing latch has to be per entry: one host-keyed
/// slot made the pair overwrite each other every tick (a low crossing
/// re-fired every 30 s forever), and a DISABLED entry's latch removal
/// deleted its enabled sibling's slot so its real crossings never
/// emitted at all.
#[test]
fn duplicate_host_entries_edge_trigger_independently() {
    let dir = tmp("blockdup");
    let d = crate::testutil::test_daemon(&dir);
    // Shared spend - these two rows have one host and one (absent)
    // username, so they are ONE account and one bill by
    // `ServerConfig::account_key`, deliberately - and different block
    // sizes: 900 of 1000 is band 1, 900 of 10000 is band 0. The LATCH
    // is still per entry, which is what this pins.
    write_cfg(
        &d,
        r#"[{"host":"blk.example","block_bytes":1000},
            {"host":"blk.example","block_bytes":10000}]"#,
    );
    d.block_threshold_tick();
    d.add_usage(&[(acct("blk.example"), 900)]);
    d.block_threshold_tick();
    assert_eq!(
        kinds(&d),
        vec!["server.block_low"],
        "the small block crosses once"
    );
    d.block_threshold_tick();
    d.block_threshold_tick();
    assert_eq!(
        kinds(&d).len(),
        1,
        "and never again while nothing else crosses: {:?}",
        kinds(&d)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the duplicate-host defect: a disabled sibling on
/// the same host must not wipe the enabled entry's latch each tick and
/// swallow its crossings.
#[test]
fn a_disabled_sibling_does_not_swallow_the_enabled_entrys_crossing() {
    let dir = tmp("blockdup2");
    let d = crate::testutil::test_daemon(&dir);
    write_cfg(
        &d,
        r#"[{"host":"blk.example","block_bytes":1000,"enabled":false},
            {"host":"blk.example","block_bytes":1000}]"#,
    );
    d.block_threshold_tick();
    d.add_usage(&[(acct("blk.example"), 900)]);
    d.block_threshold_tick();
    assert_eq!(
        kinds(&d),
        vec!["server.block_low"],
        "the enabled entry's crossing survives its disabled sibling"
    );
    d.block_threshold_tick();
    assert_eq!(kinds(&d).len(), 1, "and stays edge-triggered");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The usage flush against TWO POOL ROWS ON ONE HOST - the shape that
/// silently stopped billing about half of every paid byte.
///
/// `flush_run_usage` compared EACH ROW's cumulative counter against the
/// ONE host-keyed high-water mark that it then added EVERY row's delta
/// into. First flush: both rows read against zero, 100 + 200 billed,
/// mark stored at 300 - correct by accident. Second flush: 150 is not
/// greater than 300 and neither is 250, so the delta list came out empty
/// and the function returned having billed NOTHING, while the pair had
/// really moved another 100. The missing bytes are gone for good - out
/// of usage.json, out of the day/lifetime/per-server totals, and out of
/// every block-exhaustion decision that reads them - and it converges on
/// losing roughly half of the run. `Daemon::fold_bytes_by_account` sums
/// the rows into their ACCOUNT first - these two rows are one account,
/// having one host and one (absent) username, which is what makes them
/// the shape the bug lived in; the settle-side half is pinned by
/// `tasks::runner::runner_block_tests`, and the two must move together.
#[test]
fn the_usage_flush_folds_two_rows_on_one_host_before_billing() {
    let dir = tmp("usagefold");
    let d = crate::testutil::test_daemon(&dir);
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
    d.flush_run_usage();
    assert_eq!(d.usage_lifetime("blk.example"), 300);

    live.servers[0].bytes.store(150, Ordering::Relaxed);
    live.servers[1].bytes.store(250, Ordering::Relaxed);
    d.flush_run_usage();
    assert_eq!(
        d.usage_lifetime("blk.example"),
        400,
        "the pair moved another 100 and every byte of it is billed"
    );

    // Still idempotent at any cadence, which is the property the fold
    // must not cost: an unmoved counter bills nothing.
    d.flush_run_usage();
    assert_eq!(d.usage_lifetime("blk.example"), 400);

    // ...and the block ledger the exclusion reads is moved by it, since
    // that is the decision the lost bytes were disappearing out of.
    // Read under the ACCOUNT key the rows bill to, which is what a
    // block standing reads it under.
    assert_eq!(d.block_spent(&row().account_key()), 400);

    let _ = std::fs::remove_dir_all(&dir);
}

/// TWO ACCOUNTS ON ONE HOSTNAME METER THEIR BLOCKS APART. The finding
/// that made the ledger's key a decision rather than a detail.
///
/// A second account with one provider is how people buy more
/// connections, and a prepaid block bought from a provider you already
/// have unlimited service with lands on the same host more often than
/// not. While the meter was host-keyed the unlimited account's bytes
/// counted against the block: a flat-rate row moving 900 of a 1000-byte
/// sibling's block put that sibling in the low band having spent
/// nothing, cried wolf on the warnings pane and the `server.block_low`
/// event, and - with two BLOCK rows rather than one flat - stood a
/// funded account out of the pool early.
///
/// The usage HISTORY still merges them, and that is not an oversight
/// either: see `Daemon::add_usage`, which bills one string into a
/// host-keyed day bucket and an account-keyed lifetime.
#[test]
fn two_accounts_on_one_host_meter_their_blocks_apart() {
    let dir = tmp("blockacct");
    let d = crate::testutil::test_daemon(&dir);
    let cfg: nzbkit::config::Config = serde_json::from_str(
        r#"{"servers":[{"host":"dup.example","username":"flat"},
                       {"host":"dup.example","username":"blk","block_bytes":1000}]}"#,
    )
    .expect("config");
    let (flat, blk) = (&cfg.servers[0], &cfg.servers[1]);
    assert_ne!(
        flat.account_key(),
        blk.account_key(),
        "two usernames on one host are two accounts"
    );

    d.add_usage(&[(flat.account_key(), 900)]);
    assert_eq!(
        d.block_spent(&blk.account_key()),
        0,
        "the unlimited account's bytes are not the block's"
    );
    assert_eq!(d.block_standing(blk).band(), 0, "and it is not low");
    assert_eq!(
        d.usage_lifetime("dup.example"),
        900,
        "the per-provider history still counts them together"
    );

    d.add_usage(&[(blk.account_key(), 900)]);
    assert_eq!(d.block_spent(&blk.account_key()), 900);
    assert_eq!(d.block_standing(blk).band(), 1, "its own 90% is low");
    assert_eq!(d.usage_lifetime("dup.example"), 1_800);

    // The pool answer moves with it: the block row still has 100 left,
    // so nothing is sidelined - and a flat-rate row on the host means
    // no cap either way (`block_pool_rules` rule 3).
    let (excluded, _) = d.block_pool_rules(&cfg.servers);
    assert!(excluded.is_empty(), "a funded block is not stood down");

    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and two rows a user has duplicated VERBATIM are one account and
/// one bill, deliberately.
///
/// This is the case `pool::row_keys` refuses to alias and this ledger
/// must, and the reason the argument does not transfer: two rows are two
/// socket pools whatever their credentials say, but a provider cannot
/// issue two accounts under one username, so one host and one username
/// is one account at the provider and one prepaid block. Splitting the
/// meter here would tell somebody they had bought two.
#[test]
fn verbatim_duplicate_rows_are_one_account_and_one_bill() {
    let dir = tmp("blockdupacct");
    let d = crate::testutil::test_daemon(&dir);
    let cfg: nzbkit::config::Config = serde_json::from_str(
        r#"{"servers":[{"host":"same.example","username":"u","block_bytes":1000},
                       {"host":"same.example","username":"u","block_bytes":1000}]}"#,
    )
    .expect("config");
    assert_eq!(cfg.servers[0].account_key(), cfg.servers[1].account_key());
    d.add_usage(&[(cfg.servers[0].account_key(), 600)]);
    assert_eq!(
        d.block_spent(&cfg.servers[1].account_key()),
        600,
        "one account, one meter"
    );

    // The port is not part of the identity either: the same account
    // reached on 119 and on 563 is still one block.
    let other: nzbkit::config::ServerConfig =
        serde_json::from_str(r#"{"host":"same.example","username":"u","port":119}"#)
            .expect("server config");
    assert_eq!(other.account_key(), cfg.servers[0].account_key());

    let _ = std::fs::remove_dir_all(&dir);
}

/// The migration seeds every account on a host with that host's WHOLE
/// legacy total, base included - so the day of the upgrade reads exactly
/// as the day before it, to the byte, and the accounts diverge from
/// there.
///
/// The alternative - give the merged total to one row and start its
/// siblings at zero - is the one failure this subject exists to avoid:
/// a block that reads full when it is not. See
/// `Daemon::migrate_account_ledger`.
#[test]
fn the_account_migration_seeds_each_row_from_its_hosts_legacy_total() {
    let dir = tmp("blockmigrate");
    let d = crate::testutil::test_daemon(&dir);
    write_cfg(
        &d,
        r#"[{"host":"old.example","username":"a","block_bytes":1000},
            {"host":"old.example","username":"b","block_bytes":1000}]"#,
    );
    // A pre-5-Sep-2026 store: host-keyed lifetime and host-keyed base.
    {
        let mut u = d.usage.lock_ok();
        u.insert("lifetime".into(), json!({"old.example": 900u64}));
        u.insert("block_base".into(), json!({"old.example": 200u64}));
    }
    let cfg = nzbkit::config::Config::load(&d.cfg_path).expect("config");
    d.migrate_account_ledger();
    for s in &cfg.servers {
        assert_eq!(
            d.block_spent(&s.account_key()),
            700,
            "900 billed less a 200 base, unchanged by the migration"
        );
    }

    // ...and only now do they part company.
    d.add_usage(&[(cfg.servers[0].account_key(), 100)]);
    assert_eq!(d.block_spent(&cfg.servers[0].account_key()), 800);
    assert_eq!(d.block_spent(&cfg.servers[1].account_key()), 700);

    // One-shot: a row added AFTER the migration starts at zero, because
    // a newly configured account is a newly bought block - re-running
    // the seed would hand it a block that reads as already spent.
    write_cfg(
        &d,
        r#"[{"host":"old.example","username":"a","block_bytes":1000},
            {"host":"old.example","username":"b","block_bytes":1000},
            {"host":"old.example","username":"c","block_bytes":1000}]"#,
    );
    d.migrate_account_ledger();
    let cfg = nzbkit::config::Config::load(&d.cfg_path).expect("config");
    assert_eq!(d.block_spent(&cfg.servers[2].account_key()), 0);
    assert_eq!(
        d.block_spent(&cfg.servers[0].account_key()),
        800,
        "and the rows that were seeded are left alone"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
