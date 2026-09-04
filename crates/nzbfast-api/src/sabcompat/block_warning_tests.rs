//! A prepaid block that has run out is a CONDITION, and this is where
//! it becomes visible.
//!
//! Until 27 Aug 2026 it was visible in exactly one place: a colour on
//! the Settings server list, which is a page you have to already
//! suspect something to open. The runner drops an exhausted host out of
//! the pool at job start (`reset_hub_for_job`) and logs one line under
//! target "block"; nothing reached the user, the API or an *arr. So
//! "why was only one of my three providers used" and "why did this fail
//! on a post my fill server has" had the same invisible answer, and the
//! remedy - top up, then press Block refilled - was never suggested.
//!
//! Design and the routing half of the same subject:
//! research/BLOCK-ACCOUNT-ECONOMICS-2026-08-27.md.
//!
//! Its own file rather than `sabcompat.rs`'s, for the size gate: the
//! parent is near its 3,000-line ceiling. Not unix-gated, unlike its two
//! neighbours - nothing here needs a mode bit.

use super::*;

/// Write a config this daemon's warnings can be judged against.
///
/// A test that hands the daemon a path it never wrote is testing the
/// BOX, not the daemon: `Config::load` answers a missing file by going
/// and finding a SABnzbd install's `sabnzbd.ini` under `$HOME`, which
/// this fleet has from the competitive benchmarking and a CI runner does
/// not. The whole point here is which servers are configured, so the
/// file is the fixture.
///
/// Its own path rather than writing over `test_daemon`'s seeded
/// `nzbfast.toml`, which is the house convention elsewhere: `sab_warnings`
/// takes the config path as a PARAMETER, so these tests can state the
/// server list they are judging without disturbing the one the daemon
/// itself was built against.
fn write_cfg(dir: &std::path::Path, servers: &str) -> std::path::PathBuf {
    let p = dir.join("config.json");
    std::fs::write(&p, format!(r#"{{"servers":{servers}}}"#)).expect("write config");
    p
}

fn texts(d: &Arc<Daemon>, cfg: &std::path::Path) -> String {
    sab_warnings(d, cfg, false, None)
        .iter()
        .filter_map(|w| w.get("text").and_then(Value::as_str).map(str::to_string))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The whole cycle: a block with data left says nothing, a spent one
/// says so by name, and a refill takes the condition away again.
///
/// The refill half is the one that makes this a condition rather than a
/// log line. `block_refilled` stamps an offset and never rewinds the
/// lifetime ledger, so a warning read off `usage_lifetime` would be
/// permanent and a warning read off `block_spent` clears - and only the
/// second is true. This asserts the second.
#[test]
fn a_spent_block_is_a_warning_until_it_is_refilled() {
    let dir = std::env::temp_dir().join(format!("nzbfast-blockwarn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::testutil::test_daemon(&dir);
    let cfg = write_cfg(
        &dir,
        r#"[{"host":"flat.example"},{"host":"blk.example","block_bytes":1000}]"#,
    );

    d.add_usage(&[("blk.example".into(), 400)]);
    assert!(
        !texts(&d, &cfg).contains("blk.example"),
        "a block with data left is not a condition"
    );

    d.add_usage(&[("blk.example".into(), 600)]);
    let text = texts(&d, &cfg);
    assert!(
        text.contains("blk.example") && text.contains("Block refilled"),
        "a spent block must name the account and the remedy: {text}"
    );
    assert!(
        !text.contains("flat.example"),
        "an unlimited server has no block to spend: {text}"
    );

    d.block_refilled("blk.example");
    assert!(
        !texts(&d, &cfg).contains("blk.example"),
        "a refill clears the condition"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Two servers a warning must NOT be raised for, and both are shapes a
/// real config reaches.
///
/// A DISABLED server is not downloading anything whatever its ledger
/// says, so its block is nobody's problem until it is switched back on.
/// And `block_bytes: 0` is how the config, the pool, the job planner and
/// the settings UI all spell "no block configured" - it is an unlimited
/// plan, so there is nothing to run out of and a `spent >= 0` test would
/// warn about every flat-rate server on the install.
#[test]
fn a_disabled_server_and_a_zero_block_raise_nothing() {
    let dir = std::env::temp_dir().join(format!("nzbfast-blockwarn2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::testutil::test_daemon(&dir);
    let cfg = write_cfg(
        &dir,
        r#"[{"host":"off.example","block_bytes":1000,"enabled":false},
            {"host":"zero.example","block_bytes":0}]"#,
    );
    d.add_usage(&[
        ("off.example".into(), 9_000),
        ("zero.example".into(), 9_000),
    ]);
    let text = texts(&d, &cfg);
    assert!(
        !text.contains("off.example"),
        "a disabled server downloads nothing: {text}"
    );
    assert!(
        !text.contains("zero.example"),
        "a zero block is an unlimited plan, not a spent one: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// SAB's warning entry carries FOUR keys and we sent three.
///
/// `origin` is written unconditionally by SAB's `GUIHandler.emit`
/// (`SABnzbd.py`, identical in 4.5.0, 5.1.2 and develop, read 30 Aug
/// 2026), so a client with a non-nullable field for it dies on our
/// reply - the absent-key half of GH #69, in the payload every remote
/// app's warnings pane reads. SAB's value is the emitting source file
/// and line; ours names the daemon, because these entries are COMPUTED
/// conditions rather than captured log records and there is no one line
/// to point at.
#[test]
fn every_warning_carries_sabs_four_keys() {
    let dir = std::env::temp_dir().join(format!("nzbfast-warnkeys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::testutil::test_daemon(&dir);
    // No server configured is the first-run condition, so it is the one
    // warning that needs no other setup to provoke - but the EMPTY LIST
    // still has to be written down. A path this test never wrote is
    // `Config::load`'s missing-file fallback, which goes and finds a
    // SABnzbd install's `sabnzbd.ini` under $HOME: this box has one from
    // the competitive benchmarking, so the daemon read its servers and
    // the condition never fired. See `write_cfg`'s own note above, which
    // says exactly this and which writing a bare `dir.join(..)` walked
    // straight past.
    let cfg = write_cfg(&dir, "[]");
    let ws = sab_warnings(&d, &cfg, false, None);
    assert!(!ws.is_empty(), "the no-server condition must be reported");
    for w in &ws {
        for key in ["type", "text", "time", "origin"] {
            assert!(
                w.get(key).is_some(),
                "SAB sends `{key}` on every warning and we do not: {w}"
            );
        }
        assert!(w["type"].is_string(), "{w}");
        assert!(w["text"].is_string(), "{w}");
        assert!(w["time"].is_number(), "{w}");
        assert!(w["origin"].is_string(), "{w}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
