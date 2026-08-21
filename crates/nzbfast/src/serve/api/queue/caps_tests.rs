//! Unit tests for the Providers card's connection-cap payload.
//!
//! A sibling file rather than an inline `mod` because queue.rs sat on
//! the size gate's file ceiling (TODO 106): test code moves out, the
//! baseline does not move up. It moved here with its subject when the
//! §106 split gave `cap_payload` and its two neighbours their own file.

use super::*;
use crate::serve::testutil::test_daemon;

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-cappay-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// Through the pool's own constructor: `ServerLive`'s counters are
/// crate-private to nzbkit, and this is the shape a real job hands
/// the payload builder anyway.
fn live(host: &str) -> std::sync::Arc<nzbkit::pool::LiveStats> {
    let sc: nzbkit::config::ServerConfig = serde_json::from_value(json!({
        "host": host, "port": 119, "tls": false, "connections": 100
    }))
    .expect("server config");
    let cfg = nzbkit::pool::PoolConfig {
        connections: 64,
        ..Default::default()
    };
    nzbkit::pool::LiveStats::for_servers(&[(sc, cfg)])
}

/// A provider that has never refused us says nothing at all.
///
/// The whole feature turns on this: `connected < budget` is true of
/// every idle provider on every download, so the payload is absent
/// unless a capacity refusal actually wrote the gauge.
#[test]
fn a_provider_that_never_refused_carries_no_cap() {
    let dir = tmp("quiet");
    let d = test_daemon(&dir);
    let l = live("quiet.example.com");
    let s = &l.servers[0];
    s.connected.store(2, Ordering::Relaxed);
    assert!(cap_payload(&d, s).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The two halves are high-waters of the same measurement and
/// either can be the fresher one, so they merge by max - and the
/// stamp by MIN, because "since" is when the daemon was first
/// capped, not when the current job noticed.
#[test]
fn the_session_and_the_job_merge_by_high_water() {
    let dir = tmp("merge");
    let d = test_daemon(&dir);
    d.capped_hosts.lock_ok().insert(
        "gn.example.com".into(),
        crate::conntune::Capped {
            granted_hi: 38,
            capped_at: 100,
            since: 1_000,
            banked: 0,
        },
    );
    // A fresh job that has not yet been refused reports what the
    // SESSION knows - the seconds a row used to spend saying
    // "using 12 of 100" before rediscovering a cap it already knew.
    let l = live("gn.example.com");
    let s = &l.servers[0];
    let v = cap_payload(&d, s).expect("session half alone");
    assert_eq!(v["granted_hi"], 38);
    assert_eq!(v["since"], 1_000);

    // Once this job bounces too, the tighter ceiling wins and the
    // older stamp survives.
    s.granted_hi.store(31, Ordering::Relaxed);
    s.capped_at.store(64, Ordering::Relaxed);
    s.capped_since.store(9_000, Ordering::Relaxed);
    let v = cap_payload(&d, s).expect("both halves");
    assert_eq!(v["granted_hi"], 38, "high-water, not last-writer");
    assert_eq!(v["capped_at"], 100);
    assert_eq!(v["since"], 1_000, "the session started being capped first");

    // And a job that observes MORE than the session ever had
    // raises it.
    s.granted_hi.store(44, Ordering::Relaxed);
    assert_eq!(cap_payload(&d, s).expect("both")["granted_hi"], 44);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A ceiling the session remembers is retired by proof that it is
/// wrong, exactly as the live gauge's is.
///
/// Sweep 5's L6 taught `ConnGauge::up` to retire the POOL's gauge, and
/// its test asserts on `ServerLive` alone. That covers only the job
/// which both met a cap and then exceeded it. The shape users hit is
/// the other one: job 1 is refused at 38, the session banks it, the
/// plan is upgraded, and job 2 quietly holds 100 on a gauge that has
/// never recorded a cap of its own - so `retire_cap_if_exceeded`
/// returns at its first line and the row went on serving "capped at 38
/// of 100" from session memory until the daemon restarted (Codex sweep
/// 6, N4).
#[test]
fn a_fleet_holding_more_than_the_ceiling_retires_the_session_copy() {
    let dir = tmp("retire");
    let d = test_daemon(&dir);
    d.capped_hosts.lock_ok().insert(
        "gn.example.com".into(),
        crate::conntune::Capped {
            granted_hi: 38,
            capped_at: 100,
            since: 1_000,
            banked: 0,
        },
    );
    let l = live("gn.example.com");
    let s = &l.servers[0];
    // Precondition: this job's own gauge is clean, so the pool-side
    // retirement cannot fire for it.
    assert_eq!(s.capped_since.load(Ordering::Relaxed), 0);
    assert_eq!(s.capped_at.load(Ordering::Relaxed), 0);

    // Under the ceiling: the session's number still stands. A provider
    // merely sitting below its cap proves nothing either way.
    s.connected.store(38, Ordering::Relaxed);
    assert_eq!(
        cap_payload(&d, s).expect("still capped")["granted_hi"],
        38,
        "38 held is the ceiling met, not exceeded"
    );

    // Above it: the ceiling is disproven and must not be presented as a
    // measurement any more.
    s.connected.store(100, Ordering::Relaxed);
    assert!(
        cap_payload(&d, s).is_none(),
        "100 sessions held disproves a ceiling of 38"
    );
    assert!(
        d.capped_hosts.lock_ok().get("gn.example.com").is_none(),
        "and the session forgets it, so the idle plan row cannot revive it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
