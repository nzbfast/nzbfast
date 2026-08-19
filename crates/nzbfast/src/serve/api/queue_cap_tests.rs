//! Unit tests for the Providers card's connection-cap payload.
//!
//! A sibling file rather than an inline `mod` because queue.rs sits on
//! the size gate's file ceiling (TODO 106): test code moves out, the
//! baseline does not move up.

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
