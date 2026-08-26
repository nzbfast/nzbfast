//! TODO 306: the EARLY post-is-gone arm's evidence rule and its
//! arm-then-fire latch. A child module of `stall.rs` rather than a
//! sibling of it, so [`super::gone_evidence`] and
//! [`super::early_gone_defer`] stay private to the module that owns
//! them - the alternative was widening two items for a test.
//!
//! Nothing here touches a socket. `LiveStats::for_servers` builds the
//! same gauge block the pool publishes, and every case below writes the
//! counters by hand, which is exactly what a dead post writes into them.

use super::*;

fn live(hosts: &[&str]) -> Arc<nzbkit::pool::LiveStats> {
    let servers: Vec<_> = hosts
        .iter()
        .map(|h| {
            let sc: nzbkit::config::ServerConfig = serde_json::from_value(serde_json::json!({
                "host": h, "port": 119, "tls": false, "connections": 4
            }))
            .expect("server config");
            (sc, nzbkit::pool::PoolConfig::default())
        })
        .collect();
    nzbkit::pool::LiveStats::for_servers(&servers)
}

/// The shape the arm exists for: two servers, both asked, both
/// answering nothing but "no such article", not a byte anywhere.
#[test]
fn every_server_refusing_with_no_bytes_is_the_verdict() {
    let l = live(&["a.example", "b.example"]);
    l.servers[0].articles_tried.store(400, Ordering::Relaxed);
    l.servers[0].articles_missing.store(300, Ordering::Relaxed);
    l.servers[1].articles_tried.store(120, Ordering::Relaxed);
    l.servers[1].articles_missing.store(100, Ordering::Relaxed);
    let e = gone_evidence(&l).expect("both servers probed, no bytes");
    assert_eq!(e.misses, 400, "refusals are summed across the fleet");
    assert_eq!(e.probed, 2, "and both servers answered one themselves");
}

/// The stand-down that makes the whole arm safe to fire without a
/// warmup: one body, anywhere, from any server, and this is not the
/// shape. The windowed twin allows a job that fetched half a release
/// and only then hit a dead patch; this one must not.
#[test]
fn one_byte_anywhere_stands_the_verdict_down() {
    let l = live(&["a.example", "b.example"]);
    for s in l.servers.iter() {
        s.articles_tried.store(400, Ordering::Relaxed);
        s.articles_missing.store(400, Ordering::Relaxed);
    }
    assert!(gone_evidence(&l).is_some(), "premise: refusals only");
    l.servers[1].bytes.store(1, Ordering::Relaxed);
    assert!(
        gone_evidence(&l).is_none(),
        "a single byte from any server means SOMETHING carries this post"
    );
}

/// "No configured server carries this post" is a claim about every
/// server, so a server that is up and simply has not been asked yet
/// stands the verdict down. It might be the one that has it.
#[test]
fn a_server_that_is_up_and_unprobed_stands_the_verdict_down() {
    let l = live(&["a.example", "quiet.example"]);
    l.servers[0].articles_tried.store(900, Ordering::Relaxed);
    l.servers[0].articles_missing.store(900, Ordering::Relaxed);
    assert!(
        gone_evidence(&l).is_none(),
        "one server's refusals are not a fleet verdict"
    );

    // Down is different from silent: a server granting no connection at
    // all cannot supply anything, and is the OUTAGE arm's territory
    // rather than a reason to keep waiting here.
    l.servers[1].down_since.store(1, Ordering::Relaxed);
    let e = gone_evidence(&l).expect("the silent server is down, not unasked");
    assert_eq!(
        (e.misses, e.probed),
        (900, 1),
        "and it is not counted among the servers that answered"
    );
}

/// A fleet that has answered nothing at all is not evidence of
/// anything - which is the pre-first-response tick of every job.
#[test]
fn a_fleet_that_has_answered_nothing_is_not_a_verdict() {
    let l = live(&["a.example"]);
    assert!(gone_evidence(&l).is_none());
}

/// The latch: arm on one tick, fire on the next, and only while the
/// refusals are still arriving. A pool that has gone quiet is the
/// outage arm's shape or a job about to end on its own.
#[test]
fn the_arm_confirms_before_it_fires() {
    let dir = std::env::temp_dir().join(format!("nzbfast-gonearm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = crate::serve::testutil::test_daemon(&dir);
    // `others_waiting`: somewhere for the queue to go next, without
    // which every demotion arm correctly stays silent.
    let waiting = crate::serve::job_from_json(&serde_json::json!({
        "nzo_id": "waiting1",
        "name": "peer",
        "nzb_path": "/spool/peer.nzb",
        "out_dir": "/dl/peer",
        "state": "Queued",
    }))
    .expect("job_from_json");
    d.queue
        .lock_ok()
        .push_back(Arc::new(std::sync::Mutex::new(waiting)));

    let l = live(&["a.example"]);
    l.servers[0].articles_tried.store(80, Ordering::Relaxed);
    l.servers[0].articles_missing.store(80, Ordering::Relaxed);
    let mut armed = None;

    assert!(
        early_gone_defer(&d, &l, &mut armed, 64, 0).is_none(),
        "the first tick that sees the evidence ARMS, it never fires"
    );
    assert_eq!(armed, Some(80), "and remembers what it armed on");
    assert!(
        early_gone_defer(&d, &l, &mut armed, 64, 0).is_none(),
        "a confirming tick with no NEW refusal proves no liveness"
    );

    l.servers[0].articles_missing.store(150, Ordering::Relaxed);
    let reason = early_gone_defer(&d, &l, &mut armed, 64, 0).expect("confirmed");
    assert!(
        reason.contains("came back missing"),
        "the wording carries the refusal attribution: {reason}"
    );
    assert_eq!(armed, None, "firing consumes the latch");

    // A body landing mid-confirmation is the whole point of confirming.
    let mut armed = None;
    assert!(early_gone_defer(&d, &l, &mut armed, 64, 0).is_none());
    l.servers[0].bytes.store(4096, Ordering::Relaxed);
    l.servers[0].articles_missing.store(400, Ordering::Relaxed);
    assert!(
        early_gone_defer(&d, &l, &mut armed, 64, 0).is_none(),
        "bytes arrived between the two ticks, so there is no verdict"
    );
    assert_eq!(armed, None, "and the latch is cleared, not merely held");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The floor is a floor: below it the evidence is a handful of
/// stragglers, not a fleet saying the post is gone.
#[test]
fn the_refusal_floor_holds() {
    let dir = std::env::temp_dir().join(format!("nzbfast-gonefloor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = crate::serve::testutil::test_daemon(&dir);
    let l = live(&["a.example"]);
    l.servers[0].articles_tried.store(63, Ordering::Relaxed);
    l.servers[0].articles_missing.store(63, Ordering::Relaxed);
    let mut armed = None;
    assert!(early_gone_defer(&d, &l, &mut armed, 64, 0).is_none());
    assert_eq!(armed, None, "under the floor there is nothing to arm on");
    let _ = std::fs::remove_dir_all(&dir);
}
