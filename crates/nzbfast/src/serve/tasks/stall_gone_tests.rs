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

/// A rolling window of watchdog samples, oldest first, one per `tick`
/// seconds and ending now: `(fleet byte total, cumulative dispatches,
/// cumulative refusals)`.
///
/// One host, because [`super::flat_gone`] reads the fleet SUM and a
/// second host would only test that addition works. Which servers have
/// been asked is [`super::fleet_answered`]'s question and is driven off
/// a real `LiveStats` in the cases below.
fn window(tick: u64, samples: &[(u64, u64, u64)]) -> VecDeque<Sample> {
    let now = Instant::now();
    let last = samples.len() as u64 - 1;
    samples
        .iter()
        .enumerate()
        .map(|(i, (bytes, tried, missing))| {
            (
                now - std::time::Duration::from_secs((last - i as u64) * tick),
                vec![("a.example".to_string(), *bytes)],
                *tried,
                *missing,
            )
        })
        .collect()
}

/// A daemon with somewhere for the queue to go next, without which
/// every demotion arm correctly stays silent.
/// The guard comes back with the daemon because the daemon reads and
/// writes under `dir` for its whole life: drop it here and the tree goes
/// out from under it. Handing back a bare `Arc<Daemon>` and leaking the
/// directory is what this used to do - one `$TMPDIR` entry per tag per
/// run, forever. See `crates/nzbfast/tests/scratch/mod.rs`.
fn daemon_with_a_peer_waiting(tag: &str) -> (crate::testscratch::ScratchDir, Arc<Daemon>) {
    let dir = crate::testscratch::ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbfast-{tag}-{}", std::process::id())),
    );
    let d = crate::serve::testutil::test_daemon(&dir);
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
    (dir, d)
}

/// The flatline is the NEWEST unbroken run of samples with the same
/// fleet byte total, and it is measured from the oldest sample of that
/// run - not from the start of the window, and not from the last
/// sample that differed.
#[test]
fn the_flatline_is_the_newest_run_of_equal_byte_totals() {
    // Bytes climb for two ticks and then stop for three.
    let w = window(5, &[(10, 10, 0), (99, 40, 8), (99, 90, 58), (99, 150, 118)]);
    let f = super::flat_gone(&w).expect("three samples agree on the byte total");
    assert_eq!(f.secs as u64, 10, "two intervals of flatline, not three");
    assert_eq!(f.misses, 110, "refusals banked SINCE the last byte");
    assert_eq!(f.tried, 110, "and the dispatches they answered");
}

/// One sample is not an interval, so the first tick of every job has
/// nothing to say.
#[test]
fn a_single_sample_is_not_a_flatline() {
    assert!(super::flat_gone(&window(5, &[(0, 0, 0)])).is_none());
    assert!(
        super::flat_gone(&VecDeque::new()).is_none(),
        "and neither is an empty window"
    );
}

/// A byte landing in the newest interval ends the flatline outright -
/// which is the whole reason this arm needs no separate arm-then-fire
/// latch: an in-flight body arriving IS the stand-down.
#[test]
fn a_byte_in_the_newest_interval_ends_the_flatline() {
    let w = window(5, &[(99, 10, 0), (99, 90, 80), (100, 150, 139)]);
    assert!(
        super::flat_gone(&w).is_none(),
        "the newest sample moved, so there is no flat run behind it"
    );
}

/// The shape the arm exists for: the post's first third arrived, then
/// nothing for two ticks while the fleet kept being told "no such
/// article".
#[test]
fn a_flatline_full_of_refusals_is_the_partial_verdict() {
    let (_scratch, d) = daemon_with_a_peer_waiting("partialarm");
    let l = live(&["a.example"]);
    l.servers[0].bytes.store(4_800_000, Ordering::Relaxed);
    l.servers[0].articles_tried.store(1400, Ordering::Relaxed);
    l.servers[0].articles_missing.store(200, Ordering::Relaxed);
    let w = window(
        5,
        &[
            (4_800_000, 1200, 0),
            (4_800_000, 1300, 100),
            (4_800_000, 1400, 200),
        ],
    );
    let reason =
        super::partial_gone_defer(&d, &l, &w, 64, 10, 0).expect("10s flat, 200 refusals in it");
    assert!(
        reason.contains("carries what is left of this post"),
        "the wording has to separate this arm from both siblings: {reason}"
    );
    assert!(
        !reason.contains("answered so far came back missing")
            && !reason.contains("came back missing and not a byte arrived"),
        "and must not collide with either of theirs: {reason}"
    );

    // Bytes ARRIVED on this job, which is exactly what stands the early
    // twin down - the two arms cover disjoint shapes on purpose.
    assert!(
        gone_evidence(&l).is_none(),
        "premise: the run-cumulative arm cannot speak for a partial takedown"
    );
}

/// One interval short of the floor is not a verdict. Five seconds is
/// the length of the disk hiccup this arm has to tell itself apart
/// from, so a single tick of flatline is deliberately not enough.
#[test]
fn a_flatline_under_the_floor_holds_its_tongue() {
    let (_scratch, d) = daemon_with_a_peer_waiting("partialfloorsecs");
    let l = live(&["a.example"]);
    l.servers[0].bytes.store(4_800_000, Ordering::Relaxed);
    l.servers[0].articles_missing.store(100, Ordering::Relaxed);
    let w = window(5, &[(4_800_000, 1200, 0), (4_800_000, 1300, 100)]);
    assert!(
        super::partial_gone_defer(&d, &l, &w, 64, 10, 0).is_none(),
        "one 5s interval of flatline is under a 10s floor"
    );
}

/// A DRY TAIL is a flatline too, and it is not a takedown: the queue
/// has simply run out of articles to ask for. Refusals still landing
/// inside the stretch are what separates the two, and they are also
/// what rules out a wedged worker, which completes no transaction of
/// either kind.
#[test]
fn a_flatline_with_no_refusals_in_it_is_a_tail_not_a_takedown() {
    let (_scratch, d) = daemon_with_a_peer_waiting("partialtail");
    let l = live(&["a.example"]);
    l.servers[0].bytes.store(4_800_000, Ordering::Relaxed);
    l.servers[0].articles_missing.store(800, Ordering::Relaxed);
    // The 800 refusals are all OLDER than the flatline: nothing has
    // been answered at all for the last ten seconds.
    let w = window(
        5,
        &[
            (4_800_000, 2000, 800),
            (4_800_000, 2000, 800),
            (4_800_000, 2000, 800),
        ],
    );
    assert!(
        super::partial_gone_defer(&d, &l, &w, 64, 10, 0).is_none(),
        "a run-cumulative count must never satisfy a stretch-scoped floor"
    );
}

/// "No configured server carries what is left of this post" is a claim
/// about every server, so a server that is up and has simply not been
/// asked yet stands this arm down exactly as it does its early twin.
#[test]
fn an_unprobed_server_stands_the_partial_verdict_down() {
    let (_scratch, d) = daemon_with_a_peer_waiting("partialunprobed");
    let l = live(&["a.example", "quiet.example"]);
    l.servers[0].bytes.store(4_800_000, Ordering::Relaxed);
    l.servers[0].articles_missing.store(200, Ordering::Relaxed);
    let w = window(
        5,
        &[
            (4_800_000, 1200, 0),
            (4_800_000, 1300, 100),
            (4_800_000, 1400, 200),
        ],
    );
    assert!(
        super::partial_gone_defer(&d, &l, &w, 64, 10, 0).is_none(),
        "the quiet server might be the one that still has the rest"
    );

    // Down is different from silent, the same way it is for the early
    // arm: a server granting no connection cannot supply anything and
    // is the outage arm's business.
    l.servers[1].down_since.store(1, Ordering::Relaxed);
    assert!(
        super::partial_gone_defer(&d, &l, &w, 64, 10, 0).is_some(),
        "a DOWN server does not block the verdict"
    );
}

/// Nowhere for the queue to go is the justification every arm rests
/// on: setting a job aside costs nothing when something else can run
/// and costs a restart when nothing can.
#[test]
fn the_partial_arm_stays_silent_with_nothing_else_to_run() {
    let (_scratch, d) = daemon_with_a_peer_waiting("partialalone");
    d.queue.lock_ok().clear();
    let l = live(&["a.example"]);
    l.servers[0].bytes.store(4_800_000, Ordering::Relaxed);
    l.servers[0].articles_missing.store(200, Ordering::Relaxed);
    let w = window(
        5,
        &[
            (4_800_000, 1200, 0),
            (4_800_000, 1300, 100),
            (4_800_000, 1400, 200),
        ],
    );
    assert!(super::partial_gone_defer(&d, &l, &w, 64, 10, 0).is_none());
}
