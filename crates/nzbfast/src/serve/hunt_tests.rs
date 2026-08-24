//! §282 section C. The four rules this feature is made of each get a
//! test that fails if the rule is quietly removed:
//!
//! * item 9, an *arr-origin job is never hunted for. Two tests, one per
//!   gate, because a rule with a single guard is one refactor from gone.
//! * item 10, a post under the age gate is not hunted for.
//! * item 11, the breaker and the two caps terminate a repeated hunt.
//! * item 6/8, the search runs, the same-post candidate is refused and
//!   the surviving one is enqueued runnable.

use super::*;
use crate::serve::testutil::test_daemon;
use std::io::{Read, Write};

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-hunt-{tag}-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("t").len()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// An NZB whose files carry `date` and whose segments carry `ids`. Both
/// halves matter here: the date is what the age gate reads when the
/// failure message has no clause, and the ids are what the admission
/// test compares.
fn nzb_with(date: i64, ids: &[&str]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">",
    );
    for (i, id) in ids.iter().enumerate() {
        xml.push_str(&format!(
            "<file poster=\"x\" date=\"{date}\" subject=\"&quot;f{i}.bin&quot; yEnc (1/1)\">\
             <groups><group>g</group></groups><segments>\
             <segment bytes=\"1000\" number=\"1\">{id}</segment></segments></file>"
        ));
    }
    xml.push_str("</nzb>");
    xml
}

/// `days` ago, in seconds since the epoch.
fn days_ago(days: i64) -> i64 {
    unix_now() - days * 86_400
}

/// A repair verdict: `FailKind::Unrepairable`, post-unavailable, and it
/// carries NO age clause - so the age has to come off the NZB, which is
/// the incident §282 is written against.
const REPAIR_FAIL: &str = "verification failed and PAR2 repair could not complete";

/// The request a park would have queued.
fn req(
    dir: &Path,
    name: &str,
    origin: &str,
    fail: &str,
    age_days: i64,
    ids: &[&str],
) -> HuntRequest {
    let nzb = dir.join(format!("{}.nzb", safe_spool_stem(name)));
    std::fs::write(&nzb, nzb_with(days_ago(age_days), ids)).expect("spool nzb");
    HuntRequest {
        nzo_id: format!("nzo_{}", name.len()),
        name: name.to_string(),
        origin: origin.to_string(),
        fail_message: fail.to_string(),
        nzb_path: nzb,
        category: String::new(),
    }
}

fn on() -> HuntPolicy {
    HuntPolicy {
        enabled: true,
        ..Default::default()
    }
}

const STEM: &str = "Some.Show.S01E05.1080p.WEB.H264-AAA";

// ---- item 9: never hunt for an *arr-origin job ----

/// THE HARD RULE. Sonarr and Radarr own the retry for grabs they sent:
/// they blocklist the release and re-search. Two agents hunting one
/// episode gives double grabs and a queue full of alternates, which is
/// the same ownership question `giveup.rs` answers when it decides which
/// instance may be touched.
///
/// Pinned at BOTH gates, and pinned as being FIRST: the refusal has to
/// outrank every other reason, or a later reordering that puts (say) the
/// enabled check on top turns "we never hunt for an *arr" into "we never
/// hunt for an *arr, unless the feature happens to be off", which reads
/// identical in a passing test suite and is not the same rule.
#[test]
fn an_arr_origin_job_is_never_hunted_for() {
    let dir = tdir("arr");
    // Everything else about this job is a green light: aged well past
    // the gate, a post-unavailability verdict, a parseable name, and the
    // feature switched on.
    for origin in ["arr", "arr:sonarr", "arr:radarr"] {
        let r = req(&dir, STEM, origin, REPAIR_FAIL, 400, &["a@x"]);
        assert_eq!(
            hunt_gates(&r, on(), unix_now()).err(),
            Some(NoHunt::ArrOwned),
            "{origin} must never be hunted for"
        );
    }
    // ...and it outranks every other refusal, including the disabled
    // one, which is what "first" means.
    let bad = req(&dir, "no-identity-here", "arr", "disk full", 0, &["a@x"]);
    assert_eq!(
        hunt_gates(&bad, HuntPolicy::default(), unix_now()).err(),
        Some(NoHunt::ArrOwned),
        "the *arr refusal must be reached before any other"
    );

    // The second gate: park's own snapshot. An *arr job must not even
    // reach the worker's queue.
    let d = test_daemon(&dir);
    d.alt.auto_search.store(true, Ordering::Relaxed);
    let arr = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-arr", "name": STEM, "origin": "arr:sonarr",
            "state": "Failed", "fail_message": REPAIR_FAIL,
            "out_dir": dir.join("o").to_string_lossy(),
            "nzb_path": dir.join("x.nzb").to_string_lossy(),
        }))
        .expect("job"),
    ));
    d.hunt_request(&arr);
    assert!(
        d.hunt.q.lock_ok().is_empty(),
        "park must not queue a hunt for an *arr-origin job"
    );

    // The same job with a user origin DOES queue: without this the test
    // above would pass on a `hunt_request` that queues nothing at all.
    arr.lock_ok().origin = "dashboard".into();
    d.hunt_request(&arr);
    assert_eq!(d.hunt.q.lock_ok().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- item 10: ride the age gate ----

/// Under [`crate::diag::GONE_MIN_AGE_DAYS`] a post that 430s everywhere
/// is very likely still PROPAGATING, and every alternate a hunt finds is
/// the same fresh post. Below the gate the answer is wait and retry.
///
/// Both arms are covered, because they read the age from different
/// places: a repair verdict carries no age clause, so the figure comes
/// off the spooled NZB; a missing-articles verdict goes through
/// `missing_articles_proven_stale`, which also refuses an ambiguous loss
/// however old the post is.
#[test]
fn a_job_under_the_age_gate_is_not_hunted_for() {
    let dir = tdir("age");
    let now = unix_now();

    // Repair verdict, age off the NZB.
    for young in [0, 1, i64::from(crate::diag::GONE_MIN_AGE_DAYS) - 1] {
        let r = req(&dir, STEM, "dashboard", REPAIR_FAIL, young, &["a@x"]);
        assert_eq!(
            hunt_gates(&r, on(), now).err(),
            Some(NoHunt::StillPropagating),
            "a {young}-day-old post is still propagating"
        );
    }
    let old = req(&dir, STEM, "dashboard", REPAIR_FAIL, 400, &["a@x"]);
    assert!(
        hunt_gates(&old, on(), now).is_ok(),
        "a 400-day-old repair verdict is past the gate"
    );

    // A dateless NZB is an UNKNOWN age, and unknown does not hunt - the
    // opposite direction from the auto-retry gate, which retries on
    // unknown. A wrong retry costs one duplicate download of a post we
    // already hold most of; a wrong hunt costs a whole extra release.
    let dateless = req(&dir, STEM, "dashboard", REPAIR_FAIL, 0, &["a@x"]);
    std::fs::write(&dateless.nzb_path, nzb_with(0, &["a@x"])).unwrap();
    assert_eq!(
        hunt_gates(&dateless, on(), now).err(),
        Some(NoHunt::StillPropagating),
        "an unknown post age must not hunt"
    );

    // Missing-articles verdict: the clause in the message decides, and
    // `missing_articles_proven_stale` is what reads it. The producer of
    // that clause is pinned by diag's own round-trip test, so building
    // it here is safe.
    let aged_clause = |days: u32| {
        format!(
            "download incomplete: 3 file(s) with missing segments, 0 decode/write errors; \
             the post is {days} day(s) old, well past the minutes-to-hours a fill takes"
        )
    };
    let fresh = req(&dir, STEM, "dashboard", &aged_clause(1), 400, &["a@x"]);
    assert_eq!(
        hunt_gates(&fresh, on(), now).err(),
        Some(NoHunt::StillPropagating),
        "a 1-day-old missing-articles loss is propagation, whatever the NZB says"
    );
    let stale = req(&dir, STEM, "dashboard", &aged_clause(40), 400, &["a@x"]);
    assert!(hunt_gates(&stale, on(), now).is_ok());

    // ...and an ambiguous loss is never proven stale, however old.
    let ambiguous = format!(
        "{}; most were lost to transport/connection errors, not takedowns",
        aged_clause(40)
    );
    let amb = req(&dir, STEM, "dashboard", &ambiguous, 400, &["a@x"]);
    assert_eq!(
        hunt_gates(&amb, on(), now).err(),
        Some(NoHunt::StillPropagating),
        "a loss our own link caused is ours to fix, not the post's"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other two cheap gates, so a green suite is not one that only ever
/// exercised the happy path: a local fault is not evidence about the
/// post, and a name with no identity cannot aim a search.
#[test]
fn a_local_fault_and_an_unidentifiable_name_are_both_refused() {
    let dir = tdir("gates");
    let local = req(
        &dir,
        STEM,
        "dashboard",
        "could not write the download: 3 decode/write error(s) and no missing segments",
        400,
        &["a@x"],
    );
    assert_eq!(
        hunt_gates(&local, on(), unix_now()).err(),
        Some(NoHunt::LocalFault)
    );
    let junk = req(
        &dir,
        "some-obfuscated-blob",
        "dashboard",
        REPAIR_FAIL,
        400,
        &["a@x"],
    );
    assert_eq!(
        hunt_gates(&junk, on(), unix_now()).err(),
        Some(NoHunt::NoIdentity)
    );
    // And the whole feature is OFF unless asked for.
    let good = req(&dir, STEM, "dashboard", REPAIR_FAIL, 400, &["a@x"]);
    assert_eq!(
        hunt_gates(&good, HuntPolicy::default(), unix_now()).err(),
        Some(NoHunt::Disabled),
        "the hunt must default to off"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- item 6: the admission test ----

/// The test itself is `spare::admits` (section B's), and `spare` owns
/// its own tests. What is this module's to pin is the ONE judgement
/// this caller makes about it: an uncomparable pair is refused.
///
/// The admission side, not the promotion side. A spare that cannot be
/// compared is already on the queue and the user can see it; a hunt
/// candidate is a whole download this daemon is about to start on its
/// own initiative, and "we could not read either NZB" is not a licence
/// to spend one.
#[test]
fn a_hunt_candidate_it_cannot_compare_is_refused() {
    let readable = nzbkit::nzb::Nzb::parse(nzb_with(0, &["a@x", "b@x"]).as_bytes()).unwrap();
    let ids = spare::post_ids(&readable);
    assert!(
        !spare::admits(&ids, &ids, false),
        "the same post is refused, whatever the unknown policy"
    );
    let empty = spare::post_ids(&nzbkit::nzb::Nzb {
        files: Vec::new(),
        meta: Vec::new(),
    });
    assert!(
        !spare::admits(&ids, &empty, false),
        "a hunt must not spend a download on a pair it cannot compare"
    );
    assert!(
        spare::admits(&ids, &empty, true),
        "...which is the caller's choice, not the function's"
    );
    let other =
        spare::post_ids(&nzbkit::nzb::Nzb::parse(nzb_with(0, &["p@y", "q@y"]).as_bytes()).unwrap());
    assert!(
        spare::admits(&ids, &other, false),
        "a real repost is admitted"
    );
}

// ---- item 11: termination and cost ----

/// A hunt that never terminates is worse than no hunt: a genuinely dead
/// episode would loop for the life of the install, and on a block
/// account every lap is billed. Three independent stops, all pinned
/// here.
#[test]
fn the_breaker_and_the_caps_terminate_a_repeated_hunt() {
    let dir = tdir("breaker");
    let d = test_daemon(&dir);
    d.alt.auto_search.store(true, Ordering::Relaxed);
    // The breaker is opt-in and off by default, so the copy cap has to
    // stand on its own; give it a threshold only for the arm that is
    // about the breaker.
    d.alt.max_copies.store(2, Ordering::Relaxed);
    let r = req(&dir, STEM, "dashboard", REPAIR_FAIL, 400, &["a@x"]);

    // First failure: one distinct release has failed, the ceiling is 2,
    // so the hunt is allowed to look. It finds nothing (no indexer is
    // configured and there is no index), which is a different refusal
    // from the cost ones and is what proves it got past them.
    assert_eq!(d.hunt_one(&r).err(), Some(NoHunt::NoCandidate));
    // Same release again: the store dedups by stem, so a retry of one
    // dead release is one piece of evidence and not two.
    assert_eq!(d.hunt_one(&r).err(), Some(NoHunt::NoCandidate));

    // A second DISTINCT release of the same episode fails. That is the
    // ceiling, and the hunt stops rather than queueing a third.
    let two = req(
        &dir,
        "Some.Show.S01E05.720p.HDTV.x264-BBB",
        "dashboard",
        REPAIR_FAIL,
        400,
        &["b@x"],
    );
    assert_eq!(d.hunt_one(&two).err(), Some(NoHunt::CopyCap(2)));

    // The evidence is durable: it lives in the §96.3 store, so a restart
    // does not hand the loop a fresh budget.
    assert!(
        d.spool.join("giveup-state.json").exists(),
        "the copy count must be persisted, not held in memory"
    );

    // And the breaker itself: a target it has already given up is never
    // hunted for, whatever the copy cap says.
    d.alt.max_copies.store(99, Ordering::Relaxed);
    d.arr_giveup_threshold.store(1, Ordering::Relaxed);
    assert_eq!(d.hunt_one(&r).err(), Some(NoHunt::GivenUp));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The byte ceiling, and the one rule in it that is not a number: on an
/// install where any enabled server bills for its bytes, "unlimited"
/// stops being a legal setting. A hunt that drains a metered account is
/// the failure mode that would make this a liability rather than a
/// feature.
#[test]
fn a_block_account_refuses_an_unlimited_hunt() {
    let dir = tdir("metered");
    let d = test_daemon(&dir);
    d.alt.auto_search.store(true, Ordering::Relaxed);
    let r = req(&dir, STEM, "dashboard", REPAIR_FAIL, 400, &["a@x"]);

    // Flat rate: 0 means unlimited and the hunt runs (and finds nothing,
    // which is how we know it got past the budget).
    std::fs::write(
        &d.cfg_path,
        r#"{"servers":[{"host":"flat.example","enabled":true}]}"#,
    )
    .expect("config");
    assert_eq!(d.hunt_one(&r).err(), Some(NoHunt::NoCandidate));

    // One block account among them and 0 stops meaning unlimited.
    std::fs::write(
        &d.cfg_path,
        r#"{"servers":[{"host":"flat.example","enabled":true},
             {"host":"block.example","enabled":true,"block_account":true}]}"#,
    )
    .expect("config");
    d.giveup.lock_ok().targets.clear();
    assert_eq!(d.hunt_one(&r).err(), Some(NoHunt::MeteredNoBudget));

    // A ceiling that IS set is honoured on the same install.
    d.alt
        .max_extra_bytes
        .store(50_000_000_000, Ordering::Relaxed);
    d.giveup.lock_ok().targets.clear();
    assert_eq!(d.hunt_one(&r).err(), Some(NoHunt::NoCandidate));

    // A candidate whose size the indexer did not report is UNKNOWN, not
    // free, and while a ceiling is in force it is refused: a ceiling
    // that cannot bound what it is spending is not a ceiling, and the
    // install this matters on is the one paying by the byte.
    assert_eq!(
        d.hunt_budget(&[], HuntPolicy::default()).err(),
        Some(NoHunt::MeteredNoBudget),
        "unlimited is not a legal setting beside a block account"
    );
    assert!(
        !affordable(0, Some(1_000)),
        "an unknown size may not be spent under a ceiling"
    );
    assert!(affordable(0, None), "on flat rate an unknown size is fine");
    assert!(affordable(900, Some(1_000)));
    assert!(!affordable(1_100, Some(1_000)));

    // ...and it is spent by what previous hunts for this target already
    // pulled. The origin is where that is read from, so a hunted job
    // records `hunt:<target key>`.
    let keys = target_keys(&crate::wall::parse_release(STEM));
    let spent = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-spent", "name": STEM,
            "origin": hunt_origin(&keys[0]),
            "state": "Failed", "downloaded_bytes": 50_000_000_000u64,
            "out_dir": dir.join("o").to_string_lossy(),
            "nzb_path": dir.join("s.nzb").to_string_lossy(),
        }))
        .expect("job"),
    ));
    d.history.lock_ok().push(spent);
    d.giveup.lock_ok().targets.clear();
    assert_eq!(d.hunt_one(&r).err(), Some(NoHunt::ByteCap));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- item 8: the whole path, against a real indexer ----

/// A newznab mock. The listener is bound FIRST so `routes` can be built
/// from the base url it landed on: the search body has to name this very
/// port in its enclosure links, which is the whole reason for the
/// closure. Matched on the request path prefix, answered 200, connection
/// closed per request so the accept loop stays trivially sequential -
/// the same shape `giveup`'s *arr mock uses.
fn indexer_mock(routes: impl FnOnce(&str) -> Vec<(String, String)>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let routes = routes(&url);
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { return };
            sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .ok();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&buf[..n]),
                }
                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&raw).to_string();
            let path = head
                .lines()
                .next()
                .unwrap_or_default()
                .split(' ')
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let body = routes
                .iter()
                .find(|(prefix, _)| path.starts_with(prefix.as_str()))
                .map(|(_, b)| b.clone())
                .unwrap_or_default();
            let _ = sock.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = sock.write_all(body.as_bytes());
        }
    });
    url
}

/// Item 8 end to end, and item 6 inside it.
///
/// A job the user added themselves fails terminally with nothing held.
/// The search returns three candidates: one is the SAME POST (it shares
/// the failed job's message-ids), one is a genuine repost of the same
/// episode, and one is a different episode entirely that outranks both
/// on quality and would win the sort if the identity filter ever let it
/// through. The same-post one must be refused - it would fail
/// identically and burn a copy of the budget proving it - and the
/// survivor must land on the queue RUNNABLE, not parked as a duplicate
/// of the release it is replacing.
#[test]
fn a_replacement_is_found_and_the_same_post_is_refused() {
    let dir = tdir("path");
    let d = test_daemon(&dir);
    d.alt.auto_search.store(true, Ordering::Relaxed);
    d.alt.max_copies.store(4, Ordering::Relaxed);

    // The dead job's own articles. A candidate carrying these is the
    // same post however different its release name looks.
    let dead_ids = ["d1@x", "d2@x", "d3@x", "d4@x"];
    let r = req(&dir, STEM, "dashboard", REPAIR_FAIL, 400, &dead_ids);

    // The same post OUTRANKS the survivor on quality, so the ranker
    // reaches it FIRST and the admission test is what stops it. Ranked
    // the other way round the survivor would simply win the sort and
    // this test would pass without ever fetching the same post, which is
    // the shape of a green test that checks nothing.
    let same_post = "Some.Show.S01E05.2160p.WEB.H265-SAME";
    let fresh_post = "Some.Show.S01E05.1080p.WEB.H264-GOOD";
    let wrong_ep = "Some.Show.S01E06.2160p.REMUX.H265-WRONG";
    let url = indexer_mock(|base| {
        let feed = format!(
            r#"<?xml version="1.0"?><rss><channel>
            <item><title>{same_post}</title><guid>1</guid>
              <enclosure url="{base}/nzb?id=same" length="1000"/></item>
            <item><title>{fresh_post}</title><guid>2</guid>
              <enclosure url="{base}/nzb?id=fresh" length="2000"/></item>
            <item><title>{wrong_ep}</title><guid>3</guid>
              <enclosure url="{base}/nzb?id=wrong" length="3000"/></item>
            </channel></rss>"#
        );
        vec![
            // Longest prefixes first: the enclosures live under the same
            // host as the api endpoint.
            ("/nzb?id=same".into(), nzb_with(days_ago(400), &dead_ids)),
            (
                "/nzb?id=fresh".into(),
                nzb_with(days_ago(300), &["g1@y", "g2@y", "g3@y", "g4@y"]),
            ),
            ("/nzb?id=wrong".into(), nzb_with(days_ago(300), &["w1@z"])),
            ("/api".into(), feed),
        ]
    });

    d.indexers.lock_ok().push(crate::newznab::IndexerConfig {
        name: "mock".into(),
        url: url.clone(),
        apikey: "k".into(),
        enabled: true,
        priority: 0,
        hits_per_day: 0,
        grabs_per_day: 0,
    });

    assert_eq!(d.hunt_one(&r), Ok(()));

    let queued: Vec<(String, i32, bool, String)> = d
        .queue
        .lock_ok()
        .iter()
        .map(|j| {
            let g = j.lock_ok();
            (g.name.clone(), g.priority, g.paused, g.origin.clone())
        })
        .collect();
    assert_eq!(queued.len(), 1, "exactly one replacement: {queued:?}");
    let (name, priority, paused, origin) = &queued[0];
    assert_eq!(name, fresh_post, "the same post must not be queued");
    assert_eq!(*priority, 0);
    assert!(!paused, "the replacement has to RUN, not sit held");
    assert_eq!(
        origin,
        &hunt_origin(&target_keys(&crate::wall::parse_release(STEM))[0]),
        "the replacement records which target its bytes went on"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- the trigger: a terminal verdict, and only when nothing is held ----

/// The hunt is what happens when the M14f promote path finds NOTHING.
/// If it fired alongside a promotion the user would get two copies of
/// one release, and the held spare was free where the hunt is not.
///
/// The other half of the same rule is that the trigger is a TERMINAL
/// verdict and nothing else. An armed automatic retry is not terminal -
/// the original comes back through the queue in minutes - which is the
/// same guard the promotion above it takes, for the same reason.
#[test]
fn park_hunts_only_when_nothing_was_held() {
    let dir = tdir("trigger");
    let d = test_daemon(&dir);
    d.alt.auto_search.store(true, Ordering::Relaxed);

    let failed = |id: &str| {
        let nzb = dir.join(format!("{id}.nzb"));
        std::fs::write(&nzb, nzb_with(days_ago(400), &["a@x"])).unwrap();
        Arc::new(Mutex::new(
            job_from_json(&serde_json::json!({
                "nzo_id": id, "name": STEM, "origin": "dashboard",
                "state": "Failed", "fail_message": REPAIR_FAIL,
                "dupe_key": crate::serve::dupe_key(STEM),
                "out_dir": dir.join(id).to_string_lossy(),
                "nzb_path": nzb.to_string_lossy(),
            }))
            .expect("job"),
        ))
    };

    // Nothing held: the hunt is asked.
    let a = failed("nzo-a");
    d.queue.lock_ok().push_back(a.clone());
    d.park_gen(a, None);
    assert_eq!(
        d.hunt.q.lock_ok().len(),
        1,
        "a terminal verdict with nothing held asks the hunt"
    );
    d.hunt.q.lock_ok().clear();

    // A spare IS held against the next one, so the promotion answers and
    // the hunt must stand down.
    let spare = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-spare", "name": "Some.Show.S01E05.720p.WEB.H264-BBB",
            "origin": "dashboard", "state": "Queued", "paused": true, "priority": -3,
            "held_for": "nzo-b",
            "dupe_key": crate::serve::dupe_key(STEM),
            "out_dir": dir.join("spare").to_string_lossy(),
            "nzb_path": dir.join("spare.nzb").to_string_lossy(),
        }))
        .expect("spare"),
    ));
    let b = failed("nzo-b");
    d.queue.lock_ok().push_back(spare.clone());
    d.queue.lock_ok().push_back(b.clone());
    d.park_gen(b, None);
    assert!(
        !spare.lock_ok().paused,
        "the held spare is the answer here, and it must be promoted"
    );
    assert!(
        d.hunt.q.lock_ok().is_empty(),
        "a promoted spare means the hunt must not also queue a copy"
    );

    // ...and the case §282 item 19 created: `alt_auto_switch` OFF, so a
    // spare is HELD and nothing is promoted. The hunt must still stand
    // down. It is item 12's notice that offers the held row on a click,
    // and a hunt firing beside it puts a THIRD copy of one release in
    // front of the user. HELD, not PROMOTED, is the trigger.
    d.alt.auto_switch.store(false, Ordering::Relaxed);
    let spare2 = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-spare2", "name": "Some.Show.S01E05.720p.WEB.H264-CCC",
            "origin": "dashboard", "state": "Queued", "paused": true, "priority": -3,
            "held_for": "nzo-c",
            "dupe_key": crate::serve::dupe_key(STEM),
            "out_dir": dir.join("spare2").to_string_lossy(),
            "nzb_path": dir.join("spare2.nzb").to_string_lossy(),
        }))
        .expect("spare2"),
    ));
    let c = failed("nzo-c");
    d.queue.lock_ok().push_back(spare2.clone());
    d.queue.lock_ok().push_back(c.clone());
    d.park_gen(c, None);
    assert!(
        spare2.lock_ok().paused,
        "with the switch off the spare stays held, which is item 19's point"
    );
    assert!(
        d.hunt.q.lock_ok().is_empty(),
        "a spare that is HELD but not promoted still means the hunt stands down"
    );

    // And with the spare gone, the same shape DOES hunt - without this
    // the two assertions above would pass on a hunt that never fires.
    spare2.lock_ok().tombstone = true;
    let e = failed("nzo-e");
    d.queue.lock_ok().push_back(e.clone());
    d.park_gen(e, None);
    assert_eq!(
        d.hunt.q.lock_ok().len(),
        1,
        "nothing held means the hunt is asked"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
