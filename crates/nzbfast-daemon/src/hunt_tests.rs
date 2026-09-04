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
use crate::testutil::{flat_rate_config, test_daemon};
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
        // Deliberately None across this module: every row here exists to
        // pin what the GATES do with a given failure, and the gates read
        // the string classifier whenever no producer stated a code - so
        // leaving it unset is what keeps these rows testing the arm that
        // every version-less record on every disk still lands on. TODO
        // 307 item 1's own rows live in `failkind::tests`.
        fail_code: None,
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
            hunt_gates(&r, on(), unix_now(), Trigger::Auto).err(),
            Some(NoHunt::ArrOwned),
            "{origin} must never be hunted for"
        );
    }
    // ...and it outranks every other refusal, including the disabled
    // one, which is what "first" means.
    let bad = req(&dir, "no-identity-here", "arr", "disk full", 0, &["a@x"]);
    assert_eq!(
        hunt_gates(&bad, HuntPolicy::default(), unix_now(), Trigger::Auto).err(),
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
    crate::hunt::hunt_request(&d, &arr);
    assert!(
        d.hunt.q.lock_ok().is_empty(),
        "park must not queue a hunt for an *arr-origin job"
    );

    // The same job with a user origin DOES queue: without this the test
    // above would pass on a `hunt_request` that queues nothing at all.
    arr.lock_ok().origin = "dashboard".into();
    crate::hunt::hunt_request(&d, &arr);
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
            hunt_gates(&r, on(), now, Trigger::Auto).err(),
            Some(NoHunt::StillPropagating),
            "a {young}-day-old post is still propagating"
        );
    }
    let old = req(&dir, STEM, "dashboard", REPAIR_FAIL, 400, &["a@x"]);
    assert!(
        hunt_gates(&old, on(), now, Trigger::Auto).is_ok(),
        "a 400-day-old repair verdict is past the gate"
    );

    // A dateless NZB is an UNKNOWN age, and unknown does not hunt - the
    // opposite direction from the auto-retry gate, which retries on
    // unknown. A wrong retry costs one duplicate download of a post we
    // already hold most of; a wrong hunt costs a whole extra release.
    let dateless = req(&dir, STEM, "dashboard", REPAIR_FAIL, 0, &["a@x"]);
    std::fs::write(&dateless.nzb_path, nzb_with(0, &["a@x"])).unwrap();
    assert_eq!(
        hunt_gates(&dateless, on(), now, Trigger::Auto).err(),
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
        hunt_gates(&fresh, on(), now, Trigger::Auto).err(),
        Some(NoHunt::StillPropagating),
        "a 1-day-old missing-articles loss is propagation, whatever the NZB says"
    );
    let stale = req(&dir, STEM, "dashboard", &aged_clause(40), 400, &["a@x"]);
    assert!(hunt_gates(&stale, on(), now, Trigger::Auto).is_ok());

    // ...and an ambiguous loss is never proven stale, however old.
    let ambiguous = format!(
        "{}; most were lost to transport/connection errors, not takedowns",
        aged_clause(40)
    );
    let amb = req(&dir, STEM, "dashboard", &ambiguous, 400, &["a@x"]);
    assert_eq!(
        hunt_gates(&amb, on(), now, Trigger::Auto).err(),
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
        hunt_gates(&local, on(), unix_now(), Trigger::Auto).err(),
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
        hunt_gates(&junk, on(), unix_now(), Trigger::Auto).err(),
        Some(NoHunt::NoIdentity)
    );
    // And the whole feature is OFF unless asked for.
    let good = req(&dir, STEM, "dashboard", REPAIR_FAIL, 400, &["a@x"]);
    assert_eq!(
        hunt_gates(&good, HuntPolicy::default(), unix_now(), Trigger::Auto).err(),
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
    flat_rate_config(&d);
    // The breaker is opt-in and off by default, so the copy cap has to
    // stand on its own; give it a threshold only for the arm that is
    // about the breaker.
    d.alt.max_copies.store(2, Ordering::Relaxed);
    let r = req(&dir, STEM, "dashboard", REPAIR_FAIL, 400, &["a@x"]);

    // First failure: one distinct release has failed, the ceiling is 2,
    // so the hunt is allowed to look. It finds nothing (no indexer is
    // configured and there is no index), which is a different refusal
    // from the cost ones and is what proves it got past them.
    assert_eq!(
        crate::hunt::hunt_one(&d, &r).err(),
        Some(NoHunt::NoCandidate)
    );
    // Same release again: the store dedups by stem, so a retry of one
    // dead release is one piece of evidence and not two.
    assert_eq!(
        crate::hunt::hunt_one(&d, &r).err(),
        Some(NoHunt::NoCandidate)
    );

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
    assert_eq!(
        crate::hunt::hunt_one(&d, &two).err(),
        Some(NoHunt::CopyCap(2))
    );

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
    assert_eq!(crate::hunt::hunt_one(&d, &r).err(), Some(NoHunt::GivenUp));
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
    assert_eq!(
        crate::hunt::hunt_one(&d, &r).err(),
        Some(NoHunt::NoCandidate)
    );

    // One block account among them and 0 stops meaning unlimited.
    std::fs::write(
        &d.cfg_path,
        r#"{"servers":[{"host":"flat.example","enabled":true},
             {"host":"block.example","enabled":true,"block_account":true}]}"#,
    )
    .expect("config");
    d.giveup.lock_ok().targets.clear();
    assert_eq!(
        crate::hunt::hunt_one(&d, &r).err(),
        Some(NoHunt::MeteredNoBudget)
    );

    // A ceiling that IS set is honoured on the same install.
    d.alt
        .max_extra_bytes
        .store(50_000_000_000, Ordering::Relaxed);
    d.giveup.lock_ok().targets.clear();
    assert_eq!(
        crate::hunt::hunt_one(&d, &r).err(),
        Some(NoHunt::NoCandidate)
    );

    // A candidate whose size the indexer did not report is UNKNOWN, not
    // free, and while a ceiling is in force it is refused: a ceiling
    // that cannot bound what it is spending is not a ceiling, and the
    // install this matters on is the one paying by the byte.
    assert_eq!(
        crate::hunt::hunt_budget(&d, &[], HuntPolicy::default(), Trigger::Auto).err(),
        Some(NoHunt::MeteredNoBudget),
        "unlimited is not a legal setting beside a block account"
    );
    // ...and §282 item 20: on a CLICK it is legal, because the guard is
    // standing in for consent nobody had given and the click is that
    // consent. The ceiling arm below it is untouched - a number the user
    // SET still bounds both roads.
    assert_eq!(
        crate::hunt::hunt_budget(&d, &[], HuntPolicy::default(), Trigger::Clicked),
        Ok(None),
        "a person clicking IS the consent the metered guard stands in for"
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
    assert_eq!(crate::hunt::hunt_one(&d, &r).err(), Some(NoHunt::ByteCap));
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

/// The candidate the mock below offers that must WIN: a genuine repost
/// of the same episode, on articles of its own.
const FRESH_POST: &str = "Some.Show.S01E05.1080p.WEB.H264-GOOD";

/// Item 8's whole stage, shared by the two tests that walk the path end
/// to end: a daemon with the hunt switched on, the request a park would
/// have queued for a job that failed with nothing held, and a newznab
/// mock offering three candidates.
///
/// One is the SAME POST (it carries the failed job's own message-ids),
/// one is [`FRESH_POST`], and one is a different episode entirely that
/// outranks both on quality and would win the sort if the identity
/// filter ever let it through.
///
/// The same post OUTRANKS the survivor on quality, so the ranker reaches
/// it FIRST and the admission test is what stops it. Ranked the other
/// way round the survivor would simply win the sort and both tests would
/// pass without ever fetching the same post, which is the shape of a
/// green test that checks nothing.
fn staged_hunt(dir: &Path) -> (Arc<Daemon>, HuntRequest) {
    let d = test_daemon(dir);
    flat_rate_config(&d);
    d.alt.auto_search.store(true, Ordering::Relaxed);
    d.alt.max_copies.store(4, Ordering::Relaxed);

    // The dead job's own articles. A candidate carrying these is the
    // same post however different its release name looks.
    let dead_ids = ["d1@x", "d2@x", "d3@x", "d4@x"];
    let r = req(dir, STEM, "dashboard", REPAIR_FAIL, 400, &dead_ids);

    let same_post = "Some.Show.S01E05.2160p.WEB.H265-SAME";
    let wrong_ep = "Some.Show.S01E06.2160p.REMUX.H265-WRONG";
    let fresh_post = FRESH_POST;
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
        kind: Default::default(),
        nzbindex: Default::default(),
        name: "mock".into(),
        url,
        apikey: "k".into(),
        enabled: true,
        priority: 0,
        hits_per_day: 0,
        grabs_per_day: 0,
    });
    (d, r)
}

/// Item 8 end to end, and item 6 inside it.
///
/// A job the user added themselves fails terminally with nothing held.
/// The same-post candidate must be refused - it would fail identically
/// and burn a copy of the budget proving it - and the survivor must land
/// on the queue RUNNABLE, not parked as a duplicate of the release it is
/// replacing.
#[test]
fn a_replacement_is_found_and_the_same_post_is_refused() {
    let dir = tdir("path");
    let (d, r) = staged_hunt(&dir);
    let fresh_post = FRESH_POST;

    assert_eq!(crate::hunt::hunt_one(&d, &r), Ok(()));

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

/// §282 item 21: the LOCAL-INDEX arm, end to end.
///
/// `hunt_candidates` collects `CandSrc::Local(r.id)` from
/// `with_index_read(|ix| ix.search(..))` and `hunt_fetch` serves it with
/// `ix.make_nzb(id)`. `index_db_wanted()` (`index_enabled || spot_enabled`)
/// was already true in every `test_daemon` fixture in this file -
/// `spot_enabled` defaults ON - so the local arm's two call sites were
/// always reached; what never happened is a test putting a RELEASE behind
/// them. `with_index_read` on the daemon's never-seeded `index.db` just
/// answers "no rows", `hits.iter().filter(|r| r.complete)` is empty, and
/// the hunt falls through to the external arm with nothing to show for
/// it - a degradation, exactly as item 21 describes, and why nothing
/// caught it. `grep -c "CandSrc::Local\|make_nzb" hunt_tests.rs` was 0
/// before this.
///
/// No mock indexer is registered - `d.indexers` stays empty, so
/// `hunt_search_external` returns nothing - which is what makes a
/// passing test mean the LOCAL arm is what found and fetched the
/// replacement, not the external one.
///
/// Two candidates are staged in the index, the same shape as item 8's
/// external-arm test above: a same-post decoy carrying one of the dead
/// job's own articles, ranked ABOVE the survivor (REMUX outranks WEB) so
/// the sort reaches it first and item 6's admission test is what has to
/// stop it - not the ranking - and a genuine local candidate on its own
/// article that must win. The queued job's spooled .nzb is read back to
/// confirm it carries the bytes `make_nzb` actually produced, not a
/// stand-in: the survivor's article present, the decoy's absent.
#[cfg(feature = "indexer")]
#[test]
fn a_local_index_replacement_is_found_and_the_same_post_is_refused() {
    let dir = tdir("local");
    let d = test_daemon(&dir);
    flat_rate_config(&d);
    d.alt.auto_search.store(true, Ordering::Relaxed);
    d.alt.max_copies.store(4, Ordering::Relaxed);
    // Not load-bearing on top of `test_daemon`'s default `spot_enabled`
    // (which already opens `index_db_wanted()`), but this is what an
    // own-index install actually has on, and the real toggle to name.
    d.index_enabled.store(true, Ordering::Relaxed);

    let dead_ids = ["d1@x", "d2@x", "d3@x", "d4@x"];
    let r = req(&dir, STEM, "dashboard", REPAIR_FAIL, 400, &dead_ids);

    const SAME_LOCAL: &str = "Some.Show.S01E05.2160p.REMUX.H265-SAMELOCAL";
    const FRESH_LOCAL: &str = "Some.Show.S01E05.2160p.WEB.H265-GOODLOCAL";

    {
        let mut ix = nzbkit::index::Index::open(&d.index_db).expect("open index");
        // The decoy: same post as the dead job (one of its own
        // message-ids), so item 6's admission test must refuse it.
        ix.ingest(
            "alt.binaries.test",
            &[nzbkit::nntp::OverEntry {
                number: 1,
                subject: format!(r#""{SAME_LOCAL}.rar" yEnc (1/1)"#),
                from: "poster@example".into(),
                message_id: format!("<{}>", dead_ids[0]),
                bytes: 1_000,
                date: days_ago(400),
            }],
            unix_now(),
        )
        .expect("ingest same-post decoy");
        // The survivor: a genuine repost, its own article.
        ix.ingest(
            "alt.binaries.test",
            &[nzbkit::nntp::OverEntry {
                number: 1,
                subject: format!(r#""{FRESH_LOCAL}.rar" yEnc (1/1)"#),
                from: "poster@example".into(),
                message_id: "<local-fresh@y>".into(),
                bytes: 2_000,
                date: days_ago(300),
            }],
            unix_now(),
        )
        .expect("ingest survivor");
    }

    assert_eq!(crate::hunt::hunt_one(&d, &r), Ok(()));

    let queued: Vec<(String, i32, bool, PathBuf)> = d
        .queue
        .lock_ok()
        .iter()
        .map(|j| {
            let g = j.lock_ok();
            (g.name.clone(), g.priority, g.paused, g.nzb_path.clone())
        })
        .collect();
    assert_eq!(queued.len(), 1, "exactly one replacement: {queued:?}");
    let (name, priority, paused, nzb_path) = &queued[0];
    assert_eq!(name, FRESH_LOCAL, "the same post must not be queued");
    assert_eq!(*priority, 0);
    assert!(!paused, "the replacement has to RUN, not sit held");

    // The nzb the queue actually received must be what `make_nzb`
    // produced from the index - not the same-post decoy's article, and
    // not an empty stand-in.
    let nzb_bytes = std::fs::read(nzb_path).expect("spooled nzb");
    let nzb = String::from_utf8_lossy(&nzb_bytes);
    assert!(
        nzb.contains("local-fresh@y"),
        "the queued nzb must carry the survivor's own article: {nzb}"
    );
    assert!(
        !nzb.contains(dead_ids[0]),
        "the queued nzb must not carry the same-post decoy's article: {nzb}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A live queue row that is NOT the one being replaced: the shape every
/// test below stands a copy of the release up as.
///
/// `key` is spelled by the caller rather than derived, because
/// `job_from_json` reads `dupe_key` verbatim off the record and never
/// recomputes it - a row built here with the field left out is invisible
/// to the name arm however its name reads, which would make a green test
/// mean nothing.
fn live_row(
    dir: &Path,
    id: &str,
    name: &str,
    ids: &[&str],
    key: Option<String>,
) -> Arc<Mutex<Job>> {
    let nzb = dir.join(format!("{id}.nzb"));
    std::fs::write(&nzb, nzb_with(days_ago(300), ids)).expect("row nzb");
    Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": id, "name": name, "origin": "dashboard",
            "state": "Queued", "paused": false,
            "total_bytes": 1000 * ids.len() as u64,
            "dupe_key": key,
            "out_dir": dir.join(id).to_string_lossy(),
            "nzb_path": nzb.to_string_lossy(),
        }))
        .expect("live row"),
    ))
}

/// The replacement as it landed: name, paused, priority and what it is
/// held against. Found by NAME, never by queue position - these tests
/// stand other rows up in front of it.
fn placed(d: &Daemon, name: &str) -> (bool, i32, String) {
    let q = d.queue.lock_ok();
    let job = q
        .iter()
        .find(|j| j.lock_ok().name == name)
        .unwrap_or_else(|| panic!("{name} is not on the queue"));
    let g = job.lock_ok();
    (g.paused, g.priority, g.held_for.clone())
}

/// **§290 (Codex F-09), the residue.** A hunted replacement is a
/// duplicate of the row it replaces and of NOTHING ELSE.
///
/// `hunt_enqueue` passed a bare `allow_dupe = true` until 25 Aug 2026,
/// and that bool switched both duplicate arms off against every record
/// in both stores. The exception is written for one row - the
/// replacement IS a duplicate of the release that just failed, and
/// without the exemption the M14f hold would park the only copy that can
/// still deliver - and it was being applied to all of them. So a hunted
/// copy started downloading beside a live copy of the same release the
/// user, an *arr or a watchlist had already queued: two downloads of one
/// episode, neither of them asked for by whoever queued the other.
///
/// The admission test above cannot see this. `hunt_one` holds every
/// candidate to `spare::admits` against THE FAILED JOB's message-ids, so
/// a candidate that is the same post as the row being replaced is
/// already refused; nothing asks the question about a different live row.
#[test]
fn an_unrelated_live_copy_still_holds_a_hunted_replacement() {
    let dir = tdir("dupe-name");
    let (d, r) = staged_hunt(&dir);
    // The same episode under a different release name, with articles of
    // its own - so it is the NAME arm that must catch this, not §292's.
    let mine = "Some.Show.S01E05.720p.WEB.H264-MINE";
    d.queue.lock_ok().push_back(live_row(
        &dir,
        "nzo-mine",
        mine,
        &["m1@q", "m2@q", "m3@q", "m4@q"],
        dupe_key(mine),
    ));

    assert_eq!(crate::hunt::hunt_one(&d, &r), Ok(()));

    let (paused, priority, held_for) = placed(&d, FRESH_POST);
    assert!(
        paused,
        "a hunted copy must not run beside a live copy nobody asked it to replace"
    );
    assert_eq!(priority, DUPE_PRIORITY);
    assert_eq!(
        held_for, "nzo-mine",
        "and it is held against the copy that is already live, so it promotes if that one fails"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same defect through §292's arm, which is the half the name can
/// never reach: two grabs of ONE post from two indexers routinely carry
/// different release names, and only the message-id set can meet them.
///
/// The row here is deliberately unnameable as a duplicate - a different
/// title with no `dupe_key` at all - so the name arm passes it and the
/// hold can only come from the post identity. That is the arm
/// `allow_dupe = true` switched off along with the other one.
#[test]
fn the_same_post_arm_still_holds_a_hunted_replacement() {
    let dir = tdir("dupe-post");
    let (d, r) = staged_hunt(&dir);
    // `staged_hunt`'s surviving candidate is these four articles. The
    // row carries them under a name that shares no identity with it.
    d.queue.lock_ok().push_back(live_row(
        &dir,
        "nzo-samepost",
        "Totally.Different.Title.2019.1080p.BluRay.x264-ZZZ",
        &["g1@y", "g2@y", "g3@y", "g4@y"],
        None,
    ));

    assert_eq!(crate::hunt::hunt_one(&d, &r), Ok(()));

    let (paused, priority, held_for) = placed(&d, FRESH_POST);
    assert!(
        paused,
        "the same post is already coming down under another name - do not fetch it twice"
    );
    assert_eq!(priority, DUPE_PRIORITY);
    assert_eq!(held_for, "nzo-samepost");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other side of the narrowing, and the one a careless fix breaks:
/// the row the hunt is REPLACING never holds its own replacement.
///
/// It is usually in history as Failed by the time the worker runs - park
/// files it before `hunt_request` - and a Failed history row is not a
/// collision target for either arm, so a fix that simply turned the
/// exemption off would pass most of the time and fail in the window
/// where the row is still on the queue. Here it IS on the queue,
/// carrying the failed job's own id, name and articles, which is every
/// way it could collide at once.
#[test]
fn the_row_the_hunt_replaces_never_holds_its_own_replacement() {
    let dir = tdir("dupe-self");
    let (d, r) = staged_hunt(&dir);
    let dead = live_row(
        &dir,
        &r.nzo_id,
        STEM,
        &["d1@x", "d2@x", "d3@x", "d4@x"],
        dupe_key(STEM),
    );
    d.queue.lock_ok().push_back(dead);

    assert_eq!(crate::hunt::hunt_one(&d, &r), Ok(()));

    let (paused, priority, held_for) = placed(&d, FRESH_POST);
    assert!(
        !paused,
        "the replacement has to RUN - holding it behind the row it replaces \
         parks the only copy that can still deliver"
    );
    assert_eq!(priority, 0);
    assert!(held_for.is_empty(), "held against {held_for:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The forgiven row must not MASK the one behind it.
///
/// `dupe_collision` reports the FIRST hit it finds, so an exemption
/// applied to its answer rather than inside its scans would drop the
/// whole verdict whenever the replaced row happens to be found first -
/// and the replaced row is the one that shares the failed job's exact
/// name, so it is found first whenever it is still on the queue. Both
/// rows are here, the exempt one FIRST, and the unrelated copy must
/// still hold.
#[test]
fn a_forgiven_row_does_not_mask_the_live_copy_behind_it() {
    let dir = tdir("dupe-mask");
    let (d, r) = staged_hunt(&dir);
    let mine = "Some.Show.S01E05.720p.WEB.H264-MINE";
    {
        let mut q = d.queue.lock_ok();
        q.push_back(live_row(
            &dir,
            &r.nzo_id,
            STEM,
            &["d1@x", "d2@x", "d3@x", "d4@x"],
            dupe_key(STEM),
        ));
        q.push_back(live_row(
            &dir,
            "nzo-mine",
            mine,
            &["m1@q", "m2@q", "m3@q", "m4@q"],
            dupe_key(mine),
        ));
    }

    assert_eq!(crate::hunt::hunt_one(&d, &r), Ok(()));

    let (paused, _, held_for) = placed(&d, FRESH_POST);
    assert!(paused, "the second live copy still holds the replacement");
    assert_eq!(
        held_for, "nzo-mine",
        "the exempt row must be skipped INSIDE the scan, not subtracted from its answer"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **F-09's second hole, end to end.** The byte ceiling trusted the
/// indexer's ADVERTISED size and never weighed the NZB it actually
/// fetched, so a result advertising 1 MB and supplying 100 GB walked
/// through a 1 GB ceiling.
///
/// The stage does it to scale rather than by contrivance:
/// [`staged_hunt`]'s feed advertises `length="2000"` for the surviving
/// candidate while its .nzb really carries four 1,000-byte segments. A
/// ceiling of 3,000 therefore passes the pre-fetch filter - which is
/// the point, since that filter is what stops an unaffordable candidate
/// eating one of the four fetches - and the row must still not be
/// queued, because the thing about to run is 4,000 bytes.
///
/// The recovery is asserted too: at 5,000 the same candidate lands. A
/// refusal no setting can lift is a broken feature rather than a
/// bounded one, and it would pass the first half of this test.
#[test]
fn the_fetched_nzbs_real_size_is_weighed_not_the_indexers_advertisement() {
    let dir = tdir("realsize");
    let (d, r) = staged_hunt(&dir);
    d.alt.max_extra_bytes.store(3_000, Ordering::Relaxed);

    assert_eq!(
        crate::hunt::hunt_one(&d, &r).err(),
        Some(NoHunt::ByteCap),
        "advertised 2,000, actually 4,000, ceiling 3,000"
    );
    assert!(
        d.queue.lock_ok().is_empty(),
        "and nothing may be published before that is known"
    );

    d.alt.max_extra_bytes.store(5_000, Ordering::Relaxed);
    assert_eq!(
        crate::hunt::hunt_one(&d, &r),
        Ok(()),
        "the real size fits under 5,000"
    );
    assert_eq!(d.queue.lock_ok().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// §282 item 14 on the hunt road: BOTH rows say what happened.
///
/// Item 14 was built for the two roads that run inside `park_gen` - the
/// automatic promotion of a held spare, and item 12's offer clicked -
/// and the hunt landed later the same day stamping none of its four
/// fields. So the one road that switches releases without the user
/// having asked for anything at all was the one that rendered no clause
/// anywhere: `switch_lines` returns an empty Vec when the fields are
/// blank, and every surface reads them through it. The reader item 14
/// names in its own note - "watching an unfamiliar release name download
/// right now" - is exactly what a hunt produces.
///
/// Both directions are asserted, because they are stamped in different
/// places and by different means: the NEW row from the request the
/// worker is holding, and the ABANDONED row through
/// `history_upsert_if_present` against a record that was filed into
/// history before the worker ever ran.
#[test]
fn a_hunted_replacement_says_what_it_replaced_and_why() {
    let dir = tdir("item14");
    let (d, r) = staged_hunt(&dir);

    // The failed job as park left it: filed into history, which is where
    // the worker has to find it. `history_upsert_if_present` matches by
    // Arc identity against this very list, so a record only reachable by
    // id would silently persist nothing.
    let failed = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": r.nzo_id, "name": STEM, "origin": "dashboard",
            "state": "Failed", "fail_message": r.fail_message,
            "out_dir": dir.join("dead").to_string_lossy(),
            "nzb_path": r.nzb_path.to_string_lossy(),
        }))
        .expect("failed job"),
    ));
    d.history.lock_ok().push(failed.clone());

    assert_eq!(crate::hunt::hunt_one(&d, &r), Ok(()));

    let replacement = d.queue.lock_ok().front().cloned().expect("a replacement");
    let lines = crate::altcand::switch_lines(&replacement.lock_ok());
    assert!(
        !lines.is_empty(),
        "a hunted replacement must say what it replaced, as the other two roads do"
    );
    assert_eq!(
        lines
            .iter()
            .find(|(k, _)| *k == "replaced")
            .map(|(_, v)| v.as_str()),
        Some(STEM),
        "the clause names the release that failed: {lines:?}"
    );
    assert_eq!(
        lines
            .iter()
            .find(|(k, _)| *k == "replaced because")
            .map(|(_, v)| v.as_str()),
        Some(REPAIR_FAIL),
        "...and why it was abandoned: {lines:?}"
    );
    // The nzo_id half is what links the two rows once the names have
    // scrolled out of sight.
    assert_eq!(replacement.lock_ok().alt_from, r.nzo_id);

    // The mirror, on the row the user actually clicked and will go
    // looking for in history.
    let back = crate::altcand::switch_lines(&failed.lock_ok());
    assert_eq!(
        back.iter()
            .find(|(k, _)| *k == "replaced by")
            .map(|(_, v)| v.as_str()),
        Some(FRESH_POST),
        "the abandoned row must name what took its place: {back:?}"
    );
    // ...and durably: the record is in history, so the late mutation has
    // to reach history.jsonl or it is gone at the next start.
    let store =
        std::fs::read_to_string(dir.join("spool").join("history.jsonl")).unwrap_or_default();
    assert!(
        store.contains(FRESH_POST),
        "the abandoned row's clause has to be persisted, not only held in memory"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// §282 item 18's closing decision, pinned as an assertion rather than
/// left in prose: ONE payload shape, TWO kinds.
///
/// For one afternoon on 24 Aug 2026 this event was `job.replaced` carrying
/// `failed_nzo_id` / `failed_name` and neither `category` nor `reason`,
/// while `job.switched` - the same user-visible outcome down the other
/// two doors - carried `replaces` / `replaces_name` / `category` /
/// `reason` / `by`. A webhook consumer had to special-case the two field
/// by field. The keys are the promote door's keys now, and this test is
/// what stops them drifting back apart, since the three emit sites are
/// in three files and nothing compiles them against each other.
///
/// THE KIND IS ASSERTED TOO, and asserting it is not belt-and-braces: a
/// later reading of "unify them" that FOLDS this into `job.switched`
/// takes away the only axis a webhook target can express the difference
/// on - `hooks::wants_lifecycle` matches an exact kind or a `prefix.*`
/// and nothing in the body, so "tell me when a hunt spends new bytes"
/// would stop being sayable. That is a product decision and it should
/// have to come here and delete a named assertion to happen.
#[test]
fn a_hunted_replacement_announces_itself_in_the_promote_doors_vocabulary() {
    let dir = tdir("item18");
    let (d, mut r) = staged_hunt(&dir);
    // Non-empty, because `category` reaching the payload is one of the
    // two keys this door did not carry - an empty string would pass
    // against a `json!` that dropped it.
    r.category = "tv".into();

    assert_eq!(crate::hunt::hunt_one(&d, &r), Ok(()));

    let ring = d.life_events.lock_ok();
    let e = ring
        .iter()
        .find(|e| e["kind"] == "job.replaced")
        .unwrap_or_else(|| panic!("no job.replaced reached the lifecycle ring: {ring:?}"));

    // What replaced it, in the promote door's spelling.
    assert_eq!(e["name"], serde_json::json!(FRESH_POST), "{e}");
    assert_eq!(e["category"], serde_json::json!("tv"), "{e}");
    assert!(
        !e["nzo_id"].as_str().unwrap_or_default().is_empty(),
        "the replacement's own id is the handle a subscriber acts on: {e}"
    );
    // ...and what was abandoned. `replaces`/`replaces_name`, NOT
    // `failed_nzo_id`/`failed_name`.
    assert_eq!(e["replaces"], serde_json::json!(r.nzo_id), "{e}");
    assert_eq!(e["replaces_name"], serde_json::json!(STEM), "{e}");
    assert!(
        e["failed_nzo_id"].is_null() && e["failed_name"].is_null(),
        "the third vocabulary must be gone, not merely joined: {e}"
    );
    // Why, in the RAW form - `reason` is what an operator pastes into a
    // bug report, so it keeps the build stamp the rendered clause takes
    // off. `why_from_fail` strips a suffix, so a pre-stripped `reason`
    // is a prefix of the raw one and `assert_eq` is what catches it.
    assert_eq!(e["reason"], serde_json::json!(REPAIR_FAIL), "{e}");
    // Which door, on the key that is total across both kinds.
    assert_eq!(e["by"], serde_json::json!("hunt"), "{e}");
    // This door's own key, the way `rank` is the promote door's own.
    assert_eq!(
        e["target"],
        serde_json::json!(target_keys(&crate::wall::parse_release(STEM))[0]),
        "{e}"
    );
    // The kind stays separate. See the doc block above.
    assert!(
        !ring.iter().any(|e| e["kind"] == "job.switched"),
        "a hunt is not a switch between two copies the user already had: {ring:?}"
    );
    drop(ring);
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
    // The promotion arm below runs on the AUTOMATIC road, so it reads
    // the metered guard - see `flat_rate_config`. Without this the
    // spare stays held on any host with no SABnzbd install, which is
    // every CI runner and no machine on this fleet.
    flat_rate_config(&d);
    d.alt.auto_search.store(true, Ordering::Relaxed);

    let failed = |id: &str| {
        let nzb = dir.join(format!("{id}.nzb"));
        std::fs::write(&nzb, nzb_with(days_ago(400), &["a@x"])).unwrap();
        Arc::new(Mutex::new(
            job_from_json(&serde_json::json!({
                "nzo_id": id, "name": STEM, "origin": "dashboard",
                "state": "Failed", "fail_message": REPAIR_FAIL,
                "dupe_key": crate::dupe_key(STEM),
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
            "dupe_key": crate::dupe_key(STEM),
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
            "dupe_key": crate::dupe_key(STEM),
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

// ---- item 20: the CLICKED road ----

/// §282 item 20a and 20's own consent question, as one unit test.
///
/// TWO refusals differ between the roads and NO OTHERS do, which is the
/// whole of what [`Trigger`] is allowed to mean. Both directions are
/// asserted, because a test that only checked the clicked road would
/// pass on a `Trigger` that had quietly become the only road.
#[test]
fn a_click_is_its_own_consent_but_never_overrides_the_arr_rule() {
    let dir = tdir("click-gates");
    let now = unix_now();
    let off = HuntPolicy::default();
    let r = req(&dir, STEM, "dashboard", REPAIR_FAIL, 400, &["a@x"]);

    // The SETTING is consent for the daemon to search on its own. With
    // it off the automatic road stands down and the button still works,
    // which is the gap item 20 exists to close: requiring the opt-in for
    // a click would make the button dead on every default install.
    assert_eq!(
        hunt_gates(&r, off, now, Trigger::Auto).err(),
        Some(NoHunt::Disabled),
        "the daemon may not search on its own initiative with the setting off"
    );
    assert!(
        hunt_gates(&r, off, now, Trigger::Clicked).is_ok(),
        "a person clicking is its own consent, and does not need the setting too"
    );

    // ...and the *arr rule is NOT one of the two. Item 9 forbids the
    // automatic hunt because Sonarr and Radarr own the retry, and a
    // click does not stop that being true: the copy we would start is
    // one they never chose, under an id they have never seen, while
    // their own poll cycle blocklists and re-searches. Decided 24 Aug
    // 2026 - see the argument in `hunt_gates` - and pinned here because
    // it is exactly one `if` and reads like a leftover.
    for origin in ["arr", "arr:sonarr", "arr:radarr"] {
        let a = req(&dir, STEM, origin, REPAIR_FAIL, 400, &["a@x"]);
        assert_eq!(
            hunt_gates(&a, on(), now, Trigger::Clicked).err(),
            Some(NoHunt::ArrOwned),
            "{origin}: a click must not buy past the *arr rule"
        );
    }

    // The age gate is shared, and asserted on the clicked road too: a
    // post still propagating is the same fact whoever is asking, and its
    // alternates are the same fresh post.
    let young = req(&dir, STEM, "dashboard", REPAIR_FAIL, 0, &["a@x"]);
    assert_eq!(
        hunt_gates(&young, off, now, Trigger::Clicked).err(),
        Some(NoHunt::StillPropagating),
        "the age gate is not a consent question, so a click does not lift it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A doomed row on the queue, its verdict at §138's bar.
///
/// The wire form rather than a built struct, for `altcand_tests`' reason:
/// that is what a restored queue.json carries, so a health object built
/// as a struct would pass over a record the daemon could not restore.
fn doomed_row(r: &HuntRequest, dir: &Path) -> Arc<Mutex<Job>> {
    Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": r.nzo_id, "name": STEM, "origin": r.origin,
            "state": "Queued",
            "dupe_key": crate::dupe_key(STEM),
            "out_dir": dir.join("doomed").to_string_lossy(),
            "nzb_path": r.nzb_path.to_string_lossy(),
            "health": {
                "bucket": "red", "reason": "no server has it",
                "per_server": [{"host": "news.example", "have": 0, "missing": 8}],
                "sampled": 8, "present": 0, "absent": 8,
                "answered": 1, "servers": 1, "age_days": 644,
                "checked_at": 1, "probes": 1, "waived": false,
            },
        }))
        .expect("doomed row"),
    ))
}

/// §282 item 20 end to end: search, pick, switch.
///
/// The seam this closes is between two ticked boxes - item 12 built the
/// notice and the switch and left the search out, section C built the
/// search and wired it to a FAILED job only - so what is pinned here is
/// that a person looking at a doomed QUEUE row can get from the notice to
/// a running replacement without either half being rewritten.
///
/// Four things, and each of them is a decision rather than plumbing:
/// the list is filtered to the same release, it is ordered exactly as
/// the automatic road's attempt order, picking the same post is refused
/// by item 6's test (the list cannot know - admitting costs a fetch, and
/// fetching all of them would spend the day's grab budget on one search),
/// and the pick goes through `alt_switch`, so the abandoned row carries
/// the verdict's own failure LEAD and both rows carry item 14's clause.
#[test]
fn a_person_can_search_with_nothing_held_and_pick_a_replacement() {
    let dir = tdir("click-path");
    let (d, r) = staged_hunt(&dir);
    // OFF, on purpose: this whole path must work on a default install.
    d.alt.auto_search.store(false, Ordering::Relaxed);
    let doomed = doomed_row(&r, &dir);
    d.queue.lock_ok().push_back(doomed.clone());

    let offer = crate::hunt::hunt_offer(&d, &r.nzo_id).expect("the row may search");
    let rows = offer["candidates"].as_array().expect("candidates");
    let names: Vec<&str> = rows
        .iter()
        .map(|c| c["name"].as_str().unwrap_or_default())
        .collect();
    assert!(
        names.contains(&FRESH_POST),
        "the survivor has to be offered: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("S01E06")),
        "a different episode is not this release: {names:?}"
    );
    // Best first, the same order the automatic road would have tried
    // them in. The same post is 2160p and outranks the survivor, so it
    // leads - which is also what makes the refusal below reachable.
    assert!(names[0].ends_with("-SAME"), "best first: {names:?}");

    // Item 6, on the clicked road. The list cannot know: the message-id
    // sets only exist once the .nzb is fetched, and fetching every
    // candidate to draw a list would spend the day's grab budget on one
    // search. So the answer is at the PICK, in words.
    let same_key = rows[0]["key"].as_str().expect("a handle").to_string();
    let err = crate::hunt::hunt_pick(&d, &r.nzo_id, &same_key)
        .expect_err("the same post must be refused");
    assert!(err.contains("same post"), "{err}");
    assert!(
        d.queue
            .lock_ok()
            .iter()
            .all(|j| j.lock_ok().name != STEM || Arc::ptr_eq(j, &doomed)),
        "a refused pick leaves nothing behind"
    );

    // ...and the survivor goes all the way through.
    let fresh_key = rows
        .iter()
        .find(|c| c["name"] == FRESH_POST)
        .and_then(|c| c["key"].as_str())
        .expect("a handle for the survivor")
        .to_string();
    let new_id = crate::hunt::hunt_pick(&d, &r.nzo_id, &fresh_key).expect("the pick lands");

    let queued: Vec<(String, i32, bool, String, String)> = d
        .queue
        .lock_ok()
        .iter()
        .map(|j| {
            let g = j.lock_ok();
            (
                g.name.clone(),
                g.priority,
                g.paused,
                g.origin.clone(),
                g.alt_from_name.clone(),
            )
        })
        .collect();
    assert_eq!(queued.len(), 1, "the doomed row left the queue: {queued:?}");
    let (name, priority, paused, origin, from) = &queued[0];
    assert_eq!(name, FRESH_POST);
    assert_eq!(*priority, 0);
    assert!(
        !paused,
        "the replacement RUNS - it is parked as a spare only long enough for the switch"
    );
    assert_eq!(
        origin,
        &hunt_origin(&target_keys(&crate::wall::parse_release(STEM))[0]),
        "a hand-picked copy is charged to the same target budget a hunted one is"
    );
    // §282 item 14, written by `alt_switch` rather than re-spelled here.
    assert_eq!(from, STEM, "the new row says what it replaced");

    let hist = d
        .history
        .lock_ok()
        .first()
        .cloned()
        .expect("the abandoned row");
    let g = hist.lock_ok();
    assert_eq!(g.nzo_id, r.nzo_id);
    assert_eq!(g.state, JobState::Failed);
    assert_eq!(
        g.alt_to_name, FRESH_POST,
        "and the old row says what replaced it"
    );
    // The failure LEAD, not the bare evidence: `fail_kind` reads it by
    // prefix, and it is what tells an *arr to blocklist this release and
    // look for another rather than hand us the same dead post back.
    assert_eq!(
        crate::failkind::fail_kind(&g.fail_message),
        crate::failkind::FailKind::Gone,
        "the abandoned row keeps the verdict's own classification: {}",
        g.fail_message
    );
    drop(g);
    assert!(!new_id.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The three refusals that are about the ROW rather than about hunting,
/// each said in `alt_switch`'s own words so one drawer never explains the
/// same state two ways.
#[test]
fn a_row_with_no_verdict_is_never_offered_a_search() {
    let dir = tdir("click-noverdict");
    let (d, r) = staged_hunt(&dir);

    assert!(
        crate::hunt::hunt_offer(&d, "nzo-nothing")
            .expect_err("an unknown id")
            .contains("no longer in the queue")
    );

    // On the queue, but nothing has concluded it cannot finish - which
    // is every row of every ordinary queue. The button is drawn from
    // `alt_offer`, so reaching this means the queue moved under the tab.
    let healthy = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-healthy", "name": STEM, "origin": "dashboard",
            "state": "Queued",
            "out_dir": dir.join("h").to_string_lossy(),
            "nzb_path": r.nzb_path.to_string_lossy(),
        }))
        .expect("healthy row"),
    ));
    d.queue.lock_ok().push_back(healthy.clone());
    assert!(
        crate::hunt::hunt_offer(&d, "nzo-healthy")
            .expect_err("no verdict, no search")
            .contains("cannot finish")
    );

    // A HELD SPARE with a verdict that would otherwise fire: the offer
    // never renders on a held row (`offer_json`'s ac45c507e guard), and
    // this door must refuse the direct API call the same way - a hunt
    // FOR A SPARE is the junk-queue class that guard names (release-eve
    // sweep S10). The health here is `doomed_row`'s own, so what is
    // proven is that the refusal is the `held_for` field and not the
    // verdict.
    let held = doomed_row(&r, &dir);
    {
        let mut g = held.lock_ok();
        g.nzo_id = "nzo-heldspare".into();
        g.held_for = "nzo-some-primary".into();
        g.paused = true;
    }
    d.queue.lock_ok().push_back(held);
    assert!(
        crate::hunt::hunt_offer(&d, "nzo-heldspare")
            .expect_err("a held spare is never hunted for")
            .contains("spare held for another download")
    );

    // And a row the runner already owns: the verdict this reads is taken
    // while the queue is idle, so refusing the race is cheaper than
    // winning it.
    let doomed = doomed_row(&r, &dir);
    doomed.lock_ok().state = JobState::Downloading;
    d.queue.lock_ok().push_back(doomed);
    assert!(
        crate::hunt::hunt_offer(&d, &r.nzo_id)
            .expect_err("a running row is the runner's")
            .contains("already started")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A handle is a DIGEST of what identifies a candidate, never its index
/// in the list: a list re-taken between the render and the click
/// renumbers, and an index then picks a different release than the one
/// under the cursor (§274's rule, same reason). Two candidates with the
/// same stem from two indexers are two different fetches and must not
/// collide, and an expired list answers "search again" rather than
/// guessing.
#[test]
fn a_pick_handle_names_the_candidate_and_not_its_position() {
    let dir = tdir("click-handle");
    let mk = |stem: &str, indexer: &str, url: &str| Cand {
        stem: stem.into(),
        rank: 1,
        posted: 0,
        size: 10,
        src: CandSrc::External {
            url: url.into(),
            indexer: indexer.into(),
            origin: SourceOrigin::default(),
        },
    };
    let a = mk(STEM, "one", "http://a/1");
    let b = mk(STEM, "two", "http://b/1");
    assert_ne!(a.key(), b.key(), "same stem, two indexers, two fetches");
    assert_eq!(a.key(), mk(STEM, "one", "http://a/1").key(), "and stable");

    let d = test_daemon(&dir);
    crate::hunt::hunt_remember(&d, "nzo-x", vec![a.clone()]);
    assert!(crate::hunt::hunt_remembered(&d, "nzo-x", &a.key()).is_some());
    assert!(
        crate::hunt::hunt_remembered(&d, "nzo-x", &b.key()).is_none(),
        "a handle that is not on this row's list resolves to nothing"
    );
    assert!(
        crate::hunt::hunt_remembered(&d, "nzo-other", &a.key()).is_none(),
        "and a list belongs to the row it was taken for"
    );
    // Past the TTL the list is not picked from: an indexer's answer is a
    // statement about right now.
    d.hunt.offers.lock_ok().get_mut("nzo-x").unwrap().at -= OFFER_TTL_SECS + 1;
    assert!(
        crate::hunt::hunt_remembered(&d, "nzo-x", &a.key()).is_none(),
        "stale list"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A row that has ALREADY FAILED, filed in history (§284).
///
/// **NO `health` OBJECT, and that absence is the test.** The queue road
/// reads `altcand::terminal_reason`, which needs a pre-flight probe -
/// and §284 item 2 is precisely about the job the incident actually
/// killed: one that died DURING the run, where no probe was ever taken.
/// The parked road judges the FAILURE instead, so it reaches this shape
/// where the queue road's evidence does not exist at all.
fn parked_row(r: &HuntRequest, dir: &Path) -> Arc<Mutex<Job>> {
    Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": r.nzo_id, "name": STEM, "origin": r.origin,
            "state": "Failed",
            "fail_message": REPAIR_FAIL,
            "finished_unix": 1000,
            "dupe_key": crate::dupe_key(STEM),
            "out_dir": dir.join("parked").to_string_lossy(),
            "nzb_path": r.nzb_path.to_string_lossy(),
        }))
        .expect("parked row"),
    ))
}

/// §284 end to end: search and pick from a row that is already in
/// HISTORY.
///
/// The seam this closes is one step further out than item 20's. That
/// item put the button on the doomed QUEUE row; the moment `park_gen`
/// retains a failed job out of the queue, every id in this module and in
/// `altcand` stopped resolving - so on a default install, where
/// `alt_auto_search` is off and the automatic road stands down, a job
/// that died during its run had no route to a replacement at all.
///
/// Three things are pinned, and none of them is plumbing:
/// the row is found with NO health object (see `parked_row` - the queue
/// road's own evidence does not exist for this shape), the pick goes
/// through the same `alt_switch` so item 14's clause is written by the
/// code that already writes it, and the abandoned record is left exactly
/// as it was apart from that clause - because it failed hours ago and
/// every reader has already acted on the verdict it carries.
#[test]
fn a_person_can_search_and_pick_from_a_row_that_has_already_failed() {
    let dir = tdir("parked-path");
    let (d, r) = staged_hunt(&dir);
    // OFF, on purpose: §284 item 2 IS the default install.
    d.alt.auto_search.store(false, Ordering::Relaxed);
    let dead = parked_row(&r, &dir);
    d.history.lock_ok().push(dead.clone());
    assert!(
        crate::altcand::terminal_reason(&dead.lock_ok()).is_none(),
        "the fixture must be the shape the queue road cannot see"
    );

    let offer = crate::hunt::hunt_offer(&d, &r.nzo_id).expect("the history row may search");
    let rows = offer["candidates"].as_array().expect("candidates");
    let names: Vec<&str> = rows
        .iter()
        .map(|c| c["name"].as_str().unwrap_or_default())
        .collect();
    assert!(
        names.contains(&FRESH_POST),
        "the survivor has to be offered: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("S01E06")),
        "a different episode is not this release: {names:?}"
    );
    assert!(names[0].ends_with("-SAME"), "best first: {names:?}");

    // Item 6's admission test is the same one, so the same post is
    // refused here too - and nothing is left on the queue by a refusal.
    let same_key = rows[0]["key"].as_str().expect("a handle").to_string();
    let err = crate::hunt::hunt_pick(&d, &r.nzo_id, &same_key)
        .expect_err("the same post must be refused");
    assert!(err.contains("same post"), "{err}");
    assert!(
        d.queue.lock_ok().is_empty(),
        "a refused pick leaves nothing"
    );

    let fresh_key = rows
        .iter()
        .find(|c| c["name"] == FRESH_POST)
        .and_then(|c| c["key"].as_str())
        .expect("a handle for the survivor")
        .to_string();
    let new_id = crate::hunt::hunt_pick(&d, &r.nzo_id, &fresh_key).expect("the pick lands");
    assert!(!new_id.is_empty());

    let queued: Vec<(String, i32, bool, String, String)> = d
        .queue
        .lock_ok()
        .iter()
        .map(|j| {
            let g = j.lock_ok();
            (
                g.name.clone(),
                g.priority,
                g.paused,
                g.origin.clone(),
                g.alt_from_name.clone(),
            )
        })
        .collect();
    assert_eq!(queued.len(), 1, "one replacement, running: {queued:?}");
    let (name, priority, paused, origin, from) = &queued[0];
    assert_eq!(name, FRESH_POST);
    assert_eq!(*priority, 0);
    assert!(!paused, "the replacement RUNS");
    assert_eq!(
        origin,
        &hunt_origin(&target_keys(&crate::wall::parse_release(STEM))[0]),
        "a hand-picked copy is charged to the same target budget a hunted one is"
    );
    assert_eq!(from, STEM, "the new row says what it replaced");

    // The abandoned record: one row, still one row, and unrewritten
    // apart from item 14's half that could not be known any earlier.
    let hist = d.history.lock_ok();
    assert_eq!(hist.len(), 1, "not filed a second time");
    let g = hist[0].lock_ok();
    assert_eq!(g.nzo_id, r.nzo_id);
    assert_eq!(g.alt_to_name, FRESH_POST, "it says what replaced it");
    assert_eq!(g.fail_message, REPAIR_FAIL, "its own verdict, unrewritten");
    assert_eq!(g.finished_unix, Some(1000), "and its own finished stamp");
    drop(g);
    drop(hist);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The parked door's own refusals, in `alt_switch`'s words.
///
/// `parked_replaceable` is asked by BOTH ends - the offer the drawer is
/// drawn from and this door - so a button that is on the page is a
/// button this door answers. What is pinned here is that the door really
/// does ask it, because the alternative is a search that spends an
/// indexer hit and then refuses at the pick.
#[test]
fn a_parked_row_another_copy_cannot_help_is_never_offered_a_search() {
    let dir = tdir("parked-noverdict");
    let (d, r) = staged_hunt(&dir);

    // In neither store: the queue road answers first and its sentence
    // is the one both doors say.
    assert!(
        crate::hunt::hunt_offer(&d, "nzo-nothing")
            .expect_err("an unknown id")
            .contains("no longer in the queue")
    );

    // In history, but a LOCAL fault: a second copy fails the same way,
    // so `fail_action` never says "search" and the offer is never drawn.
    let local = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-local", "name": STEM, "origin": "dashboard",
            "state": "Failed",
            "fail_message": "unpack failed: no space left on device",
            "out_dir": dir.join("l").to_string_lossy(),
            "nzb_path": r.nzb_path.to_string_lossy(),
        }))
        .expect("local row"),
    ));
    d.history.lock_ok().push(local);
    assert!(
        crate::hunt::hunt_offer(&d, "nzo-local")
            .expect_err("a local fault")
            .contains("no longer offered")
    );

    // ...and a job that COMPLETED has nothing to replace.
    let done = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-done", "name": STEM, "origin": "dashboard",
            "state": "Completed",
            "out_dir": dir.join("d").to_string_lossy(),
            "nzb_path": r.nzb_path.to_string_lossy(),
        }))
        .expect("done row"),
    ));
    d.history.lock_ok().push(done);
    assert!(
        crate::hunt::hunt_offer(&d, "nzo-done")
            .expect_err("a finished download")
            .contains("no longer offered")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A parked *arr row gets the same refusal a queued one gets.
///
/// Item 9 forbids the automatic hunt for a job Sonarr or Radarr sent,
/// item 20 extended that to the clicked road, and §284 changes WHERE the
/// row may be found and nothing about what happens to it - so a failed
/// *arr row must not be the hole in a rule that has now been decided
/// twice. Pinned rather than assumed: it is exactly one `if`, and this
/// is the third road that has had to reach it.
#[test]
fn a_parked_arr_row_is_refused_the_search_too() {
    let dir = tdir("parked-arr");
    let (d, r) = staged_hunt(&dir);
    let arr = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-arr", "name": STEM, "origin": "arr:sonarr",
            "state": "Failed",
            "fail_message": REPAIR_FAIL,
            "out_dir": dir.join("a").to_string_lossy(),
            "nzb_path": r.nzb_path.to_string_lossy(),
        }))
        .expect("arr row"),
    ));
    d.history.lock_ok().push(arr);
    let err = crate::hunt::hunt_offer(&d, "nzo-arr").expect_err("the *arr owns the retry");
    assert_eq!(err, NoHunt::ArrOwned.why(), "{err}");
    assert!(d.queue.lock_ok().is_empty(), "and nothing was queued");
    let _ = std::fs::remove_dir_all(&dir);
}
