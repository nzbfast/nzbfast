//! Unit tests for serve/daemon.rs (TODO 106 phase 3): the helpers the
//! serve/mod.rs test module does not already cover, exercised against
//! the in-memory `test_daemon` fixture where a Daemon is needed.

use super::*;

// Duplicate handling, moved out under the size gate (TODO 106).
//
// The explicit #[path] is load-bearing: this module is itself reached by
// `#[path = "daemon_tests.rs"]` from daemon.rs, and that makes rustc
// resolve ITS children against serve/ rather than serve/daemon_tests/ -
// so a bare `mod dupe_tests;` looks for serve/dupe_tests.rs and fails.
// The subdirectory is also what size-gate.py's CFG_TEST_MOD resolver
// checks (`<base>/<modname>.rs`), so the moved tests keep being read as
// test code rather than gated at the production ceiling.
#[path = "daemon_tests/dupe_tests.rs"]
mod dupe_tests;

#[path = "daemon_tests/notice_tests.rs"]
mod notice_tests;

// The read seam's stale-statement handling, out here for the same
// ceiling and with the same #[path] requirement.
#[cfg(feature = "indexer")]
#[path = "daemon_tests/index_read_tests.rs"]
mod index_read_tests;

// `park_gen`'s three generation-fence windows, out for the ceiling and
// carrying the same #[path] requirement.
#[path = "daemon_tests/park_gen_tests.rs"]
mod park_gen_tests;

// B5's queue window, out for the ceiling and carrying the same
// #[path] requirement.
#[path = "daemon_tests/queue_window_tests.rs"]
mod queue_window_tests;

// §74's instant kick and its lock ordering, moved out for the ceiling
// and carrying the same #[path] requirement.
#[cfg(feature = "indexer")]
#[path = "daemon_tests/instant_tests.rs"]
mod instant_tests;

// B4's connection hand-back and era gating, in their own file for the
// ceiling and carrying the same #[path] requirement.
#[cfg(feature = "indexer")]
#[path = "daemon_tests/handback_tests.rs"]
mod handback_tests;

// A4's index_stats TTL cache, same ceiling and #[path] requirement.
#[cfg(feature = "indexer")]
#[path = "daemon_tests/stats_cache_tests.rs"]
mod stats_cache_tests;

// N12's per-poll caches (owned title keys, enabled backbones), out for
// the ceiling and carrying the same #[path] requirement.
#[cfg(feature = "indexer")]
#[path = "daemon_tests/owned_cache_tests.rs"]
mod owned_cache_tests;

fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
    let dir = std::env::temp_dir().join(format!("nzbfast-dmn-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = super::super::testutil::test_daemon(&dir);
    f(&d);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

fn jv(id: &str, name: &str, extra: serde_json::Value) -> Arc<Mutex<Job>> {
    let mut v = serde_json::json!({
        "nzo_id": id, "name": name, "nzb_path": "/tmp/x.nzb",
        "out_dir": format!("/tmp/out/{id}"), "state": "Queued",
    });
    if let Some(m) = extra.as_object() {
        for (k, val) in m {
            v[k] = val.clone();
        }
    }
    Arc::new(Mutex::new(job_from_json(&v).expect("job_from_json")))
}

// -- find_job (pure) --------------------------------------------------------

#[test]
fn find_job_first_match_wins_and_clones_the_arc() {
    let a = jv("id-a", "first", serde_json::json!({}));
    let b = jv("id-a", "second", serde_json::json!({}));
    let c = jv("id-c", "third", serde_json::json!({}));
    let list = [a.clone(), b, c];

    let empty: Vec<Arc<Mutex<Job>>> = Vec::new();
    assert!(find_job(empty.iter(), "id-a").is_none());
    assert!(find_job(list.iter(), "id-x").is_none());

    let got = find_job(list.iter(), "id-a").expect("match");
    assert_eq!(got.lock_ok().name, "first", "duplicate ids: first wins");
    assert!(Arc::ptr_eq(&got, &a), "same Arc, cloned not copied");

    assert_eq!(
        find_job(list.iter(), "id-c").unwrap().lock_ok().name,
        "third"
    );
}

// -- OpenedLog gaps (mod.rs already covers coalesce/expiry/bounds) ----------

#[cfg(feature = "indexer")]
#[test]
fn opened_log_trim_is_a_noop_at_or_below_the_cap() {
    let mut m: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for i in 0..10 {
        m.insert(format!("k{i}"), i);
    }
    OpenedLog::trim(&mut m);
    assert_eq!(m.len(), 10, "well below the cap: untouched");

    let mut full: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for i in 0..OPENED_MAX_ENTRIES {
        full.insert(format!("k{i}"), i as i64);
    }
    OpenedLog::trim(&mut full);
    assert_eq!(
        full.len(),
        OPENED_MAX_ENTRIES,
        "exactly at the cap: untouched"
    );
}

#[cfg(feature = "indexer")]
#[test]
fn opened_log_trim_drops_oldest_to_exactly_the_cap() {
    let mut m: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for i in 0..(OPENED_MAX_ENTRIES + 7) {
        m.insert(format!("k{i}"), i as i64);
    }
    OpenedLog::trim(&mut m);
    assert_eq!(m.len(), OPENED_MAX_ENTRIES);
    for i in 0..7 {
        assert!(!m.contains_key(&format!("k{i}")), "oldest {i} dropped");
    }
    assert!(m.contains_key("k7"));
    assert!(m.contains_key(&format!("k{}", OPENED_MAX_ENTRIES + 6)));
}

#[cfg(feature = "indexer")]
#[test]
fn opened_log_expire_keeps_age_exactly_at_the_window() {
    let mut log = OpenedLog::default();
    let now = 1_700_000_000i64;
    let window = 100i64;
    log.titles.insert("t:edge".into(), now - window);
    log.titles.insert("t:past".into(), now - window - 1);
    log.releases.insert(1, now - window);
    log.releases.insert(2, now - window - 1);
    log.expire(now, window);
    assert!(log.titles.contains_key("t:edge"), "age == window is kept");
    assert!(!log.titles.contains_key("t:past"));
    assert!(log.releases.contains_key(&1));
    assert!(!log.releases.contains_key(&2));
}

// -- pause-reason ladders ---------------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn indexing_pause_reason_precedence_ladder() {
    with_daemon("idxreason", |d| {
        d.index_enabled.store(false, Ordering::Relaxed);
        d.index_paused.store(true, Ordering::Relaxed);
        d.index_pause_on_download.store(true, Ordering::Relaxed);
        d.index_jobs_active.store(1, Ordering::Release);
        d.queue
            .lock_ok()
            .push_back(jv("q1", "job", serde_json::json!({})));

        d.offline.store(true, Ordering::Relaxed);
        assert_eq!(
            d.indexing_pause_reason(),
            Some("offline"),
            "offline beats all"
        );

        d.offline.store(false, Ordering::Relaxed);
        assert_eq!(
            d.indexing_pause_reason(),
            Some("off"),
            "disabled beats paused"
        );

        d.index_enabled.store(true, Ordering::Relaxed);
        assert_eq!(d.indexing_pause_reason(), Some("paused"));

        d.index_paused.store(false, Ordering::Relaxed);
        assert_eq!(d.indexing_pause_reason(), Some("downloading"), "active job");

        d.index_jobs_active.store(0, Ordering::Release);
        assert_eq!(
            d.indexing_pause_reason(),
            Some("downloading"),
            "a queued runnable job counts before the runner picks it"
        );

        d.queue.lock_ok().clear();
        assert_eq!(d.indexing_pause_reason(), None);

        // With pause-on-download off, neither active nor queued work holds.
        d.index_pause_on_download.store(false, Ordering::Relaxed);
        d.index_jobs_active.store(1, Ordering::Release);
        d.queue
            .lock_ok()
            .push_back(jv("q2", "job2", serde_json::json!({})));
        assert_eq!(d.indexing_pause_reason(), None);
    });
}

#[cfg(feature = "indexer")]
#[test]
fn spot_pause_reason_same_shape_reads_index_paused() {
    with_daemon("spotreason", |d| {
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.index_paused.store(true, Ordering::Relaxed);
        d.index_pause_on_download.store(true, Ordering::Relaxed);
        d.index_jobs_active.store(1, Ordering::Release);

        d.offline.store(true, Ordering::Relaxed);
        assert_eq!(d.spot_pause_reason(), Some("offline"));

        d.offline.store(false, Ordering::Relaxed);
        assert_eq!(d.spot_pause_reason(), Some("off"));

        d.spot_enabled.store(true, Ordering::Relaxed);
        // The spot leg honors the INDEX pause switch.
        assert_eq!(d.spot_pause_reason(), Some("paused"));

        d.index_paused.store(false, Ordering::Relaxed);
        assert_eq!(d.spot_pause_reason(), Some("downloading"));

        d.index_jobs_active.store(0, Ordering::Release);
        d.queue
            .lock_ok()
            .push_back(jv("q1", "job", serde_json::json!({})));
        assert_eq!(d.spot_pause_reason(), Some("downloading"));

        d.queue.lock_ok().clear();
        assert_eq!(d.spot_pause_reason(), None);
    });
}

/// Every reason either ladder can produce has to have a phrase of its
/// own. The scan legs print `pause_phrase(reason)` and nothing else, so
/// a reason word added to the ladders without one falls through to the
/// generic arm and the log goes back to saying nothing - which is the
/// whole 11 Aug 2026 failure, arrived at from the other direction.
#[cfg(feature = "indexer")]
#[test]
fn every_pause_reason_has_its_own_phrase() {
    let mut seen: Vec<(&str, &str)> = Vec::new();
    with_daemon("pausephrase", |d| {
        d.index_pause_on_download.store(true, Ordering::Relaxed);
        // Walk both ladders top to bottom, collecting what they say.
        let ladder: [(&str, &dyn Fn(&Arc<Daemon>)); 4] = [
            ("offline", &|d: &Arc<Daemon>| {
                d.offline.store(true, Ordering::Relaxed)
            }),
            ("off", &|d: &Arc<Daemon>| {
                d.offline.store(false, Ordering::Relaxed);
                d.index_enabled.store(false, Ordering::Relaxed);
                d.spot_enabled.store(false, Ordering::Relaxed);
            }),
            ("paused", &|d: &Arc<Daemon>| {
                d.index_enabled.store(true, Ordering::Relaxed);
                d.spot_enabled.store(true, Ordering::Relaxed);
                d.index_paused.store(true, Ordering::Relaxed);
            }),
            ("downloading", &|d: &Arc<Daemon>| {
                d.index_paused.store(false, Ordering::Relaxed);
                d.index_jobs_active.store(1, Ordering::Release);
            }),
        ];
        for (want, set) in ladder {
            set(d);
            assert_eq!(d.indexing_pause_reason(), Some(want));
            assert_eq!(d.spot_pause_reason(), Some(want));
            let phrase = Daemon::pause_phrase(want);
            assert_ne!(
                phrase, "standing down",
                "{want} fell through to the generic arm"
            );
            seen.push((want, phrase));
        }
    });
    for (i, (reason, phrase)) in seen.iter().enumerate() {
        assert!(
            !seen[..i].iter().any(|(_, p)| p == phrase),
            "{reason} shares a phrase with an earlier reason: {phrase}"
        );
    }
}

#[cfg(feature = "indexer")]
#[test]
fn index_db_wanted_when_either_switch_is_on() {
    with_daemon("dbwanted", |d| {
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        assert!(!d.index_db_wanted());
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(d.index_db_wanted());
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(true, Ordering::Relaxed);
        assert!(d.index_db_wanted());
    });
}

#[cfg(feature = "indexer")]
#[test]
fn predb_feed_needs_both_switches() {
    with_daemon("predbon", |d| {
        d.predb_enabled.store(true, Ordering::Relaxed);
        d.index_enabled.store(false, Ordering::Relaxed);
        assert!(!d.predb_feed_on());
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(d.predb_feed_on());
        d.predb_enabled.store(false, Ordering::Relaxed);
        assert!(!d.predb_feed_on());
    });
}

#[test]
fn queue_has_runnable_wants_queued_and_unpaused() {
    with_daemon("runnable", |d| {
        assert!(!d.queue_has_runnable(), "empty queue");
        d.queue
            .lock_ok()
            .push_back(jv("a", "a", serde_json::json!({"paused": true})));
        assert!(!d.queue_has_runnable(), "paused does not count");
        d.queue
            .lock_ok()
            .push_back(jv("b", "b", serde_json::json!({"state": "Completed"})));
        assert!(!d.queue_has_runnable(), "non-Queued does not count");
        d.queue
            .lock_ok()
            .push_back(jv("c", "c", serde_json::json!({})));
        assert!(d.queue_has_runnable());
    });
}

#[cfg(feature = "indexer")]
#[test]
fn index_maintenance_needs_no_reason_and_no_active_job() {
    with_daemon("maint", |d| {
        d.index_enabled.store(false, Ordering::Relaxed);
        d.index_paused.store(false, Ordering::Relaxed);
        d.index_pause_on_download.store(false, Ordering::Relaxed);
        assert!(!d.index_maintenance_ok(), "indexing off is a reason");

        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(d.index_maintenance_ok());

        // A job in flight blocks maintenance even when the pause-on-download
        // preference is off and the reason ladder answers None.
        d.index_jobs_active.store(1, Ordering::Release);
        assert_eq!(d.indexing_pause_reason(), None);
        assert!(!d.index_maintenance_ok());
        d.index_jobs_active.store(0, Ordering::Release);
        assert!(d.index_maintenance_ok());
    });
}

// -- pick_job / held_as_duplicate -------------------------------------------

#[test]
fn pick_job_priority_desc_then_fifo() {
    with_daemon("pickjob", |d| {
        assert!(d.pick_job(false).is_none(), "empty queue");

        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv("n1", "normal-1", serde_json::json!({"priority": 0})));
            q.push_back(jv("n2", "normal-2", serde_json::json!({"priority": 0})));
            q.push_back(jv("hi", "high", serde_json::json!({"priority": 1})));
            q.push_back(jv(
                "hp",
                "high-paused",
                serde_json::json!({"priority": 5, "paused": true}),
            ));
        }
        let got = d.pick_job(false).expect("pick");
        assert_eq!(got.lock_ok().nzo_id, "hi", "highest runnable priority wins");

        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != "hi");
        let got = d.pick_job(false).expect("pick");
        assert_eq!(got.lock_ok().nzo_id, "n1", "FIFO within a priority");

        // Per-job pause always holds a job back, whatever its priority.
        d.queue.lock_ok().retain(|j| {
            let g = j.lock_ok();
            g.nzo_id == "hp"
        });
        assert!(d.pick_job(false).is_none());
    });
}

#[test]
fn pick_job_force_runs_through_a_queue_pause() {
    with_daemon("pickforce", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv("n1", "normal", serde_json::json!({"priority": 1})));
            q.push_back(jv("f1", "forced", serde_json::json!({"priority": 2})));
        }
        assert_eq!(
            d.pick_job(true).expect("pick").lock_ok().nzo_id,
            "f1",
            "only Force (2) runs while the queue is paused"
        );
        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != "f1");
        assert!(d.pick_job(true).is_none());
        assert!(d.pick_job(false).is_some());
    });
}

#[test]
fn pick_job_deferred_runs_only_when_nothing_else_can() {
    with_daemon("pickdefer", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "df",
                "slow",
                serde_json::json!({"priority": 5, "deferred": true}),
            ));
            q.push_back(jv("ok", "fresh", serde_json::json!({"priority": 0})));
        }
        assert_eq!(
            d.pick_job(false).expect("pick").lock_ok().nzo_id,
            "ok",
            "deferred loses to any runnable job regardless of priority"
        );
        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id == "df");
        assert_eq!(d.pick_job(false).expect("pick").lock_ok().nzo_id, "df");
    });
}

/// §129 4a: an add announces itself on the event ring BEFORE the job
/// can be picked, so no consumer ever sees a job start before it
/// exists. The runner picks under the queue lock (`pick_job`), which is
/// the lock `enqueue` emits under - a picker spinning as fast as it can
/// must still land behind the job.added. Regression: the emit used to
/// sit after the push and after `save_queue`, and a loaded box really
/// did put job.started on the ring first (seq 1, 54 ms early).
#[test]
fn an_add_is_on_the_event_ring_before_the_job_can_be_picked() {
    with_daemon("addbeforepick", |d| {
        let picker = {
            let d = d.clone();
            std::thread::spawn(move || {
                // Stands in for the runner's pick arm: spin on pick_job
                // and emit job.started the moment one appears, the same
                // order tasks.rs uses (claim the job, then emit).
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while std::time::Instant::now() < deadline {
                    if let Some(j) = d.pick_job(false) {
                        let mut g = j.lock_ok();
                        g.state = JobState::Downloading;
                        d.life_emit("job.started", serde_json::json!({"nzo_id": g.nzo_id}));
                        return true;
                    }
                    std::thread::yield_now();
                }
                false
            })
        };
        let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                   <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                   <groups><group>g</group></groups><segments>\
                   <segment bytes=\"1000\" number=\"1\">ord1@x</segment>\
                   </segments></file></nzb>";
        d.enqueue(
            nzb.as_bytes(),
            "Order.Test.nzb",
            "",
            0,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
        assert!(picker.join().expect("picker thread"), "nothing was picked");

        let ring: Vec<(String, u64)> = d
            .life_events
            .lock_ok()
            .iter()
            .map(|e| {
                (
                    e["kind"].as_str().unwrap_or_default().to_string(),
                    e["seq"].as_u64().unwrap_or(0),
                )
            })
            .collect();
        let at = |kind: &str| {
            ring.iter()
                .position(|(k, _)| k == kind)
                .unwrap_or_else(|| panic!("no {kind} on the ring: {ring:?}"))
        };
        let (added, started) = (at("job.added"), at("job.started"));
        assert!(added < started, "job.started outran job.added: {ring:?}");
        // Ring order and seq order are the same claim; a fix that
        // reserved a seq early but pushed late would break this half.
        assert!(
            ring[added].1 < ring[started].1,
            "seq out of order: {ring:?}"
        );
    });
}

/// §129 2b: real per-category behavior - the category's default
/// priority fills a default add (explicit wins), its dir renames the
/// subfolder (contained, sanitized), and script resolution runs
/// job-override, then category, then global.
#[test]
fn cat_meta_priority_dir_and_script_apply() {
    with_daemon("catmeta", |d| {
        use super::CatMeta;
        d.cat_meta.lock_ok().insert(
            "tv".into(),
            CatMeta {
                dir: "series/current".into(),
                priority: Some(1),
                script: "/scripts/tv.py".into(),
                nzb_name: None,
            },
        );
        // dir: the category's subfolder is renamed, nested, contained.
        let base = d.base_out_dir("tv", "job");
        assert_eq!(base, d.out_dir().join("series").join("current").join("job"));
        // A traversal in the meta dir cannot escape the root.
        d.cat_meta.lock_ok().get_mut("tv").unwrap().dir = "../../evil".into();
        assert_eq!(
            d.base_out_dir("tv", "job"),
            d.out_dir().join("evil").join("job")
        );
        d.cat_meta.lock_ok().get_mut("tv").unwrap().dir = "series/current".into();
        // No meta = the old shape, untouched.
        assert_eq!(
            d.base_out_dir("movies", "job"),
            d.out_dir().join("movies").join("job")
        );
        assert_eq!(d.base_out_dir("", "job"), d.out_dir().join("job"));

        // priority: fills the default, loses to an explicit one.
        let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                   <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                   <groups><group>g</group></groups><segments>\
                   <segment bytes=\"1000\" number=\"1\">cm1@x</segment>\
                   </segments></file></nzb>";
        let id = d
            .enqueue(
                nzb.as_bytes(),
                "Alpha.2026.nzb",
                "tv",
                -100,
                None,
                None,
                "test",
                false,
            )
            .unwrap();
        let nzb2 = nzb.replace("cm1@x", "cm2@x");
        let id2 = d
            .enqueue(
                nzb2.as_bytes(),
                "Beta.2026.nzb",
                "tv",
                -1,
                None,
                None,
                "test",
                false,
            )
            .unwrap();
        {
            let q = d.queue.lock_ok();
            let prio = |id: &str| {
                q.iter()
                    .find(|j| j.lock_ok().nzo_id == *id)
                    .map(|j| j.lock_ok().priority)
                    .unwrap()
            };
            assert_eq!(prio(&id), 1, "category default fills a default add");
            assert_eq!(prio(&id2), -1, "an explicit priority wins");
        }

        // script resolution order.
        let job = d
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == id)
            .cloned()
            .unwrap();
        let one = |p: &str| vec![std::path::PathBuf::from(p)];
        assert_eq!(
            d.resolve_scripts(&job),
            one("/scripts/tv.py"),
            "category script beats the (unset) global"
        );
        *d.scripts.lock_ok() = one("/scripts/global.py");
        job.lock_ok().category = "movies".into();
        assert_eq!(
            d.resolve_scripts(&job),
            one("/scripts/global.py"),
            "no category script falls back to the global one"
        );
        job.lock_ok().script_override = "/scripts/mine.py".into();
        assert_eq!(
            d.resolve_scripts(&job),
            one("/scripts/mine.py"),
            "the job's own script= wins"
        );
        // §192: a rung is a CHAIN, and the first rung with anything
        // wins WHOLE - the category's chain does not append to the
        // global one.
        job.lock_ok().script_override = "/scripts/a.py,/scripts/b.py".into();
        assert_eq!(
            d.resolve_scripts(&job),
            vec![
                std::path::PathBuf::from("/scripts/a.py"),
                std::path::PathBuf::from("/scripts/b.py"),
            ],
            "the override chain runs in the order it was written"
        );
        job.lock_ok().script_override = "None".into();
        assert!(
            d.resolve_scripts(&job).is_empty(),
            "script=None means none at all"
        );

        // record_add_params: pp + script land on the job. A bare name
        // is what a SAB client sends back from mode=get_scripts, so it
        // resolves through known_scripts to the real path - stored
        // verbatim it became a cwd-relative path that ran nothing.
        // (§129 4a: record_add_params FILLS, never clobbers - at add
        // time these fields are empty unless the pre-queue hook set
        // them, and the hook outranks the request. Clear the values the
        // resolve_scripts cases above planted.)
        {
            let g = job_by(d, &id);
            let mut g = g.lock_ok();
            g.script_override = String::new();
            g.sab_pp = None;
        }
        d.record_add_params(&id, Some("1"), Some("tv.py"), false);
        {
            let g = job_by(d, &id);
            let g = g.lock_ok();
            assert_eq!(g.sab_pp, Some(1));
            assert_eq!(g.script_override, "/scripts/tv.py");
        }
        // ...and known_scripts is exactly what get_scripts offers:
        // global + per-category, deduped by basename, global first.
        let names: Vec<String> = d.known_scripts().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["global.py", "tv.py"]);
        // An unknown name is a logged compatibility note, never a
        // stored override - the category/global ladder stays in charge.
        // (Also the fill-only rule doing its other job: refusing can
        // never become a way to CLEAR an existing override.)
        d.record_add_params(&id, None, Some("ghost.py"), false);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "/scripts/tv.py");
        // §129 4a: fill-only in general - once set (at add time that
        // means the pre-queue hook set it), the request's own script=
        // does not displace it. The hook outranks the request, SAB
        // pre-queue semantics.
        d.record_add_params(&id, None, Some("/elsewhere/mine.py"), false);
        assert_eq!(
            job_by(d, &id).lock_ok().script_override,
            "/scripts/tv.py",
            "a planted override survives the request's script="
        );
        let clear = || job_by(d, &id).lock_ok().script_override = String::new();
        // A path-bearing value is operator intent and stays as written.
        clear();
        d.record_add_params(&id, None, Some("/elsewhere/mine.py"), false);
        assert_eq!(
            job_by(d, &id).lock_ok().script_override,
            "/elsewhere/mine.py"
        );
        // ...but ONLY for a full-key caller. `addfile`/`addurl` are on
        // the add-only allowlist and `resolve_scripts` hands
        // `script_override` straight to `Command::new` on the job tail,
        // so accepting a path here let the NZB key - which ships to
        // browser push extensions - choose which program the daemon
        // runs. The previous override must survive untouched: refusing
        // must not become a way to CLEAR someone else's setting.
        d.record_add_params(&id, None, Some("/tmp/pwn.sh"), true);
        assert_eq!(
            job_by(d, &id).lock_ok().script_override,
            "/elsewhere/mine.py",
            "an add-only credential may not choose the program to run"
        );
        // A configured name is still fine on the add-only key: it can
        // only select something the operator already installed.
        clear();
        d.record_add_params(&id, None, Some("tv.py"), true);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "/scripts/tv.py");
        // SAB's own null still suppresses the whole ladder.
        clear();
        d.record_add_params(&id, None, Some("None"), false);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "None");
        assert!(d.resolve_scripts(&job_by(d, &id)).is_empty());
    });
}

/// A job that never reached the QUEUE still keeps the add's `pp=` and
/// `script=`.
///
/// A pre-queue reject and dupe_action="fail" both answer the add with an
/// id and file the record straight to history, and `record_add_params`
/// searched the queue alone - so those two paths dropped the caller's
/// post-processing parameters on the floor. The record is what a History
/// retry brings back, so it has to carry them (M15, 10 Aug sweep).
#[test]
fn add_params_reach_a_job_that_went_straight_to_history() {
    with_daemon("addparams-history", |d| {
        let job = jv("hist-1", "Rejected.Release", serde_json::json!({}));
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "rejected by the pre-queue script".into();
        }
        d.history.lock_ok().push(job.clone());

        d.record_add_params("hist-1", Some("2"), Some("/scripts/mine.py"), false);
        {
            let g = job.lock_ok();
            assert_eq!(g.sab_pp, Some(2), "pp= was lost on the history path");
            assert_eq!(g.script_override, "/scripts/mine.py");
        }
        // ...and it reached the store, not just the in-memory record.
        let stored = std::fs::read_to_string(d.history_store_path()).unwrap_or_default();
        assert!(
            stored.contains("/scripts/mine.py"),
            "the history record was not persisted: {stored:?}"
        );
    });
}

fn job_by(d: &Arc<Daemon>, id: &str) -> Arc<Mutex<Job>> {
    d.queue
        .lock_ok()
        .iter()
        .find(|j| j.lock_ok().nzo_id == id)
        .cloned()
        .unwrap()
}

// -- event ring / speed ceiling ---------------------------------------------

#[test]
fn event_ring_caps_at_256_dropping_oldest_and_lists_newest_first() {
    with_daemon("events", |d| {
        for i in 0..300 {
            d.note_event("pause", format!("e{i}"));
        }
        assert_eq!(d.events.lock_ok().len(), 256);

        let all = d.recent_events(1000);
        assert_eq!(all.len(), 256);
        assert_eq!(all[0].detail, "e299", "newest first");
        assert_eq!(all[255].detail, "e44", "oldest 44 dropped");

        let two = d.recent_events(2);
        assert_eq!(two.len(), 2, "limit honored");
        assert_eq!(two[0].detail, "e299");
        assert_eq!(two[1].detail, "e298");
    });
}

#[test]
fn speed_ceiling_notes_changes_only_and_names_the_source() {
    with_daemon("ceiling", |d| {
        d.set_speed_ceiling_from(1_000_000, "schedule");
        assert_eq!(d.speed_ceiling.load(Ordering::Relaxed), 1_000_000);
        assert_eq!(*d.limit_source.lock_ok(), "schedule");
        let ev = d.recent_events(1);
        assert_eq!(ev[0].kind, "limit");
        assert_eq!(ev[0].detail, "speed limit set to 1.0 MB/s by the schedule");

        // Re-applying the number in force is not a change.
        d.set_speed_ceiling_from(1_000_000, "schedule");
        assert_eq!(d.recent_events(10).len(), 1);

        d.set_speed_ceiling_from(0, "api");
        assert_eq!(
            d.recent_events(1)[0].detail,
            "speed limit removed by an API client"
        );

        d.set_speed_ceiling(2_000_000);
        assert_eq!(d.recent_events(1)[0].detail, "speed limit set to 2.0 MB/s");
        assert_eq!(*d.limit_source.lock_ok(), "user");
    });
}

// -- stream token / cat list / rename style ---------------------------------

#[test]
fn stream_token_is_deterministic_32_char_lowercase_hex() {
    with_daemon("token", |d| {
        let t1 = d.stream_token("SABnzbd_nzo_1");
        let t2 = d.stream_token("SABnzbd_nzo_1");
        let t3 = d.stream_token("SABnzbd_nzo_2");
        assert_eq!(t1, t2, "deterministic per nzo_id");
        assert_ne!(t1, t3, "different jobs, different tokens");
        assert_eq!(t1.len(), 32);
        assert!(
            t1.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    });
}

#[test]
fn cat_list_is_sorted_star_filtered_comma_joined() {
    with_daemon("catlist", |d| {
        {
            let mut cats = d.cats.lock_ok();
            cats.clear();
            for c in ["tv", "*", "movies", "books"] {
                cats.insert(c.to_string());
            }
        }
        assert_eq!(d.cat_list(), "books, movies, tv");
    });
}

#[test]
fn rename_style_mirrors_every_toggle() {
    with_daemon("style", |d| {
        let flags: [(
            &std::sync::atomic::AtomicBool,
            fn(&crate::wall::NameStyle) -> bool,
        ); 8] = [
            (&d.rename_resolution, |s| s.resolution),
            (&d.rename_vcodec, |s| s.video_codec),
            (&d.rename_acodec, |s| s.audio_codec),
            (&d.rename_source, |s| s.source),
            (&d.rename_group, |s| s.group),
            (&d.rename_year_parens, |s| s.year_parens),
            (&d.rename_quality_brackets, |s| s.quality_brackets),
            (&d.rename_extra_words, |s| s.extra_words),
        ];
        for (atomic, _) in &flags {
            atomic.store(false, Ordering::Relaxed);
        }
        for (i, (atomic, read)) in flags.iter().enumerate() {
            atomic.store(true, Ordering::Relaxed);
            let s = d.rename_style();
            assert!(read(&s), "toggle {i} sets its mirrored field");
            for (j, (_, other)) in flags.iter().enumerate() {
                assert_eq!(other(&s), i == j, "toggle {i} flips exactly field {j}");
            }
            atomic.store(false, Ordering::Relaxed);
        }
    });
}

#[test]
fn job_suffix_is_empty_with_auto_rename_off() {
    with_daemon("suffix", |d| {
        d.auto_rename.store(false, Ordering::Relaxed);
        assert_eq!(d.job_suffix("Movie.2020.1080p.x264-GRP"), "");

        d.auto_rename.store(true, Ordering::Relaxed);
        d.rename_resolution.store(true, Ordering::Relaxed);
        for a in [
            &d.rename_vcodec,
            &d.rename_acodec,
            &d.rename_source,
            &d.rename_group,
            &d.rename_quality_brackets,
        ] {
            a.store(false, Ordering::Relaxed);
        }
        assert_eq!(d.job_suffix("Movie.2020.1080p.x264-GRP"), " 1080p");
    });
}

// -- indexer accounts / tri-state -------------------------------------------

#[test]
fn enabled_indexers_counts_only_enabled_and_drives_the_tri_state() {
    with_daemon("tristate", |d| {
        let mk = |name: &str, enabled: bool| crate::newznab::IndexerConfig {
            name: name.into(),
            url: "http://indexer.test".into(),
            apikey: String::new(),
            enabled,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        };
        d.watchlist_external_set.store(false, Ordering::Relaxed);
        assert_eq!(d.enabled_indexers(), 0);
        assert!(!d.watchlist_external_on(), "unset + no accounts = off");

        d.indexers.lock_ok().push(mk("a", false));
        assert_eq!(d.enabled_indexers(), 0);
        assert!(!d.watchlist_external_on());

        d.indexers.lock_ok().push(mk("b", true));
        assert_eq!(d.enabled_indexers(), 1);
        assert!(d.watchlist_external_on(), "unset + an account = on");

        // An explicit answer wins over the fallback in both directions.
        d.watchlist_external_set.store(true, Ordering::Relaxed);
        d.watchlist_external.store(false, Ordering::Relaxed);
        assert!(!d.watchlist_external_on());
        d.watchlist_external.store(true, Ordering::Relaxed);
        d.indexers.lock_ok().clear();
        assert!(d.watchlist_external_on());
    });
}

#[test]
fn scoreboard_reference_prefers_the_named_account_and_never_falls_through() {
    with_daemon("sbref", |d| {
        let mk = |name: &str, enabled: bool| crate::newznab::IndexerConfig {
            name: name.into(),
            url: "https://geek.test".into(),
            apikey: "k1".into(),
            enabled,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        };
        // Nothing configured at all: the ask-the-user message.
        assert!(d.scoreboard_reference().is_err());

        // Manual pair only - the pre-existing shape still works.
        *d.scoreboard_url.lock_ok() = "https://manual.test".into();
        *d.scoreboard_key.lock_ok() = Some("mk".into());
        assert_eq!(
            d.scoreboard_reference(),
            Ok(("https://manual.test".into(), "mk".into()))
        );

        // A named account wins over the manual pair, key included.
        d.indexers.lock_ok().push(mk("geek", true));
        *d.scoreboard_source.lock_ok() = "geek".into();
        assert_eq!(
            d.scoreboard_reference(),
            Ok(("https://geek.test".into(), "k1".into()))
        );

        // Disabled or deleted, the named pick is an ERROR - never a
        // silent fall-through to the manual pair, and never traffic to
        // an account the user turned off.
        d.indexers.lock_ok()[0].enabled = false;
        assert!(d.scoreboard_reference().unwrap_err().contains("turned off"));
        d.indexers.lock_ok().clear();
        assert!(
            d.scoreboard_reference()
                .unwrap_err()
                .contains("no longer in your indexer list")
        );
    });
}

/// The confirm lane's stats card mirrors `corr_confirm_reference`'s
/// verdict as four DISTINCT states: the picker deliberately keeps a
/// vanished account listed, so present-and-enabled, disabled, deleted
/// and empty must each be tellable apart - a card that only knows
/// "string present" says "0 of 24 checks used" while every tick is
/// refused.
#[test]
fn corr_confirm_source_state_tells_the_four_states_apart() {
    with_daemon("ccfstate", |d| {
        let mk = |name: &str, enabled: bool| crate::newznab::IndexerConfig {
            name: name.into(),
            url: "https://geek.test".into(),
            apikey: "k1".into(),
            enabled,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        };
        // Empty pick.
        assert_eq!(d.corr_confirm_source_state(), "none");
        assert!(d.corr_confirm_reference().is_err());

        // Present and enabled.
        d.indexers.lock_ok().push(mk("geek", true));
        *d.corr_confirm_source.lock_ok() = "geek".into();
        assert_eq!(d.corr_confirm_source_state(), "ok");
        assert!(d.corr_confirm_reference().is_ok());

        // Turned off: the string is still there, the state is not ok.
        d.indexers.lock_ok()[0].enabled = false;
        assert_eq!(d.corr_confirm_source_state(), "disabled");
        assert!(
            d.corr_confirm_reference()
                .unwrap_err()
                .contains("turned off")
        );

        // Deleted: distinct from turned off.
        d.indexers.lock_ok().clear();
        assert_eq!(d.corr_confirm_source_state(), "missing");
        assert!(
            d.corr_confirm_reference()
                .unwrap_err()
                .contains("no longer in your indexer list")
        );
    });
}

// -- evict policy / predb config --------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn evict_policy_unknown_order_falls_back_to_ladder() {
    with_daemon("evict", |d| {
        *d.index_evict_order.lock_ok() = "bogus".to_string();
        *d.index_evict_kinds.lock_ok() = vec!["movie".to_string()];
        let p = d.evict_policy();
        assert!(matches!(p.order, nzbkit::index::EvictOrder::Ladder));
        assert_eq!(p.kinds, vec!["movie".to_string()]);

        *d.index_evict_order.lock_ok() = "largest".to_string();
        assert!(matches!(
            d.evict_policy().order,
            nzbkit::index::EvictOrder::Largest
        ));
    });
}

#[cfg(feature = "indexer")]
#[test]
fn predb_irc_config_parses_every_address_form() {
    with_daemon("predbcfg", |d| {
        let cfg_for = |server: &str| {
            *d.predb_server.lock_ok() = server.to_string();
            d.predb_irc_config()
        };
        let c = cfg_for("irc.example.net");
        assert_eq!(c.host, "irc.example.net");
        assert_eq!(c.port, nzbkit::predb::DEFAULT_PORT);

        let c = cfg_for("irc.example.net:7000");
        assert_eq!((c.host.as_str(), c.port), ("irc.example.net", 7000));

        let c = cfg_for("[2001:db8::1]");
        assert_eq!(c.host, "2001:db8::1");
        assert_eq!(c.port, nzbkit::predb::DEFAULT_PORT);

        let c = cfg_for("[2001:db8::1]:7000");
        assert_eq!((c.host.as_str(), c.port), ("2001:db8::1", 7000));

        // Non-numeric port: the WHOLE raw string stays the host.
        let c = cfg_for("irc.example.net:junk");
        assert_eq!(c.host, "irc.example.net:junk");
        assert_eq!(c.port, nzbkit::predb::DEFAULT_PORT);

        let c = cfg_for("");
        assert_eq!(c.host, nzbkit::predb::DEFAULT_HOST);
        assert_eq!(c.port, nzbkit::predb::DEFAULT_PORT);

        *d.predb_channels.lock_ok() = " #pre , ,#spam,  ".to_string();
        *d.predb_nick.lock_ok() = "nick".to_string();
        let c = d.predb_irc_config();
        assert_eq!(c.channels, vec!["#pre".to_string(), "#spam".to_string()]);
        assert_eq!(c.nick, "nick");
        assert!(c.tls);
    });
}

// -- usage / reliability ledgers --------------------------------------------

#[test]
fn usage_ledger_accumulates_and_skips_zero_entries() {
    with_daemon("usage", |d| {
        assert_eq!(d.usage_lifetime("s1.example"), 0);
        d.add_usage(&[("s1.example".into(), 100), ("s2.example".into(), 0)]);
        assert_eq!(d.usage_lifetime("s1.example"), 100);
        assert_eq!(d.usage_lifetime("s2.example"), 0, "zero bytes never billed");
        d.add_usage(&[("s1.example".into(), 50)]);
        assert_eq!(d.usage_lifetime("s1.example"), 150);
        assert!(d.spool.join("usage.json").exists(), "persisted to spool");
    });
}

/// §96.5: a refill restarts the block-used counter without rewinding
/// the lifetime ledger - the ledger also answers the history totals
/// and `jobs_ever`, so the two must be able to disagree.
#[test]
fn block_refill_restarts_the_counter_but_never_the_ledger() {
    with_daemon("blockbase", |d| {
        d.add_usage(&[("blk.example".into(), 700)]);
        assert_eq!(d.block_spent("blk.example"), 700);
        d.block_refilled("blk.example");
        assert_eq!(
            d.block_spent("blk.example"),
            0,
            "refill restarts the counter"
        );
        assert_eq!(
            d.usage_lifetime("blk.example"),
            700,
            "the lifetime ledger is never rewound"
        );
        d.add_usage(&[("blk.example".into(), 300)]);
        assert_eq!(d.block_spent("blk.example"), 300);
        assert_eq!(d.usage_lifetime("blk.example"), 1000);
        // Persisted: the base must survive a restart or the refill
        // un-happens the next time the daemon loads usage.json.
        let disk = crate::persist::load_json_with_backup(&d.spool.join("usage.json")).unwrap();
        assert_eq!(
            disk.get("block_base")
                .and_then(|b| b.get("blk.example"))
                .and_then(|v| v.as_u64()),
            Some(700)
        );
    });
}

/// §96.5: the mid-job usage flush bills only the delta since the last
/// call, at any cadence - so the periodic tick and the net-drain call
/// can both run without double-billing a paid block.
#[test]
fn flush_run_usage_delta_bills_and_never_double_bills() {
    with_daemon("usageflush", |d| {
        let sc: nzbkit::config::ServerConfig =
            serde_json::from_str(r#"{"host":"blk.example"}"#).unwrap();
        let live =
            nzbkit::pool::LiveStats::for_servers(&[(sc, nzbkit::pool::PoolConfig::default())]);
        live.servers[0].bytes.store(500, Ordering::Relaxed);
        *d.hub.pool_live.lock_ok() = Some(live.clone());
        d.flush_run_usage();
        assert_eq!(d.usage_lifetime("blk.example"), 500);
        d.flush_run_usage();
        assert_eq!(
            d.usage_lifetime("blk.example"),
            500,
            "an unmoved counter must bill nothing"
        );
        live.servers[0].bytes.store(800, Ordering::Relaxed);
        d.flush_run_usage(); // the net-drain call is this same helper
        assert_eq!(d.usage_lifetime("blk.example"), 800);
        // Job boundary: pool cleared first, then the high-water map -
        // a flush tick in that gap sees no pool and bills nothing.
        *d.hub.pool_live.lock_ok() = None;
        d.run_usage_flushed.lock_ok().clear();
        d.flush_run_usage();
        assert_eq!(d.usage_lifetime("blk.example"), 800);
    });
}

/// §129 4c: the second empty state must not come back once a job has
/// run. Clearing history is the case that broke a naive "is the queue
/// empty right now" check, so the sticky term is asserted on its own -
/// with the queue and history both empty, which is exactly the state a
/// user who cleared everything is in.
#[test]
fn jobs_ever_is_sticky_across_a_cleared_history() {
    with_daemon("jobsever", |d| {
        assert!(!d.jobs_ever(), "a fresh install has never downloaded");
        // A completed download bills the lifetime bucket...
        d.add_usage(&[("s1.example".into(), 4096)]);
        assert!(d.jobs_ever(), "billed bytes say a job has run");
        // ...and the bucket outlives an emptied queue and history.
        d.queue.lock_ok().clear();
        d.history.lock_ok().clear();
        assert!(
            d.jobs_ever(),
            "clearing history must not send a working install back to onboarding"
        );
    });
}

/// The other half: a job that failed before it billed a single byte
/// still ends the empty state, because it is in history.
#[test]
fn jobs_ever_answers_off_history_alone() {
    with_daemon("jobsever-hist", |d| {
        assert!(!d.jobs_ever());
        let j = crate::serve::tests_jobs::job(serde_json::json!({
            "nzo_id": "abc", "name": "Some.Show.S01E01", "nzb_path": "/spool/a.nzb",
            "state": "Failed", "out_dir": "/dl/a",
        }));
        d.history
            .lock_ok()
            .push(std::sync::Arc::new(std::sync::Mutex::new(j)));
        assert!(d.jobs_ever(), "a failed job never bills usage, but it ran");
    });
}

#[test]
fn reliability_ledger_accumulates_and_answers_none_untried() {
    with_daemon("reliability", |d| {
        assert_eq!(d.reliability("s1.example"), None);

        // All-zero report: skipped wholesale, ledger never created.
        d.add_reliability(&[("s1.example".into(), 0, 0)]);
        assert_eq!(d.reliability("s1.example"), None);

        d.add_reliability(&[("s1.example".into(), 10, 2), ("s2.example".into(), 0, 0)]);
        assert_eq!(d.reliability("s1.example"), Some((10, 2)));
        assert_eq!(d.reliability("s2.example"), None, "tried == 0 skipped");

        d.add_reliability(&[("s1.example".into(), 5, 1)]);
        assert_eq!(d.reliability("s1.example"), Some((15, 3)));
    });
}

// -- paths ------------------------------------------------------------------

#[test]
fn base_out_dir_skips_the_category_level_when_empty() {
    with_daemon("baseout", |d| {
        let root = d.out_dir();
        assert_eq!(
            d.base_out_dir("", "Some.Release"),
            root.join("Some.Release")
        );
        assert_eq!(
            d.base_out_dir("tv", "Some.Release"),
            root.join("tv").join("Some.Release")
        );
    });
}

#[test]
fn working_state_paths_hang_off_spool_and_index_db() {
    with_daemon("paths", |d| {
        assert_eq!(d.bench_history_path(), d.spool.join("bench_history.json"));
        assert!(d.out_dir().ends_with("out"));
        #[cfg(feature = "indexer")]
        {
            assert_eq!(d.opened_path(), d.spool.join("index-opened.json"));
            assert_eq!(
                d.groups_cache_path(),
                d.index_db.with_file_name("groups.tsv")
            );
            assert_eq!(
                d.groupstats_cache_path(),
                d.index_db.with_file_name("groupstats.tsv")
            );
        }
    });
}

// -- idle clock / sampler hold ----------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn download_idle_for_is_none_while_a_job_runs() {
    with_daemon("idlefor", |d| {
        let idle = d.download_idle_for().expect("idle since boot");
        assert!(idle < std::time::Duration::from_secs(60));
        *d.started_at.lock_ok() = Some(std::time::Instant::now());
        assert!(d.download_idle_for().is_none());
    });
}

#[cfg(feature = "indexer")]
#[test]
fn sampler_holds_unless_idle_past_the_release_timeout() {
    with_daemon("sampler", |d| {
        let server = |secs: serde_json::Value| -> nzbkit::config::ServerConfig {
            serde_json::from_value(serde_json::json!({
                "host": "news.example.net", "idle_release_secs": secs,
            }))
            .expect("server config")
        };
        // Some(0) = no release policy: always hold.
        assert!(d.sampler_may_hold(&server(serde_json::json!(0))));

        // A running download holds whatever the policy says.
        *d.started_at.lock_ok() = Some(std::time::Instant::now());
        assert!(d.sampler_may_hold(&server(serde_json::json!(3600))));

        // Idle for ~0 s, timeout 3600 s: still holding.
        *d.started_at.lock_ok() = None;
        assert!(d.sampler_may_hold(&server(serde_json::json!(3600))));

        // Idle past the timeout: borrow per tick instead.
        if let Some(past) =
            std::time::Instant::now().checked_sub(std::time::Duration::from_secs(7200))
        {
            *d.last_download_end.lock_ok() = past;
            assert!(!d.sampler_may_hold(&server(serde_json::json!(3600))));
            assert!(
                d.sampler_may_hold(&server(serde_json::json!(0))),
                "0 still holds"
            );
        }
    });
}

// -- auto-retry / tail phase ------------------------------------------------

#[test]
fn will_auto_retry_wants_the_cooldown_armed_and_a_transient_failure() {
    with_daemon("autoretry", |d| {
        let failed = jv(
            "f1",
            "f1",
            serde_json::json!({"state": "Failed", "fail_message": "download incomplete: 3 articles missing"}),
        );
        assert!(!d.will_auto_retry(&failed), "secs == 0: feature off");

        d.auto_retry_secs.store(600, Ordering::Relaxed);
        assert!(d.will_auto_retry(&failed));

        let retried = jv(
            "f2",
            "f2",
            serde_json::json!({"state": "Failed", "fail_message": "download incomplete", "retries": 1}),
        );
        assert!(!d.will_auto_retry(&retried), "one automatic retry only");

        let gone = jv(
            "f3",
            "f3",
            serde_json::json!({"state": "Failed", "fail_message": "post is gone"}),
        );
        assert!(!d.will_auto_retry(&gone), "Gone is not transient");

        let done = jv("f4", "f4", serde_json::json!({"state": "Completed"}));
        assert!(!d.will_auto_retry(&done));

        // ...and transient is not enough on its own. Missing articles on
        // a post seven days old is not propagation, and the retry spent
        // a second full download (~150 s, 1.9 GB) proving the same 1965
        // segments absent - twice, 15 Aug. The bare messages above carry
        // no age at all, which is the dateless-NZB convention and still
        // retries, so both halves are pinned here.
        let aged = |days: u32| {
            format!(
                "download incomplete: 1 file(s) with missing segments, 0 decode/write \
                 errors; the post is {days} day(s) old, well past the minutes-to-hours \
                 that propagation takes"
            )
        };
        let old = jv(
            "f5",
            "f5",
            serde_json::json!({"state": "Failed", "fail_message": aged(7)}),
        );
        assert!(!d.will_auto_retry(&old), "propagation finished days ago");
        let young = jv(
            "f6",
            "f6",
            serde_json::json!({"state": "Failed", "fail_message": aged(1)}),
        );
        assert!(d.will_auto_retry(&young), "still inside the window");
    });
}

#[test]
fn tail_phase_maps_hub_activity_to_sab_vocabulary() {
    with_daemon("tailphase", |d| {
        assert_eq!(d.tail_phase("nzo1"), None, "no activity recorded");
        d.hub
            .activity
            .lock_ok()
            .insert("nzo1".to_string(), "verifying");
        d.hub
            .activity
            .lock_ok()
            .insert("nzo2".to_string(), "repairing");
        d.hub
            .activity
            .lock_ok()
            .insert("nzo3".to_string(), "extracting");
        d.hub
            .activity
            .lock_ok()
            .insert("nzo4".to_string(), "assembling");
        assert_eq!(d.tail_phase("nzo1"), Some("Verifying"));
        assert_eq!(d.tail_phase("nzo2"), Some("Repairing"));
        assert_eq!(d.tail_phase("nzo3"), Some("Extracting"));
        assert_eq!(d.tail_phase("nzo4"), None, "unmapped phases stay quiet");
        assert_eq!(d.tail_phase("nzo9"), None);
        // The engine's hand-off word and every stage the daemon writes
        // after it. One wire word between them, and it is the one a
        // `Finishing` row already reported - so this maps the window,
        // it does not widen the vocabulary the *arrs are told.
        for tok in [
            "finalizing",
            "unlocking",
            "identifying",
            "renaming",
            "scripting",
        ] {
            d.hub.activity.lock_ok().insert("nzo5".to_string(), tok);
            assert_eq!(
                d.tail_phase("nzo5"),
                Some("Moving"),
                "{tok} is a post-network stage and must read as a tail"
            );
        }
        // ...and the one word in this map that is written BEFORE the
        // network, while the record already says Downloading and
        // nothing has been fetched. A catch-all arm would report it as
        // all-in at 100%.
        d.hub
            .activity
            .lock_ok()
            .insert("nzo6".to_string(), "preflight");
        assert_eq!(
            d.tail_phase("nzo6"),
            None,
            "preflight is not a tail - the bytes have not started"
        );
    });
}

// -- owned key sets ----------------------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn owned_dupe_keys_take_all_of_queue_but_only_completed_history() {
    with_daemon("dupekeys", |d| {
        d.queue
            .lock_ok()
            .push_back(jv("q1", "q1", serde_json::json!({"dupe_key": "k-queued"})));
        d.queue
            .lock_ok()
            .push_back(jv("q2", "q2", serde_json::json!({})));
        d.history.lock_ok().push(jv(
            "h1",
            "h1",
            serde_json::json!({"state": "Completed", "dupe_key": "k-done"}),
        ));
        d.history.lock_ok().push(jv(
            "h2",
            "h2",
            serde_json::json!({"state": "Failed", "dupe_key": "k-failed"}),
        ));
        let set = d.owned_dupe_keys();
        assert!(set.contains("k-queued"));
        assert!(set.contains("k-done"));
        assert!(!set.contains("k-failed"), "failed history is not owned");
        assert_eq!(set.len(), 2, "keyless jobs contribute nothing");
    });
}

#[cfg(feature = "indexer")]
#[test]
fn owned_title_keys_parse_names_and_drop_empty_keys() {
    with_daemon("titlekeys", |d| {
        let queued = "The.Show.S01E01.720p.WEB.x264-ABC";
        let done = "Some.Movie.2021.1080p.BluRay.x264-XYZ";
        let failed = "Other.Film.2019.720p.WEB.x264-QQQ";
        d.queue
            .lock_ok()
            .push_back(jv("q1", queued, serde_json::json!({})));
        d.queue
            .lock_ok()
            .push_back(jv("q2", "", serde_json::json!({})));
        d.history
            .lock_ok()
            .push(jv("h1", done, serde_json::json!({"state": "Completed"})));
        d.history
            .lock_ok()
            .push(jv("h2", failed, serde_json::json!({"state": "Failed"})));

        let set = d.owned_title_keys();
        let key = |n: &str| crate::wall::parse_release(n).key;
        assert!(set.contains(&key(queued)));
        assert!(set.contains(&key(done)));
        assert!(!set.contains(&key(failed)), "failed history is not owned");
        // The parser never emits a bare empty key (a blank name still
        // parses to the kind prefix), so the drop guard stays defensive.
        assert!(!set.contains(""));
        assert!(
            !key("").is_empty(),
            "even a blank name keys to its kind prefix"
        );
        assert!(set.contains(&key("")));
        assert_eq!(set.len(), 3);
    });
}

/// A job's out_dir is the absolute path baked in from the download-folder
/// setting when it was ADDED. If the user later points the download folder
/// somewhere else (or a settings.json is carried between machines where the
/// old path no longer exists), `retry` must re-download into the CURRENT
/// folder - not re-run the job forever at the stale, possibly-dead path.
/// Field repro 9 Aug: out_dir was changed to a mounted path, yet retry kept
/// targeting the old /Volumes/... one and failed with the same error.
#[test]
fn retry_reresolves_a_stale_baked_out_dir_to_the_current_download_folder() {
    with_daemon("retry-staleroot", |d| {
        let old_root = d.out_dir();
        let tmp = old_root.parent().expect("tempdir").to_path_buf();
        let new_root = tmp.join("newout");
        std::fs::create_dir_all(&new_root).unwrap();

        // A Failed history job whose out_dir sits under the OLD root, exactly
        // as enqueue would have built it (root / category / stem).
        let old_dir = old_root.join("movies").join("Some.Movie.2024");
        d.history.lock_ok().push(jv(
            "SABnzbd_nzo_stale",
            "Some.Movie.2024",
            serde_json::json!({
                "out_dir": old_dir.to_string_lossy(),
                "category": "movies",
                "state": "Failed",
                "fail_message": "boom",
            }),
        ));

        // The user changes the download folder AFTER the job was added.
        *d.out_root.write_ok() = new_root.clone();

        assert!(d.retry("SABnzbd_nzo_stale"), "retry accepted");

        // Left history, landed in the queue, re-aimed at the CURRENT root.
        assert!(
            !d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_stale"),
            "the record left history"
        );
        let q = d.queue.lock_ok();
        let j = q
            .iter()
            .find(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_stale")
            .expect("re-queued")
            .clone();
        let g = j.lock_ok();
        assert!(
            g.out_dir.starts_with(&new_root),
            "retry must target the CURRENT download folder, got {}",
            g.out_dir.display()
        );
        assert!(
            !g.out_dir.starts_with(&old_root),
            "retry must not reuse the stale baked path {}",
            g.out_dir.display()
        );
        // Nothing is on disk at the new folder, so progress starts from zero.
        assert_eq!(g.downloaded_bytes, 0);
        assert_eq!(g.state, JobState::Queued);
    });
}

/// TODO 143: a scan pass publishing its connection must leave
/// `index_migrated` SET.
///
/// The flag answers "has a read-write open run the migrations", and
/// `index_read_checked` sends every query down `with_index`'s UNBOUNDED
/// wait on the write mutex while it is false - the startup-shaped moment
/// when nothing holds a long lock. The other four writers of that mutex
/// only set it on the branch where THEY open the connection
/// (`guard.is_none()`), so once a pass has published one, that branch
/// never runs again and the flag stayed false for the life of the
/// process: the read-only pool became dead code and the 28 Jul / 2 Aug
/// wedges were reopened on every install whose scan loop published
/// before the first `with_index` call.
///
/// http_wedge pins the symptom end to end. This pins the seam, because
/// that suite only caught it once Spotnet went default-on and gave its
/// groupless fixture a pass to publish from - a test whose config is
/// unrepresentative is how this stayed green while production wedged.
#[cfg(feature = "indexer")]
#[test]
fn a_published_scan_connection_marks_the_index_migrated() {
    with_daemon("published", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        // A scan pass opens its OWN connection - migrations run there -
        // and hands it over. Nothing has called with_index yet, which is
        // the ordering that made this invisible.
        let era = d.index_era();
        let fresh = nzbkit::index::Index::open(&d.index_db).expect("scan pass open");
        d.publish_index(era, fresh);
        assert!(
            d.index.lock_ok().is_some(),
            "precondition: the pass's connection is the published one"
        );
        assert!(
            d.index_migrated.load(Ordering::Acquire),
            "a published connection has run the migrations, so queries \
             must use the read pool rather than the write mutex"
        );
    });
}

/// The other half of the same rule: an ordinary failed retry whose out_dir
/// is STILL under the current download folder keeps its own directory (and
/// so its journal and its progress). The stale-path re-resolution above must
/// not disturb the common case.
#[test]
fn retry_keeps_an_out_dir_that_is_still_under_the_current_root() {
    with_daemon("retry-liveroot", |d| {
        let keep = d.out_dir().join("movies").join("Keep.Me.2024");
        d.history.lock_ok().push(jv(
            "SABnzbd_nzo_keep",
            "Keep.Me.2024",
            serde_json::json!({
                "out_dir": keep.to_string_lossy(),
                "category": "movies",
                "state": "Failed",
                "downloaded_bytes": 4096,
            }),
        ));

        assert!(d.retry("SABnzbd_nzo_keep"), "retry accepted");

        let q = d.queue.lock_ok();
        let g = q
            .iter()
            .find(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_keep")
            .expect("re-queued")
            .clone();
        let g = g.lock_ok();
        assert_eq!(
            g.out_dir, keep,
            "an under-root retry keeps its own folder in place"
        );
        // Its journal is intact at that folder, so its progress is kept.
        assert_eq!(g.downloaded_bytes, 4096);
    });
}

/// The indexer-confirm lane end to end against a mock newznab, with
/// the suggestion created by the REAL correlation machinery (seeded
/// pre + dark scanned row + catchup walk - the design's own worked
/// example numbers). Round one: the listing matches, its NZB
/// msgid-joins at quorum, the row gains the pre title as a proven
/// msgid-set name and the suggestion settles 'confirmed'. Round two:
/// a second suggestion's NZB joins nothing - stamped out, nothing
/// named, and the suggestion left standing rather than falsely
/// settled.
#[cfg(feature = "indexer")]
#[test]
fn an_indexer_confirmed_suggestion_becomes_a_proven_name() {
    use nzbkit::predb::{PreKind, PreLine};
    with_daemon("corrconfirm", |d| {
        d.index_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let seed = |ix: &mut nzbkit::index::Index, stem: &str, tag: &str, title: &str| {
            let entries: Vec<nzbkit::nntp::OverEntry> = (1..=3u64)
                .map(|n| nzbkit::nntp::OverEntry {
                    number: n,
                    subject: format!(r#""{stem}" yEnc ({n}/3)"#),
                    from: "p@x".into(),
                    message_id: format!("<{tag}{n}@test>"),
                    bytes: 1_666_666_666,
                    date: 4_600,
                })
                .collect();
            ix.ingest("alt.binaries.x264", &entries, 5_000).unwrap();
            ix.predb_store(
                &[PreLine {
                    kind: PreKind::New,
                    title: title.into(),
                    category: "X264-HD".into(),
                    size: 4_900_000_000,
                    date: 1_000,
                    source: "PRE".into(),
                    ..Default::default()
                }],
                5_000,
            )
            .unwrap();
        };
        const TITLE: &str = "Test.Release.2026.1080p.WEB.H264-GRP";
        d.with_index_mut(|ix| {
            seed(ix, "x7Pq9RtK2mVb8NcJ4wZs", "cc", TITLE);
            let (_, suggested, _) = ix.predb_corr_backlog(400, 0, false, 6_200).unwrap();
            assert_eq!(suggested, 1, "the real scorer suggested the pairing");
            let picks = ix.corr_confirm_pick(5).unwrap();
            assert_eq!(picks.len(), 1);
            assert_eq!(picks[0].1, TITLE);
            Some(())
        })
        .unwrap();

        // Mock newznab: request 1 = the search, request 2 = the NZB.
        // Connection: close forces a fresh connection per request so
        // the accept loop sees each one.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let nzb_ids: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>> =
            std::sync::Arc::new(std::sync::Mutex::new(vec!["cc1", "cc2", "cc3"]));
        let ids2 = nzb_ids.clone();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            for stream in listener.incoming().take(4) {
                let mut s = stream.unwrap();
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if req.contains("t=search") {
                    format!(
                        r#"<?xml version="1.0"?><rss><channel>
<item><title>Test.Release.2026.1080p.WEB.H264-GRP</title><guid>g1</guid>
<enclosure url="http://127.0.0.1:{port}/nzb" length="4900000000" type="application/x-nzb"/>
</item></channel></rss>"#
                    )
                } else {
                    let ids = ids2.lock().unwrap().clone();
                    let segs: String = ids
                        .iter()
                        .enumerate()
                        .map(|(i, id)| {
                            format!(
                                r#"<segment bytes="1666666666" number="{}">{id}@test</segment>"#,
                                i + 1
                            )
                        })
                        .collect();
                    format!(
                        r#"<?xml version="1.0"?><nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="p@x" date="4600" subject="&quot;x&quot; yEnc (1/3)">
<groups><group>alt.binaries.x264</group></groups>
<segments>{segs}</segments></file></nzb>"#
                    )
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });

        d.indexers.lock_ok().push(crate::newznab::IndexerConfig {
            name: "mock".into(),
            url: format!("http://127.0.0.1:{port}"),
            apikey: "k".into(),
            enabled: true,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        });
        *d.corr_confirm_source.lock_ok() = "mock".into();
        // Both switches: the confirm lane is a child of correlation
        // and stands down whenever the parent is off.
        d.predb_corr_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        d.corr_confirm_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);

        assert!(super::tasks::corr_confirm_once(d), "budget was spent");
        d.with_index(|ix| {
            let r = &ix.search("x7Pq9RtK2mVb8NcJ4wZs", 5).unwrap()[0];
            assert_eq!(r.pre_title, TITLE, "the join named the row");
            let stats = ix.predb_corr_stats().unwrap();
            let confirmed = stats
                .iter()
                .find(|(k, _)| k == "confirmed")
                .map(|(_, v)| *v)
                .unwrap_or(0);
            assert_eq!(confirmed, 1, "the suggestion settled confirmed");
            assert!(
                ix.corr_confirm_pick(5).unwrap().is_empty(),
                "checked once, never again"
            );
            Some(())
        })
        .unwrap();

        // Round two: a fresh suggestion whose fetched NZB shares no
        // message-ids with the row - the join must find nothing.
        const TITLE2: &str = "Other.Show.S01E05.1080p.WEB.H264-GRP";
        d.with_index_mut(|ix| {
            seed(ix, "q2Wm8VbN5xKj3RtY7pLc", "dd", TITLE2);
            // The backlog cursor parked below round one's rows; a seed
            // generation bump is production's own re-open mechanism.
            ix.kv_set("predb_seed_gen", "test2").unwrap();
            let (_, suggested, _) = ix.predb_corr_backlog(400, 0, false, 6_300).unwrap();
            assert_eq!(suggested, 1);
            Some(())
        })
        .unwrap();
        *nzb_ids.lock().unwrap() = vec!["ee1", "ee2", "ee3"];
        assert!(
            super::tasks::corr_confirm_once(d),
            "budget spent on the miss too"
        );
        d.with_index(|ix| {
            let r = &ix.search("q2Wm8VbN5xKj3RtY7pLc", 5).unwrap()[0];
            assert_eq!(r.pre_title, "", "no join, no name");
            assert!(
                ix.corr_confirm_pick(5).unwrap().is_empty(),
                "stamped regardless"
            );
            Some(())
        })
        .unwrap();
        drop(server);
    });
}

/// C4-4 (§131 identity substrate): an accepted NZB is a (name, payload
/// message-id set) pairing. When its payload ids are rows the scanner
/// holds, the add records a MsgidSet claim against them, provenance-
/// tagged with the add's origin - and a sub-quorum overlap records
/// nothing, because a single message-id can be seeded.
#[cfg(feature = "indexer")]
#[test]
fn an_accepted_nzb_pairs_its_msgids_onto_scanned_rows() {
    with_daemon("nzbpair", |d| {
        d.index_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // Two dark scanned rows, three articles each.
        d.with_index_mut(|ix| {
            let row = |stem: &str, tag: &str| -> Vec<nzbkit::nntp::OverEntry> {
                (1..=3u64)
                    .map(|n| nzbkit::nntp::OverEntry {
                        number: n,
                        subject: format!(r#""{stem}.part1.rar" yEnc ({n}/3)"#),
                        from: "p@x".into(),
                        message_id: format!("<{tag}{n}@test>"),
                        bytes: 1000,
                        date: 1_700_000_000,
                    })
                    .collect()
            };
            ix.ingest("a.b.dark", &row("jumbled77aa", "pair"), 1_700_000_001)
                .ok()?;
            ix.ingest("a.b.dark", &row("jumbled77bb", "sub"), 1_700_000_001)
                .ok()
        })
        .expect("seed index");
        let nzb = |ids: &[&str]| {
            let segs: String = ids
                .iter()
                .enumerate()
                .map(|(i, id)| {
                    format!(
                        r#"<segment bytes="1000" number="{}">{id}@test</segment>"#,
                        i + 1
                    )
                })
                .collect();
            format!(
                "<?xml version=\"1.0\"?><nzb><file poster=\"x\" date=\"0\" \
                 subject=\"&quot;a.bin&quot; yEnc (1/{})\"><groups><group>g</group>\
                 </groups><segments>{segs}</segments></file></nzb>",
                ids.len()
            )
        };
        // All three of the first row's ids: quorum, claim recorded.
        d.enqueue(
            nzb(&["pair1", "pair2", "pair3"]).as_bytes(),
            "Real.Show.S01E01.1080p-GRP.nzb",
            "",
            -100,
            None,
            None,
            "watch",
            false,
        )
        .unwrap();
        // Only two of the second row's: under quorum, nothing recorded.
        d.enqueue(
            nzb(&["sub1", "sub2"]).as_bytes(),
            "Wrong.Name.S09E09.720p-BAD.nzb",
            "",
            -100,
            None,
            None,
            "watch",
            true,
        )
        .unwrap();
        let (paired, sub) = d
            .with_index(|ix| {
                let rid = |posted: &str| {
                    ix.release_ids_by_stem(posted)
                        .unwrap()
                        .first()
                        .copied()
                        .expect("seeded row")
                };
                let paired = ix.name_claims(rid("jumbled77aa.part1.rar")).unwrap();
                let sub = ix.name_claims(rid("jumbled77bb.part1.rar")).unwrap();
                Some((paired, sub))
            })
            .expect("index open");
        assert_eq!(paired.len(), 1, "{paired:?}");
        let (name, tier, _key, source, _at) = &paired[0];
        assert_eq!(name, "Real.Show.S01E01.1080p-GRP");
        assert_eq!(tier, "msgid-set");
        assert_eq!(source, "nzb-watch");
        assert!(sub.is_empty(), "sub-quorum must record nothing: {sub:?}");
    });
}

/// The restart window the 10 Aug audit flagged: the stats cache is
/// empty until the first successful read, and a scan batch can hold the
/// write connection from the moment the daemon comes up - index_stats
/// answered (0,0,0,0) and the dashboard told whoever loaded the page
/// that a populated index was empty. The pooled read-only connections
/// run concurrently with that writer, so a busy write lock must not
/// read as an empty index.
#[cfg(feature = "indexer")]
#[test]
fn index_stats_answer_from_the_read_pool_while_the_writer_is_busy() {
    with_daemon("statsro", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        // Create the database (and run migrations) through the write
        // connection, exactly as startup's first ingest would.
        d.with_index(|_ix| Some(())).expect("index open");
        assert!(
            d.index_stats_cache.lock_ok().snap.is_none(),
            "precondition: no successful stats read has seeded the cache"
        );
        // A scan batch owns the write connection for the whole window.
        let _writer = d.index.lock_ok();
        let snap = d
            .index_stats_snapshot()
            .expect("the read pool serves figures while the writer is busy");
        assert!(
            snap.2 > 0,
            "a busy write lock must not read as an empty index: {snap:?}"
        );
        // And the answer seeds the cache for the next busy poll.
        assert_eq!(d.index_stats_cache.lock_ok().snap, Some(snap));
    });
}

/// The residue of the window above: write lock busy, cache cold, and
/// the read pool cannot help either (here: the database file does not
/// exist yet, so a read-only open fails). The one honest answer is "no
/// figures yet" - None, which the API forwards as stats_cold - never
/// zeros dressed up as a count.
#[cfg(feature = "indexer")]
#[test]
fn index_stats_answer_cold_not_zero_when_no_read_path_is_available() {
    with_daemon("statscold", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(d.index_stats_cache.lock_ok().snap.is_none());
        let _writer = d.index.lock_ok();
        assert_eq!(
            d.index_stats_snapshot(),
            None,
            "an unreadable index must answer cold, not empty"
        );
        // Cold answers must not seed the cache: the next poll should
        // try the real read paths again, not replay the placeholder.
        assert!(d.index_stats_cache.lock_ok().snap.is_none());
    });
}

fn outage(host: &str, secs: u64, kind: &'static str) -> ServerOutage {
    ServerOutage {
        host: host.to_string(),
        since_ms: 1_000,
        secs,
        kind,
        detail: "the server's own words".into(),
    }
}

/// The queue row names a dead provider only when the job is actually
/// stuck behind it, and only once the outage has outlived the window.
///
/// Both gates earn their keep. Without the stall gate, a job pulling at
/// full line speed from server A would put a red "no connection" line on
/// its own row because a backup B nobody needed is out - an alarm on a
/// row that is working. Without the window, every capacity bounce and
/// every ordinary redial would flicker one.
#[test]
fn a_row_names_a_dead_server_only_when_it_is_stuck_behind_it() {
    // Window default is 60 s; keep the test independent of the env knob.
    let win = server_down_secs();
    let long = outage("news.example", win + 5, "unreachable");
    let brief = outage("news.example", win.saturating_sub(1), "unreachable");

    assert!(
        row_outage(false, std::slice::from_ref(&long)).is_none(),
        "a healthy row must stay quiet about a dead backup"
    );
    assert!(
        row_outage(true, std::slice::from_ref(&brief)).is_none(),
        "an outage inside the window is a redial, not news"
    );
    let (tok, o) =
        row_outage(true, std::slice::from_ref(&long)).expect("stuck and past the window");
    assert_eq!(tok, "server_unreachable");
    assert_eq!(o.host, "news.example");
    assert!(row_outage(true, &[]).is_none());
}

/// The three causes are three tokens, because they are three different
/// things for the user to do: wait, wait for a slot, or go fix a
/// password. One "server down" phrase would have flattened them.
#[test]
fn each_outage_cause_gets_its_own_token() {
    let win = server_down_secs() + 1;
    for (kind, want) in [
        ("unreachable", "server_unreachable"),
        ("capacity", "server_capacity"),
        ("refused", "server_refused"),
    ] {
        let o = [outage("h", win, kind)];
        assert_eq!(row_outage(true, &o).expect("reported").0, want, "{kind}");
    }
}

/// Worst first: with two providers out, the row reports the one that has
/// been out longest, because that is the one least likely to come back
/// on its own.
#[test]
fn the_longest_outage_is_the_one_the_row_reports() {
    let win = server_down_secs();
    // `server_outages` sorts longest-first; `row_outage` trusts that.
    let os = [
        outage("old.example", win + 600, "unreachable"),
        outage("new.example", win + 1, "capacity"),
    ];
    assert_eq!(
        row_outage(true, &os).expect("reported").1.host,
        "old.example"
    );
}

// -- §158 item 7: neither store holds the record -----------------------------

/// A second Daemon over the same spool directory, restored from whatever
/// is on disk RIGHT NOW. The restart half of the crash harness: the
/// assertions below are made against bytes a torn write actually left,
/// not against a fixture written to match somebody's belief about it.
fn restart(d: &Arc<Daemon>) -> Arc<Daemon> {
    let dir = d.spool.parent().expect("spool has a parent").to_path_buf();
    let d2 = super::super::testutil::test_daemon(&dir);
    d2.load_queue();
    d2
}

fn one_file_nzb(seg: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
         <groups><group>g</group></groups><segments>\
         <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
         </segments></file></nzb>"
    )
}

fn stored_next_id(d: &Arc<Daemon>) -> u64 {
    crate::persist::load_json_with_backup(&d.spool.join("queue.json"))
        .and_then(|v| v.get("next_id").and_then(Value::as_u64))
        .expect("queue.json carries next_id")
}

/// §158: a duplicate add with duplicates set to "fail" never joins the
/// queue - it files straight to history - so its record reaches disk
/// through TWO writes that are not one transaction. The record's own
/// store goes first; `save_queue` runs second and carries nothing of this
/// job but the id-allocator bump.
///
/// Cut between them, which is what a kill or an ENOSPC does there. The
/// old order wrote the queue snapshot first, so the write that survived
/// the cut was the one with no trace of the job in it and the record was
/// lost from BOTH files - the spooled .nzb left on disk named by nothing,
/// and the *arr that submitted it never told the grab had failed.
#[test]
fn a_never_queued_rejection_survives_a_kill_between_its_two_store_writes() {
    with_daemon("lostboth-fail", |d| {
        let add = |seg: &str, name: &str| {
            d.enqueue(
                one_file_nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
        };
        // The original, so the next add collides with it. A name with a
        // derivable identity (SxxEyy), or there is no dupe_key to match on.
        add("one", "Show.S03E04.1080p.nzb").expect("the original add");
        *d.dupe_action.lock_ok() = "fail".into();
        let before = stored_next_id(d);

        // One more durable store write lands; the process dies before the
        // next one.
        super::super::storecut::arm_cut(1);
        let failed = add("two", "Show.S03E04.720p.nzb").expect("the duplicate add");
        super::super::storecut::disarm();

        let after = stored_next_id(d);
        assert!(
            d.queue
                .lock_ok()
                .iter()
                .all(|j| j.lock_ok().nzo_id != failed),
            "the rejected job must never have been queued"
        );

        // What a restart finds.
        let d2 = restart(d);
        assert!(
            d2.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == failed),
            "the rejected record was lost from BOTH stores"
        );
        // ...and the cut has to have actually landed inside the pair, or
        // the assertion above proves nothing: `save_queue` persists the id
        // allocator, so a stale next_id is the receipt that it never ran.
        assert_eq!(
            after, before,
            "the second write was supposed to be cut - this harness is not \
             exercising the window"
        );
    });
}

/// §158: `park` moves a record the other way, and its window is a RACE
/// rather than a kill - every queue mutation in the daemon calls
/// `save_queue`, so any other thread saving between the row leaving the
/// live queue and history.jsonl gaining it publishes a queue.json the
/// record is no longer in while no store holds it at all.
///
/// The window is a few hundred microseconds, so the harness runs that
/// save from inside it rather than racing for it, and then cuts every
/// write park still had to make.
#[test]
fn a_park_survives_a_racing_queue_save_in_its_window() {
    with_daemon("lostboth-park", |d| {
        let job = jv("nzo-park-1", "Parked.Release", serde_json::json!({}));
        d.queue.lock_ok().push_back(job.clone());
        assert!(d.save_queue(), "the queue snapshot the park starts from");
        {
            let mut g = job.lock_ok();
            g.state = JobState::Completed;
            g.finished_unix = Some(1);
        }

        super::super::storecut::on_park_gap(|d| {
            assert!(d.save_queue(), "the racing save must land");
            // ...and the process dies there: nothing park writes after
            // this point reaches disk.
            super::super::storecut::arm_cut(0);
        });
        d.park_gen(job, None);
        super::super::storecut::disarm();

        let queued = std::fs::read_to_string(d.spool.join("queue.json")).unwrap_or_default();
        assert!(
            !queued.contains("nzo-park-1"),
            "the racing save was supposed to publish a queue without the row - \
             this harness is not exercising the window"
        );

        let d2 = restart(d);
        assert!(
            d2.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-park-1"),
            "the parked record was lost from BOTH stores"
        );
        assert!(
            d2.queue.lock_ok().is_empty(),
            "and it must not come back as a queued job as well"
        );
    });
}

/// The other end of the same reorder: a delete landing INSIDE a park,
/// after its durable history row went down. The job is dropped rather
/// than filed, so the row it already wrote has to be buried - or the
/// early write would resurrect, at the next boot, exactly the job the
/// user cancelled.
#[test]
fn a_delete_inside_the_park_window_buries_the_row_park_already_wrote() {
    with_daemon("lostboth-park-del", |d| {
        let job = jv("nzo-park-2", "Cancelled.Release", serde_json::json!({}));
        d.queue.lock_ok().push_back(job.clone());
        assert!(d.save_queue());
        {
            let mut g = job.lock_ok();
            g.state = JobState::Completed;
            g.finished_unix = Some(1);
        }

        let tombstoned = job.clone();
        super::super::storecut::on_park_gap(move |_| {
            tombstoned.lock_ok().tombstone = true;
        });
        d.park_gen(job, None);
        super::super::storecut::disarm();

        assert!(
            d.history.lock_ok().is_empty(),
            "a tombstoned job is dropped, not filed"
        );
        let d2 = restart(d);
        assert!(
            d2.history.lock_ok().is_empty(),
            "the early history row outlived the delete that cancelled it"
        );
    });
}

/// M5 lets a delete verb file a RETRYABLE history row, so the record the
/// delete marked `del_on_drop` outlives the park that services it - and
/// the flag used to ride along. Nothing anywhere cleared it, so the next
/// park of that same Arc (the one at the end of a SUCCESSFUL re-run)
/// removed the payload it had just produced, moments before filing the
/// Completed row (Codex sweep 14 Aug H1).
#[test]
fn a_lane_tail_never_parks_a_record_that_was_retried_out_from_under_it() {
    with_daemon("park-generation", |d| {
        let out = d.out_dir().join("Finishing.Release");
        std::fs::create_dir_all(&out).expect("payload dir");
        let job = jv(
            "nzo-parkgen-1",
            "Finishing.Release",
            serde_json::json!({ "out_dir": out.to_string_lossy() }),
        );
        // The post-processing lane samples the generation when it starts.
        let gen0 = Daemon::record_generation(&job.lock_ok());

        // Mid-tail, a delete verb files the job into history, and the
        // user retries that row: same Arc, back in the queue, one
        // generation on.
        d.history.lock_ok().push(job.clone());
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "deleted from the queue".into();
            g.finished_unix = Some(1);
            g.delete_status = "MANUAL".into();
        }
        assert!(
            d.retry("nzo-parkgen-1"),
            "the filed delete row is retryable"
        );
        assert!(
            d.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-parkgen-1"),
            "the retry put it back in the queue"
        );

        // The retry registers its custody the moment it starts.
        let hid = || "nzo-parkgen-1".to_string();
        d.hub.activity.lock_ok().insert(hid(), "downloading");
        let sc = Arc::new(crate::repair::SideCancel::new());
        d.hub.tail_cancel.lock_ok().insert(hid(), sc);

        // NOW the old lane tail finishes and parks. It must decline.
        d.park_gen(job.clone(), Some(gen0));

        // Codex sweep 5, M5: the stale branch dropped both maps
        // unconditionally, so a delayed old tail stripped the LIVE
        // retry's entries - see release_custody_if_unclaimed.
        assert!(
            d.hub.activity.lock_ok().contains_key("nzo-parkgen-1"),
            "the stale tail took the live retry's activity token"
        );
        assert!(
            d.hub.tail_cancel.lock_ok().contains_key("nzo-parkgen-1"),
            "the stale tail took the retry's tail-cancel handle"
        );
        assert!(
            d.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-parkgen-1"),
            "the stale tail pulled the freshly retried row out of the queue"
        );
        assert_eq!(
            d.history
                .lock_ok()
                .iter()
                .filter(|j| j.lock_ok().nzo_id == "nzo-parkgen-1")
                .count(),
            0,
            "and filed it into history, consuming the retry the user pressed"
        );
        assert_eq!(
            job.lock_ok().state,
            JobState::Queued,
            "the record the retry queued must still be queued"
        );
    });
}

#[test]
fn a_retried_delete_does_not_carry_its_removal_into_the_next_park() {
    with_daemon("delondrop-retry", |d| {
        let out = d.out_dir().join("Deleted.Release");
        std::fs::create_dir_all(&out).expect("payload dir");
        std::fs::write(out.join("release.mkv"), b"first run").expect("payload file");

        let job = jv(
            "nzo-delondrop-1",
            "Deleted.Release",
            serde_json::json!({ "out_dir": out.to_string_lossy() }),
        );
        d.queue.lock_ok().push_back(job.clone());
        // Exactly what the JSON-RPC `GroupDelete` arm leaves behind for a
        // job it caught DOWNLOADING: tombstoned, stamped for history, its
        // file removal deferred to park, its directory reserved until
        // that removal lands.
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "deleted from the queue".into();
            g.finished_unix = Some(1);
            g.tombstone = true;
            g.delete_status = "MANUAL".into();
            g.del_on_drop = true;
        }
        d.reserved.lock_ok().insert(out.clone());

        d.park_gen(job.clone(), None);
        assert!(
            !out.exists(),
            "the delete's deferred removal is what park owes the user"
        );
        assert!(
            d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-delondrop-1"),
            "M5: a delete verb with a status files the row rather than dropping it"
        );

        // The user changes their mind and presses Retry on that row.
        assert!(
            d.retry("nzo-delondrop-1"),
            "the filed delete row is retryable"
        );
        assert!(
            !job.lock_ok().del_on_drop,
            "a retry is an instruction to RUN the job and KEEP what it makes"
        );

        // ...and this time it works: fresh bytes on disk, and the tail
        // parks the Completed record.
        std::fs::create_dir_all(&out).expect("payload dir");
        std::fs::write(out.join("release.mkv"), b"second run").expect("payload file");
        {
            let mut g = job.lock_ok();
            g.state = JobState::Completed;
            g.finished_unix = Some(2);
        }
        d.park_gen(job, None);

        assert!(
            out.join("release.mkv").exists(),
            "the old delete's removal followed the record through its retry \
             and destroyed the release the re-run had just completed"
        );
    });
}

// -- issue #38 follow-up: queue-lock hold at 14,500 jobs ---------------------

/// Manual perf probe for the large-queue lock work, NOT a CI assertion -
/// it prints timings and asserts only that the snapshot is complete.
/// Run it by hand:
///
///   cargo test -p nzbfast --bin nzbfast save_queue_lock_hold \
///     -- --ignored --nocapture
///
/// Phase 1 reproduces the shape save_queue had before the fix (every
/// job serialized UNDER the queue lock); phase 2 is the shipped shape
/// (Arc snapshot under the lock, serialization after). Phases 3-4 put
/// numbers on the residue walks: pick_job (runnable and all-paused) and
/// note_queue_idle (arming edge, then latched). A contender
/// thread hammers the queue lock throughout and reports the worst
/// single acquire wait it saw in each phase - that wait is exactly what
/// an API request or the dashboard felt at issue #38's queue size.
#[test]
#[ignore = "manual perf probe: prints timings, run with --ignored --nocapture"]
fn save_queue_lock_hold_at_15k_jobs() {
    with_daemon("15k-bench", |d| {
        const N: usize = 15_000;
        {
            let mut q = d.queue.lock_ok();
            for i in 0..N {
                q.push_back(jv(
                    &format!("SABnzbd_nzo_bench{i:05}"),
                    &format!("Some.Release.S01E{:02}.1080p.WEB.H264-GRP.{i}", i % 99),
                    serde_json::json!({
                        "total_bytes": 4_000_000_000u64,
                        "downloaded_bytes": 1_234_567u64,
                        "category": "tv",
                    }),
                ));
            }
        }
        fn contend(d: &Arc<Daemon>, run: impl FnOnce()) -> (std::time::Duration, u64) {
            let stop = Arc::new(AtomicBool::new(false));
            let worst = Arc::new(AtomicU64::new(0));
            let (d2, stop2, worst2) = (d.clone(), stop.clone(), worst.clone());
            let contender = std::thread::spawn(move || {
                while !stop2.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    drop(d2.queue.lock_ok());
                    worst2.fetch_max(t.elapsed().as_micros() as u64, Ordering::Relaxed);
                    std::thread::sleep(std::time::Duration::from_micros(200));
                }
            });
            let t = Instant::now();
            run();
            let took = t.elapsed();
            stop.store(true, Ordering::Relaxed);
            contender.join().expect("contender");
            (took, worst.load(Ordering::Relaxed))
        }
        // Phase 1: the pre-fix shape, serialization under the queue lock.
        let mut n_old = 0;
        let (old_took, old_worst) = contend(&d.clone(), || {
            let q = d.queue.lock_ok();
            let jobs: Vec<Value> = q.iter().map(|j| job_json(&j.lock_ok())).collect();
            n_old = jobs.len();
        });
        // Phase 2: the shipped save_queue, four times over - what one
        // completion used to cost in file rewrites.
        let (new_took, new_worst) = contend(&d.clone(), || {
            for _ in 0..4 {
                assert!(d.save_queue(), "save_queue failed");
            }
        });
        assert_eq!(n_old, N);
        // Phase 3: pick_job over 15k runnable jobs, x8 - the argmax walk
        // the download worker runs every 500 ms while polling.
        let (pick_took, pick_worst) = contend(&d.clone(), || {
            for _ in 0..8 {
                assert!(d.pick_job(false).is_some(), "pick on a runnable queue");
            }
        });
        // Everything from here on wants the all-paused queue: pick_job's
        // every-job continue, and the only shape where note_queue_idle's
        // any() cannot exit on the first job.
        {
            let q = d.queue.lock_ok();
            for j in q.iter() {
                j.lock_ok().paused = true;
            }
        }
        let (pickp_took, pickp_worst) = contend(&d.clone(), || {
            for _ in 0..8 {
                assert!(d.pick_job(false).is_none(), "all paused picks nothing");
            }
        });
        // Phase 4: note_queue_idle on the arming edge (latch clear) -
        // the full walk that actually earns its emit. Then x100 with the
        // latch already set: what every park/delete on an already-idle
        // queue pays. The fast path answers from the latch alone, so
        // this leg no longer touches the queue lock at all.
        d.queue_idle_latch.store(false, Ordering::Relaxed);
        let (idle_took, idle_worst) = contend(&d.clone(), || d.note_queue_idle());
        let (latched_took, latched_worst) = contend(&d.clone(), || {
            for _ in 0..100 {
                d.note_queue_idle();
            }
        });
        // Phase 5 (perf audit B5): the dashboard's once-a-second queue body,
        // x4. The whole walk runs under the queue lock, so the contender
        // wait here is what every other API request and every pick_job
        // pays for a poll. The two legs are the same walk with and
        // without a window: `limit=60` is the dashboard's page, no
        // params is the third-party SAB client that never sends one.
        let qp = |kv: &[(&str, &str)]| {
            kv.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<std::collections::HashMap<String, String>>()
        };
        let (all_took, all_worst) = contend(&d.clone(), || {
            for _ in 0..4 {
                let v = super::sabcompat::queue_json(d, &qp(&[]));
                assert_eq!(v["queue"]["slots"].as_array().map(Vec::len), Some(N));
            }
        });
        let (win_took, win_worst) = contend(&d.clone(), || {
            for _ in 0..4 {
                let v = super::sabcompat::queue_json(d, &qp(&[("start", "0"), ("limit", "60")]));
                assert_eq!(v["queue"]["slots"].as_array().map(Vec::len), Some(60));
                // The header still describes the WHOLE queue - that is
                // the property the window must not cost.
                assert_eq!(v["queue"]["noofslots"], N);
            }
        });
        println!(
            "15k-queue probe:\n\
             \x20 old shape (serialize under queue lock, x1): {old_took:?}, \
             worst contender lock wait {old_worst} us\n\
             \x20 new save_queue x4 (full write to disk):     {new_took:?}, \
             worst contender lock wait {new_worst} us\n\
             \x20 pick_job x8, 15k runnable:                  {pick_took:?}, \
             worst contender lock wait {pick_worst} us\n\
             \x20 pick_job x8, 15k all paused:                {pickp_took:?}, \
             worst contender lock wait {pickp_worst} us\n\
             \x20 note_queue_idle, arming edge (full walk):   {idle_took:?}, \
             worst contender lock wait {idle_worst} us\n\
             \x20 note_queue_idle x100, latch already set:    {latched_took:?}, \
             worst contender lock wait {latched_worst} us\n\
             \x20 queue_json x4, no window (15k rows built):   {all_took:?}, \
             worst contender lock wait {all_worst} us\n\
             \x20 queue_json x4, limit=60 (60 rows built):     {win_took:?}, \
             worst contender lock wait {win_worst} us"
        );
    });
}

/// The latched note_queue_idle answers from the latch ALONE - route
/// assertion for the issue #38 residue fix, in the lock-placement-oracle
/// style: hold the queue lock and call it. The fast path returns without
/// ever wanting the lock; the pre-fix shape walks every job under it and
/// parks here forever, which the recv timeout turns into a clean failure.
#[test]
fn latched_note_queue_idle_never_takes_the_queue_lock() {
    with_daemon("idle-latched-route", |d| {
        d.queue
            .lock_ok()
            .push_back(jv("SABnzbd_nzo_r1", "Held.Release", serde_json::json!({})));
        d.queue_idle_latch.store(true, Ordering::Relaxed);
        let _q = d.queue.lock_ok();
        let (tx, rx) = std::sync::mpsc::channel();
        let d2 = d.clone();
        std::thread::spawn(move || {
            d2.note_queue_idle();
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10)).expect(
            "note_queue_idle with the latch set must answer from the \
             latch, not the queue walk",
        );
    });
}

/// The arming edge's empty scan and its latch CAS share one hold of the
/// queue lock, and an enqueue cannot publish between them (Codex sweep
/// 14 Aug M3). The pre-fix shape dropped the queue guard after the scan:
/// removal of a last job A leaves the queue empty, an add of B re-arms
/// the latch and publishes job.added, and A's notifier - holding a scan
/// from before B existed - then CASes and announces queue.idle over a
/// runnable job, with the latch left set so B's own genuine idle edge
/// could be swallowed too. The seam pins the notifier in exactly that
/// window; a real enqueue must sit out the window, land after the emit,
/// and leave the latch re-armed.
#[test]
fn an_enqueue_cannot_interleave_into_the_idle_scan_cas_window() {
    with_daemon("idle-aba", |d| {
        // The shape the removal of a last job leaves behind: latch
        // re-armed (false), queue empty.
        d.queue_idle_latch.store(false, Ordering::Relaxed);
        let entered = Arc::new(std::sync::Barrier::new(2));
        let released = Arc::new(std::sync::Barrier::new(2));
        *super::daemon_park::IDLE_CAS_BARRIER.lock_ok() = Some((
            d.spool.display().to_string(),
            entered.clone(),
            released.clone(),
        ));
        let notifier = {
            let d = d.clone();
            std::thread::spawn(move || d.note_queue_idle())
        };
        // The notifier has scanned the empty queue and is pinned before
        // its CAS. Disarm the seam so nothing else trips it.
        entered.wait();
        *super::daemon_park::IDLE_CAS_BARRIER.lock_ok() = None;

        // Now the add of B, on its own thread - the interleaving's
        // other half.
        let (tx, rx) = std::sync::mpsc::channel();
        let adder = {
            let d = d.clone();
            std::thread::spawn(move || {
                let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                     <file poster=\"x\" date=\"0\" subject=\"&quot;b.bin&quot; yEnc (1/1)\">\
                     <groups><group>g</group></groups><segments>\
                     <segment bytes=\"1000\" number=\"1\">b1@x</segment>\
                     </segments></file></nzb>";
                d.enqueue(
                    nzb.as_bytes(),
                    "B.Release.nzb",
                    "",
                    -100,
                    None,
                    None,
                    "test",
                    false,
                )
                .expect("enqueue");
                let _ = tx.send(());
            })
        };
        // Route assertion, not a clock: the add must be waiting on the
        // queue lock the notifier holds, so it cannot complete while
        // the window is open. The timeout only bounds how long we watch
        // for something that must never happen.
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "an enqueue published inside the scan-to-CAS window"
        );
        released.wait();
        notifier.join().expect("notifier");
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the add completes once the notifier's hold ends");
        adder.join().expect("adder");

        // The serialized order is one the queue really passed through:
        // idle (it WAS empty), then the add.
        let (events, _, _) = d.life_since(0);
        let pos = |k: &str| {
            events
                .iter()
                .position(|e| e["kind"] == k)
                .unwrap_or_else(|| panic!("no {k} event in {events:?}"))
        };
        assert!(
            pos("queue.idle") < pos("job.added"),
            "queue.idle announced over a runnable job: {events:?}"
        );
        assert!(
            !d.queue_idle_latch.load(Ordering::Relaxed),
            "the add must leave the latch re-armed"
        );
        // ...so B's own genuine departure still gets its edge.
        d.queue.lock_ok().clear();
        d.note_queue_idle();
        let (events, _, _) = d.life_since(0);
        let idles = events.iter().filter(|e| e["kind"] == "queue.idle").count();
        assert_eq!(idles, 2, "exactly one idle edge per transition: {events:?}");
    });
}

// -- the exit path closes the index -----------------------------------------

/// The wind-down must hand the index's write-ahead log back and close
/// the database.
///
/// SQLite deletes the -wal and -shm when the last connection closes, and
/// checkpoints on the way. The daemon never reached that: it leaves by
/// `process::exit` or `exec`, neither of which runs a destructor, so
/// every stop it has ever made left the whole log on disk. Measured on
/// the live daemon 14 Aug 2026 - SIGTERM, process gone, port free, and a
/// 28.1 GiB `index.db-wal` plus a 6.9 MiB `-shm` still sitting beside a
/// 39 GiB database, for the next start to recover.
///
/// The whole wind-down runs here, not just the index step, because the
/// wiring is half the fix: this ran to completion for a year without
/// touching the index at all.
#[cfg(feature = "indexer")]
#[test]
fn the_wind_down_hands_back_the_index_write_ahead_log() {
    with_daemon("windwal", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        // Opened and written through the daemon's own accessor, so this
        // is the connection the exit has to find and close. Before the
        // runtime exists: `with_index` runs its SQLite work through
        // `block_in_place` when there is one.
        d.with_index(|ix| ix.kv_set("shutdown_probe", "written").ok())
            .expect("the index must open");
        let wal = d.index_db.with_extension("db-wal");
        let shm = d.index_db.with_extension("db-shm");
        assert!(
            wal.metadata().map(|m| m.len()).unwrap_or(0) > 0,
            "fixture left no write-ahead log - the assertions below would prove nothing"
        );

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        wind_down(d, rt.handle(), "test wind-down");

        assert!(
            !wal.exists(),
            "the wind-down left {} behind - the index was never closed, so \
             the next start pays a recovery pass over the whole log",
            wal.display()
        );
        assert!(!shm.exists(), "the wind-down left {} behind", shm.display());
        // Closed, not merely emptied: what was in the log is in the
        // database file.
        let reopened = nzbkit::index::Index::open(&d.index_db).expect("reopen");
        assert_eq!(
            reopened.kv_get("shutdown_probe").as_deref(),
            Some("written"),
            "the checkpoint dropped the committed rows"
        );
        drop(reopened);
    });
}

/// ...and nothing reopens it behind the close. A status poll or an *arr
/// query arriving in the last moments of the wind-down would otherwise
/// lazily open a fresh connection, and the daemon would exit with a new
/// -wal and -shm on disk after all.
#[cfg(feature = "indexer")]
#[test]
fn an_exiting_daemon_does_not_reopen_the_index() {
    with_daemon("windreopen", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        d.exiting.store(true, Ordering::Relaxed);

        assert!(
            d.with_index(|ix| ix.kv_get("anything")).is_none(),
            "an exiting daemon answered from the index instead of declining"
        );
        assert!(
            !d.index_db.exists(),
            "an exiting daemon created {} on its way out",
            d.index_db.display()
        );
    });
}

// -- dupe_collision: the alias arm ------------------------------------------

/// The 14 Aug 2026 double-download: one episode, two spellings of the
/// show's name, two dupe keys - the key comparison alone can never meet
/// them. The alias arm may bridge them ONLY on the index's enrichment
/// record (both title keys resolved to one TVmaze show id), never on
/// the strings: a spin-off whose name extends its parent's must never
/// read as a duplicate, because a false duplicate silently skips a
/// wanted download.
#[cfg(feature = "indexer")]
#[test]
fn dupe_alias_meets_one_show_under_two_names_and_never_a_spinoff() {
    with_daemon("dupealias", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let short = "Life.Larry.and.the.Pursuit.of.Unhappiness.S01E06.1080p.x265-ELiTE";
        let long = "Life.Larry.and.the.Pursuit.of.Unhappiness.An.Almost.History.\
                    of.America.S01E06.1080p.HEVC.x265-MeGusta";
        let title_key = |name: &str| nzbkit::release::parse_release(name).key;
        assert_ne!(
            dupe_key(short),
            dupe_key(long),
            "the premise of the gap: the smart keys differ"
        );
        d.queue.lock_ok().push_back(jv(
            "id-orig",
            short,
            serde_json::json!({"dupe_key": dupe_key(short)}),
        ));

        // No enrichment record yet: the two spellings are not provably
        // one show, and the safe answer is the old answer - admit it.
        assert!(
            d.dupe_collision(long).is_none(),
            "unresolved titles must never collide"
        );

        // Enrichment resolved BOTH spellings to the same TVmaze show.
        // Labelled, as the enricher writes: an unlabelled '' id
        // contributes no alias since the 20 Aug sweep (it may be an
        // AniList media id from before the id_src column existed).
        let fill = |ix: &nzbkit::index::Index, key: &str, id: i64| {
            ix.title_seed(key, "tv", "Life Larry", 0).unwrap();
            let m = nzbkit::index::TitleFill {
                tmdb_id: id,
                id_src: "tvmaze",
                ..Default::default()
            };
            ix.title_fill(key, &m, 1).unwrap();
        };
        d.with_index(|ix| {
            fill(ix, &title_key(short), 4242);
            fill(ix, &title_key(long), 4242);
            Some(())
        });
        let c = d
            .dupe_collision(long)
            .expect("one show id + one episode = a duplicate");
        assert_eq!((c.where_, c.nzo_id.as_str()), ("queue", "id-orig"));
        // A PROPER of the aliased spelling still passes, same as the
        // key arm's rule.
        assert!(
            d.dupe_collision(
                "Life.Larry.and.the.Pursuit.of.Unhappiness.An.Almost.History.\
                 of.America.S01E06.PROPER.1080p.HEVC.x265-MeGusta"
            )
            .is_none(),
            "a PROPER is never a duplicate"
        );
        // dupe_scope = "exact" never reaches the alias arm at all.
        *d.dupe_scope.lock_ok() = "exact".to_string();
        assert!(d.dupe_collision(long).is_none(), "exact scope: names only");
        *d.dupe_scope.lock_ok() = "smart".to_string();

        // The other direction: a parent and a spin-off share every word
        // of the parent's name and the episode number, but enrichment
        // gave them DIFFERENT show ids - not a duplicate.
        let parent = "Parent.Show.S01E06.1080p.WEB.h264-AAA";
        let spinoff = "Parent.Show.Legacy.S01E06.1080p.WEB.h264-BBB";
        d.queue.lock_ok().push_back(jv(
            "id-parent",
            parent,
            serde_json::json!({"dupe_key": dupe_key(parent)}),
        ));
        d.with_index(|ix| {
            fill(ix, &title_key(parent), 7);
            fill(ix, &title_key(spinoff), 8);
            Some(())
        });
        assert!(
            d.dupe_collision(spinoff).is_none(),
            "different show ids: a spin-off must never be its parent's duplicate"
        );

        // Codex sweep 7, H2: an equal NUMBER is not an equal show. The
        // column those ids live in carries TVmaze, AniList and TMDB
        // numbering, all small and dense, and under the keyless default
        // an anime title lands in the AniList one for no reason the user
        // ever chose. Two unrelated series colliding here is a download
        // held as a duplicate of something it has nothing to do with.
        let anime = "Some.Anime.S01E06.1080p.WEB.h264-CCC";
        let other = "Some.Other.Series.S01E06.1080p.WEB.h264-DDD";
        d.queue.lock_ok().push_back(jv(
            "id-anime",
            anime,
            serde_json::json!({"dupe_key": dupe_key(anime)}),
        ));
        let fill_src = |ix: &nzbkit::index::Index, key: &str, id: i64, src: &str| {
            ix.title_seed(key, "tv", "x", 0).unwrap();
            ix.title_fill(
                key,
                &nzbkit::index::TitleFill {
                    tmdb_id: id,
                    id_src: src,
                    ..Default::default()
                },
                1,
            )
            .unwrap();
        };
        d.with_index(|ix| {
            fill_src(ix, &title_key(anime), 5150, "anilist");
            fill_src(ix, &title_key(other), 5150, "tvmaze");
            Some(())
        });
        assert!(
            d.dupe_collision(other).is_none(),
            "two namespaces' ids collided into one show"
        );
        // ...and the same pair inside ONE namespace still meets, which
        // is what keeps the oracle working for anime at all.
        d.with_index(|ix| {
            fill_src(ix, &title_key(other), 5150, "anilist");
            Some(())
        });
        assert!(
            d.dupe_collision(other).is_some(),
            "two AniList rows with one media id are one show"
        );
    });
}

// -- the user's own delete, and what it says about the next add -------------

/// Gary, 15/16 Aug 2026: delete a job, get told the files could not be
/// removed, add the release again - and watch it sit in the queue as
/// "held (duplicate)" against nothing he could see.
///
/// The hold is NOT against the record he deleted (that one leaves both
/// stores, and this file's other tests pin that), and not against the
/// leftover folder (`dupe_collision` never looks at disk). It is against
/// whatever ELSE still carries the identity - here the held alternative
/// that was queued behind the deleted job, which is the shape that
/// deadlocks: the alternative is held for a record that no longer
/// exists, so nothing will ever fail to promote it, and the re-add is
/// then held behind the alternative. Two paused rows, no download, and
/// the only way out a control the user has to go and find.
///
/// A delete is the user saying they do not have this release any more,
/// whatever is still on disk. So it speaks for the next add of the same
/// identity - once, and only until that add lands.
#[test]
fn a_deleted_release_is_not_a_duplicate_until_the_mark_is_spent() {
    with_daemon("dupedeleted", |d| {
        let a = "Johnny.Vegas.S02E03.1080p.WEB.h264-AAA";
        let b = "Johnny.Vegas.S02E03.2160p.WEB.h264-BBB";
        // The survivor: the alternative that was queued behind the job
        // the user has just deleted. Paused at Duplicate priority, like
        // every held alternative, and still a collision - the queue arm
        // has never cared what state a row is in.
        d.queue.lock_ok().push_back(jv(
            "id-held",
            b,
            serde_json::json!({"dupe_key": dupe_key(b), "paused": true,
                               "priority": DUPE_PRIORITY}),
        ));
        assert!(
            d.dupe_collision(a).is_some(),
            "the premise: the held alternative is what the re-add collides with"
        );

        d.note_releases_deleted(&[a.to_string()]);
        assert!(
            d.dupe_collision(a).is_none(),
            "the user deleted this release - the re-add must not be held"
        );
        // The mark speaks for ONE release, not for the queue at large.
        let other = "Some.Other.Show.S01E01.1080p.WEB.h264-CCC";
        d.queue.lock_ok().push_back(jv(
            "id-other",
            other,
            serde_json::json!({"dupe_key": dupe_key(other), "state": "Completed"}),
        ));
        assert!(
            d.dupe_collision(other).is_some(),
            "a mark for one release must not release holds on another"
        );

        // Spent by the add it was made for: a SECOND copy added behind
        // that one is an ordinary duplicate again, or the window would
        // leave the identity unprotected for a whole day.
        d.clear_delete_mark(a);
        assert!(
            d.dupe_collision(a).is_some(),
            "the mark is spent by the re-add, not by the clock alone"
        );

        // ...and it does expire. Stamped by hand rather than by waiting
        // a day: the window is the only thing under test here.
        d.note_releases_deleted(&[a.to_string()]);
        d.deleted_recent.lock_ok().iter_mut().for_each(|m| {
            m.at -= 25 * 3600;
        });
        assert!(
            d.dupe_collision(a).is_some(),
            "a day-old delete no longer speaks for a fresh add"
        );
    });
}

/// The kept-files notice carries the spooled NZB the delete held back,
/// so it can offer the download again - and lets go of it when the
/// notice does. A notice with nothing to offer is ordinary: the sidecar
/// path has no spool copy left by the time it refuses.
#[test]
fn a_kept_files_notice_holds_the_nzb_it_offers_and_drops_it_with_the_note() {
    with_daemon("keptnzb", |d| {
        let nzb = d.spool.join("kept.nzb");
        std::fs::write(&nzb, b"<nzb/>").unwrap();
        let dir = d.spool.join("Some.Release");
        d.note_delete_kept(
            "Some.Release",
            &dir,
            "the Trash would not take it",
            Some(&nzb),
        );
        // One entry per path: a bulk sweep over a shared folder refuses
        // once per record and must not bury the notice in copies.
        d.note_delete_kept("Some.Release", &dir, "again", None);
        {
            let k = d.delete_kept.lock_ok();
            assert_eq!(k.len(), 1, "one notice per path");
            assert_eq!(k[0].nzb, nzb.display().to_string(), "the offer is recorded");
        }
        // Losing the notice means losing the only name that file had.
        drop_kept_nzb(&d.delete_kept.lock_ok()[0]);
        assert!(
            !nzb.exists(),
            "the kept NZB goes with the notice that named it"
        );
    });
}

/// The notice file written before the retry offer existed is an array of
/// `[name, path, why, at]` arrays, and each entry names a folder still
/// sitting on the user's disk. An upgrade that dropped them would lose
/// the one handle the notice exists to keep.
#[test]
fn kept_notices_load_from_the_shape_written_before_the_retry_offer() {
    let legacy = serde_json::json!([["A.Release", "/tmp/out/A", "refused", 1_786_778_143_i64]]);
    let k = kept_notes_from_json(&legacy).expect("the pre-struct shape must still load");
    assert_eq!(k.len(), 1);
    assert_eq!(
        (k[0].name.as_str(), k[0].path.as_str()),
        ("A.Release", "/tmp/out/A")
    );
    assert!(k[0].nzb.is_empty(), "an old notice has no NZB to offer");
    // ...and the current shape round-trips.
    let now = serde_json::to_value(&k).unwrap();
    assert_eq!(kept_notes_from_json(&now).expect("round trip").len(), 1);
}
