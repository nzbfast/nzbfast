//! Unit tests for crates/nzbfast-daemon/src/daemon.rs (TODO 106 phase 3): the helpers the
//! serve/mod.rs test module does not already cover, exercised against
//! the in-memory `test_daemon` fixture where a Daemon is needed.

use super::*;
// The five shared Daemon fixtures moved into `testutil` with lane 2
// of the serve split: this module is `#[cfg(test)]`, so nothing in
// it is visible to the bin, and the fifteen daemon-layer tests lifted
// into `crates/nzbfast/src/serve` build their Daemons with these.
// Imported back under their old bare names, so no assertion here
// moved.
use crate::testutil::{jv, one_file_nzb, restart, with_daemon};

// Duplicate handling, moved out under the size gate (TODO 106).
//
// The explicit #[path] is load-bearing: this module is itself reached by
// `#[path = "daemon_tests.rs"]` from daemon.rs, and that makes rustc
// resolve ITS children against serve/ rather than serve/daemon_tests/ -
// so a bare `mod dupe_tests;` looks for serve/dupe_tests.rs and fails
// (ref-gate: that path is the file rustc would go looking for, and its
// absence is the point of the attribute).
// The subdirectory is also what size-gate.py's CFG_TEST_MOD resolver
// checks (`<base>/<modname>.rs`), so the moved tests keep being read as
// test code rather than gated at the production ceiling.
#[path = "daemon_tests/dupe_tests.rs"]
mod dupe_tests;

// §282 section D: the queue row's offer and the switch behind it.
#[path = "daemon_tests/altcand_tests.rs"]
mod altcand_tests;

// TODO 16g / A12: enqueue's durability verdict and orphaned-spool
// recovery, same ceiling and #[path] requirement.
#[path = "daemon_tests/recover_tests.rs"]
mod recover_tests;

// The read seam's stale-statement handling, out here for the same
// ceiling and with the same #[path] requirement.
#[cfg(feature = "indexer")]
#[path = "daemon_tests/index_read_tests.rs"]
mod index_read_tests;

// `park_gen`'s three generation-fence windows, out for the ceiling and
// carrying the same #[path] requirement.
#[path = "daemon_tests/park_gen_tests.rs"]
mod park_gen_tests;

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

// TODO 218: category auto-assignment from the NZB meta/groups, plus
// the §129 2b cat_meta test, out for the ceiling.
#[path = "daemon_tests/infer_cat_tests.rs"]
mod infer_cat_tests;

// A4's index_stats TTL cache, same ceiling and #[path] requirement.
#[cfg(feature = "indexer")]
#[path = "daemon_tests/stats_cache_tests.rs"]
mod stats_cache_tests;

// N12's per-poll caches (owned title keys, enabled backbones), out for
// the ceiling and carrying the same #[path] requirement.
#[cfg(feature = "indexer")]
#[path = "daemon_tests/owned_cache_tests.rs"]
mod owned_cache_tests;

// TODO 282 section B: the ranked spares a grab holds against its own
// failure, out for the ceiling and carrying the same #[path] requirement.
#[path = "daemon_tests/spare_tests.rs"]
mod spare_tests;

// F5: what a size-gated Smart Folder rule does with a job whose declared
// bytes are unknown, end to end. Out for the ceiling and carrying the
// same #[path] requirement as its siblings above.
#[path = "daemon_tests/smart_size_tests.rs"]
mod smart_size_tests;

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
        d.predb.enabled.store(true, Ordering::Relaxed);
        d.index_enabled.store(false, Ordering::Relaxed);
        assert!(!d.predb_feed_on());
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(d.predb_feed_on());
        d.predb.enabled.store(false, Ordering::Relaxed);
        assert!(!d.predb_feed_on());
    });
}

#[cfg(feature = "indexer")]
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

/// Codex F-06: `pick_job`'s half of the relocation fence.
///
/// The daemon test `a_relocating_job_cannot_be_started_into_its_
/// destination` proves the fence end to end but cannot say WHICH arm
/// carries it - the gap between the pick and the flip is microseconds
/// and no hook holds it open, so either arm alone passes it. This pins
/// the skip, which is the arm that stops the runner spinning on a
/// fenced job for the whole of a large move: the fenced job must be
/// passed OVER for a runnable one, not merely refused.
#[test]
fn pick_job_skips_a_relocating_job() {
    with_daemon("pickreloc", |d| {
        {
            let mut q = d.queue.lock_ok();
            let moving = jv("mv", "being-relocated", serde_json::json!({"priority": 5}));
            moving.lock_ok().relocating = 1;
            q.push_back(moving);
            q.push_back(jv("ok", "runnable", serde_json::json!({"priority": 0})));
        }
        // The fenced job outranks the other one by four priority
        // levels, so a picker that merely deprioritised it would still
        // hand it back here.
        let got = d.pick_job(false).expect("pick");
        assert_eq!(
            got.lock_ok().nzo_id,
            "ok",
            "the relocating job was started into a destination still being assembled"
        );

        // ...and with nothing else runnable the answer is None, not the
        // fenced job: `start_next` answers Ended, so a picker that kept
        // returning this row would spin for the whole move.
        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id == "mv");
        assert!(d.pick_job(false).is_none());

        // The fence LIFTS. A job that can never start again would pass
        // both assertions above.
        d.queue.lock_ok()[0].lock_ok().relocating = 0;
        assert_eq!(
            d.pick_job(false).expect("pick").lock_ok().nzo_id,
            "mv",
            "the fence never lifted"
        );
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
    use crate::testutil::NO_PROGRESS;

    with_daemon("addbeforepick", |d| {
        let picker = {
            let d = d.clone();
            std::thread::spawn(move || {
                // Stands in for the runner's pick arm: spin on pick_job
                // and emit job.started the moment one appears, the same
                // order tasks.rs uses (claim the job, then emit).
                //
                // The spin stays a HOT one - `yield_now`, not a sleep -
                // because it is the ADVERSARY here: the claim is that a
                // picker going as fast as it can still lands behind
                // `job.added`. Only the BUDGET moved.
                //
                // WHY IT IS ON THE SHARED BUDGET, and this is the
                // weakest of the four sites that take it. `enqueue`
                // does call `save_queue`, but only AFTER it has
                // published under the queue lock - which is the very
                // ordering the doc comment above this test is about -
                // so the moment this spin waits for lands ahead of the
                // process-global queue-write queue rather than behind
                // it. What it IS exposed to is `enqueue`'s own
                // `write_spool_copy` - a disk write, on the far side of
                // which the job becomes visible to this thread - plus
                // the scheduler, and a hot spinner that at high load is
                // competing with the very thread it waits for.
                // Measured 31 Aug 2026, that enqueue costs 52-126 ms
                // alone and inside the full 2,768-test run, so 10 s was
                // a 79x margin and the 127x disk tail [`NO_PROGRESS`]
                // records puts the worst reading at 16.0 s - OVER the
                // old budget. 60 s is 476x, and the fix is one line.
                let deadline = std::time::Instant::now() + NO_PROGRESS;
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
        .map(|e| e.nzo_id)
        .expect("enqueue");
        // A STALL and never an ordering verdict: the picker gave up
        // without ever seeing a job, so it has nothing to say about
        // what order the ring is in.
        assert!(
            picker.join().expect("picker thread"),
            "the picker spun for {NO_PROGRESS:?} and never saw the job at all - the \
             add never became visible, so this says nothing about ring order. Check \
             `uptime`: this budget cannot cover a disk-starved box."
        );

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
            (&d.rename.resolution, |s| s.resolution),
            (&d.rename.vcodec, |s| s.video_codec),
            (&d.rename.acodec, |s| s.audio_codec),
            (&d.rename.source, |s| s.source),
            (&d.rename.group, |s| s.group),
            (&d.rename.year_parens, |s| s.year_parens),
            (&d.rename.quality_brackets, |s| s.quality_brackets),
            (&d.rename.extra_words, |s| s.extra_words),
        ];
        for (atomic, _) in &flags {
            atomic.store(false, Ordering::Relaxed);
        }
        for (i, (atomic, read)) in flags.iter().enumerate() {
            atomic.store(true, Ordering::Relaxed);
            let s = crate::naming::rename_style(d);
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
        assert_eq!(
            crate::naming::job_suffix(d, "Movie.2020.1080p.x264-GRP"),
            ""
        );

        d.auto_rename.store(true, Ordering::Relaxed);
        d.rename.resolution.store(true, Ordering::Relaxed);
        for a in [
            &d.rename.vcodec,
            &d.rename.acodec,
            &d.rename.source,
            &d.rename.group,
            &d.rename.quality_brackets,
        ] {
            a.store(false, Ordering::Relaxed);
        }
        assert_eq!(
            crate::naming::job_suffix(d, "Movie.2020.1080p.x264-GRP"),
            " 1080p"
        );
    });
}

// -- indexer accounts / tri-state -------------------------------------------

#[test]
fn enabled_indexers_counts_only_enabled_and_drives_the_tri_state() {
    with_daemon("tristate", |d| {
        let mk = |name: &str, enabled: bool| crate::newznab::IndexerConfig {
            kind: Default::default(),
            nzbindex: Default::default(),
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

#[cfg(feature = "indexer")]
#[test]
fn scoreboard_reference_prefers_the_named_account_and_never_falls_through() {
    with_daemon("sbref", |d| {
        let mk = |name: &str, enabled: bool| crate::newznab::IndexerConfig {
            kind: Default::default(),
            nzbindex: Default::default(),
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
        *d.scoreboard.url.lock_ok() = "https://manual.test".into();
        *d.scoreboard.key.lock_ok() = Some("mk".into());
        assert_eq!(
            d.scoreboard_reference(),
            Ok(("https://manual.test".into(), "mk".into()))
        );

        // A named account wins over the manual pair, key included.
        d.indexers.lock_ok().push(mk("geek", true));
        *d.scoreboard.source.lock_ok() = "geek".into();
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
#[cfg(feature = "indexer")]
#[test]
fn corr_confirm_source_state_tells_the_four_states_apart() {
    with_daemon("ccfstate", |d| {
        let mk = |name: &str, enabled: bool| crate::newznab::IndexerConfig {
            kind: Default::default(),
            nzbindex: Default::default(),
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
            *d.predb.server.lock_ok() = server.to_string();
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

        *d.predb.channels.lock_ok() = " #pre , ,#spam,  ".to_string();
        *d.predb.nick.lock_ok() = "nick".to_string();
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
        let j = crate::testutil::job(serde_json::json!({
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

/// GH #69 / TODO 320: the same call also has to write the DAY-dimensioned
/// half, because SAB's `mode=server_stats` publishes the article counters
/// as `{"YYYY-MM-DD": n}` maps and the lifetime pair above cannot answer
/// that. Both buckets move on one call, or the payload and the provider
/// card disagree about the same download.
#[test]
fn reliability_also_accumulates_a_per_day_article_row() {
    with_daemon("reldays", |d| {
        let today = {
            let days = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| (t.as_secs() / 86_400) as i64)
                .unwrap_or(0);
            let (y, m, dd) = crate::civil_from_days(days);
            format!("{y:04}-{m:02}-{dd:02}")
        };
        let row = |d: &crate::Daemon| -> Option<(u64, u64)> {
            let u = d.usage.lock_ok();
            let v = u.get("article_days")?.get("s1.example")?.get(&today)?;
            let g = |k| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
            Some((g("tried"), g("missing")))
        };

        // All-zero report: skipped wholesale, neither bucket created.
        d.add_reliability(&[("s1.example".into(), 0, 0)]);
        assert_eq!(row(d), None);

        d.add_reliability(&[("s1.example".into(), 10, 2), ("s2.example".into(), 0, 0)]);
        assert_eq!(row(d), Some((10, 2)));
        d.add_reliability(&[("s1.example".into(), 5, 1)]);
        assert_eq!(row(d), Some((15, 3)), "same day accumulates");
        assert_eq!(
            d.reliability("s1.example"),
            Some((15, 3)),
            "the lifetime half is unmoved"
        );
        assert!(
            d.usage
                .lock_ok()
                .get("article_days")
                .and_then(|v| v.get("s2.example"))
                .is_none(),
            "tried == 0 is skipped here too"
        );

        // The day bucket is not a byte bucket: `add_usage`'s prune only
        // reaches keys starting with '2', and this one must survive it.
        for _ in 0..70 {
            d.add_usage(&[("s1.example".into(), 1)]);
        }
        assert_eq!(row(d), Some((15, 3)), "survives the 60-day byte prune");
    });
}

// -- paths ------------------------------------------------------------------

#[test]
fn base_out_dir_skips_the_category_level_when_empty() {
    with_daemon("baseout", |d| {
        let root = crate::naming::out_dir(d);
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
        assert!(crate::naming::out_dir(d).ends_with("out"));
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
        let old_root = crate::naming::out_dir(d);
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
        let keep = crate::naming::out_dir(d)
            .join("movies")
            .join("Keep.Me.2024");
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

/// C4-4 (§131 identity substrate): an accepted NZB is durable file-aware
/// membership evidence. The add path only publishes its queue record and wake;
/// the bounded harvester later records and replays it. A complete one-file
/// manifest names its exact scanner row after the quiet window, while a
/// sub-quorum manifest records no claim.
#[cfg(feature = "indexer")]
#[test]
fn an_accepted_nzb_pairs_its_msgids_onto_scanned_rows() {
    with_daemon("nzbpair", |d| {
        d.index_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        d.index_pause_on_download
            .store(false, std::sync::atomic::Ordering::Relaxed);
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
        .map(|e| e.nzo_id)
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
        .map(|e| e.nzo_id)
        .unwrap();
        let mut harvest = crate::seed_harvest::HarvestState::new(d.index_era());
        for _ in 0..8 {
            crate::seed_harvest::tick(d, &mut harvest);
        }
        let settled = d
            .with_index_mut_retiring_ddl(|index| {
                index
                    .nzb_seed_reconcile(crate::epoch_secs() as i64 + 3_600, 64)
                    .ok()
            })
            .expect("settle accepted proof after the quiet window");
        assert_eq!(settled.claims_applied, 1, "{settled:?}");
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
        assert_eq!(source, "external-nzb:nzb-add");
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

/// A row NZBGet's `HistoryDelete` hid is still a row we HAVE.
///
/// That asymmetry is the whole fix for the Codex triage's finding 8:
/// `HistoryDelete` shares a facade arm with `HistoryFinalDelete` no
/// longer, and what the hide buys is precisely this - Sonarr's "Remove
/// completed downloads" fires that verb after every import, and before
/// the split it took the Completed row out of history, so `dupe_collision`
/// and `owned_dupe_keys` stopped answering for a release the user very
/// much still had. A later re-grab was not held and the wall's "you have
/// this" badge went out.
///
/// The display side is pinned from the facade
/// (`sabcompat::history_hidden_tests`); this is the identity side, and
/// it is asserted against `dupe_collision` itself rather than against
/// the flag, because a filter added to the scan tomorrow is exactly how
/// the defect comes back.
#[test]
fn a_hidden_history_row_is_still_a_duplicate() {
    with_daemon("dupehidden", |d| {
        let a = "Hidden.But.Owned.S04E05.1080p.WEB.h264-AAA";
        d.history.lock_ok().push(jv(
            "id-hidden",
            a,
            serde_json::json!({"dupe_key": dupe_key(a), "state": "Completed",
                               "hidden": true}),
        ));
        assert!(
            d.history.lock_ok()[0].lock_ok().hidden,
            "the fixture's premise: the row really is hidden"
        );
        assert!(
            d.dupe_collision(a).is_some(),
            "an *arr hiding its imported release must not un-own it"
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
