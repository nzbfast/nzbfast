//! Queue durability and the locks around it, split out of
//! `daemon_tests` under the size gate (TODO 106).
//!
//! One currency: the queue records that reached DISK, and what may
//! happen to them between two writes. A kill in the window where
//! neither store holds a record (§158 item 7), a queue save racing a
//! park, a delete landing inside that same window, a retry pulling a
//! record out from under a lane tail - each asserted against a second
//! Daemon restored from the bytes a torn write actually left, never
//! against a fixture written to match somebody's belief about them.
//! With them, the lock discipline that keeps those writes from tearing
//! in the first place (the queue-lock hold at 15k jobs, the idle-scan
//! CAS window an enqueue must not interleave into) and the wind-down
//! that hands the index back on the way out.
//!
//! `restart` / `one_file_nzb` / `stored_next_id` deliberately stayed in
//! the hub next door with `with_daemon` and `jv`: three OTHER children
//! (`recover_tests`, `park_gen_tests`, `altcand_tests`) drive them too,
//! and a test child of the hub is not a descendant of this one.
//!
//! The explicit #[path] is load-bearing for the reason the parent's own
//! header gives: `daemon_tests` is itself reached by `#[path]`, so a
//! bare `mod` here would be resolved against serve/ (ref-gate: that
//! path is the file rustc would go looking for, and its absence is the
//! point of the attribute).

use super::*;

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
            .map(|e| e.nzo_id)
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
                .map(|e| e.nzo_id)
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
