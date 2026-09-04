//! X5-03, the daemon half: journal retirement and terminal completion
//! must be ONE crash transaction.
//!
//! The row (X5-03 of the 30 Aug 2026 adversarial-row set) has two
//! oracles. `e2e_resume::crashtx` pins the first - "the exact output
//! remains" - against the `get` CLI, and its own header says at length
//! why the other two cannot be asked there: "restart performs zero BODY
//! requests" and "the row reaches Completed" are claims about a
//! PERSISTED TERMINAL STATE, and the CLI has none. The journal is its
//! only durable record, retiring it on a verified finish is correct, and
//! a plain no-PAR2 post leaves nothing on disk that certifies the bytes
//! - so a second `nzbfast get` over the same directory cannot know the
//! file is complete and refetching is the only honest thing it can do.
//!
//! The DAEMON has that durable record: the queue row. So this is where
//! the other two oracles live, and the full row is asked here.
//!
//! WHAT MAKES IT ASKABLE AT ALL is that the daemon runs the SAME
//! `get::tail::finish_job`, so the product barrier the CLI probe uses
//! (`test_park_after_engine_finish`, armed by
//! `NZBFAST_TEST_PARK_AFTER_ENGINE_FINISH_MS`) is already on the
//! daemon's path - no second seam. The window it opens is microseconds
//! wide on an idle box, so a test that SLEEPS into it is guessing, and a
//! guess on a box running nine lanes' cargo builds is a flake in both
//! directions. The product says where it is and holds still; the probe
//! waits for the LINE - a state - and kills.
//!
//! WHERE THE DAEMON'S OWN WINDOW SITS, because it is not the CLI's.
//! `postproc::Lane::submit` marks the row `Finishing` and calls
//! `save_queue_soon` the instant the network phase ends, and only THEN
//! does `run_tail` await the engine future that retires the journal. So
//! at the barrier the durable record says `Finishing`, the journal is
//! gone, the payload is on disk and nothing has committed a terminal
//! state - which is exactly the state the row names, reached through the
//! daemon's own scheduling rather than by writing a spool file by hand.
//! `job_wire`'s state arm restores anything nonterminal as `Queued`.
//!
//! A sibling-dir child of daemon.rs (the `daemon_finish` pattern) so the
//! parent stays inside its size-gate baseline. Declared from daemon.rs,
//! so these run in that binary against those fixtures; harness via
//! `super::*`.

use super::*;

/// The marker `get::tail::test_park_after_engine_finish` prints. Typed
/// here a second time because a test binary cannot see a private const
/// in the library; if the two ever part, `wait_for` below fails LOUDLY
/// with the whole log rather than passing on a window it never reached.
const PARKED: &str = "engine finish settled - parked for the crash-transaction probe";

/// The wedge bound handed to the barrier. It is not a wait - the test
/// waits for `PARKED` and for the persisted state - only the ceiling on
/// how long a parked daemon holds if the test dies before killing it.
const PARK_MS: &str = "60000";

/// One small plain no-PAR2 post, whole in a few articles: a job that
/// finishes in about a second and leaves nothing on disk that could
/// certify the bytes after the fact. That last half is the point - a
/// PAR2 set would let a restart re-verify what it found and answer the
/// row for a reason the row is not about.
fn one_file_nzb(data: &[u8], articles: &mut HashMap<String, Vec<u8>>) -> String {
    let segs = make_file_articles("f.bin", data, 30_000, "ctx", articles);
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;f.bin&quot; yEnc (1/2)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

/// Upload one NZB and return the nzo_id it was given.
fn add_nzb(port: u16, xml: &str) -> String {
    let boundary = "----crashtxb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Crash.Tx.2026.nzb\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let added = http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    added
        .split("\"nzo_ids\":[\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or_else(|| panic!("no nzo_id in {added}"))
        .to_string()
}

/// This job's row as `.spool/queue.jsonl` records it, or `None` if the
/// store does not carry it at all.
///
/// NOT `harness::queue_slot`, which reads a SAB `mode=queue` BODY -
/// `{"queue":{"slots":[..]}}` - where the store is one compact record
/// per LINE. And not a substring search for the id over the whole file:
/// the ids are minted off a plain counter, so `...nzbfast1` is a strict
/// prefix of `...nzbfast10` up, and the file carries an `out_dir` and an
/// `nzb_path` that both spell the id too. Read the field it means.
///
/// Through `queuestore::replay_bytes` rather than a hand-rolled scan of
/// the lines, because §7a's store is append-only: the LAST line for an
/// id wins, a tombstone buries it, and a crash can leave a torn tail -
/// which is precisely the state this test's subject creates, so reading
/// it any other way would answer with a superseded row.
fn spool_row(saved: &str, nzo: &str) -> Option<serde_json::Value> {
    nzbfast_daemon::queuestore::replay_bytes(saved.as_bytes())
        .rows
        .into_iter()
        .find(|(id, _, _)| id == nzo)
        .map(|(_, v, _)| v)
}

/// Every regular file under `root`, BASENAME and bytes, sorted, with
/// `.nzbfast.journal` left out.
///
/// The verdict is graded over the whole output tree rather than over one
/// expected path, because the predicted failure MOVES the payload rather
/// than deleting it: `quarantine_failed_payload` takes a failed run's
/// bytes out of circulation by RENAMING them, so a probe that read one
/// path would call a directory with no `f.bin` in it either "missing"
/// (true but unexplained) or, if it read the quarantined copy, fine.
///
/// The journal is the ONE exclusion and it is not a convenience. At the
/// barrier it is already gone - that is the whole premise, asserted
/// below - so dropping it changes nothing on that side; what it drops is
/// the FRESH one a re-running job writes, which is a true statement
/// about a restart that re-ran and has nothing to say about whether the
/// delivered bytes survived. Everything else is debris and must count.
///
/// BASENAME AND NOT THE PATH UNDER `root`, and that is measured rather
/// than lax. The barrier sits INSIDE the engine, so the daemon's own
/// completion tail has not run yet - and when it does it renames the job
/// DIRECTORY (on this fixture, `Crash.Tx.2026` -> `Crash Tx 2026`, the
/// `smart` rename, observed here 31 Aug 2026). Grading on the relative
/// path would therefore report a loss in exactly the state the row wants
/// to reach, which is a gate the fix commit could not pass. What the
/// predicted loss moves is the FILE name -
/// `quarantine_failed_payload` renames the payload out of circulation,
/// which the engine half measured as `movie.quarantined` - so the file
/// name is what has to be graded, and it still is. The oracle pairs this
/// with a read at the history row's own `storage`, so "somewhere under
/// out/" is not the whole claim.
fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().is_some_and(|n| n == ".nzbfast.journal") {
                continue;
            } else if let Ok(b) = std::fs::read(&p) {
                out.push((
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    b,
                ));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// A SIGKILL in the X5-03 window, followed by a daemon restart against a
/// post that has gone away, must leave the delivered payload byte-exact,
/// must take the row to Completed, and must ask the provider for nothing.
///
/// Run 1 completes a plain no-PAR2 job, so at the barrier the bytes are
/// on disk, the journal is gone and the persisted row says `Finishing` -
/// the exact state the row names. SIGKILL there, take the post down, and
/// restart in the same directory: the provider now answers 430 for every
/// BODY, which is what makes the question sharp. A restart that refetches
/// has nothing to refetch WITH, so anything it does to the good file it
/// does for nothing.
///
/// MEASURED 31 Aug 2026, and two of the three oracles fail. A
/// nonterminal `Finishing` restores as `Queued` (`job_wire.rs`'s
/// wildcard state arm), the journal is gone so there is nothing to
/// resume from, the job re-runs, all 44 requests are refused, and the
/// row files `Failed` over an output directory holding the finished
/// release - which is what an *arr reads.
///
/// The row's prediction was one step worse than that and is REFUTED on
/// this shape: `quarantine_failed_payload` does NOT take the complete
/// download out of the directory, because the failing run wrote nothing,
/// so the payload it would quarantine is not one that run produced. The
/// damage is narrower than predicted and entirely about the ROW. That is
/// why "the exact output remains" is graded here anyway rather than
/// dropped - it is the oracle that HOLDS, and an oracle that has only
/// ever been seen green is a rubber stamp until something has been seen
/// to make it fail (mutations M3 and M4 of
/// `research/X5-03-CRASH-TRANSACTION-2026-08-31.md` section 7).
#[tokio::test(flavor = "multi_thread")]
async fn x5_03_a_crash_after_journal_retirement_completes_the_row_without_refetching() {
    let dir = std::env::temp_dir().join(format!("nzbfast-crashtx-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let out = dir.join("complete");
    let spool = dir.join(".spool").join("queue.jsonl");
    let cfg = dir.join("config.json");

    let data = payload(600_000, 11);
    let mut articles = HashMap::new();
    let xml = one_file_nzb(&data, &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false,\"connections\":2}}]}}",
            srv.addr.port()
        ),
    )
    .unwrap();

    // `park` is only set on the FIRST daemon: the restart must run the
    // ordinary product path, or the verdict would be about the barrier.
    let build = |park: bool, cfg: PathBuf, out: PathBuf| {
        move |port: u16| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_NO_ENRICH", "1")
                // No key: every request here is a plain loopback call.
                .env("NZBFAST_OPEN", "1");
            if park {
                c.env("NZBFAST_TEST_PARK_AFTER_ENGINE_FINISH_MS", PARK_MS);
            }
            c.arg("--config")
                .arg(&cfg)
                .arg("serve")
                .arg("--bind")
                .arg("127.0.0.1")
                .arg("--port")
                .arg(port.to_string())
                .arg("--out")
                .arg(&out)
                .arg("--connections")
                .arg("2");
            c
        }
    };

    let d = serve(&dir, build(true, cfg.clone(), out.clone())).await;
    let port = d.port;

    // Run 1, killed inside the window. `wait_for` and the polls block,
    // and the mock server this daemon is talking to lives on the same
    // runtime, so the whole sequence goes off the worker threads.
    let (nzo, at_barrier) = {
        let (spool, out) = (spool.clone(), out.clone());
        let (xml, data) = (xml.clone(), data.clone());
        tokio::task::spawn_blocking(move || {
            let nzo = add_nzb(port, &xml);
            let log = d.wait_for(PARKED);
            // THE PREMISE, asserted rather than assumed. Without a
            // persisted `Finishing` the kill below lands on a record
            // that says something else, and every verdict after it is
            // about a different question - which is the shape
            // `integration::postproc_lane`'s restart leg failed in on
            // 8 Aug 2026, killing while the durable record was still
            // the "Queued" snapshot from the add. `Lane::submit` marks
            // the row and calls `save_queue_soon`, which is debounced,
            // so this really is two events and not one.
            let mut job_out = PathBuf::new();
            for i in 0..200 {
                let saved = std::fs::read_to_string(&spool).unwrap_or_default();
                if let Some(row) = spool_row(&saved, &nzo)
                    && row["state"] == "Finishing"
                {
                    job_out = PathBuf::from(row["out_dir"].as_str().unwrap_or_default());
                    break;
                }
                assert!(
                    i < 199,
                    "the row never reached a persisted Finishing state\n\
                     --- queue.jsonl ---\n{saved}\n--- log ---\n{log}"
                );
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            // ...and the bytes really are delivered at the barrier.
            // Read at the job's OWN out_dir, taken from the record above
            // rather than rebuilt from the release name, so a change in
            // how `choose_out_dir` spells a directory cannot turn this
            // premise into a quiet pass.
            let at_barrier = tree(&out);
            assert!(
                at_barrier.iter().any(|(_, b)| b == &data),
                "run 1 parked without the payload complete: {:?}\n{log}",
                at_barrier.iter().map(|(p, _)| p).collect::<Vec<_>>()
            );
            // ...and the journal is STILL THERE, which is the fix's own
            // mechanism asserted at the one instant it has to hold.
            //
            // IT USED TO ASSERT THE OPPOSITE, and the flip IS X5-03
            // rather than a loosened premise. The engine used to unlink
            // on every verified finish, so at the barrier the only
            // durable statement that the payload had arrived was already
            // gone while the persisted row still said `Finishing` -
            // which `job_wire` restores as `Queued`. The engine now
            // keeps it for whoever owns the terminal record
            // (`get::JournalOwner::Caller`) and `serve::job::
            // retire_deferred_journal` unlinks it once that record is
            // durable. Keeping it is NECESSARY and nowhere near
            // sufficient: the three oracles below are what say the
            // restart actually read it.
            assert!(
                job_out.is_dir() && job_out.join(".nzbfast.journal").exists(),
                "run 1 parked with the journal already unlinked at {job_out:?} - the \
                 daemon's terminal record is not written until its post-processing \
                 tail, so nothing on disk would say the payload had arrived\n{log}"
            );
            // SIGKILL. `Child::kill` is SIGKILL on unix, so nothing in
            // the daemon gets to run a shutdown path - which is the
            // whole premise: wind-down's own `save_queue` would flush a
            // terminal state this row is asking about the absence of.
            let _log = d.stop();
            (nzo, at_barrier)
        })
        .await
        .unwrap()
    };

    // The post is gone: every BODY is now a 430, so run 2 cannot rebuild
    // anything it destroys - and every request it makes is recorded,
    // because `BodyLog` stamps a request's ARRIVAL, before the article
    // lookup that refuses it.
    assert!(
        srv.take_down() > 0,
        "the fixture posted nothing to take down"
    );
    let asked_before = srv.body_log.lock().unwrap().len();

    let d = serve(&dir, build(false, cfg, out.clone())).await;
    let port = d.port;
    let (log, hist) = {
        let nzo = nzo.clone();
        tokio::task::spawn_blocking(move || {
            let mut hist = serde_json::Value::Null;
            for _ in 0..600 {
                let h = http(port, "/api?mode=history&output=json", None);
                let slot = history_slot(&h, &nzo);
                if !slot.is_null() {
                    hist = slot;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            (d.log(), hist)
        })
        .await
        .unwrap()
    };

    // ONE VERDICT CARRYING ALL THREE ORACLES, rather than three
    // assertions in a row. It was written that way while two of the
    // three were RED and this test was `#[ignore]`d, so that whoever
    // deleted the attribute could read off what was left rather than
    // seeing only the first failure - and it is KEPT that way now they
    // all hold, for the shape a REGRESSION has: these three fail
    // together or not at all (the journal's lifetime moves all of
    // them), so three separate `assert!`s would report one symptom of a
    // defect that has three, and the reader would fix by that one.
    // Every oracle is evaluated on every run and the report names each
    // by the row's own words.
    let mut failed = Vec::new();
    // "the row reaches Completed" - the durable terminal state the whole
    // row is about. A restart that re-runs the download can only file it
    // Failed: there is nothing on the wire left to fetch.
    if hist["status"] != "Completed" {
        failed.push(format!(
            "the row reaches Completed: it is {} - {}",
            hist["status"], hist["fail_message"]
        ));
    }
    // "restart performs zero BODY requests". The bytes were already
    // delivered and the durable record is what has to say so; asking the
    // provider at all means the restart did not know.
    let asked: Vec<String> = srv.body_log.lock().unwrap()[asked_before..].to_vec();
    if !asked.is_empty() {
        failed.push(format!(
            "restart performs zero BODY requests: it asked for {} ({:?}...)",
            asked.len(),
            &asked[..asked.len().min(3)]
        ));
    }
    // "the exact output remains". Graded over the whole tree, so a
    // quarantine RENAME is a failure rather than a pass on bytes that
    // are still somewhere - `quarantine_failed_payload` takes a failed
    // run's payload out of circulation without deleting it, which would
    // satisfy a byte comparison while handing an *arr a directory with
    // no `f.bin` in it. This one HELD when the probe was written (31 Aug
    // 2026), which is the engine half's answer arriving unchanged on the
    // daemon path.
    let after = tree(&out);
    let storage = PathBuf::from(hist["storage"].as_str().unwrap_or_default());
    if std::fs::read(storage.join("f.bin")).unwrap_or_default() != data {
        failed.push(format!(
            "the exact output remains: the payload is not byte-exact at the row's own \
             storage path {storage:?}"
        ));
    }
    if after != at_barrier {
        let names = |t: &[(String, Vec<u8>)]| {
            t.iter()
                .map(|(p, b)| format!("{p} ({} bytes)", b.len()))
                .collect::<Vec<_>>()
        };
        failed.push(format!(
            "the exact output remains: {:?} became {:?}",
            names(&at_barrier),
            names(&after)
        ));
    }
    assert!(
        failed.is_empty(),
        "X5-03 is not held on the daemon path - {} failed check(s) over its three \
         oracles:\n  - {}\n--- history row ---\n{hist}\n--- log ---\n{log}",
        failed.len(),
        failed.join("\n  - ")
    );
}

/// THE SAME ROW WITH THE CRASH REMOVED, and it must be green.
///
/// Two jobs, and the second is the one that made it worth landing.
///
/// FIRST, it is the CONTROL. A probe that is red for the predicted
/// reason AND for an unrelated one is indistinguishable from a probe
/// that is red for the unrelated one alone, so the red above is only
/// evidence if the same fixture, the same helpers and the same three
/// oracles come out green when the kill is taken away. Run 1 is allowed
/// to finish, the post is then taken down, and the daemon is restarted:
/// the row is already terminal, so it stays Completed, asks for nothing
/// and leaves the payload alone. Measured green 31 Aug 2026.
///
/// SECOND, it asks a question its sibling cannot. The sibling kills at
/// the barrier, so it never reaches the daemon's own retirement - this
/// one runs the tail to the end, and its last assertion is the only
/// thing anywhere that says an ORDINARY completion leaves no journal
/// behind. Deleting `serve::job::retire_deferred_journal` leaves the
/// crash probe GREEN (a lingering journal is harmless to a restart,
/// which is exactly why it cannot see the loss) and reddens this -
/// measured as mutation M2 of
/// `research/X5-03-CRASH-TRANSACTION-2026-08-31.md` section 8.
///
/// It was landed for a narrower reason that has since expired and is
/// recorded because it is worth copying: while the sibling was
/// `#[ignore]`d this was the ONLY thing running the module at all, so
/// the fixture, `spool_row`, `tree`, the `take_down`/`body_log` oracle
/// and the restart path would otherwise have sat unexercised until
/// somebody deleted that attribute and met a rot that had nothing to do
/// with X5-03. Land the control WITH the ignored probe, never after.
///
/// WHAT IT DELIBERATELY DOES NOT ASK is the barrier. It never sets
/// `NZBFAST_TEST_PARK_AFTER_ENGINE_FINISH_MS` and never reads the
/// persisted `Finishing`, because there is no crash here for either to
/// be about. Those two premises are its sibling's, and the mutations
/// recorded in `research/X5-03-CRASH-TRANSACTION-2026-08-31.md` are
/// what hold them.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_row_without_the_crash_completes_and_refetches_nothing() {
    let dir = std::env::temp_dir().join(format!("nzbfast-crashtxok-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let out = dir.join("complete");
    let cfg = dir.join("config.json");

    let data = payload(600_000, 11);
    let mut articles = HashMap::new();
    let xml = one_file_nzb(&data, &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false,\"connections\":2}}]}}",
            srv.addr.port()
        ),
    )
    .unwrap();
    let build = |cfg: PathBuf, out: PathBuf| {
        move |port: u16| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_NO_ENRICH", "1")
                .env("NZBFAST_OPEN", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("serve")
                .arg("--bind")
                .arg("127.0.0.1")
                .arg("--port")
                .arg(port.to_string())
                .arg("--out")
                .arg(&out)
                .arg("--connections")
                .arg("2");
            c
        }
    };

    let d = serve(&dir, build(cfg.clone(), out.clone())).await;
    let port = d.port;
    let (nzo, before) = {
        let out = out.clone();
        let xml = xml.clone();
        tokio::task::spawn_blocking(move || {
            let nzo = add_nzb(port, &xml);
            for i in 0..600 {
                let h = http(port, "/api?mode=history&output=json", None);
                if history_slot(&h, &nzo)["status"] == "Completed" {
                    break;
                }
                assert!(
                    i < 599,
                    "the control job never completed:\n--- log ---\n{}",
                    d.log()
                );
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let before = tree(&out);
            // A clean stop, not the probe's SIGKILL: this leg is about
            // what a restart does to a row that reached its terminal
            // state the ordinary way.
            let _log = d.stop();
            (nzo, before)
        })
        .await
        .unwrap()
    };

    assert!(
        srv.take_down() > 0,
        "the fixture posted nothing to take down"
    );
    let asked_before = srv.body_log.lock().unwrap().len();

    let d = serve(&dir, build(cfg, out.clone())).await;
    let port = d.port;
    let (log, hist) = {
        let nzo = nzo.clone();
        tokio::task::spawn_blocking(move || {
            // A window for the restart to do something wrong in. There
            // is no state to wait FOR here - the claim is that nothing
            // happens - so this is the one place in the module that
            // spends wall clock, and it is a floor on the observation
            // rather than a guess at when an event lands. The scheduler
            // picks within a second of the restored queue being read,
            // and the probe above measures a re-run reaching its 44th
            // refusal inside two.
            std::thread::sleep(std::time::Duration::from_secs(5));
            let h = http(port, "/api?mode=history&output=json", None);
            (d.log(), history_slot(&h, &nzo))
        })
        .await
        .unwrap()
    };

    assert_eq!(
        hist["status"], "Completed",
        "a terminal row did not survive the restart: {hist}\n--- log ---\n{log}"
    );
    let asked: Vec<String> = srv.body_log.lock().unwrap()[asked_before..].to_vec();
    assert!(
        asked.is_empty(),
        "the restart asked for {} body/bodies over a Completed row: {asked:?}\n\
         --- log ---\n{log}",
        asked.len()
    );
    assert_eq!(
        tree(&out),
        before,
        "the output changed across a restart that had nothing to do\n--- log ---\n{log}"
    );
    assert!(
        before.iter().any(|(n, b)| n == "f.bin" && b == &data),
        "the control's own premise: the payload is not on disk byte-exact"
    );
    // ...AND THE JOURNAL IS GONE, which is the OTHER half of X5-03's fix
    // and the half nothing else in this module would notice the loss of.
    // The engine no longer retires a daemon job's journal
    // (`get::JournalOwner::Caller`); `serve::job::
    // retire_deferred_journal` does, straight after the `save_queue`
    // that persists the `finalizing` marker. Delete that call and the
    // probe above still passes - a lingering journal is harmless to a
    // restart, which is exactly why `Journal::remove`'s own doc calls
    // not-retiring always safe - and every completed release would ship
    // a stray `.nzbfast.journal` into the user's library forever.
    //
    // Asserted here and not in the sibling because this is the
    // ORDINARY path - a job that completed the normal way, with no
    // crash anywhere near it - and because the sibling kills at the
    // barrier and never reaches the retirement at all. `tree()` filters
    // the journal out by name, so this reads the directory itself.
    assert!(
        !PathBuf::from(hist["storage"].as_str().unwrap_or_default())
            .join(".nzbfast.journal")
            .exists(),
        "an ordinary completion left its journal behind at {} - the daemon owns the \
         retirement now and did not do it\n--- log ---\n{log}",
        hist["storage"]
    );
}
