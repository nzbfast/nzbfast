//! X5-12: a DELETE arriving ACROSS a synchronous resume replay.
//!
//! The row (X5-12 of the 30 Aug 2026 adversarial-row set) was carried
//! unbuilt for one recorded reason: it needs a spawn-with-handle
//! harness and a way to hold the replay open, and neither existed when
//! the set was written. `run_get_spawn` landed as `23ce5ab55` and the
//! daemon half of the same family - `daemon_crashtx` - landed the
//! process control this module reuses wholesale, so what was left was
//! the second half of that sentence: a product barrier inside the
//! replay. That is `get::rig`'s `test_park_in_replay`, armed by
//! `NZBFAST_TEST_PARK_IN_REPLAY_MS`, and it is the sibling of
//! `get::tail::test_park_after_engine_finish` in shape and in argument.
//!
//! WHY A DELETE ACROSS A REPLAY IS ITS OWN QUESTION, and not a case of
//! the ordinary delete `daemon_delete` already grades. The replay is
//! `ReplayPending::feed_spans`, a SYNCHRONOUS loop that reads restored
//! bytes off disk and writes them back through the extractor - it holds
//! open file handles into `out_dir` and journals every article it feeds.
//! A `del_files=1` delete arriving mid-loop is therefore a request to
//! remove a directory that a live writer is in the middle of writing
//! into, and the two orders it could take are not equally good: remove
//! first and the replay's next chunk RECREATES what was just deleted,
//! leaving bytes an *arr can import after the user asked for them to be
//! gone. `Job::del_on_drop` is the product's answer - the handler
//! reserves the directory and defers the removal to `park()`, once the
//! fetch has drained and the writers are gone - and nothing anywhere
//! asked whether that holds when the writer is the REPLAY rather than
//! the pool.
//!
//! MEASURED 31 Aug 2026, AND THE ROW HOLDS. The delete is accepted while
//! the replay is parked mid-chunk, the replay is not torn down under it,
//! nothing is removed while it still has writers, and `park()` takes the
//! whole tree - payload and journal - once it releases. What the row
//! turns from a belief into a pinned fact is the ORDER, which is why the
//! oracle below reads the tree TWICE.
//!
//! A sibling-dir child of daemon.rs (the `daemon_crashtx` pattern) so
//! the parent stays inside its size-gate baseline. Declared from
//! daemon.rs, so these run in that binary against those fixtures;
//! harness via `super::*`.

use super::*;

/// The marker `get::rig::test_park_in_replay` prints. Typed here a
/// second time because a test binary cannot see a private const in the
/// library; if the two ever part, the wait below fails LOUDLY with the
/// whole log rather than passing on a window it never reached.
const REPLAY_PARKED: &str = "resume replay fed its first chunk - parked for the delete probe";

/// The wedge bound handed to the barrier.
///
/// SHORTER THAN ITS SIBLING'S 60 s, and for a reason that inverts the
/// trade. `daemon_crashtx` KILLS inside its window, so it never waits
/// the park out and a long bound costs nothing. This row needs the run
/// to CONTINUE - the whole question is what the replay and `park()` do
/// after the delete lands - so the bound is paid in full by every run.
/// Ten seconds against a delete issued the instant the log line appears
/// (a 25 ms poll, one loopback request) is roughly a 400x margin on a
/// box running nine lanes' cargo builds, which is the scale the
/// `WAIT_FOR_LIMIT` note in `e2e_getrun` prices these against.
const PARK_MS: &str = "10000";

/// How long to wait for the deferred removal after the delete answers.
/// It has to cover the park bound above plus the wind-down behind it,
/// and it is an ORDERING wait in `harness::wait_until`'s sense: the
/// number only has to beat scheduler starvation, never the thing being
/// waited for. Measured at 10.4 s on an idle box, of which 10 is the
/// bound above.
const REMOVAL_LIMIT: std::time::Duration = std::time::Duration::from_secs(45);

/// Three plain files in one post, each in its OWN article namespace.
///
/// The namespace is not decoration: sharing one context across the
/// files gives all three the same message-ids, and the daemon then
/// reports "NZB repeats 60 segment id(s)" and fetches each article once
/// - a third of the intended post, and a fixture that is not what it
/// says it is. Seen while building this row.
fn multi_file_nzb(files: &[(&str, Vec<u8>)], articles: &mut HashMap<String, Vec<u8>>) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, data) in files {
        let segs = make_file_articles(name, data, 30_000, name, articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/2)\">\n    <groups><group>g</group></groups>\n    <segments>\n"
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    xml
}

/// Upload one NZB and return the nzo_id it was given.
fn add_nzb(port: u16, xml: &str) -> String {
    let boundary = "----replaydelb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Replay.Del.2026.nzb\"\r\n\r\n"
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

/// Every regular file under `root`, basename and length, sorted.
///
/// The JOURNAL IS COUNTED HERE, unlike its sibling module's `tree`, and
/// the difference is the row rather than a preference. There the journal
/// is excluded because a re-running job writes a FRESH one that says
/// nothing about whether the delivered bytes survived. Here the question
/// is whether a `del_files=1` delete took the directory, and a journal
/// left behind is a directory a later adoption can still find - so it
/// counts as debris exactly like a payload file does.
///
/// Length and not bytes: the payload is written into files the extractor
/// PREALLOCATES to their full declared size, so a partial run's `a.bin`
/// is already 900,000 bytes of mostly nothing. Nothing here grades
/// content - the row is about what remains, not about what it says.
fn tree(root: &Path) -> Vec<(String, u64)> {
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
            } else if let Ok(m) = std::fs::metadata(&p) {
                out.push((
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    m.len(),
                ));
            }
        }
    }
    out.sort();
    out
}

/// Both rows' fixture and both rows' body, parameterised by whether a
/// delete is issued at the barrier.
///
/// ONE FUNCTION AND NOT TWO, because the control's whole job is to be
/// the SAME fixture, the same helpers and the same wait with only the
/// delete taken away - the division `daemon_crashtx`'s own control note
/// argues for. A probe that is red for the predicted reason AND for an
/// unrelated one is indistinguishable from a probe that is red for the
/// unrelated one alone, and here the trap is sharper than usual: the
/// main row's verdict is "the tree ended EMPTY", which a barrier that
/// had simply wedged the run would also produce.
struct Round {
    /// The nzo_id run 1 was given.
    nzo: String,
    /// What was on disk when run 1 was killed - the partial the resume
    /// restores from.
    at_kill: Vec<(String, u64)>,
    /// The delete's own JSON answer, empty when none was issued.
    delete_answer: String,
    /// The tree read WHILE the replay was still parked, immediately
    /// after the delete answered. This is the ordering half of the
    /// oracle: a removal that happened here is one that raced a live
    /// writer.
    while_parked: Vec<(String, u64)>,
    /// The tree once the run wound down, and how long that took.
    at_end: Vec<(String, u64)>,
    gone_at: Option<std::time::Duration>,
    queue_has: bool,
    history_has: bool,
    log: String,
}

async fn round(dir: &Path, delete: bool) -> Round {
    let out = dir.join("complete");
    let cfg = dir.join("config.json");
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("a.bin", payload(900_000, 21)),
        ("b.bin", payload(900_000, 22)),
        ("c.bin", payload(900_000, 23)),
    ];
    let mut articles = HashMap::new();
    let xml = multi_file_nzb(&files, &mut articles);
    // A per-BODY delay so run 1 has a window to be killed IN - see
    // `run 1` below for why the fixture is unusable without it.
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 100,
            ..Chaos::default()
        },
    )
    .await;
    // WRITTEN, never assumed: `nzbkit::config::Config::load` answers a
    // missing file by going and finding a SABnzbd install's
    // `sabnzbd.ini` through `$HOME`, so a daemon handed a path nobody
    // wrote is testing the developer's machine rather than the product
    // (`tools/host-config-gate.py`, and the two doors that cost in two
    // days).
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false,\"connections\":2}}]}}",
            srv.addr.port()
        ),
    )
    .unwrap();

    let build = |park: bool, cfg: PathBuf, out: PathBuf| {
        move |port: u16| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_NO_ENRICH", "1")
                // No key: every request here is a plain loopback call.
                .env("NZBFAST_OPEN", "1");
            if park {
                c.env("NZBFAST_TEST_PARK_IN_REPLAY_MS", PARK_MS);
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

    // Run 1, killed once it has a partial. `park` is only set on the
    // SECOND daemon: run 1 must reach its partial at full speed, and it
    // has no replay to park in anyway.
    let d = serve(dir, build(false, cfg.clone(), out.clone())).await;
    let port = d.port;
    let nzo = {
        let (xml, blog) = (xml.clone(), srv.body_log.clone());
        tokio::task::spawn_blocking(move || {
            let nzo = add_nzb(port, &xml);
            // A STATE and not a clock: `body_log` reaching a count is
            // the only honest way to reach a partial. The mock's
            // `delay_ms` above exists so that state is REACHABLE -
            // without it this fixture served all 90 articles on
            // loopback before the first poll came round, and the probe
            // silently measured a COMPLETED job whose delete then
            // answered "nothing in the queue matched that" (seen 31 Aug
            // 2026). The delay is never the thing waited for.
            for i in 0..300 {
                if blog.lock().unwrap().len() >= 30 {
                    break;
                }
                assert!(
                    i < 299,
                    "run 1 never served 30 bodies, so there is no partial to resume from\n{}",
                    d.log()
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            // SIGKILL. `Child::kill` is SIGKILL on unix, so nothing in
            // the daemon runs a shutdown path - a wind-down would flush
            // a terminal state and leave nothing to resume.
            let _log = d.stop();
            nzo
        })
        .await
        .unwrap()
    };
    let at_kill = tree(&out);

    // Run 2: resume, park inside the replay, and - for the main row -
    // delete across it.
    let d = serve(dir, build(true, cfg, out.clone())).await;
    let port = d.port;
    let (nzo2, outdir) = (nzo.clone(), out.clone());
    let mut r = tokio::task::spawn_blocking(move || {
        // THE PREMISE, waited for rather than assumed. Without the
        // barrier line the delete below lands wherever the scheduler
        // happens to have got to, and every verdict after it is about a
        // different question.
        let log = d.wait_for(REPLAY_PARKED);
        let delete_answer = if delete {
            http(
                port,
                &format!("/api?mode=queue&name=delete&value={nzo2}&del_files=1&output=json"),
                None,
            )
        } else {
            String::new()
        };
        // Read WHILE STILL PARKED. The replay thread is held inside
        // `feed_spans`, so anything the delete removed, it removed out
        // from under a live writer.
        let while_parked = tree(&outdir);
        let started = std::time::Instant::now();
        let mut gone_at = None;
        // BY SLOT, never `payload.contains(&id)`: mode=queue's whyslow
        // block names the LAST job's own nzo_id, so a substring search
        // reads TRUE against a queue whose `slots` is empty - which is
        // the very state this loop is waiting for
        // (`tools/payload-id-gate.py`, which caught it here).
        let (mut in_queue, mut in_history) = (false, false);
        while started.elapsed() < REMOVAL_LIMIT {
            let q = http(port, "/api?mode=queue&output=json", None);
            let h = http(port, "/api?mode=history&output=json", None);
            in_queue = queue_has(&q, &nzo2);
            in_history = history_has(&h, &nzo2);
            if tree(&outdir).is_empty() {
                gone_at = Some(started.elapsed());
                break;
            }
            // The control deletes nothing, so its tree never goes: it
            // waits for the job to reach a terminal history row instead.
            if !delete && in_history {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Round {
            nzo: nzo2.clone(),
            at_kill: Vec::new(),
            delete_answer,
            while_parked,
            at_end: tree(&outdir),
            gone_at,
            queue_has: in_queue,
            history_has: in_history,
            log: format!("{log}\n{}", d.log()),
        }
    })
    .await
    .unwrap();
    r.at_kill = at_kill;
    r.nzo = nzo;
    r
}

/// A `del_files=1` delete landing INSIDE the replay window must be
/// accepted, must not be acted on while the replay still has writers,
/// and must take the whole tree - payload and journal - once it does.
///
/// MEASURED 31 Aug 2026 and the row HOLDS, which is the answer rather
/// than a disappointment: the question was live because nothing had
/// asked it, and `Job::del_on_drop`'s deferral was written for the POOL
/// being the live writer, not the replay. The replay is a different
/// writer on a different thread reached by a different path, and it
/// journals as it goes.
///
/// THE ORACLE READS THE TREE TWICE, and the first read is what makes the
/// second one mean anything. "The tree ended empty" alone is satisfied
/// by a delete that removed everything IMMEDIATELY - which is the defect
/// this row is about, because the replay's next chunk then recreates
/// what was just deleted and the user is left with bytes they asked to
/// be rid of. So the row asserts the ORDER: still there while the
/// replay is parked, gone after it releases.
#[tokio::test(flavor = "multi_thread")]
async fn x5_12_a_delete_across_a_resume_replay_defers_its_removal_until_the_writers_are_gone() {
    let dir = std::env::temp_dir().join(format!("nzbfast-replaydel-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let r = round(&dir, true).await;

    // The premise: run 1 really did leave a partial with a journal in
    // it. Without one there is no replay, the barrier never fires, and
    // `wait_for` above would already have failed - but a fixture that
    // silently stopped producing a journal would leave this row
    // measuring an ordinary delete.
    assert!(
        r.at_kill.iter().any(|(n, _)| n == ".nzbfast.journal"),
        "run 1 left no journal, so run 2 has nothing to replay: {:?}",
        r.at_kill
    );

    let mut failed = Vec::new();
    // "the delete is accepted". A request landing on a job whose replay
    // thread is mid-chunk must not be refused, and must not hang.
    if !r.delete_answer.contains("\"status\":true") || !r.delete_answer.contains("\"removed\":1") {
        failed.push(format!(
            "the delete is accepted: it answered {}",
            r.delete_answer
        ));
    }
    // "nothing is removed while the replay still holds writers". The
    // ordering half - see the note above.
    if r.while_parked.is_empty() {
        failed.push(
            "nothing is removed while the replay still holds writers: the tree was already \
             empty with the replay parked mid-chunk, so the removal raced a live writer"
                .to_string(),
        );
    }
    // "the tree goes, once they are". Payload AND journal: a journal
    // left behind is a directory a later adoption can still find.
    if !r.at_end.is_empty() {
        failed.push(format!(
            "the tree goes once the writers are gone: {:?} survived a del_files=1 delete \
             (gone_at {:?})",
            r.at_end, r.gone_at
        ));
    }
    // "the row goes with it".
    if r.queue_has || r.history_has {
        failed.push(format!(
            "the row goes with it: queue_has={} history_has={}",
            r.queue_has, r.history_has
        ));
    }
    assert!(
        failed.is_empty(),
        "X5-12 is not held - {} failed check(s):\n  - {}\n--- log ---\n{}",
        failed.len(),
        failed.join("\n  - "),
        r.log
    );
}

/// THE SAME ROW WITH THE DELETE REMOVED, and it must be green.
///
/// It is the CONTROL, and here it carries more weight than a control
/// usually does. Its sibling's verdict is "the output tree ended
/// EMPTY", and a barrier that had simply WEDGED the resume would
/// produce exactly that - no replay, no download, no output, an empty
/// directory and four green oracles. So the same fixture, the same
/// barrier and the same wait are run with nothing deleted, and the job
/// must resume, finish and leave its payload where an *arr would find
/// it.
///
/// It also pins the barrier itself: `test_park_in_replay` is production
/// code behind an env var, and a run with it armed must differ from one
/// without it only in WHEN it finishes.
#[tokio::test(flavor = "multi_thread")]
async fn a_parked_replay_with_nobody_deleting_resumes_and_finishes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-replaydel-ctl-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let r = round(&dir, false).await;

    assert!(
        r.at_kill.iter().any(|(n, _)| n == ".nzbfast.journal"),
        "run 1 left no journal, so run 2 has nothing to replay: {:?}",
        r.at_kill
    );
    assert!(
        r.delete_answer.is_empty(),
        "the control must issue no delete, got {}",
        r.delete_answer
    );
    // The three payload files, complete, still there. `tree` reports
    // preallocated length rather than content, so this says the run
    // reached its outputs and nothing took them away - which is exactly
    // the claim the sibling's empty tree needs to be measured against.
    let names: Vec<&str> = r.at_end.iter().map(|(n, _)| n.as_str()).collect();
    for want in ["a.bin", "b.bin", "c.bin"] {
        assert!(
            names.contains(&want),
            "the parked replay must still finish the job: {want} is missing from {names:?}\n\
             --- log ---\n{}",
            r.log
        );
    }
    assert!(
        r.gone_at.is_none(),
        "nothing deleted anything, so nothing may have removed the tree (gone_at {:?})",
        r.gone_at
    );
}
