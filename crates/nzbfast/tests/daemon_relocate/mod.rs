//! Codex F-06 (24 Aug 2026 read-only sweep): the relocation fence.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//! It also keeps daemon.rs under the size gate, which this case would
//! have put 27 lines over on its own.

use super::*;

/// Codex F-06: the relocation fence. `requeue_category` publishes the
/// new `category`/`out_dir` under `add_lock` and then, with every lock
/// released, moves the earlier progress into that directory. The record
/// is correct, still Queued and still runnable for the whole of that
/// move, so the scheduler could pick it, snapshot the destination, and
/// begin creating and fetching there while `move_tree` was merging the
/// old tree into the same path.
///
/// The test above cannot see this window and never could: its hook fires
/// BEFORE the publish, so what it proves is the H5 refusal - a job that
/// starts in there makes the whole transaction fail. Here the
/// transaction has already succeeded, so refusing is not on the table
/// and the question is whether the runner stays off the destination
/// until the bytes behind it arrive. `NZBFAST_TEST_STALL_RELOCATE_MS`
/// holds exactly that window open.
///
/// WHAT IT DOES NOT SEPARATE, stated rather than left to be assumed:
/// the fence is honoured in two places - `pick_job` skips a fenced job,
/// and `start_next` re-reads it in the critical section that flips the
/// state - and this proves neither arm on its own. Measured 25 Aug
/// 2026: with either arm alone this test still passes, because the gap
/// between the pick and the flip is microseconds and no hook holds it
/// open. `start_next`'s is the correctness arm (it is the only moment
/// that can be atomic with the publish); `pick_job`'s stops the runner
/// spinning on a fenced job for the whole of a large move, and is
/// pinned directly by `daemon_tests::pick_job_skips_a_relocating_job`.
///
/// NEITHER ARM IS UNPINNED ANY MORE, and this paragraph stays because
/// it is still a true statement about THIS case:
/// `a_recategorize_inside_the_pick_to_start_gap_cannot_start_the_job`
/// below holds that microsecond gap open with a hook of its own and
/// takes the re-read on directly. Re-measured with only the re-read
/// removed: this case passes and that one fails.
///
/// The seeded file stands in for the old progress. Deliberately NOT
/// named `.nzbfast.journal`, though the journal is the nastiest thing
/// that can land in there first: the fence does not discriminate by
/// filename, and seeding a synthetic journal would make this a test of
/// journal parsing instead of a test of the fence.
#[tokio::test(flavor = "multi_thread")]
async fn a_relocating_job_cannot_be_started_into_its_destination() {
    let dir = std::env::temp_dir().join(format!("nzbfast-relofence-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Slow articles, so that if the fence fails the started job is still
    // visibly Downloading when we look rather than finished and gone.
    let data = payload(600_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("slow.bin", &data, 40_000, "rf", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 400,
            ..Chaos::default()
        },
    )
    .await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;slow.bin&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let out_root = dir.join("complete");
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // Hold the FENCED window open for 6 s: destination
            // published, earlier progress not moved yet.
            .env("NZBFAST_TEST_STALL_RELOCATE_MS", "6000")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(&out_root)
            .arg("--connections")
            .arg("1");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Pause, add: the job sits Queued in the uncategorized folder.
        http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
        let boundary = "----relofence";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"slow.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = r
            .split("SABnzbd_nzo_")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .map(|s| format!("SABnzbd_nzo_{s}"))
            .unwrap();

        // Seed the old directory AFTER the add, so the enqueue's own
        // `dir_claim` still reads the canonical name as free and does
        // not climb to `slow.2`.
        let old_dir = out_root.join("slow");
        let new_dir = out_root.join("movies").join("slow");
        std::fs::create_dir_all(old_dir.join("sub")).unwrap();
        let earlier = b"earlier progress, byte for byte";
        std::fs::write(old_dir.join("earlier.part"), earlier).unwrap();
        std::fs::write(old_dir.join("sub").join("nested.part"), earlier).unwrap();

        // Re-file it. The request publishes the destination and then
        // stalls inside the fenced window for 6 s.
        let id2 = id.clone();
        let cc = std::thread::spawn(move || {
            http(
                port,
                &format!("/api?mode=change_cat&value={id2}&value2=movies&apikey=sekrit&output=json"),
                None,
            )
        });

        // Wait for the publish to land, so what follows is inside the
        // fenced window rather than in front of it.
        let mut published = false;
        for _ in 0..40 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if queue_slot(&q, &id)["cat"] == "movies" {
                published = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            published,
            "change_cat never published the new destination - the stall hook is in the wrong place"
        );
        assert!(
            !new_dir.join("earlier.part").exists(),
            "the move finished before the fence could be tested - the stall hook is in the wrong place"
        );

        // The destination is published and the bytes are still on their
        // way. Let the runner loose at it.
        http(port, "/api?mode=resume&apikey=sekrit&output=json", None);
        for _ in 0..15 {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            let slot = queue_slot(&q, &id);
            assert!(
                slot["status"] != "Downloading",
                "the runner started the job into a destination that was still being assembled: {q}"
            );
        }

        let r = cc.join().unwrap();
        assert!(r.contains("\"status\":true"), "change_cat failed: {r}");

        // The earlier progress is in the new directory, byte for byte,
        // and the old tree is not left behind naming nothing.
        assert_eq!(
            std::fs::read(new_dir.join("earlier.part")).unwrap(),
            earlier,
            "the earlier progress did not reach the new directory"
        );
        assert_eq!(
            std::fs::read(new_dir.join("sub").join("nested.part")).unwrap(),
            earlier,
            "the nested earlier progress did not reach the new directory"
        );
        assert!(
            !old_dir.exists(),
            "the old directory survived the move and is named by no record"
        );

        // ...and the fence LIFTS. A job that can never start again would
        // pass every assertion above.
        let mut started = false;
        for _ in 0..40 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if queue_slot(&q, &id)["status"] == "Downloading" {
                started = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(started, "the fence never lifted: the job stayed unstartable");
    })
    .await
    .unwrap();

    // Close the daemon, keeping its log for whatever fails below.
    let _log = d.stop();
}

/// The fixture the two gap cases below share: one slow single-file job,
/// the mock server that holds it, and a daemon pointed at both.
///
/// Slow articles for the reason the case above wants them - a fence
/// that fails leaves the job visibly Downloading when the case looks,
/// rather than finished and gone before the next poll comes round.
/// `vars` is where each case puts its stall hooks; the daemon starts
/// unpaused and every case pauses it over the API before adding, so
/// the add lands on a queue the runner cannot touch yet.
///
/// Field order is drop order and matters: `d` kills the child before
/// `_scratch` takes the directory out from under it.
struct Rig {
    out_root: PathBuf,
    xml: String,
    d: Daemon,
    _srv: MockServer,
    _scratch: scratch::ScratchDir,
}

async fn relocate_rig(tag: &str, vars: &[(&str, &str)]) -> Rig {
    let dir = std::env::temp_dir().join(format!("nzbfast-{tag}-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(600_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("slow.bin", &data, 40_000, tag, &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 400,
            ..Chaos::default()
        },
    )
    .await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;slow.bin&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let out_root = dir.join("complete");
    let owned: Vec<(String, String)> = vars
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1").env("NZBFAST_NO_ENRICH", "1");
        for (k, v) in &owned {
            c.env(k, v);
        }
        c.arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(&out_root)
            .arg("--connections")
            .arg("1");
        c
    })
    .await;
    Rig {
        out_root,
        xml,
        d,
        _srv: srv,
        _scratch,
    }
}

/// Pause the queue, add the rig's job, and answer its nzo id.
fn pause_and_add(port: u16, xml: &str, boundary: &str) -> String {
    http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"slow.nzb\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=addfile&apikey=sekrit&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "{r}");
    r.split("SABnzbd_nzo_")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .map(|s| format!("SABnzbd_nzo_{s}"))
        .unwrap()
}

/// Block until the daemon announces `needle` in its own log, and answer
/// the instant it arrived.
///
/// The rendezvous both cases below turn on. Each needs to act while the
/// daemon is INSIDE a window a stall hook is holding open, and each of
/// those windows is microseconds wide without the hook - so a case that
/// guessed with a sleep would be measuring the sleep. The hooks
/// announce themselves on the way in; this waits for that line and
/// hands back the clock, so the case can also assert it acted in time.
fn wait_for_marker(log: &Path, needle: &str) -> std::time::Instant {
    for _ in 0..400 {
        if std::fs::read_to_string(log)
            .unwrap_or_default()
            .contains(needle)
        {
            return std::time::Instant::now();
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!(
        "the daemon never announced {needle:?} - the stall hook is unset, or it is in the wrong place"
    );
}

/// Codex F-06, the `start_next` arm: a recategorize that lands entirely
/// inside the gap between the pick and the flip cannot start the job.
///
/// `pick_job` drops the job lock before it returns, so the fence it
/// checked is a fact about a moment already past by the time
/// `start_next` flips the state to Downloading and snapshots `out_dir`.
/// A whole recategorize fits in that gap - it needs only `add_lock` and
/// the job lock, neither of which the runner is holding - so the re-read
/// in the flipping critical section is the CORRECTNESS arm: it is the
/// only moment that can be atomic with the publish.
///
/// The case above cannot say which arm carried it and says so. This one
/// can, because the gap is held open: `NZBFAST_TEST_STALL_PICK_MS` parks
/// the runner after a successful pick, the recategorize then publishes
/// and raises the fence behind it, and the stall expires with the fence
/// still up - which is a state `pick_job`'s arm has already been walked
/// past and cannot answer for. VERIFIED RED 25 Aug 2026 with only that
/// re-read removed and `pick_job`'s skip left in place: the job flips to
/// Downloading the instant the pick stall lifts, into a destination
/// whose bytes are still being merged.
///
/// The two stalls are deliberately far apart. The flip has to happen
/// while the fenced window is still open, and the relocate stall is what
/// holds that window - so it is four times the pick stall, and the case
/// asserts the ordering it depends on rather than trusting the arithmetic
/// on a loaded runner.
#[tokio::test(flavor = "multi_thread")]
async fn a_recategorize_inside_the_pick_to_start_gap_cannot_start_the_job() {
    const PICK_MS: u64 = 3_000;
    let rig = relocate_rig(
        "relopick",
        &[
            ("NZBFAST_TEST_STALL_PICK_MS", &PICK_MS.to_string()),
            ("NZBFAST_TEST_STALL_RELOCATE_MS", "12000"),
        ],
    )
    .await;
    let port = rig.d.port;
    let log = rig.d.log_path();
    let out_root = rig.out_root.clone();
    let xml = rig.xml.clone();

    tokio::task::spawn_blocking(move || {
        let id = pause_and_add(port, &xml, "----relopick");

        // Seed the old directory AFTER the add, so the enqueue's own
        // `dir_claim` still reads the canonical name as free.
        let old_dir = out_root.join("slow");
        let new_dir = out_root.join("movies").join("slow");
        std::fs::create_dir_all(&old_dir).unwrap();
        let earlier = b"earlier progress, byte for byte";
        std::fs::write(old_dir.join("earlier.part"), earlier).unwrap();

        // Let the runner pick it. It parks in the gap and says so.
        http(port, "/api?mode=resume&apikey=sekrit&output=json", None);
        let picked = wait_for_marker(&log, "test stall in the pick-to-start gap");

        // The runner is between its pick and its flip. Re-file the job
        // from under it: this publishes the destination, raises the
        // fence, and then stalls with the bytes still on their way.
        let id2 = id.clone();
        let cc = std::thread::spawn(move || {
            http(
                port,
                &format!(
                    "/api?mode=change_cat&value={id2}&value2=movies&apikey=sekrit&output=json"
                ),
                None,
            )
        });
        let mut published = false;
        for _ in 0..40 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if queue_slot(&q, &id)["cat"] == "movies" {
                published = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(published, "change_cat never published the new destination");
        // ...and it published INSIDE the gap. Without this the case
        // could go green having tested the ordering it does not mean:
        // a publish that landed after the flip is the H5 refusal, which
        // the case above already covers.
        assert!(
            picked.elapsed() < std::time::Duration::from_millis(PICK_MS),
            "the publish took longer than the pick stall, so the flip was not inside the fenced \
             window: this run proved nothing"
        );

        // Now hold still across the moment the stall lifts. The flip
        // comes due at picked+PICK_MS and the fence stays up for a long
        // time after that, so anything that reaches Downloading in here
        // did so by ignoring the fence in the flipping critical section.
        let deadline = picked + std::time::Duration::from_millis(PICK_MS + 4_000);
        while std::time::Instant::now() < deadline {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            assert!(
                queue_slot(&q, &id)["status"] != "Downloading",
                "the flip ignored the fence raised behind the pick and started the job into a \
                 destination that was still being assembled: {q}"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        let r = cc.join().unwrap();
        assert!(r.contains("\"status\":true"), "change_cat failed: {r}");
        assert_eq!(
            std::fs::read(new_dir.join("earlier.part")).unwrap(),
            earlier,
            "the earlier progress did not reach the new directory"
        );

        // ...and the fence LIFTS. A job that can never start again would
        // pass every assertion above. Sixty rounds rather than the
        // forty its siblings use: the pick stall fires again on the way
        // back in, so this one waits out a whole extra PICK_MS.
        let mut started = false;
        for _ in 0..60 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if queue_slot(&q, &id)["status"] == "Downloading" {
                started = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            started,
            "the fence never lifted: the job stayed unstartable"
        );
    })
    .await
    .unwrap();

    let _log = rig.d.stop();
}

/// Codex F-06, the rename front: the label and the directory of one
/// rename can never be seen disagreeing.
///
/// `rename_queued` runs the recategorize transaction to re-derive
/// `out_dir` from the new name, and then writes the name itself. Those
/// are two publications, and the fence `requeue_category` returns covers
/// only the first - so the guard is BOUND rather than dropped on the
/// `?`, which keeps it up across the second. Without that binding a job
/// started in between emits `job.started` carrying the OLD name beside
/// the directory derived from the NEW one: the two halves of one rename,
/// disagreeing, in the record the user reads.
///
/// The window is two statements wide, so this needs its own hook to
/// hold it open. VERIFIED RED 25 Aug 2026 by downgrading `let _fence`
/// to `let _`: the runner starts the job inside the window and the
/// `job.started` event names "slow" while the job is downloading into
/// the "renamed" directory.
///
/// The event is what is asserted, not the final queue payload. By the
/// time the transaction ends the name has landed either way, so the
/// record settles correct even in the broken case - what cannot be
/// taken back is what was published while it was wrong.
#[tokio::test(flavor = "multi_thread")]
async fn a_rename_holds_its_fence_until_the_new_label_lands() {
    let rig = relocate_rig("relorename", &[("NZBFAST_TEST_STALL_RENAME_MS", "6000")]).await;
    let port = rig.d.port;
    let log = rig.d.log_path();
    let out_root = rig.out_root.clone();
    let xml = rig.xml.clone();

    tokio::task::spawn_blocking(move || {
        let id = pause_and_add(port, &xml, "----relorename");

        // Rename it while the queue is paused, so nothing can start
        // before the transaction opens its window.
        let id2 = id.clone();
        let rn = std::thread::spawn(move || {
            http(
                port,
                &format!(
                    "/api?mode=queue&name=rename&value={id2}&value2=renamed&apikey=sekrit&output=json"
                ),
                None,
            )
        });
        let opened = wait_for_marker(&log, "test stall in the rename fence window");

        // The directory is published and the label has not caught up.
        // Let the runner at it.
        http(port, "/api?mode=resume&apikey=sekrit&output=json", None);
        let deadline = opened + std::time::Duration::from_millis(4_000);
        while std::time::Instant::now() < deadline {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            assert!(
                queue_slot(&q, &id)["status"] != "Downloading",
                "the job started while its rename was half published: {q}"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        let r = rn.join().unwrap();
        assert!(r.contains("\"status\":true"), "rename failed: {r}");

        // The fence lifts with the whole rename applied, so the job runs
        // under the new label in the new directory.
        let mut started = false;
        for _ in 0..40 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if queue_slot(&q, &id)["status"] == "Downloading" {
                started = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(started, "the fence never lifted: the job stayed unstartable");
        assert!(
            out_root.join("renamed").exists(),
            "the job is downloading, but not into the renamed directory"
        );

        // Nothing was ever published under the old label. This is the
        // assertion the binding exists for.
        let ev = http(
            port,
            "/api?mode=dashboard&events=0&apikey=sekrit&output=json",
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&ev).unwrap_or(serde_json::Value::Null);
        let names: Vec<String> = v["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|e| e["kind"] == "job.started" && e["nzo_id"] == id.as_str())
            .map(|e| e["name"].as_str().unwrap_or_default().to_string())
            .collect();
        assert!(
            !names.is_empty(),
            "no job.started event for this job at all - the assertion below would pass vacuously: \
             {ev}"
        );
        assert!(
            names.iter().all(|n| n == "renamed"),
            "a job.started was published under the pre-rename label beside the post-rename \
             directory: {names:?}"
        );
    })
    .await
    .unwrap();

    let _log = rig.d.stop();
}
