//! The NZBGet delete verbs, end to end: what each of the four does to
//! the queue, to history and to the files, and what deleting a job the
//! prefetch sidecar is still running has to wait for.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//! It also keeps daemon.rs under the size gate (TODO 106) - these two
//! legs arrived with the delete verbs in 65c3498c and pushed it over.

use super::*;

/// Deleting a job that is being prefetched must stop it, whichever API
/// the delete came in on.
///
/// The idle-server prefetch runs a QUEUED job in a sidecar pipeline, so
/// "not the active download" is not the same as "not running". The
/// NZBGet-facing delete never told the sidecar anything, so the job the
/// user (or Sonarr) removed kept downloading, ran the whole completion
/// tail - unlock, rename, TV filing, the move to the destination folder,
/// the pp-script - and parked itself into history as Completed. The next
/// queued job must still be prefetched normally afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn jsonrpc_delete_stops_a_prefetching_job() {
    let dir = std::env::temp_dir().join(format!("nzbfast-rpcdel-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Slow server: only job A's articles (250 ms each → A runs ~19 s).
    // Fast server: B's and C's, delayed too so the sidecar run is wide
    // enough to delete into.
    let mut slow_articles = HashMap::new();
    let a_segs = make_file_articles(
        "grinder.bin",
        &payload(3_000_000, 61),
        20_000,
        "sd",
        &mut slow_articles,
    );
    let mut fast_articles = HashMap::new();
    let b_segs = make_file_articles(
        "doomed.bin",
        &payload(2_000_000, 63),
        40_000,
        "fd",
        &mut fast_articles,
    );
    let c_segs = make_file_articles(
        "keeps.bin",
        &payload(600_000, 65),
        40_000,
        "fk",
        &mut fast_articles,
    );
    let slow_srv = MockServer::start(
        slow_articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;
    let fast_srv = MockServer::start(
        fast_articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;

    let nzb_for = |file: &str, segs: &[(String, u64, u32)]| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let a_xml = nzb_for("grinder.bin", &a_segs);
    let b_xml = nzb_for("doomed.bin", &b_segs);
    let c_xml = nzb_for("keeps.bin", &c_segs);

    let cfg = dir.join("config.json");
    // Distinct host STRINGS for the two loopback mocks: host is server
    // identity throughout, and the sidecar's busy-host exclusion must not
    // catch the idle one.
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}},{{\"host\":\"localhost\",\"port\":{},\"tls\":false}}]}}",
            slow_srv.addr.port(),
            fast_srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEFER_WARMUP_SECS", "2")
            // The idle-server SIDECAR is what this test pins. With the
            // cross-job hand-over on (`tests/integration/queue_handoff.rs`),
            // the idle server's connections go to the next job as a
            // first-class start before the sidecar's window ever opens,
            // so the sidecar path is exercised with the hand-over off.
            //
            // Scoped to THIS test, and it STAYS - asked and answered on
            // 23 Aug 2026, when F-04's owed integration test landed. The
            // pin used to mean no delete test anywhere had ever run
            // against a populated `drain_dl`, which is the gap F-04 lived
            // in; `deleting_a_draining_predecessor_stops_its_wire_and_leaves_the_successor_running`
            // now covers that case with the hand-over ON, so nothing is
            // bought by lifting it here. Lifting it was also measured:
            // this test then fails, twice out of two, on "timed out
            // waiting for B's prefetch to start" - the hand-over starts B
            // as a first-class job and the sidecar window never opens, so
            // the pin is what gives this test a subject at all.
            .env("NZBFAST_QUEUE_HANDOFF", "0")
            .env("NZBFAST_DEFER_WINDOW_SECS", "3")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let out_root = dir.join("complete");
    let deleted = tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----rpcdb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&output=json", None);
                let h = http(port, "/api?mode=history&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // A grinds on the slow server; B and C queue behind it.
        let a_id = upload(&a_xml, "grinder.nzb");
        poll(&|q, _| queue_slot(q, &a_id)["status"] == "Downloading", "job A to start");
        let b_id = upload(&b_xml, "doomed.nzb");
        let c_id = upload(&c_xml, "keeps.nzb");

        // The idle fast server picks B up.
        poll(&|q, _| queue_slot(q, &b_id)["prefetching"] == true, "B's prefetch to start");

        // Sonarr's delete: NZBGet editqueue, addressing the numeric id.
        let nzbid: i64 = b_id
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
            .parse()
            .unwrap();
        let body = format!(
            "{{\"method\":\"editqueue\",\"params\":[\"GroupDelete\",\"\",[{nzbid}]],\"id\":7}}"
        );
        let r = http(port, "/jsonrpc", Some(("application/json", body.as_bytes())));
        assert!(r.contains("true"), "GroupDelete refused: {r}");

        // C is prefetched and completes: the delete stops one job, not
        // the feature.
        let (q, h) = poll(&|_, h| history_has(h, &c_id), "C to complete on the idle server");
        assert!(h.contains("\"Completed\""), "{h}");
        assert!(
            queue_slot(&q, &a_id)["status"] == "Downloading",
            "A should still be running - the rig proves nothing otherwise: {q}"
        );

        // M5: GroupDelete is delete-and-file, not delete-and-forget. The
        // job leaves the queue, never publishes as a finished download,
        // and history gets a row that says the user removed it.
        assert!(queue_slot(&q, &b_id).is_null(), "the deleted job is still queued: {q}");
        let b_row = history_slot(&h, &b_id);
        assert!(
            !b_row.is_null(),
            "GroupDelete must file a history row for the job it removed: {h}"
        );
        assert_eq!(
            b_row["status"], "Failed",
            "a deleted row must not read as a finished download: {b_row}"
        );
        assert_eq!(b_row["fail_message"], "deleted from the queue", "{b_row}");
        // The NZBGet view spells the same row in NZBGet's own vocabulary.
        let jr = http(
            port,
            "/jsonrpc",
            Some((
                "application/json",
                br#"{"method":"history","id":9}"#.as_slice(),
            )),
        );
        assert!(
            jr.contains("\"DELETED/MANUAL\""),
            "the JSON-RPC history must mark the deleted row DELETED/MANUAL: {jr}"
        );

        // M5's active leg: GroupDelete on the DOWNLOADING job. The
        // pipeline aborts, park() finishes the cleanup - removes the
        // files GroupDelete asked for - and files the history row.
        let a_nzbid: i64 = a_id
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
            .parse()
            .unwrap();
        let body = format!(
            "{{\"method\":\"editqueue\",\"params\":[\"GroupDelete\",\"\",[{a_nzbid}]],\"id\":8}}"
        );
        let r = http(port, "/jsonrpc", Some(("application/json", body.as_bytes())));
        assert!(r.contains("true"), "GroupDelete of the active job refused: {r}");
        let (_, h) = poll(
            &|_, h| {
                let v: serde_json::Value = match serde_json::from_str(h) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                v["history"]["slots"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|s| s["nzo_id"] == a_id.as_str()))
            },
            "the active delete to park into history",
        );
        let a_row = history_slot(&h, &a_id);
        assert_eq!(a_row["fail_message"], "deleted from the queue", "{a_row}");
        // The files half is deferred to park, so it is allowed to lag
        // the history row by the drain - poll rather than assert.
        let a_out = out_root.join("grinder");
        for _ in 0..300 {
            if !a_out.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            !a_out.exists(),
            "an active GroupDelete must remove the payload once the fetch drains: {}",
            a_out.display()
        );
        b_id
    })
    .await
    .unwrap();
    let log = d.log();
    assert!(
        log.contains(&format!("[prefetch] {deleted} starting")),
        "rig: the deleted job was never the prefetched one:\n{log}"
    );
    assert!(
        !log.contains(&format!("[prefetch] {deleted} completed")),
        "the delete did not stop the prefetch:\n{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// M5 (14 Aug sweep): the four NZBGet delete verbs carry four distinct
/// contracts, and one collapsed arm served them all - no file removal,
/// no history row, every variant identical. Per NZBGet's editqueue
/// documentation and the nzbgetcom ChangeLog:
///
///   GroupDelete      files deleted, history row DELETED/MANUAL
///   GroupDupeDelete  files deleted, history row DELETED/DUPE
///   GroupFinalDelete files deleted, NO history row (what Sonarr and
///                    Radarr send to cancel - the orphaned-payload bug)
///   GroupParkDelete  files RETAINED, history row DELETED/MANUAL
///
/// Queued fixtures against a dead server, paused, so every job sits
/// still while its verb lands. The retry at the end proves the filed
/// rows are live records (spooled NZB kept, tombstone scrubbed), not
/// just rendered corpses.
#[tokio::test(flavor = "multi_thread")]
async fn nzbget_delete_variants_keep_their_own_contracts() {
    let dir = std::env::temp_dir().join(format!("nzbfast-rpcvariants-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{dead_port},\"tls\":false}}]}}"),
    )
    .unwrap();
    let out = dir.join("complete");
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let upload = |stem: &str| -> String {
            let xml = format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"{stem}.bin (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"10000\" number=\"1\">{stem}seg1@test</segment>\n    </segments>\n  </file>\n</nzb>\n"
            );
            let boundary = "----nzbfastboundary";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let ctype = format!("multipart/form-data; boundary={boundary}");
            let r = http(port, "/api?mode=addfile&output=json", Some((&ctype, &body)));
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let nzbid = |nzo: &str| -> i64 {
            nzo.chars()
                .rev()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
                .parse()
                .unwrap()
        };
        let editqueue = |cmd: &str, id: i64| -> String {
            let body = format!(
                "{{\"method\":\"editqueue\",\"params\":[\"{cmd}\",\"\",[{id}]],\"id\":3}}"
            );
            http(port, "/jsonrpc", Some(("application/json", body.as_bytes())))
        };

        let r = http(port, "/api?mode=pause&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        let ids: Vec<String> = ["alpha", "bravo", "charlie", "delta"]
            .iter()
            .map(|s| upload(s))
            .collect();
        // Every job gets a payload directory the verb must judge: three
        // verbs delete it, one retains it.
        for stem in ["alpha", "bravo", "charlie", "delta"] {
            let p = out.join(stem);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("part.bin"), b"partial payload").unwrap();
        }

        for (cmd, nzo) in [
            ("GroupDelete", &ids[0]),
            ("GroupDupeDelete", &ids[1]),
            ("GroupFinalDelete", &ids[2]),
            ("GroupParkDelete", &ids[3]),
        ] {
            let r = editqueue(cmd, nzbid(nzo));
            assert!(r.contains("true"), "{cmd} refused: {r}");
        }

        let q = http(port, "/api?mode=queue&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&q).unwrap();
        assert_eq!(v["queue"]["slots"].as_array().map(Vec::len), Some(0), "{q}");

        // File retention per verb.
        assert!(!out.join("alpha").exists(), "GroupDelete must remove the files");
        assert!(!out.join("bravo").exists(), "GroupDupeDelete must remove the files");
        assert!(!out.join("charlie").exists(), "GroupFinalDelete must remove the files");
        assert!(
            out.join("delta").join("part.bin").exists(),
            "GroupParkDelete must retain the downloaded files"
        );

        // History per verb, SAB view: three rows filed, FinalDelete none.
        let h = http(port, "/api?mode=history&output=json", None);
        assert_eq!(history_slot(&h, &ids[0])["fail_message"], "deleted from the queue", "{h}");
        assert_eq!(
            history_slot(&h, &ids[1])["fail_message"],
            "deleted from the queue as a duplicate",
            "{h}"
        );
        assert!(
            history_slot(&h, &ids[2]).is_null(),
            "GroupFinalDelete must not file a history row: {h}"
        );
        assert_eq!(history_slot(&h, &ids[3])["fail_message"], "deleted from the queue", "{h}");

        // The same rows in NZBGet's own vocabulary.
        let jr = http(
            port,
            "/jsonrpc",
            Some(("application/json", br#"{"method":"history","id":4}"#.as_slice())),
        );
        let v: serde_json::Value = serde_json::from_str(&jr).unwrap();
        let jr_status = |id: i64| -> String {
            v["result"]
                .as_array()
                .and_then(|a| a.iter().find(|e| e["NZBID"] == id))
                .map(|e| {
                    format!(
                        "{} {}",
                        e["Status"].as_str().unwrap_or(""),
                        e["DeleteStatus"].as_str().unwrap_or("")
                    )
                })
                .unwrap_or_default()
        };
        assert_eq!(jr_status(nzbid(&ids[0])), "DELETED/MANUAL MANUAL", "{jr}");
        assert_eq!(jr_status(nzbid(&ids[1])), "DELETED/DUPE DUPE", "{jr}");
        assert_eq!(jr_status(nzbid(&ids[2])), "", "{jr}");
        assert_eq!(jr_status(nzbid(&ids[3])), "DELETED/MANUAL MANUAL", "{jr}");

        // A filed row is a record, not a corpse: retry re-queues it from
        // the spooled NZB, and the re-queued job is one pick_job will
        // actually run (delete_status and tombstone both scrubbed).
        let r = http(
            port,
            &format!("/api?mode=retry&value={}&output=json", ids[0]),
            None,
        );
        assert!(r.contains("\"status\":true"), "retrying a deleted row: {r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(
            queue_has(&q, &ids[0]),
            "the retried row must be back in the queue: {q}"
        );
        let h = http(port, "/api?mode=history&output=json", None);
        assert!(
            history_slot(&h, &ids[0]).is_null(),
            "the retried row must have left history: {h}"
        );
    })
    .await
    .unwrap();

    // Close the daemon, keeping its log for whatever fails below.
    let _log = d.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Delete a job, add the same release again, and it must DOWNLOAD - not
/// sit in the queue as "held (duplicate)" behind a record the user has
/// just told us they no longer have.
///
/// Measured on the unfixed daemon, and it is worse than one row waiting:
/// with an alternative already held behind the deleted job, the re-add
/// is held behind the ALTERNATIVE, while the alternative is held for a
/// record that no longer exists - and a hold is released by its original
/// FAILING, which a deleted record can never do. Two paused rows, no
/// download, and the only way out is a control the user has to go and
/// find (one reported hunting for "that blue icon").
///
/// The whole scenario runs against a dead server with the queue paused:
/// nothing here is about downloading, only about what the add path makes
/// of the identity.
#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_release_added_again_is_not_held_as_its_own_duplicate() {
    let dir = std::env::temp_dir().join(format!("nzbfast-redel-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{dead_port},\"tls\":false}}]}}"),
    )
    .unwrap();
    let out = dir.join("complete");
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(&out);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let upload = |stem: &str| -> String {
            let xml = format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"{stem}.bin (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"10000\" number=\"1\">{stem}seg1@test</segment>\n    </segments>\n  </file>\n</nzb>\n"
            );
            let boundary = "----nzbfastboundary";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let ctype = format!("multipart/form-data; boundary={boundary}");
            let r = http(port, "/api?mode=addfile&output=json", Some((&ctype, &body)));
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        // The queue as (name, priority) pairs, which is the whole
        // question here: "Duplicate" is the held row.
        let prios = || -> Vec<(String, String)> {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap();
            v["queue"]["slots"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| {
                    (
                        s["filename"].as_str().unwrap_or_default().to_string(),
                        s["priority"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        };

        http(port, "/api?mode=pause&output=json", None);
        let a = "Johnny.Vegas.S02E03.1080p.WEB.h264-AAA";
        let b = "Johnny.Vegas.S02E03.2160p.WEB.h264-BBB";
        let a_id = upload(a);
        upload(b);
        assert_eq!(
            prios(),
            vec![
                (a.to_string(), "Normal".to_string()),
                (b.to_string(), "Duplicate".to_string())
            ],
            "the premise: B is held as an alternative to A"
        );

        // The user deletes A - with its files, the ordinary thing to
        // press - and asks for the same release again.
        let r = http(
            port,
            &format!("/api?mode=queue&name=delete&value={a_id}&del_files=1&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        upload(a);
        let after = prios();
        assert!(
            after.iter().any(|(n, p)| n == a && p == "Normal"),
            "the re-add of a release the user just deleted must run: {after:?}"
        );
        assert!(
            after.iter().any(|(n, p)| n == b && p == "Duplicate"),
            "...and the alternative behind it stays held, now against the new copy: {after:?}"
        );

        // The user's delete speaks ONCE. A third copy arriving behind
        // the re-add is an ordinary duplicate of it, or the identity
        // would be unprotected for the whole window.
        let c = "Johnny.Vegas.S02E03.720p.WEB.h264-CCC";
        upload(c);
        let after = prios();
        assert!(
            after.iter().any(|(n, p)| n == c && p == "Duplicate"),
            "the mark is spent by the add it was made for: {after:?}"
        );

        // And deleting the BACKUP copy is not a statement about the
        // identity at all - the row it was held for is still running.
        // A stamp there would let the next add of the same episode
        // download alongside it, which is a double download.
        let b_id = {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap();
            v["queue"]["slots"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["filename"] == b)
                .map(|s| s["nzo_id"].as_str().unwrap().to_string())
                .expect("the alternative")
        };
        let r = http(
            port,
            &format!("/api?mode=queue&name=delete&value={b_id}&del_files=1&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let d2 = "Johnny.Vegas.S02E03.480p.WEB.h264-DDD";
        upload(d2);
        let after = prios();
        assert!(
            after.iter().any(|(n, p)| n == d2 && p == "Duplicate"),
            "deleting a held alternative must not release the identity: {after:?}"
        );
    })
    .await
    .unwrap();

    // Close the daemon, keeping its log for whatever fails below.
    let _log = d.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The kept-files notice closes its own loop: "download it again" adds
/// the release back from the spool copy the refused delete held on to.
///
/// Before this, the notice named a release, named a folder, and offered
/// nothing but "dismiss" - so a user who deleted a download to fetch it
/// again had to leave the notice, find the release, add it by hand, and
/// then get past a duplicate hold. The refusal is forced here by taking
/// write permission off the download root, which is a unix trick; the
/// path under test is the same one a Windows Trash refusal takes (it is
/// `remove_job_files` answering `Kept` either way).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_kept_files_notice_can_add_the_release_again() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = std::env::temp_dir().join(format!("nzbfast-keptagain-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{dead_port},\"tls\":false}}]}}"),
    )
    .unwrap();
    let out = dir.join("complete");
    std::fs::create_dir_all(&out).unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(&out);
        c
    })
    .await;
    let port = d.port;
    let out2 = out.clone();

    tokio::task::spawn_blocking(move || {
        let stem = "Kept.Release.S01E01.1080p.WEB.h264-KKK";
        let xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"{stem}.bin (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"10000\" number=\"1\">keptseg1@test</segment>\n    </segments>\n  </file>\n</nzb>\n"
        );
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        http(port, "/api?mode=pause&output=json", None);
        let r = http(port, "/api?mode=addfile&output=json", Some((&ctype, &body)));
        let id = r
            .split("SABnzbd_nzo_")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| format!("SABnzbd_nzo_{s}"))
            .expect("nzo_id");

        // Payload on disk, and a download root the daemon cannot remove
        // from: exactly the state a refused Trash leaves behind.
        let payload = out2.join(stem);
        std::fs::create_dir_all(&payload).unwrap();
        std::fs::write(payload.join("part.bin"), b"partial payload").unwrap();
        std::fs::set_permissions(&out2, std::fs::Permissions::from_mode(0o555)).unwrap();
        let r = http(
            port,
            &format!("/api?mode=queue&name=delete&value={id}&del_files=1&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        std::fs::set_permissions(&out2, std::fs::Permissions::from_mode(0o755)).unwrap();

        let q = http(port, "/api?mode=queue&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&q).unwrap();
        let note = v["queue"]["delete_kept"]
            .as_array()
            .and_then(|a| a.first().cloned())
            .unwrap_or_else(|| panic!("a refused delete owes a notice: {q}"));
        assert_eq!(note["name"], stem, "{q}");
        assert_eq!(note["retry"], true, "the notice must be able to offer the add: {q}");

        // §129 1b(b): the STRIP above stays on the queue payload - it
        // describes a folder that is still on disk, not a moment that
        // scrolled past - but the once-each TOAST that nudges towards
        // it is a moment, and it rides the lifecycle ring now instead
        // of being recovered by diffing that array against a seen-set.
        let dv: serde_json::Value = serde_json::from_str(&http(
            port,
            "/api?mode=dashboard&events=0&output=json",
            None,
        ))
        .unwrap();
        let ev = dv["events"]
            .as_array()
            .expect("events array")
            .iter()
            .find(|e| e["kind"] == "job.delete_kept")
            .unwrap_or_else(|| panic!("a refused delete owes an event: {dv}"));
        assert_eq!(ev["name"], stem, "{dv}");
        assert_eq!(ev["path"], note["path"], "{dv}");
        assert_eq!(ev["retry"], true, "{dv}");
        assert_eq!(ev["schema_version"], 1, "{dv}");

        // The one click the notice now has. The path is the notice's
        // identity, and it carries '/' and (on a temp dir) '.' - so it
        // is percent-encoded rather than pasted into the query.
        let raw = note["path"].as_str().unwrap();
        let path: String = raw
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect();
        let r = http(
            port,
            &format!("/api?mode=delete_kept_retry&value={path}&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "retry from the notice: {r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&q).unwrap();
        assert_eq!(
            v["queue"]["slots"][0]["filename"], stem,
            "the release must be back in the queue: {q}"
        );
        assert_eq!(
            v["queue"]["slots"][0]["priority"], "Normal",
            "and running, not held behind the copy it replaces: {q}"
        );
        assert_eq!(
            v["queue"]["delete_kept"].as_array().map(Vec::len),
            Some(0),
            "the notice is spent once it has been acted on: {q}"
        );
    })
    .await
    .unwrap();

    // Close the daemon, keeping its log for whatever fails below.
    let _log = d.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// §296 (sweep S9): a REST history delete takes back the copies the job
/// already published at the destination, del_files or not.
///
/// The seeded row is the restart snapshot the sweep describes: a job
/// parked Completed whose whole-job move has not settled, its early
/// record still naming a copy in the completed folder. Before the fix
/// the delete arm never called `early_take`, so the record - the ONLY
/// thing naming that copy - went down with the row, and the copy sat
/// orphaned at the destination forever: an *arr import of a download
/// the user deleted. The record's own `dest` addresses the copy, so
/// the daemon needs no move_completed configured at delete time - that
/// is sweep S6's half of the same fix.
#[tokio::test(flavor = "multi_thread")]
async fn a_history_delete_takes_back_the_published_copies() {
    let dir = std::env::temp_dir().join(format!("nzbfast-histearly-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // A daemon with a server configured and nothing to download: the
    // row under test is seeded straight into the history store.
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;

    const ID: &str = "SABnzbd_nzo_early9296";
    let out_dir = dir.join("complete/Early.Publish");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("ep1.mkv"), b"payload-bytes").unwrap();
    let nas_dest = dir.join("nas/Early.Publish");
    std::fs::create_dir_all(&nas_dest).unwrap();
    std::fs::write(nas_dest.join("ep1.mkv"), b"payload-bytes").unwrap();

    let spool = dir.join("complete/.spool");
    std::fs::create_dir_all(&spool).unwrap();
    let row = serde_json::json!({
        "nzo_id": ID,
        "name": "Early.Publish",
        "nzb_path": dir.join("early.nzb").to_string_lossy(),
        "out_dir": out_dir.to_string_lossy(),
        "state": "Completed",
        "category": "",
        "total_bytes": 13u64,
        "finished_unix": 1_722_000_000i64,
        "fail_message": "",
        "early_published": [{
            "name": "ep1.mkv", "len": 13, "mtime_ns": 0, "nzf_id": "",
            "dest": nas_dest.to_string_lossy(),
        }],
    });
    std::fs::write(
        spool.join("history.jsonl"),
        format!("{}\n", serde_json::to_string(&row).unwrap()),
    )
    .unwrap();

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
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("1");
        c
    })
    .await;
    let port = d.port;
    let out_dir2 = out_dir.clone();
    let nas_dest2 = nas_dest.clone();

    tokio::task::spawn_blocking(move || {
        let h = http(port, "/api?mode=history&output=json", None);
        assert!(history_has(&h, ID), "the seeded row must restore: {h}");

        // No del_files: the record half only. The destination copies go
        // regardless - with the files kept the payload is still whole in
        // out_dir, so the copies are a partial duplicate either way.
        let r = http(
            port,
            &format!("/api?mode=history&name=delete&value={ID}&output=json"),
            None,
        );
        assert!(r.contains("\"removed\":1"), "the delete must land: {r}");

        let h = http(port, "/api?mode=history&output=json", None);
        assert!(!history_has(&h, ID), "the row is gone: {h}");
        assert!(
            !nas_dest2.join("ep1.mkv").exists(),
            "the early copy at the destination goes with the record"
        );
        assert!(
            !nas_dest2.exists(),
            "the emptied destination job folder goes with it"
        );
        assert!(
            out_dir2.join("ep1.mkv").exists(),
            "without del_files the download's own files stay"
        );
    })
    .await
    .unwrap();

    let _log = d.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// P2-1: a REST history delete over a store whose FILE cannot be
/// appended to must still forget the record, and must not destroy the
/// record's spool copy on the strength of a tombstone that never
/// landed.
///
/// `Daemon::history_write_locked` opens `history.jsonl` with
/// `create(true).append(true)`, so it needs write permission ON THE
/// FILE, while `queue.json` and the atomic rewrite go through
/// `persist::write_atomic` - private temp file, rename - and need only
/// the DIRECTORY. One `sudo nzbfast` is enough to separate them, and a
/// store left 0444 in a writable folder is exactly the state the report
/// names. The delete arm unlinked the spool copy and the published
/// copies, tombstoned LAST and threw the answer away, so the record came
/// back at the next start naming files it no longer had - under a
/// `"status": true` it had already answered.
///
/// Unix only, and not by reflex: on Windows a read-only file also
/// refuses the RENAME that replaces it, so the very asymmetry this test
/// turns on does not exist there and the fixture could not describe the
/// fault.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_history_delete_survives_a_store_that_refuses_the_append() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = std::env::temp_dir().join(format!("nzbfast-histro-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;

    const ID: &str = "SABnzbd_nzo_readonly1";
    // A second row for the harder half below, where the FOLDER goes too.
    const ID2: &str = "SABnzbd_nzo_readonly2";
    let spool = dir.join("complete/.spool");
    std::fs::create_dir_all(&spool).unwrap();
    let store = spool.join("history.jsonl");
    let mut seeded = String::new();
    let mut nzbs = Vec::new();
    for (id, stem) in [(ID, "Readonly.Store"), (ID2, "Readonly.Folder")] {
        let out_dir = dir.join("complete").join(stem);
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::write(out_dir.join("ep1.mkv"), b"payload-bytes").unwrap();
        // The retry copy: the one thing a resurrected record would need
        // and the one thing the old order destroyed first.
        let nzb = dir.join(format!("{stem}.nzb"));
        std::fs::write(&nzb, b"<nzb/>").unwrap();
        let row = serde_json::json!({
            "nzo_id": id,
            "name": stem,
            "nzb_path": nzb.to_string_lossy(),
            "out_dir": out_dir.to_string_lossy(),
            "state": "Completed",
            "category": "",
            "total_bytes": 13u64,
            "finished_unix": 1_722_000_000i64,
            "fail_message": "",
        });
        seeded.push_str(&serde_json::to_string(&row).unwrap());
        seeded.push('\n');
        nzbs.push(nzb);
    }
    std::fs::write(&store, &seeded).unwrap();

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
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("1");
        c
    })
    .await;
    let port = d.port;
    // The daemon MOVES its state out of the download directory at
    // startup ("moved daemon state out of the download directory" in the
    // log), so the file to make read-only is the one it landed on, not
    // the one the fixture seeded.
    let store2 = dir.join(".spool/history.jsonl");
    let spool2 = dir.join(".spool");
    let nzb2 = nzbs[0].clone();
    let nzb3 = nzbs[1].clone();

    tokio::task::spawn_blocking(move || {
        let h = http(port, "/api?mode=history&output=json", None);
        assert!(history_has(&h, ID), "the seeded row must restore: {h}");
        assert!(history_has(&h, ID2), "and so must the second: {h}");
        assert!(
            store2.exists(),
            "the store did not land where the fixture expects: {}",
            store2.display()
        );

        // The fault: the store file itself, and nothing else, stops
        // taking writes. Applied AFTER the restore, so the daemon has
        // read what it is about to be unable to append to.
        let mut perms = std::fs::metadata(&store2).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&store2, perms).unwrap();

        let r = http(
            port,
            &format!("/api?mode=history&name=delete&value={ID}&output=json"),
            None,
        );
        assert!(
            r.contains("\"removed\":1"),
            "the atomic rewrite needs only the folder, so the delete has a way \
             through: {r}"
        );
        assert!(
            !nzb2.exists(),
            "the removal is durable, so the record's spool copy goes with it"
        );

        // THE ASSERTION THE OLD ORDER FAILED. Read the store as a
        // restart would: a record is live unless a `"deleted": true`
        // line for it follows, and a rewrite that does not name it at
        // all is the strongest form of that. The old code left the
        // seeded row untouched and no tombstone anywhere, so the
        // deleted release came back with its `.nzb` already gone.
        let raw = std::fs::read_to_string(&store2).unwrap_or_default();
        assert!(
            !raw.contains(ID),
            "the store still names the deleted record, so a restart brings it \
             back: {raw}"
        );

        let h = http(port, "/api?mode=history&output=json", None);
        assert!(!history_has(&h, ID), "the row is gone: {h}");

        // THE OTHER HALF, and the one that pins the ORDER rather than
        // the rescue: take the FOLDER as well, so the append is refused
        // and the atomic rewrite that stands in for it is refused too.
        // Nothing is left to try, so the delete has to refuse - and it
        // has to refuse having destroyed nothing, because the record it
        // could not remove is still live in the store on disk.
        let mut perms = std::fs::metadata(&store2).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&store2, perms).unwrap();
        std::fs::set_permissions(&spool2, std::fs::Permissions::from_mode(0o555)).unwrap();

        let r = http(
            port,
            &format!("/api?mode=history&name=delete&value={ID2}&del_files=1&output=json"),
            None,
        );
        // Put the folder back before anything can fail on it: the
        // daemon has to be able to stop, and the scratch has to be able
        // to be cleaned up.
        std::fs::set_permissions(&spool2, std::fs::Permissions::from_mode(0o755)).unwrap();
        // 0600, not `set_readonly(false)`: this store holds credentials
        // and the daemon creates it 0600 for that reason - handing it
        // back world-writable would undo the thing `history_write_locked`
        // takes the trouble to set.
        std::fs::set_permissions(&store2, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(
            r.contains("\"status\":false"),
            "a delete that could not remove the record must not report success: {r}"
        );
        assert!(
            nzb3.exists(),
            "the retry .nzb went before the removal was durable"
        );
        let h = http(port, "/api?mode=history&output=json", None);
        assert!(
            history_has(&h, ID2),
            "a refused delete must leave the record where it found it: {h}"
        );
    })
    .await
    .unwrap();

    let _log = d.stop();
    let _ = std::fs::remove_dir_all(&dir);
}
