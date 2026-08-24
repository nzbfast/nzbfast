//! Sweep 8 M3's production-route regression (TODO 199 item 7): the id
//! allocator's wall-clock floor on a HISTORY-ONLY restore.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//! It also keeps daemon.rs under the size gate.

use super::*;

/// Sweep 8 M3's production-route regression (TODO 199 item 7): a
/// HISTORY-ONLY restore must still raise the id allocator's wall-clock
/// floor.
///
/// `load_queue` returns early when there is no `queue.json` - a spool
/// that only ever held finished jobs, or one whose queue file was lost.
/// That arm returned BEFORE the floor, so the allocator stayed at 1 and
/// the next enqueue minted `SABnzbd_nzo_nzbfast1` again. Ids are not
/// cosmetic here: a stream token is `H(secret, nzo_id)`, so an old
/// job's permanent bearer URL would authorize the new one, and the next
/// boot's move-sequence reconciliation can read the collision as a
/// half-written move and drop a row.
///
/// The rig is the trigger exactly: one history row carrying the id a
/// fresh allocator would mint, no queue.json, then an enqueue and a
/// restart. The shipped fix had unit-level coverage only.
#[tokio::test(flavor = "multi_thread")]
async fn a_history_only_spool_still_raises_the_id_floor() {
    let dir = std::env::temp_dir().join(format!("nzbfast-idfloor-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(80_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("later.bin", &data, 40_000, "idf", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    // The spool: one finished row, and NO queue.json. Its id is the one
    // a fresh allocator starting at 1 mints for its first job.
    const COLLIDER: &str = "SABnzbd_nzo_nzbfast1";
    let spool = dir.join("complete/.spool");
    std::fs::create_dir_all(&spool).unwrap();
    let row = serde_json::json!({
        "nzo_id": COLLIDER,
        "name": "Older.Finished.Job",
        "nzb_path": dir.join("older.nzb").to_string_lossy(),
        "out_dir": dir.join("complete/Older.Finished.Job").to_string_lossy(),
        "state": "Completed",
        "category": "",
        "total_bytes": 1_000_000u64,
        "finished_unix": 1_722_000_000i64,
        "fail_message": "",
    });
    std::fs::write(
        spool.join("history.jsonl"),
        format!("{}\n", serde_json::to_string(&row).unwrap()),
    )
    .unwrap();
    assert!(!spool.join("queue.json").exists());

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
    let build = |port: u16| {
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
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    };

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;later.bin&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    let a = serve(&dir, &build).await;
    let port_a = a.port;
    let new_id = tokio::task::spawn_blocking(move || {
        let boundary = "----idfloorb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"j.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        // Paused, so the row stays put and the ids can be compared
        // without racing a download.
        let r = http(
            port_a,
            "/api?mode=addfile&apikey=sekrit&output=json&priority=-2",
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
        // The history row was restored, so the daemon knows ids are in
        // use - and must not hand this job one of them.
        let h = http(port_a, "/api?mode=history&apikey=sekrit&output=json", None);
        assert!(history_has(&h, COLLIDER), "the history row was not restored: {h}");
        assert_ne!(
            id, COLLIDER,
            "a history-only restore re-minted an id that already carries a \
             permanent stream token: {h}"
        );
        id
    })
    .await
    .unwrap();
    drop(a);

    // Both rows survive a second load, which is the half the collision
    // used to break: move-sequence reconciliation reads two records
    // under one id as a half-written move.
    let b = serve(&dir, &build).await;
    let port_b = b.port;
    tokio::task::spawn_blocking(move || {
        let h = http(port_b, "/api?mode=history&apikey=sekrit&output=json", None);
        assert!(
            history_has(&h, COLLIDER),
            "the seeded history row is gone: {h}"
        );
        let q = http(port_b, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(
            queue_has(&q, &new_id) || history_has(&h, &new_id),
            "the enqueued job is gone after the restart:\nqueue {q}\nhistory {h}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
