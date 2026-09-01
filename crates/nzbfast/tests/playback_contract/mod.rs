//! Workstream A2, playback contract v1: the gate test for the two
//! calls the native mobile clients are frozen against
//! (`mode=playback`, `mode=stream_token`).
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`
//! for the reason the chaos rig is: a top-level file would become a
//! separate target and fall out of the standard daemon gate.
//!
//! The frozen shapes are recorded in
//! packaging/android/compose-app/CONTRACT.md, and both native shells'
//! snapshot tests read the same fields.

use super::*;

/// A2 (playback contract v1): the ONE call a phone polls.
///
/// `mode=playback` has to answer, in a single response, everything the
/// native clients used to need three calls and a probe per job for: what
/// the server is doing, the job list, whether each job can be PLAYED
/// right now and which file that would be, and the byte-serving
/// telemetry behind the player overlay. The play URL it hands back
/// carries the job's scoped token and must never carry the API key -
/// that string reaches players, `.strm` files and logs.
#[tokio::test(flavor = "multi_thread")]
async fn playback_contract_answers_readiness_and_scoped_tokens() {
    let dir = std::env::temp_dir().join(format!("nzbfast-a2-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = nzbkit::mediaprobe::testmux::mkv_padded(400_000);
    let mut articles = HashMap::new();
    let segs = make_file_articles("movie.mkv", &data, 40_000, "a2", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;movie.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
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
    delete_without_the_trash(&cfg);
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
            .arg("--apikey")
            .arg("sekrit")
            .arg("--nzbkey")
            .arg("addonly")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log_path();

    tokio::task::spawn_blocking(move || {
        let upload = |name: &str| {
            let boundary = "----a2b";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{name}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            )
        };
        upload("movie.nzb");

        let mut nzo = String::new();
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"")
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&h)
                && let Some(id) = v["history"]["slots"][0]["nzo_id"].as_str()
            {
                nzo = id.to_string();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(!nzo.is_empty(), "the job never completed\n--- log ---\n{log}");

        // Queue contents are full-key, and the compact call IS queue
        // contents - the add-only NZB key must not reach it.
        let r = http(port, "/api?mode=playback&apikey=addonly&output=json", None);
        assert!(
            r.contains("API Key Incorrect"),
            "add-only key read the queue: {r}"
        );

        let body = http(port, "/api?mode=playback&apikey=sekrit&output=json", None);
        let v: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}"));
        assert_eq!(v["status"], true, "{body}");
        assert_eq!(v["contract"], 1, "{body}");
        assert_eq!(v["paused"], false, "{body}");
        // One call, every part: server state, both lists, telemetry.
        assert!(v["nzbfast"].is_string(), "{body}");
        assert!(v["speed_bps"].is_number(), "{body}");
        // §125 anchor, additive: bps + "measured"|"line"|"" (empty =
        // no anchor known, clients scale to window).
        assert!(v["link_peak"].is_number(), "{body}");
        assert!(v["link_peak_src"].is_string(), "{body}");
        assert!(v["stream"]["readers"].is_number(), "{body}");
        assert!(v["stream"]["runway_wait_ms"].is_number(), "{body}");
        assert_eq!(v["stream"]["zero_filled_bytes"], 0, "{body}");
        // The drain latch (TODO 281 AN2, additive). The job above has
        // reached history, so the queue is not merely empty - the tail
        // is done too, which is the half `queue_total` cannot say. The
        // false case is asserted at the foot of this test, after a
        // second upload re-arms it: a key that answered a constant
        // would pass one of these two and not both.
        assert_eq!(v["queue_idle"], true, "{body}");

        let h = &v["history"][0];
        assert_eq!(h["nzo_id"], nzo.as_str(), "{body}");
        assert_eq!(h["status"], "Completed", "{body}");
        // Readiness as API truth: playable, from disk, naming the file
        // /stream would actually serve - and seekable, because a
        // finished file has its index.
        assert_eq!(h["playback"]["ready"], true, "{body}");
        assert_eq!(h["playback"]["reason"], "disk", "{body}");
        assert_eq!(h["playback"]["source"], "disk", "{body}");
        assert_eq!(h["playback"]["seekable"], true, "{body}");
        assert!(
            h["playback"]["file"]
                .as_str()
                .is_some_and(|f| f.ends_with(".mkv")),
            "{body}"
        );
        assert!(h["playback"]["size"].as_u64().unwrap_or(0) > 0, "{body}");

        // The handed-off URL carries the job's scoped token and NOT the
        // API key (the grab-apikey-leak lesson: this string ends up in
        // players, .strm files and logs).
        let url = h["stream"].as_str().unwrap_or_default().to_string();
        assert!(url.contains("/stream/") && url.contains("?t="), "{body}");
        assert!(
            !url.contains("sekrit"),
            "the play URL leaked the api key: {body}"
        );

        // ...and it plays, with no key anywhere near it.
        let path = url.split_once("/stream/").map(|(_, p)| p).unwrap();
        let r = raw(
            port,
            format!("GET /stream/{path} HTTP/1.1\r\nHost: x\r\nRange: bytes=0-99\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        let head = String::from_utf8_lossy(&r).to_string();
        assert!(
            head.starts_with("HTTP/1.1 206"),
            "the token did not play: {head}"
        );

        // The same token, minted on its own for an external handoff.
        let t = http(
            port,
            &format!("/api?mode=stream_token&value={nzo}&apikey=sekrit&output=json"),
            None,
        );
        let tv: serde_json::Value = serde_json::from_str(&t).unwrap_or_else(|e| panic!("{e}: {t}"));
        assert_eq!(tv["status"], true, "{t}");
        assert_eq!(tv["nzo_id"], nzo.as_str(), "{t}");
        assert!(tv["expires"].is_null(), "{t}");
        assert!(
            url.contains(tv["token"].as_str().unwrap_or("nope")),
            "the minted token is not the one the list handed out: {t} / {url}"
        );
        // A token for a job that does not exist is a refusal, not a
        // hash of whatever string was passed.
        let t = http(
            port,
            "/api?mode=stream_token&value=SABnzbd_nzo_nope&apikey=sekrit&output=json",
            None,
        );
        assert!(t.contains("unknown nzo_id"), "{t}");

        // A job that is queued and has not started is honestly not
        // ready - and says which of the not-ready reasons it is.
        http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
        upload("second.nzb");
        let body = http(port, "/api?mode=playback&apikey=sekrit&output=json", None);
        let v: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}: {body}"));
        assert_eq!(v["paused"], true, "{body}");
        let q = &v["queue"][0];
        assert_eq!(q["playback"]["ready"], false, "{body}");
        assert_eq!(q["playback"]["reason"], "not_started", "{body}");
        assert!(q["mb"].is_number() && q["percentage"].is_number(), "{body}");
        // Enqueue re-arms the drain latch, so a queue holding work says
        // so even though this one is paused and nothing is moving.
        assert_eq!(v["queue_idle"], false, "{body}");
    })
    .await
    .unwrap();
}
