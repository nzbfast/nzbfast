//! §73 phase 3: `/preview/media` - the same file rewrapped as fragmented
//! MP4 so a browser that will not open the container can still play what
//! is inside it.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//! It also keeps daemon.rs under the size gate.

use super::*;

/// Split an HTTP answer into its head and its body, undoing chunked
/// transfer encoding when the response used it.
///
/// The remux endpoint has no Content-Length - it cannot have one, the
/// bytes do not exist yet - so its body arrives chunked, and a test that
/// asserted on the raw socket bytes would be asserting on chunk-length
/// prefixes as much as on the file.
fn split_http(raw: &[u8]) -> (String, Vec<u8>) {
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header terminator");
    let head = String::from_utf8_lossy(&raw[..at]).to_string();
    let mut body = raw[at + 4..].to_vec();
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut out = Vec::new();
        let mut p = 0usize;
        while p < body.len() {
            let Some(eol) = body[p..].windows(2).position(|w| w == b"\r\n") else {
                break;
            };
            let n = usize::from_str_radix(String::from_utf8_lossy(&body[p..p + eol]).trim(), 16)
                .unwrap_or(0);
            p += eol + 2;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&body[p..(p + n).min(body.len())]);
            p += n + 2;
        }
        body = out;
    }
    (head, body)
}

/// §73 phase 3: `/preview/media/{nzo_id}` hands back the same file
/// rewrapped as fragmented MP4, so a browser that refuses to open
/// Matroska can still play what is inside it.
///
/// The assertions are on the bytes, not on the status line: an endpoint
/// that answers 200 with something MediaSource rejects is worse than one
/// that answers 501, because the failure surfaces as a silent black
/// rectangle. So the fixture is a real mux with real payload, and the
/// test takes the answer apart far enough to see an init segment and a
/// media fragment in it.
#[tokio::test(flavor = "multi_thread")]
async fn preview_media_remuxes_matroska_into_fragmented_mp4() {
    let dir = std::env::temp_dir().join(format!("nzbfast-preview-media-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = nzbkit::mediaprobe::testmux::mkv_remux_fixture();
    let mut articles = HashMap::new();
    let segs = make_file_articles("movie.mkv", &data, 40_000, "pm", &mut articles);
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
        let boundary = "----previewm";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        let mut nzo = String::new();
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"")
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&h)
                && let Some(slot) = v["history"]["slots"].get(0)
                && let Some(id) = slot["nzo_id"].as_str()
            {
                nzo = id.to_string();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(!nzo.is_empty(), "the job never completed\n--- log ---\n{log}");

        let get = |q: &str| {
            raw(
                port,
                format!("GET /preview/media/{nzo}{q} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
        };

        // Same credential rule as the probe and as /stream's finished
        // arm: nzo_ids are a plain counter, so an open endpoint hands
        // any LAN host the user's library one guess at a time.
        let (head, _) = split_http(&get(""));
        assert!(head.starts_with("HTTP/1.1 401"), "unauthenticated: {head}");

        // The default mode is metadata-only, and it means what it says:
        // information without a player. This is the gate the probe does
        // NOT have, and getting it wrong would give a player to every
        // install that never asked for one.
        let (head, _) = split_http(&get("?apikey=sekrit"));
        assert!(
            head.starts_with("HTTP/1.1 403"),
            "metadata-only served a player: {head}"
        );

        http(
            port,
            "/api?mode=config&name=preview&value=full&apikey=sekrit&output=json",
            None,
        );

        // Now the real thing.
        let (head, body) = split_http(&get("?apikey=sekrit"));
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.contains("X-Nzbfast-Path: remux"), "{head}");
        assert!(head.contains("Content-Type: video/mp4"), "{head}");
        // A produced stream cannot be range-requested, and saying so
        // stops a player from trying.
        assert!(head.contains("Accept-Ranges: none"), "{head}");
        assert!(!head.to_ascii_lowercase().contains("content-length"), "{head}");
        assert!(body.len() > 10_000, "the body was {} bytes: {head}", body.len());
        assert_eq!(&body[4..8], b"ftyp", "the body does not open with an init");
        assert!(
            body.windows(4).any(|w| w == b"moov"),
            "the init carries no moov"
        );
        assert!(
            body.windows(4).any(|w| w == b"moof"),
            "the body carries no media fragment"
        );
        // The payload is copied, not re-encoded, so the source's own
        // bytes are in there verbatim. The fixture's first video frame
        // is a distinctive pattern; finding it in the output is the
        // end-to-end form of the byte-identity test.
        let (video, _) = nzbkit::mediaprobe::testmux::mkv_remux_streams();
        assert!(
            body.windows(video[0].len()).any(|w| w == video[0]),
            "the first video frame did not survive the remux"
        );

        // init_only is a complete, small answer: it gets a real length.
        let (head, init) = split_http(&get("?apikey=sekrit&init_only=1"));
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.contains("Content-Length:"), "init_only was chunked: {head}");
        assert_eq!(&init[4..8], b"ftyp");
        assert!(
            !init.windows(4).any(|w| w == b"moof"),
            "init_only sent fragments"
        );

        // A seek reports the time it actually landed on, not the one it
        // was asked for: the fixture's keyframes are every 480 ms, so
        // 1200 snaps back to 960. A player told 1200 that receives 960
        // shows the seek as having failed.
        let (head, body) = split_http(&get("?apikey=sekrit&start_ms=1200"));
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(
            head.contains("X-Nzbfast-Start-Ms: 960"),
            "seek did not snap to a keyframe: {head}"
        );
        assert!(body.windows(4).any(|w| w == b"moof"), "no fragment after a seek");

        // §73 phase 4: `a=` picks which audio track the output carries,
        // counting the ENABLED audio tracks (samples::select_* filter
        // before they index, and the dashboard filters the same way).
        // The fixture has one, so a=0 IS the default and must produce
        // exactly the default's bytes - the plumbing is what is under
        // test here; which track each index names is pinned by the unit
        // tests in samples.rs.
        let (head0, body0) = split_http(&get("?apikey=sekrit&a=0"));
        assert!(head0.starts_with("HTTP/1.1 200"), "{head0}");
        let (_, plain) = split_http(&get("?apikey=sekrit"));
        assert_eq!(
            body0, plain,
            "a=0 differed from the default selection on a one-audio-track file"
        );

        // An index past the last audio track must not cost the viewer the
        // picture: the video still plays, silently. Refusing outright
        // would turn a stale index in a page that had been open a while
        // into a dead player.
        let (head, body) = split_http(&get("?apikey=sekrit&a=99"));
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "an out-of-range audio index refused the file: {head}"
        );
        assert_eq!(&body[4..8], b"ftyp", "no init after an out-of-range a=");
        assert!(
            body.windows(4).any(|w| w == b"moof"),
            "no video fragment after an out-of-range a="
        );
        // Video-only, so it is strictly smaller than the pair.
        assert!(
            body.len() < plain.len(),
            "a=99 carried an audio track anyway: {} vs {}",
            body.len(),
            plain.len()
        );

        // §73 phase 4: a Range this response cannot honour is refused
        // before a body byte.
        //
        // Safari's media loader opens every file with `Range: bytes=0-1`
        // to learn the resource length from the 206. This endpoint has
        // no length and no ranges to give, and ignoring the header - the
        // shipped behaviour until now - answered that two-byte probe
        // with the WHOLE file: measured 11 Aug 2026, Safari retried 99
        // times in six minutes and pulled 123.7 GB of a 2.5 GB episode,
        // remuxing from scratch each time, for a black screen.
        let probe = raw(
            port,
            format!(
                "GET /preview/media/{nzo}?apikey=sekrit HTTP/1.1\r\nHost: x\r\nRange: bytes=0-1\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        );
        let (head, body) = split_http(&probe);
        assert!(
            head.starts_with("HTTP/1.1 416"),
            "a two-byte range probe was not refused: {head}"
        );
        assert!(head.contains("Accept-Ranges: none"), "{head}");
        // The whole point: no media came back. A JSON refusal is small;
        // the file is 200 KB+, so this catches a body of any size.
        assert!(
            body.len() < 4_096 && !body.windows(4).any(|w| w == b"ftyp"),
            "the refusal carried {} bytes of media",
            body.len()
        );

        // `bytes=0-` IS the whole resource, which a 200 satisfies. It is
        // what Chromium sends before playing this successfully, so it
        // must keep working - refusing it would break the one browser
        // known to play the progressive stream.
        let whole = raw(
            port,
            format!(
                "GET /preview/media/{nzo}?apikey=sekrit HTTP/1.1\r\nHost: x\r\nRange: bytes=0-\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        );
        let (head, body) = split_http(&whole);
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "the whole-resource range was refused: {head}"
        );
        assert_eq!(&body[4..8], b"ftyp", "no init for a bytes=0- request");

        // An nzo_id nobody has is a 404, not somebody else's download.
        let r = raw(
            port,
            b"GET /preview/media/SABnzbd_nzo_nope?apikey=sekrit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let (head, _) = split_http(&r);
        assert!(head.starts_with("HTTP/1.1 404"), "{head}");

        // And "off" closes this door too.
        http(
            port,
            "/api?mode=config&name=preview&value=off&apikey=sekrit&output=json",
            None,
        );
        let (head, _) = split_http(&get("?apikey=sekrit"));
        assert!(head.starts_with("HTTP/1.1 403"), "preview=off still served: {head}");
    })
    .await
    .unwrap();
}
