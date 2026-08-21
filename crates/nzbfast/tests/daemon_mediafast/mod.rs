//! §76 regression: the media chip on a job too FAST to be caught mid-flight.
//!
//! The prober is a polling task. Its pass-2 list is fed only by watching
//! a job change out of `Downloading` between two ticks, so a job whose
//! whole download fits inside one tick is never admitted and never gets
//! its on-disk pass. The chip test next door hides this by padding the
//! payload to 12 MB and throttling the write to 3 MB/s, which holds the
//! download open for several seconds on purpose.
//!
//! A sibling-dir child of daemon.rs (the daemon_chip6 pattern) so the
//! parent stays inside its size-gate baseline; harness via `super::*`.

use super::*;

/// One small file, posted under a name that claims nothing, downloaded
/// with no throttle at all: it completes long before the prober's first
/// tick. The fixture is HEVC/E-AC3/HDR10 in Matroska, which is also the
/// codec shape of the report this came from.
#[tokio::test(flavor = "multi_thread")]
async fn a_download_shorter_than_one_tick_still_gets_its_chip() {
    let dir = std::env::temp_dir().join(format!("nzbfast-mediafast-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = nzbkit::mediaprobe::testmux::mkv_hdr();
    let mut articles = HashMap::new();
    let segs = make_file_articles("show.mkv", &data, 300_000, "mf", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;show.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
        // The tick is LONGER than the download on purpose: this is the
        // production shape (5 s tick, a job that takes two) compressed
        // enough to test, not an artificial one.
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_MEDIA_TICK_MS", "1500")
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
    let daemon_log = d.log.clone();

    tokio::task::spawn_blocking(move || {
        let boundary = "----mediafast";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Example.Show.S01E01.1080p.WEB-DL.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // The job completes almost at once; the chip has to arrive on
        // the history row from the final on-disk pass. Twenty seconds is
        // thirteen prober ticks, so this is not a race with the cadence.
        let mut hist = None;
        for _ in 0..200 {
            let h = http(port, "/api?mode=history&output=json", None);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&h)
                && let Some(slot) = v["history"]["slots"].get(0)
                && slot["status"] == "Completed"
                && slot["media"].is_object()
            {
                hist = Some(slot["media"].clone());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        let m = hist.unwrap_or_else(|| {
            panic!("a fast job never gained a media chip\n--- log ---\n{log}")
        });
        assert_eq!(m["res"], "1080p", "{m}");
        assert_eq!(m["vcodec"], "HEVC", "{m}");
        assert_eq!(m["container"], "mkv", "{m}");
        assert_eq!(m["complete"], true, "{m}");

        // The other half of the fix: the final pass now SAYS what it
        // read. A row with no chip used to be indistinguishable from a
        // row nobody probed, because neither left a line.
        assert!(
            log.contains("[media]") && log.contains("HEVC"),
            "the final pass read the file but logged nothing\n--- log ---\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
