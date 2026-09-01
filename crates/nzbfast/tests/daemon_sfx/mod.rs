//! The disk SFX arm, end to end: a self-extractor whose launcher stub
//! outruns the offset-0 article, so the in-stream sniff cannot see the
//! archive behind it and the whole payload takes the disk route.
//!
//! The arm had no integration coverage at all, which is how it shipped
//! finishing jobs with an EMPTY `archive_shape` - the queue row, the
//! history entry and the "Create report" download report all said nothing
//! about what the archive was, while the two other SFX routes filled
//! theirs (measured 23 Aug 2026: `sfxrar-small` blank beside an `sfx7z`
//! reading `7z one-pass` and a `comp5` reading `rar5 compressed
//! on-disk`).
//!
//! A child module of the `daemon` test crate root, not a `tests/*.rs`
//! sibling: a top-level file there would become its own auto-discovered
//! test binary and rebuild the whole harness. `use super::*` names the
//! root's fixtures exactly as they were named inline.

use super::*;

/// The badge the disk SFX arm now reports, and the payload it produced.
///
/// The stub is deliberately longer than one article: that is the whole
/// mechanism. TODO 94 C's sniff only ever looks at the offset-0 article's
/// bytes, so a stub that outruns it leaves the slot classified as a plain
/// data file - nothing archive-shaped parses, the extractor latches no
/// shape, and the SFX arm in the get tail is what eventually carves and
/// unpacks the thing. `rar5 on-disk` rather than a `one-pass` claim,
/// because that is what actually happened, and only tokens the dashboard
/// and the 27 i18n catalogues already carry.
#[tokio::test(flavor = "multi_thread")]
async fn a_deep_stub_sfx_reports_the_shape_it_unpacked() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-sfxshape-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(400_000, 21);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 400_000, &inner, false, false)]);
    // A launcher stub - a PROGRAM - and then the archive, which is what
    // a real self-extractor is. 400 KB of it against 100 KB articles, so
    // the signature sits four articles deep and the sniff never meets
    // it. The three PE fields are the ones `nzbkit::sfx::is_launcher_
    // stub` reads: this fixture carried a bare `MZ` until M4-101, and a
    // structural rule reads that as a data file that happens to start
    // with two coincidental bytes.
    let mut sfx = vec![0u8; 400_002];
    sfx[0..2].copy_from_slice(b"MZ");
    sfx[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    sfx[0x40..0x44].copy_from_slice(b"PE\0\0");
    sfx.extend(&vol);

    let mut articles = HashMap::new();
    let segs = make_file_articles("release.exe", &sfx, 100_000, "sfx", &mut articles);
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;release.exe&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    let srv = MockServer::start(articles, Chaos::default()).await;

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
            .arg(&out)
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let expected = inner.clone();
    tokio::task::spawn_blocking(move || {
        let boundary = "----sfxb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"release.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        let mut hist = String::new();
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"status\":\"Completed\"") || h.contains("\"status\":\"Failed\"") {
                hist = h;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(hist.contains("\"status\":\"Completed\""), "job: {hist}");
        assert!(
            hist.contains("\"archive_shape\":\"rar5 on-disk\""),
            "the disk SFX arm left the badge blank again: {hist}"
        );

        // ...and the badge describes an unpack that really happened.
        let mut found = None;
        for e in walkdir(&out) {
            if e.file_name().is_some_and(|n| n == "movie.mkv") {
                found = Some(e);
            }
        }
        let mkv = found.expect("the SFX payload must be unpacked");
        assert_eq!(std::fs::read(&mkv).unwrap(), expected);
    })
    .await
    .unwrap();
}

/// Every file under `dir`, one level of release folder deep - the output
/// layout is the daemon's business, not this test's.
fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(top) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in top.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(
                std::fs::read_dir(&p)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|c| c.path()),
            );
        } else {
            out.push(p);
        }
    }
    out
}
