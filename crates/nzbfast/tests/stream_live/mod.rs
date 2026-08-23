//! M11 playback: the five rigs that drive /stream against a job that
//! is still downloading - plain and encrypted store-mode rars, the
//! seek that promotes a deep window, the deep-window preempt, and the
//! `addfile&stream=1` front door with its player-handoff links.
//!
//! ...plus the other end of that contract (TODO 16m): the four rigs at
//! the bottom of this file drive /stream against a job that is NOT
//! downloading, where the whole question is whether the answer is
//! knowable now, worth waiting 30 s for, or - the last of them - an
//! honest refusal about a payload that is not where the record says.
//!
//! A sibling-dir child of daemon.rs (the daemon_chip6 / stream_chaos
//! pattern) so the parent stays inside its size-gate baseline; harness
//! via `super::*`.

use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn stream_while_downloading() {
    // M11: a store-mode rar'd mkv streams over /stream with correct bytes
    // WHILE the download is still running (write stage throttled to keep
    // the window open; the reader must block on not-yet-landed spans).
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-stream-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(24_000_000, 7); // 24 MB "movie"
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", 24_000_000, &inner[..8_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "movie.mkv",
                24_000_000,
                &inner[8_000_000..16_000_000],
                true,
                true,
            )],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 24_000_000, &inner[16_000_000..], true, false)],
            2,
        ),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("m.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("mv{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
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
            .arg("2")
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3"); // ~8 s download window
        c
    })
    .await;
    let port = d.port;

    let inner2 = inner.clone();
    tokio::task::spawn_blocking(move || {
        // Upload the NZB.
        let boundary = "----streamb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Wait for the stream to exist (download started + mkv writer up).
        let mut got: Vec<u8> = Vec::new();
        for _ in 0..200 {
            let raw = raw(
                port,
                b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=0-99999\r\nConnection: close\r\n\r\n",
            );
            let text_end = raw.windows(4).position(|w| w == b"\r\n\r\n");
            if let Some(p) = text_end {
                let head = String::from_utf8_lossy(&raw[..p]).to_string();
                if head.contains("206") {
                    got = raw[p + 4..].to_vec();
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if got.len() != 100_000 {
            panic!(
                "range length {} head_bytes={:?} tail={:?}",
                got.len(),
                &got[..24.min(got.len())],
                &got[got.len().saturating_sub(16)..]
            );
        }
        assert_eq!(&got[..], &inner2[..100_000], "streamed head bytes differ");

        // M14h: live stats while the download runs - pool gauges up,
        // download lane moving, extract writers visible.
        let s = http(port, "/api?mode=stats&output=json", None);
        assert!(s.contains("\"active\":true"), "{s}");
        assert!(s.contains("\"budget\":2"), "{s}");
        assert!(s.contains("\"connected\":"), "{s}");
        assert!(s.contains("movie.mkv"), "{s}");

        // Mid-file range while the tail is still downloading - reader must
        // block until covered, then return exact bytes.
        let raw = raw(
            port,
            b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=20000000-20050000\r\nConnection: close\r\n\r\n",
        );
        let p = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("hdrs");
        assert!(String::from_utf8_lossy(&raw[..p]).contains("206"), "{}", String::from_utf8_lossy(&raw[..p]));
        assert_eq!(&raw[p + 4..], &inner2[20_000_000..20_050_001], "mid-range bytes differ");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_encrypted_while_downloading() {
    // An ENCRYPTED store rar streams over /stream mid-download: the file
    // on disk is AES-256-CBC ciphertext (the finish decrypt hasn't run),
    // so the served bytes prove the on-the-fly CBC decryption path.
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-encstream-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(24_000_003, 8); // odd length → end-padding truncate
    let f = fixtures::encrypt_file("s3cret", &inner, 5);
    let n = f.cipher.len();
    let (a, b) = (8_000_016, 16_000_000); // 16-aligned mid splits
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("m.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("ev{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
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
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // The finish decrypt must NOT be able to reach for unrar; native
            // decryption + on-the-fly streaming is the whole point.
            .env("NZBFAST_TEST_FORBID_UNRAR", "1")
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
            .arg("2")
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3"); // ~8 s download window
        c
    })
    .await;
    let port = d.port;

    let inner2 = inner.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Upload with the {{password}} filename convention.
        let boundary = "----encstreamb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie{{{{s3cret}}}}.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Head range while still downloading (and still ciphertext).
        let mut got: Vec<u8> = Vec::new();
        for _ in 0..200 {
            let raw = raw(
                port,
                b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=0-99999\r\nConnection: close\r\n\r\n",
            );
            if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n")
                && String::from_utf8_lossy(&raw[..p]).contains("206") {
                    got = raw[p + 4..].to_vec();
                    break;
                }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(got.len(), 100_000, "head range length");
        assert_eq!(&got[..], &inner2[..100_000], "decrypted head bytes differ");

        // Mid-file range spanning a volume boundary, decrypted on the fly
        // (block-unaligned start exercises the IV-block read).
        let raw = raw(
            port,
            b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=15999990-16050000\r\nConnection: close\r\n\r\n",
        );
        let p = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("hdrs");
        assert!(String::from_utf8_lossy(&raw[..p]).contains("206"));
        assert_eq!(&raw[p + 4..], &inner2[15_999_990..16_050_001], "mid-range decrypt differs");

        // Wait for the JOB to complete - not just for the file to reach a
        // length. The inner file is preallocated to the unpacked size and
        // holds ciphertext until the finish decrypt, so length alone is
        // not a done signal (reading it mid-download yields ciphertext).
        // Poll history for Completed, then the file is plaintext.
        let mut completed = false;
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.replace(' ', "").contains("\"status\":\"Completed\"") {
                completed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(completed, "job never reached Completed");
        let mkv = dir2.join("complete/movie/movie.mkv");
        let got =
            std::fs::read(&mkv).unwrap_or_else(|e| panic!("reading {}: {e}", mkv.display()));
        assert_eq!(got.len(), inner2.len(), "final file length");
        let first_diff = got.iter().zip(&inner2).position(|(a, b)| a != b);
        assert!(first_diff.is_none(), "final file differs at byte {first_diff:?}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M11 ordering e2e: the mock server records BODY request order, so this
/// proves the two queue-shaping behaviors end to end (not just byte
/// correctness, which `stream_while_downloading` covers):
///  1. tail burst - the LAST volume's articles fetch right after the
///     first volume, before ANY middle-volume article (MKV Cues / MP4
///     moov live at file end; players read them before starting play);
///  2. seek re-prioritization - a Range request far past the write
///     frontier promotes the articles under it, so the middle volume is
///     entered at the seek point, not at its first article.
/// One connection, window 1, and a fixed per-article server delay make
/// the BODY log a faithful picture of the pending-queue order.
#[tokio::test(flavor = "multi_thread")]
async fn stream_seek_promotes_and_tail_bursts() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-seekord-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // 48 MB movie in 3 store-mode rar5 volumes of 16 MB payload each:
    // volA = inner[0..16M], volB = [16..32M], volC = [32..48M]. Volumes
    // are sized well above the promote window's 4 MB PRE_ROLL so a
    // mid-volume seek still provably enters the volume mid-way.
    let inner = payload(48_000_000, 11);
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", 48_000_000, &inner[..16_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "movie.mkv",
                48_000_000,
                &inner[16_000_000..32_000_000],
                true,
                true,
            )],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 48_000_000, &inner[32_000_000..], true, false)],
            2,
        ),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("m.part{}.rar", i + 1);
        let tag = ["volA", "volB", "volC"][i];
        let segs = make_file_articles(&name, vol, 300_000, tag, &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    // 80 ms per article paces the ~162-article download to ~13 s - wide
    // timing margins so the seek reliably lands before the middle volume
    // starts naturally, even under full-suite parallelism.
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 80,
            ..Chaos::default()
        },
    )
    .await;
    let body_log = srv.body_log.clone();

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
            .arg("1")
            .arg("--window")
            .arg("1");
        c
    })
    .await;
    let port = d.port;

    // "<volB-13@mock>" → Some(13) for tag "volB".
    fn part_of(id: &str, tag: &str) -> Option<u32> {
        id.strip_prefix('<')?
            .strip_prefix(tag)?
            .strip_prefix('-')?
            .split('@')
            .next()?
            .parse()
            .ok()
    }

    let inner2 = inner.clone();
    tokio::task::spawn_blocking(move || {
        let boundary = "----seekord";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Wait for the stream to come up (tail bytes landed, writer
        // live). Probe the file TAIL, not byte 0: a probe's reader
        // promotes a SEEK_READAHEAD (32 MB) playhead window, and from
        // position 0 that window spans volA and ALL of volB - displacing
        // the volC tail burst behind it and racing volB into the store
        // before the gate below trips. A tail probe's window is pure
        // volC, so volB provably stays untouched until the seek.
        let mut up = false;
        for _ in 0..600 {
            let raw = raw(
                port,
                b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=47900000-47999999\r\nConnection: close\r\n\r\n",
            );
            if String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 206") {
                up = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(up, "/stream never became ready");

        // 1. Tail burst: wait until a few tail-volume (volC) articles have
        // been requested and assert the middle volume (volB) hasn't been
        // touched - volC jumped the queue at build. (Queue order makes
        // this deterministic: all bursted volC precede any volB. Part 1 of
        // every volume is exempt - each volume's first article goes out
        // early so the extractor can parse rar headers and map volumes.)
        let pre_len = loop {
            let log = body_log.lock().unwrap();
            if log.iter().filter(|id| id.starts_with("<volC-")).count() >= 3 {
                assert!(
                    !log.iter().any(|id| part_of(id, "volB").is_some_and(|n| n >= 2)),
                    "middle volume fetched before the tail burst: {log:?}"
                );
                break log.len();
            }
            drop(log);
            std::thread::sleep(std::time::Duration::from_millis(25));
        };

        // 2. Seek: inner byte 24 MB is the middle of volB - far past the
        // write frontier, so the range start must promote the articles
        // under it. The read blocks until they land, then returns exact
        // bytes.
        let raw = raw(
            port,
            b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=24000000-24049999\r\nConnection: close\r\n\r\n",
        );
        let p = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("hdrs");
        assert!(
            String::from_utf8_lossy(&raw[..p]).contains("206"),
            "{}",
            String::from_utf8_lossy(&raw[..p])
        );
        assert_eq!(&raw[p + 4..], &inner2[24_000_000..24_050_000], "seek bytes differ");

        // The seek entered volB mid-volume: every volB article requested
        // so far sits at/after the promoted window (24 MB seek − 4 MB
        // pre-roll → volB offset ~4 MB → part ~14 of 54, minus the
        // ladder's ±2 slack) - linear order would have started at part 1.
        let log = body_log.lock().unwrap();
        let volb: Vec<u32> =
            log[pre_len..].iter().filter_map(|id| part_of(id, "volB")).collect();
        assert!(!volb.is_empty(), "no volB articles fetched for the seek");
        assert!(
            volb.iter().all(|&n| n >= 8),
            "volB entered at part {volb:?} - promotion should start it mid-volume"
        );
        assert!(
            volb.iter().any(|&n| (10..=20).contains(&n)),
            "no volB article near the 12 MB seek point: {volb:?}"
        );
        assert!(
            !log[..pre_len].iter().any(|id| part_of(id, "volB").is_some_and(|n| n >= 2)),
            "volB data fetched before the seek"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M11 deep-window preemption e2e: same 3-volume fixture as
/// `stream_seek_promotes_and_tail_bursts`, but with 4 connections × window
/// 4 - the real-world shape where a promote used to queue behind ~16
/// already-pipelined BODYs and a seek took tens of seconds at scale. The
/// live /stream reader engages the pool's stream mode (shallow pipelines +
/// shed of deep ones), so a promoted article must be REQUESTED within K
/// BODYs of the promote, not after every connection drains its window.
/// The final byte-identical completion check proves the shed/requeue path
/// loses nothing.
#[tokio::test(flavor = "multi_thread")]
async fn stream_promote_preempts_deep_windows() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-seekpre-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(48_000_000, 13);
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", 48_000_000, &inner[..16_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "movie.mkv",
                48_000_000,
                &inner[16_000_000..32_000_000],
                true,
                true,
            )],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 48_000_000, &inner[32_000_000..], true, false)],
            2,
        ),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("m.part{}.rar", i + 1);
        let tag = ["volA", "volB", "volC"][i];
        let segs = make_file_articles(&name, vol, 300_000, tag, &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    // 80 ms per article: 4 connections serve ~50 articles/s, so the
    // ~162-article download runs ~3 s - slow enough that the 24 MB seek
    // lands while the middle volume is still pending, fast enough for
    // the suite. (16 MB volumes: sized well above the promote window's
    // 4 MB PRE_ROLL so mid-volume entry stays provable.)
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 80,
            ..Chaos::default()
        },
    )
    .await;
    let body_log = srv.body_log.clone();
    let pause = srv.pause.clone();

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
    // `serve` captures the daemon's stdout, which this test needs: it
    // uses the "[stream] seek@… promoted" print as the exact promote
    // marker while the mock is frozen.
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
            .arg("4")
            .arg("--window")
            .arg("4");
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log_path();

    // "<volB-13@mock>" → Some(13) for tag "volB".
    fn part_of(id: &str, tag: &str) -> Option<u32> {
        id.strip_prefix('<')?
            .strip_prefix(tag)?
            .strip_prefix('-')?
            .split('@')
            .next()?
            .parse()
            .ok()
    }

    let inner2 = inner.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Liveness deadlines in this test are sized for a fully loaded
        // machine (`cargo test --workspace --release` runs many test
        // binaries in parallel and stretches the nominal ~5 s run to
        // 25 s+). The preemption assertions themselves are anchored to
        // the daemon's promote marker while the mock is frozen, so
        // generous deadlines cost nothing in correctness - they only
        // delay reporting on a genuinely hung run.
        let boundary = "----seekpre";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Wait for the stream to come up. The successful request also
        // engages the pool's stream mode - from here on, pipelines are
        // shallow and any deep pre-stream window gets shed.
        //
        // Probe the file TAIL, not byte 0: a probe's reader promotes a
        // SEEK_READAHEAD (32 MB) playhead window, and from position 0
        // that window spans volA AND ALL OF volB - displacing the volC
        // tail burst behind it and racing volB into the store before the
        // freeze below can land (the flake this test used to have under
        // suite load: the seek point was already covered, so the seek
        // promote - and its log marker - never fired). A tail probe's
        // window is pure volC, leaving volB pending until the real seek
        // no matter how slowly this thread gets scheduled.
        let mut up = false;
        for _ in 0..900 {
            let raw = raw(
                port,
                b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=47900000-47999999\r\nConnection: close\r\n\r\n",
            );
            if String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 206") {
                up = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(up, "/stream never became ready");

        // Let the run get going (tail burst served) but seek while the
        // middle volume is still pending: 3 volC articles ≈ 58 served of
        // the ~81 (volA+volC tail) that precede any volB data in queue
        // order.
        loop {
            let log = body_log.lock().unwrap();
            if log.iter().filter(|id| id.starts_with("<volC-")).count() >= 3 {
                break;
            }
            drop(log);
            std::thread::sleep(std::time::Duration::from_millis(25));
        }

        // Freeze the mock (connections stop reading commands), land the
        // seek's promote at a KNOWN point in the body log, then release.
        // Without the freeze, scheduler jitter between capturing the log
        // length and the daemon executing the promote lets an unbounded
        // number of legitimately-ordered requests slip in between.
        pause.store(true, std::sync::atomic::Ordering::Release);
        std::thread::sleep(std::time::Duration::from_millis(300));

        // Seek to inner byte 24 MB (middle of volB), far past the write
        // frontier. The promote must preempt: with stream mode active no
        // connection holds more than one in-flight BODY, so the promoted
        // articles go out within ~one BODY per connection - not after
        // 4-deep windows drain.
        //
        // Hand-rolled rather than `raw()`: this request is deliberately
        // left in flight, unread, while the assertions below run against
        // the frozen mock.
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=24000000-24049999\r\nConnection: close\r\n\r\n").unwrap();
        // Wait for the daemon's own promote print - the exact marker that
        // the queue reorder has happened - while the log is frozen, then
        // snapshot the promote point and release the world. (The world
        // is frozen, so waiting longer is free - the deadline only has
        // to beat scheduler starvation on a loaded machine.)
        let mut promoted = false;
        for _ in 0..1200 {
            let l = std::fs::read_to_string(&daemon_log).unwrap_or_default();
            if l.contains("seek@24000000 → promoted") {
                promoted = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(promoted, "the seek's promote never fired while frozen");
        let pre_len = body_log.lock().unwrap().len();
        pause.store(false, std::sync::atomic::Ordering::Release);
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let p = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("hdrs");
        assert!(
            String::from_utf8_lossy(&raw[..p]).contains("206"),
            "{}",
            String::from_utf8_lossy(&raw[..p])
        );
        assert_eq!(&raw[p + 4..], &inner2[24_000_000..24_050_000], "seek bytes differ");

        {
            let log = body_log.lock().unwrap();
            let post = &log[pre_len..];
            // The promoted window (24 MB − 4 MB pre-roll → volB from
            // ~part 12 of 54, ±2 ladder slack) must
            // be REQUESTED within K articles of the promote: 4 in-flight
            // singles + a few requests racing the promote itself. A
            // regression to backlog-drain pickup lands at ~13+ (4 conns ×
            // 3 remaining window slots ahead of it).
            const K: usize = 8;
            let first_promoted = post
                .iter()
                .position(|id| part_of(id, "volB").is_some_and(|n| n >= 8))
                .expect("no promoted volB article requested after the seek");
            assert!(
                first_promoted < K,
                "promoted article only requested after {first_promoted} others (window backlog not preempted): {post:?}"
            );
            // And the promotion entered volB mid-volume, at the seek point.
            let volb: Vec<u32> = post.iter().filter_map(|id| part_of(id, "volB")).collect();
            assert!(
                volb.iter().all(|&n| n >= 8),
                "volB entered at part {volb:?} - promotion should start it mid-volume"
            );
            assert!(
                volb.iter().any(|&n| (20..=34).contains(&n)),
                "no volB article near the 24 MB seek point: {volb:?}"
            );
        }

        // The shed/requeue path must lose nothing: the download completes
        // and the extracted movie is byte-identical. ~162 articles at
        // 80 ms across 4 connections is ~4 s nominal, but extraction +
        // suite load can multiply that several-fold.
        let mut done = false;
        for _ in 0..750 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(done, "download never completed after the seek");
        fn find_file(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
            for e in std::fs::read_dir(dir).ok()? {
                let p = e.ok()?.path();
                if p.is_dir() {
                    if let Some(f) = find_file(&p, name) {
                        return Some(f);
                    }
                } else if p.file_name().is_some_and(|f| f == name) {
                    return Some(p);
                }
            }
            None
        }
        let out = find_file(&dir2.join("complete"), "movie.mkv").expect("movie.mkv missing");
        assert_eq!(std::fs::read(&out).unwrap(), inner2, "extracted bytes differ");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// "Stream an NZB" front door: `addfile&stream=1` enqueues at Force
/// priority and answers with the player-handoff links (m3u + tokenized
/// /stream/<id>); the /m3u link serves a playlist pointing at the
/// stream. The same links come from GET /watch?url= (303 → the m3u).
#[tokio::test(flavor = "multi_thread")]
async fn stream_add_returns_player_links() {
    let dir = std::env::temp_dir().join(format!("nzbfast-streamadd-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(600_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("show.mkv", &data, 300_000, "sa", &mut articles);
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;show.mkv&quot; yEnc (1/2)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
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
        let boundary = "----streamadd";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"show.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&output=json&stream=1",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        assert!(r.contains("\"m3u\":") && r.contains("/m3u/"), "no m3u link: {r}");
        assert!(r.contains("\"stream\":") && r.contains("/stream/"), "no stream link: {r}");

        // Force priority: the queue/history slot reports it (job may
        // complete instantly - 600 KB, no delay - so check both).
        let mut forced = false;
        for _ in 0..100 {
            let q = http(port, "/api?mode=queue&output=json", None);
            let h = http(port, "/api?mode=history&output=json", None);
            if q.contains("\"priority\":\"Force\"") || q.contains("\"Force\"") {
                forced = true;
                break;
            }
            if h.contains("\"Completed\"") {
                forced = true; // ran to completion straight away - it led the queue
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(forced, "stream add neither Force-queued nor completed");

        // The m3u link answers with a playlist pointing at the stream.
        let m3u = String::from_utf8_lossy(&raw(
            port,
            b"GET /m3u/SABnzbd_nzo_nzbfast1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ))
        .to_string();
        assert!(m3u.contains("#EXTM3U") && m3u.contains("/stream/SABnzbd_nzo_nzbfast1?t="), "{m3u}");

        // /watch with a bad URL fails loudly (502), not silently.
        let bad = String::from_utf8_lossy(&raw(
            port,
            b"GET /watch?url=http://127.0.0.1:9/none.nzb HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ))
        .to_string();
        assert!(bad.starts_with("HTTP/1.1 502"), "{bad}");
        // /watch without url= is a 400.
        let nourl = String::from_utf8_lossy(&raw(
            port,
            b"GET /watch HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ))
        .to_string();
        assert!(nourl.starts_with("HTTP/1.1 400"), "{nourl}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// TODO 16m: the /stream admit wait, and the answers that need none
// ---------------------------------------------------------------------

/// A daemon over a hand-seeded spool and NO configured server.
///
/// `hist` rows go to `.spool/history.jsonl`, `queued` rows into
/// `.spool/queue.json`, both in the shape `job_from_json` restores. No
/// server means §154 holds the queue, so a seeded row stays exactly as
/// seeded and no download can race the assertions - which is the whole
/// point: these rigs are about what /stream says when nothing is
/// running, and a job that started would answer a different question.
async fn seeded_daemon(
    dir: &Path,
    hist: &[serde_json::Value],
    queued: &[serde_json::Value],
) -> harness::Daemon {
    let spool = dir.join("complete/.spool");
    std::fs::create_dir_all(&spool).unwrap();
    if !hist.is_empty() {
        let lines: String = hist
            .iter()
            .map(|r| format!("{}\n", serde_json::to_string(r).unwrap()))
            .collect();
        std::fs::write(spool.join("history.jsonl"), lines).unwrap();
    }
    if !queued.is_empty() {
        std::fs::write(
            spool.join("queue.json"),
            serde_json::json!({ "queue": queued, "history": [] }).to_string(),
        )
        .unwrap();
    }
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    serve(dir, |port| {
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
            .arg(dir.join("complete"));
        c
    })
    .await
}

/// One seeded record. `extra` overrides and adds keys, so a rig says
/// only what it is actually testing.
fn seed_row(id: &str, dir: &Path, state: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut v = serde_json::json!({
        "nzo_id": id,
        "name": format!("Seeded.{id}"),
        "nzb_path": dir.join(format!("{id}.nzb")).to_string_lossy(),
        "out_dir": dir.join(format!("complete/{id}")).to_string_lossy(),
        "state": state,
        "total_bytes": 1_000_000u64,
        "finished_unix": 1_722_000_000i64,
    });
    if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        for (k, val) in e {
            o.insert(k.clone(), val.clone());
        }
    }
    v
}

fn stream_get(id: &str) -> Vec<u8> {
    format!("GET /stream/{id}?apikey=sekrit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

/// Send `req` and give the daemon `secs` to start answering. `None` is
/// "still waiting", which is what the wait path is supposed to do;
/// `Some` carries whatever came back, including the empty string for a
/// connection closed without an answer (which is not waiting, and must
/// fail loudly rather than read as a pass).
///
/// The socket is dropped either way. A /stream response still inside
/// its admit wait holds one HTTP worker until its own deadline whatever
/// the client does, so the probe cannot shorten it - it only stops the
/// TEST from paying for it.
fn answer_within(port: u16, req: &[u8], secs: u64) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(req).expect("write");
    s.set_read_timeout(Some(std::time::Duration::from_secs(secs)))
        .unwrap();
    let mut buf = [0u8; 512];
    match s.read(&mut buf) {
        Ok(n) => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            None
        }
        Err(e) => panic!("probe failed on :{port}: {e}"),
    }
}

/// TODO 16m: a job that is finished AND settled gets its 404 at once.
///
/// The pre-fix behaviour was the M14i admit wait running to its full 30
/// s deadline and then answering "no active media" - 15 bytes that were
/// knowable the moment the request arrived. A player (and the
/// dashboard's ▶) spends that half minute looking hung on an answer we
/// already have.
///
/// A Failed row is the shape that still reached it: `Completed` +
/// `fetched` has been served from disk since 72a06c3ac, and an id in
/// NEITHER store has always been an immediate `unknown nzo_id`.
#[tokio::test(flavor = "multi_thread")]
async fn a_settled_job_answers_stream_without_waiting() {
    let dir = std::env::temp_dir().join(format!("nzbfast-16m-settled-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    const ID: &str = "SABnzbd_nzo_settled1";

    let d = seeded_daemon(
        &dir,
        &[seed_row(
            ID,
            &dir,
            "Failed",
            serde_json::json!({"fail_message": "download incomplete: 12 articles missing"}),
        )],
        &[],
    )
    .await;
    let port = d.port;

    let (took, body) = tokio::task::spawn_blocking(move || {
        let t0 = std::time::Instant::now();
        let out = String::from_utf8_lossy(&raw(port, &stream_get(ID))).to_string();
        (t0.elapsed(), out)
    })
    .await
    .unwrap();

    assert!(body.starts_with("HTTP/1.1 404"), "{body}");
    assert!(body.contains("no active media"), "{body}");
    // The answer is computed, not waited for. The bound is seconds
    // rather than the "well under a second" this actually measures
    // because the daemon suite shares a box with other sessions' builds
    // - what it has to separate is a computed answer from a 30 s
    // deadline, and any bound in between does that.
    assert!(
        took < std::time::Duration::from_secs(5),
        "the settled 404 took {took:?} - the admit wait is still being sat out"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 16m, the other side: a QUEUED job still waits the full 30 s.
///
/// The status word says nothing has happened yet, which is exactly the
/// case the wait exists for - its writers appear as soon as the runner
/// picks it up, and a player that asked a second too early must be
/// served rather than refused. This is also the only rig that pins the
/// wait's LENGTH, so an early-out that quietly swallowed the wait path
/// as well would be caught here.
#[tokio::test(flavor = "multi_thread")]
async fn a_queued_job_still_waits_out_the_admit_deadline() {
    let dir = std::env::temp_dir().join(format!("nzbfast-16m-queued-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    const ID: &str = "SABnzbd_nzo_queued1";

    // Paused as well as serverless: two independent reasons this row
    // cannot start, so the rig does not depend on either one alone.
    let d = seeded_daemon(
        &dir,
        &[],
        &[seed_row(
            ID,
            &dir,
            "Queued",
            serde_json::json!({"paused": true}),
        )],
    )
    .await;
    let port = d.port;

    let (took, body) = tokio::task::spawn_blocking(move || {
        let t0 = std::time::Instant::now();
        let out = String::from_utf8_lossy(&raw(port, &stream_get(ID))).to_string();
        (t0.elapsed(), out)
    })
    .await
    .unwrap();

    assert!(body.starts_with("HTTP/1.1 404"), "{body}");
    assert!(body.contains("no active media"), "{body}");
    assert!(
        took >= std::time::Duration::from_secs(25),
        "a queued job answered in {took:?} - the 30 s wait for its writers is gone"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 16m, the trap in the middle: a job whose settle has NOT
/// finished waits, however terminal its status word reads.
///
/// The shape here is a record that reached history while its pipeline
/// was still running - a park torn between its prewrite and its filing.
/// `job_from_json` restores any nonterminal state as `Queued`, so it
/// arrives as the queued-looking record sitting in history that
/// histstore.rs calls out by name. It is in NO queue and it has NO
/// writers, so a predicate reading only those two would answer it
/// immediately.
///
/// The settle's other half - a `Completed` record that still owes its
/// payload the move to its final home - cannot be rigged from a seeded
/// spool: startup re-enqueues every owed move before the mover worker
/// starts draining, so the flag is gone by the time a request could ask
/// about it. That arm is pinned in `serve::stream::stream_admit_tests`,
/// against the predicate directly.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_still_settling_still_waits() {
    let dir = std::env::temp_dir().join(format!("nzbfast-16m-settling-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    const TORN: &str = "SABnzbd_nzo_torn1";

    let d = seeded_daemon(
        &dir,
        &[seed_row(TORN, &dir, "Downloading", serde_json::json!({}))],
        &[],
    )
    .await;
    let port = d.port;

    let answered = tokio::task::spawn_blocking(move || answer_within(port, &stream_get(TORN), 3))
        .await
        .unwrap();
    assert!(
        answered.is_none(),
        "a torn park was answered {answered:?} - a job mid-settle must sit out the wait"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The finished-job branch's two answers that a seeded spool CAN reach:
/// the file is there and is served, or it is not and the record is
/// settled, which is the one case "no playable file on disk any more"
/// is honest about.
///
/// Its third answer - the payload is in flight to its final folder, so
/// the record names a folder the bytes have left - cannot be rigged
/// from here for the same reason 16m's `move_pending` arm could not:
/// startup re-enqueues every owed move before the mover starts
/// draining, and the fence the seam actually turns on is held only for
/// the width of one copy. It is pinned in
/// `serve::stream::stream_move_window_tests`, against the predicate and
/// against a real `mover_process` run.
///
/// Both rows here are `Completed` + `fetched`, which is what sends a
/// request down that branch rather than the library trigger or the
/// admit wait.
///
/// `/preview/probe` resolves the same job through the same
/// `finished_media_path` and now asks the same in-flight question after
/// its own miss, so the settled half of ITS answer rides along here -
/// one door down, and the arm most at risk of being broken by a change
/// to the door above. `/preview/media`, the third door onto the same
/// record and the one the dashboard's player opens, rides along for
/// the same reason.
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_job_serves_its_file_and_says_so_honestly_when_it_is_gone() {
    let dir = std::env::temp_dir().join(format!("nzbfast-16m-done-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    const KEPT: &str = "SABnzbd_nzo_kept1";
    const GONE: &str = "SABnzbd_nzo_gone1";

    let kept_dir = dir.join(format!("complete/{KEPT}"));
    std::fs::create_dir_all(&kept_dir).unwrap();
    std::fs::write(kept_dir.join("Seeded.mkv"), vec![b'k'; 4096]).unwrap();

    let done = serde_json::json!({"fetched": true});
    let d = seeded_daemon(
        &dir,
        &[
            seed_row(KEPT, &dir, "Completed", done.clone()),
            seed_row(GONE, &dir, "Completed", done),
        ],
        &[],
    )
    .await;
    let port = d.port;

    let probe_gone = format!(
        "GET /preview/probe/{GONE}?apikey=sekrit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let (kept, gone, probe) = tokio::task::spawn_blocking(move || {
        (
            String::from_utf8_lossy(&raw(port, &stream_get(KEPT))).to_string(),
            String::from_utf8_lossy(&raw(port, &stream_get(GONE))).to_string(),
            String::from_utf8_lossy(&raw(port, &probe_gone)).to_string(),
        )
    })
    .await
    .unwrap();

    assert!(kept.starts_with("HTTP/1.1 200"), "{kept}");
    assert!(kept.contains("Accept-Ranges: bytes"), "{kept}");

    // Nothing was ever written under this one's out_dir, and nothing is
    // moving, so the record really is naming a folder with no media in
    // it. 404, and NOT the 503 the in-flight arm answers - a fix that
    // called every miss a move would say "try again" forever.
    assert!(gone.starts_with("HTTP/1.1 404"), "{gone}");
    assert!(gone.contains("no playable file on disk any more"), "{gone}");

    // Same job through the probe: also a 404, and its own wording. The
    // 503 arm beside it is the in-flight one, and answering a settled
    // miss with it would tell every client to keep polling a file that
    // is never coming back.
    assert!(probe.starts_with("HTTP/1.1 404"), "{probe}");
    assert!(probe.contains("no playable file on disk"), "{probe}");
    assert!(!probe.contains("moving"), "{probe}");

    // The third door: `/preview/media` - the remux byte path the
    // dashboard's player actually opens - resolves the same job through
    // the same pick and carries the same 404-vs-503 pair. It is gated on
    // the `full` preview mode, which the seeded rig does not default to.
    let set_full = b"GET /api?mode=config&name=preview&value=full&apikey=sekrit HTTP/1.1\r\n\
                     Host: x\r\nConnection: close\r\n\r\n"
        .to_vec();
    let media_gone = format!(
        "GET /preview/media/{GONE}?apikey=sekrit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let (set, media) = tokio::task::spawn_blocking(move || {
        (
            String::from_utf8_lossy(&raw(port, &set_full)).to_string(),
            String::from_utf8_lossy(&raw(port, &media_gone)).to_string(),
        )
    })
    .await
    .unwrap();
    assert!(set.starts_with("HTTP/1.1 200"), "{set}");
    assert!(media.starts_with("HTTP/1.1 404"), "{media}");
    assert!(media.contains("no playable file on disk"), "{media}");
    assert!(!media.contains("moved"), "{media}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 16m's SECOND half: a job that finishes WHILE a player is
/// mid-request is answered from the finished file, not waited out.
///
/// The first pass asked `no_writers_and_no_prospect` exactly once, just
/// before arming the deadline, and the wait loop never asked again. So a
/// job that was Downloading when the request arrived, and completed
/// during the wait, had its writers published away and then sat out the
/// remainder of the 30 s for a 404 - with its bytes finished on disk the
/// whole time. 16m's own text named this case and the first pass did not
/// cover it.
///
/// The payload is deliberately NOT a media name. `pick_media` would
/// otherwise find its writer the moment the download started and serve
/// bytes off it, which is the M11 rig at the top of this file and a
/// different question: for THIS one the live pick has to stay empty so
/// the request reaches the wait at all. That also fixes what the answer
/// is - the finished branch's "no playable file", since a `.bin` is no
/// more playable off disk than it was off a writer - so the rig reads
/// the answer's SHAPE and its CLOCK: the same request, answered by the
/// finished-job branch in the seconds the download took, rather than by
/// the live path's "no active media" at 30 s.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_that_finishes_mid_request_is_answered_from_disk() {
    let dir = std::env::temp_dir().join(format!("nzbfast-16m-midflight-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(9_000_000, 11);
    let mut articles = HashMap::new();
    let segs = make_file_articles("payload.bin", &inner, 300_000, "pb", &mut articles);
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;payload.bin&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        // ~3 s of download at 3 MB/s, so the request below is issued
        // while the job is still on the wire and the completion lands
        // well inside the 30 s deadline it would otherwise sit out.
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3")
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

    let (took, body) = tokio::task::spawn_blocking(move || {
        let boundary = "----midflight";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"p.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let added = http(
            port,
            "/api?mode=addfile&output=json&apikey=sekrit",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        let nzo = added
            .split("\"nzo_ids\":[\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_else(|| panic!("no nzo_id in {added}"))
            .to_string();

        let t0 = std::time::Instant::now();
        let out = String::from_utf8_lossy(&raw(port, &stream_get(&nzo))).to_string();
        (t0.elapsed(), out)
    })
    .await
    .unwrap();

    assert!(body.starts_with("HTTP/1.1 404"), "{body}");
    assert!(
        body.contains("no playable file on disk"),
        "answered {body:?} - the finished-job branch never got a second look"
    );
    // It really did wait: the request was issued before the download
    // started and the throttle holds it on the wire for seconds.
    assert!(
        took >= std::time::Duration::from_secs(1),
        "answered in {took:?} - too fast to have entered the wait at all, \
         so this rig is no longer testing the mid-request completion"
    );
    // ...and it did not wait the deadline out. The measured defect was
    // 30.03 s; the bound is loose because the daemon suite shares a box.
    assert!(
        took < std::time::Duration::from_secs(20),
        "answered in {took:?} - the wait loop is still sitting out the \
         full admit deadline for a job that finished under it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 16m, the shape a stale .strm is likeliest to point at: a Failed
/// job with an automatic retry armed.
///
/// The first pass required `auto_retry_at.is_none()` to take the
/// early-out, so any armed retry kept the request waiting. The default
/// arm is 20 minutes out ("articles missing - propagation may fill
/// them"), which cannot produce a writer inside a 30 s deadline, and a
/// partly-propagated post is the commonest way a job fails - so the
/// commonest dead pointer in a media library was also the one that still
/// hung for the full half minute. The stamp is compared against the
/// wait's own end now.
///
/// Seeded rather than run to failure on purpose: this is the ENTRY
/// path's question, asked before any wait is armed, and a seeded daemon
/// has no extractor at all - which keeps the rig off the trap that a
/// failed RUN leaves its extractor installed with a media writer still
/// listed, so the live pick answers quickly off a file quarantine has
/// already renamed aside. That is a different question with the same
/// clock.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_job_with_a_far_off_retry_answers_stream_without_waiting() {
    let dir = std::env::temp_dir().join(format!("nzbfast-16m-armed-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    const ID: &str = "SABnzbd_nzo_armed1";

    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 20 * 60;
    let d = seeded_daemon(
        &dir,
        &[seed_row(
            ID,
            &dir,
            "Failed",
            serde_json::json!({
                "fail_message": "download incomplete: 12 articles missing",
                "auto_retry_at": at,
                "auto_retry_why": "propagation",
            }),
        )],
        &[],
    )
    .await;
    let port = d.port;

    let (took, body) = tokio::task::spawn_blocking(move || {
        let t0 = std::time::Instant::now();
        let out = String::from_utf8_lossy(&raw(port, &stream_get(ID))).to_string();
        (t0.elapsed(), out)
    })
    .await
    .unwrap();

    assert!(body.starts_with("HTTP/1.1 404"), "{body}");
    assert!(body.contains("no active media"), "{body}");
    assert!(
        took < std::time::Duration::from_secs(5),
        "a retry armed 20 minutes out took {took:?} - it is still being \
         read as a prospect of writers inside a 30 s wait"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
