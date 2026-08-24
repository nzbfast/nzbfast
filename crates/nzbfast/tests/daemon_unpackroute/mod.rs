//! Unpack-routing daemon tests: passwords attached mid-download, and the
//! `prefer_external_unrar` switch. Moved out of tests/daemon.rs bodily
//! (TODO 106 - the suite was 12,429 lines, over its size-gate entry).
//!
//! A child module of the `daemon` test crate root, not a `tests/*.rs`
//! sibling: a top-level file there would become its own auto-discovered
//! test binary and rebuild the whole harness. `use super::*` names the
//! root's fixtures (`KillOnDrop`, `http`, `wait_ready`, `free_port`,
//! `payload`, `scratch`) exactly as they were named inline.

use super::*;

/// C1 (one-pass encrypted plan, 2026-07-31): a password attached via
/// mode=set_password WHILE the job is still downloading reaches the live
/// run through the hub's late-password cell and unlocks the set in that
/// same run - Completed, unlocked, no password_required parking, no
/// manual retry. Since the probe-window extension (C2 step 1) the unlock
/// normally happens IN-STREAM while the set is still parked; this test
/// pins only the run-level contract, whichever route wins - the one-pass
/// route itself is pinned by set_password_mid_download_goes_one_pass
/// below. Before C1 the download task's start-time copy of j.password
/// was stale forever, so the very password the user had already typed
/// sat unread until the job failed.
#[tokio::test(flavor = "multi_thread")]
async fn set_password_mid_download_unlocks_in_same_run() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-latepw-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Encrypted RAR5 STORE set, no password known at enqueue: every slot's
    // mapper blocks (encrypted entry, no password) and the volumes demote
    // to disk - the exact shape the redditor hit.
    let inner = payload(24_000_003, 8);
    let f = fixtures::encrypt_file("l4tepw", &inner, 5);
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
        let name = format!("lp.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("lp{i}"), &mut articles);
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
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            // ~8 s download window so set_password lands mid-download.
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3");
        c
    })
    .await;
    let port = d.port;

    let inner2 = inner.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Plain filename: NO {{password}} convention, no NZB meta.
        let boundary = "----latepwb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
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

        // Wait for the download to actually start...
        let mut started = false;
        for _ in 0..150 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if q.contains(&id) && q.contains("Downloading") {
                started = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(started, "job never reached Downloading");
        // ...then attach the password mid-flight.
        let r = http(
            port,
            &format!("/api?mode=set_password&value={id}&password=l4tepw&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // The job must complete UNLOCKED in this same run.
        let mut slot = serde_json::Value::Null;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|slots| slots.iter().find(|s| s["nzo_id"] == id.as_str()).cloned())
                && (s["status"] == "Completed" || s["status"] == "Failed") {
                    slot = s;
                    break;
                }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        assert_eq!(
            slot["password_required"], false,
            "late password must unlock in the same run: {slot}"
        );

        // Plaintext on disk, byte-exact; spent volumes swept.
        let out = dir2.join("complete/movie");
        let mkv = std::fs::read(out.join("movie.mkv")).expect("movie.mkv missing");
        assert_eq!(mkv.len(), inner2.len());
        assert!(mkv == inner2, "decrypted payload differs");
        assert!(
            !out.join("lp.part1.rar").exists(),
            "spent volumes must be swept after the unlock"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Any `lp.part*.rar` anywhere under `root` - a demoted volume
/// materializing on disk. The one-pass tests below poll this the whole
/// run: for their shape a sighting at ANY moment means the set demoted
/// (a demoted volume stays on disk until the finish sweep, so a 200ms
/// poll cannot miss it).
fn find_lp_volume(root: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("lp.part"))
            {
                return Some(p);
            }
        }
    }
    None
}

/// C2 step 1 (probe-window extension): a password typed mid-download
/// reaches the slots PARKED by try_pw_await while their bytes are still
/// in RAM - the in-stream probe hook now collects the hub's late-password
/// cell as a structured candidate - so the job goes ONE-PASS. Volumes
/// never materialize on disk (no demote, no C1 unlock-from-disk at
/// finish), and the daemon log carries the in-stream probe's unlock line
/// naming set_password as the source.
#[tokio::test(flavor = "multi_thread")]
async fn set_password_mid_download_goes_one_pass() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-latepw1p-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Same shape as set_password_mid_download_unlocks_in_same_run:
    // encrypted RAR5 STORE set, no password known at enqueue.
    let inner = payload(24_000_003, 8);
    let f = fixtures::encrypt_file("l4tepw", &inner, 5);
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
        let name = format!("lp.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("lp{i}"), &mut articles);
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
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            // ~8 s download window so set_password lands mid-download
            // with most of the set still undownloaded.
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3");
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log_path();

    let inner2 = inner.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Plain filename: NO {{password}} convention, no NZB meta.
        let boundary = "----latepw1pb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
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

        // Wait for actual BYTE progress, not just the Downloading status:
        // the status publishes before the download task captures
        // j.password, and a password landing in that gap is a start-time
        // password (no park, no probe) - exactly what this test must NOT
        // exercise. Bytes on the wire prove the capture already happened.
        let mut started = false;
        for _ in 0..300 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&q)
                .ok()
                .and_then(|v| v["queue"]["slots"].as_array().cloned())
                .and_then(|slots| slots.iter().find(|s| s["nzo_id"] == id.as_str()).cloned())
            {
                let mb: f64 = s["mb"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                let mbleft: f64 = s["mbleft"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                if mb > 0.0 && mbleft < mb - 0.5 {
                    started = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(started, "job never showed download progress");
        let r = http(
            port,
            &format!("/api?mode=set_password&value={id}&password=l4tepw&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // Wait for completion, checking the WHOLE way that no volume
        // ever materializes - the set must stay parked in RAM until the
        // probe re-keys it, then stream one-pass. A volume file at any
        // point means the set demoted and took C1's disk route instead.
        let mut slot = serde_json::Value::Null;
        for _ in 0..300 {
            if let Some(v) = find_lp_volume(&dir2.join("complete")) {
                panic!("set demoted: volume materialized at {}", v.display());
            }
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|slots| slots.iter().find(|s| s["nzo_id"] == id.as_str()).cloned())
                && (s["status"] == "Completed" || s["status"] == "Failed") {
                    slot = s;
                    break;
                }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        assert_eq!(
            slot["password_required"], false,
            "late password must unlock in the same run: {slot}"
        );

        // Plaintext on disk, byte-exact; still no volumes anywhere.
        let out = dir2.join("complete/movie");
        let mkv = std::fs::read(out.join("movie.mkv")).expect("movie.mkv missing");
        assert_eq!(mkv.len(), inner2.len());
        assert!(mkv == inner2, "decrypted payload differs");
        assert!(
            find_lp_volume(&dir2.join("complete")).is_none(),
            "one-pass run must never leave volume files"
        );

        // And the unlock route is the in-stream probe fed by the typed
        // password - not a sidecar harvest, not the finish ladder.
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(
            log.contains("set_password (typed mid-download)"),
            "expected the in-stream probe to credit set_password:\n{log}"
        );
        assert!(log.contains("(in-stream probe)"), "{log}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Wrong-then-right: a wrong password typed mid-download must not burn
/// the corrected one. The probe hook's tried-set is keyed by
/// (salt, value), so the wrong value is remembered per-archive but the
/// correction is a NEW value and gets tested - the set still unlocks
/// in-stream and goes one-pass. (Keying the tried-set by salt alone
/// would skip the correction, demote the set, and fail this test with
/// volumes on disk.)
#[tokio::test(flavor = "multi_thread")]
async fn set_password_wrong_then_right_mid_download_one_pass() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-latepwwr-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(24_000_003, 8);
    let f = fixtures::encrypt_file("l4tepw", &inner, 5);
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
        let name = format!("lp.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("lp{i}"), &mut articles);
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
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3");
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log_path();

    let inner2 = inner.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let boundary = "----latepwwrb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
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

        // Same progress-wait as the one-pass variant: bytes must be
        // flowing before the first password lands, so BOTH passwords go
        // through the probe rather than the start-time capture.
        let mut started = false;
        for _ in 0..300 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&q)
                .ok()
                .and_then(|v| v["queue"]["slots"].as_array().cloned())
                .and_then(|slots| slots.iter().find(|s| s["nzo_id"] == id.as_str()).cloned())
            {
                let mb: f64 = s["mb"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                let mbleft: f64 = s["mbleft"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                if mb > 0.0 && mbleft < mb - 0.5 {
                    started = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(started, "job never showed download progress");

        // The typo first. Two seconds is >2 probe cycles (750ms cadence,
        // spans arriving continuously under the throttle), so the wrong
        // value is genuinely tried and rejected - entering the tried-set
        // under this archive's salt - before the correction lands.
        let r = http(
            port,
            &format!("/api?mode=set_password&value={id}&password=wr0ngpw&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        std::thread::sleep(std::time::Duration::from_secs(2));
        let r = http(
            port,
            &format!("/api?mode=set_password&value={id}&password=l4tepw&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let mut slot = serde_json::Value::Null;
        for _ in 0..300 {
            if let Some(v) = find_lp_volume(&dir2.join("complete")) {
                panic!(
                    "corrected password was skipped and the set demoted: \
                     volume materialized at {}",
                    v.display()
                );
            }
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|slots| slots.iter().find(|s| s["nzo_id"] == id.as_str()).cloned())
                && (s["status"] == "Completed" || s["status"] == "Failed") {
                    slot = s;
                    break;
                }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        assert_eq!(slot["password_required"], false, "{slot}");

        let out = dir2.join("complete/movie");
        let mkv = std::fs::read(out.join("movie.mkv")).expect("movie.mkv missing");
        assert_eq!(mkv.len(), inner2.len());
        assert!(mkv == inner2, "decrypted payload differs");
        assert!(
            find_lp_volume(&dir2.join("complete")).is_none(),
            "one-pass run must never leave volume files"
        );
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(
            log.contains("set_password (typed mid-download)"),
            "expected the in-stream probe to credit set_password:\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The `prefer_external_unrar` setting, applied live over the API (no
/// restart), must hand a NAMED compressed set to the unrar subprocess:
/// the top-level chase latches off (so the set materializes instead of
/// streaming through the native decoder) and the disk unpack skips the
/// native engine. Needs a working `unrar` on PATH; pr-check's Linux leg
/// installs one (TODO 60b), so there the skip below is a broken job
/// rather than reduced coverage, and `NZBFAST_REQUIRE_UNRAR` says so.
/// Everywhere else - Windows CI, a developer box with no unrar - it
/// still skips.
///
/// It is also the end-to-end guard on the free-space preflight that now
/// sits in front of that spawn (`rarfix::preflight`). The preflight's
/// dangerous direction is over-refusal - it reads a size the POSTER
/// declared, and a legitimate release declares a real and large one - so
/// this asserts the refusal did not fire on a set that fits. The other
/// direction is driven by `daemon_bomb` next door, which tells the
/// daemon what the disk holds (`NZBFAST_TEST_FREE_BYTES`, TODO 222)
/// instead of needing the sparse-image rig the 22 Aug repro used; the
/// predicate itself is pinned in `rarfix::preflight`'s own tests.
#[tokio::test(flavor = "multi_thread")]
async fn prefer_external_unrar_setting_routes_unpack_to_subprocess() {
    let have = |c: &str| {
        std::env::var_os("PATH").is_some_and(|p| {
            std::env::split_paths(&p)
                .any(|d| d.join(c).is_file() || d.join(format!("{c}.exe")).is_file())
        })
    };
    if !have("unrar") {
        // The par2 rule (`have_par2` in e2e.rs), for the same reason: a
        // silently skipped test reads exactly like a green run, and this
        // one skipped on EVERY runner for three weeks.
        assert!(
            std::env::var_os("NZBFAST_REQUIRE_UNRAR").is_none(),
            "NZBFAST_REQUIRE_UNRAR is set but no unrar is on PATH - the job \
             that sets it installs one, so this is a broken runner, not a \
             test with nothing to prove"
        );
        eprintln!("skipping: unrar not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-extunrar-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Real WinRAR m3 fixture: compressed, so it can never one-pass as a
    // store set - with the chase latched off it must reach the disk path.
    let arch = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/rars/tests/fixtures/rar50/m3_default.rar"),
    )
    .unwrap();
    let mut articles = HashMap::new();
    let segs = make_file_articles("c.rar", &arch, 4000, "xu", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;c.rar&quot; yEnc (1/3)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log_path();

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Flip the setting over the API - the whole point is that it
        // applies to the job added next, with no daemon restart.
        let r = http(
            port,
            "/api?mode=config&name=prefer_external_unrar&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(!r.contains("error"), "setting rejected: {r}");
        let r = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(
            r.contains("\"prefer_external_unrar\":true"),
            "get_config does not echo the setting: {r}"
        );

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"compressed.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("\"status\":true"), "{r}");

        let mut done = false;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            assert!(!h.contains("\"Failed\""), "job failed:\n{h}");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(done, "download never completed\n--- daemon log ---\n{log}");

        // The routing proof: the subprocess ran, the native engine did not.
        assert!(
            log.contains("unpacking archive with unrar"),
            "unrar subprocess never chosen:\n{log}"
        );
        assert!(log.contains("unrar complete"), "unrar did not finish:\n{log}");
        assert!(
            !log.contains("unpacking archive natively"),
            "native engine ran despite prefer_external_unrar:\n{log}"
        );
        // And the preflight let it through: this set declares what it
        // really unpacks to, and the disk can hold it.
        assert!(
            !log.contains("decompression bomb"),
            "the free-space preflight refused a set that fits:\n{log}"
        );

        // And the payload it published is really there.
        fn find(dir: &Path, name: &str) -> bool {
            std::fs::read_dir(dir).into_iter().flatten().flatten().any(|e| {
                let p = e.path();
                if p.is_dir() {
                    find(&p, name)
                } else {
                    p.file_name().is_some_and(|n| n == name)
                }
            })
        }
        assert!(
            find(&dir2.join("complete"), "bigtext_64k.bin"),
            "unpacked payload missing:\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The counterpart guarantee: an OBFUSCATED hash-named set ignores
/// `prefer_external_unrar` and unpacks natively - the unrar subprocess
/// derives volume names from the first volume's, which for a hash name
/// names nothing on disk, so the native header-order path is the only
/// one that can unpack this shape. Needs no external tools at all, so
/// it runs everywhere including CI.
#[tokio::test(flavor = "multi_thread")]
async fn prefer_external_unrar_setting_ignored_for_obfuscated_sets() {
    let dir = std::env::temp_dir().join(format!("nzbfast-extunrar-obf-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // The same compressed fixture under a hash name: compressed so the
    // store path demotes it to disk, extensionless so only the
    // obfuscated sniff can claim it there.
    let arch = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/rars/tests/fixtures/rar50/m3_default.rar"),
    )
    .unwrap();
    let mut articles = HashMap::new();
    let segs = make_file_articles("a91f3c0d77b2e4", &arch, 4000, "xo", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"kDjq0 [1/1]\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log_path();

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=prefer_external_unrar&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(!r.contains("error"), "setting rejected: {r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"obf.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("\"status\":true"), "{r}");

        let mut done = false;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            assert!(!h.contains("\"Failed\""), "job failed:\n{h}");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(done, "download never completed\n--- daemon log ---\n{log}");

        // The hash-named set took the native obfuscated path, and the
        // setting never routed it at the subprocess.
        assert!(
            log.contains("obfuscated RAR set"),
            "obfuscated handoff never engaged:\n{log}"
        );
        assert!(
            log.contains("native unpack complete"),
            "native obfuscated unpack did not finish:\n{log}"
        );
        assert!(
            !log.contains("unpacking archive with unrar"),
            "obfuscated set was handed to the unrar subprocess:\n{log}"
        );
        // ...and the same lines are in the ring the dashboard's log
        // pane reads, stamped and tagged. Until 22 Aug 2026 these were
        // println!s: logtee still ringed them, but bare and unfiltered,
        // so `NZBFAST_LOG=extract=info` could not turn them up and the
        // warnings were indistinguishable from progress.
        // UNIX ONLY, and the gate is the point rather than an
        // exclusion. The ring is fed by the tee, and there is no tee on
        // Windows BY DESIGN: `crates/nzbkit/src/logtee.rs` says so in
        // as many words - nothing dup2s the process's own stdio onto a
        // pipe over there, so `RING` is never populated, `active()` is
        // always false, and `mode=log` answers
        // `{"capturing":false,"lines":[]}` however well the extract
        // went. The dashboard pane reads the daemon.log FALLBACK on
        // Windows instead. Ungated, these two asserts asked Windows for
        // a capability it does not have and took the whole
        // `windows-daemon` nightly job red from 23 Aug 2026. The lines
        // themselves are already proven above off the job log, which is
        // the platform-neutral half of this test.
        if cfg!(unix) {
            let ring = http(port, "/api?mode=log&value=2000&apikey=sekrit&output=json", None);
            assert!(
                ring.contains("[extract] unpacking 1 obfuscated RAR set"),
                "stamped [extract] line missing from the log ring:\n{ring}"
            );
            assert!(
                ring.contains("[extract] native unpack complete"),
                "stamped [extract] completion missing from the log ring:\n{ring}"
            );
        }

        fn find(dir: &Path, name: &str) -> bool {
            std::fs::read_dir(dir).into_iter().flatten().flatten().any(|e| {
                let p = e.path();
                if p.is_dir() {
                    find(&p, name)
                } else {
                    p.file_name().is_some_and(|n| n == name)
                }
            })
        }
        assert!(
            find(&dir2.join("complete"), "bigtext_64k.bin"),
            "unpacked payload missing:\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
