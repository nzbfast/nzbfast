//! TODO §282 items 18 and 19: the UNATTENDED half of the
//! alternate-candidate feature - the event that tells somebody who is
//! not looking at the dashboard that a switch happened, and the shipped
//! defaults that make a switch happen at all.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//!
//! NOT in `daemon_hooks/`, which is where the chip that asked for this
//! pointed: that file is `#![cfg(unix)]`, because its subject is
//! pre-queue SHELL hooks. Nothing here is platform-specific - the
//! promote path and the ring are the same code on Windows - and burying
//! these two tests under that gate would have dropped Windows coverage
//! of a default that ships ON.
//!
//! `duplicate_held_then_promoted` came here from `daemon.rs` in the same
//! commit: it is the M14f promote path's own end-to-end test, so the
//! three now sit together, and daemon.rs was at its size-gate baseline
//! to the line - a sibling child that adds a `mod` line and moves
//! nothing out is not something that file has room for.

use super::*;

/// §282 item 19: the shipped defaults, read back off a real daemon.
///
/// This asks the question through `mode=get_config`, not through
/// `AltSettings::default()`, ON PURPOSE. A default is only shipped if
/// it survives the whole boot - the struct's `Default`, the constructor
/// in `serve/startup.rs`, and `apply_saved_settings` not stamping
/// something else over it on the way past. A unit test on the struct
/// would pass with any of those three broken.
///
/// The three values are not three tastes, they are one argument:
/// promoting a spare we already hold spends no new bytes, hunting does,
/// and an ON switch with a ZERO hold count has nothing to promote and
/// would ship a default that reads as a feature and behaves as today.
/// So the hold count is asserted NON-ZERO rather than equal to 2 - the
/// number is tunable, the non-zero-ness is the decision.
#[tokio::test(flavor = "multi_thread")]
async fn the_shipped_alternate_defaults_are_switch_on_search_off_and_a_real_hold_count() {
    let dir = std::env::temp_dir().join(format!("nzbfast-altdef-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
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
        let raw = http(port, "/api?mode=get_config&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap_or_else(|e| {
            panic!("mode=get_config did not parse ({e}): {raw}");
        });
        let cfg = &v["config"]["nzbfast"];
        assert_eq!(
            cfg["alt_auto_switch"], true,
            "alt_auto_switch must ship ON - a held spare costs no new bytes: {raw}"
        );
        assert_eq!(
            cfg["alt_auto_search"], false,
            "alt_auto_search must ship OFF - a hunt spends bytes nobody asked for: {raw}"
        );
        let held = cfg["alt_hold_count"]
            .as_u64()
            .unwrap_or_else(|| panic!("alt_hold_count is not a number: {raw}"));
        assert!(
            held > 0,
            "alt_hold_count must ship NON-ZERO or auto-switch has nothing to promote: {raw}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// §282 item 18: promoting a held alternate says so on the lifecycle
/// ring, so the away case is told.
///
/// The shape is `daemon.rs`'s `duplicate_held_then_promoted` - a 720p
/// "original" of ghost segments that must fail, a 1080p duplicate held
/// against it, and a short M32 cooldown so the retry is spent inside the
/// test's own lifetime - but the assertion is the EVENT rather than the
/// completion. `job.switched` is a plain dotted `job.*` kind, so a
/// webhook target subscribed to `job.*` receives it with no
/// configuration at all; that is the whole of what "register it the way
/// the existing keys are registered" buys.
///
/// Every key is asserted, because the payload IS the feature: an
/// operator reading this event off a webhook has to be able to answer
/// "what did nzbfast abandon, what is it downloading instead, and why"
/// without going back to the dashboard the event exists to replace.
#[tokio::test(flavor = "multi_thread")]
async fn promoting_a_held_alternate_announces_the_switch_on_the_ring() {
    let dir = std::env::temp_dir().join(format!("nzbfast-altsw-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(120_000, 23);
    let mut articles = HashMap::new();
    let segs = make_file_articles("ep.bin", &data, 40_000, "as", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let wrap = |inner: &str| {
        format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
             <file poster=\"x\" date=\"0\" subject=\"&quot;ep.bin&quot; yEnc (1/9)\">\n    \
             <groups><group>g</group></groups>\n    <segments>\n{inner}    </segments>\n  \
             </file>\n</nzb>\n"
        )
    };
    let seg_xml = |segs: &[(String, u64, u32)]| {
        let mut x = String::new();
        for (id, bytes, num) in segs {
            x.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        x
    };
    let ghost: Vec<(String, u64, u32)> = (1..=3)
        .map(|n| (format!("asghost{n}@x"), 40_000, n))
        .collect();
    let bad_xml = wrap(&seg_xml(&ghost));
    let good_xml = wrap(&seg_xml(&segs));

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
            .env("NZBFAST_AUTO_RETRY_SECS", "5")
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

    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| {
            let boundary = "----altswb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; \
                     filename=\"{fname}\"\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
        };
        // Paused, so both rows are in the queue when the dupe check runs
        // and the second is HELD rather than started beside the first.
        http(port, "/api?mode=pause&output=json", None);
        upload(&bad_xml, "Show.Name.S04E02.720p.WEB.nzb");
        upload(&good_xml, "Show.Name.S04E02.1080p.WEB.nzb");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"Duplicate\""), "the spare was not held: {q}");
        http(port, "/api?mode=resume&output=json", None);

        // The 720p fails, its automatic retry is spent, and THAT failure
        // promotes the 1080p. Poll the ring rather than the queue: the
        // event is the subject, and it is published before the promoted
        // job has done anything a queue read could show.
        let mut found = None;
        for _ in 0..250 {
            let raw = http(port, "/api?mode=dashboard&events=0&output=json", None);
            let v: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    continue;
                }
            };
            if let Some(e) = v["events"]
                .as_array()
                .and_then(|a| a.iter().find(|e| e["kind"] == "job.switched"))
            {
                found = Some(e.clone());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let e = found.expect("no job.switched reached the lifecycle ring");

        // What replaced what. The promoted row must be the 1080p (M14f
        // ranks rather than taking the first held row), and it must name
        // the 720p it replaced - by id AND by name, since the id is
        // opaque to a webhook consumer and the name is what a person
        // reads in a notification.
        assert!(
            e["name"].as_str().unwrap_or_default().contains("1080p"),
            "the switch named the wrong replacement: {e}"
        );
        assert!(
            e["replaces_name"]
                .as_str()
                .unwrap_or_default()
                .contains("720p"),
            "the switch did not name what it abandoned: {e}"
        );
        assert!(
            !e["replaces"].as_str().unwrap_or_default().is_empty(),
            "the switch carried no abandoned nzo_id: {e}"
        );
        assert_ne!(
            e["replaces"], e["nzo_id"],
            "the switch replaced a job with itself: {e}"
        );
        // ...and WHY. The failed job's own fail_message, so the sentence
        // the user would have read on the dashboard travels with the
        // event instead of being left behind on it.
        assert!(
            !e["reason"].as_str().unwrap_or_default().is_empty(),
            "the switch gave no reason: {e}"
        );
        // The ring stamps every event, and a consumer keys on these.
        assert_eq!(e["schema_version"], 1, "{e}");
        assert!(e["seq"].as_u64().unwrap_or(0) > 0, "{e}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M14f: a queued duplicate is held as ALTERNATIVE and auto-promoted
/// when the original fails.
///
/// Moved out of `daemon.rs` 24 Aug 2026 - it is the other half of what
/// the two tests above assert (they check the EVENT and the DEFAULT;
/// this checks the promoted job actually runs and completes), and
/// daemon.rs was at its size-gate baseline to the line.
///
/// "Fails" means FINALLY fails. A first missing-article failure is parked
/// with an M32 automatic retry armed, and promoting the alternative there
/// would download the same title twice in parallel - the retry is about
/// to fetch the very gaps that failed. So this runs with a 5 s cooldown
/// and checks both halves: held while the retry is pending, promoted once
/// it has been spent.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_held_then_promoted() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dupe-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(120_000, 11);
    let mut articles = HashMap::new();
    let segs = make_file_articles("ep.bin", &data, 40_000, "dp", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let seg_xml = |segs: &[(String, u64, u32)]| {
        let mut x = String::new();
        for (id, bytes, num) in segs {
            x.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        x
    };
    let wrap = |inner: &str| {
        format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;ep.bin&quot; yEnc (1/9)\">\n    <groups><group>g</group></groups>\n    <segments>\n{inner}    </segments>\n  </file>\n</nzb>\n"
        )
    };
    let ghost: Vec<(String, u64, u32)> = (1..=3)
        .map(|n| (format!("dghost{n}@x"), 40_000, n))
        .collect();
    let bad_xml = wrap(&seg_xml(&ghost)); // 720p "original" - will fail
    let good_xml = wrap(&seg_xml(&segs)); // 1080p duplicate - must take over

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
            // Short M32 cooldown instead of the 20 min default: the promotion
            // waits for the automatic retry to be spent, and the test needs to
            // see both sides of that within its own lifetime.
            .env("NZBFAST_AUTO_RETRY_SECS", "5")
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

    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| {
            let boundary = "----dupeb";
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
        };
        // Pause so both jobs sit in the queue when the dupe check runs.
        http(port, "/api?mode=pause&output=json", None);
        upload(&bad_xml, "Show.Name.S01E02.720p.WEB.nzb");
        upload(&good_xml, "Show.Name.S01E02.1080p.WEB.nzb");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"Duplicate\""), "{q}");
        assert!(q.contains("show name/s1e2"), "{q}");

        // Resume: 720p fails → 1080p ALTERNATIVE must promote and finish.
        http(port, "/api?mode=resume&output=json", None);

        // FIRST failure: an automatic retry is armed, so the alternative
        // is still held. park decides this synchronously with the history
        // push, so the queue may be read as soon as Failed appears.
        let mut held = false;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Failed\"") {
                let q = http(port, "/api?mode=queue&output=json", None);
                assert!(
                    q.contains("\"Duplicate\""),
                    "promoted while an automatic retry was pending: {q}"
                );
                held = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(held, "the original never failed");

        // The retry runs, fails again (retries == 1, no longer eligible),
        // and THAT failure promotes the alternative.
        let mut ok = false;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Completed\"") && h.contains("\"Failed\"") {
                assert!(h.contains("1080p"), "{h}");
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(ok, "alternative was never promoted/completed");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
