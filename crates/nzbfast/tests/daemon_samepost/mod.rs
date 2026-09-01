//! §292: the message-id duplicate arm, measured as an A/B.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//!
//! The A/B this drives: two grabs of the SAME post under different
//! obfuscated names - stems that derive no dupe_key, so the name-keyed
//! ladder is structurally blind to them. Leg B (the §292 arm live) is
//! the first phase: the second grab lands held, and the mock's body
//! ledger shows the post was paid for ONCE. Leg A (the pre-291
//! baseline) is the second phase, measured on the same rig by
//! releasing the hold through the documented escape (the priority
//! raise): the released row downloads in full, exactly what the
//! pre-291 tree did immediately, and the ledger shows the post paid
//! for TWICE. The ratio is printed so the number is in the test log
//! rather than a claim in a comment.

use super::*;

/// Two same-post grabs cost one download while the arm holds the
/// second, and the released hold measures the baseline's 2x on the
/// same rig.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_grab_of_the_same_post_costs_zero_extra_body_requests() {
    let dir = std::env::temp_dir().join(format!("nzbfast-samepost-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let a = make_file_articles(
        "f1.bin",
        &payload(120_000, 31),
        40_000,
        "spa",
        &mut articles,
    );
    let b = make_file_articles(
        "f2.bin",
        &payload(120_000, 37),
        40_000,
        "spb",
        &mut articles,
    );
    let c = make_file_articles(
        "f3.bin",
        &payload(120_000, 41),
        40_000,
        "spc",
        &mut articles,
    );
    let ids_total = (a.len() + b.len() + c.len()) as u64;
    let srv = MockServer::start(articles, Chaos::default()).await;

    // ONE post - both uploads carry the identical files and segments.
    // Only the upload FILENAME differs, and neither stem derives a
    // dupe_key (no SxxEyy, no year), which is the §292 condition.
    let xml = {
        let mut x = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for (file, segs) in [("f1.bin", &a), ("f2.bin", &b), ("f3.bin", &c)] {
            x.push_str(&format!(
                "  <file poster=\"x\" date=\"0\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
                segs.len()
            ));
            for (id, bytes, num) in segs.iter() {
                x.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
                ));
            }
            x.push_str("    </segments>\n  </file>\n");
        }
        x.push_str("</nzb>\n");
        x
    };

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
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let counts = move || -> u64 { srv.serve_counts().values().sum() };

    tokio::task::spawn_blocking(move || {
        let upload = |fname: &str| -> String {
            let boundary = "----spb";
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
            r.split("SABnzbd_nzo_")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .map(|s| format!("SABnzbd_nzo_{s}"))
                .expect("addfile returned no nzo_id")
        };
        let completed = |id: &str| -> bool {
            let h = http(port, "/api?mode=history&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&h).unwrap_or(serde_json::Value::Null);
            v["history"]["slots"].as_array().is_some_and(|s| {
                s.iter()
                    .any(|x| x["nzo_id"] == id && x["status"] == "Completed")
            })
        };

        // Paused, so both grabs are in the queue when the second adds.
        http(port, "/api?mode=pause&output=json", None);
        let first = upload("e4a1b2c3d4f5.nzb");
        let second = upload("f5e6d7c8b9a0.nzb");

        // Leg B, the arm live: the second grab is held exactly as a
        // name-keyed duplicate would be.
        let q = http(port, "/api?mode=queue&output=json", None);
        let held = queue_slot(&q, &second);
        assert!(held_behind_a_copy(&held), "not held: {q}");
        assert_eq!(held["status"], "Paused", "a hold is a pause: {q}");

        http(port, "/api?mode=resume&output=json", None);
        for _ in 0..300 {
            if completed(&first) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(completed(&first), "the first grab never completed");
        let leg_b = counts();
        println!(
            "A/B leg B (§292 live): {leg_b} body requests for 2 grabs of a \
             {ids_total}-article post"
        );
        assert!(
            leg_b >= ids_total && leg_b < 2 * ids_total,
            "held second grab must not have paid for the post again: \
             {leg_b} requests over {ids_total} articles"
        );

        // Leg A, the baseline, on the same rig: release the hold through
        // the documented escape and the row downloads in full - which is
        // what the pre-291 tree did the moment the second grab landed.
        let r = http(
            port,
            &format!("/api?mode=queue&name=priority&value={second}&value2=1&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        for _ in 0..300 {
            if completed(&second) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(completed(&second), "the released hold never downloaded");
        let leg_a = counts();
        println!(
            "A/B leg A (baseline, hold released): {leg_a} body requests - \
             the second copy cost {} more",
            leg_a - leg_b
        );
        assert!(
            leg_a >= 2 * ids_total,
            "the released row downloads the whole post: {leg_a} < {}",
            2 * ids_total
        );
    })
    .await
    .unwrap();
}
