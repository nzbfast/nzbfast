//! The longitudinal per-provider quality ledger, end to end: two jobs
//! against one mock provider - one clean, one whose articles the
//! provider 430s - and the aggregates the dashboard reads out of
//! `mode=usage`.
//!
//! A sibling-dir child of daemon.rs (the daemon_chip6 pattern) so the
//! parent stays inside its size-gate baseline; harness via `super::*`.
//!
//! WHAT THIS PROVES THAT THE UNIT TESTS DO NOT. `provquality_tests.rs`
//! drives `record` and `report` directly and pins every join; nothing
//! there says the daemon ever CALLS them, that the figures it hands
//! them are the pool's real counters rather than zeroes, that the fold
//! happens where the outcome is known, or that any of it reaches the
//! API. Each of those is a whole feature failing silently - the page
//! would render an empty section and every other gate would stay green.

use super::*;

/// Both jobs in one daemon, so the day bucket, the provider row and the
/// outcome counters are all the SAME record being added to twice.
///
/// The clean job runs first and the dead one second, deliberately: the
/// dead one's articles are refused by the provider, and a ledger that
/// simply overwrote rather than accumulated would then report the clean
/// job's bytes as zero. Reversing them would let that defect pass.
#[tokio::test(flavor = "multi_thread")]
async fn two_jobs_accumulate_into_one_provider_quality_ledger() {
    let dir = std::env::temp_dir().join(format!("nzbfast-provquality-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let good = make_file_articles("good.bin", &payload(40_000, 7), 20_000, "ok", &mut articles);
    let dead = make_file_articles(
        "dead.bin",
        &payload(40_000, 11),
        20_000,
        "gone",
        &mut articles,
    );
    // Only the second file's articles are refused, so ONE provider row
    // carries both a delivered and a missing count and the miss rate it
    // reports is a real fraction rather than 0% or 100%.
    let missing: std::collections::HashSet<String> =
        dead.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let srv = MockServer::start(
        articles,
        Chaos {
            missing,
            ..Default::default()
        },
    )
    .await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Ten days old, which is `nzbkit::oracle::age_bucket` 2 ("7-30d").
    // A definite date and not "now": bucket 0 is also what an UNDATED
    // post would look like if the daemon ever confused the two, and
    // `Hub::post_unix` is explicit that it must not.
    let date = now - 10 * 86_400;
    let nzb = |name: &str, segs: &[(String, u64, u32)]| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"{date}\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
    let good_xml = nzb("good.bin", &good);
    let dead_xml = nzb("dead.bin", &dead);

    let cfg = dir.join("config.json");
    // The config this daemon runs against is WRITTEN here, before the
    // daemon starts: without one, `Config::load` falls back to whatever
    // SABnzbd install the box happens to have in $HOME, and the test
    // then measures the developer's machine (tools/host-config-gate.py).
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let host = srv.addr.ip().to_string();
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
    let spool = dir.join(".spool");

    let quality = tokio::task::spawn_blocking(move || {
        let quality_now = || -> serde_json::Value {
            let r = http(port, "/api?mode=usage&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_default();
            v["quality"].clone()
        };
        // Before anything has finished the section has nothing to show,
        // and must say so with an empty ledger rather than with figures
        // invented out of an empty file.
        let q0 = quality_now();
        assert_eq!(q0["jobs"]["total"], 0, "{q0}");
        assert!(
            q0["providers"].as_array().is_some_and(|a| a.is_empty()),
            "{q0}"
        );

        // Job one: every article is there, so it completes.
        let good_id = upload_nzb(port, &good_xml, "good.nzb");
        // Job two: every article 430s, so it fails. Both are settled
        // through the post-processing lane, which is where the fold is.
        let dead_id = upload_nzb(port, &dead_xml, "dead.nzb");

        let t = std::time::Instant::now();
        let mut q = serde_json::Value::Null;
        while t.elapsed() < std::time::Duration::from_secs(180) {
            let h = http(port, "/api?mode=history&output=json", None);
            if history_has(&h, &good_id) && history_has(&h, &dead_id) {
                q = quality_now();
                if q["jobs"]["total"] == 2 {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        let h = http(port, "/api?mode=history&output=json", None);
        assert_eq!(
            history_slot(&h, &good_id)["status"],
            "Completed",
            "the clean job did not complete: {h}"
        );
        assert_eq!(
            history_slot(&h, &dead_id)["status"],
            "Failed",
            "the dead job did not fail: {h}"
        );
        q
    })
    .await
    .expect("blocking body");

    // Both jobs, each in its own outcome counter. `total` is the whole
    // assertion's anchor: a fold that ran twice for one job, or once for
    // two, shows here and nowhere else.
    assert_eq!(quality["jobs"]["total"], 2, "{quality}");
    assert_eq!(quality["jobs"]["completed"], 1, "{quality}");
    assert_eq!(quality["jobs"]["failed"], 1, "{quality}");
    // One backbone in play and one job that failed: the shortfall join
    // fires, and it is the sentence the whole feature exists to produce.
    assert_eq!(quality["jobs"]["short_no_second"], 1, "{quality}");
    // ...and nothing was rescued by a second network, because there was
    // only ever one provider. A join that fires here would be firing on
    // a provider paired with itself.
    assert_eq!(quality["jobs"]["saved_by_second"], 0, "{quality}");
    assert_eq!(quality["days"], 30, "{quality}");

    let rows = quality["providers"].as_array().expect("providers");
    assert_eq!(rows.len(), 1, "one configured provider: {quality}");
    let p = &rows[0];
    assert_eq!(p["host"], host, "{p}");
    // The counters are the POOL's own, so they must be non-zero on both
    // sides: articles were asked for, and some of them were refused.
    // Ranges rather than exact figures, because a retry and a duplicate
    // race each count as a try and the ladder's shape is not this
    // test's subject.
    assert!(
        p["tried"].as_u64().unwrap_or(0) >= 4,
        "no article tries recorded: {p}"
    );
    assert!(
        p["missing"].as_u64().unwrap_or(0) >= 2,
        "the refused articles were not recorded: {p}"
    );
    assert!(
        p["bytes"].as_u64().unwrap_or(0) > 0,
        "the delivered bytes were not recorded: {p}"
    );
    assert_eq!(p["jobs"], 2, "both jobs reached this provider: {p}");
    // The post date reached the ledger, and landed in the bucket the
    // shared `age_bucket` puts a ten-day-old post in. This is the half
    // that makes "worse on old posts" answerable at all, and it is
    // carried on a different path from the counters above.
    let ages = p["age"].as_array().expect("age ladder");
    assert_eq!(ages.len(), 1, "one post age in play: {p}");
    assert_eq!(ages[0]["key"], "2", "{p}");
    assert_eq!(ages[0]["label"], "7-30d", "{p}");
    assert_eq!(ages[0]["jobs"], 2, "{p}");

    // It is a LEDGER, so it is on disk: a report that only ever lived in
    // this process would answer every question here and lose the month
    // at the next restart, which is the whole point of the file.
    let text = std::fs::read_to_string(spool.join("provquality.json"))
        .expect("the ledger was never persisted");
    let stored: serde_json::Value = serde_json::from_str(&text).expect("valid ledger json");
    let days = stored["days"].as_object().expect("day buckets");
    assert_eq!(days.len(), 1, "one day: {text}");
    let day = days.values().next().unwrap();
    assert_eq!(day["jobs"]["total"], 2, "{text}");
    assert_eq!(day["hosts"][&host]["age"]["2"]["jobs"], 2, "{text}");

    d.stop();
}
