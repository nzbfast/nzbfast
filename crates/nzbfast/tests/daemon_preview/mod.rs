//! §303 grab-time preview: `mode=nzb_preview` answers the §294
//! completable verdict over POSTed bytes with nothing enqueued. A
//! sibling-dir child of daemon.rs (the daemon_chip6 pattern) so the
//! parent stays inside its size-gate baseline; harness via `super::*`.

use super::*;

fn nzb_for(date: i64, segs: &[(String, u64, u32)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"{date}\" subject=\"&quot;half.bin&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

fn post_preview(port: u16, xml: &str) -> serde_json::Value {
    let boundary = "----pvck";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"nzbfile\"; filename=\"p.nzb\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=nzb_preview&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    serde_json::from_str(&r).unwrap_or_default()
}

/// §303's A/B, in vivo, and the test PRINTS the number. One half-gone
/// post (30 days old, no PAR2, half its articles 430 everywhere - a
/// doomed shape §294 separates from repairable):
///
/// * Arm B, previewed at add: the verdict arrives (`completable:
///   "no"`), NOTHING joins the queue, and the provider served ZERO
///   payload bytes for it - the whole answer cost STATs.
/// * Arm A, grabbed blind: the same post added and downloaded spends
///   real payload bytes before the terminal verdict lands in history.
///
/// Plus the two guards that make the preview honest: a second ask
/// answers from the cache without new provider traffic, and a post
/// YOUNG enough that propagation explains its absences carries the
/// AMBER bucket beside the age-blind projection - the wire pair the
/// dialog's S4 discipline (soft wording below the propagation window)
/// stands on, exercised through the preview road where posts are at
/// their freshest.
#[tokio::test(flavor = "multi_thread")]
async fn preview_beats_the_blind_grab_and_enqueues_nothing() {
    let dir = std::env::temp_dir().join(format!("nzbfast-preview-ab-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // 40 segments, every odd one missing: deterministic 50% loss, so
    // the first burst is red every run and the escalation always arms.
    let mut articles = HashMap::new();
    let segs = make_file_articles(
        "half.bin",
        &payload(800_000, 41),
        20_000,
        "pv",
        &mut articles,
    );
    assert!(segs.len() >= 30, "{} segments", segs.len());
    let missing: std::collections::HashSet<String> = segs
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, (id, _, _))| format!("<{id}>"))
        .collect();
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
    // 30 days: past GONE_MIN_AGE_DAYS, so the joint verdict may reach
    // `no` at all.
    let xml = nzb_for(now - 30 * 86_400, &segs);

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
    let served = srv.served.clone();
    let bytes_out = srv.bytes_out.clone();
    let stats = srv.stats.clone();

    tokio::task::spawn_blocking(move || {
        // ARM B: the preview. The daemon is idle - nothing queued.
        let j = post_preview(port, &xml);
        assert_eq!(j["status"], true, "{j}");
        assert_eq!(j["checked"], true, "the idle daemon must check: {j}");
        let h = &j["health"];
        assert_eq!(
            h["completable"], "no",
            "half the articles gone against zero declared recovery: {h}"
        );
        assert!(
            h["absent"].as_u64().unwrap_or(0) > 0,
            "the verdict must rest on real sampled loss: {h}"
        );
        let b_served = served.load(std::sync::atomic::Ordering::Relaxed);
        let b_bytes = bytes_out.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(b_served, 0, "a preview must never fetch payload");
        assert_eq!(b_bytes, 0, "a preview must never spend payload bytes");
        let q = http(port, "/api?mode=queue&output=json", None);
        let qv: serde_json::Value = serde_json::from_str(&q).unwrap_or_default();
        assert_eq!(
            qv["queue"]["slots"].as_array().map_or(usize::MAX, Vec::len),
            0,
            "a preview must enqueue nothing: {q}"
        );

        // The cache: the same post asked again answers without one more
        // provider round trip.
        let s1 = stats.load(std::sync::atomic::Ordering::Relaxed);
        let j2 = post_preview(port, &xml);
        assert_eq!(
            j2["cached"], true,
            "the second ask must hit the cache: {j2}"
        );
        assert_eq!(
            stats.load(std::sync::atomic::Ordering::Relaxed),
            s1,
            "a cached answer must cost zero STATs"
        );

        // The S4 discipline through the same road: identical absence
        // evidence on a post dated NOW answers the AMBER bucket beside
        // the age-blind projection - the pair the dialog keys its
        // wording off (a "no" on amber gets the soft sentence, exactly
        // as altcand::terminal_reason refuses the offer below the
        // propagation window). Pinning both halves of the wire is what
        // keeps that client-side gate honest.
        let young: Vec<(String, u64, u32)> = (1..=10u32)
            .map(|n| (format!("pvghost{n}@x"), 20_000u64, n))
            .collect();
        let jy = post_preview(port, &nzb_for(now, &young));
        assert_eq!(jy["checked"], true, "{jy}");
        assert_eq!(
            jy["health"]["bucket"], "amber",
            "absence on a fresh post is a warning, not a verdict: {jy}"
        );
        assert_eq!(
            jy["health"]["completable"], "no",
            "the projection itself is deliberately age-blind on the wire: {jy}"
        );

        // ARM A: the same doomed post grabbed blind. It downloads, and
        // the bytes are spent before the terminal verdict exists.
        let id = upload_nzb(port, &xml, "half.nzb");
        let mut hist = serde_json::Value::Null;
        for _ in 0..600 {
            let hs = http(port, "/api?mode=history&output=json", None);
            hist = history_slot(&hs, &id);
            if hist["status"] == "Failed" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(
            hist["status"], "Failed",
            "the blind grab must reach its terminal verdict: {hist}"
        );
        let a_served = served.load(std::sync::atomic::Ordering::Relaxed);
        let a_bytes = bytes_out.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            a_served > 0,
            "the blind grab must have fetched payload before failing"
        );
        println!(
            "§303 A/B over one doomed post: grabbed blind, the provider served \
             {a_served} payload article(s) ({a_bytes} bytes) before the terminal \
             verdict; previewed at add, it served 0 articles (0 bytes), the \
             verdict was `no`, and nothing joined the queue."
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The not-hinder half, §77's rule at add time: while a download is
/// using the account's connections the preview answers "not checked"
/// QUICKLY and opens no probe connection, and the add path itself never
/// waits on a probe - the busy answer and a successful addfile both
/// land while the download is still running.
#[tokio::test(flavor = "multi_thread")]
async fn preview_stands_down_while_a_download_runs() {
    let dir = std::env::temp_dir().join(format!("nzbfast-preview-busy-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // A download slow enough to still be running when the preview asks:
    // per-connection throttle holds the transfer open for ~10 s however
    // many sockets the engine opens (2 MB at 40 KB/s/conn).
    let mut articles = HashMap::new();
    let segs = make_file_articles(
        "slow.bin",
        &payload(2_000_000, 42),
        50_000,
        "sl",
        &mut articles,
    );
    let srv = MockServer::start(
        articles,
        Chaos {
            throttle: nzbkit::mock::Throttle {
                line_bps: 200_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let slow_xml = nzb_for(now - 30 * 86_400, &segs);
    // The post the preview asks about: ids the server has never seen.
    let ghost: Vec<(String, u64, u32)> = (1..=10u32)
        .map(|n| (format!("busyghost{n}@x"), 20_000u64, n))
        .collect();
    let ghost_xml = nzb_for(now - 30 * 86_400, &ghost);

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
        let id = upload_nzb(port, &slow_xml, "slow.nzb");
        // Wait for the wire to actually be busy.
        let mut downloading = false;
        for _ in 0..300 {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap_or_default();
            let st = v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or_default()["status"]
                .clone();
            if st == "Downloading" || st == "Fetching" {
                downloading = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(downloading, "the slow job never started");

        // The preview, mid-download: a fast "not checked", never a
        // probe. The elapsed bound is the claim that the add dialog is
        // answered immediately rather than parked behind a 20 s STAT
        // window it is not allowed to open.
        let t0 = std::time::Instant::now();
        let j = post_preview(port, &ghost_xml);
        let took = t0.elapsed();
        assert_eq!(j["status"], true, "{j}");
        assert_eq!(
            j["checked"], false,
            "the connections belong to the running job: {j}"
        );
        assert_eq!(j["reason"], "downloading", "{j}");
        assert!(
            took < std::time::Duration::from_secs(5),
            "the busy answer must be immediate, took {took:?}"
        );

        // And the ADD path is untouched while the same download runs: a
        // second addfile lands immediately, never waiting on any probe.
        let t1 = std::time::Instant::now();
        let id2 = upload_nzb(port, &ghost_xml, "second.nzb");
        assert!(
            t1.elapsed() < std::time::Duration::from_secs(5),
            "addfile must never wait on a probe, took {:?}",
            t1.elapsed()
        );
        assert!(!id2.is_empty());
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
