//! Retention insurance, measured as the fault-injected decay A/B.
//!
//! Articles get taken down; a post promoted next week completes worse
//! than the same post banked today. Arm A is the deferred row of today:
//! added paused with the feature OFF, fetched only at promote time -
//! and by then the post is gone, so it fails. Arm B is the insurance
//! row: added paused with `insurance_cap_gb` on, its payload banked in
//! the background while the articles were alive - so the SAME takedown
//! costs it nothing and the promote-time run completes from disk,
//! extraction included. Both arms ride one daemon, one mock server and
//! one takedown ([`MockServer::take_down`]), and every figure is
//! printed, per the house rule that a test PRINTS the number or it does
//! not ship.
//!
//! The not-hinder half is its own test: with the setting off (the
//! default), a paused row puts NOTHING on the wire - zero BODY
//! requests, zero payload bytes - byte-identical to a daemon without
//! the feature.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.

use super::*;

/// A real WinRAR compressed volume (one 64 KB member, bigtext_64k.bin),
/// posted under `name`. Compressed on purpose, same reasoning as
/// daemon_bomb/daemon_retry: a stored set extracts in-stream, while a
/// compressed one goes to the DISK ladder - which is exactly the
/// promote-time path this suite exists to prove (the banked volumes on
/// disk are what the promotion run extracts from).
fn fixture_nzb(name: &str, tag: &str, articles: &mut HashMap<String, Vec<u8>>) -> (String, usize) {
    let bytes = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/rars/tests/fixtures/rar50/m3_default.rar"),
    )
    .expect("m3_default.rar fixture");
    let segs = make_file_articles(&format!("{name}.rar"), &bytes, 1_500, tag, articles);
    let n = segs.len();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}.rar&quot; yEnc (1/{n})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    ));
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    (xml, n)
}

fn upload_paused(port: u16, fname: &str, xml: &str) -> String {
    let boundary = "----insurance";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=addfile&priority=-2&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "{r}");
    r.split("SABnzbd_nzo_")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| format!("SABnzbd_nzo_{s}"))
        .expect("addfile returned no nzo_id")
}

fn history_status(port: u16, id: &str) -> Option<String> {
    let h = http(port, "/api?mode=history&output=json", None);
    let slot = history_slot(&h, id);
    slot["status"].as_str().map(str::to_string)
}

/// NOT-HINDER: with the feature off (the default), an add-paused row
/// fetches NOTHING - zero payload requests, zero payload bytes on the
/// wire. This is the arm that proves the default is byte-identical to
/// a daemon without the feature.
#[tokio::test(flavor = "multi_thread")]
async fn insurance_off_a_paused_row_fetches_nothing() {
    let dir = std::env::temp_dir().join(format!("nzbfast-insoff-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let (xml, _) = fixture_nzb("Not.Hinder.Row", "insoff", &mut articles);
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
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let served = srv.served.clone();
    let bytes_out = srv.bytes_out.clone();
    tokio::task::spawn_blocking(move || {
        let id = upload_paused(port, "nothinder.nzb", &xml);
        let q = http(port, "/api?mode=queue&output=json", None);
        assert_eq!(queue_slot(&q, &id)["status"], "Paused", "{q}");
        // Give the runner several pick cycles (it polls every 500 ms) to
        // do the wrong thing before reading the wire.
        std::thread::sleep(std::time::Duration::from_secs(4));
        let bodies = served.load(std::sync::atomic::Ordering::Relaxed);
        let wire = bytes_out.load(std::sync::atomic::Ordering::Relaxed);
        println!(
            "not-hinder (insurance off, the default): a paused row cost \
             {bodies} served payload article(s) and {wire} payload byte(s) on the wire"
        );
        assert_eq!(bodies, 0, "a paused row must fetch nothing by default");
        assert_eq!(
            wire, 0,
            "a paused row must put no payload bytes on the wire"
        );
        // ...and it is still exactly where the user left it.
        let q = http(port, "/api?mode=queue&output=json", None);
        assert_eq!(queue_slot(&q, &id)["status"], "Paused", "{q}");
    })
    .await
    .unwrap();
}

/// The decay A/B. One takedown, two deferred rows: the banked one
/// completes from disk, the unbanked one dies with the post.
#[tokio::test(flavor = "multi_thread")]
async fn banked_row_survives_the_takedown_the_deferred_row_does_not() {
    let dir = std::env::temp_dir().join(format!("nzbfast-insab-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    // Two independent posts of the same shape - no shared article, and
    // neither stem derives a dupe_key, so the duplicate ladder is out of
    // the picture on both.
    let (xml_a, n_a) = fixture_nzb("Arm.A.Promoted.After.Decay", "insa", &mut articles);
    let (xml_b, n_b) = fixture_nzb("Arm.B.Banked.Before.Decay", "insb", &mut articles);
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
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let counts = {
        let srv_counts = srv.served.clone();
        move || srv_counts.load(std::sync::atomic::Ordering::Relaxed)
    };
    let take_down = {
        // Owned handles so the blocking closure below can drive the
        // takedown without borrowing the server.
        let srv = std::sync::Arc::new(srv);
        let s = srv.clone();
        move || s.take_down()
    };

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Arm A lands while the feature is OFF, so it is a plain
        // deferred row: nothing may fetch it until promotion.
        let id_a = upload_paused(port, "arma.nzb", &xml_a);

        // Feature ON, then arm B lands - the add-time stamp makes it an
        // insurance row and the idle runner banks it.
        let r = http(
            port,
            "/api?mode=config&name=insurance_cap_gb&value=10&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id_b = upload_paused(port, "armb.nzb", &xml_b);

        // The bank: every one of arm B's articles served, and the row
        // back in the queue, still Paused, nothing in history.
        let banked = |q: &str| {
            let slot = queue_slot(q, &id_b);
            slot["status"] == "Paused" && counts() >= n_b as u64
        };
        let mut ok = false;
        for _ in 0..300 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if banked(&q) {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(ok, "arm B was never banked: {q}");
        // TODO 304 stage 2: and the row SAYS which of the two it is.
        // These two rows are one setting apart and mean opposite things
        // - arm B's payload is on disk, arm A's is still only on Usenet
        // - and until this key existed both read "Paused" at the same
        // percentage, with nothing anywhere to tell them apart.
        let b_slot = queue_slot(&q, &id_b);
        assert_eq!(b_slot["insurance"]["banked"], true, "{q}");
        assert_eq!(b_slot["insurance"]["retired"], false, "{q}");
        assert!(
            queue_slot(&q, &id_a)["insurance"].is_null(),
            "arm A was stamped before the feature came on: {q}"
        );
        assert!(
            history_status(port, &id_b).is_none(),
            "banking must not file the row"
        );
        let banked_bodies = counts();
        println!(
            "arm B banked in the background: {banked_bodies} payload article(s) served \
             of a {n_b}-article post, row still Paused in the queue"
        );
        // Arm A (stamped before the feature came on) must not have been
        // touched: everything served so far is arm B's.
        assert!(
            banked_bodies <= (n_b as u64) * 2,
            "only arm B may have been fetched: {banked_bodies} requests"
        );

        // THE DECAY: the whole spool goes, as a takedown sweep would.
        let removed = take_down();
        println!("takedown: {removed} article(s) removed from the mock spool");
        assert!(removed > 0);
        let at_takedown = counts();

        // Promote arm B: it must complete FROM DISK - the wire has
        // nothing left for it.
        let r = http(
            port,
            &format!("/api?mode=queue&name=resume&value={id_b}&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let mut b_status = None;
        for _ in 0..300 {
            b_status = history_status(port, &id_b);
            if matches!(b_status.as_deref(), Some("Completed") | Some("Failed")) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let b_extra = counts() - at_takedown;
        println!(
            "arm B promoted after the takedown: {} with {b_extra} payload \
             article(s) served after the decay",
            b_status.as_deref().unwrap_or("(never terminal)")
        );
        assert_eq!(
            b_status.as_deref(),
            Some("Completed"),
            "the banked row must complete from disk"
        );
        assert_eq!(b_extra, 0, "a banked promotion needs nothing from the wire");
        // ...and the promotion really extracted: the member is at the
        // destination.
        let extracted = walkdir(&dir2.join("complete"))
            .into_iter()
            .any(|p| p.file_name().is_some_and(|f| f == "bigtext_64k.bin"));
        assert!(
            extracted,
            "the banked volumes were not extracted at promotion"
        );

        // Promote arm A: same post, same takedown, no bank - it dies.
        let a_before = counts();
        let r = http(
            port,
            &format!("/api?mode=queue&name=resume&value={id_a}&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let mut a_status = None;
        for _ in 0..300 {
            a_status = history_status(port, &id_a);
            if matches!(a_status.as_deref(), Some("Completed") | Some("Failed")) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        println!(
            "arm A promoted after the takedown: {} with {} payload article(s) \
             served - the whole {n_a}-article post refused as 430",
            a_status.as_deref().unwrap_or("(never terminal)"),
            counts() - a_before,
        );
        assert_eq!(
            a_status.as_deref(),
            Some("Failed"),
            "the unbanked row cannot survive the takedown"
        );
    })
    .await
    .unwrap();
}

/// Every file under `root`, recursively.
fn walkdir(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&p) else {
            continue;
        };
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}
