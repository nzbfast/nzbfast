//! G2 and item 15 (TODO 358) where an *arr reads them: the daemon's
//! history row.
//!
//! - G2: a job whose main payload stayed packed is FAILED with the reason,
//!   never Completed - in the SAB `status` word and in NZBGet's `Status`,
//!   the two strings Sonarr and Radarr act on.
//! - Item 15 (decision D4): NO Partial state. A broken member OUTSIDE
//!   the main payload leaves the job Completed in both protocols, and the
//!   record names it in `not_delivered` (an additive key a client that
//!   does not know it ignores) and in SAB's free-text `script_line`.
//!
//! The CLI half, with the mechanics, is `e2e_g2` in the e2e binary.
//!
//! A child module of the `daemon` test crate root (the daemon_sfx
//! pattern): `use super::*` names the root's fixtures.

use super::*;

/// The vendored compressed RAR5 fixtures `e2e_g2` uses, for the same
/// reason: `m1_fastest` (12,582 bytes) is the main payload and holds
/// `bigtext_64k.bin`; `filter_e8` (891, 7% of it) is the extra, and
/// `m5_max` (9,922, 79%) a set too big to be one - see `e2e_g2`'s
/// constants for the line between them.
fn rar_fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/rars/tests/fixtures/rar50")
            .join(name),
    )
    .unwrap()
}

/// Headers intact, packed data damaged: every engine opens it and the
/// member's CRC fails on the way out.
fn damaged(name: &str) -> Vec<u8> {
    let mut arch = rar_fixture(name);
    let mid = arch.len() / 2;
    for b in &mut arch[mid..mid + 64] {
        *b ^= 0x5a;
    }
    arch
}

/// Post `files` as one NZB to a fresh daemon and return its SAB history
/// slot and NZBGet history row once the job is terminal.
async fn run_job(tag: &str, files: &[(&str, Vec<u8>)]) -> (serde_json::Value, serde_json::Value) {
    let dir = std::env::temp_dir().join(format!("nzbfast-g2-{tag}-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, (name, data)) in files.iter().enumerate() {
        let segs = make_file_articles(name, data, 1500, &format!("g2{i}"), &mut articles);
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
        // The depth-0 chase off, so both compressed sets demote to the
        // disk ladder - the rule under test - exactly as e2e_g2 runs it.
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_NO_TOP_RAR_CHASE", "1")
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
    let name = format!("G2.{tag}.Release");

    tokio::task::spawn_blocking(move || {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{name}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut slot = serde_json::Value::Null;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|s| s.iter().find(|s| s["name"] == name.as_str()).cloned())
                && (s["status"] == "Completed" || s["status"] == "Failed")
            {
                slot = s;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(!slot.is_null(), "the job never reached history");
        // NZBGet's own history call, the second protocol an *arr reads,
        // with the credential in the path the way NZBGet clients send it.
        let ng = http(
            port,
            "/nzbget:sekrit/jsonrpc",
            Some((
                "application/json",
                b"{\"method\":\"history\",\"params\":[false],\"id\":1}".as_slice(),
            )),
        );
        let row = serde_json::from_str::<serde_json::Value>(&ng)
            .ok()
            .and_then(|v| v["result"].as_array().cloned())
            .and_then(|r| r.iter().find(|r| r["Name"] == name.as_str()).cloned())
            .unwrap_or_else(|| panic!("no NZBGet history row for {name}: {ng}"));
        (slot, row)
    })
    .await
    .unwrap()
}

/// Item 15: a good main payload with a broken extra beside it is
/// Completed to SAB and to NZBGet - no Partial state for an *arr to
/// misread - and the record names the extra it did not deliver.
#[tokio::test(flavor = "multi_thread")]
async fn item15_a_broken_extra_completes_and_the_history_names_it() {
    let (slot, ng) = run_job(
        "extra",
        &[
            ("main.rar", rar_fixture("m1_fastest.rar")),
            ("sample.rar", damaged("filter_e8.rar")),
        ],
    )
    .await;
    assert_eq!(slot["status"], "Completed", "{slot}");
    assert_eq!(ng["Status"], "SUCCESS/UNPACK", "{ng}");
    assert_eq!(
        slot["not_delivered"],
        serde_json::json!(["sample"]),
        "{slot}"
    );
    let line = slot["script_line"].as_str().unwrap_or("");
    assert!(
        line.contains("Not delivered") && line.contains("sample"),
        "SAB's free-text slot must name the extra: {slot}"
    );
    assert_eq!(
        slot["fail_message"], "",
        "a Completed row carries no failure: {slot}"
    );
}

/// G2: the inverse. A broken main payload beside a good extra is FAILED
/// with the reason in both protocols, so an *arr blocklists and
/// re-grabs instead of importing a sample and stopping.
#[tokio::test(flavor = "multi_thread")]
async fn g2_a_broken_main_payload_beside_a_good_extra_is_failed() {
    let (slot, ng) = run_job(
        "main",
        &[
            ("main.rar", damaged("m1_fastest.rar")),
            ("sample.rar", rar_fixture("m5_max.rar")),
        ],
    )
    .await;
    assert_eq!(slot["status"], "Failed", "{slot}");
    assert!(
        ng["Status"].as_str().unwrap_or("").starts_with("FAILURE/"),
        "NZBGet must report a failure: {ng}"
    );
    let msg = slot["fail_message"].as_str().unwrap_or("");
    assert!(
        msg.contains("the main payload could not be unpacked: main"),
        "the failure must name the main payload: {slot}"
    );
    assert_eq!(
        slot["not_delivered"],
        serde_json::json!([]),
        "a Failed row publishes no not-delivered list: {slot}"
    );
}
