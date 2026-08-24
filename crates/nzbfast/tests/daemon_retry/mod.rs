//! TODO §100: a retry after an unpack-stage failure must not re-download
//! what is already on disk (Gary's 14.87 GB re-fetch, 3 Aug).
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//! It also keeps daemon.rs under the size gate.

use super::*;

/// TODO 100, the PLAIN half: an unpack-stage failure on an UNENCRYPTED
/// set must not cost a refetch either.
///
/// Gary's 14.87 GB re-download was diagnosed as candidate (c) - the
/// encrypted finish-decrypt window, fixed 8 Aug and pinned by
/// `enospc_after_decrypt_publish_retries_without_refetching` in the
/// parent daemon.rs. The other two candidates - (a) "try_unrar_spent
/// failed" and (b) "the extractor's finish propagated a raw io error" -
/// were only ever ruled out by READING the code: every failure path
/// keeps the journal because
/// the single `Journal::remove` sits in `finish_job`, after the whole
/// unpack tail. Nothing exercised that end to end, so the property was
/// standing on a code reading a refactor could quietly break - and it is
/// the property Gary's report is actually about.
///
/// The rig is the (a) shape exactly: `NZBFAST_NO_TOP_RAR_CHASE=1`
/// demotes a genuinely compressed volume to the disk ladder (so the set
/// lands whole on disk, the way it did for him), and the ladder is left
/// with no unpacker at all, so the job fails AFTER a clean, fully
/// journaled download. The retry then has to come off the disk.
///
/// Shutting the ladder takes BOTH switches, one per engine.
/// `NZBFAST_NO_NATIVE_UNRAR=1` sends the disk pass past the vendored
/// rars engine to the subprocess, and `NZBFAST_TEST_FORBID_UNRAR=1`
/// closes the subprocess. Until 22 Aug 2026 the canary alone did it,
/// because it short-circuited `try_unrar_spent` at the top and so closed
/// the native engine as a side effect; it now sits beside the
/// `external_unrar_closed` hatch and means only what it says. This test
/// is the one caller of it anywhere that wanted the whole function shut
/// rather than just the subprocess - drop the first switch and the
/// native engine unpacks `m3_default.rar` on its own, the job finishes
/// Completed, and there is no Failed record to retry.
///
/// Two of the three retry paths are driven here - the dashboard button
/// (`mode=retry`) and the NZBGet facade's `HistoryRetry`, the one an
/// *arr sends unattended. The third, the cooldown ladder
/// (`run_due_auto_retries`), is covered by
/// `auto_retry_fires_once_after_cooldown`. All three are callers of one
/// `Daemon::retry`, which is why the verdict is the same on each.
#[tokio::test(flavor = "multi_thread")]
async fn unpack_failure_retries_without_refetching() {
    let dir = std::env::temp_dir().join(format!("nzbfast-unpackretry-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // A real WinRAR compressed volume - store-mode fixtures extract
    // in-stream and never reach the disk ladder this test is about.
    let arch = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/rars/tests/fixtures/rar50/m3_default.rar"),
    )
    .expect("m3_default.rar fixture");
    let mut articles = HashMap::new();
    let segs = make_file_articles("Unpack.Retry.2026.rar", &arch, 1_500, "ur", &mut articles);
    assert!(
        segs.len() > 4,
        "want a multi-article set, got {}",
        segs.len()
    );
    let srv = MockServer::start(articles, Chaos::default()).await;
    let body_log = srv.body_log.clone();

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;Unpack.Retry.2026.rar&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // Demote the compressed set to the disk ladder...
            .env("NZBFAST_NO_TOP_RAR_CHASE", "1")
            // ...past the native engine...
            .env("NZBFAST_NO_NATIVE_UNRAR", "1")
            // ...and onto a subprocess that refuses, so the job fails at
            // the unpack stage with every volume verified on disk.
            .env("NZBFAST_TEST_FORBID_UNRAR", "1")
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

    let total_articles = segs.len();
    tokio::task::spawn_blocking(move || {
        // Deterministic timeline: this test drives the retry itself, so
        // the cooldown ladder must not fire one first.
        let r = http(
            port,
            "/api?mode=config&name=auto_retry_mins&value=0&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Unpack.Retry.2026.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json",
            Some((&ctype, &body)),
        );
        assert!(r.contains("nzo_ids"), "{r}");

        // A Failed record with `retries` at N. The count is what tells
        // the first failure from the second: the retry keeps the nzo_id
        // and the row comes back looking the same otherwise.
        let failed_at = |retries: u64| -> Option<serde_json::Value> {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|s| {
                    s.iter()
                        .find(|s| {
                            s["name"] == "Unpack.Retry.2026"
                                && s["status"] == "Failed"
                                && s["retries"].as_u64().unwrap_or(0) == retries
                        })
                        .cloned()
                })
        };
        let wait_failed = |retries: u64| -> serde_json::Value {
            for _ in 0..200 {
                if let Some(s) = failed_at(retries) {
                    return s;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!(
                "no Failed record at retries={retries}; history: {}",
                http(port, "/api?mode=history&apikey=sekrit&output=json", None)
            )
        };

        let slot = wait_failed(0);
        assert!(
            slot["fail_message"]
                .as_str()
                .unwrap_or_default()
                .contains("could not be unpacked"),
            "expected the unpack-stage failure, got: {slot}"
        );
        let nzo = slot["nzo_id"].as_str().expect("nzo_id").to_string();
        let failed_dir = PathBuf::from(slot["storage"].as_str().unwrap_or_default());
        // The two halves of the premise, both from Gary's evening: the
        // volume really is on disk, and the journal that describes it
        // survived the unpack-stage failure.
        assert!(
            failed_dir.join("Unpack.Retry.2026.rar").exists(),
            "a failed unpack must leave its volumes: {failed_dir:?}"
        );
        let journal_txt = std::fs::read_to_string(failed_dir.join(".nzbfast.journal"))
            .unwrap_or_else(|e| panic!("no journal at {failed_dir:?}: {e}"));
        let recorded: std::collections::HashSet<String> = journal_txt
            .lines()
            .filter(|l| l.starts_with("D ") || l.starts_with("R "))
            .filter_map(|l| l.rsplit(' ').next().map(str::to_string))
            .collect();
        assert!(
            recorded.len() >= total_articles - 1,
            "the clean download journaled only {} of {total_articles} articles\n--- journal ---\n{journal_txt}",
            recorded.len()
        );

        // The retry. It fails again - the unpacker is still forbidden -
        // which is the point: the assertion is about the NETWORK, not
        // about the job reaching green.
        // `body_log.len()`, NOT `served`: the mock logs an id when the
        // request ARRIVES and increments `served` only once the body is
        // fully written, so a `served` mark indexes `body_log` somewhere
        // INSIDE the previous leg and blames this one for articles it
        // never asked for.
        let asked_before = body_log.lock().unwrap().len();
        let r = http(
            port,
            &format!("/api?mode=retry&value={nzo}&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let slot = wait_failed(1);
        // Same folder, so the same journal and the same volumes: a retry
        // that refiled would have started from zero whatever the journal
        // said.
        assert_eq!(
            slot["storage"].as_str().unwrap_or_default(),
            failed_dir.to_string_lossy(),
            "an ordinary failed retry must reuse its own directory"
        );

        let refetched: Vec<String> = body_log.lock().unwrap()[asked_before..].to_vec();
        // Measured with the journal deleted between the two runs (the
        // positive control this test was built against): the retry then
        // refetches 7 of 7. With it, only the head article - whose bytes
        // are the RAR headers, which live in no output file and so are
        // journaled by nothing - comes back.
        assert!(
            refetched.len() < total_articles,
            "retry refetched the whole set: {refetched:?}\n--- journal ---\n{journal_txt}"
        );
        let leaked: Vec<&String> = refetched.iter().filter(|id| recorded.contains(*id)).collect();
        assert!(
            leaked.is_empty(),
            "journaled articles were re-downloaded by the retry: {leaked:?}\n\
             refetched {} of {total_articles}\n--- journal ---\n{journal_txt}",
            refetched.len()
        );

        // Second leg: the same property through the NZBGet facade's
        // `HistoryRetry`, which is the retry an *arr sends unattended and
        // the one nothing covered. It delegates to the same
        // `Daemon::retry` - measured here rather than left to a grep,
        // because "one implementation" is precisely the claim that would
        // stop being true first.
        let nzbid: u64 = nzo
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
            .parse()
            .unwrap_or_else(|e| panic!("no numeric id in {nzo}: {e}"));
        // `body_log.len()`, NOT `served`: the mock logs an id when the
        // request ARRIVES and increments `served` only once the body is
        // fully written, so a `served` mark indexes `body_log` somewhere
        // INSIDE the previous leg and blames this one for articles it
        // never asked for.
        let asked_before = body_log.lock().unwrap().len();
        let body = format!(
            "{{\"method\":\"editqueue\",\"params\":[\"HistoryRetry\",\"\",[{nzbid}]],\"id\":1}}"
        );
        // The facade authenticates the *arr way - HTTP Basic, any user,
        // the API key as the password (`x:sekrit`) - so this leg cannot
        // go through the `?apikey=` helper.
        let mut request = Vec::new();
        write!(
            request,
            "POST /jsonrpc HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
             Authorization: Basic eDpzZWtyaXQ=\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        request.extend_from_slice(body.as_bytes());
        let r = String::from_utf8_lossy(&raw(port, &request)).to_string();
        assert!(r.contains("true"), "HistoryRetry refused: {r}");
        let slot = wait_failed(2);
        assert_eq!(
            slot["storage"].as_str().unwrap_or_default(),
            failed_dir.to_string_lossy(),
            "the facade retry must reuse the directory too"
        );
        let refetched: Vec<String> = body_log.lock().unwrap()[asked_before..].to_vec();
        let leaked: Vec<&String> = refetched.iter().filter(|id| recorded.contains(*id)).collect();
        assert!(
            leaked.is_empty(),
            "journaled articles were re-downloaded by the facade retry: {leaked:?}\n\
             refetched {} of {total_articles}",
            refetched.len()
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
