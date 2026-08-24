//! Passworded archives, end to end: what a job does when its payload is
//! encrypted and the password arrives from somewhere other than the NZB.
//!
//! A sibling-dir child of daemon.rs (the daemon_authkey pattern) so the
//! parent stays inside its size-gate baseline - it crossed again when the
//! §99 try-order and §100 retry rounds landed. Declared from daemon.rs, so
//! these still run in that binary against those fixtures; harness via
//! `super::*`.
//!
//! One subject: each leg is a different door the password comes through -
//! `set_password` after the fact, a passwords file consulted at
//! completion, a publish that ran out of disk after the decrypt, and the
//! prompt that must never leave the archive packed on disk.

use super::*;

/// M24 passworded archives, end to end: an encrypted-header RAR
/// completes with password_required flagged in history; set_password
/// attempts an unlock (and reports a wrong password); NZB-meta and
/// "Name{{pw}}" passwords are captured at enqueue.
#[tokio::test(flavor = "multi_thread")]
async fn passworded_archive_flow() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pw-e2e-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Three posts: an encrypted-header rar, and two plain bins for the
    // password-source paths (NZB meta / name convention).
    let locked = nzbkit::rar::fixtures::rar4_encrypted_headers(4096);
    let plain = payload(60_000, 11);
    let mut articles = HashMap::new();
    let lsegs = make_file_articles(
        "Locked.Release.2026.rar",
        &locked,
        40_000,
        "lk",
        &mut articles,
    );
    let msegs = make_file_articles("meta.bin", &plain, 40_000, "mt", &mut articles);
    let nsegs = make_file_articles("named.bin", &plain, 40_000, "nm", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let nzb_for = |fname: &str, segs: &[(String, u64, u32)], head: &str| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n{head}  <file poster=\"x\" date=\"0\" subject=\"&quot;{fname}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
    let locked_xml = nzb_for("Locked.Release.2026.rar", &lsegs, "");
    let meta_xml = nzb_for(
        "meta.bin",
        &msegs,
        "  <head><meta type=\"password\">metapw</meta></head>\n",
    );
    let named_xml = nzb_for("named.bin", &nsegs, "");

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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let addfile = |nzb_name: &str, xml: &str| {
            let boundary = "----nzbfastboundary";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{nzb_name}\"\r\nContent-Type: application/x-nzb\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let ctype = format!("multipart/form-data; boundary={boundary}");
            let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
            assert!(r.contains("nzo_ids"), "{r}");
        };
        addfile("Locked.Release.2026.nzb", &locked_xml);
        addfile("Meta.Release.nzb", &meta_xml);
        addfile("Named.Release{{n4me pw}}.nzb", &named_xml);

        // All three land in history.
        let slots = |h: &str| -> Vec<serde_json::Value> {
            serde_json::from_str::<serde_json::Value>(h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .unwrap_or_default()
        };
        let mut done = Vec::new();
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            done = slots(&h);
            if done.len() == 3 && done.iter().all(|s| s["status"] == "Completed") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(done.len(), 3, "not all jobs completed: {done:?}");
        let by_name = |name: &str| -> serde_json::Value {
            done.iter().find(|s| s["name"] == name).cloned().unwrap_or_else(|| {
                panic!("no history slot named {name}: {done:?}")
            })
        };

        // Encrypted set: flagged, volumes intact on disk.
        let locked_slot = by_name("Locked.Release.2026");
        assert_eq!(locked_slot["password_required"], true, "{locked_slot}");
        assert!(
            dir2.join("complete/Locked.Release.2026/Locked.Release.2026.rar").exists(),
            "verified volume must stay on disk"
        );
        // NZB meta password captured; nothing to unlock on a plain bin.
        let meta_slot = by_name("Meta.Release");
        assert_eq!(meta_slot["has_password"], true, "{meta_slot}");
        assert_eq!(meta_slot["password_required"], false, "{meta_slot}");
        // "Name{{pw}}": password split out, clean job name.
        let named_slot = by_name("Named.Release");
        assert_eq!(named_slot["has_password"], true, "{named_slot}");

        // set_password on the locked job: accepted, background unlock
        // runs, and (our fixture being undecryptable) reports the
        // password didn't work while keeping the flag.
        let id = locked_slot["nzo_id"].as_str().unwrap();
        let r = http(
            port,
            &format!("/api?mode=set_password&value={id}&password=wrongpw&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let mut reported = false;
        for _ in 0..50 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            let s = slots(&h);
            if let Some(l) = s.iter().find(|s| s["name"] == "Locked.Release.2026")
                && l["fail_message"].as_str().unwrap_or("").contains("did not unlock") {
                    assert_eq!(l["password_required"], true, "{l}");
                    reported = true;
                    break;
                }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(reported, "wrong password never reported");
        // Unknown id rejected.
        let r = http(
            port,
            "/api?mode=set_password&value=nope&password=x&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("unknown nzo_id"), "{r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// SAB/NZBGet-parity passwords file: with `password_file` configured, a
/// job whose volumes turn out encrypted and which carries no password of
/// its own unlocks at completion with the first file candidate that
/// works - no manual set_password, no password_required parking - and
/// the winner is recorded onto the job (history reports has_password).
/// get_config exposes the path and a count, never the values.
#[tokio::test(flavor = "multi_thread")]
async fn passwords_file_unlocks_at_completion() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-pwlist-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // One encrypted-data RAR5 store volume (`rar -m0 -p…` shape): the
    // native unlock path decrypts it with no unrar on the box.
    let inner = payload(80_001, 17);
    let f = fixtures::encrypt_file("listpw", &inner, 9);
    let n = f.cipher.len();
    let vol = fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..n, false, false)], None);
    let mut articles = HashMap::new();
    let segs = make_file_articles("Listed.Release.2026.rar", &vol, 40_000, "lp", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;Listed.Release.2026.rar&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let pct = |s: &str| -> String {
            s.bytes()
                .map(|b| format!("%{b:02X}"))
                .collect::<String>()
        };
        // SAB/NZBGet-format passwords file: one per line, a wrong
        // candidate first - order is part of the contract.
        let pw_file = dir2.join("pw.txt");
        std::fs::write(&pw_file, "not-this-one\nlistpw\n").unwrap();
        let r = http(
            port,
            &format!(
                "/api?mode=config&name=password_file&value={}&apikey=sekrit&output=json",
                pct(&pw_file.to_string_lossy())
            ),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        // Only the path and the count reach the UI - never the values.
        let r = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(r.contains("\"password_file_count\":2"), "{r}");
        assert!(!r.contains("listpw"), "password value leaked into get_config: {r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Listed.Release.2026.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut slot = serde_json::Value::Null;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|s| s.iter().find(|s| s["name"] == "Listed.Release.2026").cloned())
                && s["status"] == "Completed"
            {
                slot = s;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        // Unlocked by the list, not parked - and the winner stayed on
        // the job.
        assert_eq!(slot["password_required"], false, "{slot}");
        assert_eq!(slot["has_password"], true, "{slot}");
        // Auto-rename may have retitled both the file and the folder, so
        // take the directory from the record and find the payload by its
        // unpacked (padding-truncated) size instead of by name.
        let job_dir = std::path::PathBuf::from(slot["storage"].as_str().unwrap());
        assert!(
            job_dir.starts_with(dir2.join("complete")),
            "unexpected storage dir: {job_dir:?}"
        );
        let files: Vec<_> = std::fs::read_dir(&job_dir)
            .expect("job dir")
            .flatten()
            .map(|e| e.path())
            .collect();
        assert!(
            files
                .iter()
                .any(|p| p.extension().is_some_and(|x| x == "mkv")
                    && std::fs::metadata(p).is_ok_and(|m| m.len() == 80_001)),
            "no unpacked 80001-byte mkv in {files:?}"
        );
        assert!(
            !job_dir.join("Listed.Release.2026.rar").exists(),
            "spent volume must be consumed by the unlock"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 100 (Gary's 14.87 GB re-download): an ENOSPC after a finished
/// encrypted download used to force a near-full refetch on retry - the
/// finish decrypt had retired the journal's claim over its output and
/// nothing ever told the journal the decrypt LANDED. Plaintext-once
/// retires nothing: the output holds plaintext from its first article
/// and its `E`/`K`/`T` + `D` records are written as the bytes arrive, so
/// the retry re-encrypts the local plaintext back into posted bytes and
/// fetches essentially nothing. Same assertion, now about records the
/// download wrote rather than ones a publish handed back.
///
/// `NZBFAST_DECRYPT_ENOSPC_ONCE=post` injects the disk-full exactly
/// once, after the encrypted finish verdict landed - the same journal
/// state a real unpack-stage ENOSPC leaves behind.
#[tokio::test(flavor = "multi_thread")]
async fn enospc_after_decrypt_publish_retries_without_refetching() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-decfull-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // One encrypted-data RAR5 store volume, password in the NZB's own
    // meta - known up front, so the mapper decrypts it in-stream and the
    // finish verdict adjudicates the plaintext already on disk.
    let inner = payload(200_001, 23);
    let f = fixtures::encrypt_file("decpw", &inner, 5);
    let n = f.cipher.len();
    let vol = fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..n, false, false)], None);
    let mut articles = HashMap::new();
    let segs = make_file_articles("Enospc.Retry.2026.rar", &vol, 40_000, "er", &mut articles);
    // NO wire ordering, deliberately. A `Chaos::slow_ttfb` map held
    // every article but the offset-0 one back by 400 ms here until 24
    // Aug 2026, because how many articles beat the sniff decided how
    // many `D` records the run produced: an article arriving while its
    // slot is still `Unknown` parks whole (`Persist::Held`), is re-fed
    // through `drain_holds`, and a crypto placement on that route was
    // reported NOWHERE, so it never journaled at all. Measured over 10
    // runs on a loaded box that day, the journal held 4 `D` records six
    // times, 3 once, 1 once and NOTHING twice. TODO 27.2 closed that:
    // the re-feed reports the placement WITH its crypto fact and
    // `flush_pending_r` completes the article into a `D`, so the
    // population no longer depends on the interleave and the scaffold
    // that hid the dependence is gone with it. Verified by running the
    // set entirely INVERTED - the offset-0 sniff held behind every
    // other article, so all five payload articles park - which now
    // journals the same four.
    let srv = MockServer::start(articles, Chaos::default()).await;
    let body_log = srv.body_log.clone();

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <head><meta type=\"password\">decpw</meta></head>\n  <file poster=\"x\" date=\"0\" subject=\"&quot;Enospc.Retry.2026.rar&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
            .env("NZBFAST_DECRYPT_ENOSPC_ONCE", "post")
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

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Deterministic timeline: this test drives the retry itself.
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
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Enospc.Retry.2026.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        // First run: the injected disk-full fails the job AFTER the
        // decrypt published.
        let find_slot = |want: &str| -> Option<serde_json::Value> {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|s| {
                    s.iter()
                        .find(|s| s["name"] == "Enospc.Retry.2026" && s["status"] == want)
                        .cloned()
                })
        };
        let mut slot = serde_json::Value::Null;
        for _ in 0..150 {
            if let Some(s) = find_slot("Failed") {
                slot = s;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(slot["status"], "Failed", "{slot}");
        assert!(
            slot["fail_message"]
                .as_str()
                .unwrap_or_default()
                .contains("disk-full"),
            "expected the injected disk-full, got: {slot}"
        );
        let nzo = slot["nzo_id"].as_str().expect("nzo_id").to_string();
        let failed_dir = slot["storage"].as_str().unwrap_or_default().to_string();
        let journal_txt = std::fs::read_to_string(
            std::path::Path::new(&failed_dir).join(".nzbfast.journal"),
        )
        .unwrap_or_else(|e| format!("<no journal at {failed_dir}: {e}>"));

        // Retry: everything needed is on disk (published plaintext + the
        // republished D records), so the provider sees ~nothing.
        // `body_log.len()`, NOT `served`: the mock logs an id when the
        // request ARRIVES and increments `served` only once the body is
        // fully written, so the two counters part company for every
        // in-flight request and for every one that answers 430. Slicing
        // `body_log` at a `served` mark therefore starts the "refetched"
        // window somewhere INSIDE the first run and blames it for
        // articles the retry never asked for.
        let asked_before = body_log.lock().unwrap().len();
        let r = http(
            port,
            &format!("/api?mode=retry&value={nzo}&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let mut slot = serde_json::Value::Null;
        for _ in 0..150 {
            if let Some(s) = find_slot("Completed") {
                slot = s;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        // The TODO 100 property: the publish republished the retired
        // placements as `D` records, and every one of them restores from
        // the local plaintext - none of those articles may reach the
        // provider again. (Articles the first run never managed to
        // journal - the head/tail carrying archive headers that live in
        // no output file, and any article the placement race missed -
        // legitimately refetch; that boundary predates this fix and is
        // the same one a plain crash-resume has. Before the fix the
        // journal held an X and no D at all, and the retry refetched the
        // ENTIRE set.)
        let d_ids: std::collections::HashSet<String> = journal_txt
            .lines()
            .filter(|l| l.starts_with("D "))
            .filter_map(|l| l.rsplit(' ').next().map(str::to_string))
            .collect();
        // Every article but two, and the two are named rather than
        // tolerated: the offset-0 article is the sniff itself (its
        // bytes route before any mode exists to journal them against),
        // and the tail article carries the archive's end-of-set headers,
        // which live in no output file and so are journaled by nothing.
        // That is the FULL payload population of this fixture, and since
        // TODO 27.2 closed on 24 Aug 2026 it is reached whatever order
        // the articles land in - a held crypto span now reports its
        // placement and completes into a `D` like a directly-placed one.
        // Asserted by IDENTITY and not by count, so a run that journals
        // four of the wrong four is not a pass. A bare `!is_empty()`
        // stood here until that day and was the flake; the wire ordering
        // that briefly replaced it was a workaround for the gap and went
        // out with it.
        let want: std::collections::HashSet<String> = segs[1..segs.len() - 1]
            .iter()
            .map(|(id, _, _)| format!("<{id}>"))
            .collect();
        assert_eq!(
            d_ids, want,
            "the decrypt publish journaled {} of {} articles - every one \
             but the offset-0 sniff and the header tail should have a `D`\n\
             --- journal ---\n{journal_txt}",
            d_ids.len(),
            segs.len()
        );
        // What is asserted below is the half the retry actually rides
        // on: whatever journaled restores locally and is never asked for
        // again.
        let refetched: Vec<String> = body_log.lock().unwrap()[asked_before..].to_vec();
        assert!(
            refetched.len() < segs.len(),
            "retry refetched the whole set: {refetched:?}\n--- journal ---\n{journal_txt}"
        );
        let leaked: Vec<&String> = refetched.iter().filter(|id| d_ids.contains(*id)).collect();
        assert!(
            leaked.is_empty(),
            "articles with published D records were refetched: {leaked:?}\n--- journal ---\n{journal_txt}"
        );

        // And the output is byte-valid - the local re-encrypt round-trip
        // must reproduce the plaintext exactly.
        let job_dir = std::path::PathBuf::from(slot["storage"].as_str().unwrap());
        assert!(
            job_dir.starts_with(dir2.join("complete")),
            "unexpected storage dir: {job_dir:?}"
        );
        let mkv = std::fs::read_dir(&job_dir)
            .expect("job dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| std::fs::metadata(p).is_ok_and(|m| m.len() == 200_001))
            .unwrap_or_else(|| panic!("no 200001-byte payload in {job_dir:?}"));
        assert_eq!(
            std::fs::read(&mkv).unwrap(),
            inner,
            "retried output must be byte-identical to the posted payload"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// password_prompt=never: a locked job completes QUIETLY - no failure
/// text (nothing for the dashboard to announce), the still-packed note
/// names the archive so the row says why it is packed, and
/// password_required keeps the manual 🔑 available.
#[tokio::test(flavor = "multi_thread")]
async fn password_prompt_never_leaves_archive_packed() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pwnever-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Undecryptable encrypted-header shape: no password will ever work,
    // so the job always parks locked - which is exactly the state this
    // mode reshapes.
    let locked = nzbkit::rar::fixtures::rar4_encrypted_headers(4096);
    let mut articles = HashMap::new();
    let segs = make_file_articles(
        "Quiet.Release.2026.rar",
        &locked,
        40_000,
        "qn",
        &mut articles,
    );
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;Quiet.Release.2026.rar&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=password_prompt&value=never&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        // A bad mode is rejected outright.
        let r = http(
            port,
            "/api?mode=config&name=password_prompt&value=sometimes&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":false"), "{r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Quiet.Release.2026.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut slot = serde_json::Value::Null;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|s| s.iter().find(|s| s["name"] == "Quiet.Release.2026").cloned())
                && s["status"] == "Completed"
            {
                slot = s;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        // Locked, but presented as a quiet caveat, not a failure.
        assert_eq!(slot["password_required"], true, "{slot}");
        assert_eq!(slot["fail_message"], "", "{slot}");
        let blocked = slot["unpack_blocked_by"].as_str().unwrap_or("");
        assert!(
            blocked.contains("Quiet.Release.2026.rar"),
            "still-packed note must name the archive: {slot}"
        );
        // The verified volume stays on disk for manual extraction.
        assert!(
            dir2.join("complete/Quiet.Release.2026/Quiet.Release.2026.rar").exists(),
            "volume must stay on disk"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
