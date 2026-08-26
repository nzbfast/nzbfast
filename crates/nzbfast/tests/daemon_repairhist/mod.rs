//! A job whose extraction takes the materialize-for-repair fallback must
//! still reach a TERMINAL history row.
//!
//! The observation this pins was made on 31 Jul 2026 during a three-NZB
//! queue soak: all three payloads finished correctly on disk, and the
//! harness polling `?mode=history` counted only two terminal
//! (`Completed`/`Failed`) rows and then waited out its full 3600 s
//! timeout. The last lines the daemon printed belonged to the job that
//! never appeared - "direct extraction fell back for 1 volume group(s):
//! materialized for repair - volumes on disk", then the memory summary,
//! then `[cleanup]`. It reproduced once in two legs and was never
//! reproduced again.
//!
//! Why it is worth a test rather than a note. `mode=history` is what
//! Sonarr, Radarr and the phone remotes poll, and the word in that row
//! is what they act on: a job that finishes on disk without ever
//! reporting a terminal state blocks their pipeline exactly as a failed
//! one would, with nothing to see wrong anywhere. The repair fallback is
//! also the longest tail the engine has - materialize, repair, then a
//! whole second extraction pass - so it is the route most likely to
//! outlive whatever else is watching it.
//!
//! The fixture is `e2e.rs`'s `damaged_post_repairs_and_reextracts` shape
//! driven through the DAEMON instead of `nzbfast get`: a three-volume
//! store RAR set with 20% par2 over it, a mid-volume data article
//! poisoned in part 2 and part 3's offset-0 HEADER article poisoned so
//! that volume cannot map at all. That combination is what makes the
//! mapped-repair gate decline and sends the group down the
//! materialize + repair + re-extract path - which the test asserts on
//! the daemon's own log, so a fixture that stopped taking that route
//! fails here rather than passing as a job that simply completed.

use super::*;

/// Is the external `par2` binary on this box? Same probe and same
/// `NZBFAST_REQUIRE_PAR2` assertion as `e2e.rs` - a skipped test reads
/// exactly like a green run, so the runners that install par2 on purpose
/// say so and turn the skip into a failure.
fn have_par2() -> bool {
    let ok = Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        ok || std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
        "NZBFAST_REQUIRE_PAR2 is set but `par2 -V` does not run - this test \
         would have skipped and the run would have looked green"
    );
    ok
}

/// A three-volume store RAR release of one inner file, plus a par2
/// recovery set over the volumes, posted as articles.
///
/// Returns the article map, the NZB, the inner payload bytes to compare
/// the extracted file against, and the message-ids to poison. `build` is
/// scratch: par2 needs the volumes on disk to read, and nothing after
/// this function looks in there.
fn damaged_rar_release(build: &Path) -> (HashMap<String, Vec<u8>>, String, Vec<u8>, Vec<String>) {
    use nzbkit::rar::fixtures;
    std::fs::create_dir_all(build).unwrap();
    // WinRAR-true geometry, copied from e2e's `rar_release`: volume 0
    // carries one byte more data than volume 1 (no volume-number field
    // in its main header).
    let inner = payload(900_000, 7);
    let vols = [
        fixtures::rar5_volume_n(&[("movie.mkv", 900_000, &inner[..350_001], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 900_000, &inner[350_001..700_001], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("movie.mkv", 900_000, &inner[700_001..], true, false)], 2),
    ];
    let names = ["r.part1.rar", "r.part2.rar", "r.part3.rar"];
    let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
    let mut nzb_files: Vec<(String, Vec<(String, u64, u32)>)> = Vec::new();
    for (i, (name, vol)) in names.iter().zip(&vols).enumerate() {
        std::fs::write(build.join(name), vol).unwrap();
        let tag = format!("{}-{i}", name.replace('.', "_"));
        let segs = make_file_articles(name, vol, 60_000, &tag, &mut articles);
        nzb_files.push(((*name).to_string(), segs));
    }
    // 20% recovery: enough to cover the two poisoned articles below at
    // this geometry (60 kB articles over par2's own ~450 byte blocks,
    // so one bad article costs about 134 blocks).
    let st = Command::new("par2")
        .arg("create")
        .arg("-r20")
        .arg("-q")
        .arg("testset")
        .args(names)
        .current_dir(build)
        .status();
    assert!(
        st.is_ok_and(|s| s.success()),
        "par2 create failed - `have_par2` said the binary runs"
    );
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(build)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    for (i, p) in par2s.iter().enumerate() {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let data = std::fs::read(p).unwrap();
        let tag = format!("{}-p{i}", name.replace('.', "_"));
        let segs = make_file_articles(&name, &data, 60_000, &tag, &mut articles);
        nzb_files.push((name, segs));
    }
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, segs) in &nzb_files {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    // The damage. A mid-volume DATA article of part 2, and part 3's
    // offset-0 HEADER article: without its header that volume cannot
    // map, the mapped-repair gate declines, and the group takes the
    // materialize + repair_dir + re-extract route this test is about.
    let victim = |file: &str, suffix: &str| {
        articles
            .keys()
            .find(|k| k.contains(file) && k.ends_with(suffix))
            .unwrap_or_else(|| panic!("no article matching {file}/{suffix}"))
            .clone()
    };
    let poisoned = vec![
        victim("r_part2_rar", "-3@mock>"),
        victim("r_part3_rar", "-1@mock>"),
    ];
    std::fs::remove_dir_all(build).unwrap();
    (articles, xml, inner, poisoned)
}

/// The contract: the job reaches `Completed` in `mode=history`, with the
/// repaired payload where the row says it is.
///
/// Three assertions, and the order matters. The row must be TERMINAL -
/// not `Moving`, which is what a history row reads while the mover still
/// owes a relocation, and not `Queued`, which is what a non-terminal
/// state renders as. The daemon's log must show the fallback was really
/// taken, or a fixture that quietly started one-passing would leave this
/// test green while testing nothing. And the extracted bytes must match,
/// because a repair that produced the wrong bytes still parks a green
/// row.
#[tokio::test(flavor = "multi_thread")]
async fn a_repair_fallback_job_reaches_a_terminal_history_row() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-repairhist-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (articles, xml, inner, poisoned) = damaged_rar_release(&dir.join("fixture"));
    let chaos = Chaos {
        missing: poisoned.into_iter().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(articles, chaos).await;

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
            .arg("4");
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log_path();
    let dir2 = dir.clone();

    tokio::task::spawn_blocking(move || {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"damaged.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
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
        assert!(r.contains("\"status\":true"), "{r}");
        let added: serde_json::Value = serde_json::from_str(&r).expect("addfile json");
        let nzo = added["nzo_ids"][0]
            .as_str()
            .expect("addfile returned no nzo_id")
            .to_string();

        // Bounded, and the bound is the point: the defect this pins is a
        // job that never reaches a terminal row at all, so a test that
        // waited forever would reproduce the hang rather than report it.
        // 120 s is about sixty times what this fixture takes.
        let mut status = String::new();
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            let slot = history_slot(&h, &nzo);
            if let Some(s) = slot["status"].as_str()
                && (s == "Completed" || s == "Failed")
            {
                status = s.to_string();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
        assert!(
            !status.is_empty(),
            "the job never reached a terminal history row.\n\
             queue slot: {}\nhistory slot: {}\n--- daemon log ---\n{log}",
            queue_slot(&q, &nzo),
            history_slot(&h, &nzo),
        );
        assert_eq!(status, "Completed", "history row:\n{}", history_slot(&h, &nzo));
        // The route proof. Without it a fixture that stopped demoting
        // would leave every assertion above true and this test blind.
        assert!(
            log.contains("materializing volumes for repair"),
            "the set never took the materialize-for-repair fallback:\n{log}"
        );
        assert!(
            log.contains("re-extracting"),
            "no re-extraction pass after the repair:\n{log}"
        );
        // These volumes carry no data CRC (see e2e's `rar_release_r`), so
        // nothing downstream checksums the payload - the byte comparison
        // is what stands in for it.
        let mkv = std::fs::read(dir2.join("complete/movie.mkv"))
            .or_else(|_| std::fs::read(dir2.join("complete/damaged/movie.mkv")))
            .unwrap_or_else(|e| panic!("extracted file missing: {e}\n--- daemon log ---\n{log}"));
        assert_eq!(mkv, inner, "extracted bytes differ after repair");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Upload one NZB and return the id the daemon minted for it.
fn add_nzb(port: u16, filename: &str, xml: &str) -> String {
    let boundary = "----nzbfastboundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{filename}\"\r\nContent-Type: application/x-nzb\r\n\r\n"
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
    assert!(r.contains("\"status\":true"), "{r}");
    let added: serde_json::Value = serde_json::from_str(&r).expect("addfile json");
    added["nzo_ids"][0]
        .as_str()
        .unwrap_or_else(|| panic!("addfile returned no nzo_id: {r}"))
        .to_string()
}

/// A plain single-file post: one NZB, one file, no archive and nothing
/// to repair. The company the repair job keeps in the test below.
fn plain_post(
    tag: &str,
    bytes: usize,
    seed: u8,
    articles: &mut HashMap<String, Vec<u8>>,
) -> String {
    let name = format!("{tag}.bin");
    let data = payload(bytes, seed);
    let segs = make_file_articles(&name, &data, 40_000, tag, articles);
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, b, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{b}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

/// The 31 Jul shape itself: three posts added back to back, one of them
/// taking the repair fallback, and EVERY one of them owed a terminal
/// history row.
///
/// The single-job test above pins the route. This one pins the thing
/// that was actually observed - a queue whose payloads all landed
/// correctly while `mode=history` was one terminal row short, which is
/// what an *arr sees as a job that never finished. It asserts on all
/// three ids rather than on a count, so a run where the wrong job is
/// missing fails with the id that is short rather than passing on a
/// tally that happens to add up.
#[tokio::test(flavor = "multi_thread")]
async fn every_job_in_a_queue_with_a_repair_fallback_reaches_history() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-repairq-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (mut articles, damaged_xml, inner, poisoned) = damaged_rar_release(&dir.join("fixture"));
    let first = plain_post("firstpost", 400_000, 3, &mut articles);
    let last = plain_post("lastpost", 240_000, 11, &mut articles);
    let chaos = Chaos {
        missing: poisoned.into_iter().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(articles, chaos).await;

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
            .arg("4");
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log_path();
    let dir2 = dir.clone();

    tokio::task::spawn_blocking(move || {
        // Back to back, in the order the soak added them: an ordinary
        // post, the damaged set, an ordinary post.
        let ids = [
            add_nzb(port, "first.nzb", &first),
            add_nzb(port, "damaged.nzb", &damaged_xml),
            add_nzb(port, "last.nzb", &last),
        ];
        let terminal = |h: &str, id: &str| -> Option<String> {
            match history_slot(h, id)["status"].as_str() {
                Some(s) if s == "Completed" || s == "Failed" => Some(s.to_string()),
                _ => None,
            }
        };
        let mut seen: Vec<Option<String>> = vec![None; ids.len()];
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            for (i, id) in ids.iter().enumerate() {
                if seen[i].is_none() {
                    seen[i] = terminal(&h, id);
                }
            }
            if seen.iter().all(Option::is_some) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
        for (i, id) in ids.iter().enumerate() {
            assert!(
                seen[i].is_some(),
                "{id} never reached a terminal history row.\n\
                 queue slot: {}\nhistory slot: {}\n--- daemon log ---\n{log}",
                queue_slot(&q, id),
                history_slot(&h, id),
            );
            assert_eq!(
                seen[i].as_deref(),
                Some("Completed"),
                "{id} did not complete: {}",
                history_slot(&h, id)
            );
        }
        assert!(
            log.contains("materializing volumes for repair"),
            "the set never took the materialize-for-repair fallback:\n{log}"
        );
        let mkv = std::fs::read(dir2.join("complete/movie.mkv"))
            .or_else(|_| std::fs::read(dir2.join("complete/damaged/movie.mkv")))
            .unwrap_or_else(|e| panic!("extracted file missing: {e}\n--- daemon log ---\n{log}"));
        assert_eq!(mkv, inner, "extracted bytes differ after repair");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
