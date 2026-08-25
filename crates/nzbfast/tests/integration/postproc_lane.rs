//! §129 postproc-lane e2e suite: the download slot hands off at
//! net-drain and the tail runs in a bounded lane.
//!
//! Three properties, each pinned by the design doc
//! (research/PLAN-POSTPROC-LANE-2026-08-08.md):
//!
//! 1. The §100 lane variant: an ENOSPC after the decrypt publish, WHILE
//!    a second job is actively downloading, files the failed job to
//!    history with its journal intact; a retry refetches no D-recorded
//!    article; the second job's download and output are unharmed.
//! 2. Restart mid-`Finishing`: the persisted record loads back as
//!    Queued, the journal replays, and the job completes byte-valid.
//! 3. Backpressure: with the lane saturated the worker stops picking
//!    and says so (`hold.reason == "postproc"`), then resumes and
//!    drains the whole queue.
//!
//! Run in the daemon suite's discipline (each test owns a daemon on its
//! own port; NZBFAST_NO_ENRICH=1 in the environment of every child).

use crate::scratch;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;

use crate::harness::serve;

use nzbkit::mock::{Chaos, MockServer, make_file_articles};

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
        .collect()
}

/// Response body of a request to the daemon (headers stripped). Retries
/// only a connection that produced zero bytes - see queue_soak.rs.
fn http(port: u16, req: &str, body: Option<(&str, &[u8])>) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req, body) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

fn http_once(port: u16, req: &str, body: Option<(&str, &[u8])>) -> std::io::Result<String> {
    let mut request = Vec::new();
    match body {
        None => {
            write!(
                request,
                "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        }
        Some((ctype, data)) => {
            write!(
                request,
                "POST {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n",
                data.len()
            )
            .unwrap();
            request.extend_from_slice(data);
        }
    }
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(&request)?;
    let mut out = String::new();
    let read = s.read_to_string(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

/// Segment list -> the daemon's addfile multipart body.
fn add_nzb(port: u16, name: &str, xml: &str) {
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
    let r = http(
        port,
        "/api?mode=addfile&apikey=sekrit&output=json",
        Some((&ctype, &body)),
    );
    assert!(r.contains("nzo_ids"), "{r}");
}

/// One-file NZB with optional password meta.
fn nzb_xml(subject: &str, segs: &[(String, u64, u32)], password: Option<&str>) -> String {
    let meta = password
        .map(|p| format!("  <head><meta type=\"password\">{p}</meta></head>\n"))
        .unwrap_or_default();
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n{meta}  <file poster=\"x\" date=\"0\" subject=\"&quot;{subject}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

/// Multi-file NZB (a release with its volumes and par2 set).
fn nzb_xml_multi(files: &[(String, Vec<(String, u64, u32)>)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (subject, segs) in files {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{subject}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
    xml
}

fn have_par2() -> bool {
    Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn queue_payload(port: u16) -> serde_json::Value {
    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    serde_json::from_str::<serde_json::Value>(&q)
        .ok()
        .and_then(|v| v.get("queue").cloned())
        .unwrap_or(serde_json::Value::Null)
}

fn history_slot(port: u16, name: &str, want: &str) -> Option<serde_json::Value> {
    let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
    serde_json::from_str::<serde_json::Value>(&h)
        .ok()
        .and_then(|v| v["history"]["slots"].as_array().cloned())
        .and_then(|s| {
            s.iter()
                .find(|s| s["name"] == name && s["status"] == want)
                .cloned()
        })
}

/// The SAB queue vocabulary the *arrs know. A lane row must never widen
/// it (design point 6/7: no new status strings on the compat surface).
const SAB_QUEUE_STATUSES: &[&str] = &[
    "Downloading",
    "Queued",
    "Paused",
    "Verifying",
    "Repairing",
    "Extracting",
    "Moving",
];

/// §100 lane variant + the facade shape gate.
///
/// Job 1 is the §100 encrypted store set with the post-publish ENOSPC
/// injected once; job 2 is a clean plain post whose DOWNLOAD is built to
/// outlast job 1's whole tail, so job 1's Finishing window sits inside
/// it. Along the way every queue snapshot is schema-checked: only SAB's
/// own status words, at most one Downloading row (§91 pairing), and the
/// overlap itself must be observed (a `finishing` row beside a
/// Downloading one). The arithmetic that makes that last one
/// deterministic is at the assertion.
#[tokio::test(flavor = "multi_thread")]
async fn enospc_in_lane_keeps_journal_and_second_job_unharmed() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-lane100-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Job 1: one encrypted-data RAR5 store volume, password in the NZB
    // meta - the §100 shape verbatim.
    let inner = payload(200_001, 23);
    let f = fixtures::encrypt_file("decpw", &inner, 5);
    let n = f.cipher.len();
    let vol = fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..n, false, false)], None);
    let mut articles = HashMap::new();
    let segs1 = make_file_articles("Lane.Enospc.2026.rar", &vol, 40_000, "le", &mut articles);
    // Job 2: a clean plain post whose NETWORK PHASE is built to outlast
    // job 1's whole tail - 201 articles at 180 ms of server-side delay
    // each, over a fleet pinned to 4 connections below, so the download
    // cannot drain in less than 201 x 180 ms / 4 = 9.0 s however fast
    // the box is. That floor is the whole determinism argument at the
    // overlap assertion; see the comment there before changing any of
    // these three numbers, and change them together.
    //
    // The article size is what buys the article COUNT: 1.2 MB in 40 KB
    // pieces is 31 articles, which a 25-connection fleet fetched in one
    // round in under a second - the entire download landing inside job
    // 1's stall with a ~0.5 s window for a 100 ms poll to find.
    let clean = payload(1_200_001, 91);
    let segs2 = make_file_articles("Lane.Clean.2026.mkv", &clean, 6_000, "lc", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 180,
            ..Chaos::default()
        },
    )
    .await;
    let body_log = srv.body_log.clone();

    let xml1 = nzb_xml("Lane.Enospc.2026.rar", &segs1, Some("decpw"));
    let xml2 = nzb_xml("Lane.Clean.2026.mkv", &segs2, None);

    let cfg = dir.join("config.json");
    // The fleet is PINNED to 4 connections, and that is a timing
    // control, not a preference: `delay_ms` is per BODY per connection,
    // so the download rate is width / delay and the width is the only
    // half of it the mock does not own. Left at the default the daemon
    // asks for 100, the line cap trims it to 25, and a 25-wide fleet
    // fetches this post in one round - a duration set by how fast the
    // box can dial 25 sockets, which is exactly the quantity a loaded
    // parallel run moves. `pin_connections` keeps the tuner from
    // trimming it further, so the arithmetic at the overlap assertion
    // is an equality rather than a hope.
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":4,\"pin_connections\":true}}]}}",
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
            // Hold every tail open ~4 s. This is what makes job 1's
            // Finishing window long enough to be POLLED - the real tail
            // here is a 200 KB decrypt, far too quick to race a 100 ms
            // poll against. It is NOT what makes the overlap happen:
            // that is job 2's download outlasting this stall, which is
            // the arithmetic at the overlap assertion below. Raising
            // this number widens the window and shortens the margin at
            // the same time, so it is not the lever it looks like.
            .env("NZBFAST_TEST_STALL_TAIL_MS", "4000")
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
            "/api?mode=config&name=auto_retry_mins&value=0&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        add_nzb(port, "Lane.Enospc.2026", &xml1);
        add_nzb(port, "Lane.Clean.2026", &xml2);

        // Drive to the failure while schema-checking every snapshot.
        let mut saw_overlap = false;
        // One line per CHANGE of (Downloading rows, finishing rows), for
        // the overlap assertion's own failure message: the two ways it
        // can fail - the window closing early and the poll skipping a
        // window that was open - look identical from a bare `false`, and
        // telling them apart from a daemon log took a day.
        let mut trace: Vec<String> = Vec::new();
        let t0 = std::time::Instant::now();
        let mut failed = serde_json::Value::Null;
        for _ in 0..300 {
            let q = queue_payload(port);
            if let Some(slots) = q["slots"].as_array() {
                let mut downloading = 0;
                let mut finishing = 0;
                for s in slots {
                    let st = s["status"].as_str().unwrap_or("");
                    assert!(
                        SAB_QUEUE_STATUSES.contains(&st),
                        "status {st:?} is not SAB vocabulary: {s}"
                    );
                    if st == "Downloading" {
                        downloading += 1;
                    }
                    if s["finishing"] == true {
                        finishing += 1;
                        // §91 one-instant pairing: a lane row is done
                        // fetching - 100%, nothing left, no ETA.
                        assert_eq!(s["percentage"], "100", "{s}");
                        assert_eq!(s["timeleft"], "0:00:00", "{s}");
                    }
                }
                // Two rows may be on the wire at once since the cross-job
                // hand-over (tests/integration/queue_handoff.rs): the
                // previous job's last in-flight articles drain beside
                // the next job's first ones. Three never can - the
                // runner submits N before it looks at N+1's signals.
                assert!(
                    downloading <= 2,
                    "three Downloading rows in one snapshot: {slots:?}"
                );
                if downloading == 1 && finishing >= 1 {
                    saw_overlap = true;
                }
                let mark = format!("{downloading}d/{finishing}f");
                if trace.last().is_none_or(|l| !l.ends_with(&mark)) {
                    trace.push(format!("{:.2}s {mark}", t0.elapsed().as_secs_f64()));
                }
            }
            if let Some(s) = history_slot(port, "Lane.Enospc.2026", "Failed") {
                failed = s;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(failed["status"], "Failed", "{failed}");
        assert!(
            failed["fail_message"]
                .as_str()
                .unwrap_or_default()
                .contains("disk-full"),
            "expected the injected disk-full, got: {failed}"
        );
        // The SUBJECT of this suite, and the one assertion in it that is
        // about an INSTANT rather than an outcome - so it is the one
        // that a timing drift silently deletes rather than reddens.
        //
        // What makes it deterministic is CONTAINMENT, not a wide-enough
        // window: job 1's whole Finishing window sits inside job 2's
        // download, so a poll can only miss the overlap by spending the
        // entire window inside one iteration. The two floors, both
        // wall-clock and both set above:
        //
        //   job 1 Finishing  = 4.0 s stall + its tail  (~4.2 s measured)
        //   job 2 downloading = 201 articles x 180 ms / 4 conns = 9.0 s
        //                       (9.6 s measured, dial included)
        //
        // and job 2 starts on job 1's hand-over, i.e. within ~0.3 s of
        // job 1 entering the lane. So job 2 is still on the wire ~5 s
        // after job 1 has been filed, and the window is ~40 polls wide.
        //
        // It was NOT like that until 24 Aug 2026: job 2 was 31 articles
        // at 60 ms over a 25-wide fleet, so its whole download drained
        // in 0.82 s INSIDE job 1's 4 s stall, and the overlap was a
        // ~0.5 s sliver a 100 ms poll had to hit. That failed 1 run in 3
        // of the full CI sweep and passed on nextest's retry, so the run
        // reported `1 flaky` and exit 0 - the same shape TODO 27.2
        // documents for the sibling copy of this test, `daemon_password
        // ::enospc_after_decrypt_publish_retries_without_refetching`,
        // where a 133/133 daemon suite hid a FLAKY 2/2 line nobody
        // reads.
        //
        // Do NOT reach for `Chaos::slow_ttfb` to widen this: it was
        // measured on 24 Aug 2026 and 400 ms of dead air pushes job 1's
        // finish out past job 2's whole download, so the overlap stops
        // happening at all (5 runs, 5 failures here). See the journal
        // rider below, which is where that scaffold came from.
        assert!(
            saw_overlap,
            "never observed a finishing row beside a Downloading one - \
             the lane overlap this suite exists for did not happen.\n\
             (Downloading rows / finishing rows over time: {trace:?}) - \
             an entry reading 0d/1f says job 2's download drained while \
             job 1 was still in the lane, so the containment above \
             broke; a trace with no 1f in it at all says the window was \
             open and the poll stepped over it."
        );
        let nzo = failed["nzo_id"].as_str().expect("nzo_id").to_string();
        let failed_dir = failed["storage"].as_str().unwrap_or_default().to_string();
        let journal_txt =
            std::fs::read_to_string(std::path::Path::new(&failed_dir).join(".nzbfast.journal"))
                .unwrap_or_else(|e| format!("<no journal at {failed_dir}: {e}>"));

        // The second job must complete clean despite job 1's failure.
        let mut clean_slot = serde_json::Value::Null;
        for _ in 0..300 {
            if let Some(s) = history_slot(port, "Lane.Clean.2026", "Completed") {
                clean_slot = s;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(clean_slot["status"], "Completed", "{clean_slot}");
        let clean_dir = std::path::PathBuf::from(clean_slot["storage"].as_str().unwrap());
        let clean_file = std::fs::read_dir(&clean_dir)
            .expect("clean job dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| std::fs::metadata(p).is_ok_and(|m| m.len() == 1_200_001))
            .unwrap_or_else(|| panic!("no 1200001-byte payload in {clean_dir:?}"));
        assert_eq!(
            std::fs::read(&clean_file).unwrap(),
            clean,
            "the overlapping download's output must be byte-identical"
        );

        // §100 property, unchanged by the lane: retry refetches no
        // D-recorded article.
        // `body_log.len()`, NOT `served`: the mock logs an id when the
        // request ARRIVES and increments `served` only once the body is
        // fully written, so a `served` mark indexes `body_log`
        // somewhere INSIDE the first run and blames the retry for
        // articles it never asked for.
        let asked_before = body_log.lock().unwrap().len();
        let r = http(
            port,
            &format!("/api?mode=retry&value={nzo}&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let mut slot = serde_json::Value::Null;
        for _ in 0..300 {
            if let Some(s) = history_slot(port, "Lane.Enospc.2026", "Completed") {
                slot = s;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        let d_ids: std::collections::HashSet<String> = journal_txt
            .lines()
            .filter(|l| l.starts_with("D "))
            .filter_map(|l| l.rsplit(' ').next().map(str::to_string))
            .collect();
        // A count, by identity, with NO wire-ordering scaffold - and
        // this rider needed both halves of TODO 27.2 to become one.
        // It stood at a tolerant `!d_ids.is_empty()` until 24 Aug 2026
        // because an article that beat the offset-0 sniff parked and
        // then never journaled at all, which made the population a
        // function of the interleave. The §100 test this leg was copied
        // from bought determinism for a day with a `Chaos::slow_ttfb`
        // map; the same scaffold was tried HERE and breaks this suite's
        // premise - 400 ms of dead air pushes job 1's finish out past
        // job 2's whole download, so the Finishing/Downloading overlap
        // this file exists to observe stops happening (5 runs, 5
        // failures on "never observed a finishing row beside a
        // Downloading one"). With held crypto spans journaling, no
        // scaffold is needed on either site: every article but the
        // offset-0 sniff and the header tail carries a `D` whatever
        // order they land in.
        let want: std::collections::HashSet<String> = segs1[1..segs1.len() - 1]
            .iter()
            .map(|(id, _, _)| format!("<{id}>"))
            .collect();
        assert_eq!(
            d_ids, want,
            "the decrypt publish journaled {} of {} articles - every one \
             but the offset-0 sniff and the header tail should have a `D`\n\
             --- journal ---\n{journal_txt}",
            d_ids.len(),
            segs1.len()
        );
        let refetched: Vec<String> = body_log.lock().unwrap()[asked_before..].to_vec();
        let leaked: Vec<&String> = refetched.iter().filter(|id| d_ids.contains(*id)).collect();
        assert!(
            leaked.is_empty(),
            "articles with published D records were refetched: {leaked:?}\n--- journal ---\n{journal_txt}"
        );

        // ...and the retried output is byte-valid.
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

/// The queue-soak extension (rollout gate): a DAMAGED job's repair runs
/// in the lane while a clean job downloads beside it - the exact shape
/// the A/B rig's repair leg measures - and both outputs land
/// byte-identical (no cross-contamination between two concurrent tails
/// and a live download).
#[tokio::test(flavor = "multi_thread")]
async fn damaged_jobs_repair_overlaps_clean_download_byte_identical() {
    use nzbkit::rar::fixtures;
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-lanedmg-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // A 3-volume store RAR of one 900 kB file, with a 20% par2 set -
    // the e2e suite's rar_release geometry.
    let inner = payload(900_000, 7);
    let vols = [
        fixtures::rar5_volume_n(&[("movie.mkv", 900_000, &inner[..350_001], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 900_000, &inner[350_001..700_001], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("movie.mkv", 900_000, &inner[700_001..], true, false)], 2),
    ];
    let vol_names = ["r.part1.rar", "r.part2.rar", "r.part3.rar"];
    let fxdir = dir.join("fixture");
    std::fs::create_dir_all(&fxdir).unwrap();
    for (name, vol) in vol_names.iter().zip(&vols) {
        std::fs::write(fxdir.join(name), vol).unwrap();
    }
    let ok = Command::new("par2")
        .arg("create")
        .arg("-r20")
        .arg("-q")
        .arg("testset")
        .args(vol_names)
        .current_dir(&fxdir)
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "par2 create failed");
    let mut par2s: Vec<std::path::PathBuf> = std::fs::read_dir(&fxdir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "par2"))
        .collect();
    par2s.sort();

    let mut articles = HashMap::new();
    let mut damaged_files: Vec<(String, Vec<(String, u64, u32)>)> = Vec::new();
    for (i, (name, vol)) in vol_names.iter().zip(&vols).enumerate() {
        let segs = make_file_articles(name, vol, 60_000, &format!("dv{i}"), &mut articles);
        damaged_files.push((name.to_string(), segs));
    }
    for (i, p) in par2s.iter().enumerate() {
        let data = std::fs::read(p).unwrap();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let segs = make_file_articles(&name, &data, 60_000, &format!("dp{i}"), &mut articles);
        damaged_files.push((name, segs));
    }
    // Damage: two of volume 2's payload articles vanish (430), so the
    // in-stream verify fails honestly and the tail repairs from parity.
    let missing: std::collections::HashSet<String> = damaged_files
        .iter()
        .find(|(n, _)| n == "r.part2.rar")
        .map(|(_, segs)| segs.iter().take(2).map(|(id, _, _)| id.clone()).collect())
        .unwrap();
    let clean = payload(4_000_001, 55);
    let clean_segs =
        make_file_articles("Lane.Beside.2026.mkv", &clean, 10_000, "cb", &mut articles);
    // 401 articles at 90 ms of server-side delay each, over the fleet
    // pinned to 4 connections below: the clean job's network phase
    // cannot drain in less than 401 x 90 ms / 4 = 9.0 s, which is what
    // holds the Downloading-beside-Finishing window open for the whole
    // of the damaged job's tail. See the overlap assertion below for
    // why that floor and not a wider poll or a longer stall, and change
    // the three numbers together.
    let srv = MockServer::start(
        articles,
        Chaos {
            missing,
            delay_ms: 90,
            ..Chaos::default()
        },
    )
    .await;

    let cfg = dir.join("config.json");
    // Pinned to 4 connections for the same reason as the §100 lane test
    // above: `delay_ms` is per BODY per connection, so the download rate
    // is width / delay and the width is the only half of it the mock
    // does not own. Unpinned the daemon asks for 100 and the line cap
    // trims to 25, which fetches the clean post in four rounds and puts
    // the whole overlap at the mercy of how fast the box dials.
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":4,\"pin_connections\":true}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // Hold tails open ~4 s, which is what makes the damaged
            // job's Finishing window long enough to be POLLED. It is
            // NOT what makes the overlap happen, and the comment here
            // said "the overlap window is exactly this stall" until
            // 24 Aug 2026, which was measurably false: the window ended
            // when the CLEAN job's download did, 0.95 s in, while this
            // stall ran to 4.95 s.
            .env("NZBFAST_TEST_STALL_TAIL_MS", "4000")
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

    tokio::task::spawn_blocking(move || {
        add_nzb(port, "Lane.Damaged.2026", &nzb_xml_multi(&damaged_files));
        let xml2 = nzb_xml("Lane.Beside.2026.mkv", &clean_segs, None);
        add_nzb(port, "Lane.Beside.2026", &xml2);

        let mut saw_overlap = false;
        // Same trace the §100 lane test above keeps, for the same
        // reason: a bare `false` cannot tell a window that closed early
        // from a poll that stepped over an open one.
        let mut trace: Vec<String> = Vec::new();
        let t0 = std::time::Instant::now();
        let mut done = (false, false);
        for _ in 0..600 {
            let q = queue_payload(port);
            if let Some(slots) = q["slots"].as_array() {
                let downloading = slots
                    .iter()
                    .any(|s| s["status"] == "Downloading" && s["finishing"] != true);
                let finishing = slots.iter().any(|s| s["finishing"] == true);
                if downloading && finishing {
                    saw_overlap = true;
                }
                let mark = format!("{}d/{}f", u8::from(downloading), u8::from(finishing));
                if trace.last().is_none_or(|l| !l.ends_with(&mark)) {
                    trace.push(format!("{:.2}s {mark}", t0.elapsed().as_secs_f64()));
                }
            }
            done = (
                history_slot(port, "Lane.Damaged.2026", "Completed").is_some(),
                history_slot(port, "Lane.Beside.2026", "Completed").is_some(),
            );
            if done.0 && done.1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(done.0, "the damaged job never completed");
        assert!(done.1, "the clean job never completed");
        // Deterministic by CONTAINMENT, exactly as at the §100 lane
        // test above, and this site carried the same defect until
        // 24 Aug 2026. The damaged job's whole Finishing window sits
        // inside the clean job's download:
        //
        //   damaged Finishing = 4.0 s stall + repair  (4.08 s measured)
        //   clean downloading = 401 articles x 90 ms / 4 conns = 9.0 s
        //                       (9.75 s measured, dial included)
        //
        // Before, the clean post was 101 articles at 40 ms over a
        // 25-wide fleet: it drained 0.95 s in, so the window was 0.95 s
        // and NOT the 4 s this file's comments claimed for it. A longer
        // repair only ever HELPS here - the window is the intersection
        // of the two, so a tail that runs late widens it and only the
        // clean download running short can close it.
        assert!(
            saw_overlap,
            "the damaged job's tail never overlapped the clean download.\n\
             (a Downloading row / a finishing row over time: {trace:?}) - \
             read the GAP, not any single entry: a `1d/0f` line followed \
             straight by a `0d/1f` one says the clean download drained \
             before the damaged job reached the lane, which is the \
             containment above breaking, while `1d` and `1f` intervals \
             that plainly overlap with no `1d/1f` line between them say \
             the poll stepped over an open window. Unlike the §100 test \
             above, this loop runs on until BOTH jobs are filed, so a \
             trailing `0d/1f` is just the clean job in its own tail and \
             means nothing."
        );

        let slot = history_slot(port, "Lane.Damaged.2026", "Completed").unwrap();
        let job_dir = std::path::PathBuf::from(slot["storage"].as_str().unwrap());
        // The auto-rename pass gives the single video the job's name -
        // find it by size, judge it by bytes.
        let movie = std::fs::read_dir(&job_dir)
            .expect("damaged job dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| std::fs::metadata(p).is_ok_and(|m| m.len() == 900_000))
            .unwrap_or_else(|| panic!("no 900000-byte payload in {job_dir:?}"));
        assert_eq!(
            std::fs::read(&movie).unwrap(),
            inner,
            "repaired output must be byte-identical to the posted payload"
        );
        let slot = history_slot(port, "Lane.Beside.2026", "Completed").unwrap();
        let job_dir = std::path::PathBuf::from(slot["storage"].as_str().unwrap());
        let file = std::fs::read_dir(&job_dir)
            .expect("clean job dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| std::fs::metadata(p).is_ok_and(|m| m.len() == 4_000_001))
            .unwrap_or_else(|| panic!("no 4000001-byte payload in {job_dir:?}"));
        assert_eq!(
            std::fs::read(&file).unwrap(),
            clean,
            "the clean job beside a repairing tail must land byte-identical"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Restart mid-`Finishing` (design point 5.2): kill the daemon while a
/// job's tail is stalled open, prove the persisted record says
/// "Finishing", and prove a fresh daemon loads it as Queued and runs it
/// to a byte-valid completion.
#[tokio::test(flavor = "multi_thread")]
async fn restart_mid_finishing_requeues_and_completes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-lanerst-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(300_001, 7);
    let mut articles = HashMap::new();
    let segs = make_file_articles("Lane.Restart.2026.mkv", &data, 40_000, "lr", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let xml = nzb_xml("Lane.Restart.2026.mkv", &segs, None);

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
    let build = |stall_ms: u64, cfg: std::path::PathBuf, out: std::path::PathBuf| {
        move |port: u16| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_OPEN", "1")
                .env("NZBFAST_NO_ENRICH", "1")
                .env("NZBFAST_TEST_STALL_TAIL_MS", stall_ms.to_string())
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
                .arg(&out);
            c
        }
    };
    let d = serve(&dir, build(30_000, cfg.clone(), dir.join("complete"))).await;
    let port = d.port;
    let dir3 = dir.clone();
    let spool = dir.join(".spool").join("queue.json");
    // Wait for the row to enter the lane AND for that to reach the
    // durable record, then kill the daemon mid-tail. Both, because the
    // lane sets `Finishing` on the job and only then calls save_queue:
    // the API can show a finishing row a beat before queue.json carries
    // one, and on a loaded box that beat is long enough to SIGKILL
    // inside (this test's first-attempt failure, 8 Aug 2026, where the
    // persisted record was still the "Queued" snapshot from the add).
    let persisted = spool.clone();
    tokio::task::spawn_blocking(move || {
        add_nzb(port, "Lane.Restart.2026", &xml);
        for i in 0..200 {
            let q = queue_payload(port);
            let finishing = q["slots"]
                .as_array()
                .is_some_and(|s| s.iter().any(|s| s["finishing"] == true));
            let saved = std::fs::read_to_string(&persisted).unwrap_or_default();
            if finishing && saved.contains("\"Finishing\"") {
                return;
            }
            assert!(
                i < 199,
                "job never reached a persisted Finishing state\n\
                 --- queue payload ---\n{q}\n--- queue.json ---\n{saved}"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    })
    .await
    .unwrap();
    // SIGKILL mid-Finishing. The log guard outlives the daemon, so the
    // assertions below still print it if they fail.
    let _log = d.stop();

    // The persisted record carries the new state, intact through the
    // kill (the write is atomic, so a SIGKILL mid-save leaves the
    // previous record, never a half-written one)...
    let queue_json = std::fs::read_to_string(&spool).expect("queue.json");
    assert!(
        queue_json.contains("\"Finishing\""),
        "queue.json does not record the Finishing state:\n{queue_json}"
    );

    // ...and a fresh daemon (no stall this time) loads it as Queued,
    // replays the journal and completes byte-identical.
    let d = serve(&dir, build(0, cfg, dir3.join("complete"))).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let mut slot = serde_json::Value::Null;
        for _ in 0..300 {
            if let Some(s) = history_slot(port, "Lane.Restart.2026", "Completed") {
                slot = s;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        let job_dir = std::path::PathBuf::from(slot["storage"].as_str().unwrap());
        let file = std::fs::read_dir(&job_dir)
            .expect("job dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| std::fs::metadata(p).is_ok_and(|m| m.len() == 300_001))
            .unwrap_or_else(|| panic!("no 300001-byte payload in {job_dir:?}"));
        assert_eq!(
            std::fs::read(&file).unwrap(),
            data,
            "post-restart output must be byte-identical"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Backpressure (design point 3): lane width 1 (settings.json), four
/// jobs whose tails are stalled open. The worker must stop picking with
/// `hold.reason == "postproc"` once running+waiting reaches 2x width,
/// then resume and drain everything to Completed.
#[tokio::test(flavor = "multi_thread")]
async fn saturated_lane_pauses_picks_with_stated_reason_then_drains() {
    let dir = std::env::temp_dir().join(format!("nzbfast-lanebp-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let mut jobs: Vec<(String, String, Vec<u8>)> = Vec::new();
    for i in 0..4u8 {
        let name = format!("Lane.Backpressure.{i}.2026.mkv");
        let stem = format!("Lane.Backpressure.{i}.2026");
        let data = payload(120_001, 40 + i);
        let segs = make_file_articles(&name, &data, 40_000, &format!("lb{i}"), &mut articles);
        jobs.push((stem, nzb_xml(&name, &segs, None), data));
    }
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
    // Lane width 1 -> backpressure bound 2. settings.json is the only
    // home the knob has (deliberately no UI row yet).
    std::fs::write(dir.join("settings.json"), "{\"postproc_jobs\":1}\n").unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_TEST_STALL_TAIL_MS", "5000")
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

    tokio::task::spawn_blocking(move || {
        for (stem, xml, _) in &jobs {
            add_nzb(port, stem, xml);
        }
        // With 5 s tails and near-instant downloads the lane saturates
        // after two jobs drain; the hold must appear, named.
        let mut saw_hold = false;
        for _ in 0..600 {
            let q = queue_payload(port);
            if q["hold"]["reason"] == "postproc" {
                saw_hold = true;
            }
            let all_done = jobs
                .iter()
                .all(|(stem, _, _)| history_slot(port, stem, "Completed").is_some());
            if all_done {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            saw_hold,
            "the postproc backpressure hold never surfaced in the queue payload"
        );
        // Everything drains: the hold is backpressure, not a wedge.
        for (stem, _, data) in &jobs {
            let slot = history_slot(port, stem, "Completed")
                .unwrap_or_else(|| panic!("{stem} never completed"));
            let job_dir = std::path::PathBuf::from(slot["storage"].as_str().unwrap());
            let file = std::fs::read_dir(&job_dir)
                .expect("job dir")
                .flatten()
                .map(|e| e.path())
                .find(|p| std::fs::metadata(p).is_ok_and(|m| m.len() == 120_001))
                .unwrap_or_else(|| panic!("no 120001-byte payload in {job_dir:?}"));
            assert_eq!(
                std::fs::read(&file).unwrap(),
                *data,
                "{stem}: output must be byte-identical"
            );
        }
        // And once drained the hold is gone. Not at the same instant
        // though: a tail's last act is filing the job to history, while
        // the hold is withdrawn by the guard loop, which publishes its
        // snapshot and then sleeps a second before re-reading the lane.
        // The last two tails can both park inside one of those sleeps,
        // so "every job Completed" is routinely true while the
        // published hold is still the snapshot taken before they parked
        // (this assertion's first-attempt failure under a loaded
        // parallel run, 8 Aug 2026). Wait on the condition itself,
        // bounded far above that 1 s cadence so a hold that is actually
        // wedged still fails here.
        let t = std::time::Instant::now();
        let mut q = queue_payload(port);
        while q["hold"]["reason"] == "postproc" && t.elapsed().as_secs() < 10 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            q = queue_payload(port);
        }
        assert_ne!(
            q["hold"]["reason"],
            "postproc",
            "the hold must clear once the lane drains, still held {:.1} s \
             after the last job completed: {q}",
            t.elapsed().as_secs_f64()
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
