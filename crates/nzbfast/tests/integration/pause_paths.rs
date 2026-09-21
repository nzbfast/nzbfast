//! A pause must stop the wire, on EVERY path that puts bytes on it, and
//! the page must never say `paused` over a transfer without saying why.
//!
//! The report (21 Sep 2026): the dashboard's Pause flipped the header to
//! "paused" and showed Resume while the download went on at 110-120 MB/s
//! for minutes. `daemon.log` carried one line from the pause path and the
//! wind-down's own per-job line never appeared, so the pause had matched
//! NO job. The persisted queue answers why: the job was `priority: 2`.
//! The row's download-anyway button (which a held duplicate offers) writes
//! Force, and Force runs through a queue pause by SAB semantics - that is
//! `pick_job`'s rule and it stands. What was wrong is what surrounded it:
//!
//! - the header, the pause answer and the log all said `paused` and
//!   nothing else (`pause_exempt` now names the jobs it did not stop);
//! - pausing the Force job BY NAME set its flag and answered success and
//!   left it transferring, because the wind-down asked `priority < 2` and
//!   never whether the job carried its own pause;
//! - the idle-server prefetch runs a still-Queued record on a hub of its
//!   own, which neither the state test nor the hub signal reaches, so an
//!   early start kept pulling the NEXT job's articles through a pause for
//!   as long as a Force primary ran.
//!
//! The way OUT of Force is here too (`unforcing_*`, and the copy that goes
//! back on hold): withdrawing the exemption from a running job under a
//! queue pause has to stop its wire, and with no pause it must not.
//!
//! One test per way onto the wire: a Force job paused by name, a queue
//! pause over a Force job (the exemption stands and is named), a released
//! duplicate under a queue pause (ordinary and Force), the drain-behind of
//! a hand-over, and the prefetch sidecar under a Force primary. The plain
//! single job is `pause_suspends_active_download` in tests/daemon.rs.
//!
//! OFFLINE is the other wind-down, and it exempts nobody: Force runs
//! through a PAUSE and must not run through OFFLINE (TODO 65 - the
//! runner already refuses to START a Force job under it). Three more
//! tests: a Force job on the wire when Offline is pressed (stopped, kept
//! in the queue, resumed by Online), the same job running through a
//! pause, and a Force primary with a Force early start.
//!
//! The witness is the mock server's own request log: a wire that has
//! stopped stops being asked for articles, whatever the queue says.

use crate::harness::serve;
use crate::scratch;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nzbkit::mock::{Chaos, MockServer, make_file_articles};

const ART: usize = 20_000;
/// 500 articles at 100 ms over two connections is ~25 s of transfer: far
/// longer than any assertion below waits, so a transfer nobody stopped is
/// still going when they have all run - and one that stopped has visibly
/// left most of the set unfetched.
const ARTICLES: usize = 500;
const CUT_SHORT: usize = ARTICLES / 2;

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
        .collect()
}

fn http(port: u16, req: &str, body: Option<(&str, &[u8])>) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req, body) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(Duration::from_millis(100 * u64::from(attempt) + 50));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

fn http_once(port: u16, req: &str, body: Option<(&str, &[u8])>) -> std::io::Result<String> {
    let mut request = Vec::new();
    match body {
        None => write!(
            request,
            "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .unwrap(),
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

fn json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("not JSON ({e}): {s}"))
}

fn nzb_xml(subject: &str, segs: &[(String, u64, u32)]) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{subject}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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

/// Add an NZB and return its `nzo_id`. `extra` is appended to the query
/// (`&priority=2`).
fn add_nzb(port: u16, name: &str, xml: &str, extra: &str) -> String {
    let boundary = "----pausepaths";
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
        &format!("/api?mode=addfile&apikey=sekrit&output=json{extra}"),
        Some((&ctype, &body)),
    );
    json(&r)["nzo_ids"][0]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no nzo_id in {r}"))
}

fn queue(port: u16) -> serde_json::Value {
    json(&http(
        port,
        "/api?mode=queue&apikey=sekrit&output=json",
        None,
    ))["queue"]
        .clone()
}

fn slot(port: u16, id: &str) -> Option<serde_json::Value> {
    queue(port)["slots"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
}

fn status_of(port: u16, id: &str) -> String {
    slot(port, id)
        .and_then(|s| s["status"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn history_has(port: u16, id: &str) -> bool {
    let h = json(&http(
        port,
        "/api?mode=history&apikey=sekrit&output=json",
        None,
    ));
    h["history"]["slots"]
        .as_array()
        .is_some_and(|a| a.iter().any(|s| s["nzo_id"] == id))
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(60) {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting: {what}");
}

type Wire = Arc<Mutex<nzbkit::mock::BodyLog>>;

/// Distinct articles of the set tagged `tag` this server was asked for.
/// Deduplicated because a hedge duplicate is the same article twice.
fn asked_for(wire: &Wire, tag: &str) -> usize {
    wire.lock()
        .unwrap()
        .iter()
        .filter(|id| id.starts_with(tag))
        .collect::<HashSet<_>>()
        .len()
}

/// Wait for the wire to fall silent and return how many distinct articles
/// it was asked for by then. `quiet` outlasts one slow body: a graceful
/// wind-down admits nothing new but lets the in-flight window land. A
/// wire nobody stopped never goes quiet inside the bound.
fn wait_for_quiet_wire(wire: &Wire, tag: &str) -> usize {
    let quiet = Duration::from_secs(2);
    let mut last = asked_for(wire, tag);
    let mut since = Instant::now();
    let t0 = Instant::now();
    loop {
        let n = asked_for(wire, tag);
        if n != last {
            last = n;
            since = Instant::now();
        }
        if since.elapsed() >= quiet {
            return n;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(25),
            "the wire for {tag} never went quiet - {n} articles asked for and still \
             climbing, so the pause never reached the transfer"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Is the wire still moving? True as soon as a new article is asked for.
fn wire_moves_within(wire: &Wire, tag: &str, within: Duration) -> bool {
    let n0 = asked_for(wire, tag);
    let t0 = Instant::now();
    while t0.elapsed() < within {
        if asked_for(wire, tag) > n0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

struct Rig {
    port: u16,
    wire: Wire,
    /// The big job's NZB, tag `pp`.
    xml: String,
    /// A one-article job on the same server, tag `aa`, that finishes at once.
    a_xml: String,
    _srv: MockServer,
    _d: crate::harness::Daemon,
    _scratch: scratch::ScratchDir,
}

const TAG: &str = "<pp-";

/// One daemon, one provider serving a 500-article file at 100 ms a body.
async fn rig(tag: &str) -> Rig {
    let dir = std::env::temp_dir().join(format!("nzbfast-pausepaths-{tag}-{}", std::process::id()));
    let scratch = scratch::ScratchDir::attach(&dir);
    let bytes = payload(ART * ARTICLES, 51);
    let mut articles = HashMap::new();
    let segs = make_file_articles("pp.bin", &bytes, ART, "pp", &mut articles);
    let a_segs = make_file_articles("a.bin", &payload(ART, 7), ART, "aa", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 100,
            ..Chaos::default()
        },
    )
    .await;
    let wire = srv.body_log.clone();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":2}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_LOG", "info")
            .env_remove("RUST_LOG")
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
            .arg("2");
        c
    })
    .await;
    Rig {
        port: d.port,
        wire,
        xml: nzb_xml("pp.bin", &segs),
        a_xml: nzb_xml("a.bin", &a_segs),
        _srv: srv,
        _d: d,
        _scratch: scratch,
    }
}

/// Start the big job at `extra` (a query suffix) and return once it is
/// Downloading and demonstrably asking for articles.
fn start_big(rig: &Rig, name: &str, extra: &str) -> String {
    let id = add_nzb(rig.port, name, &rig.xml, extra);
    wait_until("the job never started downloading", || {
        status_of(rig.port, &id) == "Downloading"
    });
    wait_until("the job never asked for an article", || {
        asked_for(&rig.wire, TAG) > 10
    });
    id
}

/// PAUSING A FORCE JOB BY NAME STOPS IT. Force outranks a QUEUE pause and
/// never the job's own: `pick_job` has always skipped a job that carries
/// its own flag at any priority, and the wind-down now reads the same
/// rule. Before, the row answered success, read `Downloading`, and pulled
/// the rest of the set at line rate.
#[tokio::test(flavor = "multi_thread")]
async fn a_force_job_paused_by_name_stops_its_wire() {
    let rig = rig("byname").await;
    let (port, wire) = (rig.port, rig.wire.clone());
    tokio::task::spawn_blocking(move || {
        let id = start_big(&rig, "forced", "&priority=2");
        let r = json(&http(
            port,
            &format!("/api?mode=queue&name=pause&value={id}&apikey=sekrit&output=json"),
            None,
        ));
        assert_eq!(r["status"], true, "{r}");

        let seen = wait_for_quiet_wire(&wire, TAG);
        assert!(
            seen <= CUT_SHORT,
            "pausing the Force job by name did not cut its transfer short: \
             {seen} of {ARTICLES} articles"
        );
        wait_until("the paused job never read Paused", || {
            status_of(port, &id) == "Paused"
        });
        assert!(
            !history_has(port, &id),
            "a paused job must not reach history"
        );
    })
    .await
    .unwrap();
}

/// A QUEUE PAUSE OVER A FORCE JOB: the exemption stands (that is SAB's
/// rule and not this change's to move) and is NAMED - in the pause's own
/// answer and in the queue the header is drawn from - so a page can say
/// what is still moving instead of a bare `paused`. Pausing the job by
/// name then stops it, and the list empties with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_queue_pause_names_the_force_job_it_leaves_running() {
    let rig = rig("exempt").await;
    let (port, wire) = (rig.port, rig.wire.clone());
    tokio::task::spawn_blocking(move || {
        let id = start_big(&rig, "forced", "&priority=2");

        let r = json(&http(
            port,
            "/api?mode=pause&apikey=sekrit&output=json",
            None,
        ));
        assert_eq!(r["status"], true, "{r}");
        assert_eq!(
            r["pause_exempt"],
            serde_json::json!([id]),
            "the pause's answer must name the job it did not stop: {r}"
        );

        let q = queue(port);
        assert_eq!(q["paused"], true, "{q}");
        assert_eq!(q["pause_exempt"], serde_json::json!([id]), "{q}");
        assert_eq!(
            status_of(port, &id),
            "Downloading",
            "the row must not claim a pause it is not under"
        );
        assert!(
            wire_moves_within(&wire, TAG, Duration::from_secs(3)),
            "Force runs through a queue pause; the wire stopped"
        );

        // The way to stop it is the job's own pause, and the list agrees.
        let r = json(&http(
            port,
            &format!("/api?mode=queue&name=pause&value={id}&apikey=sekrit&output=json"),
            None,
        ));
        assert_eq!(r["status"], true, "{r}");
        let seen = wait_for_quiet_wire(&wire, TAG);
        assert!(seen <= CUT_SHORT, "{seen} of {ARTICLES} articles");
        wait_until("the exemption list never emptied", || {
            queue(port)["pause_exempt"] == serde_json::json!([])
        });

        // ...and a resume clears it as well as everything else.
        http(port, "/api?mode=resume&apikey=sekrit&output=json", None);
        assert_eq!(queue(port)["pause_exempt"], serde_json::json!([]));
    })
    .await
    .unwrap();
}

/// A queue pause names nothing when nothing is exempt - the field is a
/// statement about a pause in force, not a constant.
#[tokio::test(flavor = "multi_thread")]
async fn a_queue_pause_over_an_ordinary_job_exempts_nothing_and_stops_it() {
    let rig = rig("plain").await;
    let (port, wire) = (rig.port, rig.wire.clone());
    tokio::task::spawn_blocking(move || {
        let id = start_big(&rig, "plain", "");
        let r = json(&http(
            port,
            "/api?mode=pause&apikey=sekrit&output=json",
            None,
        ));
        assert_eq!(r["status"], true, "{r}");
        assert_eq!(r["pause_exempt"], serde_json::json!([]), "{r}");
        let seen = wait_for_quiet_wire(&wire, TAG);
        assert!(seen <= CUT_SHORT, "{seen} of {ARTICLES} articles");
        // Parked back in the queue under a paused queue: not on the wire,
        // and not filed anywhere. (A queue pause reads `Queued` on the
        // row once the wind-down has parked it; `Paused` is the per-job
        // word, tested above.)
        wait_until("the job never left Downloading", || {
            status_of(port, &id) != "Downloading"
        });
        assert!(!history_has(port, &id));
        assert_eq!(queue(port)["pause_exempt"], serde_json::json!([]));
    })
    .await
    .unwrap();
}

/// THE REPORTED SHAPE, both ways: a duplicate the daemon held is released
/// and then the queue is paused.
///
/// `ordinary` releases it with a plain priority write (the drawer's
/// select), which is an ordinary job and stops. `force` releases it the
/// way the row's download-anyway button does - Force, then resume - which
/// is what the user pressed: the pause then names it and it keeps going.
async fn released_duplicate_then_pause(tag: &str, force: bool) {
    let rig = rig(tag).await;
    let (port, wire) = (rig.port, rig.wire.clone());
    tokio::task::spawn_blocking(move || {
        // A finishes at once, so B (same episode, so a duplicate of a
        // completed download) is held rather than queued.
        let a_id = add_nzb(port, "Show.Name.S03E04.720p.WEB", &rig.a_xml, "");
        wait_until("A never left the queue", || history_has(port, &a_id));

        let b_id = add_nzb(port, "Show.Name.S03E04.1080p.WEB", &rig.xml, "");
        wait_until("B was never held as a duplicate", || {
            slot(port, &b_id).is_some_and(|s| s["status"] == "Paused")
        });

        if force {
            let r = json(&http(
                port,
                &format!(
                    "/api?mode=queue&name=priority&value={b_id}&value2=2&apikey=sekrit&output=json"
                ),
                None,
            ));
            assert_eq!(r["status"], true, "{r}");
            let r = json(&http(
                port,
                &format!("/api?mode=queue&name=resume&value={b_id}&apikey=sekrit&output=json"),
                None,
            ));
            assert_eq!(r["status"], true, "{r}");
        } else {
            let r = json(&http(
                port,
                &format!(
                    "/api?mode=queue&name=priority&value={b_id}&value2=1&apikey=sekrit&output=json"
                ),
                None,
            ));
            assert_eq!(r["status"], true, "{r}");
        }
        wait_until("the released duplicate never downloaded", || {
            status_of(port, &b_id) == "Downloading" && asked_for(&wire, TAG) > 10
        });

        let r = json(&http(
            port,
            "/api?mode=pause&apikey=sekrit&output=json",
            None,
        ));
        assert_eq!(r["status"], true, "{r}");
        if force {
            assert_eq!(r["pause_exempt"], serde_json::json!([b_id]), "{r}");
            assert!(
                wire_moves_within(&wire, TAG, Duration::from_secs(3)),
                "a Force job runs through a queue pause"
            );
            assert_eq!(queue(port)["pause_exempt"], serde_json::json!([b_id]));
        } else {
            assert_eq!(r["pause_exempt"], serde_json::json!([]), "{r}");
            let seen = wait_for_quiet_wire(&wire, TAG);
            assert!(
                seen <= CUT_SHORT,
                "the released duplicate went on downloading through a queue pause: \
                 {seen} of {ARTICLES} articles"
            );
            wait_until("the duplicate never left Downloading", || {
                status_of(port, &b_id) != "Downloading"
            });
            assert!(!history_has(port, &b_id));
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_released_duplicate_stops_on_a_queue_pause() {
    released_duplicate_then_pause("dupe-plain", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_duplicate_released_with_download_anyway_is_named_by_a_queue_pause() {
    released_duplicate_then_pause("dupe-force", true).await;
}

/// `mode=queue&name=priority` exactly as the page's stop-forcing button
/// and the drawer's select send it. The answer is the daemon's.
fn set_priority(port: u16, id: &str, value: i32) -> serde_json::Value {
    json(&http(
        port,
        &format!(
            "/api?mode=queue&name=priority&value={id}&value2={value}&apikey=sekrit&output=json"
        ),
        None,
    ))
}

/// STOPPING A FORCE UNDER A QUEUE PAUSE. The exemption is Force's own, so
/// a user who withdraws it is asking the pause to apply - and before, the
/// priority write changed a number, answered success and left the job at
/// line rate under a `paused` header. Now the wire stops, the row stays in
/// the queue at Normal (no restart, no delete, nothing in history), the
/// header's exemption list empties, and a resume carries on from the
/// journal.
#[tokio::test(flavor = "multi_thread")]
async fn unforcing_a_running_job_under_a_queue_pause_stops_its_wire() {
    let rig = rig("unforce").await;
    let (port, wire) = (rig.port, rig.wire.clone());
    tokio::task::spawn_blocking(move || {
        let id = start_big(&rig, "forced", "&priority=2");
        // What the row is badged from, before and after.
        assert_eq!(slot(port, &id).unwrap()["priority"], "Force");

        let r = json(&http(
            port,
            "/api?mode=pause&apikey=sekrit&output=json",
            None,
        ));
        assert_eq!(r["pause_exempt"], serde_json::json!([id]), "{r}");
        assert!(
            wire_moves_within(&wire, TAG, Duration::from_secs(3)),
            "Force runs through a queue pause; the setup is not the report"
        );

        let r = set_priority(port, &id, 0);
        assert_eq!(r["status"], true, "{r}");

        let seen = wait_for_quiet_wire(&wire, TAG);
        assert!(
            seen <= CUT_SHORT,
            "the wire kept going after the Force was withdrawn: \
             {seen} of {ARTICLES} articles"
        );
        wait_until("the job never left Downloading", || {
            status_of(port, &id) != "Downloading"
        });
        let s = slot(port, &id).expect("the row must stay in the queue");
        assert_eq!(s["priority"], "Normal", "{s}");
        assert!(!history_has(port, &id), "stopping a Force is not the end");
        wait_until("the exemption list never emptied", || {
            queue(port)["pause_exempt"] == serde_json::json!([])
        });

        // ...and a resume carries on rather than starting over.
        let before = asked_for(&wire, TAG);
        http(port, "/api?mode=resume&apikey=sekrit&output=json", None);
        wait_until("the job never resumed", || {
            status_of(port, &id) == "Downloading"
        });
        assert!(
            wire_moves_within(&wire, TAG, Duration::from_secs(10)),
            "the resumed job never asked for another article"
        );
        assert!(asked_for(&wire, TAG) > before);
    })
    .await
    .unwrap();
}

/// The other half: with NO pause in force, withdrawing Force is a
/// re-ranking and never an interruption.
#[tokio::test(flavor = "multi_thread")]
async fn unforcing_with_no_queue_pause_leaves_the_transfer_running() {
    let rig = rig("unforce-live").await;
    let (port, wire) = (rig.port, rig.wire.clone());
    tokio::task::spawn_blocking(move || {
        let id = start_big(&rig, "forced", "&priority=2");
        let r = set_priority(port, &id, 0);
        assert_eq!(r["status"], true, "{r}");
        assert_eq!(slot(port, &id).unwrap()["priority"], "Normal");
        assert!(
            wire_moves_within(&wire, TAG, Duration::from_secs(3)),
            "a priority write stopped a transfer nothing had paused"
        );
        assert_eq!(status_of(port, &id), "Downloading");
    })
    .await
    .unwrap();
}

/// A copy released with download-anyway (Force, then resume) can go BACK
/// to its hold: Duplicate priority on a row that was held for another is
/// the hold again. A running one stops; the row reads as the held
/// alternative it was, and is neither deleted nor in history.
#[tokio::test(flavor = "multi_thread")]
async fn a_forced_duplicate_goes_back_on_hold_and_stops() {
    let rig = rig("rehold").await;
    let (port, wire) = (rig.port, rig.wire.clone());
    tokio::task::spawn_blocking(move || {
        let a_id = add_nzb(port, "Show.Name.S03E04.720p.WEB", &rig.a_xml, "");
        wait_until("A never left the queue", || history_has(port, &a_id));
        let b_id = add_nzb(port, "Show.Name.S03E04.1080p.WEB", &rig.xml, "");
        wait_until("B was never held as a duplicate", || {
            slot(port, &b_id).is_some_and(|s| s["status"] == "Paused")
        });
        let held = slot(port, &b_id).unwrap();
        assert!(
            !held["held_for"].as_str().unwrap_or("").is_empty(),
            "{held}"
        );

        // Download anyway, exactly as the page's button does it.
        assert_eq!(set_priority(port, &b_id, 2)["status"], true);
        let r = json(&http(
            port,
            &format!("/api?mode=queue&name=resume&value={b_id}&apikey=sekrit&output=json"),
            None,
        ));
        assert_eq!(r["status"], true, "{r}");
        wait_until("the released duplicate never downloaded", || {
            status_of(port, &b_id) == "Downloading" && asked_for(&wire, TAG) > 10
        });
        let running = slot(port, &b_id).unwrap();
        assert_eq!(running["priority"], "Force", "{running}");
        assert_eq!(running["labels"], serde_json::json!([]), "{running}");

        // ...and back. No queue pause: the row's own hold is the pause.
        let r = set_priority(port, &b_id, -3);
        assert_eq!(r["status"], true, "{r}");
        let seen = wait_for_quiet_wire(&wire, TAG);
        assert!(
            seen <= CUT_SHORT,
            "the hold left the copy downloading: {seen} of {ARTICLES} articles"
        );
        wait_until("the copy never read as held again", || {
            slot(port, &b_id).is_some_and(|s| s["status"] == "Paused")
        });
        let back = slot(port, &b_id).unwrap();
        assert_eq!(back["labels"], serde_json::json!(["ALTERNATIVE"]), "{back}");
        assert!(!history_has(port, &b_id));
    })
    .await
    .unwrap();
}

/// The early-start rig: two providers, a Force-or-not primary on the slow
/// one and a second job the idle fast one starts early.
///
/// Slow server: ONLY A's articles, 250 ms each (~37 s of transfer at two
/// connections). Fast server: ONLY B's, 100 ms each (~20 s). A's copies
/// of B's articles are what make the fast server idle for A.
struct Side {
    port: u16,
    slow_wire: Wire,
    fast_wire: Wire,
    a_xml: String,
    b_xml: String,
    log_path: std::path::PathBuf,
    _slow: MockServer,
    _fast: MockServer,
    _d: crate::harness::Daemon,
    _scratch: scratch::ScratchDir,
}

async fn side_rig(tag: &str) -> Side {
    let dir = std::env::temp_dir().join(format!("nzbfast-pausepaths-{tag}-{}", std::process::id()));
    let scratch = scratch::ScratchDir::attach(&dir);
    let mut slow_articles = HashMap::new();
    let a_segs = make_file_articles(
        "sideA.bin",
        &payload(ART * 300, 61),
        ART,
        "sa",
        &mut slow_articles,
    );
    let mut fast_articles = HashMap::new();
    let b_segs = make_file_articles(
        "sideB.bin",
        &payload(ART * 400, 63),
        ART,
        "sb",
        &mut fast_articles,
    );
    let slow = MockServer::start(
        slow_articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;
    let fast = MockServer::start(
        fast_articles,
        Chaos {
            delay_ms: 100,
            ..Chaos::default()
        },
    )
    .await;
    let (slow_wire, fast_wire) = (slow.body_log.clone(), fast.body_log.clone());
    let cfg = dir.join("config.json");
    // Distinct HOST STRINGS for the two loopback mocks: host is server
    // identity throughout, and the sidecar's busy-host exclusion must not
    // catch the idle one.
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}},{{\"host\":\"localhost\",\"port\":{},\"tls\":false}}]}}",
            slow.addr.port(),
            fast.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_LOG", "info")
            .env_remove("RUST_LOG")
            .env("NZBFAST_DEFER_WARMUP_SECS", "2")
            // The sidecar is the subject: with the cross-job hand-over on,
            // the idle server's connections go to the next job as a
            // first-class start before the sidecar's window ever opens.
            .env("NZBFAST_QUEUE_HANDOFF", "0")
            .env("NZBFAST_DEFER_WINDOW_SECS", "3")
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
            .arg("2");
        c
    })
    .await;
    Side {
        port: d.port,
        slow_wire,
        fast_wire,
        a_xml: nzb_xml("sideA.bin", &a_segs),
        b_xml: nzb_xml("sideB.bin", &b_segs),
        log_path: d.log_path(),
        _slow: slow,
        _fast: fast,
        _d: d,
        _scratch: scratch,
    }
}

/// A runs on the slow server at `a_extra`; B is queued behind it and the
/// idle fast server starts it early. Returns `(a_id, b_id)` once B's early
/// start is demonstrably asking for articles.
fn start_early_start(side: &Side, a_extra: &str, b_extra: &str) -> (String, String) {
    let port = side.port;
    let a_id = add_nzb(port, "sideA", &side.a_xml, a_extra);
    wait_until("A never started downloading", || {
        status_of(port, &a_id) == "Downloading"
    });
    let b_id = add_nzb(port, "sideB", &side.b_xml, b_extra);
    wait_until("B was never started early", || {
        slot(port, &b_id).is_some_and(|s| s["prefetching"] == true)
    });
    wait_until("the early start never asked for an article", || {
        asked_for(&side.fast_wire, "<sb-") > 10
    });
    (a_id, b_id)
}

/// THE EARLY START. The idle-server prefetch runs the NEXT job on a hub
/// and a fleet of its own, as a still-Queued record: the wind-down's state
/// test and its hub signal both miss it, and only the runner's job-end
/// `stop_sidecar` ever stopped it. With an ordinary primary that is a few
/// seconds late. With a Force primary - which a queue pause leaves running -
/// the job end never comes, so the early start went on pulling the next
/// job's articles through the pause for as long as the primary ran.
///
/// A is Force on the slow server; B waits on the fast one and is started
/// early on it. The queue pause stops B's wire and leaves A's alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_queue_pause_stops_the_early_start_beside_a_force_primary() {
    let side = side_rig("side").await;
    tokio::task::spawn_blocking(move || {
        let port = side.port;
        let (a_id, b_id) = start_early_start(&side, "&priority=2", "");

        let r = json(&http(
            port,
            "/api?mode=pause&apikey=sekrit&output=json",
            None,
        ));
        assert_eq!(r["status"], true, "{r}");
        assert_eq!(
            r["pause_exempt"],
            serde_json::json!([a_id]),
            "the Force primary is the one job the pause leaves running: {r}"
        );

        let seen = wait_for_quiet_wire(&side.fast_wire, "<sb-");
        assert!(
            seen < 400,
            "the early start finished the whole job through a queue pause: {seen} of 400"
        );
        assert!(
            seen <= 200,
            "the queue pause did not cut the early start short: {seen} of 400 articles"
        );
        // Force runs through the pause, so A's wire is still moving.
        assert!(
            wire_moves_within(&side.slow_wire, "<sa-", Duration::from_secs(3)),
            "the Force primary stopped with the queue pause"
        );
        let log = std::fs::read_to_string(&side.log_path).unwrap_or_default();
        assert!(
            log.contains(&format!("[prefetch] {b_id} wound down")),
            "the early start's wind-down is not in the log:\n{log}"
        );
    })
    .await
    .unwrap();
}

/// OFFLINE OUTRANKS FORCE (TODO 65) - and the runner's start gate is only
/// half of that. The confirm dialog promises every connection is closed
/// "so you can use the account from another machine", and the gate keeps
/// a Force job from STARTING under Offline. A Force job already
/// transferring when Offline was pressed is the other half: the wind-down
/// spared it, as it must for a plain PAUSE, so the dot went red, the
/// call answered success, and the whole fleet stayed connected - the
/// operator's other machine was then refused at the account's connection
/// cap. This pins the whole arc on the wire: Offline stops a Force job,
/// keeps it in the queue, says so in the log and in the payload, holds it
/// quiet, and going Online resumes the SAME job.
#[tokio::test(flavor = "multi_thread")]
async fn going_offline_stops_a_force_jobs_wire_and_going_online_resumes_it() {
    let rig = rig("offforce").await;
    let (port, wire) = (rig.port, rig.wire.clone());
    let log_path = rig._d.log_path();
    tokio::task::spawn_blocking(move || {
        let id = start_big(&rig, "forced", "&priority=2");

        let r = json(&http(
            port,
            "/api?mode=offline&apikey=sekrit&output=json",
            None,
        ));
        assert_eq!(r["offline"], true, "{r}");

        let seen = wait_for_quiet_wire(&wire, TAG);
        assert!(
            seen <= CUT_SHORT,
            "Offline did not stop the Force job's transfer: {seen} of {ARTICLES} articles"
        );
        // Parked, not failed and not filed: it is still the same queue row.
        wait_until("the Force job never left Downloading", || {
            status_of(port, &id) != "Downloading"
        });
        assert!(
            slot(port, &id).is_some(),
            "the job left the queue instead of parking in it"
        );
        assert!(!history_has(port, &id), "offline must not file the job");
        // The header must not say forced downloads keep running under
        // Offline: nothing is exempt, so nothing is named.
        let q = queue(port);
        assert_eq!(q["offline"], true, "{q}");
        assert_eq!(q["pause_exempt"], serde_json::json!([]), "{q}");
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            log.contains(&format!("{id} is Force priority and is stopped anyway")),
            "the offline wind-down did not name the Force job it stopped:\n{log}"
        );
        // ...and it stays quiet for as long as we are offline.
        assert!(
            !wire_moves_within(&wire, TAG, Duration::from_secs(4)),
            "the Force job went back on the wire while offline"
        );

        // Coming back online resumes the same job from where it stopped.
        let r = json(&http(
            port,
            "/api?mode=online&apikey=sekrit&output=json",
            None,
        ));
        assert_eq!(r["offline"], false, "{r}");
        wait_until("the Force job never resumed after going online", || {
            status_of(port, &id) == "Downloading"
        });
        wait_until("the resumed job never asked for another article", || {
            asked_for(&wire, TAG) > seen
        });
        assert!(!history_has(port, &id));
    })
    .await
    .unwrap();
}

/// The same, with the queue ALREADY paused: the Force job is running
/// through the pause, exactly the case a pause exempts, and Offline still
/// stops it. Coming back online must not take the user's own pause with
/// it - the queue stays paused and the Force job, which runs through a
/// pause, resumes.
#[tokio::test(flavor = "multi_thread")]
async fn going_offline_stops_a_force_job_that_is_running_through_a_pause() {
    let rig = rig("offpaused").await;
    let (port, wire) = (rig.port, rig.wire.clone());
    tokio::task::spawn_blocking(move || {
        let id = start_big(&rig, "forced", "&priority=2");
        let r = json(&http(
            port,
            "/api?mode=pause&apikey=sekrit&output=json",
            None,
        ));
        assert_eq!(r["pause_exempt"], serde_json::json!([id]), "{r}");
        assert!(
            wire_moves_within(&wire, TAG, Duration::from_secs(3)),
            "Force runs through a queue pause; the wire stopped"
        );

        http(port, "/api?mode=offline&apikey=sekrit&output=json", None);
        let seen = wait_for_quiet_wire(&wire, TAG);
        assert!(
            seen <= CUT_SHORT,
            "Offline did not stop a Force job running through a pause: \
             {seen} of {ARTICLES} articles"
        );
        assert_eq!(queue(port)["pause_exempt"], serde_json::json!([]));
        assert!(slot(port, &id).is_some() && !history_has(port, &id));

        http(port, "/api?mode=online&apikey=sekrit&output=json", None);
        let q = queue(port);
        assert_eq!(q["offline"], false, "{q}");
        assert_eq!(
            q["paused"], true,
            "coming back online must not unpause a queue the user paused: {q}"
        );
        wait_until("the Force job never resumed", || {
            asked_for(&wire, TAG) > seen
        });
    })
    .await
    .unwrap();
}

/// THE EARLY START UNDER OFFLINE, both ends Force: a Force primary on the
/// slow server and a Force job the idle fast one started early. Offline
/// stops BOTH wires - the primary through the wind-down, the early start
/// through the sidecar's own hub - where a pause leaves each running.
#[tokio::test(flavor = "multi_thread")]
async fn going_offline_stops_a_force_primary_and_its_force_early_start() {
    let side = side_rig("offside").await;
    tokio::task::spawn_blocking(move || {
        let port = side.port;
        let (a_id, b_id) = start_early_start(&side, "&priority=2", "&priority=2");

        let r = json(&http(
            port,
            "/api?mode=offline&apikey=sekrit&output=json",
            None,
        ));
        assert_eq!(r["offline"], true, "{r}");

        let seen_fast = wait_for_quiet_wire(&side.fast_wire, "<sb-");
        assert!(
            seen_fast <= 200,
            "Offline did not cut the Force early start short: {seen_fast} of 400 articles"
        );
        let seen_slow = wait_for_quiet_wire(&side.slow_wire, "<sa-");
        assert!(
            seen_slow <= 150,
            "Offline did not stop the Force primary: {seen_slow} of 300 articles"
        );
        assert!(
            !wire_moves_within(&side.fast_wire, "<sb-", Duration::from_secs(3))
                && !wire_moves_within(&side.slow_wire, "<sa-", Duration::from_secs(3)),
            "a wire came back while offline"
        );
        for id in [&a_id, &b_id] {
            assert!(slot(port, id).is_some(), "{id} left the queue");
            assert!(!history_has(port, id), "{id} was filed by going offline");
        }
        assert_eq!(queue(port)["pause_exempt"], serde_json::json!([]));
        let log = std::fs::read_to_string(&side.log_path).unwrap_or_default();
        assert!(
            log.contains(&format!("{a_id} is Force priority and is stopped anyway")),
            "the offline wind-down did not name the Force primary:\n{log}"
        );
        assert!(
            log.contains(&format!(
                "{b_id} is Force priority and its early start is stopped anyway"
            )),
            "the offline wind-down did not name the Force early start:\n{log}"
        );
    })
    .await
    .unwrap();
}
