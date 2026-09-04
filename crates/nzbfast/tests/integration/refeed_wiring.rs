//! TODO 280 (issue #54): the CALL SITE, not the feature.
//!
//! `refeed.rs` already has nine unit tests, and every one of them
//! calls `Daemon::refeed_completed` by hand with a Job built in memory.
//! They prove the judgement - the refusals, the depth cap, the sha
//! dedupe, the paused landing. None of them proves the one thing that
//! makes the feature reachable at all: that `finalize_completed_gen`
//! (job.rs, the `done_ok` arm) still calls it, on a real finished
//! download, at a moment when the payload is where the record says.
//!
//! That call sits between the unpack/sweep/rename step and the
//! destination move, and the position is load-bearing rather than
//! incidental: before the move, `out_dir` still describes where the
//! files ARE. Reorder that function, or hoist the mover above it, and
//! the feature switches off in silence - the setting stays on, the
//! dashboard checkbox stays ticked, no gate and no unit test says a
//! word. So this suite drives the whole pipeline: a real daemon, a real
//! mock server, a real download, and the assertion is made on the queue
//! the daemon publishes rather than on a return value.
//!
//! The fixture is the smallest thing that is honestly a container post:
//! ONE posted file whose decoded bytes are a valid `.nzb` document. No
//! archive, so no unpack step to go wrong, and no recovery set, so the
//! par2 gate has nothing to say about it and a box with no `par2`
//! binary runs this like any other.
//!
//! ONE POSTED FILE IS ALSO WHAT MAKES THE FIXTURE SURVIVE THE SWEEP, and
//! that is measured rather than assumed - the daemon log of a run with
//! the call site removed shows it. `nzb` is in `smart::JUNK_EXTS`, and
//! `sweep_junk` runs on this job (`rename_junk` is on by default and the
//! release classifies movie-like), so the inner NZB is classified doomed
//! before the refeed hook is reached. What saves it is the all-junk
//! guard: every file in the release is furniture, and emptying a release
//! is never the sweep's answer. That coupling is legitimate rather than
//! incidental - a lone `.nzb` IS the container post, so a sweep that
//! started eating it would have broken the feature for real - which is
//! why this test is left holding it rather than turning `rename_junk`
//! off to look away.
//!
//! The setting is off by default, which is a trap of its own: a test
//! that forgot to turn it on would find no second row and could only
//! fail with "the wiring is gone". So the read-back below asserts the
//! daemon really is holding `refeed_nzb` true BEFORE the job is added.
//! A failure there says "the setting", a failure later says "the call
//! site", and the two are never confused.
//!
//! Same discipline as the other modules here: the test owns a daemon on
//! its own port, `NZBFAST_NO_ENRICH=1` in the child's environment.

use crate::scratch;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

use crate::harness::serve;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};

/// The parent post, as it is named on the wire and on disk. Its decoded
/// bytes ARE the inner NZB, so the `.nzb` extension is the file's own
/// and not something the daemon adds.
const INNER_FILE: &str = "Inner.Refeed.Payload.nzb";

/// What the child queue row is called once `enqueue` has taken the
/// extension off, exactly as it does for a watch-folder pickup.
const CHILD_NAME: &str = "Inner.Refeed.Payload";

/// The parent job. Deliberately shares no stem with the child and
/// carries neither an SxxEyy nor a year, so `enqueue`'s duplicate hold
/// has nothing to catch and the child lands in the queue proper.
const PARENT: &str = "Refeed.Container.Post";

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

fn json(port: u16, req: &str) -> serde_json::Value {
    let r = http(port, req, None);
    serde_json::from_str(&r).unwrap_or_else(|e| panic!("{req} did not answer JSON: {e}: {r}"))
}

/// A well-formed one-file NZB document. This is the PAYLOAD - the bytes
/// the parent post carries - so it has to satisfy `Nzb::parse` after a
/// round trip through yEnc, which is most of what the wiring is for.
///
/// Its own segments name articles the mock server has never heard of,
/// and that is deliberate: the child is queued PAUSED, so nothing is
/// ever fetched for it. A child that somehow started downloading would
/// fail loudly rather than quietly pass this test.
fn inner_nzb() -> Vec<u8> {
    br#"<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <file poster="x" date="0" subject="&quot;Inner.Refeed.Payload.mkv&quot; yEnc (1/1)">
    <groups><group>g</group></groups>
    <segments>
      <segment bytes="4096" number="1">inner-refeed-1@mock</segment>
    </segments>
  </file>
</nzb>
"#
    .to_vec()
}

/// One-file NZB in the quoted-subject form every classifier here reads.
fn nzb_xml(name: &str, segs: &[(String, u64, u32)]) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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

fn add_nzb(port: u16, name: &str, xml: &str) -> String {
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
    serde_json::from_str::<serde_json::Value>(&r)
        .ok()
        .and_then(|v| v["nzo_ids"][0].as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("no nzo_id in {r}"))
}

fn queue_slots(port: u16) -> Vec<serde_json::Value> {
    json(port, "/api?mode=queue&apikey=sekrit&output=json")["queue"]["slots"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn history_status(port: u16, name: &str) -> Option<String> {
    json(port, "/api?mode=history&apikey=sekrit&output=json")["history"]["slots"]
        .as_array()
        .and_then(|s| s.iter().find(|s| s["name"] == name).cloned())
        .and_then(|s| s["status"].as_str().map(str::to_string))
}

/// `refeed_depth` off the persisted record. It is not on any HTTP
/// surface - it is a durability field, and `stamp_refeed_depth` saves
/// the queue synchronously precisely so a restart cannot forget it - so
/// the file it is saved to is where it is read from.
fn refeed_depth_of(dir: &std::path::Path, nzo: &str) -> u64 {
    let row = crate::harness::stored_job(dir, nzo).unwrap_or_else(|| {
        panic!(
            "{nzo} is not in the queue store: {}",
            crate::harness::stored_queue_text(dir)
        )
    });
    row["refeed_depth"]
        .as_u64()
        .unwrap_or_else(|| panic!("{nzo} has no refeed_depth in the queue store"))
}

/// The whole wiring in one run: a container post downloaded by a real
/// daemon leaves a second, paused row behind it.
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_container_post_leaves_its_inner_nzb_paused_in_the_queue() {
    let dir = std::env::temp_dir().join(format!("nzbfast-refeedwire-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let segs = make_file_articles(INNER_FILE, &inner_nzb(), 40_000, "rf", &mut articles);
    let xml = nzb_xml(INNER_FILE, &segs);

    let mock = MockServer::start(articles, Chaos::default()).await;
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":2}}]}}",
            mock.addr.ip(),
            mock.addr.port()
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
            .arg("2");
        c
    })
    .await;
    let port = d.port;
    let dir2 = dir.clone();

    tokio::task::spawn_blocking(move || {
        // Off by default. Turn it on, then READ IT BACK before anything
        // is queued: a test that silently ran with the feature off
        // could only report "the call site is gone", which is the one
        // sentence this suite must not say when it is wrong.
        let set = json(
            port,
            "/api?mode=config&name=refeed_nzb&value=1&apikey=sekrit&output=json",
        );
        assert_eq!(set["status"], true, "setting refeed_nzb: {set}");
        let cfgv = json(port, "/api?mode=get_config&apikey=sekrit&output=json");
        assert_eq!(
            cfgv["config"]["nzbfast"]["refeed_nzb"], true,
            "the daemon is not holding refeed_nzb on, so nothing below would mean anything: {}",
            cfgv["config"]["nzbfast"]
        );

        let parent = add_nzb(port, PARENT, &xml);

        // The parent runs the real pipeline: fetch, decode, the whole
        // completed tail. It is in history when that tail has finished.
        let mut status = None;
        for _ in 0..300 {
            status = history_status(port, PARENT);
            if status.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            status.as_deref(),
            Some("Completed"),
            "the parent never completed, so the refeed was never reached"
        );

        // The child is queued from inside that tail, so it may land a
        // beat after the history row appears.
        let mut child = None;
        for _ in 0..100 {
            let slots = queue_slots(port);
            if let Some(s) = slots.iter().find(|s| s["nzo_id"] != parent.as_str()) {
                child = Some(s.clone());
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let child = child.unwrap_or_else(|| {
            panic!(
                "no second queue row after {PARENT} completed - finalize_completed_gen did not \
                 reach refeed_completed. Queue: {:?}",
                queue_slots(port)
            )
        });

        assert_eq!(child["filename"], CHILD_NAME, "{child}");
        assert_eq!(
            child["status"], "Paused",
            "the child must WAIT for the user to start it: {child}"
        );
        assert_eq!(
            child["origin"], "refeed",
            "the child must say where it came from: {child}"
        );
        let nzo = child["nzo_id"].as_str().expect("nzo_id").to_string();
        assert_ne!(nzo, parent, "the child is a second record, not the parent");
        assert_eq!(
            refeed_depth_of(&dir2, &nzo),
            1,
            "the child is one generation deep, which is what stops the next one"
        );
    })
    .await
    .expect("the assertions ran");
    // `d` is dropped here, which kills the daemon and - on an unwind -
    // prints its log tail beside the assertion that failed.
}
