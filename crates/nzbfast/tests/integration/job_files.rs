//! TODO 274 (issue #51): the per-file surface - `mode=get_files` and
//! `mode=queue&name=promote_file`.
//!
//! The load-bearing property is that a file's handle is THE SAME whether
//! it was read while the job waited in the queue or while the job was on
//! the wire. A client lists a job when it appears and acts on a file
//! seconds later; if the two halves derived their ids differently the
//! action would land on nothing, or worse on the wrong row. So this test
//! reads the listing twice across the transition and compares the handles
//! rather than testing each half on its own.
//!
//! The fixture is deliberately four files of three kinds: two payload
//! files, the main `.par2`, and one recovery VOLUME. The volume is the
//! one row that gets no slot in the plan - it is never queued unless
//! repair needs it - and it is the case a listing built from the slots
//! alone would silently drop.
//!
//! Same discipline as the other modules here: the test owns a daemon on
//! its own port, `NZBFAST_NO_ENRICH=1` in the child's environment.

use crate::scratch;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::harness::serve;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};

/// Slow enough that the job is provably still downloading while the
/// assertions run, at a size that keeps the whole test a few seconds.
const ART: usize = 20_000;
const ARTICLES: usize = 60;
const DELAY_MS: u64 = 120;

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
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

fn json(port: u16, req: &str) -> serde_json::Value {
    let r = http(port, req, None);
    serde_json::from_str(&r).unwrap_or_else(|e| panic!("{req} did not answer JSON: {e}: {r}"))
}

/// A multi-file NZB. One `<file>` per entry, subjects in the quoted form
/// every classifier here reads.
fn nzb_xml(files: &[(&str, Vec<(String, u64, u32)>)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, segs) in files {
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

fn files_of(port: u16, nzo: &str) -> Vec<serde_json::Value> {
    json(
        port,
        &format!("/api?mode=get_files&value={nzo}&apikey=sekrit&output=json"),
    )["files"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn handles(rows: &[serde_json::Value]) -> Vec<String> {
    rows.iter()
        .map(|r| r["nzf_id"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn row<'a>(rows: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    rows.iter()
        .find(|r| r["filename"] == name)
        .unwrap_or_else(|| panic!("no row for {name} in {rows:?}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_s_files_carry_the_same_handles_queued_and_downloading_and_one_can_be_promoted() {
    let dir = std::env::temp_dir().join(format!("nzbfast-jobfiles-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let a = payload(ART * ARTICLES, 7);
    let b = payload(ART * ARTICLES, 19);
    let mut articles = HashMap::new();
    let sa = make_file_articles("pack.part01.rar", &a, ART, "fa", &mut articles);
    let sb = make_file_articles("pack.part02.rar", &b, ART, "fb", &mut articles);
    let sp = make_file_articles("pack.par2", &payload(4_000, 3), ART, "fp", &mut articles);
    let sv = make_file_articles(
        "pack.vol000+01.par2",
        &payload(40_000, 5),
        ART,
        "fv",
        &mut articles,
    );
    let xml = nzb_xml(&[
        ("pack.part01.rar", sa),
        ("pack.part02.rar", sb),
        ("pack.par2", sp),
        ("pack.vol000+01.par2", sv),
    ]);

    let mock = MockServer::start(
        articles,
        Chaos {
            delay_ms: DELAY_MS,
            ..Chaos::default()
        },
    )
    .await;
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

    // Paused first, so the queued half of the listing is read with no
    // race against the scheduler picking the job up.
    let p = json(port, "/api?mode=pause&apikey=sekrit&output=json");
    assert_eq!(p["status"], true, "pause: {p}");
    let nzo = add_nzb(port, "pack", &xml);

    // --- the queued listing ------------------------------------------
    let queued = files_of(port, &nzo);
    assert_eq!(queued.len(), 4, "every NZB file is listed: {queued:?}");
    let ids = handles(&queued);
    assert!(
        ids.iter().all(|h| h.len() == 16
            && h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())),
        "handles are 16 lowercase hex: {ids:?}"
    );
    assert!(
        ids.iter().collect::<std::collections::HashSet<_>>().len() == 4,
        "handles are unique: {ids:?}"
    );
    // Opaque: a handle must not be the name, or a client keying on it
    // is keying on the name again with extra steps.
    assert!(
        !ids.iter().any(|h| h.contains("pack") || h.contains("rar")),
        "handles are digests, not names: {ids:?}"
    );
    assert_eq!(row(&queued, "pack.part01.rar")["status"], "queued");
    assert_eq!(row(&queued, "pack.part01.rar")["state"], "queued");
    assert!(
        row(&queued, "pack.part01.rar")["bytes"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "the NZB's declared bytes are reported: {queued:?}"
    );
    // The recovery set is told apart BEFORE the job starts, from the
    // NZB's own classification (`NzbFile::kind`) rather than from a slot
    // that does not exist yet - the same call `get/plan.rs` makes when it
    // decides not to queue a volume's articles at all. A client that
    // could not see it here counts the par2 set as payload, and on a
    // typical post that is a third of the rows.
    for name in ["pack.par2", "pack.vol000+01.par2"] {
        assert_eq!(row(&queued, name)["recovery"], true, "{queued:?}");
    }
    for name in ["pack.part01.rar", "pack.part02.rar"] {
        assert_eq!(row(&queued, name)["recovery"], false, "{queued:?}");
    }

    // Promotion needs a queue to reorder, and a paused job has none.
    // Refused in words rather than silently doing nothing.
    let refused = json(
        port,
        &format!(
            "/api?mode=queue&name=promote_file&value={nzo}&value2={}&apikey=sekrit&output=json",
            ids[0]
        ),
    );
    assert_eq!(refused["status"], false, "{refused}");
    assert_eq!(refused["error"], "not the active job", "{refused}");

    // An id nothing answers to is an empty listing plus an error, so a
    // client that reads only `files` still parses the reply.
    let unknown = json(
        port,
        "/api?mode=get_files&value=SABnzbd_nzo_nope&apikey=sekrit&output=json",
    );
    assert_eq!(unknown["files"].as_array().map(Vec::len), Some(0));
    assert_eq!(unknown["error"], "unknown nzo_id", "{unknown}");

    // --- the same job, now on the wire -------------------------------
    let r = json(port, "/api?mode=resume&apikey=sekrit&output=json");
    assert_eq!(r["status"], true, "resume: {r}");
    // Waited out until a payload file has provably MOVED, not merely
    // until the table exists: a row that reports the plan's opening
    // numbers proves nothing about the counters being read live.
    let deadline = Instant::now() + Duration::from_secs(60);
    let live = loop {
        let rows = files_of(port, &nzo);
        let moved = rows.iter().any(|r| {
            r["filename"] == "pack.part01.rar"
                && r["segments_remaining"].as_u64().is_some_and(|n| n < 60)
        });
        if moved {
            break rows;
        }
        assert!(
            Instant::now() < deadline,
            "the job never started: {}",
            d.log()
        );
        std::thread::sleep(Duration::from_millis(200));
    };

    // THE point of the test: the handles did not move across the
    // transition, so a client that listed while queued can still act.
    assert_eq!(handles(&live), ids, "handles must survive the job starting");
    assert_eq!(live.len(), 4, "and the recovery volume is still listed");

    // Live progress on the file that moved: SAB's word, ours, and the
    // remainder all agree, and the remainder is quoted in the same unit
    // as the queue's own denominator.
    let part1 = row(&live, "pack.part01.rar");
    assert_eq!(part1["state"], "active", "{part1}");
    assert_eq!(part1["status"], "active", "{part1}");
    assert!(
        part1["bytes_left"].as_u64().unwrap_or(u64::MAX) < part1["bytes"].as_u64().unwrap(),
        "the remainder shrinks with the segments: {part1}"
    );

    // The recovery VOLUME is the row with no slot: reported, marked, and
    // honestly refused for promotion - the plan never queued it.
    let vol = row(&live, "pack.vol000+01.par2");
    assert_eq!(vol["recovery"], true, "{vol}");
    assert!(
        vol.get("segments_remaining").is_none(),
        "a volume with no slot has no live counters to report: {vol}"
    );
    let vol_promote = json(
        port,
        &format!(
            "/api?mode=queue&name=promote_file&value={nzo}&value2={}&apikey=sekrit&output=json",
            vol["nzf_id"].as_str().unwrap()
        ),
    );
    assert_eq!(vol_promote["status"], false, "{vol_promote}");
    assert_eq!(
        vol_promote["error"], "file has no queued articles",
        "{vol_promote}"
    );

    // A payload file promotes, and the reply says how much actually
    // moved rather than claiming the queue was rewritten.
    let part2 = row(&live, "pack.part02.rar");
    let moved = json(
        port,
        &format!(
            "/api?mode=queue&name=promote_file&value={nzo}&value2={}&apikey=sekrit&output=json",
            part2["nzf_id"].as_str().unwrap()
        ),
    );
    assert_eq!(moved["status"], true, "{moved}");
    assert_eq!(moved["nzf_id"], part2["nzf_id"], "{moved}");
    // Most of this file is still pending at this point - the loop above
    // broke on the FIRST article of the job to land - so a promote that
    // reordered nothing would mean the ids never reached the queue.
    assert!(
        moved["moved"].as_u64().unwrap_or(0) > 0,
        "a file with pending articles must move some of them: {moved}"
    );

    // A handle from another job (or a typo) is refused by name.
    let bad = json(
        port,
        &format!(
            "/api?mode=queue&name=promote_file&value={nzo}&value2=deadbeefdeadbeef&apikey=sekrit&output=json"
        ),
    );
    assert_eq!(bad["status"], false, "{bad}");
    assert_eq!(bad["error"], "unknown file id", "{bad}");

    d.stop();
}
