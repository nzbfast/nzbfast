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
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::harness::serve;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};

/// Slow enough that the job is provably still downloading while the
/// assertions run, at a size that keeps the whole test a few seconds.
const ART: usize = 20_000;
const ARTICLES: usize = 60;
const DELAY_MS: u64 = 120;
/// Connections the daemon is given, and so the exact number of articles
/// that can still land after the freeze arms - see the guard at the foot
/// of the test.
const CONNS: u64 = 2;

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
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":{CONNS}}}]}}",
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
            .arg(CONNS.to_string());
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
    // `bytes` is SAB's spelling and carries SAB's TYPE - a "%.2f"
    // STRING, which is what `build_file_list` writes in 4.5.0, 5.1.2 and
    // develop alike. It was a JSON number here until 31 Aug 2026, which
    // is GH #69's crash exactly: a statically-typed client
    // deserializing a String from a number throws at parse time. The
    // numeric reading has a key of its own beside it, the way
    // `bytes_left` already sits beside SAB's `mbleft`. Both are pinned,
    // because a test that pins only one of them cannot see the pair
    // drifting.
    let part = row(&queued, "pack.part01.rar");
    assert!(
        part["bytes"].as_str().is_some_and(|s| s.ends_with(".00")),
        "SAB's `bytes` is a \"%.2f\" string: {queued:?}"
    );
    assert!(
        part["bytes"]
            .as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0)
            > 0.0,
        "the NZB's declared bytes are reported: {queued:?}"
    );
    assert_eq!(
        part["bytes_total"].as_u64().map(|n| n as f64),
        part["bytes"].as_str().and_then(|s| s.parse::<f64>().ok()),
        "the two spellings describe one number: {queued:?}"
    );
    // SAB emits `age` on every file row and we emitted none, which is
    // the absent-key half of the same class. The fixture's NZB carries
    // no date attribute, so SAB's own "-" fallback is the right answer -
    // present, and honest about being unknown.
    assert!(
        part["age"].as_str().is_some(),
        "SAB sends `age` on every file row: {queued:?}"
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
    // ...and `status: false` beside it, which is SAB's error shape, so a
    // client that switches on that key rather than on `files` is not
    // left reading a null.
    assert_eq!(unknown["status"], false, "{unknown}");

    // --- the same job, now on the wire -------------------------------
    let r = json(port, "/api?mode=resume&apikey=sekrit&output=json");
    assert_eq!(r["status"], true, "resume: {r}");

    // THE PREMISE OF EVERYTHING BELOW is that this job is still in
    // flight, and until 31 Aug 2026 nothing held it there. The loop
    // here polled `files_of` over HTTP until part01 reported
    // `segments_remaining < 60` and then asserted on the row it had
    // just read - which is a race the daemon always wins on a loaded
    // box, because the whole job is only ~14 s of mock (240 articles,
    // `DELAY_MS` each, over two connections) while ONE HTTP round trip
    // to a starved daemon is seconds. Measured under 8x load on 30 Aug
    // 2026: this test inflated from 1.99 s to 93 s. It failed with
    // `left: "complete"`, `right: "active"` on a row reporting
    // `segments_remaining: 0`, `bytes_left: 0` - the file had finished
    // between the poll noticing movement and the assertion reading the
    // state. A longer deadline cannot fix that; the deadline was never
    // what expired.
    //
    // So the world is FROZEN before anything is read, and the freeze is
    // triggered off the MOCK's own counter rather than off a reply to
    // an HTTP request. That ordering is the whole fix: there is no
    // round trip between deciding to stop and stopping, so the job
    // cannot run to completion inside the gap. `pause` exists for
    // exactly this ("freeze the world ... no wall-clock races" - see
    // [`nzbkit::mock::MockServer::pause`]).
    let deadline = Instant::now() + Duration::from_secs(60);
    while mock.served.load(Ordering::Relaxed) < 3 {
        assert!(
            Instant::now() < deadline,
            "the job never started - the mock served nothing: {}",
            d.log()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    // Frozen.
    mock.pause.store(true, Ordering::Release);
    let served_at_arm = mock.served.load(Ordering::Relaxed);

    // NOW poll the daemon's own view. This poll cannot overshoot: the
    // articles it is waiting to see counted are already served and no
    // further one can be, so the state it settles on is the state every
    // assertion below reads. It is a wait for the daemon to CATCH UP,
    // which is a different quantity from the wait it replaced.
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
            "the mock served {} articles and the job never counted one: {}",
            mock.served.load(Ordering::Relaxed),
            d.log()
        );
        std::thread::sleep(Duration::from_millis(50));
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
        part1["bytes_left"].as_u64().unwrap_or(u64::MAX) < part1["bytes_total"].as_u64().unwrap(),
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
    // Most of this file is still pending at this point - the mock was
    // frozen after three articles, so ~237 of the job's 240 are still
    // queued and CANNOT drain while these assertions run. That is the
    // freeze earning its keep a second time: this premise used to hold
    // only because the job was slower than the test, which is the same
    // bet the `active` assertion above lost under load.
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

    // A GREEN RUN CANNOT TELL A WORKING FREEZE FROM AN INERT ONE, and
    // the freeze is the premise of every assertion above - so it is
    // asserted rather than assumed. The idea is `stream_repair.rs`'s
    // `Freeze::assert_held`, which reached it in the same week for the
    // same reason; the QUANTITY is different, and the difference is
    // measured rather than stylistic.
    //
    // THE FREEZE HAS AN EXACT RESIDUE, AND IT IS NOT ZERO. The mock
    // tests `pause` at the top of its command loop, so a connection
    // already blocked in `read_line` has passed the gate and will serve
    // the next command the client sends it, whenever that comes, before
    // parking. That is at most ONE PER CONNECTION for the life of the
    // freeze - and it is not theoretical: asserting no growth at all
    // over a 300 ms window failed here with exactly +2 on a 2-connection
    // config, seconds after arming, with the freeze working perfectly.
    //
    // So the bound is on the TOTAL growth since arming, which is exact,
    // and it needs no observation window - no wall clock anywhere in it,
    // which is the point of this whole change. A window would have to be
    // long enough to outrun ~2.5 articles per 300 ms of unfrozen mock,
    // which is the same order as the residue it has to tolerate.
    // The settle is not a threshold and nothing is compared against it:
    // it gives a download that is still running time to SHOW itself, so
    // that the exact bound below has something to catch. Without it the
    // check is inert on an idle box, where every assertion above
    // finishes in less time than one article takes - measured, a freeze
    // deleted from this test still passed. The mock's pacing is its own
    // wall clock and does not slow when the box is starved, so this
    // reveals a live download under load too.
    std::thread::sleep(Duration::from_millis(300));
    let leaked = mock.served.load(Ordering::Relaxed) - served_at_arm;
    assert!(
        leaked <= CONNS,
        "the provider served {leaked} more article(s) after the freeze armed, \
         against the {CONNS} a connection already past the pause gate can \
         still take - the freeze is inert and this test is racing the download \
         again"
    );
    // AND DID IT STOP THE WORLD SHORT OF THE END - a freeze armed after
    // the last article was already served is perfectly stable and holds
    // nothing back.
    let served = mock.served.load(Ordering::Relaxed);
    assert!(
        served < (ARTICLES * 4) as u64,
        "all {} of the fixture's articles had been asked for by the time the \
         freeze armed, so it is holding nothing back",
        ARTICLES * 4
    );

    // Thawed before the shutdown: every assertion above is done, and a
    // daemon asked to stop while its connections are parked against a
    // frozen server pays a read timeout it has nothing to learn from.
    mock.pause.store(false, Ordering::Release);
    d.stop();
}
