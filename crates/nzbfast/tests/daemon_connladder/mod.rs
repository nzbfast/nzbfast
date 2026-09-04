//! The connection-ladder DOOR against a download already on the wire.
//!
//! A sibling-dir child of daemon.rs (the `stream_chaos` pattern) so the
//! parent stays inside its size-gate baseline; harness via `super::*`.
//!
//! **What was live until 1 Sep 2026.** `m_connladder` took the shared
//! `LadderPermit` and ran. That permit excludes another LADDER and says
//! nothing about the thing most likely to be using the account, which is
//! the download - so pressing Test mid-job opened up to 100 fresh
//! sockets and climbed for as long as four minutes, then two more
//! re-measuring, against an account the job was already holding. Past
//! the connection or IP cap the probe's dials are refused, and the LIVE
//! JOB's own reconnects then fail; short of it, both readings are wrong,
//! because a rung sharing the line with a download measures the
//! download. The carry probe one door over has refused this since it was
//! written (`serve::api::servers::carry_refusal`); the ladder, which is
//! an order of magnitude heavier, did not.
//!
//! **What is NOT covered here, and why.** The two re-asks INSIDE a run -
//! the one after the 60 s STAT gate and the per-rung one in the climb's
//! own callback - are not reachable from this door at test size. Both
//! need a ladder that is genuinely climbing, which needs a supply of
//! real articles `probeids` will STAT-verify, which is the 298 MB
//! fixture `daemon_carry`'s own rung test builds - and then a download
//! started underneath it, mid-climb, on a timer. Priced and declined
//! 1 Sep 2026 for the same reason that module declines its two
//! timeouts: the cost is a fixture, and what would be asserted is that
//! a check written three lines from the one below it fires. The ENTRY
//! refusal is the one an ordinary user reaches, and it is the one
//! pinned. If that judgement is revisited, the shape to build is
//! `daemon_carry`'s two-listener `BenchSet` with a job queued against a
//! second provider partway through the climb.
//!
//! The rule itself is pinned by
//! `serve::api::servers::tests::the_ladder_reads_the_same_running_download_rule_as_the_carry_probe`,
//! over the predicate both doors call. What is pinned HERE is the thing
//! a unit test cannot reach: that the DOOR asks it, over the real HTTP
//! surface, against a real running job.

use super::*;

/// A job parked on a provider that is refusing connections is a RUNNING
/// job - the runner holds its ticket, so `index_jobs_active` is up -
/// which is what makes this hold cheap. No bytes need to move, and the
/// window closes on its own when the mock heals.
const REFUSE_MS: u64 = 30_000;

fn nzb_for(name: &str, segs: &[(String, u64, u32)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

fn upload(port: u16, xml: &str) {
    let boundary = "----ladderb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"j.nzb\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=addfile&apikey=sekrit&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "{r}");
}

/// Pressing Test while a download is running is refused, and refused
/// BEFORE the shared permit is taken.
///
/// The second half is the one that would rot silently. A door that
/// claimed the permit and then turned the caller away has to remember to
/// drop it on every path, and a leaked one takes the Test button down
/// for the life of the process with the only symptom being a button that
/// says something else is already running when nothing is - the same
/// leak `daemon_carry` exists to catch on the door next to this one.
/// Asked here by pressing Test TWICE: the second answer must be the
/// download refusal again, never "a connection test is already running".
#[tokio::test(flavor = "multi_thread")]
async fn the_ladder_refuses_to_dial_over_a_running_download() {
    let dir = std::env::temp_dir().join(format!("nzbfast-connladder-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let data = payload(120_000, 11);
    let mut articles = HashMap::new();
    let segs = make_file_articles("ladder.bin", &data, 40_000, "ld", &mut articles);

    // The daemon comes up against an EMPTY server list, before the mock
    // exists: `refuse_connect_ms` is measured from the mock's own birth
    // and daemon startup is not free (measured elsewhere in this suite
    // at ~215 ms warm but 2,805 ms cold), so a mock started first would
    // spend its window on the daemon booting. Nothing is dialled until a
    // job is queued and the download path re-reads the config per job,
    // so the real server is written in below.
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    let d = serve(&dir, {
        let cfg = cfg.clone();
        let dir = dir.clone();
        move |port: u16| {
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
                // The suite's daemons run on a box with other sessions
                // building on it; a min-free hold would park the job
                // somewhere this test cannot tell from a refusal.
                .arg("--min-free")
                .arg("0")
                .arg("--connections")
                .arg("2");
            c
        }
    })
    .await;
    let port = d.port;

    let srv = MockServer::start(
        articles,
        Chaos {
            refuse_connect_ms: REFUSE_MS,
            ..Default::default()
        },
    )
    .await;
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":8}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();

    tokio::task::spawn_blocking(move || {
        upload(port, &nzb_for("ladder.bin", &segs));
        // `connecting` is the queue's own word for this job OWNING THE
        // POOL with no connections up and no bytes moved: a first dial
        // getting nowhere, which is exactly a job whose runner ticket is
        // held - and the ticket is what `index_jobs_active` counts.
        // Waited for rather than slept at, because the whole point is
        // that the refusal below is asked while the counter is genuinely
        // raised.
        //
        // Do NOT widen this to `"status":"Downloading"`. Tried, and it
        // broke the rig: `mode=queue` carries more than its slots (the
        // whyslow diagnostic block among them), so the token appears in
        // the payload before the runner holds anything, the poll breaks
        // out early, and the door then answers `no_real_articles` -
        // green-looking machinery measuring nothing. Same trap
        // `tools/payload-id-gate.py` exists for, one field over.
        let mut seen = String::new();
        for _ in 0..200 {
            seen = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if seen.contains("\"activity\":\"connecting\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            seen.contains("\"activity\":\"connecting\""),
            "the job never took the pool, so nothing below is measuring the \
             refusal:\n{seen}"
        );

        // Pressed twice. Both answers must be the DOWNLOAD refusal: the
        // first proves the door asks, the second proves the first did
        // not leave the shared permit behind on its way out.
        for pressed in 1..=2 {
            let r = http(
                port,
                "/api?mode=connladder&value=0&apikey=sekrit&output=json",
                None,
            );
            assert!(
                r.contains("\"status\":false"),
                "press {pressed}: the ladder ran over a live download: {r}"
            );
            // The flag the panel keys on, so a refusal is told from a
            // failure without pattern-matching the prose.
            assert!(
                r.contains("\"downloading\":true"),
                "press {pressed}: the refusal is unlabelled: {r}"
            );
            assert!(
                r.contains("a download is running"),
                "press {pressed}: not the tree's own words for it: {r}"
            );
            assert!(
                !r.contains("already running"),
                "press {pressed}: the permit was taken before the refusal and \
                 leaked - the Test button is now down for the life of the \
                 process: {r}"
            );
        }
    })
    .await
    .unwrap();
}
