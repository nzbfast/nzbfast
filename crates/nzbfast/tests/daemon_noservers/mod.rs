//! TODO §154: the queue holds when no server is configured.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//! It also keeps daemon.rs under the size gate - this test is the 182
//! lines that pushed it back over its baseline.

use super::*;

/// TODO §154: a job added while no server is configured is HELD, not
/// failed - and the hold clears itself the moment a server appears.
///
/// The bug this pins: `pick_job` consulted only the queue, so the next
/// 500 ms tick picked the job, the download died with "config has no
/// servers", and it filed to history Failed inside about half a second.
/// `FailKind::Local` is the right class and is also what makes it
/// terminal - Local is not `transient()`, so no auto-retry ladder ever
/// looked at it again. On the SAB facade that Failed row IS failed-
/// download handling to an *arr: blocklist the release, search for
/// another. A user who wires up Sonarr before configuring servers had
/// every incoming grab insta-failed and a healthy release blocklisted,
/// one per poll, silently.
///
/// So the assertions are, in order: the job stays Queued, history stays
/// EMPTY (a Failed row is the actual damage - the queue state is only
/// how it gets there), the hold says which of the guards is holding, and
/// then - with nothing restarted and no retry clicked - writing a real
/// server into the same config file starts the download and completes
/// it.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_added_with_no_servers_is_held_not_failed() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nosrv-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(120_000, 7);
    let mut articles = HashMap::new();
    let segs = make_file_articles("held.bin", &data, 40_000, "ns", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"x\" date=\"0\" subject=\"&quot;held.bin&quot; yEnc (1/3)\">\
         <groups><group>g</group></groups><segments>",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "<segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>"
        ));
    }
    xml.push_str("</segments></file></nzb>");

    // The state under test: a config with an empty server list. The
    // loader reports this as its `NoServers` error rather than as an
    // empty vec, which is why the guard cannot be written as a plain
    // `Ok(c) => c.servers.is_empty()`.
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let cfg2 = cfg.clone();
    let addr = srv.addr;
    tokio::task::spawn_blocking(move || {
        let boundary = "----noservers";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Held.S01E01.nzb\"\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&cat=tv&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // Well past the ~500 ms it used to take to fail, and past the
        // guard's own 1 s cadence, so a hold that never appeared shows
        // up here as the old instant Failed row rather than as a race.
        let mut saw_hold = false;
        for _ in 0..40 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if q.contains("\"noservers\"") {
                saw_hold = true;
            }
            let h = http(port, "/api?mode=history&output=json", None);
            assert!(
                !h.contains("\"Failed\""),
                "the job perma-failed instead of waiting - this is §154's *arr \
                 blocklist bug\n--- history ---\n{h}\n--- queue ---\n{q}"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(saw_hold, "no hold was published while the queue waited\n{q}");
        assert!(
            q.contains("\"Queued\""),
            "the job must still be in the queue, waiting\n{q}"
        );
        assert!(
            q.contains("\"reason\":\"noservers\""),
            "the hold must name itself so the dashboard can say why\n{q}"
        );
        // Not the quota hold's shape: nothing here is a gigabyte.
        assert!(
            !q.contains("\"spent_gb\""),
            "a no-servers hold must not publish the quota pair\n{q}"
        );

        // Force is the one thing that walks past the quota hold. It must
        // NOT walk past this one - there is nothing to dial, so all it
        // could do is reproduce the instant fail.
        let ids: Vec<String> = q
            .split("\"nzo_id\":\"")
            .skip(1)
            .filter_map(|s| s.split('"').next().map(str::to_string))
            .collect();
        let id = ids.first().expect("the queued job's id").clone();
        let r = http(
            port,
            &format!("/api?mode=queue&name=priority&value={id}&value2=2&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        for _ in 0..20 {
            let h = http(port, "/api?mode=history&output=json", None);
            assert!(
                !h.contains("\"Failed\""),
                "Force must not bypass the no-servers hold\n{h}"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // It clears itself: the runner re-reads the config every tick,
        // so adding a server is the whole remedy - no restart, no retry
        // click, and the job that was waiting is the job that runs.
        std::fs::write(
            &cfg2,
            format!(
                "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
                addr.ip(),
                addr.port()
            ),
        )
        .unwrap();
        let mut done = false;
        for _ in 0..200 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            assert!(
                !h.contains("\"Failed\""),
                "the held job failed once the server appeared\n{h}"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(done, "the held job never ran after a server was added\n{q}");
        assert!(
            !q.contains("\"noservers\""),
            "the hold must be withdrawn once a server exists\n{q}"
        );
    })
    .await
    .unwrap();

    // Close the daemon, keeping its log for whatever fails below.
    let _log = d.stop();
}
