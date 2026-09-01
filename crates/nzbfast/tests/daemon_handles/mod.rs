//! Output-handle leaks: the daemon must not sit holding a finished or a
//! failed job's files open.
//!
//! Both halves of one invariant, so they live together. Moved out of
//! daemon.rs by the size gate (TODO 106) and declared there, so they
//! still run in that binary against those fixtures - the sibling-dir
//! pattern every other `mod daemon_*` here uses.
//!
//! The failed half is Gary's 15 Aug report: a job whose articles were
//! ~44% missing failed, armed its retry, and then refused to be deleted
//! because something still had its output open.

use super::*;

/// A finished job must not leave the daemon holding its output files
/// open.
///
/// `Extractor::finish` keeps its writers open on purpose, and the hub
/// keeps the extractor installed until the NEXT job starts - so an idle
/// daemon used to sit on a descriptor for every file the last job wrote.
/// On unix that descriptor keeps the blocks allocated after the file is
/// unlinked, which is precisely what happens next: cleanup deletes the
/// volumes and then Sonarr/Radarr imports the release and removes the
/// folder. Reported from Unraid on 2 Aug as "nzbfast was reserving space
/// on my SSD even when the file was moved... I had to keep restarting
/// nzbfast before the folder was able to be deleted".
///
/// The download tail now parks the writers, so the assertion is simply
/// that the OS sees no handle on the payload once history has the job.
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_job_holds_no_output_handles() {
    let dir = std::env::temp_dir().join(format!("nzbfast-fdrelease-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // One plain file, named distinctively enough that a substring match
    // over the daemon's whole descriptor table means only this payload.
    let data = payload(400_000, 11);
    let mut articles = HashMap::new();
    let segs = make_file_articles("fdrelease-payload.bin", &data, 40_000, "fd", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;fdrelease-payload.bin&quot; yEnc (1/11)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
    let (port, pid) = (d.port, d.pid());

    let held = tokio::task::spawn_blocking(move || {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"fdrelease.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
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

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");

        // History has the job, so the tail task has run to its end. The
        // short retry is for the post-processing passes that open the
        // payload for a moment of their own (the media probe reads its
        // head), not for the leak: a leaked handle is held forever.
        let mut held: Option<Vec<String>> = None;
        for _ in 0..15 {
            let hits: Vec<String> = open_files(pid)?
                .into_iter()
                .filter(|p| p.contains("fdrelease-payload.bin"))
                .collect();
            if hits.is_empty() {
                return Some(Vec::new());
            }
            held = Some(hits);
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        held
    })
    .await
    .unwrap();

    match held {
        None => eprintln!("skipping the descriptor check: this box has no /proc and no lsof"),
        Some(held) => assert!(
            held.is_empty(),
            "the daemon still holds the finished job's output open, so its \
             blocks survive an *arr import: {held:?}"
        ),
    }
}

/// The same invariant as above, on the path that was never covered: a
/// job that FAILED.
///
/// `a_finished_job_holds_no_output_handles` pins the success tail, which
/// is where the 2 Aug Unraid report landed. Gary hit the mirror image on
/// 15 Aug: a download whose articles were ~44% missing failed, armed its
/// automatic retry, and then refused to be deleted - "its files could not
/// be removed ... Some operations were aborted". He deleted the same
/// folder by hand later without trouble, and nothing had written to it
/// for hours, so nothing was mid-transfer; something simply still had it
/// open. That is Windows-only as a SYMPTOM - `IFileOperation` will not
/// move an open file to the Recycle Bin, while POSIX unlinks it happily -
/// but the leak it reports is not platform-specific, and this test asks
/// the portable half of the question on the box we actually build on.
///
/// The failing shape is Gary's: articles the server refuses with 430, no
/// recovery volumes worth the name, so the job ends Failed rather than
/// Completed. A failed run also QUARANTINES its partial payload
/// (`quarantine_partials` renames it `<name>.nzbfast-partial`), which is
/// why the scan matches on a substring rather than the exact name - and
/// why `.nzbfast.journal` is scanned for too. The journal is the file the
/// resume path keeps open by design DURING a run; the question here is
/// whether it is still open once the run is over.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_job_holds_no_output_handles() {
    let dir = std::env::temp_dir().join(format!("nzbfast-fdfail-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(400_000, 13);
    let mut articles = HashMap::new();
    let segs = make_file_articles("fdfail-payload.bin", &data, 40_000, "fdf", &mut articles);

    // Refuse a bit under half the articles with 430, the way a post that
    // never fully propagated reads. Enough that no amount of retrying
    // completes the file, so the job reaches Failed and parks.
    let mut chaos = Chaos::default();
    for (id, _, num) in &segs {
        if num % 2 == 0 {
            chaos.missing.insert(format!("<{id}>"));
        }
    }
    let srv = MockServer::start(articles, chaos).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;fdfail-payload.bin&quot; yEnc (1/11)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
    let (port, pid) = (d.port, d.pid());
    // Taken BEFORE the closure: `dir` is still needed for the cleanup
    // below, and the scan only ever wanted the path as a string.
    let scratch = dir.to_string_lossy().into_owned();

    let held = tokio::task::spawn_blocking(move || {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"fdfail.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
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

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        // The point of the fixture is that it CANNOT complete. If it did,
        // the chaos set stopped biting and this test is no longer asking
        // the question it claims to.
        assert!(
            hist.contains("\"Failed\""),
            "the fixture was supposed to fail and did not: {hist}"
        );

        // Same tolerance as the completed twin: post-failure passes may
        // open the payload for a moment of their own. A leaked handle is
        // held forever, so a few seconds separates the two.
        let mut held: Option<Vec<String>> = None;
        for _ in 0..15 {
            let hits: Vec<String> = open_files(pid)?
                .into_iter()
                .filter(|p| {
                    p.contains(&scratch)
                        && (p.contains("fdfail-payload.bin") || p.contains(".nzbfast.journal"))
                })
                .collect();
            if hits.is_empty() {
                return Some(Vec::new());
            }
            held = Some(hits);
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        held
    })
    .await
    .unwrap();

    match held {
        None => eprintln!("skipping the descriptor check: this box has no /proc and no lsof"),
        Some(held) => assert!(
            held.is_empty(),
            "the daemon still holds a FAILED job's files open, so on Windows \
             its folder cannot be deleted until the daemon restarts: {held:?}"
        ),
    }
}
