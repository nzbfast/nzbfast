//! Watch-folder dedupe against HISTORY, not just the live queue.
//!
//! The watcher deletes an ingested .nzb, and that deletion is the durable
//! "consumed" marker. When it cannot happen - a read-only share, a NAS
//! that refuses the unlink, a user who keeps the file deliberately - the
//! only thing standing between the release and a second full download is
//! the nzb_sha check. That check asked the live queue and nothing else,
//! so the moment the job finished and moved to history the answer went
//! back to "no" and the next daemon start re-downloaded the whole thing.
//! The in-process skip list covers the running process only.
//!
//! Both directions are asserted here: a completed history row stops the
//! re-ingest, and an install with no such row still ingests normally (so
//! a passing skip test cannot be a watcher that simply never ran).

use crate::scratch;

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::harness::Daemon;

/// A minimal but COMPLETE nzb - the watcher refuses anything without a
/// closing tag, and the whole point of this test is what happens after it
/// is accepted.
fn sample_nzb() -> String {
    "<?xml version=\"1.0\"?>\n\
     <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
     <file poster=\"x\" date=\"0\" subject=\"&quot;dedupe.bin&quot; yEnc (1/1)\">\n    \
     <groups><group>g</group></groups>\n    \
     <segments>\n      \
     <segment bytes=\"1000\" number=\"1\">dedupe@x</segment>\n    \
     </segments>\n  </file>\n</nzb>\n"
        .to_string()
}

fn sha_of(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// A config dir, a watch dir with one .nzb in it, and the sha the daemon
/// will compute for that file.
fn scratch(name: &str) -> (scratch::ScratchDir, PathBuf, String) {
    let dir =
        std::env::temp_dir().join(format!("nzbfast-watchdedupe-{}-{name}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    let watch = dir.join("watch");
    std::fs::create_dir_all(&watch).unwrap();
    // No servers: nothing here is allowed to reach a provider.
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    // ...and no Trash either. Ingesting a watched .nzb DELETES it, and
    // `smart::TRASH` defaults ON outside a `cfg(test)` build - which the
    // daemon spawned below is not - so two of the tests here were filing
    // release.nzb into the developer's own ~/.Trash on every `cargo test`.
    // The daemon reads this key from settings.json on startup, next to the
    // config, and there is no flag for it.
    std::fs::write(dir.join("settings.json"), "{\"delete_to_trash\":false}").unwrap();
    let nzb = sample_nzb();
    std::fs::write(watch.join("release.nzb"), &nzb).unwrap();
    (dir, watch, sha_of(nzb.as_bytes()))
}

/// Seed `.spool/queue.json` with one history record, exactly as the
/// daemon would have persisted it after finishing this release.
fn seed_history(dir: &Path, sha: &str, state: &str) {
    let spool = dir.join(".spool");
    std::fs::create_dir_all(&spool).unwrap();
    let record = serde_json::json!({
        "nzo_id": "SABnzbd_nzo_seed",
        "name": "release.nzb",
        "nzb_path": spool.join("release.nzb").to_string_lossy(),
        "out_dir": dir.join("complete/release").to_string_lossy(),
        "state": state,
        "nzb_sha": sha,
    });
    let v = serde_json::json!({ "next_id": 2, "queue": [], "history": [record] });
    std::fs::write(
        spool.join("queue.json"),
        serde_json::to_string_pretty(&v).unwrap(),
    )
    .unwrap();
}

/// Start the daemon watching `watch`, loopback-bound and keyless (the
/// assertions here are about the watch poller, not about auth), and
/// return only once OUR daemon is actually serving.
///
/// The readiness gate matters here even though nothing in this file ever
/// speaks HTTP - which is exactly why its absence stayed invisible. There
/// is no request to be refused, so a daemon that lost `free_port()` to a
/// parallel test (the port is closed between our bind(:0) and the child's,
/// and a full `cargo test -p nzbfast` runs a lot of daemons) simply exited,
/// and every `wait_for` below then spun out its full 20 s and blamed the
/// watch poller: "never saw `has already been downloaded`" is a confusing
/// way to say "the daemon was never up". Same missing retry as the other
/// suites had, with a quieter and more misleading symptom.
///
/// The banner is read from THIS daemon's own log, so it cannot be another
/// test's daemon answering on a port we lost.
fn serve(dir: &Path, watch: &Path) -> Daemon {
    crate::harness::serve_blocking(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        cmd.env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_OPEN", "1")
            // Q1 of the 08-10 Codex sweep. Every assertion in this file
            // reads the daemon's own log, so the filter has to be ours
            // rather than whatever the shell happened to export:
            // logging.rs honours RUST_LOG (second, after NZBFAST_LOG), and
            // a developer or runner with RUST_LOG=warn set drops every
            // INFO line these tests wait for - `wait_for` then spins its
            // full 30 s and fails on a log that never had the line in it.
            // `info` IS the default filter, so this pins the behaviour
            // the tests were written against instead of changing it.
            .env("NZBFAST_LOG", "info")
            .env_remove("RUST_LOG")
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--watch")
            .arg(watch);
        cmd
    })
}

/// THE REGRESSION: an unremovable watched .nzb whose release is already
/// in history must be left alone, not downloaded a second time.
#[test]
fn a_completed_history_row_stops_a_watched_nzb_being_ingested_again() {
    let (dir, watch, sha) = scratch("completed");
    seed_history(&dir, &sha, "Completed");

    let r = serve(&dir, &watch);
    let log = r.wait_for("has already been downloaded");
    assert!(
        !log.contains("release.nzb rejected"),
        "the skip must be the history check, not a parse failure\n{log}"
    );
    // The user's file is the thing at stake: still there, untouched.
    assert!(
        watch.join("release.nzb").exists(),
        "a skipped file must be left where the user put it\n{log}"
    );
    // ...and nothing was queued behind it.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let queued = std::fs::read_to_string(dir.join(".spool/queue.json")).unwrap_or_default();
    assert!(
        !queued.contains("\"origin\": \"watch\""),
        "the release was enqueued despite already being in history\n{queued}"
    );

    drop(r);
}

/// The control: with nothing in history, the same file is ingested and
/// the source is taken away as usual. Without this, a watcher that never
/// ran at all would pass the test above.
#[test]
fn a_watched_nzb_with_no_history_is_still_ingested() {
    let (dir, watch, _sha) = scratch("fresh");

    let r = serve(&dir, &watch);
    for _ in 0..200 {
        if !watch.join("release.nzb").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        !watch.join("release.nzb").exists(),
        "an unseen .nzb should have been ingested and its source removed\n--- log ---\n{}",
        r.log()
    );

    drop(r);
}

/// A FAILED row must NOT suppress the file: a takedown that later
/// refills, or a provider outage, is exactly the case where the user
/// keeps the .nzb around so it can be retried.
#[test]
fn a_failed_history_row_still_lets_the_file_be_retried() {
    let (dir, watch, sha) = scratch("failed");
    seed_history(&dir, &sha, "Failed");

    let r = serve(&dir, &watch);
    for _ in 0..200 {
        if !watch.join("release.nzb").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let log = r.log();
    assert!(
        !log.contains("has already been downloaded"),
        "a failed job must not become a permanent refusal to look at the file\n{log}"
    );
    assert!(
        !watch.join("release.nzb").exists(),
        "the retry should have been ingested\n{log}"
    );

    drop(r);
}

/// §129 2c: with `watch_recursive` on, a file dropped in a subfolder is
/// picked up, and the subfolder's name becomes the job's category.
#[test]
fn recursive_watch_uses_the_first_subfolder_as_the_category() {
    let (dir, watch, _sha) = scratch("recurse");
    // The root file is not this test's subject.
    std::fs::remove_file(watch.join("release.nzb")).unwrap();
    std::fs::write(
        dir.join("settings.json"),
        "{\"delete_to_trash\":false,\"watch_recursive\":true}",
    )
    .unwrap();
    let tv = watch.join("tv");
    std::fs::create_dir_all(&tv).unwrap();
    // Distinct bytes from sample_nzb(): identical content would trip
    // the sha dedupe, which is the other tests' subject, not ours.
    std::fs::write(
        tv.join("show.nzb"),
        sample_nzb().replace("dedupe", "recurse"),
    )
    .unwrap();

    let r = serve(&dir, &watch);
    let log = r.wait_for("picked up show.nzb from watch/tv");
    for _ in 0..100 {
        if !tv.join("show.nzb").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        !tv.join("show.nzb").exists(),
        "the subfolder file should have been ingested\n{log}"
    );
    // The job may be in the QUEUE or already in HISTORY when we look:
    // this config has no servers, so the runner's next pick (a 500 ms
    // tick) dials, fails the job with "config has no servers" and parks
    // it to .spool/history.jsonl - queue.json then holds an empty queue
    // array. The category rides the record to history unchanged, so
    // read both; on a fast box the park wins the race often enough to
    // flake CI (seen on windows-unit as "got []").
    let queued: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(".spool/queue.json")).unwrap())
            .unwrap();
    let mut cats: Vec<String> = queued["queue"]
        .as_array()
        .unwrap()
        .iter()
        .map(|j| j["category"].as_str().unwrap_or_default().to_string())
        .collect();
    let hist = std::fs::read_to_string(dir.join(".spool/history.jsonl")).unwrap_or_default();
    cats.extend(hist.lines().filter_map(|l| {
        let j: serde_json::Value = serde_json::from_str(l).ok()?;
        Some(j["category"].as_str().unwrap_or_default().to_string())
    }));
    assert!(
        cats.contains(&"tv".to_string()),
        "the job's category should be the subfolder name, got {cats:?}\n--- log ---\n{}",
        r.log()
    );

    drop(r);
}

/// The control for the test above: with the switch OFF (the default) a
/// subfolder file is invisible - a walker that ignored the flag would
/// silently make recursion always-on.
#[test]
fn subfolders_are_not_scanned_unless_recursive_is_on() {
    let (dir, watch, _sha) = scratch("norecurse");
    std::fs::remove_file(watch.join("release.nzb")).unwrap();
    std::fs::write(
        dir.join("settings.json"),
        "{\"delete_to_trash\":false,\"watch_interval_secs\":1}",
    )
    .unwrap();
    let tv = watch.join("tv");
    std::fs::create_dir_all(&tv).unwrap();
    std::fs::write(
        tv.join("show.nzb"),
        sample_nzb().replace("dedupe", "norecurse"),
    )
    .unwrap();

    let r = serve(&dir, &watch);
    // Three 1 s passes are plenty for a wrongly-recursive walk to bite.
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(
        tv.join("show.nzb").exists(),
        "a subfolder file must be left alone with recursion off\n--- log ---\n{}",
        r.log()
    );
    assert!(
        !r.log().contains("picked up show.nzb"),
        "a subfolder file must not be queued with recursion off\n--- log ---\n{}",
        r.log()
    );

    drop(r);
}

/// §129 2c: with `watch_move_rejected` on, a complete-but-unusable file
/// is moved into <watch>/rejected/ with a note saying why - and the
/// quarantine folder itself is never scanned, so it cannot boomerang.
#[test]
fn a_rejected_file_is_quarantined_with_a_note_when_the_switch_is_on() {
    let (dir, watch, _sha) = scratch("reject");
    std::fs::remove_file(watch.join("release.nzb")).unwrap();
    std::fs::write(
        dir.join("settings.json"),
        "{\"delete_to_trash\":false,\"watch_move_rejected\":true,\"watch_recursive\":true,\"watch_interval_secs\":1}",
    )
    .unwrap();
    // Complete (closing </nzb> present) but unusable: no files inside.
    std::fs::write(
        watch.join("bad.nzb"),
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n</nzb>\n",
    )
    .unwrap();

    let r = serve(&dir, &watch);
    r.wait_for("moved to");
    assert!(
        !watch.join("bad.nzb").exists(),
        "the rejected file should have moved out of the watch root\n--- log ---\n{}",
        r.log()
    );
    let moved = watch.join("rejected/bad.nzb");
    assert!(
        moved.exists(),
        "the rejected file should be in the quarantine\n--- log ---\n{}",
        r.log()
    );
    let note = std::fs::read_to_string(watch.join("rejected/bad.nzb.why.txt"))
        .expect("the quarantine should carry a .why.txt note");
    assert!(
        note.contains("could not use this file"),
        "the note should explain the failure, got:\n{note}"
    );
    // Even with recursion on, the quarantine is not rescanned: exactly
    // one rejection in the log after a few more passes.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let rejections = r.log().matches("bad.nzb rejected: ").count();
    assert_eq!(
        rejections,
        1,
        "the quarantined file must not be scanned again\n--- log ---\n{}",
        r.log()
    );

    drop(r);
}

/// One GET against our own daemon. The `/api` answers here carry a
/// Content-Length (they are built whole before they are sent), so the
/// body is whatever follows the header break - no dechunking.
///
/// Retried like every other suite's helper: a daemon under a fully
/// parallel run can drop a connection unread when it cannot spawn a
/// thread, which arrives as ECONNRESET and is not an answer.
fn http(port: u16, req: &str) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req) {
            Ok(body) => return body,
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

fn http_once(port: u16, req: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        s,
        "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = Vec::new();
    let read = s.read_to_end(&mut raw);
    if raw.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    Ok(String::from_utf8_lossy(&raw)
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .to_string())
}

/// §129 1b(b): a watch-folder pickup reaches an open dashboard as a
/// `watch.picked` LIFECYCLE EVENT, not as a bounded array on the queue
/// payload for the page to diff against a seen-set of its own.
///
/// The sentence this carries is the whole reason the notice exists: the
/// daemon consumes the user's .nzb, so the file vanishes from the folder
/// and a browser lists its own download as "Removed" (Gary, v1.0.14).
/// Both halves are asserted - the event says WHAT was picked up and from
/// WHICH folder, because the folder name is what the user recognises -
/// and so is the retirement of the old transport, since leaving both in
/// place would toast every pickup twice.
#[test]
fn a_watch_folder_pickup_reaches_the_dashboard_as_a_lifecycle_event() {
    let (dir, watch, _sha) = scratch("pickevent");

    let r = serve(&dir, &watch);
    r.wait_for("picked up release.nzb from watch");

    // `events=0` is "everything this boot" - the cursor a page that has
    // seen nothing would hold. An ABSENT param would prime instead and
    // deliberately replay nothing, which is the page-load contract.
    let body = http(r.port, "/api?mode=dashboard&events=0&output=json");
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"));
    let ev = v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .find(|e| e["kind"] == "watch.picked")
        .unwrap_or_else(|| panic!("no watch.picked on the ring: {body}"));
    assert_eq!(ev["name"], "release.nzb", "{body}");
    assert_eq!(ev["folder"], "watch", "{body}");
    assert_eq!(ev["schema_version"], 1, "{body}");
    assert!(ev["seq"].as_u64().unwrap_or(0) > 0, "{body}");

    // ...and the queue payload no longer carries the retired array.
    let plain = http(r.port, "/api?mode=queue&output=json");
    assert!(
        !plain.contains("watch_picked"),
        "the queue-borne ring should be gone: {plain}"
    );

    drop(r);
}
