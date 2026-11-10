//! TODO 358 item 6 (a Weaver parity row): a destination that refuses
//! the download's writes - EACCES, EPERM, EISDIR - halts the job with a
//! verdict that names the refusal, exactly as a full disk always has,
//! instead of downloading the rest of the post into the same refusal and
//! instead of being reported as out of disk space. A child module so
//! e2e.rs stays inside its size-gate baseline (the e2e_sample pattern:
//! harness reached through `super::*`).
//!
//! Unix only: the shapes are staged with permission bits, which Windows
//! does not have in this form. The classifier's Windows arm
//! (ERROR_ACCESS_DENIED) is pinned at the unit level in nzbkit-base.
//!
//! Each leg stages the refusal deterministically rather than racing a
//! `chmod` against the download: the job's folder stays writable (the
//! resume journal lives in it and opens first), and the PAYLOAD'S OWN
//! NAME is what refuses - a read-only file there (EACCES on the
//! truncating open) or a directory (EISDIR). That is the article write
//! path the halt arm covers. The third leg is the whole folder at mode
//! 0, which refuses one door earlier, at the journal, and is here so the
//! "chmod 0 completed dir" shape is pinned to a failure too.

#![cfg(unix)]

use super::*;
use std::os::unix::fs::PermissionsExt;

/// The verdict `get::workers::drain_network` writes for this halt. Its
/// OPENING is what the daemon classifies on (as `Local`: no automatic
/// retry, never reported to an indexer as a dead post).
const REFUSED: &str = "the output folder refused writes";

/// Puts a path's mode back on drop, pass or fail, so the fixture's
/// scratch cleanup can remove what the leg locked. Declared AFTER the
/// fixture in each leg, so it drops first.
struct Restore(PathBuf, u32);

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
    }
}

/// A post whose FIRST file is `blocked.bin` and whose other four carry
/// the bulk, served over a paced line so a halt that works is visibly
/// short of the whole post. Returns the fixture, the server and how many
/// articles the post holds.
async fn paced_post(tag: &str) -> (Fixture, MockServer, usize) {
    let mut fx = Fixture::new(tag);
    fx.add_file("blocked.bin", &payload(120_000, 3), 40_000);
    for (i, name) in ["b.bin", "c.bin", "d.bin", "e.bin"].iter().enumerate() {
        fx.add_file(name, &payload(480_000, 10 + i as u8), 40_000);
    }
    let total = fx.articles.len();
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    // ~2 MB of post at 1 MB/s: two seconds to fetch it all, against a
    // halt that lands on the first article of the first file.
    srv.set_line_bps(1_000_000);
    (fx, srv, total)
}

/// Run the job and assert the refusal verdict: a failure, named as a
/// refusal and never as a full disk, with the fetch stopped short.
async fn assert_refused(fx: &Fixture, srv: &MockServer, total: usize, out: PathBuf, shape: &str) {
    let cfg = fx.write_config(&[srv]);
    let nzb = fx.write_nzb();
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(!ok, "{shape}: a refused write must fail the job:\n{log}");
    assert!(
        log.contains(REFUSED),
        "{shape}: the verdict must name the refusal:\n{log}"
    );
    assert!(
        log.contains("refused a write - stopping the download"),
        "{shape}: the halt must fire at the write, not at the end:\n{log}"
    );
    assert!(
        !log.contains("out of disk space"),
        "{shape}: a refusal is not a full disk - that verdict sends the \
         user to free space they already have:\n{log}"
    );
    let served: u64 = srv.serve_counts().values().sum();
    assert!(
        (served as usize) < total,
        "{shape}: the halt must stop the fetch short of the post \
         ({served} of {total} articles served):\n{log}"
    );
}

/// EACCES: a read-only file already holds the payload's name, so the
/// truncating open is refused. Skipped where the permission bits do not
/// bind (running as root), which the leg finds out by trying.
#[tokio::test(flavor = "multi_thread")]
async fn a_read_only_payload_name_halts_with_the_refusal_verdict() {
    let (fx, srv, total) = paced_post("refused-eacces").await;
    let out = fx.dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let leaf = out.join("blocked.bin");
    std::fs::write(&leaf, b"in the way").unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o444)).unwrap();
    let _restore = Restore(leaf.clone(), 0o644);
    if std::fs::OpenOptions::new().write(true).open(&leaf).is_ok() {
        eprintln!("skipping: permission bits do not bind here (root?)");
        return;
    }
    assert_refused(&fx, &srv, total, out, "EACCES").await;
    // The refused file is untouched: nothing was written around the
    // refusal or over it.
    assert_eq!(std::fs::read(&leaf).unwrap(), b"in the way");
}

/// EISDIR: a directory stands where the payload's file has to go.
#[tokio::test(flavor = "multi_thread")]
async fn a_directory_in_the_payloads_place_halts_with_the_refusal_verdict() {
    let (fx, srv, total) = paced_post("refused-eisdir").await;
    let out = fx.dir.join("out");
    std::fs::create_dir_all(out.join("blocked.bin")).unwrap();
    assert_refused(&fx, &srv, total, out.clone(), "EISDIR").await;
    assert!(
        out.join("blocked.bin").is_dir(),
        "the directory is left alone"
    );
}

/// The "chmod 0 completed dir" shape: the job's whole folder refuses.
/// This one is refused at the resume journal, before a single article is
/// asked for, so it never reaches the write-path halt - what it pins is
/// that the job FAILS, naming the permission, and fetches nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_mode_zero_output_folder_fails_before_fetching_anything() {
    let (fx, srv, _total) = paced_post("refused-mode0").await;
    let out = fx.dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o000)).unwrap();
    let _restore = Restore(out.clone(), 0o755);
    if std::fs::read_dir(&out).is_ok() {
        eprintln!("skipping: permission bits do not bind here (root?)");
        return;
    }
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out2 = out.clone();
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out2, &[]))
        .await
        .unwrap();
    assert!(!ok, "a mode-0 output folder must fail the job:\n{log}");
    assert!(
        log.to_ascii_lowercase().contains("permission denied"),
        "the failure must name the permission:\n{log}"
    );
    assert!(!log.contains("out of disk space"), "{log}");
    let served: u64 = srv.serve_counts().values().sum();
    assert_eq!(
        served, 0,
        "nothing may be fetched into a folder that refuses:\n{log}"
    );
}
