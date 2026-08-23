//! TODO 163 item 6 end to end: a `.tar` INSIDE a store RAR - the shape
//! the section calls the honest case for tar on usenet - streams
//! through the real `get` pipeline, and the two roads away from that
//! (the kill switch, and a member the reader refuses) both leave the
//! job completing. Where they DIFFER is what the disk pass can do with
//! what landed: TODO 163 item 6's disk half unpacks the container the
//! kill switch materializes, and declines the one holding a member the
//! reader refuses, because it makes the chase's refusals out of the
//! chase's own reader.
//!
//! A child module so e2e.rs stays inside its size-gate baseline (the
//! e2e_zipsplit pattern: harness reached through `super::*`).

use super::*;

/// The post under test: a store RAR5 wrapping a tar of `movie.mkv` and
/// a small `readme.txt`, plus a `notes.txt` beside the tar so the outer
/// archive is not a single-entry special case. `specs` builds whatever
/// tar the caller wants inside it. Returns the fixture and the payload.
fn tar_in_rar_post(
    tag: &str,
    seed: u64,
    extra: &[nzbkit::tar::fixtures::Spec<'_>],
) -> (Fixture, Vec<u8>) {
    use nzbkit::tar::fixtures::Spec;
    let mut fx = Fixture::new(tag);
    let movie = incompressible(900_000, seed);
    let readme = b"release notes\n".repeat(200);
    let mut specs = vec![
        Spec::file("movie.mkv", &movie),
        Spec::file("readme.txt", &readme),
    ];
    specs.extend(extra.iter().cloned());
    let arch = nzbkit::tar::fixtures::tar_of(&specs);
    let notes = b"outer notes\n".repeat(100);
    let outer = fixtures::rar5_volume(&[
        ("inner.tar", arch.len() as u64, &arch, false, false),
        ("notes.txt", notes.len() as u64, &notes[..], false, false),
    ]);
    fx.add_file("o.rar", &outer, 60_000);
    assert!(fx.add_par2(10, &["o.rar"], 60_000));
    (fx, movie)
}

/// One pass all the way down: rc=0, the payload byte-exact, no chase
/// demoted, and neither the outer volume nor the inner `.tar` ever
/// touched the output directory.
#[tokio::test(flavor = "multi_thread")]
async fn a_tar_in_a_store_rar_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, movie) = tar_in_rar_post("rartar", 61, &[]);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        !log.contains("fell back") && !log.contains("nested fallback"),
        "chase demoted:\n{log}"
    );
    // The tar's two members plus the outer archive's own `notes.txt` -
    // three files out of the stream, and NOT the container that held
    // them. That count is how the one-pass road and the road below
    // differ in the log.
    assert!(
        log.contains("extracted 3 file(s) in-stream"),
        "the tar did not stream:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(fx.dir.join("out/readme.txt").exists(), "{log}");
    assert!(fx.dir.join("out/notes.txt").exists(), "{log}");
    for v in ["o.rar", "inner.tar"] {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "{v} must not touch disk:\n{log}"
        );
    }
}

/// A bare posted `.tar` streams too - the same worker at depth 0, with
/// no outer archive above it. Cheaper than the nested leg (no par2
/// set), and it pins that the top-level road is not gated off.
#[tokio::test(flavor = "multi_thread")]
async fn a_posted_tar_extracts_one_pass() {
    use nzbkit::tar::fixtures::Spec;
    let mut fx = Fixture::new("toptar");
    let movie = incompressible(900_000, 62);
    let readme = b"release notes\n".repeat(200);
    let arch = nzbkit::tar::fixtures::tar_of(&[
        Spec::file("movie.mkv", &movie),
        Spec::file("readme.txt", &readme),
    ]);
    fx.add_file("release.tar", &arch, 60_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(fx.dir.join("out/readme.txt").exists(), "{log}");
    assert!(
        !fx.dir.join("out/release.tar").exists(),
        "the container must not touch disk:\n{log}"
    );
}

/// The top-level disk road, which is where a posted `.tar` has always
/// landed: the chase is off, the container materializes whole, and the
/// post-pass ladder's tar arm unpacks it there. No outer archive above
/// it and no par2 set, so this is the cheap pin on the road that the
/// resumed-run case (extraction disabled wholesale, nothing chased)
/// takes as well.
#[tokio::test(flavor = "multi_thread")]
async fn a_posted_tar_with_the_gate_off_unpacks_on_disk() {
    use nzbkit::tar::fixtures::Spec;
    let mut fx = Fixture::new("toptaroff");
    let movie = incompressible(900_000, 65);
    let readme = b"release notes\n".repeat(200);
    let arch = nzbkit::tar::fixtures::tar_of(&[
        Spec::file("movie.mkv", &movie),
        Spec::file("readme.txt", &readme),
    ]);
    fx.add_file("release.tar", &arch, 60_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) =
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_TAR", "1")]))
            .await
            .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(fx.dir.join("out/readme.txt").exists(), "{log}");
}

/// The road the arm replaced, still open behind `NZBFAST_NO_TAR=1`: the
/// child declines the container, the `.tar` lands as a plain file
/// beside the outer archive's own entry, and the JOB STILL COMPLETES.
///
/// Since TODO 163 item 6's DISK half (23 Aug 2026) the two roads then
/// CONVERGE: the post-pass ladder's tar arm unpacks the container it
/// finds in the output directory, and the spent-intermediate sweep
/// removes it once the payload sits beside it, so the gate-off ending
/// differs from the one-pass ending in what it cost, not in what the
/// user is left holding. This leg used to assert the opposite - that
/// `movie.mkv` never appeared, because nothing on disk unpacked a
/// `.tar` - and it was left in place precisely so that whoever built
/// the disk half would be told by a failing test which leg to update.
#[tokio::test(flavor = "multi_thread")]
async fn a_tar_with_the_gate_off_lands_and_the_job_completes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, movie) = tar_in_rar_post("rartaroff", 63, &[]);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) =
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_TAR", "1")]))
            .await
            .unwrap();
    assert!(ok, "get failed:\n{log}");
    // Two files out of the stream, not three: the `.tar` itself and the
    // outer archive's `notes.txt`.
    assert!(
        log.contains("extracted 2 file(s) in-stream"),
        "the tar did not land as a plain file:\n{log}"
    );
    // ...and the disk ladder unpacks that plain file, so the payload
    // lands whole either way.
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(fx.dir.join("out/readme.txt").exists(), "{log}");
    assert!(fx.dir.join("out/notes.txt").exists(), "{log}");
    // The container was materialized by our own outer extraction and is
    // now spent: a clean one-pass run never writes it at all, so leaving
    // it would end the job holding the payload twice.
    assert!(
        !fx.dir.join("out/inner.tar").exists(),
        "the spent container must be swept:\n{log}"
    );
    assert!(
        !fx.dir.join("out/o.rar").exists(),
        "the outer volume must not touch disk:\n{log}"
    );
}

/// A member the reader refuses demotes the container alone and the job
/// completes: the `.tar` materializes byte-for-byte, no half-extracted
/// payload survives beside it, and - the point of the
/// `TAR_DISK_FALLBACK_PREFIX` marker - the RAR remediation ladder never
/// sees the reason and goes hunting for volumes to unrar.
///
/// The disk arm does NOT rescue this one, and that is the design: it
/// makes the same refusals the chase makes, out of the same reader. So
/// it declines the container, records it as refused (which keeps the
/// spent-intermediate sweep off it), and leaves the job Completed with
/// a standard container on disk - the ending every tar had before
/// either half existed.
#[tokio::test(flavor = "multi_thread")]
async fn a_tar_holding_a_symlink_demotes_and_the_job_completes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, _movie) = tar_in_rar_post(
        "rartarlink",
        64,
        &[nzbkit::tar::fixtures::Spec::special("latest", b'2')],
    );
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        log.contains("symlink"),
        "the refusal must be legible:\n{log}"
    );
    assert!(fx.dir.join("out/inner.tar").exists(), "{log}");
    assert!(
        !fx.dir.join("out/movie.mkv").exists(),
        "no payload from a demoted chase:\n{log}"
    );
    assert!(
        !fx.dir.join("out/o.rar").exists(),
        "the outer volume must not touch disk:\n{log}"
    );
}
