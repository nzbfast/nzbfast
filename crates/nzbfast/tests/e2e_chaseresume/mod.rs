//! TODO 213 item 2: a 7z or zip chase that forfeits on the held-bytes
//! cap KEEPS its in-stream output, and the disk pass appends to that
//! prefix instead of extracting the member again from byte zero.
//!
//! A sibling-dir child module (the `e2e_repair` pattern, harness reached
//! through `super::*`) so `e2e.rs` stays inside its size-gate baseline.
//!
//! The RAR half of the ledger shipped on 22 Aug 2026 and was PRICED on
//! the bench (`research/RESUME-AFTER-FORFEIT-2026-08-22.md`: 1.9x of
//! payload in device I/O back down to the 1.55x plain-forfeit floor).
//! These two legs pin the container-format half's BEHAVIOUR instead -
//! that the prefix is offered, that the append lands the exact payload,
//! and that the escape hatch still puts the pass back on byte zero. The
//! byte-level contract of the append itself, that the writer swallows
//! exactly the mark and not one byte more, is `resumeout`'s own unit
//! test, which can assert on it directly.

use super::*;

/// One arm of one container format's forfeit, run and asserted the same
/// way in all four: a STORED container well past this run's share of a
/// small memory limit, with the drop-behind trim held off so it has no
/// way out but the cap. The worker decodes a good prefix of the only
/// member before the budget goes over, so the demote is exactly the
/// trim-then-forfeit shape the ledger exists for.
///
/// `container` is the posted name; the format follows from its
/// extension, and `NZBFAST_NO_7Z_TRIM` gates the trim for both (one
/// `sevenz_trim_set` serves the 7z and zip chases alike). The 7z leg
/// reaches its members through `for_each_entries` on one reader, the zip
/// leg through a worker pool that opens its entry writers on other
/// threads - two different roads into the same ledger, and the reason
/// item 2 was left out of the RAR one.
///
/// Answers the run's log for the one assertion that differs between the
/// arms. Everything true of all of them is asserted here: the forfeit
/// happened, the disk pass ran, the payload is byte-exact, and no
/// disambiguated second copy was left beside it - `lift_scratch_into`
/// invents an `extracted-1-movie.mkv` rather than overwrite, so a stale
/// partial still sitting under the member's own name would shunt the
/// real payload to that name instead of failing.
async fn forfeited_arm(tag: &str, container: &str, hatch: bool) -> String {
    let mut fx = Fixture::new(tag);
    let movie = incompressible(36 << 20, 44);
    let arch = if container.ends_with(".7z") {
        sevenz_store_container(&[("movie.mkv", &movie)])
    } else {
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)])
    };
    // No PAR2, for the same reason the sibling demote test skips it: the
    // set costs more to build than the rest of the case put together,
    // and a repair anywhere in the job is a ledger-voiding event with
    // its own tests.
    fx.add_file(container, &arch, 700_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let mut env: Vec<(&str, &str)> = vec![("NZBFAST_NO_7Z_TRIM", "1")];
    if hatch {
        env.push(("NZBFAST_NO_CHASE_RESUME", "1"));
    }
    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || {
            run_get_args(&cfg, &nzb, &out, &env, &["--mem-limit", "64M"])
        })
        .await
        .unwrap()
    };
    assert!(ok, "get failed:\n{log}");
    assert!(
        log.contains("held-bytes cap: chase memory"),
        "the chase never forfeited, so this leg proves nothing:\n{log}"
    );
    let done = format!(
        "{} unpack complete",
        if container.ends_with(".7z") {
            "7z"
        } else {
            "zip"
        }
    );
    assert!(log.contains(&done), "the post-pass never ran:\n{log}");
    assert_eq!(
        std::fs::read(out.join("movie.mkv")).expect("payload after the disk pass"),
        movie,
        "the resumed member is not the payload"
    );
    let strays: Vec<String> = std::fs::read_dir(&out)
        .expect("output dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with("movie.mkv") && n != "movie.mkv")
        .collect();
    assert!(
        strays.is_empty(),
        "a partial survived under a disambiguated name {strays:?}:\n{log}"
    );
    log
}

/// The default, 7z: the forfeit leaves the member's contiguous prefix on
/// disk, the disk pass takes it, and the payload comes out exact having
/// written the prefix once instead of twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_forfeited_7z_chase_resumes_its_member_on_disk() {
    let log = forfeited_arm("res7z", "release.7z", false).await;
    assert!(
        log.contains("resuming 1 member(s)"),
        "the 7z arm wrote no ledger, so the member re-extracted from byte zero:\n{log}"
    );
}

/// The default, zip. Same ledger, a different disk pass: the zip arm
/// opens its entry writers on a small worker pool, so the plan has to be
/// taken on the ladder's own thread (the ledger is a thread-local) and
/// the appended files collected across the pool.
#[tokio::test(flavor = "multi_thread")]
async fn a_forfeited_zip_chase_resumes_its_member_on_disk() {
    let log = forfeited_arm("reszip", "release.zip", false).await;
    assert!(
        log.contains("resuming 1 member(s)"),
        "the zip arm wrote no ledger, so the member re-extracted from byte zero:\n{log}"
    );
}

/// The hatch: `NZBFAST_NO_CHASE_RESUME=1` is the pre-ledger behaviour -
/// the partial goes, the disk pass writes the member from byte zero, and
/// the payload is still exact. One binary, two arms, which is what an
/// A/B of the saving needs. Pinned on the 7z leg alone: the hatch is
/// read in the extractor, at the one site both formats forfeit through,
/// so a zip twin would re-run the same branch.
#[tokio::test(flavor = "multi_thread")]
async fn the_kill_switch_puts_a_forfeited_7z_back_on_byte_zero() {
    let log = forfeited_arm("res7zoff", "release.7z", true).await;
    assert!(
        !log.contains("resuming"),
        "the hatch was set and the pass resumed anyway:\n{log}"
    );
}
