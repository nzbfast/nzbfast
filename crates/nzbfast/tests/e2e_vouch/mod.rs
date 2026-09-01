//! TODO 164: a failed archive set the job's OWN PAR2 set vouches for
//! fails the job; one the set knows nothing about keeps the decoy
//! tolerance. Driven through the real binary and the get tail, where
//! the recovery set is in scope - the unit pins in
//! `rarfix::vouch::tests` cover the verdict, these cover that the
//! verdict reaches the exit status.
//!
//! A child module so e2e.rs stays inside its size-gate baseline (the
//! e2e_split pattern: harness reached through `super::*`).
//!
//! Every leg posts TWO compressed (m3/m5) RAR sets under different stems
//! with the depth-0 chase off, so both demote to the disk ladder and the
//! ladder's "any group produced" rule is what is under test: `c.rar`
//! always unpacks, and what sits beside it decides the job.

use super::*;

/// A real compressed RAR whose packed data has been damaged in the
/// middle: headers intact, so every engine opens it, and the member's
/// CRC fails on the way out. The PAR2 set is created OVER these bytes,
/// so it verifies the post as complete - the poster vouched for a
/// broken archive, which is exactly the evidence the discriminator
/// reads.
fn damaged_compressed_rar() -> Vec<u8> {
    let mut arch = std::fs::read(rars_fixture_dir().join("m5_max.rar")).unwrap();
    let mid = arch.len() / 2;
    for b in &mut arch[mid..mid + 64] {
        *b ^= 0x5a;
    }
    arch
}

fn good_compressed_rar() -> Vec<u8> {
    std::fs::read(rars_fixture_dir().join("m3_default.rar")).unwrap()
}

/// `run_get` with `password` on the GET subcommand (the harness's
/// `extra_args` land ahead of it, where clap refuses them).
fn run(fx: &Fixture, srv: &MockServer, password: Option<&str>) -> (String, bool) {
    let cfg = fx.write_config(&[srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    cmd.env("NZBFAST_OPEN", "1")
        .env("NZBFAST_NO_TOP_RAR_CHASE", "1")
        .arg("--config")
        .arg(&cfg)
        .arg("get")
        .arg(&nzb)
        .arg("--out")
        .arg(&out)
        .arg("--connections")
        .arg("4")
        .arg("--window")
        .arg("3")
        .arg("--decoders")
        .arg("4");
    if let Some(pw) = password {
        cmd.arg("--password").arg(pw);
    }
    let res = cmd.output().expect("run nzbfast");
    // stdout/stderr are separate pipes with no shared clock - label the
    // seam so a bare join can't be misread as one chronology. Copy the
    // comment along with the string.
    let log = format!(
        "{}\n----- stderr (a SEPARATE stream: not in sequence with stdout above) -----\n{}",
        String::from_utf8_lossy(&res.stdout),
        String::from_utf8_lossy(&res.stderr)
    );
    (log, res.status.success())
}

/// Regression 1: a vouched group that stays packed fails the job - the
/// exit status and the job-level sentence, not just the warning. Before
/// TODO 164 this leg exited 0 with the release still packed beside the
/// unpacked sibling, and only the leftovers warning said so.
#[tokio::test(flavor = "multi_thread")]
async fn a_par2_vouched_set_that_stays_packed_fails_the_job() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("vouchfail");
    fx.add_file("c.rar", &good_compressed_rar(), 1500);
    fx.add_file("d.rar", &damaged_compressed_rar(), 1500);
    assert!(
        fx.add_par2(20, &["c.rar", "d.rar"], 1500),
        "par2 create failed"
    );
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let (log, ok) = tokio::task::spawn_blocking(move || {
        let r = run(&fx, &srv, None);
        // The sibling DID unpack and was spent; the vouched set stays
        // on disk for the retry, exactly as a failed single set would.
        assert!(
            fx.dir.join("out/bigtext_64k.bin").exists(),
            "sibling payload missing:\n{}",
            r.0
        );
        assert!(
            fx.dir.join("out/d.rar").exists(),
            "the vouched set must be kept:\n{}",
            r.0
        );
        r
    })
    .await
    .unwrap();
    assert!(
        !ok,
        "a PAR2-vouched set left packed must fail the job:\n{log}"
    );
    assert!(
        log.contains("the PAR2 set vouches for 1 archive set(s) that did not unpack: d"),
        "the failure must name the vouched set:\n{log}"
    );
}

/// Regression 2: the decoy shape keeps its tolerance. The same damaged
/// archive beside the same release, but the recovery set names only the
/// release - the leftover is PAR2-unknown, so the job completes with
/// the leftovers warning and nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn an_unvouched_decoy_that_stays_packed_still_completes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("vouchdecoy");
    fx.add_file("c.rar", &good_compressed_rar(), 1500);
    fx.add_file("decoy.rar", &damaged_compressed_rar(), 1500);
    assert!(fx.add_par2(20, &["c.rar"], 1500), "par2 create failed");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let (log, ok) = tokio::task::spawn_blocking(move || run(&fx, &srv, None))
        .await
        .unwrap();
    assert!(ok, "an unvouched decoy must not fail the job:\n{log}");
    assert!(
        log.contains("did not unpack and are still packed: decoy"),
        "the leftovers warning must still name the decoy:\n{log}"
    );
    assert!(
        !log.contains("the PAR2 set vouches for"),
        "nothing was vouched for:\n{log}"
    );
}

/// Regression 3: an encrypted vouched group that was never offered a
/// password lands on the existing completed-but-locked shape - exit 0,
/// the 🔒 line, volumes kept - and NOT on a failure. The daemon's
/// finalize reads that shape off the finished directory and raises
/// `password_required` on a Completed record (tests/daemon_password
/// `passworded_archive_flow`), which is the 🔑 affordance with the
/// automatic retry untouched; a Failed record carrying
/// `password_required` would have killed it (12 Aug 2026 sweep).
#[tokio::test(flavor = "multi_thread")]
async fn an_encrypted_vouched_set_without_a_password_is_locked_not_failed() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("vouchlocked");
    fx.add_file("c.rar", &good_compressed_rar(), 1500);
    let enc = std::fs::read(rars_fixture_dir().join("encrypted_solid.rar")).unwrap();
    fx.add_file("e.rar", &enc, 1500);
    assert!(
        fx.add_par2(20, &["c.rar", "e.rar"], 1500),
        "par2 create failed"
    );
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let (log, ok) = tokio::task::spawn_blocking(move || {
        let r = run(&fx, &srv, None);
        assert!(
            fx.dir.join("out/e.rar").exists(),
            "the locked set must be kept:\n{}",
            r.0
        );
        r
    })
    .await
    .unwrap();
    assert!(
        ok,
        "a locked vouched set is the completed-but-locked shape, not a failure:\n{log}"
    );
    assert!(
        log.contains("the PAR2 set vouches for 1 encrypted archive set(s) still packed: e"),
        "the locked set must be named as vouched:\n{log}"
    );
    assert!(
        log.contains("🔒 archive is password-protected and no password was found"),
        "the existing locked line must be printed:\n{log}"
    );
    assert!(
        !log.contains("that did not unpack"),
        "must not also fail:\n{log}"
    );
}

/// The other half of regression 3, and the tail-level twin of the U1
/// pair (`each_encrypted_rar_group_resolves_its_own_password`): with
/// the password supplied, the same two vouched sets both unpack and the
/// job is plainly green - the vouching never reaches for a verdict on
/// a set that produced.
#[tokio::test(flavor = "multi_thread")]
async fn an_encrypted_vouched_set_with_its_password_unpacks_green() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("vouchopen");
    fx.add_file("c.rar", &good_compressed_rar(), 1500);
    let enc = std::fs::read(rars_fixture_dir().join("encrypted_solid.rar")).unwrap();
    fx.add_file("e.rar", &enc, 1500);
    assert!(
        fx.add_par2(20, &["c.rar", "e.rar"], 1500),
        "par2 create failed"
    );
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let (log, ok) = tokio::task::spawn_blocking(move || {
        let r = run(&fx, &srv, Some("testpass"));
        assert!(
            !fx.dir.join("out/e.rar").exists(),
            "the unlocked set must be spent:\n{}",
            r.0
        );
        r
    })
    .await
    .unwrap();
    assert!(ok, "both sets unpack with the password:\n{log}");
    assert!(
        !log.contains("the PAR2 set vouches for"),
        "nothing stayed packed:\n{log}"
    );
    assert!(!log.contains("🔒"), "nothing is locked:\n{log}");
}
