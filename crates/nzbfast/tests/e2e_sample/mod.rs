//! The download-time sample skip (PLAN M32 leftover, sabnzbd#3475), as
//! a child module so e2e.rs stays inside its size-gate baseline (the
//! e2e_chip6 / e2e_repair pattern: harness reached through `super::*`).

use super::*;
use std::process::Command;

/// `run_get_args`, but the extra arguments go to the `get` SUBCOMMAND
/// instead of ahead of it. The shared helper passes its extras as
/// GLOBAL flags, which is right for everything that has needed one so
/// far; `--skip-samples` is a `get` flag, so it needs the other side of
/// the subcommand word. Local rather than in e2e.rs, which is at its
/// size-gate baseline.
fn get_with(config: &Path, nzb: &Path, out: &Path, sub_args: &[&str]) -> (String, bool) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    // Keyless on purpose, the same deliberate opt-out `run_get_win` takes.
    cmd.env("NZBFAST_OPEN", "1");
    cmd.arg("--config")
        .arg(config)
        .arg("get")
        .arg(nzb)
        .arg("--out")
        .arg(out)
        .arg("--connections")
        .arg("4")
        .arg("--window")
        .arg("3")
        .arg("--decoders")
        .arg("4")
        .args(sub_args);
    let out = cmd.output().expect("run nzbfast");
    (
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        out.status.success(),
    )
}

/// A release posted as its feature plus a teaser, with the PAR2 set
/// covering BOTH - which is the shape the whole interaction turns on.
fn feature_plus_sample(tag: &str) -> (Fixture, Vec<u8>, Vec<u8>) {
    let mut fx = Fixture::new(tag);
    // 900 kB feature against a 40 kB teaser: comfortably under the
    // sweep's 15% line, which is the same constant the plan-time
    // classifier measures against.
    let feature = payload(900_000, 11);
    let teaser = payload(40_000, 23);
    fx.add_file("Movie.2024.1080p-GRP.mkv", &feature, 60_000);
    fx.add_file("Movie.2024.1080p-GRP-sample.mkv", &teaser, 60_000);
    assert!(
        fx.add_par2(
            20,
            &[
                "Movie.2024.1080p-GRP.mkv",
                "Movie.2024.1080p-GRP-sample.mkv"
            ],
            60_000,
        ),
        "par2 create failed"
    );
    (fx, feature, teaser)
}

/// The setting does what it says, and the PAR2 set does not undo it.
///
/// The trap this pins: the recovery set lists every file the poster
/// packed, so a teaser we never fetched reads to the verifier exactly
/// like one the servers lost. Left alone it would be charged to
/// `damage`, and the repair would then pull recovery volumes off the
/// wire to rebuild the very bytes the setting exists to not download -
/// MORE traffic than simply fetching it, for a file the user asked not
/// to have. The job must complete, the feature must be byte-correct,
/// the teaser must simply not be there, and no repair may run.
#[tokio::test(flavor = "multi_thread")]
async fn a_skipped_sample_is_not_damage() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, feature, _teaser) = feature_plus_sample("skipsample");
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || get_with(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    assert!(ok, "the control run must succeed:\n{log}");
    assert!(
        out.join("Movie.2024.1080p-GRP-sample.mkv").exists(),
        "control: with the setting off the teaser is downloaded:\n{log}"
    );

    // And now with the setting on, into a fresh output directory.
    let out2 = fx.dir.join("out-skipped");
    let (log, ok) =
        tokio::task::spawn_blocking(move || get_with(&cfg, &nzb, &out2, &["--skip-samples"]))
            .await
            .unwrap();
    assert!(ok, "a skipped sample must not fail the job:\n{log}");

    let out2 = fx.dir.join("out-skipped");
    assert_eq!(
        std::fs::read(out2.join("Movie.2024.1080p-GRP.mkv")).unwrap(),
        feature,
        "the feature must arrive whole:\n{log}"
    );
    assert!(
        !out2.join("Movie.2024.1080p-GRP-sample.mkv").exists(),
        "the teaser was fetched anyway:\n{log}"
    );
    assert!(
        log.contains("skipping 1 sample file(s)"),
        "the skip was never announced:\n{log}"
    );
    // The two halves of the trap, stated as the log states them.
    assert!(
        log.contains("sample skipped on request, so not repaired either"),
        "the teaser was not struck off the recovery set's missing list:\n{log}"
    );
    assert!(
        log.contains("clean download - no repair"),
        "a file nobody wanted put the job through a repair:\n{log}"
    );
    assert!(
        !log.contains("file missing entirely"),
        "the skip was counted as damage:\n{log}"
    );
}

/// The gate errs toward downloading. A job whose ONLY video is
/// sample-named is the release the user asked for - name-based
/// classification has destroyed real payload here before (issue #40,
/// the named `.cbr`) - so the setting must leave it alone.
#[tokio::test(flavor = "multi_thread")]
async fn the_only_video_in_a_job_is_still_downloaded() {
    let mut fx = Fixture::new("skipsample-sole");
    let teaser = payload(120_000, 31);
    fx.add_file("Some.Teaser.Post-sample.mkv", &teaser, 60_000);
    fx.add_file("Some.Teaser.Post.nfo", b"scene notes", 60_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking({
        let out = out.clone();
        move || get_with(&cfg, &nzb, &out, &["--skip-samples"])
    })
    .await
    .unwrap();
    assert!(ok, "{log}");
    assert_eq!(
        std::fs::read(out.join("Some.Teaser.Post-sample.mkv")).unwrap(),
        teaser,
        "the job's only video was thrown away on its name:\n{log}"
    );
    assert!(
        !log.contains("skipping"),
        "nothing should have been skipped here:\n{log}"
    );
}
