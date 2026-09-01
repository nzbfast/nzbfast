//! No-RAR matrix, extreme rows M4-26/29/30/31/32 - the adversarial tail
//! of the family `e2e_norar` covers (rows recorded in
//! research/NORAR-DEOBF-MATRIX-2026-08-29.md).
//!
//! A CHILD of `e2e_norar` rather than more rows appended to it: that
//! file is 2,658 lines against the size gate's 3,000-line ceiling and
//! these do not fit, and `tests/e2e.rs` - where a new sibling dir would
//! have to be declared - sits EXACTLY on its own baseline, which only
//! ever goes down. Nesting costs `e2e_norar` one `mod` line and keeps
//! the fixture VOCABULARY shared rather than copied: `use super::*`
//! reaches `add_par2_patched`, `rename_filedesc` and `out_tree`
//! directly, and through the parent's own glob the harness itself.
//! Two hand-copied fixture builders drifting apart is the failure this
//! repo keeps writing gates about.
//!
//! Five rows, and only ONE of them was red: M4-30. The other four were
//! PREDICTED to fail and MEASURED green on origin/main at `8fbe1c3bd`,
//! so each doc below records what the run actually did and - because a
//! green pin over an unarmed fixture is worth nothing - the mutation of
//! the REAL tree that was verified to redden it.

use super::*;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};

/// `run_norar` for a run carrying `get` SUBCOMMAND flags. M4-29 needs
/// `--skip-samples`, which is neither a config key nor a global flag:
/// clap refuses it ahead of `--config`, so `run_get_args` - whose
/// `extra_args` land in the GLOBAL position, where `--mem-limit` goes -
/// cannot express it.
///
/// The command is built here rather than by widening `run_get_win`
/// because `crates/nzbfast/tests/e2e.rs` sits EXACTLY on its size-gate
/// baseline, and that baseline only ever goes down. The dial is not
/// duplicated with it: `GET_CONNS` / `GET_WINDOW` are the parent's own
/// constants, which
/// `rotated_ladder_does_not_fetch_every_article_twice` derives its
/// bounds from, so a dial moved there moves here too.
async fn run_norar_args(fx: &Fixture, sub_args: &[&str]) -> (String, bool, PathBuf) {
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let args: Vec<String> = sub_args.iter().map(|s| s.to_string()).collect();
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            // Keyless on purpose, the same deliberate opt-out every
            // other e2e leg takes (see serve::first_run_apikey).
            cmd.env("NZBFAST_OPEN", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--connections")
                .arg(GET_CONNS.to_string())
                .arg("--window")
                .arg(GET_WINDOW.to_string())
                .arg("--decoders")
                .arg("4")
                .args(&args);
            let done = cmd.output().expect("run nzbfast");
            (
                // stdout/stderr are separate pipes with no shared clock -
                // label the seam so a bare join can't be misread as one
                // chronology. Copy the comment along with the string.
                format!(
                    "{}\n----- stderr (a SEPARATE stream: not in sequence with stdout above) -----\n{}",
                    String::from_utf8_lossy(&done.stdout),
                    String::from_utf8_lossy(&done.stderr)
                ),
                done.status.success(),
            )
        }
    })
    .await
    .unwrap();
    if std::env::var("NORAR_DUMP_LOG").is_ok() {
        eprintln!("==== run log ====\n{log}\n==== end ====");
    }
    (log, ok, out)
}

/// `out_tree` reduced to a shape a panic can carry.
fn shape(tree: &[(String, Vec<u8>)]) -> Vec<(String, usize)> {
    tree.iter().map(|(n, b)| (n.clone(), b.len())).collect()
}

// ---------------------------------------------------------------- M4-26

/// Split a payload into its even and its odd BYTES. Neither half
/// contains one contiguous PAR2 block of the join, so no sliding scan
/// can stitch either back - which is what makes this row different from
/// M4-02, where each half still carries aligned blocks.
fn deinterleave(whole: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut a = Vec::with_capacity(whole.len().div_ceil(2));
    let mut b = Vec::with_capacity(whole.len() / 2);
    for (i, &byte) in whole.iter().enumerate() {
        if i % 2 == 0 {
            a.push(byte)
        } else {
            b.push(byte)
        }
    }
    (a, b)
}

/// Matrix row M4-26 - PASS, measured 30 Aug 2026 on origin/main at
/// `8fbe1c3bd`. Predicted: "adoption reports 0 blocks harvested, then
/// either reconstructs (PASS) or prices wholly missing and fails
/// despite enough slices (FAIL)."
///
/// It reconstructs. The run log is unambiguous about both halves of
/// that: `[verify] verified 0 file(s): 0 blocks in-stream` (neither
/// donor gave up a single block, so the seam IS armed - a fixture whose
/// halves happened to be harvestable would show blocks here), then
/// `[verify] ✘ Interleaved.mkv - file missing entirely` and `[repair]
/// need 2000 block(s) → fetching 11 volume(s)`, rebuilding the whole
/// 200 KB file from parity alone.
///
/// The assertion is NOT vacuous: the identical fixture at `-r5` instead
/// of `-r100` fails this test with `rc_ok=false join=None`, so the
/// green above is real reconstruction and not a fixture that would pass
/// whatever the engine did.
///
/// The two donors stay on disk under their hash names. That is correct
/// and deliberately pinned rather than swept: they are payload the
/// poster really posted and no descriptor in the set names them, so
/// deleting them would be destroying content on a guess.
#[tokio::test(flavor = "multi_thread")]
async fn byte_interleaved_donors_are_ignored_and_the_join_comes_from_parity() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarext26");
    let whole = payload(200_000, 31);
    let (even, odd) = deinterleave(&whole);
    std::fs::write(fx.dir.join("Interleaved.mkv"), &whole).unwrap();
    assert!(fx.add_par2(100, &["Interleaved.mkv"], 40_000));
    // Only the two halves are posted; the join itself never goes on the
    // wire, so the only route to it is the recovery set.
    std::fs::remove_file(fx.dir.join("Interleaved.mkv")).unwrap();
    for (hash, bytes) in [("Ev3nBy7esAa", &even), ("Od9dBy7esBb", &odd)] {
        let tag = format!("norarext26-{hash}");
        let segs = make_file_articles(hash, bytes, 40_000, &tag, &mut fx.articles);
        fx.nzb_files.push((hash.to_string(), segs));
    }
    let (log, ok, out) = run_norar_args(&fx, &[]).await;
    let tree = out_tree(&out);
    let got = tree.iter().find(|(n, _)| n == "Interleaved.mkv");
    assert!(
        ok && got.is_some_and(|(_, b)| *b == whole),
        "byte-interleaved donors: rc_ok={ok} join={:?}; tree {:?}\n{log}",
        got.map(|(_, b)| b.len()),
        shape(&tree)
    );
    assert!(
        tree.iter().any(|(_, b)| *b == even) && tree.iter().any(|(_, b)| *b == odd),
        "the donors are payload nothing names, and are kept: {:?}\n{log}",
        shape(&tree)
    );
    drop(fx);
}

// ---------------------------------------------------------------- M4-29

/// Matrix row M4-29 - PASS, measured 30 Aug 2026 on origin/main at
/// `8fbe1c3bd`. `skip_samples` decides from the NZB hint in `plan.rs`,
/// long before any FileDesc name exists, so a post whose SUBJECT is
/// `Movie.Sample.mkv` and whose FileDesc calls the same bytes
/// `Feature.mkv` never queues an article for the payload.
///
/// The row allows three outcomes - the FileDesc cancels the skip, or
/// repair reconstructs, or an honest fail that names the skip - and the
/// engine takes the second. Measured log: `[get] skipping 1 sample
/// file(s) - 2 article(s) ... Movie.Sample.mkv` (the seam is armed),
/// `[verify] ✘ Feature.mkv - file missing entirely`, then `[repair]
/// need 182 block(s)` and `1 file(s) recreated from parity`. rc=0 with
/// the payload byte-exact.
///
/// Its twin below is the control that makes this one mean something:
/// the same fixture with too little parity does NOT land the file, so
/// the byte compare here is testing the repair and not the fixture.
///
/// THAT GAP IS CLOSED, 31 Aug 2026 (claim
/// `skip-samples-loss-attribution`). It was recorded here rather than
/// fixed on the day: when the rebuild was NOT possible the failure said
/// how many blocks were short and never that the shortfall was a file
/// the user's own `--skip-samples` declined. Both facts sat in this same
/// log - the skip banner is its first line - and nothing joined them.
/// `repair::skipped_samples_clause` now appends the attribution to the
/// fail message, reading `FileSlot::sample_skipped` rather than the
/// plan-side list that never leaves `get::plan` (which is why
/// `get::residual::charge_missing_files` could not do it). CONDITIONAL,
/// not an accusation: the posted hint and the FileDesc name cannot be
/// joined, and that gap is this very row. The twin below pins the
/// sentence; the control is two lines down from here.
#[tokio::test(flavor = "multi_thread")]
async fn a_skipped_sample_a_filedesc_covers_is_rebuilt_from_parity() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarext29");
    let feature = payload(40_000, 41);
    // 10x the sample, and a video, so `skippable_samples` has a feature
    // to be a sample OF - without one it skips nothing and the row is
    // never exercised at all.
    let bulk = payload(400_000, 42);
    fx.add_file_renamed_by_par2("Feature.mkv", "Movie.Sample.mkv", &feature, 20_000);
    fx.add_file_obfuscated("Main.Video.mkv", "Main.Video.mkv", &bulk, 40_000);
    assert!(fx.add_par2(50, &["Feature.mkv", "Main.Video.mkv"], 40_000));
    let (log, ok, out) = run_norar_args(&fx, &["--skip-samples"]).await;
    assert!(
        log.contains("skipping 1 sample file(s)"),
        "the skip never fired, so this fixture pins nothing\n{log}"
    );
    let tree = out_tree(&out);
    let got = tree.iter().find(|(n, _)| n == "Feature.mkv");
    assert!(
        ok && got.is_some_and(|(_, b)| *b == feature),
        "skip-samples lost a FileDesc-covered payload: rc_ok={ok} feature={:?}; tree {:?}\n{log}",
        got.map(|(_, b)| b.len()),
        shape(&tree)
    );
    // Control for the attribution its twin below pins: the parity was
    // enough, so there is no shortfall to attribute and the sentence must
    // NOT appear. A clause that fired on every skipped sample would pass
    // that twin and be noise on every job the setting ever ran on.
    assert!(
        !log.contains("at your request"),
        "the skip attribution surfaced on a job that repaired cleanly\n{log}"
    );
    drop(fx);
}

/// The half of M4-29 that could actually lose data, and the control for
/// the leg above: the same skip with too little parity to rebuild what
/// was skipped. Measured green - `[repair] unrepairable: 182 blocks
/// needed, only 20 recovery blocks in the NZB` and a non-zero exit.
///
/// What this refuses is rc=0 with the payload absent. It does NOT
/// require the file to land: with the bytes never fetched and the
/// parity short, there is nothing left to rebuild it from, and failing
/// is the correct answer.
///
/// Since 31 Aug 2026 it also pins the WORDING, which is what the M4-29
/// follow-up bought - see the assertions at the foot of the body. The
/// block COUNT is still not asserted, and now for a second reason as
/// well: the external `par2` picks the block size when `add_par2`
/// passes no `-s`, and it picks a DIFFERENT one per version, so the
/// figure is a property of the host's par2 rather than of this fixture.
///
/// # Why the payloads are `unique_payload` and must stay that way
///
/// This row was RED on `nightly.yml`'s `one-process-heavy` in both
/// 31 Aug 2026 runs (33423815436, 33433649696) and green on every dev
/// box, and the difference was neither load nor a polluting neighbour -
/// measured, 0 of 20 runs failed here alone under 40 spinners. It was
/// the everyday `payload`, whose header states the trap this row walked
/// into: two seeds are ONE periodic sequence SHIFTED, and
/// `payload(_, 44)` is `payload(_, 43)` displaced by 512 bytes, so
/// `Feature.mkv[512..] == Main.Video.mkv[..39488]` exactly. Every full
/// PAR2 block of the file the skip declined sat verbatim inside the
/// file that landed, so the adoption scan could rebuild it with no
/// recovery data at all - and this row's whole verdict is that it
/// CANNOT be rebuilt.
///
/// Whether that greened turned on the block size, which turns on the
/// par2 version. CI installs 0.8.1 and picks 224; every box here is on
/// 1.3.0 and picks 220. At 224 the 40,000 bytes split into 178 full
/// blocks and a 128-byte tail, adoption finds all 178, and the single
/// short block is covered by the 20 recovery blocks - `repair complete
/// ... 178 block(s) adopted from Main.Video.mkv`, rc=0, and this row's
/// `!ok` fires. Reproduced deterministically here by forcing `-s224`,
/// byte-identical to the runner's log. At 220 it is 181 full blocks and
/// a 180-byte tail, and the same run does not green.
///
/// `payloads::unique_payload` has no block repeated at any alignment
/// within a file or across two seeds, so adoption finds ZERO here at
/// either block size - measured, both 220 and 224. That makes the
/// verdict a statement about the parity, which is what the row is for,
/// and independent of which par2 built the set. Do NOT put `payload`
/// back, and do not "fix" a recurrence by pinning `-s`: the block size
/// is not what was wrong.
#[tokio::test(flavor = "multi_thread")]
async fn a_skipped_sample_with_too_little_parity_fails_rather_than_going_green() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarext29b");
    let feature = payloads::unique_payload(40_000, 43);
    let bulk = payloads::unique_payload(400_000, 44);
    fx.add_file_renamed_by_par2("Feature.mkv", "Movie.Sample.mkv", &feature, 20_000);
    fx.add_file_obfuscated("Main.Video.mkv", "Main.Video.mkv", &bulk, 40_000);
    assert!(fx.add_par2(1, &["Feature.mkv", "Main.Video.mkv"], 40_000));
    let (log, ok, out) = run_norar_args(&fx, &["--skip-samples"]).await;
    assert!(
        log.contains("skipping 1 sample file(s)"),
        "the skip never fired, so this fixture pins nothing\n{log}"
    );
    let tree = out_tree(&out);
    let landed = tree
        .iter()
        .any(|(n, b)| n == "Feature.mkv" && *b == feature);
    assert!(
        !ok || landed,
        "rc=0 with the skipped FileDesc payload absent; tree {:?}\n{log}",
        shape(&tree)
    );
    // The M4-29 follow-up, landed 31 Aug 2026: the VERDICT must join the
    // two facts this log has always carried separately. Measured before
    // it was pinned - `Error: verification failed and PAR2 repair could
    // not complete: 77 recovery block(s) needed ... carries only 20. This
    // job also skipped 1 sample file(s) at your request (the "Skip sample
    // files" setting, --skip-samples): Movie.Sample.mkv - if the recovery
    // set covers one of those under a different name, its blocks are part
    // of this shortfall`. The skip
    // BANNER is asserted separately above, so neither assertion can stand
    // in for the other: the banner has been in this log since the row was
    // written and is not evidence that anything joined it to the verdict.
    assert!(
        !ok,
        "this fixture is the failing half of M4-29 and must not go green\n{log}"
    );
    assert!(
        log.contains("skipped 1 sample file(s) at your request"),
        "the shortfall verdict never named the setting that declined the file\n{log}"
    );
    assert!(
        log.contains("Movie.Sample.mkv - if the recovery set covers one of those"),
        "the verdict must name the declined file and stay CONDITIONAL: the posted \
         hint and the FileDesc name cannot be joined, which is the M4-29 gap \
         itself, so it must not assert which missing file the skip cost\n{log}"
    );
    drop(fx);
}

// ---------------------------------------------------------------- M4-91

/// Matrix row M4-91 - MEASURED RED on origin/main at `ed6857955`, and
/// red in the shape that costs the user the file: a series called Proof
/// whose 400 MB episode sits beside a 3 GB double-length special is
/// under `SAMPLE_MAX_FRACTION` of it, so `--skip-samples` - a setting
/// turned on to save a TEASER's bytes - declined to fetch an episode.
///
/// `is_sample_named` was `stem.contains("sample") || contains("proof")`,
/// so the same door was open to `Bulletproof.S01E01.mkv`, in which no
/// poster ever said "teaser" and the letters are inside another word.
///
/// This is the only one of the three sample rules with no second
/// chance. `is_deletable_sample` probes the container and refuses to
/// call anything that RUNS like an episode a teaser; here there is no
/// file to probe, because the bytes are what was skipped, and the
/// post-download sweep never sees one either.
///
/// The unit pins for the predicate are in `smart/sample.rs`; this leg
/// is the full-stack half - that the plan reached by `get` really does
/// fetch the episode - which no unit test of `skippable_samples` can
/// show. The skip banner must be ABSENT: its presence is the defect.
#[tokio::test(flavor = "multi_thread")]
async fn a_title_that_merely_contains_sample_or_proof_is_still_fetched() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarext91");
    let episode = payload(40_000, 91);
    // Over 10x the episode, so the size gate that used to carry this
    // decision on its own is armed: 40_000 is well under 0.15 * 400_000.
    let special = payload(400_000, 92);
    fx.add_file_obfuscated("Proof.S01E01.mkv", "Proof.S01E01.mkv", &episode, 20_000);
    fx.add_file_obfuscated(
        "Proof.S01E00.Special.mkv",
        "Proof.S01E00.Special.mkv",
        &special,
        40_000,
    );
    assert!(fx.add_par2(4, &["Proof.S01E01.mkv", "Proof.S01E00.Special.mkv"], 40_000));
    let (log, ok, out) = run_norar_args(&fx, &["--skip-samples"]).await;
    assert!(
        !log.contains("skipping") || !log.contains("sample file(s)"),
        "an episode of a series called Proof was declined as a teaser\n{log}"
    );
    let tree = out_tree(&out);
    let got = tree.iter().find(|(n, _)| n == "Proof.S01E01.mkv");
    assert!(
        ok && got.is_some_and(|(_, b)| *b == episode),
        "the episode did not land: rc_ok={ok} got={:?}; tree {:?}\n{log}",
        got.map(|(_, b)| b.len()),
        shape(&tree)
    );
    // The special is not collateral: both files are the release.
    assert!(
        tree.iter()
            .any(|(n, b)| n == "Proof.S01E00.Special.mkv" && *b == special),
        "tree {:?}\n{log}",
        shape(&tree)
    );
    drop(fx);
}

/// The control the row above must not cost, and the reason it is a
/// SEPARATE leg rather than an assertion inside the one before: with
/// the trigger removed - the same two files, the teaser now named after
/// the feature the way every scene post names one - `--skip-samples`
/// must still do the job the user turned it on for.
///
/// Without this pin, "stop skipping things" passes M4-91 by retiring
/// the setting.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_teaser_beside_the_same_feature_is_still_skipped() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarext91b");
    let teaser = payload(40_000, 93);
    let special = payload(400_000, 94);
    fx.add_file_obfuscated(
        "Proof.S01E00.Special.sample.mkv",
        "Proof.S01E00.Special.sample.mkv",
        &teaser,
        20_000,
    );
    fx.add_file_obfuscated(
        "Proof.S01E00.Special.mkv",
        "Proof.S01E00.Special.mkv",
        &special,
        40_000,
    );
    assert!(fx.add_par2(
        50,
        &[
            "Proof.S01E00.Special.sample.mkv",
            "Proof.S01E00.Special.mkv"
        ],
        40_000
    ));
    let (log, _ok, _out) = run_norar_args(&fx, &["--skip-samples"]).await;
    assert!(
        log.contains("skipping 1 sample file(s)"),
        "a teaser named after the feature beside it is still a teaser, \
         and its bytes are what the setting exists to save\n{log}"
    );
    drop(fx);
}

// ---------------------------------------------------------------- M4-30

/// Matrix row M4-30 - the full-stack half. `splitjoin_tests.rs` holds
/// the detector pins; this one proves the ladder actually reaches the
/// join in a real job, which a `collect_split_sets` unit test cannot.
///
/// MEASURED RED on origin/main at `8fbe1c3bd`, and red in the worst
/// shape: `rc_ok=true; tree ["Movie.mkv.000", "Movie.mkv.001"]`. The
/// job reported success with the payload undelivered, because
/// `collect_split_sets` required a run of exactly `1..=n` and `.000
/// .001` is not one. Fixed in `splitjoin.rs` rule 1.
#[tokio::test(flavor = "multi_thread")]
async fn a_zero_origin_split_post_joins_end_to_end() {
    let mut fx = Fixture::new("norarext30");
    let whole = payload(240_000, 71);
    for (i, chunk) in whole.chunks(120_000).enumerate() {
        fx.add_file(&format!("Movie.mkv.{i:03}"), chunk, 40_000);
    }
    let (log, ok, out) = run_norar_args(&fx, &[]).await;
    let tree = out_tree(&out);
    let names: Vec<&str> = tree.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        ok && tree.iter().any(|(n, b)| n == "Movie.mkv" && *b == whole)
            && !names
                .iter()
                .any(|n| n.ends_with(".000") || n.ends_with(".001")),
        "0-origin split did not join: rc_ok={ok}; tree {names:?}\n{log}"
    );
    drop(fx);
}

// ---------------------------------------------------------------- M4-31

/// Matrix row M4-31 - PASS, measured 30 Aug 2026 on origin/main at
/// `8fbe1c3bd`, exactly as the row predicted ("likely PASS as a pin").
/// `sanitize_relpath_for` runs `sanitize_filename_for` per COMPONENT,
/// and the reserved-DOS-name rule inside it is not gated on the
/// platform, so `VIDEO/COM1/VTS.IFO` lands as `VIDEO/_COM1/VTS.IFO` on
/// every host.
///
/// The e2e exists for the thing the unit test
/// (`components_go_through_the_per_component_rules`) cannot see: the
/// no-COLLISION half. A genuine flat `VIDEO_COM1_VTS.IFO` is posted
/// beside the tree member, so a flatten rewrite has somewhere to
/// collide. MEASURED that it bites: with `sanitize_out_name_for`
/// mutated to always flatten, this test fails with `tree
/// ["001-VIDEO_COM1_VTS.IFO", "VIDEO_COM1_VTS.IFO", ...]` - the tree
/// member pushed off its own name by the flat one, which is the M4-12
/// family exactly.
///
/// `COM1` cannot be a DIRECTORY on Windows, so `par2 create` sees a
/// safe stem and the FileDesc is patched to the reserved spelling
/// afterwards; the fixture therefore stages nothing Windows refuses.
#[tokio::test(flavor = "multi_thread")]
async fn a_reserved_dos_stem_as_a_path_component_keeps_its_tree() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarext31");
    let inner = payload(60_000, 51);
    let flat = payload(60_000, 52);
    fx.add_file_renamed_by_par2("VIDEO/SAFE1/VTS.IFO", "Rs4vDm81QpZ", &inner, 20_000);
    fx.add_file_renamed_by_par2("VIDEO_COM1_VTS.IFO", "Fl8tNc26WkY", &flat, 20_000);
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["VIDEO/SAFE1/VTS.IFO", "VIDEO_COM1_VTS.IFO"],
        40_000,
        |d| {
            // par2cmdline records the path with whichever separator the
            // host writes; both spellings are patched so the fixture is
            // not a statement about the creator's platform.
            let hits = rename_filedesc(d, "VIDEO/SAFE1/VTS.IFO", "VIDEO/COM1/VTS.IFO")
                + rename_filedesc(d, "VIDEO\\SAFE1\\VTS.IFO", "VIDEO/COM1/VTS.IFO");
            assert!(hits > 0, "no tree FileDesc to patch");
        }
    ));
    let (log, ok, out) = run_norar_args(&fx, &[]).await;
    let tree = out_tree(&out);
    let names: Vec<&str> = tree.iter().map(|(n, _)| n.as_str()).collect();
    assert!(
        ok && tree
            .iter()
            .any(|(n, b)| n == "VIDEO/_COM1/VTS.IFO" && *b == inner)
            && tree
                .iter()
                .any(|(n, b)| n == "VIDEO_COM1_VTS.IFO" && *b == flat),
        "reserved component: rc_ok={ok}; tree {names:?}\n{log}"
    );
    drop(fx);
}

// ---------------------------------------------------------------- M4-32

/// Matrix row M4-32 - PASS, measured 30 Aug 2026 on origin/main at
/// `8fbe1c3bd`. Two distinct FileDescs whose names the SANITIZER
/// collapses onto one: `...` (all dots) and `   ` (all spaces) both
/// come out of `sanitize_filename` as the literal `unnamed`. The
/// collision is produced by us, not by the packet, which is what makes
/// it different from W4-16.
///
/// The row accepts a collapse only if it is decided and VISIBLE, and it
/// is: `[extract] renamed Nm1qWs74WlP → unnamed` and `[extract] renamed
/// Nm2qWs75WlQ → 001-unnamed`. Both payloads land byte-exact under
/// distinct names, no hash is left behind, and the second name says in
/// the directory listing that it was disambiguated.
///
/// MEASURED that this bites: with `PublishedNames::claim` mutated to
/// skip its `free_for` check, the run goes rc=0 with `tree ["testset.
/// par2", "unnamed"]` - the second publish silently OVERWRITES the
/// first and one payload is destroyed with a green exit, which is
/// precisely the row's prediction.
#[tokio::test(flavor = "multi_thread")]
async fn two_filedescs_that_sanitize_to_unnamed_both_land_disambiguated() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarext32");
    let one = payload(60_000, 61);
    let two = payload(60_000, 62);
    fx.add_file_renamed_by_par2("descA.bin", "Nm1qWs74WlP", &one, 20_000);
    fx.add_file_renamed_by_par2("descB.bin", "Nm2qWs75WlQ", &two, 20_000);
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["descA.bin", "descB.bin"],
        40_000,
        |d| {
            assert!(rename_filedesc(d, "descA.bin", "...") > 0);
            assert!(rename_filedesc(d, "descB.bin", "   ") > 0);
        }
    ));
    let (log, ok, out) = run_norar_args(&fx, &[]).await;
    let tree = out_tree(&out);
    let names: Vec<&str> = tree.iter().map(|(n, _)| n.as_str()).collect();
    let name_of = |want: &[u8]| tree.iter().find(|(_, b)| b == want).map(|(n, _)| n.clone());
    let (a, b) = (name_of(&one), name_of(&two));
    let hash_left = names.iter().any(|n| n.starts_with("Nm"));
    assert!(
        ok && a.is_some() && b.is_some() && a != b && !hash_left,
        "two unnamed FileDescs: rc_ok={ok} one={a:?} two={b:?} \
         hash_left={hash_left}; tree {names:?}\n{log}"
    );
    // The collapse is allowed only because it is SAID: both names are
    // built off the one `unnamed` the sanitizer produced, and the
    // second wears the disambiguating prefix rather than a name of its
    // own invention.
    assert!(
        [a.unwrap(), b.unwrap()]
            .iter()
            .all(|n| n.ends_with("unnamed")),
        "the disambiguation must stay recognisably the sanitized name; tree {names:?}\n{log}"
    );
    drop(fx);
}
