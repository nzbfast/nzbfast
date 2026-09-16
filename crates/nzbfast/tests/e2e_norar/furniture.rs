//! Wave-4 matrix-read rows M4-33 and M4-34: the spare rule, and the
//! naming tier under a set that names no payload.
//!
//! Both rows were PREDICTED by the 30 Aug 2026 third extreme pass and
//! measured on the baseline (origin/main 8fbe1c3bd) before an assertion
//! was written. M4-33 came back RED and worse than predicted - both
//! halves the row named fired at once. M4-34 came back GREEN off
//! a1ec1c12d's per-file gate and is landed as a pass pin.
//!
//! A CHILD of `e2e_norar` for `pins.rs`'s reason, unchanged and worth
//! restating because the pressure that produced it has not eased: three
//! M4 lanes are appending to `mod.rs` at once, and adding these three
//! fixtures there put it 94 lines over its 3,000 size-gate ceiling. A
//! child module sees the parent's private builders through `use
//! super::*` where a sibling directory would need every one of them
//! made `pub(crate)` on lines those lanes are also editing.

use super::*;

/// Row M4-33 (30 Aug 2026): a text release IS its `.txt`, so the spare
/// rule may not read the posted hint's EXTENSION as the whole answer.
///
/// `census::is_furniture_ext` reads `.nfo` `.sfv` `.txt` `.md5` `.diz`
/// as optional furniture, and `get::tail::drop_spared_metadata` then
/// DELETES what it spares - deliberately, because a holed `.nfo` left in
/// the directory looks exactly like a real one. That delete is safe only
/// on its stated premise, "they are furniture rather than payload", and
/// this row is the post where the premise is false.
///
/// Measured on the 30 Aug baseline, and it is the worse half of the two
/// the row predicted rather than either alone: `[get] all 2 files
/// complete ✔`, then `complete, without 1 metadata file(s) no server
/// had: Novel.Chapter.txt (the partial copy was removed - nothing can
/// rebuild it)`, rc 0, output directory holding the 11-byte `.nfo` and
/// nothing else. The user asked for a book and got an empty directory,
/// reported as a success.
///
/// 64 KiB DELIBERATELY, and it is the size the row asks for by name: on
/// a real post that is ONE article, exactly like a scene `.nfo`, so
/// there is no size floor that separates them - every floor low enough
/// to spare a 30 KB ASCII-art `.nfo` still eats a novella. The fix is
/// structural instead (`census::SpareRule`), and this pin is what stops
/// the next lane reaching for the floor.
#[tokio::test(flavor = "multi_thread")]
async fn m4_33_a_text_release_is_not_furniture_because_of_its_extension() {
    let mut fx = Fixture::new("norarbooktxt");
    let data = payload(65_536, 77);
    fx.add_file("Novel.Chapter.txt", &data, 20_000);
    fx.add_file("release.nfo", b"scene nfo\r\n", 40_000);
    let chaos = Chaos {
        missing: HashSet::from(["<Novel_Chapter_txt-0-2@mock>".to_string()]),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    let names = tree_names(&out);
    assert!(
        !ok,
        "a text release short one article completed green - the only file \
         the user asked for was spared on its extension and then deleted \
         as an unrebuildable partial. Tree: {names:?}\n{log}"
    );
    assert!(
        !log.contains("the partial copy was removed"),
        "the deliverable was dropped as spared metadata: {names:?}\n{log}"
    );
    // The bytes that DID arrive stay on disk (as the resume partial):
    // failing the job and destroying the download are different answers,
    // and only the first one is this row's.
    assert!(
        names.iter().any(|n| n.starts_with("Novel.Chapter.txt")),
        "the 48 KiB that did arrive were destroyed as well as the job \
         failed: {names:?}\n{log}"
    );
    // Keep the fixture alive: a dropped one is graded against a deleted
    // tree, which reads as a false red on every assertion above.
    drop(fx);
}

/// Issue #23's own reporter, which the M4-33 fix must not break: a short
/// single-article `.nfo` BESIDE a whole video still completes green.
///
/// The control for the pin above, and the reason its fix is the payload
/// arm rather than "sparing removed". Same damage, same extension, one
/// difference - this post has something in it that is not furniture.
#[tokio::test(flavor = "multi_thread")]
async fn a_short_nfo_beside_a_whole_video_still_completes() {
    let mut fx = Fixture::new("norarnfobeside");
    let data = payload(120_000, 78);
    fx.add_file("Feature.Main.mkv", &data, 40_000);
    fx.add_file("release.nfo", b"scene nfo\r\n", 40_000);
    let chaos = Chaos {
        missing: HashSet::from(["<release_nfo-1-1@mock>".to_string()]),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(
        ok,
        "issue #23 is back: a job whose payload is whole failed on one \
         missing article in its .nfo\n{log}"
    );
    let got = std::fs::read(out.join("Feature.Main.mkv"))
        .unwrap_or_else(|e| panic!("payload missing: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("release.nfo").exists(),
        "a holed .nfo was left in the directory - it looks exactly like a \
         real one, which is why the spare rule deletes what it spares\n{log}"
    );
    drop(fx);
}

/// Row M4-34 (30 Aug 2026) - PASS pin. A PAR2 set that covers only
/// FURNITURE must not suppress the SFV naming tier for the payload it
/// never names.
///
/// W4-05 was PAR2 covering SOME payload with an SFV naming the rest;
/// this is the sharper shape, where the set's ONLY FileDesc is
/// `release.sfv` and every payload file in the post is outside it. The
/// predicted failure is a fix for W4-05 that still keys on "a set
/// exists": a set activates, `land_sfv_names` runs only on the no-set
/// path, and twenty hashed movies stay hashed at rc 0 with the sidecar
/// that names every one of them sitting on disk.
///
/// Measured GREEN on the 30 Aug baseline: a1ec1c12d already moved the
/// gate from per-JOB to per-FILE, so the tier runs over the slots no
/// recovery set CLAIMED, whatever the set happens to cover. Landed as a
/// pin rather than skipped because "a set exists" is the obvious wrong
/// predicate and the per-file `claimed` filter that refuses it is one
/// line.
///
/// What this pin is and is NOT, measured rather than claimed: restoring
/// the per-job gate reddens this AND
/// `par2_and_an_sfv_compose_on_disjoint_files`, so it does not
/// distinguish itself from W4-05 by mutation and must not be read as
/// covering an arm that one leaves open. What it holds is the SHAPE - it
/// is the only fixture in this suite whose recovery set names no payload
/// at all, and a set that covers only its own sidecar is the post where
/// a reader is most likely to reason that suppressing the tier is
/// harmless.
#[tokio::test(flavor = "multi_thread")]
async fn m4_34_a_furniture_only_set_does_not_suppress_the_sfv_tier() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsfvonlyset");
    let a = payload(120_000, 41);
    let b = payload(90_000, 42);
    fx.add_file_obfuscated("Pm4hSx62WbJ", "Pm4hSx62WbJ", &a, 40_000);
    fx.add_file_obfuscated("Qn7kVz19YtR", "Qn7kVz19YtR", &b, 40_000);
    let sfv = format!(
        "Movie.One.mkv {:08X}\r\nMovie.Two.mkv {:08X}\r\n",
        crc32fast::hash(&a),
        crc32fast::hash(&b)
    );
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    // The whole point: the set names the SIDECAR and nothing else.
    assert!(fx.add_par2(20, &["release.sfv"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "furniture-only-set post failed:\n{log}");
    assert!(
        log.contains("set live"),
        "the set never activated, so this post never asked the question \
         the row is about\n{log}"
    );
    for (name, want) in [("Movie.One.mkv", &a), ("Movie.Two.mkv", &b)] {
        let got = std::fs::read(out.join(name)).unwrap_or_else(|e| {
            panic!(
                "{name} kept its hash - a PAR2 set covering only the sidecar \
                 suppressed the tier that reads it: {e}; tree: {:?}\n{log}",
                tree_names(&out)
            )
        });
        assert!(got == *want, "{name} not byte-exact\n{log}");
    }
    drop(fx);
}

/// Item 34 of the 16 Sep 2026 Fable sweep (data-loss): a `.nfo` the
/// census SPARED and the disk-side PAR2 fallback then REBUILT from
/// parity must survive the good finish.
///
/// `drop_spared_metadata`'s whole safety argument is the rule that
/// selected the name - "the recovery set does not cover them, so nothing
/// can rebuild them". The census can only ask that of the IN-STREAM
/// verifier (`census.rs`'s `set_names` comes from `verifier.sets()`), so
/// on a post whose PAR2 INDEX never arrives the answer is structurally
/// "no set covers anything" - and the volumes that land a moment later
/// carry the same critical packets, name the `.nfo`, and repair it.
/// Before the fix the good arm then deleted the file parity had just
/// restored and logged "nothing can rebuild it" about it.
///
/// THE SHAPE IS THE CONJUNCTION AND EVERY PART OF IT IS LOAD-BEARING:
/// a named post (the spare rule only fires on a furniture EXTENSION, so
/// a wholly obfuscated post cannot reach here at all), a `.nfo` short an
/// article, payload beside it (`SpareRule::any_payload`), an index whose
/// every article 430s so no set activates in stream, and volumes with
/// enough parity to solve. The assertions below pin the index arm
/// explicitly: if a set ever DOES activate here the premise is gone and
/// the test would pass for the wrong reason.
///
/// The negative control is
/// `e2e_sniffedpar2::a_disk_repair_does_not_certify_files_outside_its_recovery_set`,
/// where the `.nfo` is genuinely outside the set and must still be
/// deleted - a fix that spares on presence alone leaves a holed `.nfo`
/// in a completed directory, which is the hazard the delete exists for.
#[tokio::test(flavor = "multi_thread")]
async fn item34_a_parity_rebuilt_nfo_is_not_dropped_as_spared_metadata() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsparedrebuilt");
    let video = payload(240_000, 63);
    let nfo = payload(90_000, 64);
    fx.add_file("Feature.Main.mkv", &video, 40_000);
    fx.add_file("release.nfo", &nfo, 40_000);
    // Index AND volumes, posted under their real names. The index is
    // then shot out from under the job below.
    assert!(fx.add_par2(30, &["Feature.Main.mkv", "release.nfo"], 40_000));

    let mut missing: HashSet<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("testset_par2-"))
        .cloned()
        .collect();
    assert!(
        !missing.is_empty(),
        "the PAR2 index was never posted, so nothing here forces the \
         set-less settle path"
    );
    // One article of the .nfo, so the file lands with a hole rather than
    // never being written at all: both are `files_created`/`files_patched`
    // to the repair, and the holed one is the shape the delete was
    // written for.
    let mut nfo_arts: Vec<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("release_nfo-"))
        .cloned()
        .collect();
    nfo_arts.sort();
    assert!(nfo_arts.len() >= 2, "expected a multi-article .nfo");
    missing.insert(nfo_arts[1].clone());

    let (log, ok, out) = run_norar_chaos(
        &fx,
        Chaos {
            missing,
            ..Chaos::default()
        },
    )
    .await;

    assert!(
        !log.contains("[par2] set live"),
        "a set activated IN STREAM, so this post never reaches the \
         set-less settle path this row is about:\n{log}"
    );
    assert!(
        log.contains("repairing from disk"),
        "the disk-side PAR2 fallback never ran, so nothing rebuilt the \
         .nfo and this pins nothing:\n{log}"
    );
    assert!(ok, "the job did not complete:\n{log}");
    let got = std::fs::read(out.join("release.nfo")).unwrap_or_else(|e| {
        panic!(
            "the .nfo parity had just rebuilt was deleted as spared \
             metadata: {e}; tree: {:?}\n{log}",
            tree_names(&out)
        )
    });
    assert!(
        got == nfo,
        "the .nfo survived but is not the posted bytes\n{log}"
    );
    assert!(
        !log.contains("nothing can rebuild it"),
        "the closing line claims nothing could rebuild a file parity \
         rebuilt:\n{log}"
    );
    // The payload is untouched either way - this row is about the
    // furniture, and a fix that traded one for the other is not one.
    assert!(
        std::fs::read(out.join("Feature.Main.mkv")).unwrap() == video,
        "the payload is not byte-exact\n{log}"
    );
    drop(fx);
}

/// THE NEGATIVE CONTROL for the row above, on the SAME set-less path:
/// a spared `.nfo` the disk-side set does NOT name is still deleted.
///
/// Identical fixture to `item34_...` in every respect but one - the PAR2
/// set covers the payload alone - so the two differ only in whether the
/// repair can speak for the furniture. That is the whole discrimination
/// the fix rests on, and it is the reason the prune reads the repair's
/// own report rather than anything about the file: the `.nfo` here is
/// present, is exactly its posted length, and is a zero-filled lie, so
/// neither presence nor size could tell these two runs apart.
///
/// Sparing it instead would be a leak, not a fix - a holed `.nfo` handed
/// to an *arr is the hazard `drop_spared_metadata` exists to prevent
/// (issue #23), and a completed directory is not a scratch directory.
#[tokio::test(flavor = "multi_thread")]
async fn item34_a_spared_nfo_no_disk_set_covers_is_still_dropped() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsparedunrebuilt");
    let video = payload(240_000, 63);
    let nfo = payload(90_000, 64);
    fx.add_file("Feature.Main.mkv", &video, 40_000);
    fx.add_file("release.nfo", &nfo, 40_000);
    // THE ONE DIFFERENCE: the set names the payload and nothing else.
    assert!(fx.add_par2(30, &["Feature.Main.mkv"], 40_000));

    let mut missing: HashSet<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("testset_par2-"))
        .cloned()
        .collect();
    assert!(!missing.is_empty(), "the PAR2 index was never posted");
    let mut nfo_arts: Vec<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("release_nfo-"))
        .cloned()
        .collect();
    nfo_arts.sort();
    assert!(nfo_arts.len() >= 2, "expected a multi-article .nfo");
    missing.insert(nfo_arts[1].clone());

    let (log, ok, out) = run_norar_chaos(
        &fx,
        Chaos {
            missing,
            ..Chaos::default()
        },
    )
    .await;

    assert!(
        !log.contains("[par2] set live"),
        "a set activated in stream, so this is not the same path as the \
         row it controls:\n{log}"
    );
    assert!(
        log.contains("repairing from disk"),
        "the disk-side PAR2 fallback never ran, so this control is \
         vacuous - it has to reach the same pass the row it controls \
         does and come back with nothing to say about the .nfo:\n{log}"
    );
    assert!(ok, "the job did not complete:\n{log}");
    assert!(
        !out.join("release.nfo").exists(),
        "a holed .nfo no recovery set covers survived in the completed \
         directory - the spare was turned into a leak: {:?}\n{log}",
        tree_names(&out)
    );
    assert!(
        log.contains("metadata file(s) no server had"),
        "the job completed silently about what it completed without:\n{log}"
    );
    assert!(
        std::fs::read(out.join("Feature.Main.mkv")).unwrap() == video,
        "the payload is not byte-exact\n{log}"
    );
    drop(fx);
}
