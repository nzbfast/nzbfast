//! M4-18 / M4-19 / M4-28 (30 Aug 2026): a packet sniff, or a name that
//! merely looks like parity, must not eat a payload.
//!
//! The inverse of the naming rows next door. Those stop a NAME
//! finalizing identity against content proof; these ask whether CONTENT
//! that only resembles parity - or a `.par2` suffix on ordinary bytes -
//! can capture a slot the payload owns.
//!
//! A child of e2e_norar rather than a sibling of it, for two reasons:
//! the fixtures here need that module's builders (`run_norar`,
//! `add_par2_named`, `out_tree`), which a sibling could not reach, and
//! `mod.rs` was at 2,809 of its size-gate 3,000-line ceiling - two lanes
//! appending to it on 30 Aug 2026 is what forced this split.

use super::*;
use crate::payloads;

/// A REAL but FOREIGN PAR2 index: par2cmdline run over a scratch file in
/// a subdirectory of the fixture, returned as bytes and the subdirectory
/// removed. Genuine packets - Main, FileDesc, IFSC, Creator - every one
/// of them MD5-sealed, carrying a recovery-set id that is not this
/// post's. Splicing those bytes into a payload is exactly the polyglot
/// the M4-18 / M4-19 rows describe: valid packets, wrong set. Chance
/// magic would not do - `scan_packets` verifies each packet's own MD5,
/// so only real packets reach a parser's set-id test.
fn foreign_par2_index(fx: &Fixture, tag: &str) -> Vec<u8> {
    let sub = fx.dir.join(format!("plant-{tag}"));
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("plant.bin"), payload(4096, 200)).unwrap();
    let st = Command::new("par2")
        .arg("create")
        .arg("-r20")
        .arg("-q")
        .arg("plantset")
        .arg("plant.bin")
        .current_dir(&sub)
        .status();
    assert!(
        matches!(st, Ok(s) if s.success()),
        "par2 create for the foreign plant failed"
    );
    let data = std::fs::read(sub.join("plantset.par2")).unwrap();
    std::fs::remove_dir_all(&sub).unwrap();
    assert!(!data.is_empty(), "the foreign plant index is empty");
    data
}

/// M4-18 (30 Aug 2026): a payload whose first bytes ARE a valid PAR2
/// packet. `collect_packet_files` sniffs every non-`.par2` file by one
/// 8-byte read at offset 0, so a poster who prefixes a tiny recovery
/// index onto a video hands the engine a file that is a payload by
/// FileDesc and a packet file by sniff. Content at offset 0 is the whole
/// seam - n27 is the inverse (an outer set NAMING inner volumes
/// `.par2`).
///
/// Expected: the movie lands under its FileDesc name, byte-exact,
/// prefix included; a foreign index riding at the head is ignored, never
/// allowed to eat the file it is glued to.
#[tokio::test(flavor = "multi_thread")]
async fn a_payload_opening_with_a_foreign_par2_packet_still_lands_as_itself() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarpolyhead");
    let mut data = foreign_par2_index(&fx, "head");
    data.extend_from_slice(&payload(180_000, 71));
    fx.add_file_renamed_by_par2("Polyglot.Feature.mkv", "Hq3nZv84MtB", &data, 40_000);
    assert!(fx.add_par2(20, &["Polyglot.Feature.mkv"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "polyglot-head post failed:\n{log}");
    let got = std::fs::read(out.join("Polyglot.Feature.mkv")).unwrap_or_else(|e| {
        let tree: Vec<String> = out_tree(&out)
            .into_iter()
            .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
            .collect();
        panic!(
            "the payload never landed under its FileDesc name - a magic \
             prefix took it for a recovery volume: {e}; tree: {tree:?}\n{log}"
        )
    });
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("Hq3nZv84MtB").exists(),
        "the obfuscated source name survived beside the published one:\n{log}"
    );
    // The spend oracle: every byte arrived on the wire, so no recovery
    // block may be bought to put it on disk. The seam DOES fire here -
    // the log carries "recovery volume identified in-stream" - and the
    // issue #14 reconcile then takes the file back as payload rather
    // than rebuilding it from parity.
    assert!(
        !log.contains("repair complete") && !log.contains("unrepairable"),
        "parity was spent on a payload that arrived intact\n{log}"
    );
}

/// M4-18's control arm: the SAME fixture with the magic prefix removed.
/// A probe that is red for the predicted reason and for an unrelated one
/// is indistinguishable from outside, so this is the negative that says
/// the prefix is what did it.
#[tokio::test(flavor = "multi_thread")]
async fn the_polyglot_head_control_without_the_prefix_is_green() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarpolyheadctl");
    let mut data = payload(4096, 199);
    data.extend_from_slice(&payload(180_000, 71));
    fx.add_file_renamed_by_par2("Polyglot.Feature.mkv", "Hq3nZv84MtB", &data, 40_000);
    assert!(fx.add_par2(20, &["Polyglot.Feature.mkv"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "control post failed:\n{log}");
    let got = std::fs::read(out.join("Polyglot.Feature.mkv"))
        .unwrap_or_else(|e| panic!("control payload missing: {e}\n{log}"));
    assert!(got == data, "control payload not byte-exact\n{log}");
}

/// M4-19 (30 Aug 2026): valid packets planted LATER inside a payload
/// that a FileDesc names `.par2`. The offset-0 sniff cannot see a
/// mid-file plant, but extension collection does not sniff at all -
/// `find_magic` then walks the whole haystack and `scan_packets`
/// promotes whatever it finds. Distinct from M4-18, which is content at
/// offset 0 on a hash-named file.
///
/// Expected: the video bytes are not a recovery set. Both payloads land
/// byte-exact under their FileDesc names and the real set still works.
#[tokio::test(flavor = "multi_thread")]
async fn packets_planted_mid_payload_do_not_capture_a_par2_named_file() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarpolymid");
    let plant = foreign_par2_index(&fx, "mid");
    let mut decoy = payload(60_000, 72);
    let at = 30_000;
    decoy.splice(at..at, plant.iter().copied());
    let feature = payload(120_000, 73);
    fx.add_file_renamed_by_par2("Feature.mkv", "Rw6bKd37XpL", &feature, 40_000);
    fx.add_file_renamed_by_par2("bonus.par2", "Cx8pRt41KwN", &decoy, 40_000);
    // `add_par2_named` and not `add_par2`: the latter globs every
    // `*.par2` in the fixture dir once par2cmdline has run, which would
    // sweep the STAGED decoy into the post as a second wire file and
    // delete it off disk. Collecting only this base's own outputs leaves
    // the decoy where it belongs - reachable on the wire under its hash
    // alone, so the FileDesc is the only thing that can name it.
    assert!(add_par2_named(
        &mut fx,
        "testset",
        &["Feature.mkv", "bonus.par2"],
        40_000,
        false
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "mid-file plant post failed:\n{log}");
    let got_f = std::fs::read(out.join("Feature.mkv")).unwrap_or_else(|e| {
        let tree: Vec<String> = out_tree(&out)
            .into_iter()
            .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
            .collect();
        panic!(
            "the real set stopped working - a planted packet in a sibling \
             payload poisoned it: {e}; tree: {tree:?}\n{log}"
        )
    });
    assert!(got_f == feature, "Feature.mkv not byte-exact\n{log}");
    let got_b = std::fs::read(out.join("bonus.par2")).unwrap_or_else(|e| {
        panic!("the `.par2`-named payload was eaten rather than published: {e}\n{log}")
    });
    assert!(got_b == decoy, "bonus.par2 not byte-exact\n{log}");
    assert!(
        !log.contains("repair complete") && !log.contains("unrepairable"),
        "parity was spent on payloads that arrived intact\n{log}"
    );
}

/// M4-28 (30 Aug 2026): the wire name is `set.par2` and the bytes are
/// the movie. Packet-identity theft rather than W4-02's crossed pair -
/// a `.par2` suffix is not stronger evidence than any other name, and
/// content proof (md5_16k / whole-file MD5 in the FileDesc) is what
/// should decide.
///
/// Expected: the movie lands under its FileDesc name, byte-exact, and is
/// neither deferred as a recovery volume nor swept as a spent one.
#[tokio::test(flavor = "multi_thread")]
async fn a_par2_wire_name_over_movie_bytes_does_not_claim_the_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarpar2name");
    let data = payload(150_000, 74);
    fx.add_file_renamed_by_par2("Stolen.Feature.mkv", "set.par2", &data, 40_000);
    assert!(fx.add_par2(20, &["Stolen.Feature.mkv"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "par2-named payload post failed:\n{log}");
    let got = std::fs::read(out.join("Stolen.Feature.mkv")).unwrap_or_else(|e| {
        let tree: Vec<String> = out_tree(&out)
            .into_iter()
            .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
            .collect();
        panic!(
            "a `.par2` wire name took the payload slot - the movie never \
             landed under its FileDesc name: {e}; tree: {tree:?}\n{log}"
        )
    });
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("set.par2").exists(),
        "the `.par2` wire name survived beside the published payload:\n{log}"
    );
    // The spend oracle, and on this row it is the whole tell. Before the
    // fix the file was excluded from the payload census, so it priced as
    // wholly missing and repair was asked for 1974 blocks against the
    // 395 the post carries - an unrepairable job over a download whose
    // every byte had already arrived.
    assert!(
        !log.contains("repair complete") && !log.contains("unrepairable"),
        "parity was spent rebuilding a payload that arrived intact\n{log}"
    );
}

/// M4-98 (30 Aug 2026): the NZB SUBJECT says `.par2` and the body is the
/// movie. Three fixtures, because the row's own mechanism paragraph
/// names two doors (`Par2Main capture / Par2Volume deferred`) and the
/// answer differs by whether a recovery set is there to prove anything
/// against.
///
/// MEASURED GREEN on the Par2Main half, and it fell out of M4-28's fix
/// rather than needing one of its own: `NzbFile::kind` reads the subject
/// and nothing else, so `abc123.par2` builds a `Par2Main` slot exactly
/// as a `.par2` WIRE name does, and `reclaim_par2_named_payload` demotes
/// it on the same content proof. The subject and the wire name are two
/// routes to one classification, which is why one guard covers both.
///
/// The Par2VOLUME half is RED and is deliberately NOT pinned here - see
/// the M4-98 section of the wave-4 matrix handoff. A volume-spelled
/// subject (`abc123.vol000+50.par2`) never gets a slot at all
/// (`plan.rs`'s `continue`), so its bytes are never fetched and there is
/// nothing on disk for any content proof to read. That is follow-up P1
/// of the M4-28 lane, it is a scheduling question rather than a
/// classification one, and half-building it here was refused.
///
/// The classifier itself is NOT at fault and gets no new unit test:
/// `abc123.par2` really is a `Par2Main` CLAIM by name, and
/// `classify_subject` answering so is correct. The family rule
/// (`2b7f5495e`) is about what may FINALIZE identity, and the finalizing
/// happens downstream.
#[tokio::test(flavor = "multi_thread")]
async fn a_par2_subject_over_movie_bytes_is_published_as_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarpar2subj");
    let data = payload(150_000, 91);
    // Subject lies, yEnc `name=` tells the truth: the shape a poster
    // reaches by naming the manifest entry after the recovery set.
    fx.add_file_obfuscated("abc123.par2", "Lying.Subject.mkv", &data, 40_000);
    assert!(add_par2_named(
        &mut fx,
        "testset",
        &["Lying.Subject.mkv"],
        40_000,
        false
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "par2-subject post failed:\n{log}");
    let got = std::fs::read(out.join("Lying.Subject.mkv")).unwrap_or_else(|e| {
        let tree: Vec<String> = out_tree(&out)
            .into_iter()
            .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
            .collect();
        panic!(
            "a `.par2` SUBJECT took the payload slot - the movie never \
             landed under its FileDesc name: {e}; tree: {tree:?}\n{log}"
        )
    });
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("abc123.par2").exists(),
        "the `.par2` subject name survived beside the published payload:\n{log}"
    );
    // THE DEMOTION IS THE ASSERTION, and without this line the test
    // passes on the yEnc rename alone - the sibling below is the control
    // arm that proves it. `all 1 files complete` is the other half:
    // demotion is what puts the slot into the payload census, and the
    // control arm reaches `all 0` with the very same bytes on disk.
    assert!(
        log.contains("is named like a recovery file but its bytes are payload"),
        "the subject route never reached the content-proof demotion\n{log}"
    );
    assert!(
        log.contains("all 1 files complete"),
        "the demoted slot never entered the payload census\n{log}"
    );
    assert!(
        !log.contains("repair complete") && !log.contains("unrepairable"),
        "parity was spent rebuilding a payload that arrived intact\n{log}"
    );
}

/// M4-98, the CONTROL ARM for the pin above and a row in its own right:
/// the same lying `.par2` subject with NO recovery set anywhere in the
/// post, so there is no FileDesc for the demotion to match and the
/// content proof cannot run at all.
///
/// The bytes still survive, because the yEnc `name=` renames the slot
/// independently of the classification - which is exactly why the pin
/// above has to assert the demotion LINE rather than the file landing.
/// Here the file lands and the census still reads `all 0 files complete`.
#[tokio::test(flavor = "multi_thread")]
async fn a_par2_subject_with_no_recovery_set_still_publishes_the_body() {
    let mut fx = Fixture::new("norarpar2subjnoset");
    let data = payload(150_000, 92);
    fx.add_file_obfuscated("abc123.par2", "Lying.Subject.mkv", &data, 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "par2-subject post with no set failed:\n{log}");
    let got = std::fs::read(out.join("Lying.Subject.mkv")).unwrap_or_else(|e| {
        let tree: Vec<String> = out_tree(&out)
            .into_iter()
            .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
            .collect();
        panic!("the movie was consumed as recovery data: {e}; tree: {tree:?}\n{log}")
    });
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("abc123.par2").exists(),
        "the `.par2` subject name survived beside the published payload:\n{log}"
    );
    assert!(
        !log.contains("is named like a recovery file but its bytes are payload"),
        "the demotion fired with no recovery set to prove anything against - \
         it is matching on something weaker than a FileDesc\n{log}"
    );
}

/// M4-98, the worst honest case: the subject AND the yEnc `name=` both
/// say `.par2`, and no recovery set is posted - so nothing anywhere in
/// the post carries a true name and no content proof is available.
///
/// The row predicted "the articles are parsed as PAR2 packets, fail, and
/// the movie never lands". Half right: the parse does fail, twice
/// (activation, then the post-download pass). The bytes are KEPT, under
/// the only name the poster gave, which is the most this can honestly
/// answer. The pin is that a failed packet parse never costs the file.
#[tokio::test(flavor = "multi_thread")]
async fn a_par2_subject_and_wire_name_with_no_set_keeps_the_bytes() {
    let mut fx = Fixture::new("norarpar2subjboth");
    let data = payload(150_000, 93);
    fx.add_file_obfuscated("abc123.par2", "abc123.par2", &data, 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "doubly-lying par2 post failed:\n{log}");
    let got = std::fs::read(out.join("abc123.par2")).unwrap_or_else(|e| {
        let tree: Vec<String> = out_tree(&out)
            .into_iter()
            .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
            .collect();
        panic!(
            "the payload was eaten by the packet parser rather than \
             published: {e}; tree: {tree:?}\n{log}"
        )
    });
    assert!(got == data, "payload not byte-exact\n{log}");
}

/// M4-90's JOB-LEVEL pin, and it could not be written until 31 Aug 2026.
///
/// The row landed on 30 Aug as an IN-STREAM rule: `archive_sniff_eligible_name`
/// stopped the byte-0 RAR/7z arms magic-sniffing a file the poster named
/// as content, so `Movie.mkv` stopped attaching to the extractor
/// mid-flight. That is observable at `Extractor::slot_plain_by_sniff`
/// and is pinned next door in `nzbkit::extract::polyglot_tests`.
///
/// It changed nothing a user could see. `unpack::is_extractable_archive`
/// asked the same question of the file once it had LANDED and gated RAR
/// and 7z on `is_final_file` alone, so the declined movie materialized
/// whole, was listed as an entry archive by the disk post-pass, unpacked,
/// and then swept as a spent intermediate - and the job reported
/// Completed holding a folder of archive members where the movie had
/// been. An e2e asserting "the named movie survives the job" therefore
/// FAILED on 30 Aug with the stream half already correct, which is why
/// this file carried no such row until the disk half closed.
///
/// WHAT IS ASSERTED, and why it is not the in-stream observable: reading
/// the output tree cannot distinguish a slot the sniff DECLINED from one
/// that attached and later demoted - both end with bytes on disk. So the
/// job-level question is the plain one the user would ask. The movie is
/// still there, under the name it was posted under, byte-exact; the
/// members that unpacking it would have produced are not.
///
/// WHICH SITE ACTUALLY LOSES THE MOVIE, measured with this row on 31 Aug
/// 2026 by reverting one site at a time, because it is not the one the
/// item was written against. Reverting `is_extractable_archive` ALONE
/// leaves this row GREEN: `Movie.mkv` carries no RAR name grammar, so
/// the file never reaches the entry-archive list at all - it is claimed
/// by `collect_obfuscated_rar_volumes`, which had the identical hole and
/// whose caller DELETES what it spends. Reverting THAT one alone is
/// enough to fail this row, with the log line
/// `[nest] could not remove spent intermediate .../out/Movie.mkv`.
///
/// So do not read the entry-archive gate as the fix and the collectors
/// as tidying: for the commonest shape the collector IS the fix, and a
/// lane that had closed only the site named in the report would have
/// shipped a green suite and an unchanged product. That is the whole
/// reason this row is at job level rather than a unit pin on a
/// predicate.
///
/// The fixture is a REAL RAR5 archive, not crafted magic: `solid.rar`
/// from the vendored rars corpus, whose two members (`hello.txt`,
/// `tiny.txt`) are what an unpack would leave behind. Chance magic would
/// prove less - a file that merely starts `Rar!` fails to open, so
/// declining it and failing to unpack it look identical from the tree.
/// Here the archive is perfectly valid and the ONLY reason it survives
/// is the name.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_rar_posted_under_a_payload_name_survives_the_whole_job() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let rar = std::fs::read(rars_fixture_dir().join("solid.rar")).unwrap();
    assert!(
        rar.starts_with(b"Rar!\x1a\x07\x01\x00"),
        "the fixture must be a real RAR5 or this row proves nothing"
    );
    let mut fx = Fixture::new("norarm490disk");
    fx.add_file("Movie.mkv", &rar, 40_000);
    // A second, ordinary payload so the job is a release rather than one
    // lone file: the sweep that deletes spent intermediates only runs
    // over a directory it believes held archives, and this keeps the
    // fixture on the same path a real post takes.
    let feature = payload(120_000, 91);
    fx.add_file("Notes.nfo", &feature, 40_000);
    assert!(fx.add_par2(20, &["Movie.mkv", "Notes.nfo"], 40_000));

    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "payload-named RAR post failed:\n{log}");

    let got = std::fs::read(out.join("Movie.mkv")).unwrap_or_else(|e| {
        let tree: Vec<String> = out_tree(&out)
            .into_iter()
            .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
            .collect();
        panic!(
            "the movie was unpacked and swept - the name did not hold: \
             {e}; tree: {tree:?}\n{log}"
        )
    });
    assert!(
        got == rar,
        "the movie survived but is not byte-exact\n{log}"
    );
    for member in ["hello.txt", "tiny.txt"] {
        assert!(
            !out.join(member).exists(),
            "{member} is on disk, so the archive WAS unpacked:\n{log}"
        );
    }
    assert!(
        std::fs::read(out.join("Notes.nfo")).unwrap() == feature,
        "the ordinary payload beside it did not land\n{log}"
    );
}

/// The control arm for the row above, and it is the one that keeps the
/// rule honest rather than merely satisfied. The SAME archive, posted
/// under this product's own model of an obfuscated name, MUST still be
/// unpacked: a hash name is the absence of evidence, not weaker
/// evidence, so the content magic is the strongest thing available and
/// the one-pass path is exactly what it is for.
///
/// Without this arm, "fixing" a future polyglot report by widening the
/// deny list onto `.bin` or onto extensionless names would pass every
/// assertion above while breaking every obfuscated set in production -
/// which is the regression the deny list was chosen over an allow list
/// to avoid in the first place.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_rar_under_an_obfuscated_name_is_still_unpacked() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let rar = std::fs::read(rars_fixture_dir().join("solid.rar")).unwrap();
    let mut fx = Fixture::new("norarm490ctl");
    fx.add_file("a1b2c3d4e5f6.bin", &rar, 40_000);
    assert!(fx.add_par2(20, &["a1b2c3d4e5f6.bin"], 40_000));

    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "obfuscated control post failed:\n{log}");
    let tree: Vec<String> = out_tree(&out)
        .into_iter()
        .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
        .collect();
    assert!(
        out.join("hello.txt").exists() && out.join("tiny.txt").exists(),
        "the obfuscated archive was NOT unpacked - the name rule has \
         been widened onto the shape the one-pass path exists for; \
         tree: {tree:?}\n{log}"
    );
}

/// `par2 create` with the recovery geometry spelled out, posting the
/// INDEX as well as the volumes.
///
/// `add_par2_named` next door is `-r<pct>` over par2cmdline's default
/// LIMITED layout, which is exponential - 1, 2, 4, 8, ... blocks - so
/// the block total is whatever that arithmetic lands on. The row below
/// is about a comparison between two totals and needs both of them
/// exact, which is what `-c<blocks> -n<volumes> -u` buys: `volumes`
/// uniform volumes of `blocks / volumes` slices each.
///
/// The index IS posted, unlike `ondisk_recovery`'s sibling helper: a
/// post that bootstraps from its smallest volume starts with recovery
/// already on disk, and `on_hand` at zero is what keeps this row's
/// arithmetic to the one subtraction it is about.
fn add_par2_uniform(
    fx: &mut Fixture,
    block_size: u64,
    recovery_blocks: u32,
    volumes: u32,
    files: &[&str],
    art_size: usize,
) -> bool {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-s{block_size}"))
        .arg(format!("-c{recovery_blocks}"))
        .arg(format!("-n{volumes}"))
        .arg("-u")
        .arg("-q")
        .arg("testset")
        .args(files)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return false,
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    let mut posted = 0usize;
    for p in &par2s {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let data = std::fs::read(p).unwrap();
        let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
        let segs = make_file_articles(&name, &data, art_size, &tag, &mut fx.articles);
        fx.nzb_files.push((name, segs));
        posted += 1;
        std::fs::remove_file(p).unwrap();
    }
    // A geometry par2cmdline declined to produce would leave this row
    // measuring some other post's arithmetic, so it is a refusal rather
    // than a quiet pass: `volumes` volumes plus the one index.
    posted == volumes as usize + 1
}

/// L2 of the wave-4 matrix read (31 Aug 2026): a recovery volume was
/// credited with the block count its FILENAME claimed, and `have` - the
/// only gate in front of `repair::shortfall_is_final` - is the fold of
/// those counts. One `.volNNNN+MMMMMM.par2` name over a body with no
/// room for the slices it names therefore carries `have` past `needed`
/// on its own, and the whole escalation chain behind that gate - donor
/// dirs, `adoption_candidates_present`, `in_set_harvest_possible`,
/// `repeated_block_donor_possible` - is skipped for the job.
///
/// THE ARITHMETIC, every figure asserted rather than described.
/// 2,000-byte blocks over a 100,000-byte payload is 50 blocks; `-c20 -n4
/// -u` posts 20 recovery blocks as four uniform volumes of five. A
/// 4,000-byte article is two whole blocks, so fifteen corrupted articles
/// is **30** blocks damaged - more than the 20 the post really carries,
/// so a shortfall is the honest answer and its arithmetic is what the
/// gate prints. The impostor's body is 10,000 bytes, which at this block
/// size has room for **5** slices however loudly its name says 900,000,
/// so `have` is 20 + 5 = **25** and 25 under 30 is the shortfall branch.
///
/// WITHOUT THE CEILING `have` is 900,020, the gate is never called at
/// all, and the run goes straight to sizing a buy off a budget that does
/// not exist. That is the direction which LOOKS safe - a larger `have`
/// makes `have < needed` less likely, so it errs toward escalating - and
/// it is exactly why this went unnoticed. Both halves are asserted here:
/// the honest line must be present, and the buy must not.
///
/// THE VOLUME-COUNT LIE IS NOT WHAT THE AFFINITY FILTER IS FOR, which is
/// why the impostor is named `testset.*`. That filter asks which SET a
/// volume belongs to; every name in this post answers `testset`, so it
/// passes all five and has nothing to say about whether any of them is
/// telling the truth about its own SIZE. Naming the impostor anything
/// else would leave this row measuring the filter instead - and would
/// measure it wrongly, because the index lands in `out_dir` here, so
/// `index_bases_on_disk` arms the filter and a foreign base is dropped
/// before the count is ever folded.
///
/// DO NOT relax the two counts. `30` is the damage the corrupted
/// articles place block for block, and `25` is the whole subject of the
/// row: 20 real blocks plus the five the impostor's bytes have room for,
/// against the 900,000 its name claims.
#[tokio::test(flavor = "multi_thread")]
async fn a_volume_name_cannot_credit_more_blocks_than_its_bytes_have_room_for() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarvolcount");
    let data = payloads::unique_payload(100_000, 61);
    let posted = "Qm4vTr91Ls3";
    fx.add_file_renamed_by_par2("Repair.Me.mkv", posted, &data, 4_000);
    assert!(add_par2_uniform(
        &mut fx,
        2_000,
        20,
        4,
        &["Repair.Me.mkv"],
        40_000,
    ));
    // The impostor, added AFTER par2 create so the recovery set does not
    // cover it: a volume-shaped SUBJECT over a body with room for five
    // slices, whose name declares nine hundred thousand.
    fx.add_file_obfuscated(
        "testset.vol9000+900000.par2",
        "Impostor.Chunk.bin",
        &payloads::unique_payload(10_000, 62),
        40_000,
    );
    // Parts are 1-based over 4,000-byte articles, and 4,000 is two whole
    // 2,000-byte blocks, so parts 6..=20 is exactly 30 blocks.
    let mut corrupt = HashSet::new();
    for p in 6..=20 {
        corrupt.insert(format!("<{posted}-0-{p}@mock>"));
    }
    let (log, ok, _out) = run_norar_chaos(
        &fx,
        Chaos {
            corrupt,
            ..Chaos::default()
        },
    )
    .await;
    assert!(
        !ok,
        "30 blocks of damage against 20 declared recovery blocks is not \
         repairable - this row's premise has moved:\n{log}"
    );
    // THE PREMISE: the damage really is the 30 blocks the geometry says,
    // so the `25` below is being compared against the right thing.
    assert!(
        log.contains("Repair.Me.mkv - 30/50 blocks bad"),
        "the corrupted articles did not place the damage this row's \
         arithmetic assumes\n{log}"
    );
    // THE GATE RAN, and it ran on the parity the post can actually
    // support.
    assert!(
        log.contains("unrepairable: 30 blocks needed, only 25 recovery blocks in the NZB"),
        "the shortfall gate was skipped or was handed an inflated `have` \
         - a name claiming 900,000 slices in 10,000 bytes was believed\n{log}"
    );
    // ...and nothing was bought on the strength of it. This is the line
    // the inflated `have` reaches instead.
    assert!(
        !log.contains("block(s) \u{2192} fetching"),
        "recovery was bought against a block budget the post does not \
         carry\n{log}"
    );
    // The fixture outlives every assertion above - its `ScratchDir`
    // guard removes the tree the failure messages are graded against.
    drop(fx);
}

/// L1 / M4-28's P1 (31 Aug 2026): the SAME theft as
/// `a_par2_subject_over_movie_bytes_is_published_as_payload` above,
/// spelled as a recovery VOLUME instead of as the set index. One string
/// differs between the two fixtures.
///
/// It was a total loss on origin/main `632096f71` and the log is in
/// `crates/nzbfast/src/repair/volpayload.rs`: the file is never fetched
/// at ALL, because `build_fetch_plan` skips a non-bootstrap
/// `Par2Volume` before a slot exists, so every rescue in
/// `get/settle.rs` is blind to it by construction - `all 0 files
/// complete`, `file missing entirely`, `1974 blocks needed, only 395`,
/// and the job ERRORS. `reclaim_par2_named_payload` could not be
/// widened onto it: it is slot-indexed and there is no slot.
///
/// The rescue runs at the one moment the alternative to spending the
/// fetch is losing the file - a FINAL recovery shortfall with a FileDesc
/// wholly absent - and identifies what it buys by CONTENT (exact length
/// plus the FileDesc's md5-16k), never by the name the poster gave.
#[tokio::test(flavor = "multi_thread")]
async fn a_payload_posted_under_a_recovery_volume_name_is_rescued() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarvolsubj");
    let data = payload(150_000, 91);
    fx.add_file_obfuscated("abc123.vol000+50.par2", "Vol.Subject.mkv", &data, 40_000);
    assert!(add_par2_named(
        &mut fx,
        "testset",
        &["Vol.Subject.mkv"],
        40_000,
        false
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "volume-subject post failed:\n{log}");
    let got = std::fs::read(out.join("Vol.Subject.mkv")).unwrap_or_else(|e| {
        let tree: Vec<String> = out_tree(&out)
            .into_iter()
            .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
            .collect();
        panic!(
            "a recovery-VOLUME subject took the payload out of the post - the \
             movie was never fetched: {e}; tree: {tree:?}\n{log}"
        )
    });
    assert!(got == data, "payload not byte-exact\n{log}");
    // THE RESCUE IS THE ASSERTION. Without it the file cannot arrive by
    // any other route: the plan skipped it, so nothing on the wire ever
    // asked for those articles.
    assert!(
        log.contains("is payload the recovery set covers"),
        "the volume route never reached the content-proof rescue\n{log}"
    );
    assert!(
        log.contains("repair complete"),
        "the rescue landed the bytes but nothing re-read the set off disk\n{log}"
    );
    // NOT `!log.contains("unrepairable")`: the recovery ARITHMETIC really
    // is final here and `shortfall_is_final` says so before the rescue is
    // reached at all - that warn is the trigger, not a verdict. What must
    // not survive is the JOB's failure, which is this line.
    assert!(
        !log.contains("PAR2 repair could not complete"),
        "the job still gave up on a download whose every byte was postable\n{log}"
    );
}

/// The CONTROL ARM for the pin above, and the one that keeps its cost
/// honest: the identical post with a TRUTHFUL volume name, so nothing is
/// missing and the rescue must never arm. Its trigger is a FINAL
/// recovery shortfall with a wholly absent FileDesc, and a healthy post
/// has neither - so the log must carry no sign of it and no volume may
/// be bought for it.
#[tokio::test(flavor = "multi_thread")]
async fn a_healthy_post_never_spends_the_volume_payload_rescue() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarvolhealthy");
    let data = payload(150_000, 94);
    fx.add_file("Vol.Subject.mkv", &data, 40_000);
    assert!(add_par2_named(
        &mut fx,
        "testset",
        &["Vol.Subject.mkv"],
        40_000,
        false
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "healthy control post failed:\n{log}");
    assert!(
        std::fs::read(out.join("Vol.Subject.mkv")).unwrap() == data,
        "control payload not byte-exact\n{log}"
    );
    assert!(
        !log.contains("are the size of one of them"),
        "the rescue's screen ran on a post with nothing missing\n{log}"
    );
    assert!(
        !log.contains("is payload the recovery set covers"),
        "the rescue fired on a healthy post\n{log}"
    );
}

/// The CONSERVATIVE arm: a post that really is short of parity must
/// still fail, and must not buy the rescue's way out of it. Same shape
/// as the pin above minus the lie - the payload is posted honestly and
/// then wholly LOST, so a FileDesc is absent, the shortfall is final,
/// and the only recovery volumes in the NZB are real ones sized by their
/// own block counts.
///
/// This is what stops the screen degenerating into "buy everything when
/// a file is missing", which would spend the whole recovery set's wire
/// on every unrepairable job.
#[tokio::test(flavor = "multi_thread")]
async fn a_genuinely_lost_file_still_fails_without_buying_the_whole_set() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarvollost");
    let data = payload(150_000, 95);
    // On disk for par2 to cover, and NOT on the wire: the file is
    // declared by the set and no article anywhere carries it.
    std::fs::write(fx.dir.join("Gone.Subject.mkv"), &data).unwrap();
    assert!(add_par2_named(
        &mut fx,
        "testset",
        &["Gone.Subject.mkv"],
        40_000,
        false
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(
        !ok,
        "a post with no payload articles at all reported success:\n{log}"
    );
    // MEASURED 31 Aug 2026 and pinned deliberately: at this geometry ONE
    // real recovery volume (166,038 declared bytes against a 150,000-byte
    // FileDesc) falls inside the band, so the screen DOES buy something
    // here. That is the trade the band makes on purpose - a miss is a
    // total loss and a false positive is one volume-sized fetch on a job
    // that was already failing - and this arm is what proves the second
    // half of it is survivable.
    assert!(
        log.contains("are the size of one of them"),
        "the screen never ran, so this arm is not testing the rejection\n{log}"
    );
    assert!(
        log.contains("none of the volume-named candidates carried a missing file's bytes"),
        "the content proof did not reject a real recovery volume\n{log}"
    );
    assert!(
        !log.contains("is payload the recovery set covers"),
        "the rescue claimed a real recovery volume as payload\n{log}"
    );
    assert!(
        log.contains("unrepairable"),
        "the honest shortfall verdict was lost\n{log}"
    );
    assert!(
        log.contains("PAR2 repair could not complete"),
        "a post whose payload was never posted must still fail\n{log}"
    );
    // L1 residue (31 Aug 2026): the candidate the content proof declined
    // is on disk, and NOTHING was renaming it aside. Measured at
    // `b30f29813` this directory held `testset.par2.nzbfast-partial`
    // beside a BARE `testset.vol007+008.par2` of 160,408 bytes - the
    // inversion of the quarantine's own stated invariant, because the
    // one file that arrived through the rescue's side door is the one it
    // could not see: it has no slot (`build_fetch_plan` skips a
    // non-bootstrap `Par2Volume` before a slot exists, which is the
    // whole reason the rescue exists) and it was never extracted.
    //
    // Graded as the invariant rather than by naming that one volume, and
    // neither its name nor its size is pinned: a failing job leaves NO
    // importable name behind, whatever geometry the par2 on THIS box
    // chose. CI installs 0.8.1 where every dev box is on 1.3.0 (claim
    // `red-one-process-light-4d1945ca`), so a pinned volume name or byte
    // count is a red that says nothing about this fix. The journal is
    // the deliberate exception - it is the resume state, it is a
    // dotfile, and no importer reads it.
    let bare: Vec<String> = std::fs::read_dir(&out)
        .expect("read the failed job's output directory")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.') && !n.ends_with(nzbkit::journal::PARTIAL_SUFFIX))
        .collect();
    assert!(
        bare.is_empty(),
        "a failed job left importable name(s) behind: {bare:?}\n{log}"
    );
    // And the bytes are KEPT, not deleted - the rename is what the retry
    // path's `unquarantine_partials` undoes, so a candidate this bought
    // is still there for the next attempt to reason about.
    let vol_kept: Vec<u64> = std::fs::read_dir(&out)
        .expect("read the failed job's output directory")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".vol"))
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .collect();
    assert!(
        vol_kept.iter().any(|&n| n > 0),
        "the declined candidate's bytes did not survive the quarantine\n{log}"
    );
}
