//! Wave-4 matrix-read, FOURTH extreme pass: rows M4-56, M4-57, M4-58
//! and M4-62 - the four repair-side rows.
//!
//! A CHILD of `e2e_norar` rather than a sibling directory, for `pins.rs`
//! and `zipzero.rs`'s reason word for word: a child sees the parent's
//! builders through `use super::*` where a sibling would need every one
//! of them made `pub(crate)` on lines other M4 lanes are also editing.
//! It is its own file because `e2e_norar/mod.rs` was 94 lines under the
//! size gate's ceiling with about a dozen lanes appending to it.
//!
//! All four rows were PREDICTIONS and all four were MEASURED on the
//! 30 Aug 2026 baseline before an assertion was written. M4-56 and
//! M4-62 came back RED and land with their fixes (both in `nzbkit`, and
//! both pinned directly in `par2repair/unit_tests.rs` as well - this
//! file carries M4-62's closed-world half). M4-57 and M4-58 came back
//! GREEN and land as pass pins with the measurement that falsifies
//! them, which is the family convention and not a courtesy: a row that
//! comes back green is a fact about the engine that nothing else
//! records.

use super::*;

/// M4-57 - a FileDesc names a `.7z` or a `.tar` we then extract. The row
/// predicted "extract-and-spend, false green or a missing-file warning",
/// and it explicitly refused to be settled by M4-39's green on the zip:
/// the follow-up note that opened it (Z1, in the matrix read) says the
/// analogy does not carry, because the 7z arm CHASES the archive to disk
/// and `sevenz_finish` deletes it, where the zip never lands at all.
///
/// MEASURED GREEN, 30 Aug 2026, on the ONE-PASS path - and for M4-39's
/// reason after all, which is the thing that had to be measured rather
/// than inferred. The log orders itself:
///
/// ```text
/// [verify] verified 1 file(s): 66 blocks in-stream, 0 by read-back, 0 bad
/// [extract] extracted 2 file(s) in-stream - volumes never touched disk [7z · one-pass]
/// ```
///
/// The archive's own descriptor is satisfied ON THE WIRE, block by block
/// against the IFSC, before any byte of it becomes an inner member. The
/// tar arm is the same shape without the badge. Both are pinned here
/// because M4-39's zip pin cannot speak for either: `top_level_7z_
/// extracts_one_pass` and `e2e_tar` ask the EXTRACTION question of these
/// containers and neither asks the PAR2 one.
///
/// The load-bearing assertion is the in-stream verify line. An engine
/// that started unpacking before the set could check the archive would
/// still land both members and still exit 0, and only that line would
/// move.
#[tokio::test(flavor = "multi_thread")]
async fn a_filedesc_named_7z_and_tar_are_verified_before_being_unpacked() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let a = b"alpha member of the container, first\n".repeat(60);
    let b = b"beta member of the container, second\n".repeat(60);
    for (name, arch) in [
        (
            "photos.7z",
            sevenz_container(&[("alpha.txt", &a), ("beta.txt", &b)]),
        ),
        (
            "photos.tar",
            nzbkit::tar::fixtures::tar_of(&[
                nzbkit::tar::fixtures::Spec::file("alpha.txt", &a),
                nzbkit::tar::fixtures::Spec::file("beta.txt", &b),
            ]),
        ),
    ] {
        let mut fx = Fixture::new(&format!("norar{}deliv", &name[7..]));
        fx.add_file(name, &arch, 40_000);
        assert!(fx.add_par2(20, &[name], 40_000));
        let (log, ok, out) = run_norar(&fx).await;
        assert!(ok, "{name} as the deliverable failed to post:\n{log}");
        assert!(
            log.contains("verified 1 file(s)") && log.contains("blocks in-stream"),
            "{name}'s own FileDesc was never checked against the wire bytes - \
             the unpack ran ahead of the recovery set\n{log}"
        );
        assert!(
            log.contains("clean download"),
            "no clean verdict for a post whose only FileDesc verified\n{log}"
        );
        for (member, want) in [("alpha.txt", &a), ("beta.txt", &b)] {
            let got = std::fs::read(out.join(member)).unwrap_or_else(|e| {
                panic!("{member} missing from the unpacked {name}: {e}\n{log}")
            });
            assert!(got == *want, "{member} is not byte-exact\n{log}");
        }
        assert!(
            !out.join(name).exists(),
            "the mapped container was materialized after all\n{log}"
        );
        drop(fx);
    }
}

/// M4-57's sharp half, and the one Z1 said had to be measured on its own
/// terms: the arm where the archive DOES land on disk and IS deleted.
/// A damaged `.7z` cannot be repaired in a chased slot (its bytes are in
/// RAM, not a file par2 can patch), so the ladder materializes it,
/// repairs it in place, unpacks from disk, and `sevenz_finish` removes
/// it. "A file that existed on disk and was removed is not the same
/// closed-world question as a container that never landed."
///
/// MEASURED GREEN, 30 Aug 2026, and the mechanism is a DIFFERENT one
/// from the row above - which is exactly why inferring it from M4-39
/// would have been wrong. The log orders itself:
///
/// ```text
/// [repair] repair complete ✔ (native, in place: 3 block(s) rebuilt across 1 file(s))
/// [extract] 7z unpack complete ✔
/// [nest] removed spent intermediate .../out/photos.7z
/// ```
///
/// The descriptor is satisfied by the REPAIR - the archive is rebuilt
/// and re-hashed against its FileDesc MD5 - before extraction spends it,
/// and the deletion is then reported as what it is rather than left for
/// a census to notice. `damaged_top_level_7z_materializes_repairs_and_
/// unpacks` pins the extraction half of this path and says nothing about
/// the ordering.
#[tokio::test(flavor = "multi_thread")]
async fn a_repaired_7z_is_proved_before_the_unpack_spends_it() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norar7zdmg");
    let a = incompressible(300_000, 71);
    let b = incompressible(300_000, 72);
    let arch = sevenz_container(&[("alpha.bin", &a), ("beta.bin", &b)]);
    fx.add_file("photos.7z", &arch, 60_000);
    // An explicit block size: left to par2cmdline a single-file set of
    // this size picks a tiny block and one corrupt article becomes
    // thousands of bad blocks, which measures a shortfall and not this.
    assert!(fx.add_par2_opts(40, Some(20_000), &["photos.7z"], 60_000));
    let victim = fx
        .articles
        .keys()
        .find(|k| k.contains("photos_7z") && k.ends_with("-2@mock>"))
        .cloned()
        .expect("photos.7z article 2");
    let chaos = Chaos {
        corrupt: HashSet::from([victim]),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "a damaged 7z-as-deliverable took the job down:\n{log}");
    let at =
        |needle: &str, what: &str| log.find(needle).unwrap_or_else(|| panic!("{what}:\n{log}"));
    let repaired = at("repair complete", "the archive was never repaired");
    let unpacked = at("7z unpack complete", "the archive was never unpacked");
    let removed = at(
        "removed spent intermediate",
        "the spent archive was removed silently",
    );
    assert!(
        repaired < unpacked && unpacked < removed,
        "the archive's descriptor must be satisfied by the repair BEFORE \
         the unpack spends it and before it is deleted\n{log}"
    );
    for (member, want) in [("alpha.bin", &a), ("beta.bin", &b)] {
        let got = std::fs::read(out.join(member))
            .unwrap_or_else(|e| panic!("{member} missing: {e}\n{log}"));
        assert!(got == *want, "{member} is not byte-exact\n{log}");
    }
    drop(fx);
}

/// M4-58 - two recovery sets in a reconstruct CYCLE: A names B's packet
/// files, B names A's, and neither Main is on disk until the other set
/// reconstructs it. The row predicted "a deadlock or an unbounded retry"
/// and set the bar at "bounded attempts, then honest Unrepairable /
/// leftover hashes, never a hang and never rc=0 with both payloads
/// unnamed".
///
/// TWO FINDINGS, 30 Aug 2026, and the first is the more useful.
///
/// A GENUINE TWO-WAY CYCLE IS NOT CONSTRUCTIBLE. A FileDesc binds its
/// covered file by content MD5, so A's packets must contain MD5(B) and
/// B's must contain MD5(A) - a mutual MD5 fixed point across two files.
/// That is a preimage-strength construction, not something a poster
/// hostile or otherwise can produce. Every attempt collapses to a CHAIN
/// with one real edge (which is W4-12's row) plus one STALE edge, and
/// the fixture below is that maximal form: `setB` is cut over the real
/// `setA.par2`, then `setA` is re-cut to name `setB.par2`, which leaves
/// B describing bytes that no longer exist.
///
/// AND THERE IS NO RETRY TO RUN AWAY. `latesets::apply_nonactivated_
/// disk_sets` is a single `for` over one `disk_sets_scoped` snapshot;
/// nothing re-scans, so "a loop until timeout" has nowhere to live.
///
/// MEASURED GREEN against the row's own bar: the job finishes in one to
/// two seconds, exits NON-zero, names the missing edge (`✘ setA.par2 - file
/// missing entirely`), states the arithmetic ("729 recovery block(s)
/// needed ... carries only 0"), consults the non-activated set
/// exactly once and declines it ("matched nothing here - ignored"), and
/// still lands `payloadB.bin` under its real name. No hang, and no rc=0.
///
/// THE TIMEOUT IS A HANG DETECTOR, NOT A DEADLINE. The failure this row
/// is about is non-termination, so a bare wall-clock assertion would
/// report a slow box as the defect and invite somebody to raise the
/// number. 90 s against a ~1.5 s run is ~60x of headroom - it can only
/// fire on something that is not going to finish - and the panic says
/// so in those words.
#[tokio::test(flavor = "multi_thread")]
async fn two_sets_naming_each_others_packets_terminate_with_an_honest_verdict() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarcycle");
    let pa = payload(60_000, 81);
    let pb = payload(60_000, 82);
    std::fs::write(fx.dir.join("payloadA.bin"), &pa).unwrap();
    std::fs::write(fx.dir.join("payloadB.bin"), &pb).unwrap();
    let cut = |base: &str, files: &[&str]| {
        Command::new("par2")
            .arg("create")
            .arg("-r20")
            .arg("-q")
            .arg(base)
            .args(files)
            .current_dir(&fx.dir)
            .status()
            .is_ok_and(|s| s.success())
    };
    assert!(cut("setA", &["payloadA.bin"]));
    assert!(cut("setB", &["payloadB.bin", "setA.par2"])); // the real edge
    for e in std::fs::read_dir(&fx.dir).unwrap().flatten() {
        if e.file_name().to_string_lossy().starts_with("setA") {
            std::fs::remove_file(e.path()).unwrap();
        }
    }
    assert!(cut("setA", &["payloadA.bin", "setB.par2"])); // closes the ring
    let a_idx = std::fs::read(fx.dir.join("setA.par2")).unwrap();
    let b_idx = std::fs::read(fx.dir.join("setB.par2")).unwrap();
    // All four obfuscated in subject AND yEnc name, so neither set can
    // activate off a name and both have to be found on disk.
    for (real, subject, data) in [
        ("payloadA.bin", "Zq58aP", &pa),
        ("payloadB.bin", "Zq58bP", &pb),
        ("setA.par2", "Zq58aI", &a_idx),
        ("setB.par2", "Zq58bI", &b_idx),
    ] {
        let s = subject.to_string();
        add_file_yenc_names(&mut fx, real, subject, data, 20_000, move |p| {
            format!("{s}.{p:03}")
        });
    }
    // The ONLY wall-clock assertion in this test, and it is a hang
    // detector rather than a deadline - see the note above. A second,
    // tighter elapsed-time check was written here and removed: two
    // guards where either alone suffices leave both unfalsifiable.
    let run = tokio::time::timeout(std::time::Duration::from_secs(90), run_norar(&fx)).await;
    let (log, ok, out) = run.unwrap_or_else(|_| {
        panic!(
            "HANG DETECTED: two mutually-naming recovery sets did not \
             terminate in 90s (a healthy run of this fixture is ~1.5s). \
             This is non-termination, not a slow box - do not raise the \
             bound, find the loop."
        )
    });
    assert!(
        !ok,
        "rc=0 with a payload the ring could never name - the row's own \
         second failure mode\n{log}"
    );
    assert!(
        log.contains("recovery block(s) needed"),
        "the verdict must state the arithmetic rather than fail bare\n{log}"
    );
    // WHICH HALF OF THE RING WINS THE BOOTSTRAP ELECTION IS A GENUINE
    // RACE (found 31 Aug 2026 chasing this test's ~5% flake under load;
    // claim repairpins-ring-verdict-phrasing). The ring is only stale in
    // ONE direction: setA's final FileDesc correctly names the CURRENT
    // setB.par2 (never invalidated), while setB's FileDesc still names
    // the FIRST, since-deleted setA.par2 - `cut("setA", ...)` runs a
    // second time to close the ring and only setB is left pointing at a
    // ghost. So the two possible winners produce two different, both
    // honest, verdict shapes:
    //
    // * setB wins: its own in-stream verify meets the stale "setA.par2"
    //   directly, so the PRIMARY repair ladder reports the shortfall
    //   itself (`RepairShortfall::Blocks`, unaffected by the fix below)
    //   and setA - found on disk afterwards, named by nobody active -
    //   is the "non-activated ... matched nothing" line.
    // * setA wins: its own coverage (payloadA.bin, setB.par2) is
    //   genuinely intact and verifies CLEAN - the ring's one stale edge
    //   only surfaces once setB is found on disk and VOUCHED by setA
    //   (`apply_nonactivated_disk_sets`'s `mine` arm). Until 31 Aug 2026
    //   that arm warned with different wording and never fed the job's
    //   own fail message at all, which is what made the assertion above
    //   flaky rather than the ring itself - fixed by propagating a
    //   `RepairShortfall` out of the late-set pass (`get/latesets.rs`,
    //   `get/settle.rs`) the same way the disk-fallback arm already
    //   does (`blocks_over_set`).
    //
    // Assert whichever the log actually shows, not one hardcoded shape -
    // a test that only ever exercises the branch that happens to win
    // under an idle box is worth nothing under load, which is exactly
    // how this one flaked for as long as it did.
    let via_vouched_late_set = log.contains("a recovery set this job's own set vouches for finds");
    assert!(
        via_vouched_late_set
            || log.contains("a non-activated recovery set on disk matched nothing here"),
        "the second set was never consulted, so nothing here measured the \
         ring at all\n{log}"
    );
    if via_vouched_late_set {
        // setA won. This branch used to say the repair engine was
        // all-or-nothing per SET, so setB's own intact payloadB.bin was
        // never published here even though it verifies byte-exact on
        // disk - flagged as a real, separate gap and not this row's
        // question. THAT GAP IS CLOSED (31 Aug 2026, claim
        // `unrepairable-per-file-publish-impl`): a short set now
        // publishes every member whose own blocks were all present or
        // adopted, and says so in this very log line.
        //
        // Asserted as an IMPLICATION rather than outright, for this
        // test's own stated reason - the branch is a race that wins
        // 5-12% of the time, and whether setB's member is publishable
        // depends on what adoption reached on this run. What must never
        // happen is the engine CLAIMING a publish that is not on disk,
        // and that is checkable on every run of this branch.
        if log.contains("individually verified and published anyway") {
            assert_eq!(
                std::fs::read(out.join("payloadB.bin")).unwrap_or_default(),
                pb,
                "the shortfall verdict reported a published member, so it \
                 must be on disk byte-exact\n{log}"
            );
        }
    } else {
        // setB won: the half of the ring that IS satisfiable still
        // lands named. A verdict that took the whole post down would
        // pass every assertion above and be a worse engine.
        assert_eq!(
            std::fs::read(out.join("payloadB.bin")).unwrap_or_default(),
            pb,
            "the reachable half of the ring lost its name too\n{log}"
        );
    }
    drop(fx);
}

/// `add_par2_opts` at a chosen block size, posting ONLY the index file.
/// Local to this module rather than a sixth builder in `mod.rs`, which
/// a dozen M4 lanes are appending to at once.
fn add_par2_index_only_at(fx: &mut Fixture, bs: u64, files: &[&str], art_size: usize) -> bool {
    let ok = Command::new("par2")
        .arg("create")
        .arg(format!("-s{bs}"))
        .arg("-r5")
        .arg("-q")
        .arg("testset")
        .args(files)
        .current_dir(&fx.dir)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        return false;
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    for p in par2s {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if name == "testset.par2" {
            let data = std::fs::read(&p).unwrap();
            let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
            let segs = make_file_articles(&name, &data, art_size, &tag, &mut fx.articles);
            fx.nzb_files.push((name, segs));
        }
        std::fs::remove_file(&p).unwrap();
    }
    true
}

/// M4-62 in the closed world - the half the unit pins
/// (`par2repair::unit_tests::a_padded_last_block_donor_serves_its_bytes_
/// and_is_not_spent`) cannot reach, because what makes the defect
/// destructive is not the adoption, it is `sweep_spent_sources` acting
/// on the verdict.
///
/// A 100,012-byte payload at a 20,000-byte block has five whole blocks
/// and a sixth of TWELVE real bytes followed by 19,988 of zero padding.
/// The decoy posted beside it is exactly that padded window - a real
/// 20,000-byte file, every byte of it on disk, which the sliding scan
/// legitimately CRC-hits. Twelve of those bytes are the payload's;
/// 19,988 are padding the payload does not contain at all, because the
/// file ends at 100,012.
///
/// The last article is corrupted, so the tail block is genuinely
/// missing (a damaged article leaves a hole, and a hole would read as
/// zeros and verify PRESENT if the block were all-zero - it is not,
/// which is why the fixture puts twelve real bytes there).
///
/// Both halves are asserted. The adoption MUST still happen: those
/// bytes really are on disk and refusing them would be a strictly worse
/// engine. The decoy must SURVIVE: before the bound in
/// `adopt::proven_spent`, merged coverage of a window counted its
/// padding, the file read as fully donated, and a file the poster put
/// in the NZB was swept for bytes the target never had.
#[tokio::test(flavor = "multi_thread")]
async fn a_padded_last_block_decoy_is_not_swept_after_donating() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarpadwin");
    // "The adoption MUST still happen", above, spelled where
    // `refuse_a_solve_that_solved_nothing` reads it. Index-only means
    // there is no parity to solve from at all, so 0 rebuilt is the
    // premise rather than a payload artefact.
    crate::adoptguard::adoption_is_the_premise(
        &fx.dir,
        "the set is INDEX-ONLY, so no block of it can come from parity - \
         the decoy donating its twelve real bytes and surviving the \
         sweep IS the row",
    );
    const BS: usize = 20_000;
    let movie = payload(BS * 5 + 12, 62);
    fx.add_file("movie.bin", &movie, BS);
    // INDEX-ONLY at a chosen block size, so adoption is the only route
    // to the missing block and the row is not measuring parity. `-r0`
    // is not available - par2cmdline refuses it outright ("Redundancy
    // and Redundancysize not set") - and `add_par2_index_only` takes no
    // block size, which this fixture's whole geometry depends on. So
    // the volumes are created and then simply not posted, which is what
    // a manifest-only poster does.
    assert!(add_par2_index_only_at(
        &mut fx,
        BS as u64,
        &["movie.bin"],
        BS
    ));
    let mut decoy = movie[BS * 5..].to_vec();
    decoy.resize(BS, 0);
    // Posted AFTER the set is cut, so no FileDesc speaks for it, and
    // under an obfuscated subject and yEnc name so it lands as an
    // unclaimed adoption candidate rather than a named file.
    add_file_yenc_names(&mut fx, "decoyZq62.bin", "Zq62D", &decoy, BS, |p| {
        format!("Zq62D.{p:03}")
    });
    let victim = fx
        .articles
        .keys()
        .find(|k| k.contains("movie_bin") && k.ends_with("-6@mock>"))
        .cloned()
        .expect("movie.bin article 6 (the twelve-byte tail)");
    let chaos = Chaos {
        corrupt: HashSet::from([victim]),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "the padded-window adoption failed the job:\n{log}");
    assert_eq!(
        std::fs::read(out.join("movie.bin")).unwrap_or_default(),
        movie,
        "the tail block was never adopted from the decoy that held it\n{log}"
    );
    let survivors: Vec<String> = std::fs::read_dir(&out)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.metadata().is_ok_and(|m| m.len() == BS as u64))
                .map(|e| e.file_name().to_string_lossy().into())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !survivors.is_empty(),
        "the decoy was swept: 19,988 of its 20,000 bytes are the target's \
         zero PADDING and are absent from a file that ends at {}. \
         out/ holds {:?}\n{log}",
        movie.len(),
        std::fs::read_dir(&out)
            .map(|rd| rd
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect::<Vec<_>>())
            .unwrap_or_default()
    );
    drop(fx);
}
