//! `RepairStatus::Unrepairable` is all-or-nothing PER SET, not per file
//! (`status.rs`'s enum has no `per_file`-shaped arm for it, unlike
//! [`super::super::RepairReport`]). Found chasing claim
//! `repairpins-ring-verdict-phrasing` in
//! `crates/nzbfast/tests/e2e_norar/repairpins.rs`, whose
//! `two_sets_naming_each_others_packets_terminate_with_an_honest_verdict`
//! flags it in a comment on its `via_vouched_late_set` branch ("a real,
//! separate gap ... flagged, not fixed, here") without a deterministic
//! reproduction - that race wins one way roughly 5-12% of the time, so
//! nothing there pins the shape on every run.
//!
//! This module is that reproduction, built directly against
//! [`super::super::repair_dir`] so it needs no NZB layer, no tokio race
//! and no `par2` subprocess timing to land on the interesting branch:
//! `a.bin` never exists under its own name, but a byte-identical copy
//! sits under an unrelated donor name (the obfuscated-post shape
//! `a_wholly_renamed_copy_is_adopted_and_reported_consumed` next door
//! already exercises for a ONE-file set) - so the adoption scan finds
//! every one of `a.bin`'s own blocks with nothing missing for it
//! specifically. `b.bin` sits in the SAME recovery set, damaged beyond
//! what the one recovery slice on disk can rebuild. The set as a whole
//! is genuinely `Unrepairable` (that part is correct and stays so), but
//! the engine USED TO bail out before writing anything AT ALL - so
//! `a.bin`, whose own bytes were fully proven, never got created under
//! its real name either, and the caller (`RepairStatus::Unrepairable`
//! carried no per-file report) had no way to ask for it.
//!
//! CLOSED 31 Aug 2026 (claim `unrepairable-per-file-publish-impl`).
//! `repair_dir_set_inner` no longer returns at the `by_exp.len() <
//! needed` bailout: it records a `shortfall`, skips the Reed-Solomon
//! pass, and runs the SAME write / whole-file-MD5-verify / rename path
//! over the targets [`super::super::status::publishable`] admits, then
//! ends on [`super::super::status::finish`], which turns the report into
//! `Unrepairable { .., partial }` instead of `Repaired`. The verdict and
//! its arithmetic are byte-for-byte what they were.
//!
//! TWO NARROWINGS make the whole verdict STRICTLY ADDITIVE to the
//! directory, and the tests below pin both because they are the reason
//! this is safe to do inside a data-integrity path at all:
//!
//! * only a target that does NOT already exist is published, so nothing
//!   is ever overwritten. An existing file that fails this set's block
//!   hashes may be another set's payload under a shared name, and the
//!   evidence that would tell them apart (`DirContext`'s `contested` /
//!   `declared`) is EMPTY on the late-set path that reaches here - live
//!   claim `latesets-empty-dircontext`.
//!
//!   WIDENED 31 Aug 2026, claim `shortfall-publish-patch-existing`, and
//!   the sentence above is preserved as the reason it was narrow. That
//!   blocker was cleared by `92828385d`: the late-set entry point now
//!   derives its own `DirContext`, so the ownership evidence is there.
//!   An existing member is patched where the CALLER opts in, which is a
//!   statement that this verdict is the last word on the set - true of
//!   `get::latesets`, false of `repair::nativepass`' probe. The argument
//!   is at [`super::super::status::publishable`]; the three tests below
//!   pin the opt-in, the opt-out and the unsurveyed entry point.
//! * `consumed_sources` is always empty, so no donor is ever reported
//!   spent. A donor is proven redundant by its bytes existing under a
//!   name the set declares, and a still-absent sibling target makes that
//!   proof unavailable for any donor that may also have fed it.
//!
//! So this pass can only ADD a file the adoption scan proved byte-exact,
//! or - where the caller opted in - replace one whole with a copy this
//! set's own hashes proved, staged and verified before it moves. It
//! never deletes one, and never decides whether the job healed - `nzbfast::get::latesets` deliberately feeds neither
//! `chained` nor `residual` from this verdict, so a short set cannot
//! green its own job.
//!
//! The safety case rests on nothing new. A PAR2 FileDesc packet carries
//! a whole-file MD5 and its IFSC packet a CRC32+MD5 per block, and
//! nothing in the format binds one file's hashes to a sibling's - so
//! "do these bytes match this file's own declared hashes" already has no
//! dependency on any other member's state.
//! [`super::super::status::RepairReport::file_had_bytes_on_disk`] and
//! its test ("a SIBLING's donor is not this member's evidence") already
//! treat that evidence as sufficient per file; this asks the same
//! question one branch earlier, when the WHOLE set fails rather than
//! only when it succeeds. See claim `unrepairable-per-file-publish` and
//! its `--src` handoff for the writeup that preceded the fix.
//!
//! A child module for `padded_windows`' own reason: `unit_tests.rs` had
//! 36 lines of headroom under the 3,000-line ceiling when this was
//! written, nowhere near enough for a fixture plus its writeup.

use super::*;

/// The row itself: a member the adoption scan proved byte-exact is
/// published under its FileDesc name even though a sibling sinks the
/// set. This assertion was written the other way round on the day the
/// gap was found, and flipping it is what closing the gap means.
#[test]
fn an_individually_intact_member_of_an_unrepairable_set_is_published() {
    let dir = tmpdir("unrep_partial");
    let a = payload(200, 41);
    let b = payload(200, 42);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b)];
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    // a.bin: NEVER written under its own name - only a byte-identical
    // copy under an unrelated donor name, exactly the obfuscated-post
    // shape the wholly-renamed-copy test next door exercises for a
    // single-file set. Every one of its 4 blocks (200 bytes / BS=64)
    // is therefore found by the adoption scan, with nothing of its own
    // left in the global `missing` list.
    std::fs::write(dir.join("a9f1c2-donor"), &a).unwrap();
    // b.bin: present under its real name, with its first two blocks
    // (global slices 4 and 5) corrupted - the other two are untouched
    // so the present-set walk's name gate sees a real FileDesc name on
    // disk and attempts the repair at all.
    let mut b_damaged = b.clone();
    for x in &mut b_damaged[0..128] {
        *x ^= 0x66;
    }
    std::fs::write(dir.join("b.bin"), &b_damaged).unwrap();
    // One recovery slice - enough for either of b's two damaged blocks
    // alone, not both.
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();

    let status = repair_dir(&dir).expect("shortfall is a verdict, not an error");
    let partial = match status {
        RepairStatus::Unrepairable {
            needed,
            have,
            adopted,
            partial,
        } => {
            // THE VERDICT AND ITS ARITHMETIC ARE UNCHANGED. Publishing a
            // member does not make the set repairable and must not be
            // allowed to move these numbers - they are what
            // `nzbfast::repair::blocks_over_set` sizes a recovery fetch
            // by, and what the shortfall UI reports.
            assert_eq!(
                (needed, have),
                (2, 1),
                "b.bin's two damaged blocks against the one recovery slice on disk"
            );
            assert_eq!(
                adopted, 4,
                "a.bin's own 4 blocks were fully proven by the donor scan - \
                 they are what this row is about"
            );
            partial
        }
        other => panic!("expected Unrepairable, got {other:?}"),
    };

    // THE ROW: a.bin's own evidence was complete - proven byte-exact via
    // IFSC-hash-matched adoption, zero blocks of its own missing - so it
    // is written under its real name and whole-file-MD5 verified, even
    // though b.bin sinks the set.
    assert!(
        dir.join("a.bin").exists(),
        "a.bin was individually publishable and must be published"
    );
    assert_eq!(
        std::fs::read(dir.join("a.bin")).unwrap(),
        a,
        "and byte-exact, not merely present"
    );
    assert_eq!(
        partial.files_created,
        vec!["a.bin".to_string()],
        "the caller is TOLD which member landed - the whole point of the \
         report riding on the shortfall verdict"
    );
    assert_eq!(
        partial.blocks_rebuilt, 0,
        "a shortfall runs no Reed-Solomon pass, so nothing was rebuilt"
    );

    // NOTHING IS SPENT. The donor is byte-identical to a target and this
    // pass has just landed those bytes under the FileDesc name, which on
    // a REPAIRED set is exactly the exact-MD5 arm's spend case - and it
    // is still not reported here, because b.bin is absent from disk and
    // no proof about a donor that may also have fed it is available.
    assert!(
        partial.consumed_sources.is_empty(),
        "a shortfall publishes files and spends nothing"
    );
    assert_eq!(std::fs::read(dir.join("a9f1c2-donor")).unwrap(), a);
    // b.bin is untouched, same as `too_little_recovery_reports_the_
    // shortfall` already pins for the one-file case.
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b_damaged);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The narrowing that REMAINS, pinned from the other side: in an
/// UNSURVEYED directory a member whose own blocks are all accounted for
/// but which ALREADY EXISTS is left exactly as it is, damage and all.
///
/// `b.bin` here is publishable by the block test - a donor carries every
/// one of its damaged blocks - and it is deliberately not published,
/// because an existing file that fails this set's hashes may be another
/// set's payload under a shared name and NOTHING HERE CAN TELL: this
/// test drives [`super::super::repair_dir`], which is single-set by
/// definition and passes a `DirContext::default()`, so `declared` is
/// empty. Overwriting on a set that has ALREADY failed with no evidence
/// of ownership is not a trade worth taking; creating an absent file
/// costs nobody anything, which is why `a.bin` below still lands.
///
/// The entry point is the whole difference between this row and
/// [`a_surveyed_shortfall_patches_an_existing_member_it_can_prove`]
/// below, which builds the same directory and gets `b.bin` repaired:
/// `repair_dir` cannot reach the opt-in at all, because only the
/// surveying entry point grants it. Empty `contested` is TRUE rather
/// than unknown here, but the two are spelled the same, which is why
/// the flag is granted where the survey happens rather than inferred
/// from the name sets later.
#[test]
fn a_shortfall_publish_never_overwrites_a_member_that_is_already_there() {
    let dir = tmpdir("unrep_partial_noclobber");
    let a = payload(200, 41);
    let b = payload(200, 42);
    let c = payload(200, 43);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b), ("c.bin", &c)];
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    // a.bin: absent, donor-proven - the published one.
    std::fs::write(dir.join("a9f1c2-donor"), &a).unwrap();
    // b.bin: present and damaged, with a donor carrying its good bytes,
    // so the adoption scan accounts for every block it owns.
    let mut b_damaged = b.clone();
    for x in &mut b_damaged[0..128] {
        *x ^= 0x66;
    }
    std::fs::write(dir.join("b.bin"), &b_damaged).unwrap();
    std::fs::write(dir.join("b41d7e-donor"), &b).unwrap();
    // c.bin: present, damaged, and nothing to account for it - this is
    // what keeps the set short.
    let mut c_damaged = c.clone();
    for x in &mut c_damaged[0..128] {
        *x ^= 0x5a;
    }
    std::fs::write(dir.join("c.bin"), &c_damaged).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();

    let partial = match repair_dir(&dir).expect("shortfall is a verdict, not an error") {
        RepairStatus::Unrepairable { partial, .. } => partial,
        other => panic!("expected Unrepairable, got {other:?}"),
    };
    assert_eq!(
        partial.files_created,
        vec!["a.bin".to_string()],
        "the absent member is created; the two present ones are not touched"
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(
        std::fs::read(dir.join("b.bin")).unwrap(),
        b_damaged,
        "publishable by its blocks, but it EXISTS - left exactly as it was"
    );
    assert_eq!(std::fs::read(dir.join("c.bin")).unwrap(), c_damaged);
    assert!(
        partial.consumed_sources.is_empty(),
        "and neither donor is reported spent"
    );
    assert_eq!(std::fs::read(dir.join("b41d7e-donor")).unwrap(), b);

    let _ = std::fs::remove_dir_all(&dir);
}

/// [`par2_index`] with ONE file's declared whole-file MD5s replaced by
/// a lie, while its IFSC block hashes stay TRUE.
///
/// That combination is the only way a publishable member can fail its
/// final verify, and it is not a contrived one: `status::publishable`
/// admits a target only once every block it owns has matched an IFSC
/// CRC32+MD5 pair, so the whole-file MD5 can then disagree only through
/// a hash collision or a bug in this engine - which is exactly the pair
/// of causes `status::publish_failed` is written for. Simulating it in
/// the packets is what makes that reachable from a test at all; nothing
/// weaker gets there, because honest packets make the two agree by
/// construction.
fn index_lying_about_md5(files: &[(&str, &[u8])], liar: usize) -> Vec<u8> {
    let mut main = Vec::new();
    main.extend_from_slice(&(BS as u64).to_le_bytes());
    main.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for i in 0..files.len() {
        main.extend_from_slice(&fid(i));
    }
    let mut out = pkt(SET, par2::TYPE_MAIN, &main);
    for (i, (name, data)) in files.iter().enumerate() {
        let mut desc = Vec::new();
        desc.extend_from_slice(&fid(i));
        // Both whole-file hashes move together: on these short fixtures
        // md5_16k IS the whole-file MD5, so lying about one alone would
        // be a shape no real packet writer can produce.
        let mut whole: [u8; 16] = Md5::digest(data).into();
        let mut head: [u8; 16] = Md5::digest(&data[..data.len().min(16384)]).into();
        if i == liar {
            whole[0] ^= 0xff;
            head[0] ^= 0xff;
        }
        desc.extend_from_slice(&whole);
        desc.extend_from_slice(&head);
        desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
        let mut nb = name.as_bytes().to_vec();
        while nb.len() % 4 != 0 {
            nb.push(0);
        }
        desc.extend_from_slice(&nb);
        out.extend(pkt(SET, par2::TYPE_FILEDESC, &desc));
        // The block hashes are honest - this is what makes the member
        // publishable in the first place.
        let mut body = fid(i).to_vec();
        for chunk in data.chunks(BS) {
            let mut padded = chunk.to_vec();
            padded.resize(BS, 0);
            body.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&padded)));
            body.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
        }
        out.extend(pkt(SET, par2::TYPE_IFSC, &body));
    }
    out
}

/// THE RULING (claim `shortfall-publish-error-degrades-verdict`,
/// 31 Aug 2026): a member that fails its whole-file MD5 out of a set
/// that was ALREADY short does not land, and costs the caller nothing
/// else. The verdict stays `Ok(Unrepairable)` and its arithmetic is
/// untouched.
///
/// Between 6c71c020d and that ruling this returned `Err`, which is not
/// a cosmetic difference: `nzbfast::repair::nativepass` answers
/// `NativeVerdict::Backstop` on `Err` where it would have answered
/// `NoRecovery { needed, have }`, and
/// `nzbfast::repair::adoption_narrowed_need` turns the first into
/// `NarrowedNeed::Buy(needed)` - the FULL unnarrowed recovery buy - and
/// the second into the narrowed one. So a failed courtesy write made the
/// job spend bandwidth it did not need.
#[test]
fn a_failed_member_verify_does_not_cost_a_short_set_its_verdict() {
    let dir = tmpdir("unrep_partial_verifyfail");
    let a = payload(200, 41);
    let b = payload(200, 42);
    let c = payload(200, 43);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b), ("c.bin", &c)];
    // a.bin lies about its whole-file MD5, so it is publishable by its
    // blocks and then fails the final verify.
    std::fs::write(dir.join("set.par2"), index_lying_about_md5(files, 0)).unwrap();
    // a.bin and c.bin: absent, each fully proven by its own donor. Only
    // c.bin's packets are honest, so only c.bin may land.
    std::fs::write(dir.join("a9f1c2-donor"), &a).unwrap();
    std::fs::write(dir.join("c3b8e0-donor"), &c).unwrap();
    // b.bin: present, two damaged blocks, no donor - what keeps the set
    // short against the one recovery slice below.
    let mut b_damaged = b.clone();
    for x in &mut b_damaged[0..128] {
        *x ^= 0x66;
    }
    std::fs::write(dir.join("b.bin"), &b_damaged).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();

    let partial = match repair_dir(&dir).expect("a failed publish is not a failed call") {
        RepairStatus::Unrepairable {
            needed,
            have,
            partial,
            ..
        } => {
            // THE ARITHMETIC IS THE POINT. These are the numbers
            // `nzbfast::repair::blocks_over_set` sizes a recovery fetch
            // by, and a member failing to publish must not move them.
            assert_eq!(
                (needed, have),
                (2, 1),
                "b.bin's two damaged blocks against the one recovery slice"
            );
            partial
        }
        other => panic!("expected Unrepairable, got {other:?}"),
    };

    // The liar did not land, and - the half a `renames`-only fix would
    // have got wrong - is NOT reported as though it had. `files_patched`
    // is what `status::published_clause` counts, so a member left in
    // `damaged` would have been announced to the user as published while
    // its temp was being deleted.
    assert!(
        !dir.join("a.bin").exists(),
        "a.bin failed its whole-file MD5 - it must not be left on disk"
    );
    assert!(
        !partial.files_patched.contains(&"a.bin".to_string()),
        "and must not be reported as published either"
    );
    assert!(!partial.files_created.contains(&"a.bin".to_string()));
    // No temp is left behind for it.
    let strays: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let n = e.ok()?.file_name().to_string_lossy().into_owned();
            n.contains("nzbfast-repair").then_some(n)
        })
        .collect();
    assert!(strays.is_empty(), "repair temps left behind: {strays:?}");

    // PER-MEMBER, not all-or-nothing: the honest sibling still lands.
    // That is the feature's own premise - nothing in the PAR2 format
    // binds one file's hashes to another's - so one member's failure
    // must not withdraw another member's proof.
    assert!(dir.join("c.bin").exists(), "c.bin's own proof was complete");
    assert_eq!(std::fs::read(dir.join("c.bin")).unwrap(), c);
    assert_eq!(partial.files_created, vec!["c.bin".to_string()]);
    // And b.bin, which was never publishable, is untouched.
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b_damaged);

    let _ = std::fs::remove_dir_all(&dir);
}

/// THE CONTROL, and the reason the ruling above is narrow: on a set that
/// is NOT short, a failed whole-file MD5 is still an `Err`.
///
/// That is the engine's self-proving contract - "a native bug can never
/// ship bad bytes, it falls through to par2cmdline instead" - and the
/// `Backstop` it buys is worth having there, because there IS a repair
/// to salvage. On a shortfall there is not: the set is short by
/// arithmetic this pass has already proven, so par2cmdline would be
/// asked to do the one thing already established as impossible.
#[test]
fn on_a_repairable_set_a_failed_member_verify_is_still_an_error() {
    let dir = tmpdir("unrep_partial_verifyfail_control");
    let a = payload(200, 41);
    let b = payload(200, 42);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b)];
    std::fs::write(dir.join("set.par2"), index_lying_about_md5(files, 0)).unwrap();
    std::fs::write(dir.join("a9f1c2-donor"), &a).unwrap();
    let mut b_damaged = b.clone();
    for x in &mut b_damaged[0..128] {
        *x ^= 0x66;
    }
    std::fs::write(dir.join("b.bin"), &b_damaged).unwrap();
    // TWO slices this time - enough for both of b.bin's damaged blocks,
    // so the set is repairable and the shortfall arm never runs.
    std::fs::write(
        dir.join("set.vol0+2.par2"),
        par2_volume(SET, BS, files, &[0, 1]),
    )
    .unwrap();

    match repair_dir(&dir) {
        Err(RepairError::VerifyFailed(name)) => assert_eq!(name, "a.bin"),
        other => panic!("expected VerifyFailed on a repairable set, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The WIDENING (claim `shortfall-publish-patch-existing`, 31 Aug
/// 2026): the same directory, entered through the SURVEYED entry point
/// with the caller's `patch_existing` opt-in - and now `b.bin` is
/// repaired in place of being left damaged.
///
/// Byte-for-byte the fixture of
/// [`a_shortfall_publish_never_overwrites_a_member_that_is_already_there`]
/// above, deliberately: the ONLY difference between the two rows is how
/// the engine was entered, so what is being pinned is the gate and
/// nothing about the payload. Under the old flat `!t.exists` rule this
/// test's `b.bin` comes back damaged, and so it does with the opt-in
/// dropped - which is what
/// `a_shortfall_publish_without_the_callers_opt_in_still_refuses` below
/// holds from the other side, on this same fixture.
///
/// THREE THINGS ARE ASSERTED AND THE LAST IS THE POINT. `b.bin` is whole
/// and equals its declared bytes, so the widening did what it is for.
/// `c.bin`, which nothing accounts for, is untouched - the block test
/// still gates every publish, and a set short of recovery data does not
/// get to guess. And the verdict is STILL `Unrepairable`: publishing a
/// member says nothing about whether the set healed, which is the
/// invariant `nzbfast::get::latesets` leans on when it declines to feed
/// `chained` from this report.
#[test]
fn a_surveyed_shortfall_patches_an_existing_member_it_can_prove() {
    let dir = tmpdir("unrep_partial_surveyed");
    let a = payload(200, 41);
    let b = payload(200, 42);
    let c = payload(200, 43);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b), ("c.bin", &c)];
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(dir.join("a9f1c2-donor"), &a).unwrap();
    let mut b_damaged = b.clone();
    for x in &mut b_damaged[0..128] {
        *x ^= 0x66;
    }
    std::fs::write(dir.join("b.bin"), &b_damaged).unwrap();
    std::fs::write(dir.join("b41d7e-donor"), &b).unwrap();
    let mut c_damaged = c.clone();
    for x in &mut c_damaged[0..128] {
        *x ^= 0x5a;
    }
    std::fs::write(dir.join("c.bin"), &c_damaged).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();

    let partial = match crate::par2repair::repair_dir_set_with_donors_scoped(
        &dir,
        &SET,
        &[],
        crate::par2repair::PacketScope::Flat,
        true,
        None,
    )
    .expect("shortfall is a verdict, not an error")
    {
        RepairStatus::Unrepairable { partial, .. } => partial,
        other => panic!("expected Unrepairable, got {other:?}"),
    };
    assert_eq!(
        std::fs::read(dir.join("b.bin")).unwrap(),
        b,
        "the existing damaged member is patched whole in a surveyed directory"
    );
    assert!(
        partial.files_patched.iter().any(|n| n == "b.bin"),
        "and the report says so, got {:?}",
        partial.files_patched
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(
        std::fs::read(dir.join("c.bin")).unwrap(),
        c_damaged,
        "nothing accounts for c.bin, so the block test still refuses it"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The OPT-IN half of the gate, pinned on its own: the same surveyed
/// entry point, `patch_existing` false, and `b.bin` is left damaged.
///
/// This is the shape `repair::nativepass`' probe pass is in, and the
/// reason the flag exists rather than the survey deciding alone. That
/// pass calls the engine BEFORE any recovery volume has been bought and
/// then goes on to buy some and try again, so its shortfall is not the
/// last word on anything - and a first cut without this flag had it
/// healing, early, exactly the members the real pass would have adopted.
/// `e2e_norar::twin_adopt::a_claimed_twin_donates_the_shared_head_it_declares_twice`
/// and
/// `e2e_norar::ondisk_recovery::recovery_already_on_disk_is_subtracted_before_the_shortfall_is_called_final`
/// are what found it, each on the adoption count in its own success
/// line; this row is the unit-level statement of the same rule.
#[test]
fn a_shortfall_publish_without_the_callers_opt_in_still_refuses() {
    let dir = tmpdir("unrep_partial_optout");
    let a = payload(200, 41);
    let b = payload(200, 42);
    let c = payload(200, 43);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b), ("c.bin", &c)];
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(dir.join("a9f1c2-donor"), &a).unwrap();
    let mut b_damaged = b.clone();
    for x in &mut b_damaged[0..128] {
        *x ^= 0x66;
    }
    std::fs::write(dir.join("b.bin"), &b_damaged).unwrap();
    std::fs::write(dir.join("b41d7e-donor"), &b).unwrap();
    let mut c_damaged = c.clone();
    for x in &mut c_damaged[0..128] {
        *x ^= 0x5a;
    }
    std::fs::write(dir.join("c.bin"), &c_damaged).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();

    let partial = match crate::par2repair::repair_dir_set_with_donors(&dir, &SET, &[])
        .expect("shortfall is a verdict, not an error")
    {
        RepairStatus::Unrepairable { partial, .. } => partial,
        other => panic!("expected Unrepairable, got {other:?}"),
    };
    assert_eq!(
        partial.files_created,
        vec!["a.bin".to_string()],
        "the absent member still lands - that half needs no opt-in"
    );
    assert_eq!(
        std::fs::read(dir.join("b.bin")).unwrap(),
        b_damaged,
        "a surveyed directory is not enough: without the caller's opt-in \
         an existing member is left exactly as it was"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
