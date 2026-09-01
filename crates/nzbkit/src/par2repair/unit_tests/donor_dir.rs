//! §293's donor directory: adopting bytes out of a FAILED
//! PREDECESSOR's output when the successor's own recovery set cannot
//! finish the repair.
//!
//! Twelve tests, every one of them through `repair_dir_with_donors`,
//! moved here whole on 31 Aug 2026 (claim
//! `par2repair-unit-tests-ceiling`) because `unit_tests.rs` was at
//! 2,980 of the 3,000-line ceiling with 38 commits in the two days
//! before. A PURE MOVE: not a line of test code changed, and the parent
//! with these lines taken out is byte-identical to what it was.
//!
//! A child of `unit_tests` rather than a sibling, for the two reasons
//! every other child here gives: `use super::*` reaches the parent's
//! fixtures - `payload`, `par2_index`, `par2_volume`, `tmpdir`, `BS`,
//! `SET` - exactly as an inline test did, and the module is named for
//! its file so size-gate.py's CFG_TEST_MOD resolver keeps scoring it as
//! test code.
//!
//! WHAT IS DELIBERATELY NOT HERE, so the next reader does not go
//! hunting for it: the donor tests the parent still carries are the
//! ones that belong to a second subject as much as to this one - the
//! copy-is-verified-by-its-own-bytes guard, the ambiguous-member
//! refusal, the two `field_shape` complementary-damage arms, and
//! M4-62's `a_padded_last_block_donor_serves_its_bytes_and_is_not_spent`
//! with its `a_full_block_donor_is_still_proven_spent` control, which
//! `padded_windows.rs`'s own header cites by bare name and would have
//! been stranded by moving.

use super::*;

/// §293, the offline experiment: a DONOR directory - a failed
/// predecessor's output - completes a repair its own recovery set
/// cannot. The successor is a DIFFERENT post of the same release: its
/// own set id, its own block size (so not one checksum is shared with
/// whatever set the predecessor carried), a download that landed no
/// data files at all, and one recovery slice against thirteen missing
/// blocks. Baseline leg: Unrepairable, 13 needed, 1 held. Treatment
/// leg: every block adopted out of the donor - two files through the
/// whole-file fast path, the third found INSIDE a junk-named file at
/// an unaligned offset (the different-volume-cut shape only the
/// rolling-CRC scan can see) - and the donor's own files are
/// untouched and never reported consumed, because a donor is another
/// job's payload and the sweep is scoped to the repair dir.
#[test]
fn a_donor_directory_completes_a_repair_the_recovery_set_cannot() {
    let donor = tmpdir("donor-src");
    let dir = tmpdir("donor-dst");
    let f1 = payload(200, 11);
    let f2 = payload(300, 12);
    let f3 = payload(500, 13);
    std::fs::write(donor.join("f1.bin"), &f1).unwrap();
    std::fs::write(donor.join("f2.bin"), &f2).unwrap();
    // The third travels under a different cut: junk prefix, junk name.
    let mut cut = payload(37, 99);
    cut.extend_from_slice(&f3);
    std::fs::write(donor.join("9a3d1c.dat"), &cut).unwrap();

    let files: &[(&str, &[u8])] = &[("f1.bin", &f1), ("f2.bin", &f2), ("f3.bin", &f3)];
    let set_b = [7u8; 16];
    let bs = 96usize;
    std::fs::write(dir.join("set.par2"), par2_index(set_b, bs, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(set_b, bs, files, &[0]),
    )
    .unwrap();

    // Baseline: without the donor, the set is short by twelve slices.
    match repair_dir(&dir).expect("baseline runs") {
        RepairStatus::Unrepairable { needed, have, .. } => {
            println!("§293 A/B baseline: Unrepairable, {needed} needed, {have} held");
            assert_eq!((needed, have), (13, 1));
        }
        other => panic!("baseline must be unrepairable, got {other:?}"),
    }

    // Treatment: the donor directory completes it.
    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("donor repair runs")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    println!(
        "§293 A/B treatment: {} of 13 blocks adopted from the donor, {} rebuilt",
        report.blocks_adopted, report.blocks_rebuilt
    );
    assert_eq!(report.blocks_adopted, 13, "every block found on the donor");
    assert_eq!(
        report.blocks_rebuilt, 0,
        "the one recovery slice was never needed"
    );
    assert_eq!(
        report.consumed_sources,
        Vec::<PathBuf>::new(),
        "donor files are another job's payload - never offered for sweeping"
    );
    for (name, data) in files {
        assert_eq!(
            std::fs::read(dir.join(name)).unwrap(),
            *data,
            "{name} landed byte-exact"
        );
    }
    assert_eq!(std::fs::read(donor.join("f1.bin")).unwrap(), f1);
    assert_eq!(std::fs::read(donor.join("f2.bin")).unwrap(), f2);
    assert_eq!(std::fs::read(donor.join("9a3d1c.dat")).unwrap(), cut);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// §293's do-not-hinder half: a donor carrying the WRONG bytes - the
/// repack shape, same file names, different content - donates nothing
/// and changes nothing. The verdict with the poisoned donor must be
/// BYTE-IDENTICAL to the verdict without any donor (same Unrepairable
/// arithmetic), the donor's own file untouched, and an unreadable
/// donor path in the same list is skipped rather than fatal. This is
/// the case that proves a wrong guess costs one scan and nothing else:
/// every adoption needs a per-block CRC32 match confirmed by MD5, so
/// foreign bytes cannot be adopted, and the whole-file MD5 backstop
/// stands behind even that.
#[test]
fn a_donor_with_wrong_bytes_donates_nothing_and_changes_nothing() {
    let donor = tmpdir("poison-src");
    let dir = tmpdir("poison-dst");
    let real = payload(260, 21);
    let files: &[(&str, &[u8])] = &[("f1.bin", &real)];
    // The repack: same name, same length, different bytes.
    let wrong = payload(260, 22);
    std::fs::write(donor.join("f1.bin"), &wrong).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();

    let baseline = match repair_dir(&dir).expect("baseline runs") {
        RepairStatus::Unrepairable { needed, have, .. } => (needed, have),
        other => panic!("5 blocks missing, 1 slice held - must be short, got {other:?}"),
    };
    let ghost = donor.join("no-such-subdir");
    let with_poison =
        match repair_dir_with_donors(&dir, &[donor.clone(), ghost]).expect("poisoned run") {
            RepairStatus::Unrepairable { needed, have, .. } => (needed, have),
            other => panic!("wrong bytes must not repair anything, got {other:?}"),
        };
    assert_eq!(
        with_poison, baseline,
        "a poisoned donor must leave the arithmetic exactly as it found it"
    );
    assert_eq!(
        std::fs::read(donor.join("f1.bin")).unwrap(),
        wrong,
        "and the donor's own file untouched"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// §293 plan-side arm: a WHOLE member found on a donor is placed in the
/// job's own directory under the SET's name, before a byte is fetched.
///
/// The three files are the three answers a real switch gets: one whole
/// and byte-exact (donated), one the same length with different bytes -
/// the repack shape - and one absent from the donor entirely. Only the
/// first may be placed, and the other two must leave the destination
/// untouched, because a plan that struck their articles out on a wrong
/// donor would have no way back: the payload would never be fetched.
#[test]
fn whole_members_are_donated_and_a_repack_shaped_donor_is_refused() {
    let donor = tmpdir("donate-src");
    let dir = tmpdir("donate-dst");
    let good = payload(260, 31);
    let repack_real = payload(320, 32);
    let repack_wrong = payload(320, 33);
    let absent = payload(200, 34);
    let files: &[(&str, &[u8])] = &[
        ("good.bin", &good),
        ("repack.bin", &repack_real),
        ("absent.bin", &absent),
    ];
    std::fs::write(donor.join("good.bin"), &good).unwrap();
    std::fs::write(donor.join("repack.bin"), &repack_wrong).unwrap();
    // A .par2 on the donor is never a candidate - the successor fetches
    // its own set, and the predecessor's is a different one.
    std::fs::write(donor.join("set.par2"), par2_index(SET, BS, files)).unwrap();

    let index = par2_index(SET, BS, files);
    let set = par2::Par2Set::parse(&[&index]).expect("fixture parses");
    let placed = donate_whole_files(&set, std::slice::from_ref(&donor), &dir);

    assert_eq!(
        placed.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
        ["good.bin"],
        "only the byte-exact member may be donated: {placed:?}"
    );
    assert_eq!(std::fs::read(dir.join("good.bin")).unwrap(), good);
    assert!(
        !dir.join("repack.bin").exists(),
        "a same-name same-length donor with different bytes must place NOTHING"
    );
    assert!(!dir.join("absent.bin").exists());
    assert_eq!(
        std::fs::read(donor.join("repack.bin")).unwrap(),
        repack_wrong,
        "and the donor's own files are read-only to this pass"
    );
    // No half-written temporaries survive a run.
    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".donating"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporaries left behind: {leftovers:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// An absent donor directory, an unreadable one, and a destination that
/// already holds the member: all three donate nothing new and change
/// nothing. The first two are the §293 ownership rule - a donor is a
/// directory this job does not own, so a racing cleanup degrades to no
/// donation and never to an error - and the third is the re-run: the
/// member already in place is REPORTED (the plan must still strike its
/// articles) and copied nowhere.
#[test]
fn an_absent_donor_donates_nothing_and_a_member_already_in_place_is_reported_once() {
    let donor = tmpdir("donate-idem-src");
    let dir = tmpdir("donate-idem-dst");
    let data = payload(260, 41);
    let files: &[(&str, &[u8])] = &[("f1.bin", &data)];
    let index = par2_index(SET, BS, files);
    let set = par2::Par2Set::parse(&[&index]).expect("fixture parses");

    let ghost = donor.join("no-such-subdir");
    assert!(
        donate_whole_files(&set, std::slice::from_ref(&ghost), &dir).is_empty(),
        "an absent donor directory must donate nothing"
    );
    assert!(!dir.join("f1.bin").exists());

    std::fs::write(donor.join("f1.bin"), &data).unwrap();
    let first = donate_whole_files(&set, &[ghost.clone(), donor.clone()], &dir);
    assert_eq!(first.len(), 1, "the readable donor beside the ghost wins");
    assert_eq!(first[0].from, donor.join("f1.bin"));

    // Second pass over the same destination: same answer, and the
    // donor is not read again for it (the file is already right).
    let again = donate_whole_files(&set, std::slice::from_ref(&donor), &dir);
    assert_eq!(again.len(), 1, "a re-run reports the member already held");
    assert_eq!(
        again[0].from,
        dir.join("f1.bin"),
        "and credits it to the destination, not to a second copy"
    );
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), data);

    // A destination file that is NOT the member is left alone: an
    // in-flight fetch owns that inode.
    std::fs::write(dir.join("f1.bin"), payload(260, 42)).unwrap();
    assert!(
        donate_whole_files(&set, std::slice::from_ref(&donor), &dir).is_empty(),
        "a wrong-bytes destination is never overwritten by a donation"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// The same "left alone" promise, held to an ENTRY rather than to a
/// name that RESOLVES (31 Aug 2026 rename-occupancy census).
/// `Path::exists` follows symlinks and answers false on any error, so a
/// link at a member's name read as free and the donation's closing
/// `fs::rename` removed it - rename removes whatever entry is at its
/// destination and never resolves it. Declining costs one donation and
/// the member comes off the wire instead, which is the baseline this
/// whole function is an optimisation over.
#[cfg(unix)]
#[test]
fn a_member_name_an_entry_already_holds_is_never_donated_over() {
    let donor = tmpdir("donate-link-src");
    let dir = tmpdir("donate-link-dst");
    let data = payload(260, 43);
    let files: &[(&str, &[u8])] = &[("f1.bin", &data)];
    let index = par2_index(SET, BS, files);
    let set = par2::Par2Set::parse(&[&index]).expect("fixture parses");
    std::fs::write(donor.join("f1.bin"), &data).unwrap();

    std::os::unix::fs::symlink(dir.join("on-the-nas"), dir.join("f1.bin")).unwrap();
    assert!(
        donate_whole_files(&set, std::slice::from_ref(&donor), &dir).is_empty(),
        "a dangling link is an entry, so the member name is taken"
    );
    assert!(
        std::fs::symlink_metadata(dir.join("f1.bin"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "and the link is still a link"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// Sweep S3: the directory-level tolerance above, held at FILE level.
/// A donor file the walk listed but the read cannot open (the racing
/// delete-files cleanup, one step later; an unreadable file is its
/// deterministic stand-in - same `File::open` error, no timing) must
/// degrade to "no donation": the repair still completes when its own
/// recovery suffices, and lands on the ordinary shortfall arithmetic
/// when it does not - never on an I/O error. Both donor roads are
/// exercised: the whole-file fast path (candidate length matches the
/// missing target, so the head hash is what trips) and the sliding
/// scan (length matches nothing, so `scan_candidate`'s open is what
/// trips). Run as root the chmod bites nothing and the candidate is
/// just wrong bytes - every assertion still holds, only the error
/// path goes unexercised.
#[cfg(unix)]
#[test]
fn an_unreadable_donor_file_degrades_to_no_donation() {
    use std::os::unix::fs::PermissionsExt;
    let real = payload(260, 21);
    let files: &[(&str, &[u8])] = &[("f1.bin", &real)];

    // Recovery suffices: five slices missing, five held - the dead
    // donor file (length == the target's, so the fast path hashes it)
    // must not stop the rebuild.
    let donor = tmpdir("deadfile-src");
    let dir = tmpdir("deadfile-dst");
    let dead = donor.join("aaaa.dat");
    std::fs::write(&dead, payload(260, 99)).unwrap();
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+5.par2"),
        par2_volume(SET, BS, files, &[0, 1, 2, 3, 4]),
    )
    .unwrap();
    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("a dead donor file must not fail the repair")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("recovery covers all five slices, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 0, "nothing readable to adopt");
    assert_eq!(report.blocks_rebuilt, 5, "recovery did the whole job");
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), real);
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);

    // Recovery short: the same dead donor (length matching no target,
    // so it reaches the sliding scan) must leave the verdict at the
    // ordinary needed/have arithmetic, exactly as with no donor.
    let donor = tmpdir("deadfile2-src");
    let dir = tmpdir("deadfile2-dst");
    let dead = donor.join("aaaa.dat");
    std::fs::write(&dead, payload(100, 99)).unwrap();
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();
    match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("a dead donor file must not fail the shortfall verdict either")
    {
        RepairStatus::Unrepairable { needed, have, .. } => {
            assert_eq!((needed, have), (5, 1), "the no-donor arithmetic, untouched")
        }
        other => panic!("one slice held against five missing, got {other:?}"),
    }
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// And the drop is per-FILE, not per-donation: a dead donor file
/// sorted ahead of a good copy in the same donor directory costs only
/// itself - the scan moves on and the good copy still donates
/// everything.
#[cfg(unix)]
#[test]
fn an_unreadable_donor_file_does_not_block_a_readable_one() {
    use std::os::unix::fs::PermissionsExt;
    let donor = tmpdir("deadpair-src");
    let dir = tmpdir("deadpair-dst");
    let real = payload(260, 21);
    let files: &[(&str, &[u8])] = &[("f1.bin", &real)];
    let dead = donor.join("aaaa.dat");
    std::fs::write(&dead, payload(260, 99)).unwrap();
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::write(donor.join("zzzz.dat"), &real).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();
    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("the dead file costs itself, not the repair")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("the good copy covers everything, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 5, "adopted from the readable copy");
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), real);
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// Sweep S3's residue, the patch-time half: the adoption decision is
/// final, the donor file is then DELETED (the racing delete-files
/// cleanup landing one phase later, during the solve or the patch), and
/// the read that wants the donor's bytes must still be served - through
/// the handle [`adopt::pin_donor_sources`] held open at decision time.
/// The delete is issued between the pin and the read, which is the exact
/// window, made deterministic. No cfg arm on purpose: the platform claim
/// the pin rests on is that BOTH unix (an unlinked inode stays readable)
/// and Windows (std opens with FILE_SHARE_DELETE) serve a deleted file
/// through an open handle, so the same test body pins both.
#[test]
fn a_donor_vanishing_after_the_adoption_decision_still_serves_its_bytes() {
    let donor = tmpdir("pinwin-src");
    let bytes = payload(2 * BS, 41);
    let path = donor.join("gone.dat");
    std::fs::write(&path, &bytes).unwrap();
    let cands: Vec<(PathBuf, u64)> = vec![(path.clone(), bytes.len() as u64)];
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    adopted.insert(0, AdoptSrc { cand: 0, offset: 0 });
    adopted.insert(
        1,
        AdoptSrc {
            cand: 0,
            offset: BS as u64,
        },
    );
    let mut missing: Vec<usize> = Vec::new();
    let open = adopt::pin_donor_sources(&cands, &(0..1), &mut adopted, &mut missing);
    assert_eq!(open.len(), 1, "the referenced donor is pinned");
    assert_eq!(adopted.len(), 2, "nothing degraded");
    assert!(missing.is_empty());
    std::fs::remove_file(&path).unwrap();
    assert!(!path.exists(), "the path is really gone");
    let mut reader = super::super::adopt::CandReader {
        cands: &cands,
        open,
    };
    let got = reader
        .read(
            AdoptSrc {
                cand: 0,
                offset: BS as u64,
            },
            BS,
        )
        .expect("the held handle serves the unlinked bytes");
    assert_eq!(&got[..], &bytes[BS..2 * BS]);
    let _ = std::fs::remove_dir_all(&donor);
}

/// A donor that vanished BETWEEN the scan and the pin degrades exactly
/// as a scan-time vanish does (§293's ownership rule): the adoption is
/// dropped, its slices rejoin `missing` in ascending order (the solve's
/// row mapping consumes that order), and nothing errors - the caller's
/// needed/have arithmetic judges the shortfall from there.
#[test]
fn a_donor_unopenable_at_pin_time_degrades_to_no_donation() {
    let donor = tmpdir("pinmiss-src");
    let path = donor.join("never-there.dat");
    let cands: Vec<(PathBuf, u64)> = vec![(path, 4 * BS as u64)];
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    adopted.insert(7, AdoptSrc { cand: 0, offset: 0 });
    adopted.insert(
        3,
        AdoptSrc {
            cand: 0,
            offset: BS as u64,
        },
    );
    let mut missing: Vec<usize> = vec![1, 5];
    let open = adopt::pin_donor_sources(&cands, &(0..1), &mut adopted, &mut missing);
    assert!(open.is_empty(), "nothing to hold");
    assert!(adopted.is_empty(), "the vanished donor's adoptions dropped");
    assert_eq!(missing, vec![1, 3, 5, 7], "slices rejoin missing, sorted");
    let _ = std::fs::remove_dir_all(&donor);
}

/// End-to-end: the pin is WIRED into the directory driver - a donor
/// deleted while the repair is mid-patch no longer fails it. Two
/// junk-named donor files each carry a whole missing target, so the
/// fast path adopts every slice, nothing needs Reed-Solomon, and the
/// PATCH is the first reader of the donor bytes; a helper thread
/// deletes both donor files the moment the patch's first temp file
/// appears in the repair dir. With the pin the deletion is a non-event
/// at any interleaving, so this passes deterministically; without it
/// the patch's lazy open lands on an unlinked path (verified to bite
/// with the pin neutered - see the landing commit).
#[test]
fn a_donor_deleted_during_the_patch_no_longer_fails_the_repair() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let donor = tmpdir("pinrace-src");
    let dir = tmpdir("pinrace-dst");
    let f1 = payload(5 * BS, 51);
    let f2 = payload(5 * BS, 52);
    let files: &[(&str, &[u8])] = &[("f1.bin", &f1), ("f2.bin", &f2)];
    std::fs::write(donor.join("aaaa.dat"), &f1).unwrap();
    std::fs::write(donor.join("zzzz.dat"), &f2).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    let done = std::sync::Arc::new(AtomicBool::new(false));
    let killer = {
        let (donor, dir, done) = (donor.clone(), dir.clone(), done.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let tmp_seen = std::fs::read_dir(&dir).is_ok_and(|rd| {
                    rd.flatten()
                        .any(|e| e.file_name().to_string_lossy().contains(".nzbfast-repair."))
                });
                if tmp_seen {
                    break;
                }
                std::hint::spin_loop();
            }
            let _ = std::fs::remove_file(donor.join("aaaa.dat"));
            let _ = std::fs::remove_file(donor.join("zzzz.dat"));
        })
    };
    let res = repair_dir_with_donors(&dir, std::slice::from_ref(&donor));
    done.store(true, Ordering::Relaxed);
    killer.join().unwrap();
    let report = match res.expect("a donor deleted mid-patch must not fail the repair") {
        RepairStatus::Repaired(r) => r,
        other => panic!("both files adoptable from the donor, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 10, "every slice adopted");
    assert_eq!(report.blocks_rebuilt, 0, "none rebuilt");
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), f1);
    assert_eq!(std::fs::read(dir.join("f2.bin")).unwrap(), f2);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// §293: adoption and Reed-Solomon COMPOSE. A truncated donor covers
/// the head of the missing file, the recovery slices cover the tail,
/// and neither alone is enough - four blocks adopted, two rebuilt, the
/// landed file byte-exact. Pins that adopted blocks feed the solve as
/// present rather than crowding it out.
#[test]
fn adoption_and_recovery_slices_compose_on_one_file() {
    let donor = tmpdir("compose-src");
    let dir = tmpdir("compose-dst");
    let f1 = payload(6 * BS - 20, 31);
    let files: &[(&str, &[u8])] = &[("f1.bin", &f1)];
    // The donor carries only the first four blocks' bytes, junk-named.
    std::fs::write(donor.join("7fa2c1.dat"), &f1[..4 * BS]).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+2.par2"),
        par2_volume(SET, BS, files, &[0, 1]),
    )
    .unwrap();

    match repair_dir(&dir).expect("baseline runs") {
        RepairStatus::Unrepairable { needed, have, .. } => assert_eq!((needed, have), (6, 2)),
        other => panic!("six missing, two held - must be short alone, got {other:?}"),
    }
    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("composed repair runs")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("donor head + recovery tail must compose, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 4, "the donor's four blocks");
    assert_eq!(report.blocks_rebuilt, 2, "and the recovery's two");
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), f1);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

#[test]
fn a_wholly_renamed_copy_is_adopted_and_reported_consumed() {
    let dir = tmpdir("adopt");
    let a = payload(200, 7);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    // The obfuscated-post shape: the payload exists only under a hash
    // name, the FileDesc name is absent, no recovery slices anywhere.
    std::fs::write(dir.join("0f9a7c"), &a).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    // The name gate skips the set (no FileDesc name on disk)...
    assert!(
        repair_present_sets(&dir)
            .expect("present-set walk")
            .is_empty(),
        "no declared name on disk means the plain entry point skips"
    );
    // ...and the renamed fallback attempts it anyway and succeeds.
    let outcomes = repair_present_or_renamed_sets(&dir).expect("fallback runs");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].names, ["a.bin"]);
    let report = match outcomes[0].status.as_ref().expect("set repairs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 4, "every slice found in the copy");
    assert_eq!(report.files_created, ["a.bin"]);
    assert_eq!(
        report.consumed_sources,
        [dir.join("0f9a7c")],
        "the donor is a proven byte-for-byte copy, so the caller may sweep it"
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    // With the payload landed, the plain entry point now sees the set
    // and reports it clean.
    let again = repair_present_sets(&dir).expect("present-set walk");
    assert_eq!(again.len(), 1);
    assert!(
        matches!(again[0].status, Ok(RepairStatus::NoDamage)),
        "{:?}",
        again[0].status
    );
    let _ = std::fs::remove_dir_all(&dir);
}
