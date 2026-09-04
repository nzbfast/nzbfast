//! Harvesting a DONOR directory's own PAR2 recovery volumes as parity
//! for this repair, scoped by recovery set id (claim
//! `donor-parity-catalog-harvest`, 1 Sep 2026).
//!
//! A child of `unit_tests` for the two reasons every other child here
//! gives: `use super::*` reaches the parent's fixtures - `payload`,
//! `par2_index`, `par2_volume`, `tmpdir`, `BS` - exactly as an inline
//! test did, and the module is named for its file so size-gate.py's
//! CFG_TEST_MOD resolver keeps scoring it as test code.
//!
//! THE DONOR DIRECTORIES HERE HOLD NOTHING BUT `.par2` FILES, and that
//! is the point rather than a convenience: `is_recovery_by_name_and_content`
//! excludes a recovery volume from the adoption walk, so nothing these
//! donors contain can reach the repair through TODO 293's adoption path.
//! Anything that changes is the parity harvest talking.

use super::*;

/// The shape the harvest is for: the repair dir holds the set's index
/// and ONE volume, and a predecessor's directory holds the volumes the
/// successor never got - same release, same par2, so the same recovery
/// set id. Baseline leg (no donor): Unrepairable, short by every block
/// but one. Treatment leg: the donor's slices fill the selection, the
/// solve runs, and every member comes back byte-exact - which is the
/// proof that matters, because the whole-file MD5 at the end of the
/// repair is what a wrong slice would fail.
#[test]
fn a_donor_directorys_recovery_volumes_complete_the_repair() {
    let donor = tmpdir("donor-parity-src");
    let dir = tmpdir("donor-parity-dst");
    let f1 = payload(200, 21);
    let f2 = payload(300, 22);
    let files: &[(&str, &[u8])] = &[("f1.bin", &f1), ("f2.bin", &f2)];
    let set = [0x21u8; 16];

    // The repair directory: the set's criticals, one recovery slice,
    // and no payload at all (both members have to be rebuilt whole).
    std::fs::write(dir.join("set.par2"), par2_index(set, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(set, BS, files, &[0]),
    )
    .unwrap();

    // f1 is 200 bytes = 4 blocks at BS 64, f2 is 300 = 5. Nine missing,
    // one held.
    let need = f1.len().div_ceil(BS) + f2.len().div_ceil(BS);
    match repair_dir(&dir).expect("baseline runs") {
        RepairStatus::Unrepairable { needed, have, .. } => {
            assert_eq!((needed, have), (need, 1));
        }
        other => panic!("baseline must be unrepairable, got {other:?}"),
    }

    // The donor: the SAME set's volumes, carrying the exponents this
    // directory never received. Nothing else - not one payload byte.
    std::fs::write(
        donor.join("set.vol1+8.par2"),
        par2_volume(set, BS, files, &[1, 2, 3, 4, 5, 6, 7, 8]),
    )
    .unwrap();

    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("donor-parity repair runs")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("donor volumes must complete the repair, got {other:?}"),
    };
    assert_eq!(report.blocks_rebuilt, need, "every block from parity");
    assert_eq!(
        report.blocks_adopted, 0,
        "a recovery volume is not an adoption candidate - nothing may come through §293 here"
    );
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), f1);
    assert_eq!(std::fs::read(dir.join("f2.bin")).unwrap(), f2);
    // A donor is another job's directory: never patched, never swept.
    assert!(donor.join("set.vol1+8.par2").exists());
    assert!(report.consumed_sources.is_empty());
}

/// THE CONTROL THAT MATTERS. A donor volume whose recovery set id
/// DIFFERS was computed over a different global input grid - different
/// main packet, so a different block size and different file ids - and
/// its slices are arithmetic garbage against this set. Admitting one
/// would be a correctness bug, not a missed optimisation, so the id
/// compare is the harvest's only admission rule.
///
/// The foreign set is built over the same NAMES and the same block size
/// on purpose: everything a name- or shape-based arm could match on is
/// identical, and only the id says no. And it must change NOTHING - the
/// same verdict, the same arithmetic, no error - because a job
/// directory routinely sits beside an unrelated predecessor.
#[test]
fn a_donor_volume_from_a_different_set_changes_nothing() {
    let donor = tmpdir("donor-parity-foreign-src");
    let dir = tmpdir("donor-parity-foreign-dst");
    let f1 = payload(200, 31);
    let f2 = payload(300, 32);
    let files: &[(&str, &[u8])] = &[("f1.bin", &f1), ("f2.bin", &f2)];
    let ours = [0x31u8; 16];
    let theirs = [0x32u8; 16];

    std::fs::write(dir.join("set.par2"), par2_index(ours, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(ours, BS, files, &[0]),
    )
    .unwrap();
    // Same names, same block size, same exponents - a DIFFERENT set id.
    std::fs::write(
        donor.join("set.vol1+8.par2"),
        par2_volume(theirs, BS, files, &[1, 2, 3, 4, 5, 6, 7, 8]),
    )
    .unwrap();

    let need = f1.len().div_ceil(BS) + f2.len().div_ceil(BS);
    let baseline = match repair_dir(&dir).expect("baseline runs") {
        RepairStatus::Unrepairable { needed, have, .. } => (needed, have),
        other => panic!("baseline must be unrepairable, got {other:?}"),
    };
    assert_eq!(baseline, (need, 1));

    match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("a foreign donor set must not be an error")
    {
        RepairStatus::Unrepairable { needed, have, .. } => {
            assert_eq!(
                (needed, have),
                baseline,
                "a foreign set id must not move the arithmetic by one slice"
            );
        }
        other => panic!("a foreign donor set must change nothing, got {other:?}"),
    }
    // Nothing was written from garbage parity.
    assert!(!dir.join("f1.bin").exists());
    assert!(!dir.join("f2.bin").exists());
}

/// NO-REGRESSION ARM: a repair whose own parity already covers the
/// damage finishes exactly as it did before the harvest existed, with a
/// donor sitting beside it carrying the same set's volumes.
///
/// The gate is `needed > by_exp.len()`, which is false here (one block
/// damaged, one local slice held), so the harvest never runs - but that
/// is a statement about the code, not something this fixture can see:
/// the donor's exponent 0 is a DUPLICATE of the local one, so the
/// selection would be identical either way. What it does pin is that
/// the outcome does not move. The discriminating arm for WHICH copy of
/// a shared exponent wins is
/// [`the_repair_dirs_own_slice_wins_a_shared_exponent`] below.
#[test]
fn a_donor_beside_a_repair_that_needs_no_help_changes_nothing() {
    let donor = tmpdir("donor-parity-nogap-src");
    let dir = tmpdir("donor-parity-nogap-dst");
    let f1 = payload(200, 41);
    let files: &[(&str, &[u8])] = &[("f1.bin", &f1)];
    let set = [0x41u8; 16];

    std::fs::write(dir.join("set.par2"), par2_index(set, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(set, BS, files, &[0]),
    )
    .unwrap();
    std::fs::write(
        donor.join("set.vol0+4.par2"),
        par2_volume(set, BS, files, &[0, 1, 2, 3]),
    )
    .unwrap();

    // One block of the member corrupted: one missing, one slice held.
    let mut damaged = f1.clone();
    damaged[70] ^= 0xff;
    std::fs::write(dir.join("f1.bin"), &damaged).unwrap();

    let report =
        match repair_dir_with_donors(&dir, std::slice::from_ref(&donor)).expect("repair runs") {
            RepairStatus::Repaired(r) => r,
            other => panic!("one block against one local slice must repair, got {other:?}"),
        };
    assert_eq!(report.blocks_rebuilt, 1);
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), f1);
}

/// A donor whose volumes sit in a SUBDIRECTORY is still harvested: the
/// packet walk over a donor is `PacketScope::Nested`, matching the
/// donor half of the adoption walk, because a donor is somebody else's
/// output tree and its par2 may sit wherever publication put it.
#[test]
fn donor_volumes_below_the_donor_root_are_harvested() {
    let donor = tmpdir("donor-parity-nested-src");
    let dir = tmpdir("donor-parity-nested-dst");
    let f1 = payload(200, 51);
    let files: &[(&str, &[u8])] = &[("f1.bin", &f1)];
    let set = [0x51u8; 16];

    std::fs::write(dir.join("set.par2"), par2_index(set, BS, files)).unwrap();
    std::fs::create_dir_all(donor.join("meta")).unwrap();
    std::fs::write(
        donor.join("meta").join("set.vol0+4.par2"),
        par2_volume(set, BS, files, &[0, 1, 2, 3]),
    )
    .unwrap();

    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("nested donor repair runs")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("a nested donor volume must be found, got {other:?}"),
    };
    assert_eq!(report.blocks_rebuilt, f1.len().div_ceil(BS));
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), f1);
}

/// THE `or_insert` ORDERING, WITH A FIXTURE THAT CAN TELL. The harvest
/// fills gaps only: a repair directory's own slice must keep an
/// exponent a donor also carries, so a directory that needed no help
/// selects byte-for-byte what it selected before.
///
/// Stating that is easy and pinning it is not, because a donor's honest
/// duplicate of an exponent gives the same answer whichever copy wins.
/// So the donor's exponent 0 here is DISHONEST: a well-formed packet
/// carrying this set's id, this block size and a full-length payload,
/// computed over a different release's bytes. It survives the packet
/// MD5 (it is a real packet, just of the wrong thing) and it is
/// arithmetic garbage in the solve. The donor's exponent 1 is honest
/// and is the slice the shortfall actually needs.
///
/// So: two blocks damaged against one local slice, the harvest runs,
/// and the repair can only come out byte-exact if the LOCAL exponent 0
/// beat the donor's. Swap the `or_insert` for an `insert` and the
/// member fails its whole-file MD5 instead.
#[test]
fn the_repair_dirs_own_slice_wins_a_shared_exponent() {
    let donor = tmpdir("donor-parity-order-src");
    let dir = tmpdir("donor-parity-order-dst");
    let f1 = payload(200, 61);
    let files: &[(&str, &[u8])] = &[("f1.bin", &f1)];
    // Same name, same length, same block grid - different bytes, so the
    // recovery computed over it is well formed and wrong.
    let decoy_bytes = payload(200, 62);
    let decoy: &[(&str, &[u8])] = &[("f1.bin", &decoy_bytes)];
    let set = [0x61u8; 16];

    std::fs::write(dir.join("set.par2"), par2_index(set, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(set, BS, files, &[0]),
    )
    .unwrap();

    let mut donor_vol = par2_volume(set, BS, decoy, &[0]);
    donor_vol.extend(par2_volume(set, BS, files, &[1]));
    std::fs::write(donor.join("set.vol0+2.par2"), &donor_vol).unwrap();

    // Two blocks corrupted against one local slice: the harvest runs.
    let mut damaged = f1.clone();
    damaged[10] ^= 0xff;
    damaged[140] ^= 0xff;
    std::fs::write(dir.join("f1.bin"), &damaged).unwrap();

    let report =
        match repair_dir_with_donors(&dir, std::slice::from_ref(&donor)).expect("repair runs") {
            RepairStatus::Repaired(r) => r,
            other => panic!("the local exponent 0 must beat the donor's copy of it, got {other:?}"),
        };
    assert_eq!(report.blocks_rebuilt, 2);
    assert_eq!(
        std::fs::read(dir.join("f1.bin")).unwrap(),
        f1,
        "a wrong-release slice reached the solve"
    );
}
