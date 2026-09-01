//! Y2 and Y3 (wave-4 follow-ups, 31 Aug 2026) - the two halves of row
//! M4-62 that were reasoned about rather than measured.
//!
//! M4-62 named three harms a target's PADDED last-block window could
//! cause: "mark the last block present, get spent as a donor, or
//! cross-assign if two files share an all-zero tail pad." The SPEND was
//! red and landed with its fix (the `min` bound in
//! [`super::super::adopt::proven_spent`]'s fully-donated arm, pinned by
//! `a_padded_last_block_donor_serves_its_bytes_and_is_not_spent`).
//! "Mark present" was measured and is not reachable. The other two were
//! read, not run, and this module runs them.
//!
//! A child of `unit_tests` rather than a sibling, for its fixture
//! helpers - `payload`, `par2_index`, `tmpdir`, `BS`, `SET` - and
//! because `unit_tests.rs` was at 2,822 of the 3,000-line ceiling when
//! this landed.

use super::*;

/// Y2, the row's literal shape: two targets in ONE set whose padded
/// last-block windows COLLIDE, both missing their last block, both fed
/// by one donor window.
///
/// Constructing it is the finding. The block checksums cover the WHOLE
/// padded window, so two windows collide only by being identical byte
/// for byte, and here that means the two files share the same
/// `length % bs` AND the same final `r` bytes - so whichever target the
/// donated bytes are handed to, they are that target's bytes.
///
/// THAT IS THIS FIXTURE'S SHAPE AND NOT A LAW, which this pin claimed
/// as one until 31 Aug 2026. Two files with DIFFERENT `length % bs`
/// collide too when both tails are all zeros, which is M4-62's literal
/// wording -
/// `two_all_zero_tails_of_different_widths_collide_and_each_target_takes_its_own`
/// below is the counterexample. What holds across both is weaker and is
/// the thing actually worth pinning: every byte the engine hands a
/// target is a byte that target's own FileDesc accounts for, because
/// the width is taken from `t.file.length` and never from the window.
///
/// The reason to pin THIS shape is the two places the engine could
/// still get it wrong.
///
/// FIRST, the CLAIM has to reach both. `by_crc` maps a CRC to a VEC of
/// wanted slices and `scan_candidate` walks all of them at a hit, so
/// one window claims every slice it matches. A map holding one slice
/// per checksum would repair the first file and report the second
/// wholly missing, with no donor left to find - the failure this
/// asserts against by demanding BOTH files back byte-exact.
///
/// SECOND, the SPEND has to price the window once per target and by
/// each target's own real bytes. Two adoptions from one candidate at
/// one offset are two spans, not twice the coverage, so M4-62's bound
/// must still refuse: 8 real bytes of a 64-byte donor are wanted here,
/// exactly as in the single-target row, and `sweep_spent_sources`
/// unlinks whatever it is handed.
#[test]
fn two_targets_sharing_a_padded_last_block_are_both_fed_and_the_donor_is_not_spent() {
    let dir = tmpdir("y2pad");
    // 200 bytes at BS=64 is 3 full slices and a last slice of 8 real
    // bytes followed by 56 of pad. The lengths must be congruent mod
    // BS or the two windows have different real widths and cannot
    // collide at all; here they are equal, which is the sharpest form.
    let a = payload(200, 61);
    let mut b = payload(200, 62);
    b[192..].copy_from_slice(&a[192..]);
    assert_ne!(a, b, "the two files must differ everywhere but the tail");
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b)];
    // TRUNCATED rather than damaged, for the reason M4-40 and the M4-62
    // row both record: a hole reads as zeros and an all-zero block can
    // verify PRESENT off the target's own file, so no candidate is ever
    // consulted.
    std::fs::write(dir.join("a.bin"), &a[..192]).unwrap();
    std::fs::write(dir.join("b.bin"), &b[..192]).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    let mut window = a[192..].to_vec();
    window.resize(BS, 0);
    std::fs::write(dir.join("junkY2.bin"), &window).unwrap();

    let report = match repair_dir(&dir).expect("adoption repairs without recovery") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(
        report.blocks_adopted, 2,
        "one window matching two wanted slices must claim BOTH - a checksum \
         index holding one slice per CRC repairs the first file and reports \
         the second wholly missing"
    );
    assert_eq!(report.adopted_from, ["junkY2.bin"]);
    assert_eq!(
        std::fs::read(dir.join("a.bin")).unwrap(),
        a,
        "the first target must come back whole, at its full length"
    );
    assert_eq!(
        std::fs::read(dir.join("b.bin")).unwrap(),
        b,
        "and so must the second - a collision is never an ambiguity, because \
         the checksum covers the whole padded window"
    );
    assert!(
        report.consumed_sources.is_empty(),
        "M4-62's bound must survive a window serving TWO targets: two \
         adoptions at one offset are two spans, not twice the coverage, and \
         {} of this donor's {BS} bytes are absent from either target: {:?}",
        BS - 8,
        report.consumed_sources
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Y2's other half, and the only cross-assign that changes what a
/// window is WORTH: a padded tail colliding with a FULL interior block
/// of another file in the same set. That is constructible without any
/// hash collision - an interior block ending in `bs - r` zeros has the
/// same bytes as a tail whose `r` real bytes match its head - and it is
/// where M4-62's `min` could go wrong in the OTHER direction.
///
/// Priced by the tail alone the donor is 8 of 64 bytes covered and
/// kept, which would be the pre-F9 clutter this arm exists to sweep.
/// Priced by the window it is 64 of 64 either way, which is M4-62's
/// defect. Priced per target by that target's own real bytes - which is
/// what the bound says - the interior block covers the donor's whole
/// length and it is correctly reported spent, because every byte of it
/// really is in the second target now.
#[test]
fn a_window_serving_a_tail_and_an_interior_block_is_priced_by_each_targets_own_bytes() {
    let dir = tmpdir("y2cross");
    let a = payload(200, 71);
    let mut b = payload(BS * 4, 72);
    // Block 1 of `b` becomes `a`'s 8 real tail bytes plus 56 zeros -
    // byte-identical to `a`'s padded last-block window, with no
    // collision engineering anywhere.
    b[BS..BS + 8].copy_from_slice(&a[192..]);
    b[BS + 8..BS * 2].fill(0);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b)];
    std::fs::write(dir.join("a.bin"), &a[..192]).unwrap();
    // `b` keeps its length and loses block 1 to damage, so it stays an
    // IDENTIFIED target (blocks 0, 2 and 3 verify) and is never handed
    // to the sliding scan as a donor for `a`.
    let mut bd = b.clone();
    bd[BS..BS * 2].fill(0xEE);
    std::fs::write(dir.join("b.bin"), &bd).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(dir.join("junkY2x.bin"), &b[BS..BS * 2]).unwrap();

    let report = match repair_dir(&dir).expect("adoption repairs without recovery") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 2);
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b);
    assert_eq!(
        report
            .consumed_sources
            .iter()
            .filter_map(|p| p.file_name())
            .collect::<Vec<_>>(),
        ["junkY2x.bin"],
        "an interior block wants all {BS} of this donor's bytes, so the \
         window IS fully donated however little of it the tail wanted: {:?}",
        report.consumed_sources
    );
    // The engine never unlinks; it reports, and the caller owns the
    // directory (see `RepairReport::consumed_sources`).
    assert!(dir.join("junkY2x.bin").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Y3 - [`super::super::adopt::proven_spent`]'s DAMAGED-TWIN arm
/// against a candidate SHORTER on disk than the length the candidate
/// table carries for it.
///
/// M4-62's bound went into the fully-donated arm only. The twin arm
/// above it looks sound for a different reason: it requires
/// `t.file.length == len`, so target and candidate end at the same
/// place and the target's padding lies beyond both. That is a reading
/// of the code. The shape it does not obviously survive is a candidate
/// whose recorded length no longer matches its bytes:
/// `adoption_candidates` stats every candidate once, up front, and this
/// arm reads them again after the patch and the final verify.
///
/// WHERE THAT IS REACHABLE FROM is worth stating exactly, because the
/// obvious answer is the wrong one and this lane gave it first. The
/// DONOR-directory race - the one `sliding_scan`'s "shrank mid-scan"
/// tolerance and `pin_donor_sources` exist for - cannot reach this arm
/// AT ALL: the TODO 293 guard at the spend loop skips every candidate
/// not under `dir`, so only the repair directory's own files are ever
/// priced for a spend. What reaches it is that the repair directory is
/// not private to this job - `Job::filed` puts every episode of a show
/// in one `out_dir`, so it routinely holds files this download did not
/// write and some other process may be truncating.
///
/// Driven directly rather than through `repair_dir`, because the
/// disagreement between the table and the disk is exactly what a
/// black-box fixture cannot stage: the two are read at the same
/// instant by any test that only writes files.
///
/// MEASURED GREEN. The arm reads every slice it has no construction
/// proof for off the candidate, `read_span` answers false on a short
/// read, and a false there refuses the whole twin - the direction that
/// KEEPS the file. The control below is the same fixture with the
/// truncation removed and nothing else, so the refusal is caused by the
/// shortness and by nothing else in the construction.
///
/// STATED LIMIT. A target every slice of which is adopted from this
/// candidate or rebuilt from recovery performs no read at all, and the
/// majority test then decides on `fed_by_ci` alone - so a short
/// candidate could pass that path. It cannot be reached: those
/// adoptions are read through `CandReader::read`, whose
/// `disk::read_exact_at` is fatal on a short candidate, so the repair
/// errors out long before any spend is priced.
#[test]
fn a_candidate_shorter_than_its_recorded_length_is_never_proven_a_twin() {
    let dir = tmpdir("y3twin");
    // 200 bytes: slices 0..2 full, slice 3 is 8 real bytes of a target
    // that ends where the candidate's record says the candidate does.
    let a = payload(200, 81);
    std::fs::write(dir.join("a.bin"), &a).unwrap();
    // A damaged twin: the first three blocks are this repair's donation
    // (excused by construction), the tail is the one span the arm has
    // to read off the candidate to believe.
    let mut twin = payload(200, 82);
    twin[192..].copy_from_slice(&a[192..]);
    let full = dir.join("twin.bin");
    std::fs::write(&full, &twin).unwrap();

    let target = Target {
        file: Par2File {
            file_id: [1u8; 16],
            name: "a.bin".into(),
            length: 200,
            md5: [0u8; 16],
            md5_16k: [0u8; 16],
            blocks: Vec::new(),
        },
        path: dir.join("a.bin"),
        first_slice: 0,
        n_slices: 4,
        present: vec![true, true, true, false],
        intact: false,
        exists: true,
        resume: None,
    };
    // Slices 0..2 adopted from this candidate at their own offsets, so
    // `fed_by_ci` is 3 of 4 and clears the majority bar; slice 3 is the
    // one the arm must prove by reading.
    let adopted: HashMap<usize, AdoptSrc> = (0..3)
        .map(|li| {
            (
                li,
                AdoptSrc {
                    cand: 0,
                    offset: (li as u64) * BS as u64,
                },
            )
        })
        .collect();
    let rebuilt: HashSet<usize> = HashSet::new();
    let targets = [target];

    // The CONTROL, first: with the candidate's bytes matching its
    // record, this is a genuine twin and the arm fires.
    let cands = [(full.clone(), 200u64)];
    assert!(
        adopt::proven_spent(&full, 200, 0, &targets, &adopted, &rebuilt, &cands, BS),
        "a same-length damaged twin whose every unexcused span matches the \
         target must still be proven spent - without this the probe below \
         proves nothing"
    );

    // The probe: the same fixture, the same table, and the file on disk
    // one block shorter than the table says.
    std::fs::write(&full, &twin[..192]).unwrap();
    assert!(
        !adopt::proven_spent(&full, 200, 0, &targets, &adopted, &rebuilt, &cands, BS),
        "a candidate whose recorded length outruns its bytes was proven a \
         twin on spans nothing could read - the caller unlinks what this \
         says is spent"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Y2 again, at the row's LITERAL wording - "if two files share an
/// all-zero tail pad" - which the two pins above do not reach and which
/// falsifies the reason they were first written down with.
///
/// The claim was that two padded windows collide only by being
/// identical byte for byte, "which forces the two files to share the
/// same `length % bs` and the same final `r` bytes". The second half is
/// false, and this is the counterexample: a 200-byte member ends in 8
/// real zero bytes plus 56 of pad, a 208-byte member in 16 real zero
/// bytes plus 48 of pad, and BOTH windows are 64 zeros. Different
/// `length % bs`, different real widths, no shared content at all, one
/// checksum. Nothing about the format prevents it, and an all-zero tail
/// is not exotic - it is what a container's trailing padding looks like.
///
/// MEASURED GREEN anyway, for a reason that survives the correction:
/// the donated bytes are zeros and both targets' real tails ARE zeros,
/// so each gets its own `r` of them and comes back byte-exact at its
/// own length. What carries it is not the windows being equal, it is
/// `real_bytes_of` pricing each slice by the target that owns it - the
/// same per-target arithmetic
/// `a_window_serving_a_tail_and_an_interior_block_is_priced_by_each_targets_own_bytes`
/// pins on the spend side, here on the WRITE side.
///
/// M4-40's `real >= tail[o]` rule is what keeps this honest at the
/// other end: this donor is a full 64 real bytes, so it may stand in
/// for both. A one-byte `0x00` decoy has `real == 1` and is refused for
/// both, which is the harm that rule was written for.
#[test]
fn two_all_zero_tails_of_different_widths_collide_and_each_target_takes_its_own() {
    let dir = tmpdir("y2zero");
    let mut a = payload(200, 91);
    let mut b = payload(208, 92);
    a[192..].fill(0);
    b[192..].fill(0);
    // The point of the fixture: the two members disagree about how much
    // of that last window is theirs, and the checksums cannot tell.
    assert_eq!(a.len() % BS, 8);
    assert_eq!(b.len() % BS, 16);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b)];
    std::fs::write(dir.join("a.bin"), &a[..192]).unwrap();
    std::fs::write(dir.join("b.bin"), &b[..192]).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(dir.join("junkY2z.bin"), vec![0u8; BS]).unwrap();

    let report = match repair_dir(&dir).expect("adoption repairs without recovery") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 2);
    assert_eq!(
        std::fs::read(dir.join("a.bin")).unwrap(),
        a,
        "the narrower member must take 8 bytes and end at 200"
    );
    assert_eq!(
        std::fs::read(dir.join("b.bin")).unwrap(),
        b,
        "and the wider one 16, ending at 208 - one window, two real widths"
    );
    assert!(
        report.consumed_sources.is_empty(),
        "M4-62's bound prices this donor at max(8, 16) of {BS} bytes, so it \
         is not fully donated and must not be swept: {:?}",
        report.consumed_sources
    );
    let _ = std::fs::remove_dir_all(&dir);
}
