//! P10, the `.par2`-named decoy: a set that declares NO file names must
//! not be attempted by the renamed-set fallback, because attempting it
//! fails the whole directory and takes the real set's verdict with it.
//!
//! The shape comes from catalog row `n2-p2-p10-par2-named-decoy`,
//! whose `note` argues it at length. A post names
//! ONE file `.par2` whose bytes are not a recovery set: a genuine Main
//! packet, a genuine Creator packet, and no FileDesc at all. Everything
//! else in the post - the payload and the real set alike - rides under
//! wire tokens, so the plain presence gate in `repair_sets_catalog`
//! matches nothing and the renamed fallback is what has to rescue the
//! job by adopting the token payload back under its FileDesc name.
//!
//! That fallback attempts EVERY set the walk found. The decoy's Main
//! packet lists a file id no FileDesc describes, so `repair_dir_set`
//! answers `Malformed("No details available for recoverable file number
//! N. ... FileDesc missing for file id ...")` - an Err,
//! which the caller
//! (`nzbfast_engine::get::settle::noset::disk_par2_fallback`) reads as
//! a repair failure for the directory. The real set repaired the
//! payload correctly in the same pass and the job failed anyway.
//!
//! A set that names nothing is no set. That is the same rule finding
//! F11 applies one layer up, where a LIVE set naming zero files is
//! turned back into "no set" before settle chooses a path.
//!
//! NARROW, and the second test is what says so: only a set with ZERO
//! declared names is skipped. A set with SOME descriptors missing is a
//! genuinely damaged index of a set this post really has, and it still
//! reaches the repair and still reports its error.
//!
//! A CHILD of `unit_tests` for `padded_windows`' two reasons: it
//! reaches the helpers above while that file stays inside its size-gate
//! ceiling.

use super::*;

/// The decoy set id - distinct from `SET`, which the real set uses.
const DECOY: [u8; 16] = [0xd1; 16];

/// The decoy's bytes: a well-formed Main packet declaring `n` file ids
/// and not one FileDesc packet to describe them.
///
/// Deliberately VALID down to the seals, because that is what the
/// generator posts (`postfast::recovery::create_decoy` argues the shape
/// at length): random bytes under a `.par2` name are turned away on the
/// packet-magic rung and would say nothing about this one. What makes
/// it a decoy is the last rung alone - the set it declares names no
/// member.
fn decoy_packets(n: usize) -> Vec<u8> {
    let mut main = Vec::new();
    main.extend_from_slice(&(BS as u64).to_le_bytes());
    main.extend_from_slice(&(n as u32).to_le_bytes());
    for i in 0..n {
        // Offset the ids well past the real set's, so a skip here can
        // never be a collision between the two sets' file ids.
        main.extend_from_slice(&fid(200 + i));
    }
    pkt(DECOY, par2::TYPE_MAIN, &main)
}

/// The row. A `.par2`-named decoy beside a real set whose every file is
/// on disk under a token, and the payload comes back under its declared
/// name.
#[test]
fn a_par2_named_decoy_that_names_nothing_does_not_fail_the_real_set() {
    let dir = tmpdir("p10-decoy");
    let a = payload(200, 11);
    let files: &[(&str, &[u8])] = &[("Sniffed.Decoy.2026.bin", &a)];
    // The real set and its payload, both under wire tokens: no declared
    // name is on disk, which is what puts this on the renamed fallback.
    std::fs::write(dir.join("4f1c9a59f85db226"), &a).unwrap();
    std::fs::write(dir.join("97f5e4824def1920"), par2_index(SET, BS, files)).unwrap();
    // ...and the one file in the post that announces itself as parity is
    // the one file that is not parity.
    std::fs::write(dir.join("extras.par2"), decoy_packets(1)).unwrap();

    let outcomes = repair_present_or_renamed_sets(&dir).expect("the fallback runs");
    assert_eq!(
        outcomes.len(),
        1,
        "the decoy declares no file name, so it is not a set to attempt - only the \
         real set is, and every outcome here is one the caller turns into a verdict \
         for the whole directory: {outcomes:?}"
    );
    assert_eq!(
        outcomes[0].set_id, SET,
        "and the one attempted is the real one"
    );
    let report = match outcomes[0].status.as_ref().expect("the real set repairs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert!(
        report.blocks_adopted > 0,
        "the token payload is what the set's member is rebuilt from"
    );
    assert_eq!(report.files_created, ["Sniffed.Decoy.2026.bin"]);
    assert_eq!(
        std::fs::read(dir.join("Sniffed.Decoy.2026.bin")).unwrap(),
        a,
        "the payload lands under the name its FileDesc gives it, byte-exact"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The control, and the whole reason the skip is written as
/// `names.is_empty()` rather than as anything wider: a set that names
/// SOME of its files and lost the descriptor for another is a damaged
/// index of a set this post really has. It is still attempted and it
/// still reports, because a caller that silently skipped it would be
/// dropping a real set's parity on the floor.
#[test]
fn a_set_that_lost_one_descriptor_is_still_attempted_and_still_reports() {
    let dir = tmpdir("p10-partial");
    let a = payload(200, 12);
    let b = payload(200, 13);
    let files: &[(&str, &[u8])] = &[("First.bin", &a), ("Second.bin", &b)];
    // A two-file index with the SECOND FileDesc packet removed: Main
    // still lists both ids, so the set names one file and is missing the
    // description of the other.
    let whole = par2_index(SET, BS, files);
    let mut cut = Vec::new();
    let mut at = 0usize;
    let mut descs = 0usize;
    while let Some((len, ptype)) = peek_packet(&whole[at..]) {
        let keep = !(ptype == *par2::TYPE_FILEDESC && {
            descs += 1;
            descs == 2
        });
        if keep {
            cut.extend_from_slice(&whole[at..at + len]);
        }
        at += len;
    }
    assert_eq!(
        descs, 2,
        "the fixture must have had two descriptors to cut one"
    );
    std::fs::write(dir.join("d0e1f2a3b4c5d6e7"), &a).unwrap();
    std::fs::write(dir.join("a1b2c3d4e5f60718"), cut).unwrap();

    let outcomes = repair_present_or_renamed_sets(&dir).expect("the fallback runs");
    assert_eq!(
        outcomes.len(),
        1,
        "a set that names something is a set, whatever it lost: {outcomes:?}"
    );
    assert!(
        outcomes[0].status.is_err(),
        "and it reports rather than being skipped: {:?}",
        outcomes[0].status
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Packet length and type at the head of `buf`, or `None` past the last
/// complete packet. The fixtures above are built by `par2_index`, so
/// the walk only has to be right about what that writes.
fn peek_packet(buf: &[u8]) -> Option<(usize, [u8; 16])> {
    if buf.len() < 64 || &buf[..8] != par2::MAGIC {
        return None;
    }
    let len = u64::from_le_bytes(buf[8..16].try_into().ok()?) as usize;
    if len < 64 || len > buf.len() {
        return None;
    }
    let mut ptype = [0u8; 16];
    ptype.copy_from_slice(&buf[48..64]);
    Some((len, ptype))
}
