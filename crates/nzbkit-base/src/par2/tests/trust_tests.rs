//! What a PAR2 set is TAKEN TO SAY when its own packets disagree.
//!
//! One subject, split out of `par2.rs`'s test module on 30 Aug 2026
//! under the size gate (TODO 106) - the file came out of a merge at
//! 3,210 raw lines with three lanes appending to it. A child of `tests`
//! rather than a sibling, reached by `#[path]`, so `use super::*` still
//! names that module's own packet builders (`pkt`, `main_ids`,
//! `desc_body`, `identity`) instead of a second copy of them.
//!
//! Every test here asks the same question from a different side. Two
//! individually valid packets contradicting each other must not resolve
//! to whichever the scanner reached first (W4-10); a descriptor Main
//! never mentioned is still a name (M4-64); and an IFSC entry that
//! disagrees with the FileDesc digest over the same bytes is an
//! unusable entry rather than a report of damage (M4-69).

use super::*;

/// W4-10. Two individually valid FileDesc packets under ONE set id and
/// ONE file id, contradicting each other about name, length and
/// digest. The set is malformed either way; what it must never do is
/// let the order the packets arrived in pick which fact is trusted.
///
/// Both arms in one test because the FINDING is the differential: an
/// arm that only checked "A,B drops the file" would still pass a
/// build that answered B,A with B's identity.
#[test]
fn contradictory_filedescs_are_dropped_in_either_order() {
    let set = [0x10u8; 16];
    let fid = [0x11u8; 16];
    let a = pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xAA, 1000, "A.bin"));
    let b = pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xBB, 2000, "B.bin"));
    let main = pkt(set, TYPE_MAIN, &main_ids(100, &[fid]));

    let cat = |first: &[u8], second: &[u8]| {
        let mut v = main.clone();
        v.extend_from_slice(first);
        v.extend_from_slice(second);
        v
    };
    let ab = identity(&Par2Set::parse(&[&cat(&a, &b)]));
    let ba = identity(&Par2Set::parse(&[&cat(&b, &a)]));
    assert_eq!(ab, ba, "packet order chose the trusted identity");
    assert_eq!(ab, "bs=100 files=[]", "the contradicted file is dropped");

    // The same split across two INPUTS - the shape a job actually
    // meets, one packet file off the wire and one off disk.
    let mut one = main.clone();
    one.extend_from_slice(&a);
    let across_a = identity(&Par2Set::parse(&[&one, &b]));
    let across_b = identity(&Par2Set::parse(&[&b, &one]));
    assert_eq!(across_a, across_b, "input-vector order chose it instead");
    assert_eq!(across_a, "bs=100 files=[]");

    // A repeat of the SAME descriptor is not a contradiction: packets
    // legitimately repeat across volumes, and re-padding the name
    // makes a different packet MD5 out of one descriptor.
    let mut padded = desc_body(fid, 0xAA, 1000, "A.bin");
    padded.extend_from_slice(&[0u8; 4]);
    let mut twice = main.clone();
    twice.extend_from_slice(&a);
    twice.extend_from_slice(&pkt(set, TYPE_FILEDESC, &padded));
    let set2 = Par2Set::parse(&[&twice]).expect("one descriptor, written twice");
    assert_eq!(set2.files.len(), 1);
    assert_eq!(set2.files[0].name, "A.bin");
}

/// W4-10, Main arm. Two valid Main packets with different block
/// sizes: the geometry every block checksum and every repair plan is
/// derived from cannot be settled by which one was read first, and
/// there is nothing to fall back to, so the set is refused.
#[test]
fn contradictory_main_packets_are_refused_in_either_order() {
    let set = [0x20u8; 16];
    let fid = [0x21u8; 16];
    let desc = pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xCC, 4000, "M.bin"));
    let m100 = pkt(set, TYPE_MAIN, &main_ids(100, &[fid]));
    let m400 = pkt(set, TYPE_MAIN, &main_ids(400, &[fid]));

    let cat = |first: &[u8], second: &[u8]| {
        let mut v = first.to_vec();
        v.extend_from_slice(second);
        v.extend_from_slice(&desc);
        v
    };
    let refused = |v: &[u8]| Par2Set::parse(&[v]).unwrap_err();
    assert_eq!(refused(&cat(&m100, &m400)), Par2Error::ContradictoryPackets);
    assert_eq!(refused(&cat(&m400, &m100)), Par2Error::ContradictoryPackets);
    // A third copy of either reading must not re-admit it.
    let mut three = cat(&m100, &m400);
    three.extend_from_slice(&m100);
    assert_eq!(refused(&three), Par2Error::ContradictoryPackets);
}

/// Two Unicode Filename packets under one file id that DISAGREE
/// annihilate, and the FileDesc's own spelling stands - the W4-10
/// rule (`Claim`) applied to the packet type M4-22 added, because
/// resolving them by whichever the scanner reached first is article
/// arrival order on the wire and packet-file order on disk, neither
/// of which is evidence about the post.
///
/// Driven in BOTH orders: a rule that resolves by order passes one of
/// them.
#[test]
fn contradictory_unicode_names_leave_the_filedesc_spelling() {
    for swap in [false, true] {
        let set_id = [17u8; 16];
        let fid = [9u8; 16];
        let mut buf = pkt(set_id, TYPE_MAIN, &main_ids(4, &[fid]));
        buf.extend(pkt(
            set_id,
            TYPE_FILEDESC,
            &desc_body(fid, 1, 1, "ascii.mkv"),
        ));
        let a = pkt(
            set_id,
            TYPE_UNIFILEN,
            &uni_body(fid, "Ünö.mkv", true, false),
        );
        let b = pkt(
            set_id,
            TYPE_UNIFILEN,
            &uni_body(fid, "Ünä.mkv", true, false),
        );
        if swap {
            buf.extend(b);
            buf.extend(a);
        } else {
            buf.extend(a);
            buf.extend(b);
        }
        let set = Par2Set::parse(&[&buf]).unwrap();
        assert_eq!(set.files[0].name, "ascii.mkv", "swap={swap}");
    }
}

/// Two Main packets that agree about everything repair is derived
/// from and disagree only about the NON-recovery members still
/// describe a usable set: the verify-only list annihilates on its own
/// and the set parses.
///
/// This is why `SetClaims::nonrec` is claimed apart from
/// `SetClaims::main` rather than folded into it. Folded, the same
/// input is a CONTRADICTED Main, which is fatal - so a post would
/// lose repair it can perform over a disagreement about files that
/// carry no parity, and it would lose it on input this build parsed
/// happily before the non-recovery list was read at all.
///
/// The control below is the other half: a disagreement about the
/// GEOMETRY is still fatal, so this is not the contradiction rule
/// being weakened.
///
/// Since M4-64 it is also the pin that the ORPHAN pass composes with
/// this rule instead of swallowing it. `x.nfo`'s descriptor survives
/// in `descs` after the annihilation, and a pass over "whatever is
/// left" would hand it straight back - so orphan harvesting is scoped
/// to ids NO Main packet mentioned (`SetClaims::mentioned`). Main
/// saying nothing is not Main contradicting itself.
#[test]
fn a_contradicted_nonrecovery_list_does_not_refuse_a_set_that_repairs() {
    let set_id = [18u8; 16];
    let rec = [10u8; 16];
    let (x, y) = ([11u8; 16], [12u8; 16]);
    let desc = pkt(set_id, TYPE_FILEDESC, &desc_body(rec, 1, 1, "a.bin"));
    let descx = pkt(set_id, TYPE_FILEDESC, &desc_body(x, 2, 1, "x.nfo"));
    let mut buf = pkt(set_id, TYPE_MAIN, &main_ids_nonrec(4, &[rec], &[x]));
    buf.extend(pkt(set_id, TYPE_MAIN, &main_ids_nonrec(4, &[rec], &[y])));
    buf.extend(desc.clone());
    buf.extend(descx.clone());
    let set = Par2Set::parse(&[&buf]).unwrap();
    assert_eq!(
        set.files
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        ["a.bin"],
        "the recovery set is untouched by the verify-only disagreement"
    );
    assert!(
        set.nonrecovery.is_empty(),
        "a contradicted verify-only list must annihilate, not pick one"
    );
    // Control: the SAME shape with the block size in disagreement is
    // still fatal, so the arm above is a narrower claim and not a
    // hole in the contradiction rule.
    let mut fatal = pkt(set_id, TYPE_MAIN, &main_ids_nonrec(4, &[rec], &[x]));
    fatal.extend(pkt(set_id, TYPE_MAIN, &main_ids_nonrec(8, &[rec], &[x])));
    fatal.extend(desc);
    fatal.extend(descx);
    assert_eq!(
        Par2Set::parse(&[&fatal]).err(),
        Some(Par2Error::ContradictoryPackets)
    );
}

/// M4-64 (30 Aug 2026): a well-formed FileDesc for a file id the Main
/// packet lists in NEITHER half. MultiPar and some rebuild tools emit
/// them; this parser walked Main's id lists and `descs.remove(&fid)`,
/// so an ORPHAN descriptor - a complete name, length and pair of
/// digests - was parsed and then dropped on the floor. An obfuscated
/// post whose only honest name sat in one stayed hashed.
///
/// The inverse of M4-21 (Main listing ids that are not recovery-set
/// members) and it takes M4-21's answer, because the EVIDENCE is the
/// same: a name plus a whole-file MD5, which nominates and is
/// finalized by content. `nonrecovery` and never `files` - that list
/// is the global slice index space repair lays exponents onto
/// positionally, and a member Main never counted has no slices in it.
///
/// Both packet ORDERS, because the finding is the differential: the
/// orphan pass reads a HashMap, so an arm that only checked one order
/// would pass a build whose answer moved with the hasher.
#[test]
fn a_filedesc_no_main_packet_lists_is_still_a_name() {
    let sid = [9u8; 16];
    let (a, orph1, orph2) = ([1u8; 16], [0xBBu8; 16], [0x22u8; 16]);
    let main = pkt(sid, TYPE_MAIN, &main_ids(4, &[a]));
    let d_a = pkt(sid, TYPE_FILEDESC, &desc_body(a, 0x11, 4, "A.bin"));
    let d_1 = pkt(sid, TYPE_FILEDESC, &desc_body(orph1, 0x33, 8, "Orphan.mkv"));
    let d_2 = pkt(sid, TYPE_FILEDESC, &desc_body(orph2, 0x44, 9, "Second.nfo"));
    for order in [[&main, &d_a, &d_1, &d_2], [&d_2, &d_1, &d_a, &main]] {
        let mut input = Vec::new();
        for part in order {
            input.extend_from_slice(part);
        }
        let set = Par2Set::parse(&[&input]).expect("parse");
        assert_eq!(
            set.files
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["A.bin"],
            "an orphan descriptor must never enter the slice index space"
        );
        assert_eq!(
            set.nonrecovery
                .iter()
                .map(|f| (f.name.as_str(), f.length))
                .collect::<Vec<_>>(),
            [("Second.nfo", 9), ("Orphan.mkv", 8)],
            "orphan FileDescs are a name source, in file-id order in \
                 either packet order"
        );
    }
}

/// The orphan pass may not resurrect a descriptor the set has already
/// spent or refused. Three shapes in one test, because each is a
/// different way the second walk over `descs` could double-count:
/// a recovery member (removed by the first walk), a declared
/// verify-only member (removed by the second), and a CONTRADICTED
/// descriptor, which W4-10 drops on purpose and which the orphan pass
/// must not offer a second time as if Main had never mentioned it.
#[test]
fn the_orphan_pass_never_doubles_a_descriptor_main_already_spent() {
    let sid = [9u8; 16];
    let (a, b, c) = ([1u8; 16], [2u8; 16], [3u8; 16]);
    let mut input = pkt(sid, TYPE_MAIN, &main_ids_nonrec(4, &[a], &[b, c]));
    input.extend(pkt(sid, TYPE_FILEDESC, &desc_body(a, 0x11, 4, "A.bin")));
    input.extend(pkt(sid, TYPE_FILEDESC, &desc_body(b, 0x22, 5, "B.nfo")));
    // Two readings of C: contradicted, so W4-10 drops it.
    input.extend(pkt(sid, TYPE_FILEDESC, &desc_body(c, 0x33, 6, "C.one")));
    input.extend(pkt(sid, TYPE_FILEDESC, &desc_body(c, 0x44, 7, "C.two")));
    let set = Par2Set::parse(&[&input]).expect("parse");
    assert_eq!(
        set.files
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        ["A.bin"]
    );
    assert_eq!(
        set.nonrecovery
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        ["B.nfo"],
        "a spent or contradicted descriptor must not come back as an orphan"
    );
}

/// M4-69 (30 Aug 2026): an IFSC entry carries a CRC32 and an MD5 of
/// the SAME block, so a file whose bytes satisfy one and not the
/// other has been handed an entry that describes two different
/// blocks. `verify_file_blocks` requires both, so a forged block MD5
/// turned a BYTE-EXACT file into 100% damage and the settle scan
/// printed `n/n blocks bad, md5 ok` in one breath - a full
/// reconstruct spent on intact bytes, or Unrepairable when the
/// parity fell short.
///
/// The FileDesc whole-file MD5 covers every byte of every block, so
/// when it matches it settles the question and no per-block claim may
/// outrank it. BOTH hostile directions, because either checksum can
/// be the forged one and the reverse (honest MD5, lying CRC) is the
/// one in-stream fast verify exists to miss until settle.
///
/// The CONTROL is the third arm and is what makes this a narrowing
/// rather than a hole: real damage still flags its block, because a
/// damaged file does not hash to the descriptor.
#[test]
fn a_whole_file_md5_outranks_an_ifsc_that_contradicts_it() {
    let bs = 16u64;
    let data: Vec<u8> = (0..48u8).collect();
    let honest: Vec<BlockCheck> = data
        .chunks(bs as usize)
        .map(|c| BlockCheck {
            md5: Md5::digest(c).into(),
            crc32: crc32fast::hash(c),
        })
        .collect();
    let file = |blocks: Vec<BlockCheck>| Par2File {
        file_id: [1u8; 16],
        name: "x.bin".into(),
        length: data.len() as u64,
        md5: Md5::digest(&data).into(),
        md5_16k: Md5::digest(&data).into(),
        blocks,
    };
    let lying_md5: Vec<BlockCheck> = honest
        .iter()
        .map(|b| BlockCheck {
            md5: [0xAB; 16],
            ..*b
        })
        .collect();
    let lying_crc: Vec<BlockCheck> = honest
        .iter()
        .map(|b| BlockCheck {
            crc32: b.crc32 ^ 0xDEAD_BEEF,
            ..*b
        })
        .collect();
    for (case, blocks) in [
        ("honest", honest.clone()),
        ("lying block MD5s", lying_md5),
        ("lying block CRCs", lying_crc),
    ] {
        let f = file(blocks);
        let v = verify_file(&f, bs, &data);
        assert!(v.md5_ok, "{case}: the file IS the described bytes");
        assert!(
            v.blocks.iter().all(|&ok| ok),
            "{case}: the whole-file MD5 covers every block, so no entry \
                 disagreeing with it may report damage"
        );
        // The streaming twin must not answer differently - a verdict
        // that moves with which reader ran is the defect W4-10 named.
        let sv = verify_file_streaming(&f, bs, &data[..]).expect("stream");
        assert_eq!(sv.blocks, v.blocks, "{case}: streaming twin diverged");
        assert_eq!(sv.md5_ok, v.md5_ok, "{case}: streaming md5_ok diverged");
        let seek =
            verify_file_seekable(&f, bs, std::io::Cursor::new(&data)).expect("seekable cursor");
        assert_eq!(seek.blocks, v.blocks, "{case}: seekable twin diverged");
        assert_eq!(seek.md5_ok, v.md5_ok, "{case}: seekable md5_ok diverged");
    }
    // Control: an honest set over DAMAGED bytes still flags exactly
    // the damaged block, so this is the strongest evidence winning
    // and not the block check being switched off.
    let mut broken = data.clone();
    broken[20] ^= 0xff;
    let f = file(honest);
    let v = verify_file(&f, bs, &broken);
    assert!(!v.md5_ok);
    assert_eq!(v.blocks, [true, false, true], "only block 1 is damaged");
    assert_eq!(
        verify_file_streaming(&f, bs, &broken[..])
            .expect("stream")
            .blocks,
        v.blocks
    );
    assert_eq!(
        verify_file_seekable(&f, bs, std::io::Cursor::new(&broken))
            .expect("seekable cursor")
            .blocks,
        v.blocks
    );
}
