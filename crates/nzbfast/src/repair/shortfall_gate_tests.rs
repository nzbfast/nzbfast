//! Follow-up 13a: the third arm of [`super::shortfall_is_final`], which
//! decides whether a recovery-block shortfall is final for a set whose
//! files are all CLAIMED - renamed to the names the set declares, so
//! [`super::adoption_candidates_present`] excludes every one of them,
//! their bytes being their own descriptors' (follow-up 13a-3 made that
//! last clause do real work: a declared name is no longer proof on its
//! own, and the last case here is what it is worth instead).
//!
//! Its own file rather than a block in `repair_tests.rs`, which sat at
//! 2,939 of the size gate's 3,000-line ceiling when this subject came
//! out - the same reason `ladder_tests`, `side_fetch_tests`,
//! `unpackprog_tests` and `vol_affinity_tests` are each out here.
//!
//! What is NOT pinned here is the payoff, because no in-memory case can
//! show it: that the engine really does lift those blocks across is
//! `e2e_norar`'s `a_claimed_twin_donates_the_shared_head_it_declares_twice`,
//! and the arithmetic behind the predicate is written up at its own
//! header. These cases pin the DECISION and its cost - that the arm
//! stays silent on a set with nothing declared twice, which is the
//! measured shape of every ordinary post.

use super::*;
use nzbkit::par2::{BlockCheck, Par2File, Par2Set};

/// A scratch directory of this test's own. Named for the case rather
/// than for the process, because these run in one process alongside
/// ~1750 others and a pid-only name is one directory two cases share.
fn scratch(tag: &str) -> crate::testscratch::ScratchDir {
    let d = std::env::temp_dir().join(format!("nzbfast-shortfall-{tag}-{}", std::process::id()));
    crate::testscratch::ScratchDir::attach(&d)
}

fn blk(n: u8) -> BlockCheck {
    BlockCheck {
        md5: [n; 16],
        crc32: u32::from(n),
    }
}

fn pfile(name: &str, blocks: Vec<BlockCheck>) -> Par2File {
    Par2File {
        file_id: [1u8; 16],
        name: name.to_string(),
        length: 200_000,
        md5: [0u8; 16],
        md5_16k: [0u8; 16],
        blocks,
    }
}

fn pset(files: Vec<Par2File>) -> Par2Set {
    Par2Set {
        recovery_set_id: [0u8; 16],
        block_size: 2000,
        files,
        nonrecovery: Vec::new(),
        recovery_blocks_seen: 0,
    }
}

/// Both members on disk under the names the set declares, and the set
/// declares FOUR blocks twice - a shared run, which is what an
/// identical-head twin group is, reduced to the only facts the
/// predicate reads. Four rather than one because the count is now
/// weighed against the shortfall, so a one-block fixture can only ever
/// exercise a one-block gap.
fn twin_dir(dir: &std::path::Path, shared: bool) -> Par2Set {
    for n in ["Alpha.vob", "Beta.vob"] {
        std::fs::write(dir.join(n), b"payload").unwrap();
    }
    let a = vec![blk(1), blk(2), blk(7), blk(8), blk(9), blk(10)];
    let b = if shared {
        vec![blk(3), blk(7), blk(8), blk(9), blk(10)]
    } else {
        vec![blk(3), blk(11), blk(12), blk(13), blk(14)]
    };
    pset(vec![pfile("Alpha.vob", a), pfile("Beta.vob", b)])
}

#[test]
fn a_set_that_declares_a_block_twice_is_worth_scanning_even_with_every_file_claimed() {
    let d = scratch("shared");
    let set = twin_dir(&d, true);
    // The premise: nothing here is an ordinary adoption candidate.
    assert!(
        !adoption_candidates_present(&d, &set),
        "both members carry declared names - the F7/F9 arm must not fire"
    );
    assert!(
        repeated_block_donor_possible(&d, &set, 1),
        "a block the set declares twice is a block the escalation can lift \
         out of whichever copy survived"
    );
    assert!(
        !shortfall_is_final(30, 26, &[], &d, &set, &[]),
        "the shortfall must fall through to the repair engines"
    );
}

#[test]
fn a_set_with_nothing_declared_twice_still_gives_up_without_buying_recovery() {
    let d = scratch("distinct");
    let set = twin_dir(&d, false);
    assert!(
        !repeated_block_donor_possible(&d, &set, 1),
        "no two blocks share content, so no aligned donation is possible \
         and a recovery fetch would buy nothing"
    );
    assert!(
        shortfall_is_final(30, 26, &[], &d, &set, &[]),
        "the ordinary unrepairable post must keep the verdict it always had"
    );
}

#[test]
fn a_repeat_inside_one_file_counts_and_an_empty_ifsc_cannot_argue_for_a_fetch() {
    let d = scratch("selfrepeat");
    std::fs::write(d.join("Alpha.vob"), b"payload").unwrap();
    // Self-donation: one file, one block content twice. A run of zeros
    // long enough to span two blocks is exactly this shape.
    let one = pset(vec![pfile("Alpha.vob", vec![blk(5), blk(9), blk(5)])]);
    assert!(repeated_block_donor_possible(&d, &one, 1));
    // No IFSC packet survived parsing, so the set says nothing about its
    // own block contents - and silence must never buy a fetch.
    let none = pset(vec![pfile("Alpha.vob", Vec::new())]);
    assert!(!repeated_block_donor_possible(&d, &none, 1));
}

#[test]
fn a_set_whose_members_never_reached_disk_has_no_donor_to_scan() {
    let d = scratch("nofiles");
    let set = pset(vec![
        pfile("Alpha.vob", vec![blk(7)]),
        pfile("Beta.vob", vec![blk(7)]),
    ]);
    assert!(
        !repeated_block_donor_possible(&d, &set, 1),
        "the escalation reads FILES - an empty directory has nothing to lift from"
    );
    // A zero-length member is the same nothing, spelled differently.
    std::fs::write(d.join("Alpha.vob"), b"").unwrap();
    assert!(!repeated_block_donor_possible(&d, &set, 1));
    std::fs::write(d.join("Alpha.vob"), b"x").unwrap();
    assert!(repeated_block_donor_possible(&d, &set, 1));
}

/// Read-only sweep finding 3 (31 Aug 2026): a set that names its members
/// with a TREE - the disc shape `VIDEO_TS/VTS_01_1.VOB` that
/// `sanitize_out_name` preserves - has its members on disk one directory
/// down, and this gate has to see them.
///
/// It walked `read_dir(out_dir)` and compared BASENAMES, so the walk saw
/// one DIRECTORY entry, `is_file()` dropped it, `any_member` was false
/// and the escalation never ran with every block sitting right there.
/// The engine's own present-set gate resolves a FileDesc name through
/// `join_out_name` onto the job directory, on the rule that "a FileDesc
/// name is relative to the JOB"; this now asks the same question the
/// same way.
///
/// The control is the flat case one level up: a file wearing only the
/// LEAF name at the top level is NOT this set's member, and must not
/// arm the escalation on its own.
#[test]
fn a_set_that_names_a_tree_finds_its_members_one_directory_down() {
    let d = scratch("treedonor");
    let set = pset(vec![pfile(
        "VIDEO_TS/VTS_01_1.VOB",
        vec![blk(5), blk(9), blk(5)],
    )]);
    assert!(
        !repeated_block_donor_possible(&d, &set, 1),
        "nothing on disk yet - the escalation reads FILES"
    );
    // The leaf alone, at the top level: not this set's member.
    std::fs::write(d.join("VTS_01_1.VOB"), b"payload").unwrap();
    assert!(
        !repeated_block_donor_possible(&d, &set, 1),
        "a bare leaf at the top level is not the member the set declares"
    );
    // The member where the set actually says it is.
    std::fs::create_dir_all(d.join("VIDEO_TS")).unwrap();
    std::fs::write(d.join("VIDEO_TS").join("VTS_01_1.VOB"), b"payload").unwrap();
    assert!(
        repeated_block_donor_possible(&d, &set, 1),
        "the member is on disk under the name the set declares - a basename \
         walk cannot see it and answers a false no"
    );
}

/// The F7/F9 arm this one sits beside, pinned here because the three
/// are now ONE chain and a case that only exercises the third leaves
/// the second free to be deleted (measured: it survived until this
/// case existed).
#[test]
fn an_unclaimed_file_still_falls_through_on_a_set_that_repeats_nothing() {
    let d = scratch("unclaimed");
    let set = twin_dir(&d, false);
    std::fs::write(d.join("Rk8vQm31Zx7"), b"the hash-named leftover").unwrap();
    assert!(
        !repeated_block_donor_possible(&d, &set, 1),
        "the third arm must be silent, or this case proves nothing"
    );
    assert!(!shortfall_is_final(30, 26, &[], &d, &set, &[]));
}

/// The count is an UPPER BOUND on aligned donation, so a shortfall
/// wider than the set can possibly close must not buy the fetch -
/// which is the arm that stops the ordinary
/// "one volume wholly missing" job paying for an answer arithmetic has
/// already given (measured: 38 repeats against a 376-block gap).
#[test]
fn a_gap_wider_than_the_set_can_close_is_still_final() {
    let d = scratch("gap");
    let set = twin_dir(&d, true);
    // Four repeats are declared, so a four-block gap is worth a look...
    assert!(repeated_block_donor_possible(&d, &set, 4));
    // ...and a five-block one is not: donation can supply at most four,
    // so the fetch would be bought for an answer arithmetic has given.
    assert!(!repeated_block_donor_possible(&d, &set, 5));
    assert!(shortfall_is_final(31, 26, &[], &d, &set, &[]));
    assert!(!shortfall_is_final(30, 26, &[], &d, &set, &[]));
    // A closed shortfall is not this arm's business either.
    assert!(!repeated_block_donor_possible(&d, &set, 0));
}

#[test]
fn a_donor_directory_still_overrules_both_arms() {
    let d = scratch("donor");
    let set = twin_dir(&d, false);
    let donors = [d.to_path_buf()];
    assert!(
        !shortfall_is_final(30, 26, &donors, &d, &set, &[]),
        "§293's donor road is never final, whatever the set declares"
    );
}

/// Follow-up 13a-3: what a DECLARED NAME is now worth to
/// [`super::adoption_candidates_present`], which until 31 Aug 2026 took
/// it as proof the file was the set's own and skipped it unread.
///
/// Three states, and the gate has to tell them apart. The length screen
/// comes first and is free; only past it is the bounded per-block probe
/// asked, and only a POSITIVE DENIAL - blocks were read and none of
/// them is this descriptor's - lets the file through. The fake
/// checksums in `blk` match no real bytes, so any block this reads is a
/// miss, which is exactly the "carries none of that file's bytes" side
/// of the question; the other side is measured end to end in
/// `e2e_norar::shiftname`, where the blocks are real and the file comes
/// back byte-exact.
#[test]
fn a_declared_name_is_judged_on_its_bytes_and_not_on_its_name() {
    let d = scratch("declaredname");
    let set = pset(vec![pfile("Alpha.vob", vec![blk(1), blk(2), blk(3)])]);
    // (a) WRONG LENGTH, and readable: every probed block is read and
    // none is the descriptor's, which is the shifted/foreign shape and
    // is an ordinary adoption candidate to the engine.
    std::fs::write(d.join("Alpha.vob"), vec![7u8; 210_000]).unwrap();
    assert!(
        adoption_candidates_present(&d, &set),
        "a file the set's own IFSC denies is one the sliding scan must be \
         allowed to read, whatever name it wears"
    );
    // (b) WRONG LENGTH, and nothing of it can be read - every article
    // of the member failed. Silence is not a denial (`settle_binding`'s
    // rule), so the name still stands and the file stays excluded.
    std::fs::write(d.join("Alpha.vob"), b"tiny").unwrap();
    assert!(
        !adoption_candidates_present(&d, &set),
        "a member whose bytes cannot be read denies nothing - reading that \
         as a denial makes every unreadable member buy a recovery fetch"
    );
    // (c) THE DECLARED LENGTH: not probed at all. The stated limit of
    // the screen, pinned here so widening it is a decision somebody
    // makes rather than a regression - see the gate's own header for
    // what paying the probe on every full-length member would cost.
    std::fs::write(d.join("Alpha.vob"), vec![7u8; 200_000]).unwrap();
    assert!(
        !adoption_candidates_present(&d, &set),
        "a full-length member is held out before the probe - if this fell \
         through, the length screen is gone"
    );
}

/// Follow-up 13a-4: the fourth state, and the one the three above could
/// not tell from state (c) - WRONG LENGTH with a block that MATCHES.
///
/// That is a mid-file insertion: the head still verifies, so the member
/// is IDENTIFIED, and the rest of its content is byte-shifted inside
/// itself, so it is DAMAGED. It is the exact target
/// `par2repair::repair_dir_set_inner`'s last-resort escalation appends
/// to the scan, and until 31 Aug 2026 this gate excluded it on the hit
/// alone - so on the get path, with parity short, the escalation
/// written for that file was never reached.
///
/// The descriptor's block 0 is the REAL digest of the file's first
/// block, built exactly as `live::blockcheck::block_digest` does, so
/// the probe genuinely hits rather than being assumed to; blocks 1 and
/// 2 are fake and match nothing, which is the damaged tail. `e2e_norar`
/// `::shiftname` is where the same shape is driven end to end and the
/// file comes back byte-exact.
#[test]
fn a_wrong_length_member_whose_head_still_verifies_is_not_intact() {
    use md5::Digest as _;
    let d = scratch("midfileinsert");
    // Block 0 as it will really be read: 2,000 bytes at offset 0.
    let head = vec![7u8; 2_000];
    let real0 = BlockCheck {
        md5: md5::Md5::digest(&head).into(),
        crc32: crc32fast::hash(&head),
    };
    let set = pset(vec![pfile("Alpha.vob", vec![real0, blk(2), blk(3)])]);
    std::fs::write(d.join("Alpha.vob"), vec![7u8; 210_000]).unwrap();
    assert!(
        adoption_candidates_present(&d, &set),
        "a matched block past the length screen cannot mean INTACT - only \
         identified and damaged, which is what the engine's escalation \
         scans. Excluding on the hit alone keeps the get path from the \
         one shape that escalation exists for"
    );
    // And the screen still outranks it: the same match at the DECLARED
    // length is the ordinary damaged member and stays out, so this is a
    // widening of the hit rule and not a hole in the screen.
    std::fs::write(d.join("Alpha.vob"), vec![7u8; 200_000]).unwrap();
    assert!(
        !adoption_candidates_present(&d, &set),
        "the length screen still runs first - if this fell through, the \
         widening took the screen with it"
    );
}
// ---------------------------------------------------------------------
// Follow-up 13a-1: [`super::adoption_narrowed_need`], the reorder that
// lets the adoption scan look BEFORE the recovery volumes are bought.
//
// These are in-memory because the decision is, and the engine is
// injected as a closure for exactly that reason. What no in-memory case
// can show is the payoff - that is `e2e_norar`'s
// `a_filedesc_naming_the_join_of_posted_halves_assembles` (buys nothing
// at all) and `a_claimed_twin_donates_the_shared_head_it_declares_twice`
// (buys 20 blocks instead of 26), and the pricing behind the whole
// reorder is `research/ADOPT-SCAN-ORDER-2026-08-31.md`.
//
// The SUBTRACTION is what these exist for. The engine reports its TOTAL
// post-adoption missing count next to what it already holds on disk;
// this caller's `needed` is ADDITIONAL, net of the same volumes. No e2e
// row on the tree runs with recovery already on disk AND a shortfall, so
// the wrong and right forms agree in every one of them - which is how a
// version that declares a buyable post unrepairable would have shipped.

/// The whole point: a scan that closes the gap means no fetch at all.
#[test]
fn a_scan_that_repairs_the_set_buys_nothing() {
    let out = adoption_narrowed_need(171, 34, &[], &|_| NativeVerdict::Done);
    assert!(
        matches!(out, NarrowedNeed::Repaired),
        "a probe that repaired the set must not go on to buy recovery"
    );
}

/// The partial arm: buy what the scan LEFT, not what the ledger said.
#[test]
fn a_partial_scan_narrows_the_buy_to_what_is_left() {
    let out = adoption_narrowed_need(171, 103, &[], &|_| NativeVerdict::NoRecovery {
        needed: 69,
        have: 0,
    });
    assert!(matches!(out, NarrowedNeed::Buy(69)), "{out:?}");
}

/// The bail arm, which is where four of the five priced fixtures land:
/// nothing the NZB still has to sell can close the post-adoption gap, so
/// the old order's whole-declared-set purchase buys a failure.
#[test]
fn a_gap_the_remaining_volumes_cannot_close_buys_nothing() {
    let out = adoption_narrowed_need(171, 34, &[], &|_| NativeVerdict::NoRecovery {
        needed: 120,
        have: 0,
    });
    assert!(
        matches!(out, NarrowedNeed::Final { needed: 120 }),
        "{out:?} - and the figure must be the POST-adoption 120, not the \
         ledger's 171: it is what the job's fail message states"
    );
}

/// THE TRAP. `have: 12` is recovery already on disk - a bootstrap,
/// sniffed or resume-recognised volume, which is the ordinary case - and
/// the engine's `needed` counts it. Subtract and 8 more blocks close the
/// job; compare raw and a post with 10 buyable blocks is told it is
/// unrepairable.
#[test]
fn on_disk_recovery_is_subtracted_before_the_engine_is_compared() {
    let engine = |_: bool| NativeVerdict::NoRecovery {
        needed: 20,
        have: 12,
    };
    let out = adoption_narrowed_need(30, 10, &[], &engine);
    assert!(
        matches!(out, NarrowedNeed::Buy(8)),
        "{out:?} - 20 total minus 12 on disk is 8 more to buy, and 8 is \
         inside the 10 still for sale"
    );
    // ...and one block further out it is genuinely final.
    let engine = |_: bool| NativeVerdict::NoRecovery {
        needed: 20,
        have: 9,
    };
    assert!(
        matches!(
            adoption_narrowed_need(30, 10, &[], &engine),
            NarrowedNeed::Final { needed: 11 }
        ),
        "11 more against 10 for sale is final"
    );
}

/// The "covered N of M" line subtracts, so it is worth saying WHY it
/// cannot underflow rather than leaving the guard looking defensive.
/// The probe only runs where `needed > have`, and the Buy arm only
/// returns where `extra <= have`, so on that arm `extra < needed`
/// holds by construction - an engine that wants MORE than the ledger
/// did lands on `Final` instead and never reaches the subtraction.
/// Both halves of that are pinned here, at the exact boundary.
#[test]
fn the_widest_buy_the_probe_can_authorise_is_the_whole_remainder() {
    // extra == have exactly: the widest narrowing that is still a buy.
    let out = adoption_narrowed_need(30, 10, &[], &|_| NativeVerdict::NoRecovery {
        needed: 10,
        have: 0,
    });
    assert!(matches!(out, NarrowedNeed::Buy(10)), "{out:?}");
    // One block past it is the bail, not a wider buy.
    let out = adoption_narrowed_need(30, 10, &[], &|_| NativeVerdict::NoRecovery {
        needed: 11,
        have: 0,
    });
    assert!(matches!(out, NarrowedNeed::Final { needed: 11 }), "{out:?}");
}

/// Three ways the probe must NOT run, each for its own reason.
#[test]
fn the_probe_stays_out_of_the_three_places_it_does_not_belong() {
    let ran = std::cell::Cell::new(false);
    let engine = |_: bool| {
        ran.set(true);
        NativeVerdict::Done
    };
    // 1. The NZB declares enough: the fetch is already right-sized and
    //    probing would tax every ordinary repair.
    assert!(matches!(
        adoption_narrowed_need(30, 30, &[], &engine),
        NarrowedNeed::Buy(30)
    ));
    assert!(matches!(
        adoption_narrowed_need(30, 40, &[], &engine),
        NarrowedNeed::Buy(30)
    ));
    // 2. A declined mapped attempt banked volumes: narrowing `needed`
    //    breaks the reuse comparison and re-buys what is on disk.
    assert!(matches!(
        adoption_narrowed_need(30, 10, &[7], &engine),
        NarrowedNeed::Buy(30)
    ));
    assert!(!ran.get(), "the probe ran where it must not");
    // 3. No native engine to ask (NZBFAST_NO_NATIVE_REPAIR, or an
    //    engine error): par2cmdline adopts too, but its exit code
    //    cannot say how many blocks it found, so the old order stands.
    assert!(matches!(
        adoption_narrowed_need(30, 10, &[], &|_| NativeVerdict::Backstop),
        NarrowedNeed::Buy(30)
    ));
}

/// The probe is asked AS a probe, so `native_shortfall` picks the
/// wording that fits a pass running before anything has been bought.
#[test]
fn the_engine_is_told_it_is_a_probe() {
    let seen = std::cell::Cell::new(None);
    let engine = |p: bool| {
        seen.set(Some(p));
        NativeVerdict::NoRecovery { needed: 5, have: 0 }
    };
    let _ = adoption_narrowed_need(30, 10, &[], &engine);
    assert_eq!(seen.get(), Some(true));
}

/// The shortfall clause reports HOW MANY blocks adoption found and
/// never WHERE, because two of the three writers into that count read
/// files the set declares. Pinned as an exact string: the defect this
/// replaces was a location claim that read perfectly well and was
/// simply false, so a shape assertion would have passed on it. See
/// [`super::adopted_clause`] for the whole argument, and
/// `e2e_norar`'s `a_claimed_twin_donates_the_shared_head_it_declares_twice`
/// for the in-set donation that showed the old wording lying.
#[test]
fn the_adopted_clause_counts_without_claiming_a_place() {
    assert_eq!(
        super::adopted_clause(10),
        " (adoption already found 10 of them in files already on disk)"
    );
    assert!(
        !super::adopted_clause(10).contains("outside"),
        "the clause must not claim the blocks came from outside the set - \
         harvest_in_set and the damaged-target escalation both read the \
         set's own files into the same count"
    );
    // The everyday line is unchanged when nothing was adopted.
    assert_eq!(super::adopted_clause(0), "");
}

/// The FOURTH arm ([`super::whole_file_md5_refutes_the_grid`]): a
/// member on disk at its declared length whose whole-file MD5 matches
/// is a member the block grid is provably wrong about, so the
/// arithmetic built on that grid is not final.
///
/// The bytes are real here, unlike everywhere else in this file: the
/// whole point is a digest that the file on disk actually satisfies,
/// and `blk` checksums that match nothing are what stands in for the
/// forged IFSC. That is the M4-69 mirror shape reduced to the only
/// facts the predicate reads - the grid says damaged, the descriptor
/// says intact.
fn md5_dir(dir: &std::path::Path, bytes: &[u8], honest_digest: bool) -> Par2Set {
    std::fs::write(dir.join("Alpha.vob"), bytes).unwrap();
    let md5: [u8; 16] = <md5::Md5 as md5::Digest>::digest(bytes).into();
    let head = &bytes[..bytes.len().min(16384)];
    let md5_16k: [u8; 16] = <md5::Md5 as md5::Digest>::digest(head).into();
    pset(vec![Par2File {
        file_id: [1u8; 16],
        name: "Alpha.vob".to_string(),
        length: bytes.len() as u64,
        md5: if honest_digest { md5 } else { [0xABu8; 16] },
        md5_16k,
        // A grid that calls every block bad, matching nothing on disk.
        blocks: vec![blk(1), blk(2), blk(3)],
    }])
}

#[test]
fn a_descriptor_that_proves_the_damaged_member_intact_is_not_a_final_shortfall() {
    let d = scratch("md5refute");
    let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let set = md5_dir(&d, &bytes, true);
    let damaged = vec!["alpha.vob".to_string()];
    // The premise: no cheaper arm answers, so a verdict here is this
    // arm's own. Without this the case could pass for another arm's
    // reason, which is how the 30 Aug fixture passed while the defect
    // was live.
    assert!(
        !adoption_candidates_present(&d, &set),
        "a full-length declared member is held out before the probe"
    );
    assert!(
        !repeated_block_donor_possible(&d, &set, 1),
        "nothing is declared twice, so the third arm must not answer"
    );
    assert!(
        whole_file_md5_refutes_the_grid(&d, &set, &damaged),
        "the whole-file MD5 covers every byte of every block and matches - \
         no per-block claim may outrank it"
    );
    assert!(
        !shortfall_is_final(30, 26, &[], &d, &set, &damaged),
        "the shortfall must fall through to the repair engine, which \
         arbitrates from disk"
    );
}

#[test]
fn the_fourth_arm_never_launders_real_damage() {
    let d = scratch("md5real");
    let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let damaged = vec!["alpha.vob".to_string()];
    // (a) The digest DISAGREES with the bytes: ordinary damage, and the
    // rule is "the whole-file MD5 outranks the entries", never "a
    // failing block is ignored".
    let set = md5_dir(&d, &bytes, false);
    assert!(
        !whole_file_md5_refutes_the_grid(&d, &set, &damaged),
        "a member the descriptor does not vouch for refutes nothing"
    );
    assert!(
        shortfall_is_final(30, 26, &[], &d, &set, &damaged),
        "the ordinary unrepairable post must keep the verdict it always had"
    );
    // (b) NOTHING IS CLAIMED DAMAGED: a shortfall made of files that
    // are not there is arithmetic no digest on disk can argue with.
    let honest = md5_dir(&d, &bytes, true);
    assert!(
        !whole_file_md5_refutes_the_grid(&d, &honest, &[]),
        "with no damage claim named there is nothing here to contradict"
    );
    assert!(
        shortfall_is_final(30, 26, &[], &d, &honest, &[]),
        "an empty damage list must not turn into a fall-through"
    );
    // (c) THE DAMAGED MEMBER IS NOT WHOLE. `md5_matches` re-checks the
    // length itself, so this case is answered twice over and cannot
    // tell which guard spoke - the `stat` screen's own job is pinned
    // separately below, where only it can answer.
    std::fs::write(d.join("Alpha.vob"), &bytes[..1000]).unwrap();
    assert!(
        !whole_file_md5_refutes_the_grid(&d, &honest, &damaged),
        "a member short of its declared length refutes nothing"
    );
    // (d) THE DAMAGED MEMBER IS NOT THERE AT ALL - the §282 shape.
    std::fs::remove_file(d.join("Alpha.vob")).unwrap();
    assert!(
        !whole_file_md5_refutes_the_grid(&d, &honest, &damaged),
        "a member that never landed cannot be vouched for by anything"
    );
}

/// The `stat` screen's own job, which is the ONE thing the whole-file
/// hash cannot do: it reads every member of the set, and the hash only
/// ever reads the ones the grid names.
///
/// So a set whose damaged member is byte-exact while a DIFFERENT member
/// never landed has real work no digest can argue away - and without
/// this screen the arm would fall through on it, having hashed only the
/// intact one. Written as its own case because the cases above are
/// answered twice over by `md5_matches`, which re-checks the length and
/// fails on a missing file, so removing the screen leaves every one of
/// them green (measured 31 Aug 2026: it did).
#[test]
fn a_member_the_grid_says_nothing_about_can_still_be_missing() {
    let d = scratch("md5sibling");
    let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut set = md5_dir(&d, &bytes, true);
    let damaged = vec!["alpha.vob".to_string()];
    // The control: one member, intact, named damaged - this DOES refute.
    assert!(
        whole_file_md5_refutes_the_grid(&d, &set, &damaged),
        "the one-member fixture must refute, or the case below proves nothing"
    );
    // Now a SECOND member the grid says nothing about, and which never
    // reached disk. The shortfall is partly about bytes that are not
    // there, and `Alpha.vob`'s descriptor cannot speak for them.
    set.files.push(pfile("Beta.vob", vec![blk(4), blk(5)]));
    assert!(
        !whole_file_md5_refutes_the_grid(&d, &set, &damaged),
        "a member that never landed is real work - and it is unnamed by the \
         damage claim, so only the stat walk over every member can see it"
    );
    assert!(
        shortfall_is_final(30, 26, &[], &d, &set, &damaged),
        "and the shortfall stays final"
    );
}

/// A name in `damaged` that is not this set's own settles nothing, and
/// a set whose OWN damaged member is not named is not refuted either.
/// The permissive direction is stated at the function's own header; this
/// pins that it is the only direction available.
#[test]
fn the_fourth_arm_reads_only_names_this_set_declares() {
    let d = scratch("md5names");
    let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let set = md5_dir(&d, &bytes, true);
    assert!(
        !whole_file_md5_refutes_the_grid(&d, &set, &["beta.vob".to_string()]),
        "a damage claim against another set's file is not this set's to refute"
    );
    assert!(
        whole_file_md5_refutes_the_grid(&d, &set, &["alpha.vob".to_string()]),
        "the same fixture with this set's own name IS refuted - so the case \
         above failed on the name and not on the fixture"
    );
}

/// Wave-4 row M4-52 at the GATE, the third seam of that row and the one
/// in FRONT of the other two.
///
/// [`super::adoption_candidates_present`] screened the recovery
/// extension on the NAME alone until 31 Aug 2026, while the engine it
/// predicts - `par2repair::is_recovery_by_name_and_content`, the
/// predicate this now calls rather than re-spells - has opened the file
/// and let the packet magic decide since the row landed. The row's own
/// composition is the first case below: an obfuscated payload posted
/// under a `<hash>` name wearing the recovery extension, which no set
/// in the stream claims. Every entry hit the extension screen, this
/// answered NO, and a NO here is an arm of
/// [`super::shortfall_is_final`] - so the job took the give-up branch
/// without `adoption_narrowed_need` ever probing for the bytes lying in
/// the same directory.
///
/// Four states, because the screen has to tell them apart and only the
/// first is the defect. The last two are the parts a widening could
/// silently take with it: a real volume must STILL be skipped, or this
/// gate hands the engine its own parity as an adoption source, and an
/// unreadable name must keep the historical answer, because a candidate
/// that cannot be opened is no donor either way. That fallback is the
/// engine's, asserted here so the two are pinned to agree.
#[test]
fn a_recovery_name_is_judged_on_its_bytes_and_not_on_its_extension() {
    let d = scratch("recoveryname");
    let set = pset(vec![pfile("movie.mkv", vec![blk(1), blk(2), blk(3)])]);
    let volume = {
        let mut v = Vec::from(*nzbkit::par2::MAGIC);
        v.resize(4_096, 0u8);
        v
    };
    // (a) THE ROW: a payload wearing the extension and carrying no
    // packet magic, as the directory's only candidate.
    let payload = d.join("9f3a1c40b2.par2");
    std::fs::write(&payload, vec![7u8; 210_000]).unwrap();
    assert!(
        adoption_candidates_present(&d, &set),
        "M4-52: the name NOMINATES and the content decides. A file the \
         magic denies is one the engine will offer to the sliding scan, \
         so answering NO here gives the job up with the bytes on disk"
    );
    // (b) And the mixed shape the row really produces - the payload
    // beside the set's own volumes, which is what a failing repair
    // directory holds.
    std::fs::write(d.join("post.vol000+01.par2"), &volume).unwrap();
    std::fs::write(d.join("post.vol001+02.par2"), &volume).unwrap();
    assert!(
        adoption_candidates_present(&d, &set),
        "real volumes beside the payload must not hide it"
    );
    // (c) The volumes ALONE are still this directory's own recovery
    // data and still buy nothing - the widening must not turn the
    // set's parity into an adoption source.
    std::fs::remove_file(&payload).unwrap();
    assert!(
        !adoption_candidates_present(&d, &set),
        "a file that opens with the packet magic is the set's own parity; \
         if this fires, every failing repair buys a scan of its own volumes"
    );
    // (d) Too short to carry the magic, so the answer cannot be
    // denied and the historical one stands. This was `read_exact` of
    // eight bytes FAILING until the window landed (see case (e)); it is
    // now an explicit short-read arm, and it has to be, because a
    // 72-byte read of a 4-byte file SUCCEEDS.
    std::fs::write(d.join("truncated.par2"), b"PAR2").unwrap();
    assert!(
        !adoption_candidates_present(&d, &set),
        "a name whose head cannot be read denies nothing - reading that as \
         a payload makes every truncated volume buy an adoption scan"
    );
    // (e) The claim `adopt-sniff-window-outlier` (31 Aug 2026): a
    // volume behind a UTF-8 BOM is STILL the set's own parity. Row
    // M4-65 widened the product's content sniff to "the magic begins
    // within `par2::SNIFF_WINDOW`" and this seam's predicate stayed at
    // byte 0, so the same bytes were recovery data to every other
    // reader in the repair and a payload here. Measured before the fix:
    // `head_is_packet_file` true, the predicate false, this gate TRUE -
    // and a real `repair_dir` over the same shape named the set's own
    // `vol000+01` in `adopted_from`. It is case (c) with a prefix, so it
    // must answer exactly as case (c) does.
    std::fs::remove_file(d.join("truncated.par2")).unwrap();
    std::fs::remove_file(d.join("post.vol000+01.par2")).unwrap();
    std::fs::remove_file(d.join("post.vol001+02.par2")).unwrap();
    std::fs::write(d.join("bom.vol000+01.par2"), {
        let mut v = vec![0xEFu8, 0xBB, 0xBF];
        v.extend_from_slice(&volume);
        v
    })
    .unwrap();
    assert!(
        !adoption_candidates_present(&d, &set),
        "a BOM in front of the magic does not turn a volume into a payload; \
         if this fires, every failing repair with a prefixed volume buys an \
         adoption scan of its own parity and names it in `adopted_from`"
    );
}

/// The DOT half of the same screen, which is deliberately still
/// narrower than the engine - `adoption_candidates` has no dot test at
/// all - and is a different question from the one above.
///
/// This gate predicts the engine's OUTCOME rather than its candidate
/// list. The dotted files a download directory really holds are the
/// ones this daemon did not write: its own journal and `.nzbfast-*`
/// scratch, and the OS's furniture. The engine would take those as
/// candidates and slide-scan them to no effect, so skipping them
/// predicts the right answer for nothing - where skipping a payload on
/// its extension predicted the wrong one.
///
/// What makes it sound belongs to `nzbkit::disk::sanitize_out_name`,
/// which maps a leading dot to `_` (row M4-66), so no name this job can
/// publish reaches disk wearing one. `get::latesets`'
/// `the_dot_skip_is_sound_only_while_nothing_we_publish_can_be_dotted`
/// is the interlock for that property and carries the fix for this seam
/// too: if a leading dot is ever let through, skip the names WE write
/// rather than every dotted name.
#[test]
fn the_dot_screen_stays_a_name_test_and_says_why() {
    let d = scratch("dotscreen");
    let set = pset(vec![pfile("movie.mkv", vec![blk(1), blk(2), blk(3)])]);
    std::fs::write(d.join(".DS_Store"), vec![7u8; 210_000]).unwrap();
    std::fs::write(d.join(".nzbfast.journal"), vec![7u8; 4_096]).unwrap();
    assert!(
        !adoption_candidates_present(&d, &set),
        "furniture and our own scratch are not adoption sources; the engine \
         would scan them and find nothing, which is the outcome this \
         predicts cheaply"
    );
    // And the property the skip leans on, asserted here rather than
    // assumed - see this test's note.
    let out = nzbkit::disk::sanitize_out_name(".9f3a1c40b2");
    assert!(
        !out.rsplit('/').next().unwrap_or(&out).starts_with('.'),
        "if a published name can keep its leading dot, this screen hides a \
         real leftover and must be narrowed to the names we write"
    );
}
