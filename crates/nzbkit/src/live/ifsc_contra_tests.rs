//! M4-69: an IFSC entry that contradicts ITSELF about one block.
//!
//! A sibling file rather than a block in `live/tests.rs`, by the rule
//! that file's own header gives - one subject per file, and live.rs and
//! its test module both sit near the size gate. Reached by `#[path]`
//! from live.rs, so `use super::*` names the verifier's own module.
//!
//! The seam. An IFSC entry carries a CRC32 and an MD5 of the SAME block,
//! and [`super::check_block`] compares both. A hostile producer that
//! ships HONEST CRCs and FORGED MD5s therefore hands us a set whose
//! every block reads "bad" over bytes that are byte-exact - the settle
//! report says 100% damage, repair spends a full reconstruct on intact
//! bytes, and where the parity falls short the job fails Unrepairable on
//! a perfect post.
//!
//! The answer is the authority rule this family runs on: the FileDesc
//! whole-file MD5 covers every byte of every block, so where it matches
//! it is the strongest evidence the settled file admits and no per-block
//! claim may outrank it. Reaching for it is gated on the CONTRADICTION -
//! a CRC32 that matched beside an MD5 that did not, which
//! `check_block`'s existing CRC-first order computes for free and which
//! no well-formed set can produce.
//!
//! AND THE MIRROR, 31 Aug 2026: honest MD5s beside FORGED CRC32s. The
//! block fails on the CRC, so the MD5 that would have disagreed with it
//! is never computed and nothing latches - there is no free signal here
//! at all, which is why this half was left open when the first was
//! closed and is the one thing to understand before touching either.
//! Measured, it is the worse half: it fails the JOB rather than merely
//! spending on it (any set under 100% redundancy is told it needs more
//! recovery blocks than it carries), and it bites on the DEFAULT setting
//! rather than only under `NZBFAST_FAST_VERIFY=0`, because in-stream
//! fast verify is CRC32-only and the forged half IS the CRC32.
//!
//! ONE HAZARD CHECKED AND CLEARED, 31 Aug 2026, because the trigger
//! makes the whole-file read reachable far more often than the first two
//! did: `get::settle::settle_slots` hands a mapped or chased slot in as
//! `Extractor::read_at`, which plans under the extractor lock and
//! PREADS. It is not the frontier's `read_covered_blocking`, whose
//! coverage gate a whole-file read of an all-bad file would wait on
//! forever - that door is reached only from `extract::sevenz` and the
//! `BlockingRangeSource` impl the rars engine drives. So the escalation
//! is non-blocking by construction rather than by luck. (A 720 s hang
//! during this work looked exactly like that wedge and was not: two of
//! this lane's own e2e suites plus another lane's sweep on one box. The
//! full suite under `--profile ci`, whose per-test ceiling would have
//! reported a real one, is 391/391.)
//!
//! Same authority rule, on a trigger that is GATED because it is not
//! free: every block of the file is bad. That is the one shape whose
//! price - a pass over the file - is bounded by what it refutes, a claim
//! whose only two outcomes are rebuilding the whole file or failing the
//! job. The arithmetic that makes it sound is the same arithmetic that
//! refuses the general case; both are written out at the trigger in
//! `finish_slot_from` and at `BlockVerdict::Damaged`.

use super::*;
use md5::{Digest, Md5};

const BS: usize = 4096;
const TYPE_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";
const TYPE_IFSC: &[u8; 16] = b"PAR 2.0\0IFSC\0\0\0\0";

fn pseudo(len: usize, seed: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x = seed | 1;
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push((x & 0xff) as u8);
    }
    v
}

fn pkt(ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(crate::par2::MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&[1u8; 16]);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

/// How this index's IFSC entries relate to the bytes they describe.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ifsc {
    Honest,
    /// Honest CRC32s of the real bytes, forged MD5s: the row's shape.
    LyingMd5,
    /// The mirror: honest MD5s of the real bytes, forged CRC32s. Never
    /// detectable per block for free - `check_block` runs the CRC first
    /// and returns on the miss, so the MD5 that would disagree with it
    /// is never computed.
    LyingCrc,
}

/// A one-file index over `data`, with a full IFSC grid built `how`.
fn index(name: &str, data: &[u8], how: Ifsc) -> Vec<u8> {
    let fid = [7u8; 16];
    let mut main = (BS as u64).to_le_bytes().to_vec();
    main.extend_from_slice(&1u32.to_le_bytes());
    main.extend_from_slice(&fid);
    let mut out = pkt(TYPE_MAIN, &main);

    let mut desc = fid.to_vec();
    desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
    desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(
        &data[..data.len().min(16384)],
    )));
    desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
    let mut nb = name.as_bytes().to_vec();
    nb.resize(nb.len().next_multiple_of(4), 0);
    desc.extend_from_slice(&nb);
    out.extend(pkt(TYPE_FILEDESC, &desc));

    let mut ifsc = fid.to_vec();
    for c in data.chunks(BS) {
        // The spec's checksums cover the block zero-padded to the block
        // size; every chunk here is full, so no padding arises.
        let md5: [u8; 16] = match how {
            Ifsc::Honest | Ifsc::LyingCrc => Md5::digest(c).into(),
            Ifsc::LyingMd5 => [0xAB; 16],
        };
        let crc: u32 = match how {
            Ifsc::Honest | Ifsc::LyingMd5 => crc32fast::hash(c),
            Ifsc::LyingCrc => crc32fast::hash(c) ^ 0xDEAD_BEEF,
        };
        ifsc.extend_from_slice(&md5);
        ifsc.extend_from_slice(&crc.to_le_bytes());
    }
    out.extend(pkt(TYPE_IFSC, &ifsc));
    out
}

fn rig(data: &[u8], how: Ifsc) -> LiveVerifier {
    let v = LiveVerifier::with_partials_cap(2, 1 << 20);
    v.activate(&[index("movie.mkv", data, how).as_slice()])
        .expect("index parses");
    v
}

/// Feed the whole file as one unverified (full-MD5) span and settle it
/// from memory, the way a lean-off download reaches the block checks.
fn settle(v: &LiveVerifier, data: &[u8]) -> SlotReport {
    v.on_data_unverified(0, "movie.mkv", data.len() as u64, 0, data);
    let read = |off: u64, buf: &mut [u8]| -> std::io::Result<()> {
        let off = off as usize;
        if off + buf.len() > data.len() {
            return Err(std::io::Error::other("short"));
        }
        buf.copy_from_slice(&data[off..off + buf.len()]);
        Ok(())
    };
    v.finish_slot_from(0, ReadAt::Reader(&read))
        .expect("the slot claimed the only descriptor")
}

/// The row. Honest CRCs, forged MD5s, byte-exact bytes: every block
/// fails its entry, and the whole-file MD5 says the file is exactly what
/// the descriptor describes. The strongest evidence wins.
///
/// The CONTROL beside it is what makes this a narrowing and not a hole:
/// the same rig over an HONEST index reports the same clean verdict, so
/// a green here is not the block grid having been switched off.
#[test]
fn forged_block_md5s_do_not_make_an_intact_file_100_percent_damaged() {
    let data = pseudo(8 * BS, 11);
    let honest = settle(&rig(&data, Ifsc::Honest), &data);
    assert_eq!(honest.total_blocks, 8);
    assert!(
        honest.bad_blocks.is_empty(),
        "control: an honest set is clean"
    );

    let r = settle(&rig(&data, Ifsc::LyingMd5), &data);
    assert_eq!(r.total_blocks, 8);
    assert!(
        r.bad_blocks.is_empty(),
        "the FileDesc MD5 covers every byte of every block and matched, so \
         entries disagreeing with it are unusable, not damage - got {:?}",
        r.bad_blocks
    );
}

/// The escalation may not launder REAL damage. Same forged-MD5 index,
/// but one byte of the file is wrong: the whole-file MD5 misses, so the
/// block report stands exactly as it did and the job still repairs.
///
/// This is the arm that keeps the gate honest. The rule is "the
/// whole-file MD5 outranks the entries", never "a contradicted entry is
/// ignored" - a set that lies about its blocks over bytes that are also
/// wrong gets no credit for the lie.
#[test]
fn the_whole_file_escalation_never_launders_real_damage() {
    let data = pseudo(8 * BS, 11);
    // Past the first 16 KiB, so the md5-16k tier still claims the
    // descriptor and the test reaches the block verdict it is about.
    let mut broken = data.clone();
    broken[5 * BS + 7] ^= 0xff;
    let v = rig(&data, Ifsc::LyingMd5);
    let r = settle(&v, &broken);
    assert!(
        !r.bad_blocks.is_empty(),
        "the file does not hash to its descriptor, so nothing here proves it"
    );
}

/// The three-valued verdict itself, which is what the escalation is
/// gated on and which costs nothing to compute: `check_block` runs the
/// CRC first and only reaches the MD5 once the CRC has matched, so the
/// disagreeing pair is the one pair already fully in hand.
///
/// `Damaged` and `Contradicted` are deliberately different answers. A
/// damaged block failed the CRC and its MD5 was never consulted; a
/// contradicted one passed the CRC, so its entry describes two different
/// blocks and describes neither.
#[test]
fn a_block_check_says_which_half_disagreed() {
    let block = pseudo(BS, 5);
    let real = BlockCheck {
        md5: Md5::digest(&block).into(),
        crc32: crc32fast::hash(&block),
    };
    assert_eq!(check_block_verdict(&real, BS, &block), BlockVerdict::Ok);
    assert_eq!(
        check_block_verdict(
            &BlockCheck {
                md5: [0xAB; 16],
                ..real
            },
            BS,
            &block
        ),
        BlockVerdict::Contradicted,
        "the CRC matched, so the MD5 was reached and disagreed with it"
    );
    assert_eq!(
        check_block_verdict(
            &BlockCheck {
                crc32: real.crc32 ^ 0xDEAD_BEEF,
                ..real
            },
            BS,
            &block
        ),
        BlockVerdict::Damaged,
        "a CRC miss is ordinary damage and never consults the MD5"
    );
    // And the bool form is unchanged, which is the contract
    // `par2::verify_file_blocks` is held to.
    assert!(check_block(&real, BS, &block));
    assert!(!check_block(
        &BlockCheck {
            md5: [0xAB; 16],
            ..real
        },
        BS,
        &block
    ));
}

/// THE MIRROR DIRECTION - M4-69's stated limit, closed 31 Aug 2026.
///
/// Honest block MD5s beside FORGED CRC32s, over byte-exact bytes. Every
/// block fails on the CRC, so `check_block` returns before it reaches
/// the MD5 that would have disagreed with it and
/// `ifsc_self_contradicted` never latches. The row predicted the outcome
/// would stay correct and cost only spend. IT DOES NOT: measured end to
/// end that day at 20% redundancy, the job FAILS -
/// `[verify] x Covered.bin - 2000/2000 blocks bad` followed by
/// `[repair] unrepairable: 2000 blocks needed, only 400 recovery blocks
/// in the NZB`, over a payload that is byte-exact on disk. Any set under
/// 100% redundancy fails that way. And unlike the forged-MD5 direction,
/// which only bites where every block takes a full check, this one bites
/// in the DEFAULT configuration: in-stream fast verify is CRC32-only, so
/// the lying half is the only half it reads.
///
/// The answer is the same authority rule, on a third trigger - see
/// `finish_slot_from`. What made the first two free was that the evidence was
/// already computed; this one is not, so it is gated on the one shape
/// whose price is bounded by what it prevents.
///
/// The CONTROL beside it is what makes this a narrowing and not a hole.
#[test]
fn forged_block_crcs_do_not_make_an_intact_file_100_percent_damaged() {
    let data = pseudo(8 * BS, 11);
    let honest = settle(&rig(&data, Ifsc::Honest), &data);
    assert!(
        honest.bad_blocks.is_empty(),
        "control: an honest set is clean"
    );

    let r = settle(&rig(&data, Ifsc::LyingCrc), &data);
    assert_eq!(r.total_blocks, 8);
    assert!(
        r.bad_blocks.is_empty(),
        "every block arrived and every one failed its CRC32, and the FileDesc \
         MD5 covers every byte of every block and matched - the entries do not \
         describe this file, which is not the same as the file being wrong - \
         got {:?}",
        r.bad_blocks
    );
}

/// The mirror's laundering arm, and it carries exactly the weight its
/// forged-MD5 sibling does: the rule is "the whole-file MD5 outranks the
/// entries", never "a failing block is ignored because they all failed".
/// Same forged-CRC index, one byte of the file wrong: the digest misses,
/// so the block report stands and the job still repairs.
#[test]
fn the_all_blocks_bad_escalation_never_launders_real_damage() {
    let data = pseudo(8 * BS, 11);
    // Past the first 16 KiB, so the md5-16k tier still claims the
    // descriptor and the test reaches the block verdict it is about.
    let mut broken = data.clone();
    broken[5 * BS + 7] ^= 0xff;
    let r = settle(&rig(&data, Ifsc::LyingCrc), &broken);
    assert!(
        !r.bad_blocks.is_empty(),
        "the file does not hash to its descriptor, so nothing here proves it"
    );
}

/// THE TRIGGER MAY NOT DEPEND ON HOW THE PARTIALS BUDGET FELL, and this
/// is a regression pin for a defect the fix shipped with for an hour.
///
/// The first cut screened on `SlotState::live_bad` - blocks a span
/// DELIVERED and that failed there - rather than on the count of bad
/// blocks, to hold out a file nothing arrived for. It passed alone and
/// FAILED under the full e2e suite: the partials budget spills under
/// memory pressure, so the same fixture that verified 2000 blocks
/// in-stream on an idle box verified 666 with 1334 read back on a loaded
/// one, `live_bad` never reached the block count, and the escalation
/// silently stopped firing. A byte-exact download failed its job because
/// of what else was running on the machine.
///
/// So the file arrives in two halves here: one span in stream, the rest
/// read back from disk at settle. Every block still fails its forged
/// CRC32, the whole-file MD5 still covers every byte, and the verdict
/// must not move.
///
/// What the discarded screen was guarding is unreachable in any case -
/// `settle_binding` drops a binding no content tier earned, so a file of
/// holes claims no descriptor and settles no report at all. Measured the
/// same day: `finish_slot_from` over an all-zeros file answers None,
/// name-bound or not.
#[test]
fn the_escalation_does_not_depend_on_in_stream_versus_read_back() {
    let data = pseudo(8 * BS, 11);
    let v = rig(&data, Ifsc::LyingCrc);
    // Half in stream; the rest read back from the same byte-exact bytes.
    v.on_data_unverified(0, "movie.mkv", data.len() as u64, 0, &data[..4 * BS]);
    let read = |off: u64, buf: &mut [u8]| -> std::io::Result<()> {
        let off = off as usize;
        if off + buf.len() > data.len() {
            return Err(std::io::Error::other("short"));
        }
        buf.copy_from_slice(&data[off..off + buf.len()]);
        Ok(())
    };
    let r = v
        .finish_slot_from(0, ReadAt::Reader(&read))
        .expect("the slot claimed the only descriptor");
    assert!(
        r.bad_blocks.is_empty(),
        "the verdict moved with the split between in-stream and read-back \
         verification, which is a property of machine load and not of the \
         bytes - got {:?}",
        r.bad_blocks
    );
}
