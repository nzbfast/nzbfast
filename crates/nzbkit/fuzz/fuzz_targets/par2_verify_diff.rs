#![no_main]
//! Differential fuzz over PAR2 target VERIFICATION (TODO 133.3).
//!
//! `par2_parse` fuzzes the packet parser and could never have found H7:
//! that input was not malformed, it was internally INCONSISTENT - a
//! FileDesc describing bytes A beside an IFSC list describing bytes B of
//! the same length, both packets well-formed, both parsing fine. The bug
//! was a VERDICT answered from the wrong one of the two claims, and it
//! showed up only as a disagreement between the serial pass and the
//! thread-pool pass over identical metadata.
//!
//! So this target generates the inconsistency deliberately - the
//! descriptor MD5, the IFSC list and the bytes on disk are each drawn
//! from an independent source - and asserts the three verdicts cannot
//! disagree:
//!
//! * `verify_pass1(threads = 1)` (serial scanner)
//! * `verify_pass1(threads = 8)` (the pool branch, which under
//!   `--cfg fuzzing` opens at 8 KiB instead of 8 MiB)
//! * `md5_matches` (the post-repair self-prove)
//!
//! plus an oracle computed here from the bytes that were actually
//! written, so "all three agree" cannot be satisfied by all three being
//! wrong together. Any future path that answers a verdict from a
//! different piece of metadata fails on the first inconsistent set.
//!
//! `Pass1Out` is a TRI-state, and the assertions below are written
//! around that: `md5_unfinished` says the whole-file digest stopped at
//! the first block the IFSC denied, so `clean`/`intact` false there is
//! "not proven" rather than "disproven". Under it this target asserts
//! the shape of the contract (the flag only ever withholds a positive,
//! it is only ever raised over a denied block, and the bitmap is exact
//! anyway) instead of the FileDesc verdicts. The H7 direction - a
//! satisfied IFSC laundering bytes the FileDesc MD5 denies into a
//! "clean" - is unreachable through that flag by construction, and
//! stays fully pinned.

use crc32fast::Hasher as Crc32;
use libfuzzer_sys::fuzz_target;
use md5::{Digest, Md5};
use nzbkit::par2::{BlockCheck, Par2File};
use nzbkit::par2repair::{md5_matches, md5_matches_resumed, verify_pass1};
use std::path::PathBuf;
use std::sync::OnceLock;

/// Declared lengths stay well above the 8 KiB fuzzing pool gate but
/// small enough that a case costs microseconds, not milliseconds.
const MAX_LEN: usize = 40 << 10;
/// Block sizes are multiples of 4 per spec; 4 gives thousands of slices
/// over a 40 KiB file, 16384 gives a single one.
const BLOCK_SIZES: [usize; 6] = [4, 16, 64, 512, 4096, 16384];

/// Cheap deterministic bytes - xorshift64, not a PRNG crate, because the
/// only property needed is "two seeds give unrelated content".
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

/// The fuzzer's bytes, read as a stream of small choices.
struct Src<'a> {
    d: &'a [u8],
    i: usize,
}

impl Src<'_> {
    fn byte(&mut self) -> u8 {
        let b = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        b
    }
    fn u16(&mut self) -> usize {
        let (a, b) = (self.byte(), self.byte());
        u16::from_le_bytes([a, b]) as usize
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.byte() as usize % xs.len()]
    }
    fn md5_like(&mut self) -> [u8; 16] {
        let mut m = [0u8; 16];
        for b in &mut m {
            *b = self.byte();
        }
        m
    }
}

fn md5_of(b: &[u8]) -> [u8; 16] {
    Md5::digest(b).into()
}

/// One file's IFSC list over `data`, padded per spec.
fn blocks_of(data: &[u8], bs: usize, n: usize) -> Vec<BlockCheck> {
    (0..n)
        .map(|i| {
            let off = i * bs;
            let end = (off + bs).min(data.len());
            let mut slice = if off < data.len() {
                data[off..end].to_vec()
            } else {
                Vec::new()
            };
            slice.resize(bs, 0);
            let mut crc = Crc32::new();
            crc.update(&slice);
            BlockCheck {
                md5: md5_of(&slice),
                crc32: crc.finalize(),
            }
        })
        .collect()
}

/// What the verify paths MUST say, computed from the bytes on disk and
/// the metadata as generated - deliberately a plain re-statement of the
/// contract, not a second call into the code under test.
///
/// The presence bitmap comes back whenever the set HAS an IFSC list,
/// including for a file the FileDesc MD5 proves clean - `verify_pass1`
/// drops the bitmap in that case, and folding that in is the caller's
/// job, because a result whose FileDesc verdict was WITHHELD carries
/// the bitmap and still has to match it.
///
/// Presence is a TWO-part rule and both halves are restated below: the
/// slice's declared bytes must all be on disk and its padded CRC32 must
/// match, AND the entry must be a real one - an all-zero MD5 is
/// `BlockCheck::UNPROVEN` and vouches for nothing.
fn oracle(disk: &[u8], file: &Par2File, bs: usize) -> (bool, bool, Option<Vec<bool>>) {
    let decl = file.length as usize;
    let clean = disk.len() >= decl && md5_of(&disk[..decl]) == file.md5;
    let intact = clean && disk.len() == decl;
    if file.blocks.is_empty() {
        return (clean, intact, None);
    }
    let n_slices = decl.div_ceil(bs);
    let present = (0..n_slices)
        .map(|i| {
            let off = i * bs;
            let declared = (decl - off).min(bs);
            let avail = disk.len().saturating_sub(off).min(bs);
            // A block whose declared bytes are not all on disk is damage
            // by definition, and a block with no IFSC entry is unproven.
            if avail < declared {
                return false;
            }
            let Some(check) = file.blocks.get(i) else {
                return false;
            };
            // An all-zero MD5 is RESERVED - it is `BlockCheck::UNPROVEN`,
            // the placeholder a SHORT IFSC packet is padded out with, and
            // it must never read as proven over any bytes at all. The
            // CRC32 beside it is not the guard (every u32 is somebody's
            // CRC32), so a wire entry spelling that MD5 is unproven too,
            // whatever its CRC field says: `crc_matches` answers false
            // before it ever looks. Restated here rather than called, so
            // the oracle stays a statement of the contract rather than a
            // second call into the code under test. Missing this cost a
            // 30.7M-execution campaign its first crash (2 Sep 2026, and
            // libFuzzer got there by SOLVING the CRC32 comparison with
            // its CMP instrumentation, then zeroing the MD5 beside it).
            if check.md5 == [0u8; 16] {
                return false;
            }
            let mut slice = disk[off..off + declared].to_vec();
            slice.resize(bs, 0);
            let mut crc = Crc32::new();
            crc.update(&slice);
            crc.finalize() == check.crc32
        })
        .collect();
    (clean, intact, Some(present))
}

fn target_path() -> &'static PathBuf {
    static P: OnceLock<PathBuf> = OnceLock::new();
    P.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("nzbkit-verifydiff-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join("t.bin")
    })
}

fuzz_target!(|data: &[u8]| {
    // Coverage guard, not a correctness one: the parallel branch opens at
    // `hash_par_min_bytes()`, and if `--cfg fuzzing` ever stops reaching
    // nzbkit that becomes 8 MiB - larger than anything generated here, so
    // every case would quietly take the serial path and the differential
    // would prove nothing while still passing.
    assert!(
        nzbkit::par2repair::hash_par_min_bytes() < MAX_LEN as u64,
        "the pool gate is above every length this target generates"
    );
    // Same guard for the resumed self-prove: its snapshot gate must sit
    // below most of BLOCK_SIZES or assertion 4 below stops covering it.
    assert!(
        nzbkit::par2repair::resume_min_block() <= 16,
        "the resume gate is above the block sizes this target generates"
    );
    let mut src = Src { d: data, i: 0 };
    let bs = src.pick(&BLOCK_SIZES);
    let decl_len = src.u16() % (MAX_LEN + 1);
    let a = payload(decl_len, 0x9e37_79b9_7f4a_7c15 ^ src.byte() as u64);
    let b = payload(decl_len, 0xbf58_476d_1ce4_e5b9 ^ src.byte() as u64);

    // The bytes that end up on disk: one source, the other, or a splice
    // of both (partial damage), then resized short or long.
    let mut disk = match src.byte() % 4 {
        0 => a.clone(),
        1 => b.clone(),
        2 => {
            let cut = if decl_len == 0 {
                0
            } else {
                src.u16() % decl_len
            };
            let mut m = a.clone();
            m[cut..].copy_from_slice(&b[cut..]);
            m
        }
        _ => {
            // Single-block damage: the shape a real bad article makes.
            let mut m = a.clone();
            if !m.is_empty() {
                let at = src.u16() % m.len();
                m[at] ^= 0x5a;
            }
            m
        }
    };
    let delta = src.u16() % (8 << 10);
    match src.byte() % 3 {
        0 => {} // exactly the declared length
        1 => disk.truncate(decl_len.saturating_sub(delta)),
        _ => disk.extend_from_slice(&payload(delta, 0x2545_f491_4f6c_dd1d)),
    }

    // The two independent claims in the descriptor, drawn independently:
    // this is the H7 shape whenever they disagree.
    let md5 = match src.byte() % 4 {
        0 => md5_of(&a),
        1 => md5_of(&b),
        2 => md5_of(&disk[..disk.len().min(decl_len)]),
        _ => src.md5_like(),
    };
    let n_slices = decl_len.div_ceil(bs);
    // The list length is its own axis: par2.rs's only FileDesc<->IFSC
    // check is an entry count, so short, exact and over-long lists all
    // have to reach the verdict code.
    let n_entries = match src.byte() % 4 {
        0 => n_slices,
        1 => n_slices.saturating_sub(1),
        2 => n_slices + 1,
        _ => 0,
    };
    let blocks = match src.byte() % 4 {
        0 => blocks_of(&a, bs, n_entries),
        1 => blocks_of(&b, bs, n_entries),
        2 => blocks_of(&disk, bs, n_entries),
        _ => (0..n_entries)
            .map(|_| BlockCheck {
                md5: src.md5_like(),
                crc32: u32::from_le_bytes([src.byte(), src.byte(), src.byte(), src.byte()]),
            })
            .collect(),
    };

    let file = Par2File {
        file_id: [0u8; 16],
        name: "t.bin".to_string(),
        length: decl_len as u64,
        md5,
        md5_16k: md5_of(&a[..a.len().min(16384)]),
        blocks,
    };

    let p = target_path();
    if std::fs::write(p, &disk).is_err() {
        return;
    }

    let serial = verify_pass1(p, &file, bs, 1).expect("serial verify");
    let par = verify_pass1(p, &file, bs, 8).expect("parallel verify");
    let self_prove = md5_matches(p, &file).expect("md5_matches");

    // 1. The two paths answer one set of metadata identically. This is
    //    the assertion H7 failed: same bytes, same packets, one verdict
    //    per core count.
    assert_eq!(par.exists, serial.exists, "exists disagrees");
    assert_eq!(par.clean, serial.clean, "clean disagrees");
    assert_eq!(par.intact, serial.intact, "intact disagrees");
    assert_eq!(par.present, serial.present, "presence bitmap disagrees");

    let (want_clean, want_intact, want_present) = oracle(&disk, &file, bs);

    // 2. The post-repair self-prove rereads the file on its own and
    //    must answer the bytes that are actually there. Stated against
    //    the oracle rather than against `serial.intact`, because those
    //    two are only required to agree where the verify pass finished
    //    asking the question - see 3.
    assert_eq!(self_prove, want_intact, "md5_matches vs the bytes on disk");

    // 3. And the verify verdicts against those same bytes, so a shared
    //    wrong premise cannot pass by agreeing with itself.
    //
    //    `md5_unfinished` (2 Sep 2026, `7f195ff27`) is the tri-state:
    //    the whole-file digest stops at the first block the IFSC
    //    denies, because the self-prove after the patch rehashes those
    //    bytes anyway, so `clean`/`intact` are then answered on IFSC
    //    evidence alone and mean "not proven". `repair_dir_set_inner`
    //    finishes the digest before the one verdict that can turn on it
    //    - a shortfall - is declared. So under the flag the FileDesc
    //    verdicts are not this target's to check; what is, is that the
    //    flag stays a WITHHOLDING and nothing more.
    if serial.md5_unfinished {
        assert!(
            !serial.clean && !serial.intact,
            "md5_unfinished may only withhold a positive verdict"
        );
        assert!(
            serial.resume.is_some(),
            "md5_unfinished without a snapshot to finish the digest from"
        );
        // Only ever raised over a block the IFSC actually denied: a
        // digest stopped anywhere else would be dropping the FileDesc
        // proof for nothing.
        assert!(
            want_present
                .as_ref()
                .is_some_and(|p| p.iter().any(|&ok| !ok)),
            "the digest stopped without a block the IFSC denied"
        );
        // The bitmap is still fully decided, and still by the CRC32s.
        assert_eq!(
            serial.present, want_present,
            "presence vs the IFSC CRC32s (digest cut short)"
        );
    } else {
        assert_eq!(serial.clean, want_clean, "clean vs the FileDesc MD5");
        assert_eq!(serial.intact, want_intact, "intact vs the FileDesc MD5");
        // A clean file is the one shape that drops the bitmap.
        let want = if want_clean { None } else { want_present };
        assert_eq!(serial.present, want, "presence vs the IFSC CRC32s");
    }

    // 4. The resumed self-prove (TODO 133.1) is the same proof as the
    //    full one. On the unpatched file the snapshot's prefix state
    //    covers exactly the bytes still on disk, so the resumed verdict
    //    must equal the full-reread verdict bit for bit - any drift
    //    here is the H7 class again, one verdict per code path.
    if let Some(res) = &serial.resume {
        let resumed = md5_matches_resumed(p, &file, res).expect("md5_matches_resumed");
        assert_eq!(resumed, self_prove, "resumed vs full self-prove");
    }
});
