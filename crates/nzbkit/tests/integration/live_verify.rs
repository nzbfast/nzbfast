//! Differential tests: LiveVerifier (in-stream, out-of-order) must agree
//! with `par2::verify_file_blocks` (the sequential reference) on the same
//! data, for every arrival order and damage pattern.
//!
//! Uses the real par2cmdline fixture set (block size 4096):
//!   beta.bin  33 KiB → 9 blocks,  alpha.bin 10 KiB → 3 blocks.

use crate::scratch;

use nzbkit::live::LiveVerifier;
use nzbkit::par2::verify_file_blocks;

const MAIN: &[u8] = include_bytes!("../fixtures/par2/testset.par2");
const ALPHA: &[u8] = include_bytes!("../fixtures/par2/alpha.bin");
const BETA: &[u8] = include_bytes!("../fixtures/par2/beta.bin");

/// Deterministic PRNG (no deps).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Split `data` into articles of `art_size` bytes and return (offset, chunk)
/// pairs in a shuffled order.
fn shuffled_articles(data: &[u8], art_size: usize, rng: &mut Rng) -> Vec<(u64, Vec<u8>)> {
    let mut arts: Vec<(u64, Vec<u8>)> = data
        .chunks(art_size)
        .enumerate()
        .map(|(i, c)| ((i * art_size) as u64, c.to_vec()))
        .collect();
    for i in (1..arts.len()).rev() {
        arts.swap(i, rng.below(i as u64 + 1) as usize);
    }
    arts
}

fn feed_all(
    v: &LiveVerifier,
    slot: usize,
    name: &str,
    data: &[u8],
    art_size: usize,
    rng: &mut Rng,
) {
    for (off, chunk) in shuffled_articles(data, art_size, rng) {
        v.on_data(slot, name, data.len() as u64, off, &chunk);
    }
}

fn bad_set(report: &nzbkit::live::SlotReport) -> Vec<usize> {
    report.bad_blocks.clone()
}

/// Reference: indexes of blocks verify_file_blocks flags bad.
fn reference_bad(name: &str, data: &[u8]) -> Vec<usize> {
    let set = nzbkit::par2::Par2Set::parse(&[MAIN]).unwrap();
    let f = set.files.iter().find(|f| f.name == name).unwrap();
    verify_file_blocks(f, set.block_size, data)
        .iter()
        .enumerate()
        .filter(|(_, ok)| !**ok)
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn pristine_out_of_order_all_live_zero_readback() {
    // Article sizes deliberately misaligned with the 4096 block size so
    // boundary partials are exercised heavily.
    for &art in &[1000usize, 4096, 5000, 7000, 33000] {
        let mut rng = Rng(art as u64 * 7 + 1);
        let v = LiveVerifier::new(2);
        v.activate(&[MAIN]).unwrap();
        feed_all(&v, 0, "beta.bin", BETA, art, &mut rng);
        feed_all(&v, 1, "alpha.bin", ALPHA, art, &mut rng);
        let rb = v.finish_slot(0, None).unwrap();
        let ra = v.finish_slot(1, None).unwrap();
        assert!(rb.all_ok(), "beta clean (art={art}): {:?}", rb.bad_blocks);
        assert!(ra.all_ok(), "alpha clean (art={art})");
        assert_eq!(rb.readback_blocks, 0, "beta zero read-back (art={art})");
        assert_eq!(ra.readback_blocks, 0, "alpha zero read-back (art={art})");
        assert_eq!(rb.total_blocks, 9);
        assert_eq!(ra.total_blocks, 3);
    }
}

#[test]
fn corruption_differential_random_orders() {
    let mut rng = Rng(0xDEAD_BEEF);
    for trial in 0..50u32 {
        let art = 600 + rng.below(9000) as usize;
        let mut data = BETA.to_vec();
        // 1–3 corrupt bytes at random positions.
        for _ in 0..1 + rng.below(3) {
            let pos = rng.below(data.len() as u64) as usize;
            data[pos] ^= 0x5A;
        }
        let v = LiveVerifier::new(1);
        v.activate(&[MAIN]).unwrap();
        feed_all(&v, 0, "beta.bin", &data, art, &mut rng);
        let r = v.finish_slot(0, None).unwrap();
        assert_eq!(
            bad_set(&r),
            reference_bad("beta.bin", &data),
            "trial {trial} (art={art}) diverged from reference"
        );
        assert_eq!(
            r.readback_blocks, 0,
            "no read-back needed when all data flows"
        );
    }
}

#[test]
fn late_activation_settles_via_readback() {
    // Half the articles arrive BEFORE the par2 set is known; their blocks
    // must settle from disk at finish time.
    let dir = std::env::temp_dir().join(format!("nzbfast-live-test-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let path = dir.join("beta.bin");
    std::fs::write(&path, BETA).unwrap();

    let mut rng = Rng(42);
    let arts = shuffled_articles(BETA, 5000, &mut rng);
    let v = LiveVerifier::new(1);
    let half = arts.len() / 2;
    for (off, chunk) in &arts[..half] {
        v.on_data(0, "beta.bin", BETA.len() as u64, *off, chunk);
    }
    v.activate(&[MAIN]).unwrap();
    for (off, chunk) in &arts[half..] {
        v.on_data(0, "beta.bin", BETA.len() as u64, *off, chunk);
    }
    let r = v.finish_slot(0, Some(&path)).unwrap();
    assert!(r.all_ok(), "bad blocks: {:?}", r.bad_blocks);
    assert!(
        r.readback_blocks > 0,
        "pre-activation spans must go through read-back"
    );
}

#[test]
fn missing_article_hole_flags_its_blocks() {
    // Write the file with a hole (sparse zeros where the article vanished);
    // never feed that span. Its blocks must come out Bad, matching the
    // reference run against the holed data.
    let dir = std::env::temp_dir().join(format!("nzbfast-live-hole-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let path = dir.join("beta.bin");

    let art = 5000usize;
    let missing_idx = 3usize; // article covering [15000, 20000)
    let mut holed = BETA.to_vec();
    holed[missing_idx * art..(missing_idx + 1) * art].fill(0);
    std::fs::write(&path, &holed).unwrap();

    let mut rng = Rng(7);
    let v = LiveVerifier::new(1);
    v.activate(&[MAIN]).unwrap();
    for (off, chunk) in shuffled_articles(BETA, art, &mut rng) {
        if off as usize == missing_idx * art {
            continue;
        }
        v.on_data(0, "beta.bin", BETA.len() as u64, off, &chunk);
    }
    let r = v.finish_slot(0, Some(&path)).unwrap();
    assert_eq!(bad_set(&r), reference_bad("beta.bin", &holed));
    assert!(!r.bad_blocks.is_empty());
}

#[test]
fn obfuscated_name_matches_by_md5_16k() {
    // Subject/yEnc name is hash garbage; matching must fall back to the
    // first-16k hash. Until the head completes, spans can't hash live -
    // they settle by read-back, so the file must exist on disk (as it
    // always does in `get`, which writes before verifying).
    let dir = std::env::temp_dir().join(format!("nzbfast-live-obf-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let path = dir.join("obf.bin");
    std::fs::write(&path, BETA).unwrap();

    let mut rng = Rng(99);
    let v = LiveVerifier::new(1);
    v.activate(&[MAIN]).unwrap();
    feed_all(&v, 0, "a9f3c2e8b1d4.bin", BETA, 5000, &mut rng);
    let r = v.finish_slot(0, Some(&path)).unwrap();
    assert_eq!(r.par2_name.as_deref(), Some("beta.bin"));
    assert!(r.all_ok(), "bad: {:?}", r.bad_blocks);
}

#[test]
fn short_file_obfuscated_match() {
    // alpha.bin (10 KiB < 16 KiB): head = whole file, md5_16k = file md5.
    let dir = std::env::temp_dir().join(format!("nzbfast-live-obf2-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let path = dir.join("obf2.bin");
    std::fs::write(&path, ALPHA).unwrap();

    let mut rng = Rng(100);
    let v = LiveVerifier::new(1);
    v.activate(&[MAIN]).unwrap();
    feed_all(&v, 0, "deadbeef.dat", ALPHA, 3000, &mut rng);
    let r = v.finish_slot(0, Some(&path)).unwrap();
    assert_eq!(r.par2_name.as_deref(), Some("alpha.bin"));
    assert!(r.all_ok(), "bad: {:?}", r.bad_blocks);
}

#[test]
fn unrelated_slot_reports_none() {
    let v = LiveVerifier::new(1);
    v.activate(&[MAIN]).unwrap();
    let junk = vec![0xABu8; 8000];
    v.on_data(0, "readme.nfo", junk.len() as u64, 0, &junk);
    assert!(v.finish_slot(0, None).is_none(), "nfo must not match");
    // Both par2 files remain unclaimed.
    assert_eq!(v.unclaimed_files().len(), 2);
}

#[test]
fn concurrent_slots_and_threads() {
    // Hammer one verifier from multiple threads (mirrors the decoder pool).
    use std::sync::Arc;
    let v = Arc::new(LiveVerifier::new(2));
    v.activate(&[MAIN]).unwrap();
    let mut rng = Rng(1234);
    let beta_arts = Arc::new(shuffled_articles(BETA, 1500, &mut rng));
    let alpha_arts = Arc::new(shuffled_articles(ALPHA, 1500, &mut rng));

    let mut handles = Vec::new();
    for t in 0..4 {
        let v = v.clone();
        let beta = beta_arts.clone();
        let alpha = alpha_arts.clone();
        handles.push(std::thread::spawn(move || {
            for (i, (off, chunk)) in beta.iter().enumerate() {
                if i % 4 == t {
                    v.on_data(0, "beta.bin", BETA.len() as u64, *off, chunk);
                }
            }
            for (i, (off, chunk)) in alpha.iter().enumerate() {
                if i % 4 == t {
                    v.on_data(1, "alpha.bin", ALPHA.len() as u64, *off, chunk);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let rb = v.finish_slot(0, None).unwrap();
    let ra = v.finish_slot(1, None).unwrap();
    assert!(rb.all_ok(), "beta: {:?}", rb.bad_blocks);
    assert!(ra.all_ok(), "alpha: {:?}", ra.bad_blocks);
    assert_eq!(rb.readback_blocks + ra.readback_blocks, 0);
}

#[test]
fn fast_verify_matches_full_on_clean_and_damaged() {
    // Fast mode (CRC32-only in-stream claims, TODO §10) must agree with
    // full MD5+CRC verification on real corruption: CRC32 catches every
    // damage pattern here; only an engineered 2⁻³² collision could differ.
    let mut rng = Rng(0xFA57_0001);
    for trial in 0..30u32 {
        let art = 600 + rng.below(9000) as usize;
        let mut data = BETA.to_vec();
        if trial % 3 != 0 {
            for _ in 0..1 + rng.below(3) {
                let pos = rng.below(data.len() as u64) as usize;
                data[pos] ^= 0x5A;
            }
        }
        let v = LiveVerifier::new(1);
        v.set_fast_verify(true);
        v.activate(&[MAIN]).unwrap();
        feed_all(&v, 0, "beta.bin", &data, art, &mut rng);
        let r = v.finish_slot(0, None).unwrap();
        assert_eq!(
            bad_set(&r),
            reference_bad("beta.bin", &data),
            "fast-verify trial {trial} (art={art}) diverged from reference"
        );
        assert_eq!(r.readback_blocks, 0);
    }
}

#[test]
fn fast_verify_settle_readback_still_uses_md5() {
    // Blocks that miss the in-stream window settle by read-back, which
    // must keep the full MD5+CRC check even in fast mode: corrupt the
    // on-disk bytes of a span that was never fed live and expect Bad.
    let dir = std::env::temp_dir().join(format!("nzbfast-live-fast-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let path = dir.join("beta.bin");

    let art = 5000usize;
    let skipped = 3usize; // article covering [15000, 20000) never fed
    let mut holed = BETA.to_vec();
    holed[skipped * art..(skipped + 1) * art].fill(0);
    std::fs::write(&path, &holed).unwrap();

    let mut rng = Rng(0xFA57_0002);
    let v = LiveVerifier::new(1);
    v.set_fast_verify(true);
    v.activate(&[MAIN]).unwrap();
    for (off, chunk) in shuffled_articles(BETA, art, &mut rng) {
        if off as usize == skipped * art {
            continue;
        }
        v.on_data(0, "beta.bin", BETA.len() as u64, off, &chunk);
    }
    let r = v.finish_slot(0, Some(&path)).unwrap();
    assert_eq!(bad_set(&r), reference_bad("beta.bin", &holed));
    assert!(
        r.readback_blocks > 0,
        "skipped span must settle by read-back"
    );
}

#[test]
fn check_block_variants_semantics() {
    // Document the exact contract: full check needs MD5 AND CRC; the
    // CRC-only variant accepts a block whose MD5 would not match.
    use md5::{Digest, Md5};
    use nzbkit::live::{check_block, check_block_crc};
    use nzbkit::par2::BlockCheck;

    let bs = 4096usize;
    let bytes = vec![0x37u8; 1000]; // short block → zero-padded to bs
    let mut padded = bytes.clone();
    padded.resize(bs, 0);
    let good = BlockCheck {
        md5: Md5::digest(&padded).into(),
        crc32: crc32fast::hash(&padded),
    };
    assert!(check_block(&good, bs, &bytes));
    assert!(check_block_crc(&good, bs, &bytes));

    let mut wrong_md5 = good;
    wrong_md5.md5[0] ^= 0xFF;
    assert!(
        !check_block(&wrong_md5, bs, &bytes),
        "full check must reject bad MD5"
    );
    assert!(
        check_block_crc(&wrong_md5, bs, &bytes),
        "CRC-only ignores MD5 by design"
    );

    let mut wrong_crc = good;
    wrong_crc.crc32 ^= 1;
    assert!(!check_block(&wrong_crc, bs, &bytes));
    assert!(!check_block_crc(&wrong_crc, bs, &bytes));
}

#[test]
fn crc_only_zero_extension_matches_hashing_the_padding() {
    // The CRC-only check extends over the block's zero padding in
    // O(log n) instead of hashing it. That must be bit-identical to the
    // literal padded hash at every shape: a full block (no padding at
    // all), a file's short final block, and a one-byte block whose
    // padding is nearly the whole 1 MiB.
    use nzbkit::live::check_block_crc;
    use nzbkit::par2::BlockCheck;

    let bs = 1 << 20; // 1 MiB, a real PAR2 block size
    let mut rng = Rng(0x21D_0BEEF);
    let full: Vec<u8> = (0..bs).map(|_| (rng.next() >> 24) as u8).collect();
    for len in [bs, bs - 1, 700_003, 4096, 1, 0] {
        let bytes = &full[..len];
        let mut padded = bytes.to_vec();
        padded.resize(bs, 0);
        let check = BlockCheck {
            // Unused by the CRC-only path, but NOT all-zero: that
            // exact value is `BlockCheck::UNPROVEN`, the placeholder
            // `par2::fit_ifsc` fills a short IFSC's grid out with, and
            // `crc_matches` refuses one whatever the CRC says.
            md5: [1; 16],
            crc32: crc32fast::hash(&padded),
        };
        assert!(
            check_block_crc(&check, bs, bytes),
            "zero-extension disagreed with the padded hash at len {len}"
        );
        let mut wrong = check;
        wrong.crc32 ^= 1;
        assert!(
            !check_block_crc(&wrong, bs, bytes),
            "a wrong CRC was accepted at len {len}"
        );
    }
}

#[test]
fn fast_mode_disk_fed_spans_still_flag_damage() {
    // Disk-fed spans (backfill/crash-resume) route through
    // on_data_from_disk, which must verify (full MD5+CRC) even in fast
    // mode - regression guard for the trusted/untrusted split.
    let mut rng = Rng(0xFA57_0003);
    let mut data = BETA.to_vec();
    data[9000] ^= 0x5A;
    let v = LiveVerifier::new(1);
    v.set_fast_verify(true);
    v.activate(&[MAIN]).unwrap();
    for (off, chunk) in shuffled_articles(&data, 5000, &mut rng) {
        v.on_data_from_disk(0, "beta.bin", data.len() as u64, off, &chunk);
    }
    let r = v.finish_slot(0, None).unwrap();
    assert_eq!(bad_set(&r), reference_bad("beta.bin", &data));
    assert!(!r.bad_blocks.is_empty());
}

#[test]
fn fast_verify_boundary_blocks_hold_zero_bytes() {
    // B1: under fast verify, boundary blocks are tracked as fragment
    // CRC32s - the partials byte budget must never be touched, whatever
    // the arrival order. (Full mode on the same feed DOES buffer.)
    for &art in &[600usize, 1000, 5000, 7000] {
        let mut rng = Rng(art as u64);
        let v = LiveVerifier::new(1);
        v.set_fast_verify(true);
        v.activate(&[MAIN]).unwrap();
        feed_all(&v, 0, "beta.bin", BETA, art, &mut rng);
        let (peak, spilled) = v.partials_stats();
        assert_eq!(peak, 0, "fast mode buffered bytes (art={art})");
        assert_eq!(spilled, 0, "fast mode spilled (art={art})");
        let r = v.finish_slot(0, None).unwrap();
        assert!(r.all_ok());
        assert_eq!(r.readback_blocks, 0, "art={art}");
    }
    // Control: the same shuffled feed in full-MD5 mode uses the buffer
    // path (peak > 0) - proves the assertion above isn't vacuous.
    let mut rng = Rng(77);
    let v = LiveVerifier::new(1);
    v.activate(&[MAIN]).unwrap();
    feed_all(&v, 0, "beta.bin", BETA, 5000, &mut rng);
    assert!(
        v.partials_stats().0 > 0,
        "full mode should buffer boundaries"
    );
}

#[test]
fn tiny_partials_budget_never_spills_in_fast_mode() {
    // The low-RAM scenario B1 exists for: a 1-byte partials cap (the
    // floor) would force every boundary block to spill in byte mode.
    // CRC-parts are budget-exempt, so fast mode still verifies every
    // block live - zero spill, zero read-back.
    let mut rng = Rng(0xB1);
    let v = LiveVerifier::with_partials_cap(1, 1);
    v.set_fast_verify(true);
    v.activate(&[MAIN]).unwrap();
    feed_all(&v, 0, "beta.bin", BETA, 5000, &mut rng);
    let (_, spilled) = v.partials_stats();
    assert_eq!(spilled, 0);
    let r = v.finish_slot(0, None).unwrap();
    assert!(r.all_ok());
    assert_eq!(r.readback_blocks, 0);
    // (with_partials_cap clamps to a 1 MB floor, so a byte-mode control
    // can't be made to spill with these small fixtures - the byte-vs-crc
    // contrast is asserted by fast_verify_boundary_blocks_hold_zero_bytes.)
}

#[test]
fn fast_verify_mixed_disk_fragment_degrades_to_readback() {
    // A disk-fed span (backfill/crash-resume) whose fragment lands on a
    // CRC-parts boundary block can't be composed (no bytes held, and
    // disk spans owe full MD5). The block must fall back to settle
    // read-back and still verdict correctly.
    let dir = std::env::temp_dir().join(format!("nzbfast-live-b1mix-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let path = dir.join("beta.bin");
    std::fs::write(&path, BETA).unwrap();

    let art = 5000usize; // misaligned with bs=4096 → every join straddles
    let v = LiveVerifier::new(1);
    v.set_fast_verify(true);
    v.activate(&[MAIN]).unwrap();
    // Article 0 arrives fresh (starts CRC parts for boundary block 1),
    // article 1 arrives from disk (its fragment hits that CRC block).
    let arts: Vec<(u64, &[u8])> = BETA
        .chunks(art)
        .enumerate()
        .map(|(i, c)| ((i * art) as u64, c))
        .collect();
    v.on_data(0, "beta.bin", BETA.len() as u64, arts[0].0, arts[0].1);
    v.on_data_from_disk(0, "beta.bin", BETA.len() as u64, arts[1].0, arts[1].1);
    for (off, chunk) in &arts[2..] {
        v.on_data(0, "beta.bin", BETA.len() as u64, *off, chunk);
    }
    let r = v.finish_slot(0, Some(&path)).unwrap();
    assert!(r.all_ok(), "bad: {:?}", r.bad_blocks);
    assert!(
        r.readback_blocks > 0,
        "the mixed-trust boundary block must settle by read-back"
    );
}

/// M32 perf: integrity delegation truth table. The article-CRC skip is
/// only licensed when the verifier fully re-hashes the bytes: set
/// active AND slot matched AND fast verify OFF. Everything else - no
/// set yet, fast mode, unmatched slot - must keep the article CRC.
#[test]
fn delegates_integrity_only_when_full_md5_covers_the_slot() {
    let mut rng = Rng(42);
    let v = LiveVerifier::new(2);
    // Waiting (no set yet): never delegate.
    assert!(!v.delegates_integrity(0));
    v.activate(&[MAIN]).unwrap();
    // Active but slot not yet matched (no article seen): no delegation.
    assert!(!v.delegates_integrity(0));
    feed_all(&v, 0, "beta.bin", BETA, 5000, &mut rng);
    // Matched + full-MD5 mode: delegate.
    assert!(
        v.delegates_integrity(0),
        "matched slot under full MD5 delegates"
    );
    // Fast verify flips it off - CRC-only claims lean on the pcrc.
    v.set_fast_verify(true);
    assert!(
        !v.delegates_integrity(0),
        "fast verify must keep the article CRC"
    );
    // …unless the user opted into lean (single-CRC32 in-stream).
    v.set_lean(true);
    assert!(
        v.delegates_integrity(0),
        "lean mode delegates under fast verify"
    );
    v.set_lean(false);
    v.set_fast_verify(false);
    // A slot the set has never matched stays undelegated.
    assert!(!v.delegates_integrity(1));

    // And a delegated-skip span still verifies clean end to end when
    // fed as untrusted (full MD5), matching the main.rs wiring.
    v.on_data_from_disk(0, "beta.bin", BETA.len() as u64, 0, BETA);
    let r = v.finish_slot(0, None).unwrap();
    assert!(r.all_ok());
}
