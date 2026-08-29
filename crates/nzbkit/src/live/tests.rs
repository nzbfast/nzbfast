//! Unit tests for [`super`] - the in-stream PAR2 verifier.
//!
//! A sibling file rather than an inline `mod tests`: live.rs sits at its
//! size-gate ceiling and TODO 311's multi-set work is what took it over.
//! Reached by `#[path]` from live.rs, so `use super::*` still names the
//! verifier's own module and every test moved verbatim.

use super::*;

/// A slot the gate was never sized for is UNGATED, not a panic:
/// the mapped repair mints root slots past the NZB's count for a
/// wholly-missing volume it rebuilds from parity (gated e2e matrix,
/// 22 Aug 2026). Engaging one grows the gate instead.
#[test]
fn verify_gate_tolerates_slots_past_its_size() {
    let g = VerifyGate::new(2);
    assert_eq!(g.watermark(5), u64::MAX);
    assert_eq!(g.engaged_mark(5), None);
    g.wait_past(5, 100, std::time::Duration::from_millis(1));
    g.engage(5);
    assert_eq!(g.watermark(5), 0);
    g.advance(7, 40);
    assert_eq!(g.engaged_mark(7), Some(40));
    assert_eq!(g.engaged_mark(6), None);
    assert_eq!(g.watermark(1), u64::MAX);
}

/// §94 B VerifyGate contract: ungated reads as MAX, a claim engages
/// at 0, advances are monotonic (a stale racer can never lower the
/// mark), and wait_past returns immediately once covered.
#[test]
fn verify_gate_engage_advance_monotonic() {
    let g = VerifyGate::new(2);
    assert_eq!(g.watermark(0), u64::MAX, "ungated = MAX");
    g.engage(0);
    assert_eq!(g.watermark(0), 0, "engaged at zero");
    assert_eq!(g.watermark(1), u64::MAX, "other slots untouched");
    g.advance(0, 4096);
    assert_eq!(g.watermark(0), 4096);
    g.advance(0, 1024); // stale racer
    assert_eq!(g.watermark(0), 4096, "advance is monotonic");
    g.engage(0); // idempotent, never lowers
    assert_eq!(g.watermark(0), 4096);
    g.advance(0, u64::MAX);
    assert_eq!(g.watermark(0), u64::MAX, "fully verified ungates");
    // Covered: returns without blocking.
    g.wait_past(0, 0, std::time::Duration::from_secs(5));
    // Uncovered: bounded by the timeout, not hung.
    g.engage(1);
    let t0 = std::time::Instant::now();
    g.wait_past(1, 100, std::time::Duration::from_millis(50));
    assert!(t0.elapsed() < std::time::Duration::from_secs(2));
}

/// Pre-activation spans are re-fed by the M15b backfill under ONE
/// source per slot, so a span no wire CRC covered must not come back
/// as a fresh-strength `Rehash` claim - the disk round trip would
/// otherwise hand a pcrc-absent article a CRC32-only verdict.
#[test]
fn unvouched_pre_spans_take_the_disk_backfill() {
    let data = [7u8; 4096];
    let v = LiveVerifier::new(3);
    v.set_fast_verify(true);

    // Every span wire-CRC'd: the CRC-parts backfill route stands.
    v.on_data(0, "a.bin", 8192, 0, &data);
    v.on_data(0, "a.bin", 8192, 4096, &data);
    assert_eq!(v.take_pre_spans(0).1, PreSpanSrc::Backfill);

    // One pcrc-absent article taints the slot in default fast mode.
    v.on_data(1, "b.bin", 8192, 0, &data);
    v.on_data_unverified(1, "b.bin", 8192, 4096, &data);
    assert_eq!(v.take_pre_spans(1).1, PreSpanSrc::Disk);

    // Lean owns the weaker contract, so its own spans keep the route.
    v.set_lean(true);
    v.on_data_unverified(2, "c.bin", 8192, 0, &data);
    assert_eq!(v.take_pre_spans(2).1, PreSpanSrc::Backfill);
}

// ===== Par2Set fixtures: real serialized packets, parsed by the =====
// ===== same code the wire feeds, so activate() is exercised too. =====

/// Wrap a body in a valid packet (magic, length, body MD5) - the same
/// shape par2.rs's own tests build. Header is 64 bytes per spec.
fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(crate::par2::MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // md5 patched below
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

fn fid(i: usize) -> [u8; 16] {
    let mut f = [0u8; 16];
    f[0] = i as u8 + 1;
    f
}

/// Serialized single-set PAR2 metadata describing `files`. With
/// `ifsc` false every file lands on the whole-file-MD5 path.
fn par2_meta(set_id: [u8; 16], block_size: usize, files: &[(&str, &[u8])], ifsc: bool) -> Vec<u8> {
    use crate::par2::{TYPE_FILEDESC, TYPE_IFSC, TYPE_MAIN};
    let mut main = Vec::new();
    main.extend_from_slice(&(block_size as u64).to_le_bytes());
    main.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for i in 0..files.len() {
        main.extend_from_slice(&fid(i));
    }
    let mut out = pkt(set_id, TYPE_MAIN, &main);
    for (i, (name, data)) in files.iter().enumerate() {
        let mut desc = Vec::new();
        desc.extend_from_slice(&fid(i));
        desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
        let head = &data[..data.len().min(HEAD_LEN)];
        desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(head)));
        desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
        let mut nb = name.as_bytes().to_vec();
        while nb.len() % 4 != 0 {
            nb.push(0);
        }
        desc.extend_from_slice(&nb);
        out.extend(pkt(set_id, TYPE_FILEDESC, &desc));
        if ifsc {
            let mut body = fid(i).to_vec();
            for chunk in data.chunks(block_size) {
                let mut md5 = Md5::new();
                md5.update(chunk);
                pad_to(block_size, chunk.len(), |z| md5.update(z));
                body.extend_from_slice(&<[u8; 16]>::from(md5.finalize()));
                let mut crc = crc32fast::Hasher::new();
                crc.update(chunk);
                pad_to(block_size, chunk.len(), |z| crc.update(z));
                body.extend_from_slice(&crc.finalize().to_le_bytes());
            }
            out.extend(pkt(set_id, TYPE_IFSC, &body));
        }
    }
    out
}

/// A single-file set whose file is DECLARED huge without any of its
/// bytes existing: real IFSC entries for every block, but only the
/// one named in `real` carries the checksums of `data` (the rest are
/// zeroed and never checked). The only way to exercise a PAR2 offset
/// past `u32::MAX` in a unit test - `par2_meta` hashes the file it is
/// given, and a 4 GiB fixture is not a unit test.
fn par2_meta_declared(
    set_id: [u8; 16],
    block_size: usize,
    name: &str,
    length: u64,
    real: usize,
    data: &[u8],
) -> Vec<u8> {
    use crate::par2::{TYPE_FILEDESC, TYPE_IFSC, TYPE_MAIN};
    let mut main = Vec::new();
    main.extend_from_slice(&(block_size as u64).to_le_bytes());
    main.extend_from_slice(&1u32.to_le_bytes());
    main.extend_from_slice(&fid(0));
    let mut out = pkt(set_id, TYPE_MAIN, &main);

    let mut desc = Vec::new();
    desc.extend_from_slice(&fid(0));
    desc.extend_from_slice(&[0u8; 16]); // whole-file MD5: never settled here
    desc.extend_from_slice(&[0u8; 16]); // md5-16k: matched by NAME
    desc.extend_from_slice(&length.to_le_bytes());
    let mut nb = name.as_bytes().to_vec();
    while !nb.len().is_multiple_of(4) {
        nb.push(0);
    }
    desc.extend_from_slice(&nb);
    out.extend(pkt(set_id, TYPE_FILEDESC, &desc));

    let blocks = length.div_ceil(block_size as u64) as usize;
    let mut body = fid(0).to_vec();
    for bi in 0..blocks {
        if bi == real {
            let mut md5 = Md5::new();
            md5.update(data);
            pad_to(block_size, data.len(), |z| md5.update(z));
            body.extend_from_slice(&<[u8; 16]>::from(md5.finalize()));
            let mut crc = crc32fast::Hasher::new();
            crc.update(data);
            pad_to(block_size, data.len(), |z| crc.update(z));
            body.extend_from_slice(&crc.finalize().to_le_bytes());
        } else {
            body.extend_from_slice(&[0u8; 20]);
        }
    }
    out.extend(pkt(set_id, TYPE_IFSC, &body));
    out
}

/// A PAR2 offset past `u32::MAX` claims the block it really names.
///
/// Nothing on a 64-bit host can regress this - the test exists for
/// the linux-armv7 beta, where nightly runs the suite under qemu and
/// `usize` is 32 bits. Before the fix `add_span` computed the whole
/// span, every block start and every fragment bound in `usize`, so
/// this article at exactly 4 GiB became a span at offset 0: block
/// 4096 stayed Pending and a boundary fragment of block 0 was
/// claimed from bytes belonging four gigabytes away. Writes go out at
/// u64 `pwrite` offsets, so the real bytes never moved - the verdict
/// did, and `settle` then saw no damage to repair.
#[test]
fn a_span_past_four_gibibytes_claims_the_block_it_names() {
    const BS: usize = 1 << 20;
    const LEN: u64 = (1u64 << 32) + 4096;
    let tail = data_of(4096, 3);
    let last = (LEN.div_ceil(BS as u64) - 1) as usize;
    assert_eq!(last, 4096, "the block a 32-bit multiply cannot reach");

    let v = LiveVerifier::new(1);
    let meta = par2_meta_declared([9u8; 16], BS, "huge.bin", LEN, last, &tail);
    let sets = v.activate(&[meta.as_slice()]).expect("fixture parses");
    assert_eq!(sets[0].files[0].blocks.len(), last + 1);

    v.on_data(0, "huge.bin", LEN, 1u64 << 32, &tail);
    assert_eq!(
        v.live_counts(),
        (1, 0),
        "the last block hashes clean from its own bytes"
    );
    let (peak, spilled) = v.partials_stats();
    assert_eq!(
        (peak, spilled),
        (0, 0),
        "and nothing was held as a fragment of some other block"
    );
}

/// The head capture is in file coordinates too: an article at 4 GiB +
/// 16 is not the head of the file. `offset as usize` wrapped it to 16
/// on a 32-bit target and captured those bytes as the first sixteen
/// of the file, which is what `md5_16k` matching then judged.
#[test]
fn the_head_capture_ignores_an_article_past_four_gibibytes() {
    const BS: usize = 1 << 20;
    const LEN: u64 = (1u64 << 32) + 4096;
    let tail = data_of(4096, 4);
    let last = (LEN.div_ceil(BS as u64) - 1) as usize;
    let v = LiveVerifier::new(1);
    let meta = par2_meta_declared([9u8; 16], BS, "huge.bin", LEN, last, &tail);
    v.activate(&[meta.as_slice()]).expect("fixture parses");
    // Before activation matters not at all here: capture_head runs on
    // every span, and this one is far past the head either way.
    v.on_data(0, "huge.bin", LEN, (1u64 << 32) + 16, &tail);
    assert!(
        v.slots[0].lock_ok().head.is_none(),
        "no head buffer was opened for a span past the head"
    );
}

fn data_of(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn active_verifier(files: &[(&str, &[u8])], bs: usize) -> (LiveVerifier, Arc<Par2Set>) {
    let v = LiveVerifier::new(files.len());
    let meta = par2_meta([9u8; 16], bs, files, true);
    let sets = v.activate(&[meta.as_slice()]).expect("fixture parses");
    assert_eq!(sets.len(), 1, "one input, one set");
    (v, sets.into_iter().next().unwrap())
}

/// The happy path: whole-file spans arrive after activation, every
/// block hashes from the decode buffer, settle reads back nothing.
#[test]
fn in_stream_verify_whole_spans() {
    let data = data_of(2048 + 100, 1); // 3 blocks, short last
    let (v, set) = active_verifier(&[("a.bin", &data)], 1024);
    assert_eq!(set.block_size, 1024);
    assert_eq!(set.files[0].blocks.len(), 3);
    assert_eq!(v.sets().len(), 1);

    assert!(!v.slot_in_set(0), "unmatched slot is not in the set");
    v.on_data(0, "a.bin", data.len() as u64, 0, &data);
    assert!(v.slot_in_set(0));
    assert!(
        v.delegates_integrity(0),
        "matched + full-MD5 mode delegates"
    );
    v.set_fast_verify(true);
    assert!(!v.delegates_integrity(0), "fast mode blocks delegation");
    v.set_lean(true);
    assert!(v.delegates_integrity(0), "lean opts back in");
    v.set_fast_verify(false);
    v.set_lean(false);

    let (live, bad) = v.live_counts();
    assert_eq!((live, bad), (3, 0));
    let r = v.finish_slot(0, None).expect("matched slot reports");
    assert!(r.all_ok(), "{r:?}");
    assert_eq!(r.par2_name.as_deref(), Some("a.bin"));
    assert_eq!(r.total_blocks, 3);
    assert_eq!(r.live_blocks, 3);
    assert_eq!(r.readback_blocks, 0);
    assert_eq!(r.length, data.len() as u64);
    assert!(v.unclaimed_files().is_empty());
    let (peak, spilled) = v.partials_stats();
    assert_eq!((peak, spilled), (0, 0));
}

/// The instrument-first reuse-geometry census counts what it claims:
/// only a decoder-fresh span under fast verify that is exactly one
/// untrimmed, block-aligned PAR2 block. Everything else is a span
/// seen and nothing more.
///
/// The short FINAL block still qualifies - its padded IFSC CRC32
/// follows from the article's own by zero-extension (`crc32_zeros`),
/// which is where the reuse would splice in, not a second hash.
#[test]
fn crc_reuse_geometry_counts_exact_blocks_only() {
    let data = data_of(2048 + 100, 5); // blocks of 1024 / 1024 / 100
    let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
    v.set_fast_verify(true);

    // Exactly block 0, untrimmed, decoder-fresh: the geometry in
    // question, and the only thing that may ever count.
    v.on_data(0, "a.bin", data.len() as u64, 0, &data[..1024]);
    let g = v.crc_reuse_geometry();
    assert_eq!((g.spans, g.qualifying), (1, 1), "{g:?}");
    assert_eq!((g.spans_bytes, g.qualifying_bytes), (1024, 1024), "{g:?}");

    // The short last block qualifies too (see the note above).
    v.on_data(0, "a.bin", data.len() as u64, 2048, &data[2048..]);
    assert_eq!(v.crc_reuse_geometry().qualifying, 2);

    // Aligned to no block boundary: two half-blocks, neither whole.
    v.on_data(0, "a.bin", data.len() as u64, 512, &data[512..1536]);
    // Half a block: block-aligned, but the CRC covers half the bytes.
    v.on_data(0, "a.bin", data.len() as u64, 1024, &data[1024..1536]);
    // yEnc padding past the PAR2 length: the clamp trims the span, so
    // the article's CRC covers bytes the block does not.
    let overrun = data_of(200, 6);
    v.on_data(0, "a.bin", data.len() as u64, 2048, &overrun);
    // A span with no wire CRC behind it has no CRC to reuse.
    v.on_data_unverified(0, "a.bin", data.len() as u64, 0, &data[..1024]);
    // And under full MD5 there is no CRC-only claim to shortcut.
    v.set_fast_verify(false);
    v.on_data(0, "a.bin", data.len() as u64, 0, &data[..1024]);

    let g = v.crc_reuse_geometry();
    assert_eq!(g.qualifying, 2, "a disqualified span was counted: {g:?}");
    assert_eq!(g.spans, 7, "every mapped span is seen: {g:?}");
    assert_eq!(g.qualifying_bytes, 1024 + 100, "{g:?}");
    // The process-global twin takes every bump this run made, and
    // whatever the rest of the suite made - a lower bound, since the
    // unit suite runs its tests as threads of one process.
    assert!(crc_reuse_geometry_total().spans >= g.spans);
}

/// Boundary blocks under full-MD5 mode accumulate byte partials; the
/// completing span routes them through the full-MD5 check, and the
/// budget accounting returns to zero.
#[test]
fn boundary_blocks_byte_partials() {
    let data = data_of(2048, 2);
    let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
    v.on_data(0, "a.bin", 2048, 0, &data[..700]);
    let (peak, _) = v.partials_stats();
    assert_eq!(peak, 1024, "one boundary block's bytes are held");
    v.on_data(0, "a.bin", 2048, 700, &data[700..]);
    let r = v.finish_slot(0, None).unwrap();
    assert!(r.all_ok(), "{r:?}");
    assert_eq!(r.live_blocks, 2, "both blocks claimed in-stream");
    assert_eq!(r.readback_blocks, 0);
}

/// Fast verify routes boundary fragments through CRC parts (B1): no
/// bytes held, the short last block zero-pads via crc32_zeros, and
/// out-of-order fragments still compose.
#[test]
fn fast_verify_crc_parts_compose() {
    let data = data_of(2048 + 100, 3); // short last block
    let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
    v.set_fast_verify(true);
    // Out of order, straddling every block boundary.
    v.on_data(0, "a.bin", 2148, 1100, &data[1100..]);
    v.on_data(0, "a.bin", 2148, 0, &data[..700]);
    v.on_data(0, "a.bin", 2148, 700, &data[700..1100]);
    let (peak, spilled) = v.partials_stats();
    assert_eq!((peak, spilled), (0, 0), "CRC parts hold no bytes");
    let r = v.finish_slot(0, None).unwrap();
    assert!(r.all_ok(), "{r:?}");
    assert_eq!(r.live_blocks, 3);
    assert_eq!(r.readback_blocks, 0);
}

/// A corrupted span claims Bad in-stream, and the report names the
/// block. summarize_damage folds it into the repair plan's view.
#[test]
fn corrupt_block_reported() {
    let data = data_of(3072, 4);
    let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
    let mut wrong = data.clone();
    wrong[1500] ^= 0xFF; // damage block 1 only
    v.on_data(0, "a.bin", 3072, 0, &wrong);
    let (live, bad) = v.live_counts();
    assert_eq!((live, bad), (3, 1));
    let r = v.finish_slot(0, None).unwrap();
    assert!(!r.all_ok());
    assert_eq!(r.bad_blocks, vec![1]);
    let d = summarize_damage(std::iter::once(&r));
    assert_eq!(d.bad_blocks, 1);
    assert_eq!(d.damaged_files, vec!["a.bin".to_string()]);
}

/// M15 budget: a boundary block bigger than the global cap is never
/// allocated - it spills to settle read-back, which full-MD5s it off
/// disk. Also the plain finish_slot(path) read-back route.
#[test]
fn partials_budget_spills_to_readback() {
    let bs = 2 << 20; // 2 MiB blocks against the 1 MiB cap floor
    let data = data_of(2 * bs, 5);
    let v = LiveVerifier::with_partials_cap(1, 1);
    let meta = par2_meta([9u8; 16], bs, &[("a.bin", &data)], true);
    v.activate(&[meta.as_slice()]).unwrap();
    v.on_data(0, "a.bin", data.len() as u64, 0, &data[..1 << 20]);
    let (peak, spilled) = v.partials_stats();
    assert_eq!(peak, 0, "over-budget block was never allocated");
    assert_eq!(spilled, 1);

    let dir = std::env::temp_dir().join(format!("nzbkit-live-spill-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("a.bin");
    std::fs::write(&path, &data).unwrap();
    let r = v.finish_slot(0, Some(&path)).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(r.all_ok(), "{r:?}");
    assert_eq!(r.readback_blocks, 2, "both blocks settled off disk");
    assert_eq!(r.live_blocks, 0);
}

/// A block bigger than the 8 MiB read-back chunk takes the streamed
/// path (chunked read, composed CRC padding, then MD5) - and agrees
/// with the single-buffer verdict.
#[test]
fn oversized_block_readback_is_chunked() {
    let bs = 16 << 20;
    let data = data_of(9 << 20, 6); // one 9 MiB block, 7 MiB padding
    let v = LiveVerifier::new(1);
    let meta = par2_meta([9u8; 16], bs, &[("big.bin", &data)], true);
    v.activate(&[meta.as_slice()]).unwrap();
    v.set_name_hint(0, "big.bin");
    let ok = v
        .finish_slot_from(
            0,
            ReadAt::Reader(&|off, buf| {
                let off = off as usize;
                buf.copy_from_slice(&data[off..off + buf.len()]);
                Ok(())
            }),
        )
        .unwrap();
    assert!(ok.all_ok(), "{ok:?}");
    assert_eq!(ok.readback_blocks, 1);

    // The same block with one corrupt byte fails the streamed check.
    let mut wrong = data.clone();
    wrong[8 << 20] ^= 1;
    let v2 = LiveVerifier::new(1);
    v2.activate(&[meta.as_slice()]).unwrap();
    v2.set_name_hint(0, "big.bin");
    let bad = v2
        .finish_slot_from(
            0,
            ReadAt::Reader(&|off, buf| {
                let off = off as usize;
                buf.copy_from_slice(&wrong[off..off + buf.len()]);
                Ok(())
            }),
        )
        .unwrap();
    assert_eq!(bad.bad_blocks, vec![0]);
}

/// Pre-activation spans: heads are captured while Waiting, the spans
/// coalesce (overlaps merged, contained spans dropped), and the
/// backfill re-feed verifies them without settle read-back.
#[test]
fn pre_activation_backfill_roundtrip() {
    let data = data_of(2048, 7);
    let v = LiveVerifier::new(1);
    v.on_data(0, "a.bin", 2048, 0, &data[..800]);
    v.on_data(0, "a.bin", 2048, 600, &data[600..1400]); // overlap
    v.on_data(0, "a.bin", 2048, 700, &data[700..900]); // contained
    v.on_data(0, "a.bin", 2048, 1400, &data[1400..]);
    let meta = par2_meta([9u8; 16], 1024, &[("a.bin", &data)], true);
    v.activate(&[meta.as_slice()]).unwrap();
    let (spans, how) = v.take_pre_spans(0);
    assert_eq!(how, PreSpanSrc::Backfill);
    assert_eq!(spans, vec![(0, 2048)], "coalesced to one span");
    for &(off, len) in &spans {
        let (off, len) = (off as usize, len as usize);
        v.on_data_backfill(0, "a.bin", 2048, off as u64, &data[off..off + len]);
    }
    let r = v.finish_slot(0, None).unwrap();
    assert!(r.all_ok(), "{r:?}");
    assert_eq!(r.readback_blocks, 0, "backfill left nothing to settle");
}

/// Crash-resume seeds split at the u32 boundary and force the whole
/// slot onto the Disk backfill route.
#[test]
fn resume_seeds_split_and_route_to_disk() {
    let v = LiveVerifier::new(1);
    let big = (u32::MAX as u64) + 10;
    v.seed_pre_spans(0, &[(0, big), (big + 100, 50)]);
    let (spans, how) = v.take_pre_spans(0);
    assert_eq!(how, PreSpanSrc::Disk);
    assert_eq!(spans, vec![(0, big), (big + 100, 50)]);
}

/// Obfuscated posts: the yEnc name lies (or is absent), and the slot
/// still claims its PAR2 file through the md5-16k of its head.
#[test]
fn md5_16k_matches_obfuscated_slot() {
    let data = data_of(3000, 8); // < 16 KiB: head is the whole file
    let (v, _set) = active_verifier(&[("real-name.bin", &data)], 1024);
    v.on_data(0, "jibberish123", 3000, 0, &data);
    assert!(v.slot_in_set(0), "claimed via md5-16k despite the name");
    let r = v.finish_slot(0, None).unwrap();
    assert!(r.all_ok(), "{r:?}");
    assert_eq!(r.par2_name.as_deref(), Some("real-name.bin"));
}

/// Codex sweep 13 Aug R1: slots differing only by case must never
/// cross-claim each other's descriptors. With FileDesc order
/// [a.txt, A.txt] the first slot to match used to take the OTHER
/// file's descriptor case-insensitively (one first-hit loop over
/// exact and approximate classes), and the second slot then claimed
/// what was left - both crossed, each verifying and publishing
/// under the other's name.
#[test]
fn same_name_different_case_slots_never_cross_claim() {
    let a = data_of(3000, 21);
    let b = data_of(3000, 22);
    // Adversarial descriptor order: the lowercase twin first.
    let (v, _set) = active_verifier(&[("a.txt", &a), ("A.txt", &b)], 1024);
    // The uppercase slot arrives first.
    v.on_data(0, "A.txt", 3000, 0, &b);
    v.on_data(1, "a.txt", 3000, 0, &a);
    let r0 = v.finish_slot(0, None).unwrap();
    let r1 = v.finish_slot(1, None).unwrap();
    assert_eq!(r0.par2_name.as_deref(), Some("A.txt"), "crossed claim");
    assert_eq!(r1.par2_name.as_deref(), Some("a.txt"), "crossed claim");
    assert!(r0.all_ok() && r1.all_ok(), "{r0:?} {r1:?}");
}

/// ...and when the name tier is genuinely AMBIGUOUS - one slot
/// whose sanitized name matches two descriptors - FileDesc order
/// must not pick the winner. The name tier declines and the
/// md5-16k tier settles it by content.
#[test]
fn ambiguous_sanitized_names_settle_by_content_not_desc_order() {
    let a = data_of(3000, 23);
    let b = data_of(3000, 24);
    // Both descriptor names sanitize to "a_b.txt".
    let (v, _set) = active_verifier(&[("a/b.txt", &a), ("a\\b.txt", &b)], 1024);
    v.on_data(0, "a_b.txt", 3000, 0, &b);
    let r = v.finish_slot(0, None).unwrap();
    assert_eq!(
        r.par2_name.as_deref(),
        Some("a\\b.txt"),
        "content, not descriptor order, must decide the ambiguous claim"
    );
    assert!(r.all_ok(), "{r:?}");
}

/// 14 Aug sweep: an AMBIGUOUS name decline must not latch the slot
/// unmatchable. Slot 0's sanitized name matches two descriptors and
/// its head matches neither (damage inside the first 16k), so both
/// tiers decline - but the candidates are real, and once the twin
/// slot claims its descriptor by exact name the ambiguity resolves
/// to unique. The latch froze the slot forever and downgraded a
/// patchable file to wholly-missing.
#[test]
fn ambiguous_decline_stays_retryable_until_twin_resolves_it() {
    let a = data_of(3000, 25);
    let b = data_of(3000, 26);
    let corrupt = data_of(3000, 27); // head matches neither descriptor
    let (v, _set) = active_verifier(&[("a/b.txt", &a), ("a\\b.txt", &b)], 1024);
    // Slot 0: ambiguous name, corrupt head - both tiers decline.
    v.on_data(0, "a_b.txt", 3000, 0, &corrupt);
    assert!(!v.slot_in_set(0), "nothing claimable yet");
    // Slot 1 claims a/b.txt by exact name, making slot 0's
    // approximate match unique.
    v.on_data(1, "a/b.txt", 3000, 0, &a);
    assert!(v.slot_in_set(1));
    // Slot 0's next span retries the match and must now claim.
    v.on_data(0, "a_b.txt", 3000, 0, &corrupt);
    assert!(
        v.slot_in_set(0),
        "ambiguity resolved by the twin's claim - the slot must not stay latched unmatchable"
    );
}

/// A slot whose name AND head both match nothing (nfo/sfv/sample)
/// goes unmatchable, stops rescanning, reports None - and its PAR2
/// files stay on the unclaimed list.
#[test]
fn unmatchable_slot_reports_none() {
    let data = data_of(2048, 9);
    let stranger = data_of(2048, 10);
    let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
    v.on_data(0, "not-in-set.nfo", 2048, 0, &stranger);
    assert!(!v.slot_in_set(0));
    assert!(!v.delegates_integrity(0));
    v.on_data(0, "not-in-set.nfo", 2048, 0, &stranger); // early-out path
    assert!(v.finish_slot(0, None).is_none());
    assert_eq!(v.unclaimed_files(), vec!["a.bin".to_string()]);
}

/// No IFSC packet: the slot settles on the whole-file MD5, engaged
/// gates release either way, and a mismatch reads as one bad block.
#[test]
fn no_ifsc_settles_on_whole_file_md5() {
    let data = data_of(5000, 11);
    let v = LiveVerifier::new(2);
    let g = VerifyGate::new(2);
    v.set_gate(g.clone());
    let meta = par2_meta([9u8; 16], 1024, &[("a.bin", &data)], false);
    v.activate(&[meta.as_slice()]).unwrap();
    // A span arriving on a matched no-IFSC slot is a no-op (no block
    // map to claim against), but it does claim the file.
    v.on_data(0, "a.bin", 5000, 0, &data);
    assert_eq!(g.watermark(0), 0, "claim engaged the gate");
    let ok = v
        .finish_slot_from(
            0,
            ReadAt::Reader(&|off, buf| {
                let off = off as usize;
                buf.copy_from_slice(&data[off..off + buf.len()]);
                Ok(())
            }),
        )
        .unwrap();
    assert!(ok.all_ok(), "{ok:?}");
    assert_eq!(ok.total_blocks, 0);
    assert_eq!(g.watermark(0), u64::MAX, "no-IFSC settle releases the gate");

    // Missing source: the whole-file check cannot pass, and the
    // verdict is damage rather than a hang.
    let v2 = LiveVerifier::new(1);
    v2.activate(&[meta.as_slice()]).unwrap();
    v2.set_name_hint(0, "a.bin");
    let bad = v2.finish_slot(0, None).unwrap();
    assert_eq!(bad.bad_blocks, vec![0]);
    assert!(!bad.all_ok());
}

/// §94 B: the published watermark tracks the contiguous Ok prefix -
/// an out-of-order claim publishes nothing until the prefix catches
/// up, and a fully verified slot publishes MAX.
#[test]
fn gate_watermark_tracks_ok_prefix() {
    let data = data_of(3072, 12);
    let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
    let g = VerifyGate::new(1);
    v.set_gate(g.clone());
    v.on_data(0, "a.bin", 3072, 2048, &data[2048..]); // block 2 first
    assert_eq!(g.watermark(0), 0, "no contiguous prefix yet");
    v.on_data(0, "a.bin", 3072, 0, &data[..1024]);
    assert_eq!(g.watermark(0), 1024, "prefix = block 0");
    v.on_data(0, "a.bin", 3072, 1024, &data[1024..2048]);
    assert_eq!(g.watermark(0), u64::MAX, "every block verified");
}

/// Mixed trust on a CRC-parts block: a fragment that cannot claim
/// CRC-only (settle/disk source) may not lend bytes to someone
/// else's CRC-only claim - the block abandons to read-back.
#[test]
fn mixed_trust_abandons_crc_partial() {
    let data = data_of(2048, 13);
    let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
    v.set_fast_verify(true);
    v.on_data(0, "a.bin", 2048, 0, &data[..700]); // CRC fragment
    v.on_data_from_disk(0, "a.bin", 2048, 700, &data[700..1024]);
    let (_, spilled) = v.partials_stats();
    assert_eq!(spilled, 1, "the CRC partial was abandoned");
    // The rest arrives whole; block 1 claims, block 0 reads back.
    v.on_data(0, "a.bin", 2048, 1024, &data[1024..]);
    let dir = std::env::temp_dir().join(format!("nzbkit-live-mixed-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("a.bin");
    std::fs::write(&path, &data).unwrap();
    let r = v.finish_slot(0, Some(&path)).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(r.all_ok(), "{r:?}");
    assert_eq!(r.readback_blocks, 1);
}

/// An overlapping re-feed cannot compose CRCs losslessly - the block
/// abandons rather than guessing, then a whole-block span claims it.
#[test]
fn overlapping_crc_refeed_abandons_then_recovers() {
    let data = data_of(2048, 14);
    let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
    v.set_fast_verify(true);
    v.on_data(0, "a.bin", 2048, 0, &data[..700]);
    v.on_data(0, "a.bin", 2048, 0, &data[..700]); // exact overlap
    let (_, spilled) = v.partials_stats();
    assert_eq!(spilled, 1);
    v.on_data(0, "a.bin", 2048, 0, &data[..1024]); // whole block 0
    v.on_data(0, "a.bin", 2048, 1024, &data[1024..]);
    let r = v.finish_slot(0, None).unwrap();
    assert!(r.all_ok(), "{r:?}");
}

/// set_off: spans are dropped, no set, no reports - and Waiting
/// (never activated) reports None the same way.
#[test]
fn off_and_waiting_report_nothing() {
    let v = LiveVerifier::new(1);
    assert!(v.finish_slot(0, None).is_none(), "Waiting reports None");
    assert!(v.sets().is_empty());
    v.set_off();
    v.on_data(0, "a.bin", 100, 0, &[0u8; 100]);
    assert!(v.finish_slot(0, None).is_none());
    assert!(!v.slot_in_set(0));
    assert!(!v.delegates_integrity(0));
    assert!(v.unclaimed_files().is_empty());
}

/// set_name_hint seeds a name for a slot no article will flow
/// through, and finish_slot's last-chance match claims on it.
#[test]
fn name_hint_enables_last_chance_match() {
    let data = data_of(2048, 15);
    let (v, _set) = active_verifier(&[("a.bin", &data)], 1024);
    v.set_name_hint(0, "a.bin");
    v.set_name_hint(0, "loser.bin"); // first hint wins
    let dir = std::env::temp_dir().join(format!("nzbkit-live-hint-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("a.bin");
    std::fs::write(&path, &data).unwrap();
    let r = v.finish_slot(0, Some(&path)).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(r.all_ok(), "{r:?}");
    assert_eq!(r.readback_blocks, 2, "every block settled off disk");
    assert_eq!(r.live_blocks, 0);
}

/// A head restarted by a late-learned file size still md5-16k
/// matches: the first article carried no size, the second did.
#[test]
fn head_restarts_when_size_learned_late() {
    let data = data_of(1000, 16);
    let v = LiveVerifier::new(1);
    v.on_data(0, "", 0, 0, &data[..500]); // size unknown: 16 KiB head
    v.on_data(0, "", 1000, 0, &data[..500]); // size learned: restart
    v.on_data(0, "", 1000, 500, &data[500..]);
    let meta = par2_meta([9u8; 16], 1024, &[("real.bin", &data)], true);
    v.activate(&[meta.as_slice()]).unwrap();
    // Backfill re-feed completes the head and matches via md5-16k.
    let (spans, how) = v.take_pre_spans(0);
    assert_eq!(how, PreSpanSrc::Backfill);
    for &(off, len) in &spans {
        let (off, len) = (off as usize, len as usize);
        v.on_data_backfill(0, "", 1000, off as u64, &data[off..off + len]);
    }
    let r = v.finish_slot(0, None).unwrap();
    assert!(r.all_ok(), "{r:?}");
    assert_eq!(r.par2_name.as_deref(), Some("real.bin"));
}

/// TODO 311: mixed recovery sets are ALL adopted, largest first.
///
/// This test used to be `pick_set_prefers_larger_of_mixed`, and it
/// pinned the defect: two sets in, one out, the two-file one kept
/// because `max_by_key` says so. It moves with the fix, which is what
/// §311 said it would do - its existence never meant the discard had
/// been considered and chosen for a post whose sets are COMPLEMENTS
/// rather than RIVALS.
///
/// Order is asserted, not incidental: largest first, so the surfaces
/// that still want one representative set read the same one the old
/// code adopted, and ties break on set id so the answer does not
/// depend on which `.par2` finished downloading first.
#[test]
fn every_mixed_recovery_set_is_adopted_largest_first() {
    let a = data_of(1024, 17);
    let b = data_of(1024, 18);
    let one = par2_meta([1u8; 16], 1024, &[("solo.bin", &a)], true);
    let two = par2_meta([2u8; 16], 1024, &[("x.bin", &a), ("y.bin", &b)], true);
    let sets = pick_sets(&[one.as_slice(), two.as_slice()]).expect("both sets are adopted");
    assert_eq!(sets.len(), 2, "seventeen of eighteen used to vanish here");
    assert_eq!(sets[0].files.len(), 2);
    assert_eq!(sets[0].recovery_set_id, [2u8; 16]);
    assert_eq!(sets[1].files.len(), 1);
    assert_eq!(sets[1].recovery_set_id, [1u8; 16]);
    // Input order must not decide the answer - it is download order.
    let flipped = pick_sets(&[two.as_slice(), one.as_slice()]).unwrap();
    assert_eq!(
        flipped
            .iter()
            .map(|s| s.recovery_set_id)
            .collect::<Vec<_>>(),
        sets.iter().map(|s| s.recovery_set_id).collect::<Vec<_>>(),
    );
    assert!(matches!(
        pick_sets(&[b"not a par2 at all".as_slice()]),
        Err(Par2Error::NoMainPacket)
    ));
    // activate() surfaces parse failures without adopting a plan.
    let v = LiveVerifier::new(1);
    assert!(v.activate(&[b"garbage".as_slice()]).is_err());
    assert!(v.sets().is_empty());
}

/// #63's shape in miniature: one set PER FILE, every file claimed and
/// verified, and each slot attributed to the set that can heal it.
///
/// The block sizes DIFFER on purpose. That is the property a
/// synthetic merged set could not hold - `Par2Set::block_size` is one
/// field - and it is why the sets are kept as a list.
#[test]
fn a_set_per_file_verifies_every_file_under_its_own_block_size() {
    let a = data_of(2048, 21);
    let b = data_of(1536, 22);
    let one = par2_meta([1u8; 16], 1024, &[("a.bin", &a)], true);
    let two = par2_meta([2u8; 16], 512, &[("b.bin", &b)], true);
    let v = LiveVerifier::new(2);
    let sets = v
        .activate(&[one.as_slice(), two.as_slice()])
        .expect("both sets adopted");
    assert_eq!(sets.len(), 2);
    v.on_data(0, "a.bin", a.len() as u64, 0, &a);
    v.on_data(1, "b.bin", b.len() as u64, 0, &b);
    let ra = v.finish_slot(0, None).unwrap();
    let rb = v.finish_slot(1, None).unwrap();
    assert_eq!(ra.par2_name.as_deref(), Some("a.bin"));
    assert_eq!(rb.par2_name.as_deref(), Some("b.bin"));
    assert!(ra.all_ok() && rb.all_ok(), "{ra:?} {rb:?}");
    assert_eq!(ra.total_blocks, 2, "a.bin is 2 blocks of 1024");
    assert_eq!(rb.total_blocks, 3, "b.bin is 3 blocks of 512");
    assert!(v.unclaimed_files().is_empty(), "both sets fully claimed");
    // Each slot names the set whose parity speaks for it.
    let (sa, sb) = (v.slot_set(0).unwrap(), v.slot_set(1).unwrap());
    assert_ne!(sa, sb);
    assert_eq!(sets[sa].recovery_set_id, [1u8; 16]);
    assert_eq!(sets[sb].recovery_set_id, [2u8; 16]);
}

/// TODO 311 follow-on B: live damage charged to the set whose parity
/// can heal it, and the slot map that both arms read it through.
///
/// `live_counts` answers the JOB's total, which is the right figure for
/// a dashboard gauge and the wrong one for a margin: on a per-file-set
/// post it would charge every set its siblings' damage, so no set's
/// on-hand parity could ever clear its own 2x ceiling.
#[test]
fn live_damage_is_charged_to_the_set_that_can_heal_it() {
    let a = data_of(2048, 31);
    let b = data_of(1536, 32);
    let one = par2_meta([1u8; 16], 1024, &[("a.bin", &a)], true);
    let two = par2_meta([2u8; 16], 512, &[("b.bin", &b)], true);
    let v = LiveVerifier::new(2);
    let sets = v
        .activate(&[one.as_slice(), two.as_slice()])
        .expect("both sets adopted");
    assert_eq!(sets.len(), 2);
    // b.bin arrives with its first block corrupted; a.bin is clean.
    let mut bad = b.clone();
    bad[0] ^= 0xff;
    v.on_data(0, "a.bin", a.len() as u64, 0, &a);
    v.on_data(1, "b.bin", b.len() as u64, 0, &bad);
    let (_, job_bad) = v.live_counts();
    assert!(job_bad > 0, "the fixture must produce live damage");
    let by_set = v.live_bad_by_set();
    assert_eq!(by_set.len(), 2);
    assert_eq!(
        by_set.iter().sum::<u64>(),
        job_bad,
        "no block charged twice"
    );
    let sb = v.slot_set(1).unwrap();
    assert_eq!(by_set[sb], job_bad, "all of it belongs to b.bin's set");
    assert_eq!(by_set[1 - sb], 0, "and none of it to its sibling");
    // The batch map is the singular's answer for every slot at once -
    // both arms re-decide five times a second and read the whole map.
    assert_eq!(
        v.slot_sets(),
        vec![v.slot_set(0), v.slot_set(1)],
        "slot_sets must agree with slot_set, slot for slot"
    );
}

/// Neither per-set accessor may claim anything before a set is active:
/// an empty answer is what tells the callers there is nothing to
/// decide, and a `vec![0]` would read as a live set carrying no damage.
#[test]
fn the_per_set_maps_are_empty_until_a_set_is_active() {
    let v = LiveVerifier::new(2);
    assert!(v.sets().is_empty());
    assert!(v.live_bad_by_set().is_empty());
    assert_eq!(v.slot_sets(), vec![None, None]);
}

/// Two slots, two files: claims don't collide, and per-slot verdicts
/// stay independent.
#[test]
fn two_slots_claim_distinct_files() {
    let a = data_of(2048, 19);
    let b = data_of(1500, 20);
    let (v, _set) = active_verifier(&[("a.bin", &a), ("b.bin", &b)], 1024);
    v.on_data(1, "b.bin", 1500, 0, &b);
    v.on_data(0, "a.bin", 2048, 0, &a);
    let ra = v.finish_slot(0, None).unwrap();
    let rb = v.finish_slot(1, None).unwrap();
    assert_eq!(ra.par2_name.as_deref(), Some("a.bin"));
    assert_eq!(rb.par2_name.as_deref(), Some("b.bin"));
    assert!(ra.all_ok() && rb.all_ok());
    assert!(v.unclaimed_files().is_empty());
}

// ===== B6 differential: the indexed matcher vs the pre-B6 linear =====
// ===== drain. Same scripted sequence through both, every visible  =====
// ===== outcome must agree at every step.                          =====

/// One matcher step: optionally learn a name (the `on_data` rule: only
/// if none yet, only if non-empty), optionally feed head bytes from
/// offset 0 with a declared file size, then attempt a match under the
/// caller guards (skip if claimed or latched unmatchable).
type Step<'a> = (usize, Option<&'a str>, Option<(&'a [u8], u64)>);

fn mk_active(files: &[(&str, &[u8])], bs: usize) -> Active {
    let v = LiveVerifier::new(0);
    let meta = par2_meta([7u8; 16], bs, files, true);
    Active::new(v.activate(&[meta.as_slice()]).expect("fixture parses"))
}

#[expect(clippy::type_complexity)]
fn run_world(
    files: &[(&str, &[u8])],
    steps: &[Step],
    indexed: bool,
) -> (Vec<Option<usize>>, Vec<(Option<usize>, bool)>, Vec<bool>) {
    let active = mk_active(files, 512);
    let nslots = steps.iter().map(|s| s.0 + 1).max().unwrap_or(0);
    let mut slots: Vec<SlotState> = (0..nslots).map(|_| SlotState::empty()).collect();
    let mut rets = Vec::new();
    for &(si, name, head) in steps {
        let s = &mut slots[si];
        if let Some(n) = name
            && s.name.is_none()
            && !n.is_empty()
        {
            s.name = Some(n.to_string());
        }
        if let Some((bytes, size)) = head {
            if s.file_size == 0 {
                s.file_size = size;
            }
            s.capture_head(0, bytes);
        }
        let r = if s.file.is_some() || s.unmatchable {
            false
        } else if indexed {
            s.try_match(si, &active)
        } else {
            s.try_match_linear(si, &active)
        };
        rets.push(r);
    }
    let claimed = active.claimed.lock_ok().clone();
    let state = slots.iter().map(|s| (s.file, s.unmatchable)).collect();
    (claimed, state, rets)
}

fn assert_matchers_agree(files: &[(&str, &[u8])], steps: &[Step]) {
    let a = run_world(files, steps, true);
    let b = run_world(files, steps, false);
    assert_eq!(
        a,
        b,
        "indexed vs linear diverged; files {:?} steps {:?}",
        files.iter().map(|f| f.0).collect::<Vec<_>>(),
        steps
            .iter()
            .map(|(s, n, h)| (*s, *n, h.map(|(b, sz)| (b.len(), sz))))
            .collect::<Vec<_>>()
    );
}

/// The Codex-R1 case-cross shape plus duplicates: exact must beat
/// approximate in both impls whichever arrival order, and duplicate
/// names must claim in FileDesc order.
#[test]
fn differential_exact_precedence_and_duplicates() {
    let d: Vec<Vec<u8>> = (0..4).map(|i| data_of(700, i as u8 + 40)).collect();
    let files: &[(&str, &[u8])] = &[
        ("a.txt", &d[0]),
        ("A.txt", &d[1]),
        ("dup.bin", &d[2]),
        ("dup.bin", &d[3]),
    ];
    for order in [[0usize, 1, 2, 3], [3, 2, 1, 0], [1, 0, 3, 2]] {
        let names = ["A.txt", "a.txt", "dup.bin", "dup.bin"];
        let steps: Vec<Step> = order.iter().map(|&s| (s, Some(names[s]), None)).collect();
        assert_matchers_agree(files, &steps);
    }
}

/// Ambiguity must stay retryable identically: a slot whose name folds
/// onto two descriptors (one via case, one via sanitize) claims nothing
/// and never latches, then claims once a twin's exact match removes the
/// other candidate.
#[test]
fn differential_ambiguity_across_both_key_classes() {
    let d: Vec<Vec<u8>> = (0..2).map(|i| data_of(600, i as u8 + 50)).collect();
    // "ab.txt." matches "AB.TXT." case-folded and "ab.txt" sanitized.
    let files: &[(&str, &[u8])] = &[("AB.TXT.", &d[0]), ("ab.txt", &d[1])];
    let junk = data_of(600, 99);
    let steps: &[Step] = &[
        // Ambiguous, complete head that md5-matches nothing: no claim,
        // and the latch must NOT set (retryable ambiguity).
        (0, Some("ab.txt."), Some((&junk, 600))),
        (1, Some("AB.TXT."), None), // exact claims descriptor 0
        (0, None, None),            // retry: now unique via sanitize
    ];
    assert_matchers_agree(files, steps);
}

/// Sanitize-tier variants (separators, trims) and the md5-16k
/// fallback + unmatchable latch, same answers from both impls.
#[test]
fn differential_sanitize_and_md5_paths() {
    let d: Vec<Vec<u8>> = (0..3).map(|i| data_of(900, i as u8 + 60)).collect();
    let files: &[(&str, &[u8])] = &[("al/pha.bin", &d[0]), ("beta.bin", &d[1]), ("x", &d[2])];
    let junk = data_of(900, 98);
    let steps: &[Step] = &[
        (0, Some("al_pha.bin"), None),               // sanitize-only hit
        (1, Some(" beta.bin"), None),                // leading space, sanitize hit
        (2, Some("obfuscated"), Some((&d[2], 900))), // md5-16k claim
        (3, Some("junk.nfo"), Some((&junk, 900))),   // full miss: latch
        (3, None, None),                             // latched: caller skips
        (4, Some(""), Some((&junk, 900))),           // nameless: md5 miss, NO latch
        (4, None, None),
    ];
    assert_matchers_agree(files, steps);
}

/// Seeded fuzz over name-variant pools (case flips, separators,
/// trailing dots, duplicates, empties) and random step orders, with
/// occasional matching or junk heads - every world pair must agree.
#[test]
fn differential_fuzz_variant_pools() {
    let mut rng = 0x9e3779b97f4a7c15u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let pool = [
        "alpha.bin",
        "Alpha.bin",
        "ALPHA.BIN",
        "alpha.bin.",
        " alpha.bin",
        "al/pha.bin",
        "al_pha.bin",
        "beta.bin",
        "beta.nfo",
        "..",
        "",
    ];
    let data: Vec<Vec<u8>> = (0..pool.len())
        .map(|i| data_of(400 + i * 37, i as u8))
        .collect();
    let junk = data_of(4096, 250);
    for _ in 0..300 {
        let nf = 2 + (next() % 7) as usize;
        let files: Vec<(&str, &[u8])> = (0..nf)
            .map(|_| {
                let p = (next() % pool.len() as u64) as usize;
                // Descriptor names must be non-empty to survive parsing;
                // fall back to a fixed name for the "" pool entry.
                let name = if pool[p].is_empty() { "x" } else { pool[p] };
                (name, data[p].as_slice())
            })
            .collect();
        let mut steps: Vec<Step> = Vec::new();
        for _ in 0..24 {
            let slot = (next() % 8) as usize;
            let name = if next() % 4 == 0 {
                None
            } else {
                Some(pool[(next() % pool.len() as u64) as usize])
            };
            let head = match next() % 5 {
                0 => {
                    let (_, d) = files[(next() % nf as u64) as usize];
                    Some((d, d.len() as u64))
                }
                1 => Some((junk.as_slice(), junk.len() as u64)),
                _ => None,
            };
            steps.push((slot, name, head));
        }
        assert_matchers_agree(&files, &steps);
    }
}
