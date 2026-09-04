//! Unit tests for [`super`] - the in-stream PAR2 verifier.
//!
//! A sibling file rather than an inline `mod tests`: live.rs sat at its
//! size-gate ceiling when this split was made (TODO 311's multi-set work
//! is what took it over; recalibrated 31 Aug 2026).
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

/// §94 B per RANGE: a block ABOVE the damage is individually vouched
/// for, and the gate says so - which is the whole of what a tail-first
/// container reader (a zip central directory, a 7z end header) needs to
/// get off the ground on a damaged post. The contiguous prefix answer
/// is unchanged underneath it.
#[test]
fn verify_gate_answers_per_range_above_the_prefix() {
    let g = VerifyGate::new(1);
    g.engage(0);
    // 10 blocks of 1,000: [0,3) Ok, 3 damaged, [4,10) Ok - the shape of
    // a container whose map sits at the tail and whose damage does not.
    let bits = g.arm_vouch(0, 10, 1000);
    for bi in [0, 1, 2, 4, 5, 6, 7, 8, 9] {
        bits.set_ok(bi);
    }
    g.advance(0, 3000); // the prefix stops at the first bad block
    assert_eq!(g.watermark(0), 3000, "the prefix is unmoved");
    assert_eq!(g.vouched_end(0, 0), 3000, "inside the prefix: the prefix");
    assert_eq!(g.vouched_end(0, 2999), 3000);
    assert_eq!(g.vouched_end(0, 3000), 3000, "the damaged block parks");
    assert_eq!(
        g.vouched_end(0, 3999),
        3999,
        "...and parks from anywhere in it"
    );
    assert_eq!(
        g.vouched_end(0, 4000),
        u64::MAX,
        "an Ok run reaching the last block ungates its tail"
    );
    assert_eq!(g.vouched_end(0, 9500), u64::MAX, "the map's own offset");
    assert_eq!(g.vouched_end(0, 10_000), u64::MAX, "past the grid");
}

/// The per-range answer STOPS at the next unvouched block rather than
/// running to the end of the file, and a run that does not reach the
/// last block answers a finite limit - the reader serves that much and
/// asks again.
#[test]
fn verify_gate_per_range_stops_at_the_next_hole() {
    let g = VerifyGate::new(1);
    g.engage(0);
    let bits = g.arm_vouch(0, 10, 1000);
    for bi in [4, 5, 6] {
        bits.set_ok(bi);
    }
    assert_eq!(g.watermark(0), 0);
    assert_eq!(g.vouched_end(0, 4000), 7000, "the run ends at block 7");
    assert_eq!(g.vouched_end(0, 6999), 7000, "asked from inside it");
    assert_eq!(g.vouched_end(0, 7000), 7000, "and block 7 itself parks");
    // A slot with no map at all is the prefix answer and nothing else -
    // an ungated run maintains no bitmap and must not start serving
    // ranges off one that does not exist.
    let g2 = VerifyGate::new(1);
    g2.engage(0);
    g2.advance(0, 500);
    assert_eq!(g2.vouched_end(0, 500), 500, "no map: park at the prefix");
    assert_eq!(g2.vouched_end(0, 100), 500);
}

/// A rebind throws the block grid away, and the map goes with it: a
/// reader still holding the old `Arc` sees NOTHING vouched rather than
/// a verdict about a descriptor this slot no longer holds. Clearing is
/// the safe direction in the one way that matters - it parks a reader,
/// it never serves an unvouched byte.
#[test]
fn verify_gate_rearming_clears_the_map_a_reader_still_holds() {
    let g = VerifyGate::new(1);
    g.engage(0);
    let old = g.arm_vouch(0, 10, 1000);
    for bi in 0..10 {
        old.set_ok(bi);
    }
    assert_eq!(g.vouched_end(0, 5000), u64::MAX);
    // The slot rebinds against a different descriptor.
    let fresh = g.arm_vouch(0, 4, 2500);
    assert_eq!(
        old.vouched_end(5000),
        5000,
        "the handle a reader kept answers nothing-vouched"
    );
    assert_eq!(g.vouched_end(0, 5000), 5000, "and so does the gate");
    fresh.set_ok(2);
    assert_eq!(g.vouched_end(0, 5000), 7500, "the new grid's block 2");
}

/// The default [`ChaseGate::vouched_end`] is exactly the prefix answer,
/// so a gate with no per-block verdicts behind it (a routed child whose
/// chain is unanchored, a test double) is no more permissive than it
/// was before per-range vouching existed.
#[test]
fn chase_gate_default_per_range_is_the_prefix() {
    struct Prefix(u64);
    impl ChaseGate for Prefix {
        fn watermark(&self) -> u64 {
            self.0
        }
        fn wait_past(&self, _offset: u64, _timeout: std::time::Duration) {}
    }
    let g = Prefix(4096);
    assert_eq!(g.vouched_end(0), 4096);
    assert_eq!(g.vouched_end(4095), 4096);
    assert_eq!(g.vouched_end(4096), 4096, "at the limit: park");
    assert_eq!(g.vouched_end(9000), 9000, "above it: park");
}

/// The [`SlotGate`] wrapper asks the cell it names and nothing else.
#[test]
fn slot_gate_forwards_the_per_range_question() {
    let gate = VerifyGate::new(2);
    gate.engage(1);
    let bits = gate.arm_vouch(1, 4, 100);
    bits.set_ok(3);
    let sg = SlotGate {
        gate: Arc::clone(&gate),
        slot: 1,
    };
    assert_eq!(ChaseGate::vouched_end(&sg, 300), u64::MAX);
    assert_eq!(ChaseGate::vouched_end(&sg, 100), 100);
    let other = SlotGate {
        gate: Arc::clone(&gate),
        slot: 0,
    };
    assert_eq!(
        ChaseGate::vouched_end(&other, 300),
        u64::MAX,
        "an unengaged slot is ungated, per range as by prefix"
    );
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
pub(super) fn par2_meta(
    set_id: [u8; 16],
    block_size: usize,
    files: &[(&str, &[u8])],
    ifsc: bool,
) -> Vec<u8> {
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

/// A `ReadAt::Reader` closure over `src`, ON THE CONTRACT that enum
/// documents: a range the source cannot FULLY serve is an `Err`, never
/// a short read, zero padding or a panic. Every fixture reader here
/// goes through this, because `src_md5` asks a Reader its length by
/// reading one byte past the descriptor's end (M4-41) - a closure that
/// panicked there instead was modelling `Extractor::read_at`, which
/// returns `nofile()`, incorrectly.
fn read_span(src: &[u8], off: u64, buf: &mut [u8]) -> std::io::Result<()> {
    let off = off as usize;
    let end = off.saturating_add(buf.len());
    if end > src.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "past the source's end",
        ));
    }
    buf.copy_from_slice(&src[off..end]);
    Ok(())
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

/// Feed `data` as `article`-byte spans to two verifiers over the same
/// set - one hashing every block from bytes, one handed each article's
/// CRC32 - and return both reports plus the CRC verifier's geometry.
/// `order` permutes arrival.
fn twin_feed(
    data: &[u8],
    bs: usize,
    article: usize,
    order: impl Fn(usize) -> Vec<usize>,
) -> (SlotReport, SlotReport, CrcReuseGeometry) {
    let (plain, _) = active_verifier(&[("a.bin", data)], bs);
    let (crc, _) = active_verifier(&[("a.bin", data)], bs);
    plain.set_fast_verify(true);
    crc.set_fast_verify(true);
    let n = data.len().div_ceil(article);
    for i in order(n) {
        let off = i * article;
        let span = &data[off..(off + article).min(data.len())];
        plain.on_data(0, "a.bin", data.len() as u64, off as u64, span);
        crc.on_data_with_crc(
            0,
            "a.bin",
            data.len() as u64,
            off as u64,
            span,
            Some(crc32fast::hash(span)),
        );
    }
    assert_eq!(
        plain.live_counts(),
        crc.live_counts(),
        "in-stream tallies agree"
    );
    assert_eq!(
        plain.crc_reuse_geometry().spared_bytes,
        0,
        "no CRC, nothing to spare"
    );
    let g = crc.crc_reuse_geometry();
    (
        plain.finish_slot(0, None).unwrap(),
        crc.finish_slot(0, None).unwrap(),
        g,
    )
}

/// A block claimed from a verified article CRC and a block claimed by
/// re-hashing its bytes agree, over every geometry the composition
/// handles: article == block, article inside a block, article
/// straddling a boundary, article wider than a block, the short last
/// block, and out-of-order arrival. The spared-bytes counter proves the
/// CRC arm really composed rather than fell back.
#[test]
fn composition_and_rehash_claims_agree() {
    let check = |data: &[u8], bs: usize, article: usize, order: &dyn Fn(usize) -> Vec<usize>| {
        let (a, b, g) = twin_feed(data, bs, article, order);
        assert!(a.all_ok(), "{a:?}");
        assert!(b.all_ok(), "{b:?}");
        assert_eq!(a.live_blocks, b.live_blocks, "bs {bs} article {article}");
        assert_eq!(a.live_blocks as usize, data.len().div_ceil(bs));
        assert_eq!((a.readback_blocks, b.readback_blocks), (0, 0));
        assert!(
            g.spared_bytes > 0,
            "bs {bs} article {article}: nothing spared {g:?}"
        );
        g.spared_bytes
    };
    let in_order = |n: usize| (0..n).collect::<Vec<_>>();
    let reversed = |n: usize| (0..n).rev().collect::<Vec<_>>();
    let interleaved = |n: usize| {
        (0..n)
            .step_by(2)
            .chain((1..n).step_by(2))
            .collect::<Vec<_>>()
    };

    // Exactly one block per article, short last block: nothing hashed.
    let data = data_of(4096 + 300, 11);
    assert_eq!(check(&data, 1024, 1024, &in_order), data.len() as u64);
    // Articles smaller than the block, misaligned: each straddling
    // article hashes its smaller side, each contained one nothing.
    let data = data_of(4096 + 300, 12);
    for order in [
        &in_order as &dyn Fn(usize) -> Vec<usize>,
        &reversed,
        &interleaved,
    ] {
        check(&data, 1024, 700, order);
    }
    // Articles wider than the block: a full block plus two fragments,
    // the full block derived, and the partial tail.
    let data = data_of(4096 + 300, 13);
    for order in [
        &in_order as &dyn Fn(usize) -> Vec<usize>,
        &reversed,
        &interleaved,
    ] {
        check(&data, 512, 700, order);
    }
    // Articles spanning several whole blocks: one of them is derived.
    let data = data_of(8192 + 100, 14);
    check(&data, 256, 1000, &in_order);
    // A file smaller than one article, and a one-block file.
    let data = data_of(500, 15);
    assert_eq!(check(&data, 1024, 700, &in_order), 500);
    let data = data_of(1024, 16);
    assert_eq!(check(&data, 1024, 1024, &in_order), 1024);
}

/// A corrupted article is caught the same way under composition as under
/// re-hash: its CRC (honestly computed over the bytes that arrived,
/// which is what the decoder vouches for) composes to a block CRC the
/// IFSC rejects. And a CRC that LIES about its bytes can only fail a
/// block, never pass one.
#[test]
fn a_corrupted_article_is_caught_under_composition() {
    let data = data_of(4096 + 300, 21);
    let mut wrong = data.clone();
    wrong[1500] ^= 0x40; // inside the article at 1400..2100, block 1
    // Both arms fed the SAME damaged bytes against the intact set.
    let (plain, _) = active_verifier(&[("a.bin", &data)], 1024);
    let (crc, _) = active_verifier(&[("a.bin", &data)], 1024);
    plain.set_fast_verify(true);
    crc.set_fast_verify(true);
    for off in (0..wrong.len()).step_by(700) {
        let span = &wrong[off..(off + 700).min(wrong.len())];
        plain.on_data(0, "a.bin", data.len() as u64, off as u64, span);
        crc.on_data_with_crc(
            0,
            "a.bin",
            data.len() as u64,
            off as u64,
            span,
            Some(crc32fast::hash(span)),
        );
    }
    assert_eq!(plain.live_counts(), crc.live_counts());
    assert!(
        crc.crc_reuse_geometry().spared_bytes > 0,
        "the CRC arm composed"
    );
    let ra = plain.finish_slot(0, None).unwrap();
    let rb = crc.finish_slot(0, None).unwrap();
    assert_eq!(ra.bad_blocks, vec![1]);
    assert_eq!(rb.bad_blocks, vec![1]);
    assert_eq!(ra.live_blocks, rb.live_blocks);

    // A lying CRC over intact bytes: the derived piece is wrong, so the
    // block it lands in fails - and ONLY that block, since every other
    // piece was hashed from the bytes. Never an Ok it did not earn.
    let (lie, _) = active_verifier(&[("a.bin", &data)], 1024);
    lie.set_fast_verify(true);
    for off in (0..data.len()).step_by(700) {
        let span = &data[off..(off + 700).min(data.len())];
        let c = crc32fast::hash(span) ^ if off == 1400 { 0xDEAD_BEEF } else { 0 };
        lie.on_data_with_crc(0, "a.bin", data.len() as u64, off as u64, span, Some(c));
    }
    let r = lie.finish_slot(0, None).unwrap();
    // The 1400..2100 article straddles blocks 1 and 2; its larger side
    // (1400..2048, block 1) is the derived one.
    assert_eq!(r.bad_blocks, vec![1], "{r:?}");
}

/// The measurement gate (`NZBFAST_NO_CRC_REUSE`, [`LiveVerifier::set_crc_reuse`])
/// must change the COST and nothing else: with reuse off nothing is
/// spared, every needed piece is hashed from the bytes, and the verdicts
/// are the same ones the reuse arm reaches. An arm that changed a verdict
/// would make every A/B built on it meaningless.
#[test]
fn crc_reuse_gate_changes_cost_and_not_verdicts() {
    let data = data_of(4096 + 300, 77);
    let mut damaged = data.clone();
    damaged[1500] ^= 0x40; // inside the 1400..2100 article, block 1
    for bytes in [&data, &damaged] {
        let (on, _) = active_verifier(&[("a.bin", &data)], 1024);
        let (off, _) = active_verifier(&[("a.bin", &data)], 1024);
        on.set_fast_verify(true);
        off.set_fast_verify(true);
        off.set_crc_reuse(false);
        for start in (0..bytes.len()).step_by(700) {
            let span = &bytes[start..(start + 700).min(bytes.len())];
            let c = Some(crc32fast::hash(span));
            let (len, at) = (data.len() as u64, start as u64);
            on.on_data_with_crc(0, "a.bin", len, at, span, c);
            off.on_data_with_crc(0, "a.bin", len, at, span, c);
        }
        assert!(
            on.crc_reuse_geometry().spared_bytes > 0,
            "the on arm composed"
        );
        assert_eq!(
            off.crc_reuse_geometry().spared_bytes,
            0,
            "the off arm spared nothing"
        );
        // The census half is geometry, not reuse, so it is unaffected.
        assert_eq!(
            on.crc_reuse_geometry().qualifying,
            off.crc_reuse_geometry().qualifying
        );
        assert_eq!(on.live_counts(), off.live_counts());
        let (ra, rb) = (
            on.finish_slot(0, None).unwrap(),
            off.finish_slot(0, None).unwrap(),
        );
        assert_eq!(ra.bad_blocks, rb.bad_blocks, "{ra:?} {rb:?}");
        assert_eq!(ra.live_blocks, rb.live_blocks);
    }
}

/// Micro-benchmark for the reuse, not a test: 700 KB articles over 1 MiB
/// blocks, 1 GiB, fed in order with and without the article CRC. Prints
/// the feed wall time of each leg; the recorded figures are in the commit
/// that added it. Run in release, ignored by default:
///
///     cargo test --release -p nzbkit --lib live::tests::crc_reuse_bench -- --ignored --nocapture
///
/// `NZBFAST_CRC_REUSE_LEG=plain|crc` runs one leg for `/usr/bin/time -l`.
#[test]
#[ignore]
fn crc_reuse_bench() {
    use std::time::Instant;
    const BS: usize = 1 << 20;
    const ART: usize = 700 * 1000;
    const TOTAL: usize = 1 << 30;
    let leg = std::env::var("NZBFAST_CRC_REUSE_LEG").unwrap_or_else(|_| "both".into());
    let mut data = vec![0u8; TOTAL];
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    for chunk in data.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
    }
    let arts: Vec<(usize, &[u8], u32)> = (0..TOTAL.div_ceil(ART))
        .map(|i| {
            let off = i * ART;
            let span = &data[off..(off + ART).min(TOTAL)];
            (off, span, crc32fast::hash(span))
        })
        .collect();
    let meta = par2_meta([7u8; 16], BS, &[("a.bin", &data)], true);
    let run = |with_crc: bool| -> (f64, u64) {
        let v = LiveVerifier::new(1);
        v.activate(&[meta.as_slice()]).unwrap();
        v.set_fast_verify(true);
        let t0 = Instant::now();
        for &(off, span, c) in &arts {
            if with_crc {
                v.on_data_with_crc(0, "a.bin", TOTAL as u64, off as u64, span, Some(c));
            } else {
                v.on_data(0, "a.bin", TOTAL as u64, off as u64, span);
            }
        }
        let wall = t0.elapsed().as_secs_f64();
        let r = v.finish_slot(0, None).unwrap();
        assert!(r.all_ok() && r.readback_blocks == 0, "{r:?}");
        (wall, v.crc_reuse_geometry().spared_bytes)
    };
    for _ in 0..3 {
        if leg != "crc" {
            let (w, _) = run(false);
            eprintln!(
                "plain: {:.1} ms ({:.2} GB/s)",
                w * 1e3,
                TOTAL as f64 / w / 1e9
            );
        }
        if leg != "plain" {
            let (w, spared) = run(true);
            eprintln!(
                "crc:   {:.1} ms ({:.2} GB/s), spared {:.1}% of bytes",
                w * 1e3,
                TOTAL as f64 / w / 1e9,
                spared as f64 * 100.0 / TOTAL as f64
            );
        }
    }
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
        .finish_slot_from(0, ReadAt::Reader(&|off, buf| read_span(&data, off, buf)))
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
        .finish_slot_from(0, ReadAt::Reader(&|off, buf| read_span(&wrong, off, buf)))
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

/// W4-11: the yEnc `size=` is a per-article claim about the whole file,
/// and the article that arrives FIRST must not be the one believed.
///
/// The head this slot captures is sized by that claim (`head_want` is
/// `min(16 KiB, declared length)`), and the head's MD5 is the only
/// identity an obfuscated post has. So an under-declaring article that
/// lands first shrank the head to its lie, the md5-16k tier could never
/// match the descriptor's own 16 KiB digest, and an intact file went
/// unclaimed - priced `file missing entirely` downstream.
///
/// The correction is not a second guess at the length: this article
/// carries bytes 0..8192 and declares the file 8192 long, and the NEXT
/// one carries 8192..16384, which is the same post refuting itself. The
/// floor is what the bytes prove.
#[test]
fn an_under_declared_size_arriving_first_does_not_shrink_the_head() {
    let data = data_of(20_000, 41);
    let (v, _set) = active_verifier(&[("real-name.bin", &data)], 4096);
    // The liar covers exactly the head it claims is the whole file, so
    // that head COMPLETES at 8192 and is judged - and judged against a
    // descriptor whose own md5_16k covers 16 KiB, so it matches nothing.
    v.on_data(0, "jibberish123", 8_192, 0, &data[..8_192]);
    assert!(
        !v.slot_in_set(0),
        "8 KiB of a 20 KB file is not yet an identity - nothing to claim on"
    );
    // ...and the next article proves the file is longer, which both
    // grows the head and voids the refusal reached on the short one.
    v.on_data(0, "jibberish123", 20_000, 8_192, &data[8_192..16_384]);
    assert!(
        v.slot_in_set(0),
        "the head grew to the full 16 KiB and claimed the descriptor by \
         content, so the first article's declared size did not decide it"
    );
}

/// M4-94, the other direction of W4-11's row and CONFIRMED RED on
/// origin/main 31 Aug 2026 (`80c00ccb5`): an article that declares NO
/// size, then a later one that declares a SHORT one, and the head this
/// slot has already captured is thrown away.
///
/// `head_want` is `min(16 KiB, declared length)` and `file_size` is 0
/// until some article declares one, so an article omitting `size=`
/// captures its bytes under the full 16 KiB. The first article to
/// declare a length BELOW that shrinks `want` - and `capture_head`
/// restarted the buffer from empty there. The offset-0 article has by
/// then been consumed and is never re-fed, so the head could never
/// complete again: `head_key` stayed `None`, and the md5-16k tier, which
/// is the only identity an obfuscated post has, was dead for that slot
/// for the rest of the run.
///
/// This is NOT W4-11 with the numbers changed. There the first
/// declaration is nonzero and the correction is to RAISE it to what the
/// bytes prove, which grows the head; the grow arm keeps the captured
/// bytes precisely because that row measured what discarding them costs.
/// Here the shrink is legitimate - the file really may be shorter than
/// 16 KiB, and PAR2's `md5_16k` covers the whole file when it is - so
/// the length must move and only the BYTES must survive it.
///
/// The article declaring 8192 covers exactly `4096..8192`, so its own
/// `=ypart` range does not refute it and W4-11's floor leaves it alone.
/// That is what makes this reach the shrink at all.
#[test]
fn a_size_declared_after_a_sizeless_article_does_not_discard_the_head() {
    let data = data_of(20_000, 41);
    let (v, _set) = active_verifier(&[("real-name.bin", &data)], 4096);
    // No declared size: `want` is the full 16 KiB and these are the
    // file's first bytes.
    v.on_data(0, "jibberish123", 0, 0, &data[..4_096]);
    // The first declaration, and it is short. `want` shrinks to 8192.
    v.on_data(0, "jibberish123", 8_192, 4_096, &data[4_096..8_192]);
    // The rest of the post proves the file is longer and grows the head
    // back to 16 KiB - but nothing carries offset 0 a second time.
    v.on_data(0, "jibberish123", 20_000, 8_192, &data[8_192..12_288]);
    v.on_data(0, "jibberish123", 20_000, 12_288, &data[12_288..16_384]);
    assert!(
        v.slot_in_set(0),
        "M4-94: the shrink discarded the offset-0 bytes, so the head \
         never completed and the md5-16k tier could never claim - on a \
         file that arrived INTACT"
    );
}

/// The control for the test above, and it is what makes that one a test
/// of the sizeless FIRST article rather than of the offsets: the same
/// four spans with every article declaring the truth.
#[test]
fn control_four_honest_articles_claim_by_head() {
    let data = data_of(20_000, 41);
    let (v, _set) = active_verifier(&[("real-name.bin", &data)], 4096);
    for (off, end) in [
        (0, 4_096),
        (4_096, 8_192),
        (8_192, 12_288),
        (12_288, 16_384),
    ] {
        v.on_data(0, "jibberish123", 20_000, off as u64, &data[off..end]);
    }
    assert!(
        v.slot_in_set(0),
        "control: the honest post claims by md5-16k"
    );
}

/// The SHORT-FILE half of the same shrink, and the reason the fix is a
/// truncation rather than a high-water mark on `want`.
///
/// A genuinely 5000-byte file's `md5_16k` is the MD5 of all 5000 bytes,
/// so `want` MUST come down to 5000 for the digest to match at all. A
/// `want` frozen at 16 KiB would hash 5000 real bytes plus 11384 zeros
/// and claim nothing - which would trade M4-94 for a wider defect.
/// Here the shrink happens AND the head still completes.
#[test]
fn a_short_file_whose_first_article_omitted_its_size_still_claims() {
    let data = data_of(5_000, 42);
    let (v, _set) = active_verifier(&[("small.bin", &data)], 2048);
    v.on_data(0, "jibberish456", 0, 0, &data[..2_500]);
    v.on_data(0, "jibberish456", 5_000, 2_500, &data[2_500..]);
    assert!(
        v.slot_in_set(0),
        "the head shrank to the file's real length and kept the bytes \
         already captured under the 16 KiB default"
    );
    let r = v.finish_slot(0, None).unwrap();
    assert_eq!(r.par2_name.as_deref(), Some("small.bin"));
}

/// The control for the test above, and it is what makes it a test of
/// the SIZE rather than of the offsets: the same two spans with both
/// articles declaring the truth. A green here on a tree where the leg
/// above is red says the declared size is the only thing that moved.
#[test]
fn control_two_honest_articles_claim_the_same_slot() {
    let data = data_of(20_000, 41);
    let (v, _set) = active_verifier(&[("real-name.bin", &data)], 4096);
    v.on_data(0, "jibberish123", 20_000, 0, &data[..8_192]);
    v.on_data(0, "jibberish123", 20_000, 8_192, &data[8_192..16_384]);
    assert!(v.slot_in_set(0), "the honest post claims by md5-16k");
}

/// W4-15: two ACTIVE recovery sets describing the SAME file are not two
/// files, and the md5-16k tier must not decline them as rivals.
///
/// The rivalry that tier exists to decline is two DIFFERENT files
/// sharing a 16 KiB head - zero-filled heads, padded VOBs - and what
/// tells those apart is the whole-file MD5. Two descriptors agreeing on
/// the length AND that MD5 describe the same bytes, which is what a post
/// carrying two overlapping sets over one member looks like. Declining
/// there left the slot unclaimed on a file that was merely damaged, and
/// the whole-file tier cannot rescue it either: a damaged file matches
/// no candidate's MD5 at all.
#[test]
fn one_file_described_by_two_sets_is_not_an_ambiguous_head() {
    let data = data_of(3000, 44);
    let v = LiveVerifier::new(1);
    // Two sets, different ids and different block sizes, one member.
    let alpha = par2_meta([1u8; 16], 1024, &[("shared.bin", &data)], true);
    let bravo = par2_meta([2u8; 16], 1028, &[("shared.bin", &data)], true);
    let sets = v
        .activate(&[alpha.as_slice(), bravo.as_slice()])
        .expect("two sets parse");
    assert_eq!(sets.len(), 2, "both sets adopted");
    v.on_data(0, "jibberish123", 3000, 0, &data);
    assert!(
        v.slot_in_set(0),
        "the slot declined BOTH descriptors as an ambiguous head, though \
         the two name one file - same length, same whole-file MD5"
    );
    let r = v.finish_slot(0, None).unwrap();
    assert_eq!(r.par2_name.as_deref(), Some("shared.bin"));
}

/// The control for the test above: two descriptors that really ARE
/// rivals - same 16 KiB head, DIFFERENT files behind it - must still be
/// declined, or the rule above is just "claim the first candidate".
///
/// Both members open with the same 3000 bytes and differ after, so the
/// md5-16k tier cannot tell them apart and the whole-file MD5 can.
#[test]
fn control_two_different_files_sharing_a_head_are_still_declined() {
    let head = data_of(3000, 45);
    let mut a = head.clone();
    a.extend_from_slice(&data_of(1000, 46));
    let mut b = head.clone();
    b.extend_from_slice(&data_of(1000, 47));
    let v = LiveVerifier::new(1);
    let meta = par2_meta(
        [9u8; 16],
        1024,
        &[("twin-a.bin", &a), ("twin-b.bin", &b)],
        true,
    );
    v.activate(&[meta.as_slice()]).expect("fixture parses");
    // Only the shared head has arrived, so nothing distinguishes them.
    v.on_data(0, "jibberish123", 4000, 0, &head);
    assert!(
        !v.slot_in_set(0),
        "two genuinely different files sharing a head were resolved by \
         candidate order - the cross-set rule must not reach them"
    );
}

/// W4-15: a second activation must EXTEND the live plan, never replace
/// it. The in-stream sniff elects a bootstrap volume per recovery set,
/// so a post carrying two sets activates twice - the second set's volume
/// is sniffed long after the first set's bootstrap has completed.
///
/// Replacing built a fresh claim table and a fresh flat index, so a slot
/// bound before the second call kept a `file` index into the OLD table:
/// its claim vanished and the same member was then charged BOTH as
/// damaged (the stale binding's blocks) and as wholly missing (its
/// now-unclaimed descriptor).
#[test]
fn a_second_activation_keeps_the_first_sets_claims() {
    let data = data_of(3000, 48);
    let other = data_of(2000, 49);
    let v = LiveVerifier::new(2);
    let alpha = par2_meta([1u8; 16], 1024, &[("first.bin", &data)], true);
    let bravo = par2_meta([2u8; 16], 1028, &[("second.bin", &other)], true);
    v.activate(&[alpha.as_slice()]).expect("first set parses");
    v.on_data(0, "jibberish123", 3000, 0, &data);
    assert!(v.slot_in_set(0), "claimed under the first set");
    let sets = v
        .activate(&[alpha.as_slice(), bravo.as_slice()])
        .expect("both sets parse");
    assert_eq!(sets.len(), 2, "the second set was adopted beside the first");
    assert!(
        v.slot_in_set(0),
        "the second activation dropped the first set's binding"
    );
    assert_eq!(v.slot_set(0), Some(0), "and it still names the same set");
    // The BINDING surviving is not the same thing as the CLAIM
    // surviving, and only the second is the defect: a replacing
    // activation builds a fresh claim table, so `first.bin` reads as
    // unclaimed - charged WHOLLY MISSING beside the very slot that is
    // verifying it - while the slot's own `file` index still happens to
    // point at the right descriptor. Assert the claim table.
    assert_eq!(
        v.unclaimed_files(),
        ["second.bin"],
        "the first set's descriptor lost its claim across the second \
         activation, so it reads as a file nothing delivered"
    );
    let r = v.finish_slot(0, None).unwrap();
    assert_eq!(r.par2_name.as_deref(), Some("first.bin"));
    assert!(r.all_ok(), "{r:?}");
}

/// W4-15: the damage a slot reports belongs to every set that names the
/// same file, each in its OWN block geometry - not only to the one that
/// won the binding, which is decided by the in-stream arrival race.
///
/// The two sets here differ in block size (1024 against 1028) precisely
/// because a count rescaled by a ratio is not a count of anything: the
/// bad blocks are mapped through byte ranges.
#[test]
fn a_shared_members_damage_is_charged_to_both_sets() {
    let data = data_of(8192, 50);
    let v = LiveVerifier::new(1);
    let alpha = par2_meta([1u8; 16], 1024, &[("shared.bin", &data)], true);
    let bravo = par2_meta([2u8; 16], 1028, &[("shared.bin", &data)], true);
    v.activate(&[alpha.as_slice(), bravo.as_slice()])
        .expect("two sets parse");
    v.on_data(0, "jibberish123", 8192, 0, &data);
    assert!(v.slot_in_set(0), "claimed one of the two descriptors");
    let owner = v.slot_set(0).expect("an owning set");
    // One block of the owner's geometry, restated for the sibling.
    let twins = v.slot_twin_damage(0, &[3]);
    assert_eq!(
        twins.len(),
        1,
        "the sibling set names the same file and must hear about the damage"
    );
    assert_ne!(twins[0].0, owner, "the owner is not its own twin");
    assert!(
        twins[0].1 >= 1,
        "a block of damage cannot restate as no damage at all"
    );
    // A slot with nothing wrong owes the sibling nothing.
    assert!(v.slot_twin_damage(0, &[]).is_empty());
}

/// The control for the test above: two sets over DIFFERENT files share
/// no damage. Without it the rule reads as "tell every set about
/// everything", which would send an unrelated set shopping for parity.
#[test]
fn control_disjoint_sets_share_no_damage() {
    let data = data_of(8192, 51);
    let other = data_of(8192, 52);
    let v = LiveVerifier::new(1);
    let alpha = par2_meta([1u8; 16], 1024, &[("mine.bin", &data)], true);
    let bravo = par2_meta([2u8; 16], 1028, &[("theirs.bin", &other)], true);
    v.activate(&[alpha.as_slice(), bravo.as_slice()])
        .expect("two sets parse");
    v.on_data(0, "jibberish123", 8192, 0, &data);
    assert!(v.slot_in_set(0));
    assert!(
        v.slot_twin_damage(0, &[3]).is_empty(),
        "a set that does not name this file was charged its damage"
    );
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
    // Both descriptor names sanitize to the tree name "x/y.txt" now
    // (the backslash spelling normalizes to the same path); the slot's
    // own spelling differs in bytes from both, so nothing is exact.
    let (v, _set) = active_verifier(&[("x/y.txt", &a), ("x\\y.txt", &b)], 1024);
    // Slot 0: ambiguous name, corrupt head - both tiers decline.
    v.on_data(0, "x/y.txt.", 3000, 0, &corrupt);
    assert!(!v.slot_in_set(0), "nothing claimable yet");
    // Slot 1 claims x/y.txt by exact name, making slot 0's
    // approximate match unique.
    v.on_data(1, "x/y.txt", 3000, 0, &a);
    assert!(v.slot_in_set(1));
    // Slot 0's next span retries the match and must now claim.
    v.on_data(0, "x/y.txt.", 3000, 0, &corrupt);
    assert!(
        v.slot_in_set(0),
        "ambiguity resolved by the twin's claim - the slot must not stay latched unmatchable"
    );
}

/// Matrix finding F1 (29 Aug 2026): two same-length files sharing an
/// identical first 16 KiB both match both descriptors on the md5-16k
/// key, and first-hit made WHICH slot claimed which a worker-thread
/// race - crossed, every differing block read as damage and an intact
/// post paid a repair (or died at low redundancy). The tier now
/// DECLINES the ambiguity, neither slot latches, and finish settles
/// each by whole-file MD5 - the first finisher through the whole-file
/// tier, the second through the md5-16k tier gone unique.
#[test]
fn identical_head_twins_decline_and_settle_by_whole_file_md5() {
    let mut a = vec![0u8; 20_000];
    let mut b = vec![0u8; 20_000];
    a[16_384..].copy_from_slice(&data_of(3_616, 71));
    b[16_384..].copy_from_slice(&data_of(3_616, 72));
    let (v, _set) = active_verifier(&[("twin.a.vob", &a), ("twin.b.vob", &b)], 1024);
    // Obfuscated names, CROSSED arrival order: slot 0 carries b.
    v.on_data(0, "Xk1jibber", 20_000, 0, &b);
    v.on_data(1, "Qz2jibber", 20_000, 0, &a);
    assert!(
        !v.slot_in_set(0) && !v.slot_in_set(1),
        "ambiguous heads must decline, not race"
    );
    assert!(
        v.slot_undecided(0) && v.slot_undecided(1),
        "declined ambiguity must stay retryable, never latch unmatchable"
    );
    let dir = std::env::temp_dir().join(format!("nzbkit-live-twins-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (pb, pa) = (dir.join("s0"), dir.join("s1"));
    std::fs::write(&pb, &b).unwrap();
    std::fs::write(&pa, &a).unwrap();
    let r0 = v.finish_slot(0, Some(&pb)).unwrap();
    let r1 = v.finish_slot(1, Some(&pa)).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(r0.par2_name.as_deref(), Some("twin.b.vob"), "crossed claim");
    assert_eq!(r1.par2_name.as_deref(), Some("twin.a.vob"), "crossed claim");
    assert!(r0.all_ok() && r1.all_ok(), "{r0:?} {r1:?}");
}

/// Sweep item 13 (30 Aug 2026): the DAMAGED half of finding F1.
///
/// The whole-file tier can only name an identical-head twin that is
/// INTACT - the difference between a damaged slot and its own
/// descriptor IS the damage, so every candidate's whole-file MD5 fails
/// by construction and the slot used to stay unclaimed, priced wholly
/// missing. Per-block IFSC evidence settles it: the surviving blocks
/// carry one twin's own PAR2 block checksums and not the other's.
///
/// Both slots are damaged here, which is the case the deferral worried
/// about, and neither is crossed: each claims the descriptor its
/// surviving blocks name, and each reports the ONE block that is
/// really bad rather than every block of a file nobody claimed.
#[test]
fn damaged_identical_head_twins_claim_on_per_block_evidence() {
    let mut a = vec![0u8; 20_000];
    let mut b = vec![0u8; 20_000];
    a[16_384..].copy_from_slice(&data_of(3_616, 71));
    b[16_384..].copy_from_slice(&data_of(3_616, 72));
    let (v, _set) = active_verifier(&[("twin.a.vob", &a), ("twin.b.vob", &b)], 1024);
    // Block 16 (bytes 16384..17408) of each is damaged. PAST the shared
    // 16 KiB head, so the heads still agree, the md5-16k tier still
    // declines the pair, and the whole-file MD5 can name neither.
    let (mut da, mut db) = (a.clone(), b.clone());
    da[17_000] ^= 0xff;
    db[17_000] ^= 0xff;
    // CROSSED arrival order: slot 0 carries b's bytes.
    v.on_data(0, "Xk1jibber", 20_000, 0, &db);
    v.on_data(1, "Qz2jibber", 20_000, 0, &da);
    assert!(
        !v.slot_in_set(0) && !v.slot_in_set(1),
        "ambiguous heads must decline in stream, not race"
    );
    let (r0, r1) = (
        finish_from(&v, 0, &db).unwrap(),
        finish_from(&v, 1, &da).unwrap(),
    );
    assert_eq!(r0.par2_name.as_deref(), Some("twin.b.vob"), "crossed claim");
    assert_eq!(r1.par2_name.as_deref(), Some("twin.a.vob"), "crossed claim");
    assert_eq!(r0.bad_blocks, vec![16], "{r0:?}");
    assert_eq!(r1.bad_blocks, vec![16], "{r1:?}");
}

/// The rule's refusal, and the reason it is not "one candidate is left,
/// so it must be ours": twins that differ ONLY in the block this slot
/// is damaged in have no MATCHED distinguishing block, so nothing
/// separates them and the tier declines exactly as it did before the
/// evidence arm existed. A pairing picked here would publish one twin's
/// bytes under the other's name at rc=0.
#[test]
fn twins_damaged_in_their_only_distinguishing_block_decline() {
    let mut a = vec![0u8; 20_000];
    a[16_384..].copy_from_slice(&data_of(3_616, 71));
    // Identical everywhere but block 17 (bytes 17408..18432).
    let mut b = a.clone();
    b[17_408..18_432].copy_from_slice(&data_of(1_024, 99));
    let (v, _set) = active_verifier(&[("only.a.vob", &a), ("only.b.vob", &b)], 1024);
    let (mut da, mut db) = (a.clone(), b.clone());
    da[17_500] ^= 0xff;
    db[17_500] ^= 0xff;
    v.on_data(0, "Xk1jibber", 20_000, 0, &da);
    v.on_data(1, "Qz2jibber", 20_000, 0, &db);
    assert!(
        finish_from(&v, 0, &da).is_none() && finish_from(&v, 1, &db).is_none(),
        "evidence that does not separate the twins must not claim either"
    );
    assert!(
        v.slot_undecided(0) && v.slot_undecided(1),
        "a decline stays retryable, never latches unmatchable"
    );
}

/// A slot carrying blocks of BOTH twins is not a pairing anybody may
/// make. Spliced bytes score for each candidate on distinguishing
/// blocks, so the rival clause refuses even though one side scores
/// strictly higher - the arm a plain highest-score rule would cross.
#[test]
fn a_slot_carrying_blocks_of_both_twins_declines() {
    let mut a = vec![0u8; 20_000];
    let mut b = vec![0u8; 20_000];
    a[16_384..].copy_from_slice(&data_of(3_616, 71));
    b[16_384..].copy_from_slice(&data_of(3_616, 72));
    let (v, _set) = active_verifier(&[("mix.a.vob", &a), ("mix.b.vob", &b)], 1024);
    // a's file with b's block 17 spliced in: a scores higher, but b
    // holds a distinguishing block of its own.
    let mut mixed = a.clone();
    mixed[17_408..18_432].copy_from_slice(&b[17_408..18_432]);
    mixed[19_600] ^= 0xff; // and damaged, so no whole-file MD5 can pass
    v.on_data(0, "Xk1jibber", 20_000, 0, &mixed);
    assert!(
        finish_from(&v, 0, &mixed).is_none(),
        "blocks of both twins is ambiguity, not a majority vote"
    );
}

/// Settle a slot from `bytes` in memory - the twin rows need a source
/// the whole-file tier can read, and a `ReadAt::Reader` is one without
/// a tempdir per row.
fn finish_from(v: &LiveVerifier, slot: usize, bytes: &[u8]) -> Option<SlotReport> {
    v.finish_slot_from(
        slot,
        ReadAt::Reader(&|off, buf| {
            let off = off as usize;
            if off + buf.len() > bytes.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "past end",
                ));
            }
            buf.copy_from_slice(&bytes[off..off + buf.len()]);
            Ok(())
        }),
    )
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
        .finish_slot_from(0, ReadAt::Reader(&|off, buf| read_span(&data, off, buf)))
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

/// F13 (1 Sep 2026): a tentative binding that LOSES the claim race
/// releases the §94 B gate cell it engaged - AT FINISH, and not before.
///
/// A NAME nomination locks nobody out (`slotstate.rs` binds the sole
/// nominee without writing `claimed[fi]`), so an NZB that carries the
/// same volume twice under one name puts two slots on one descriptor and
/// both engage the gate. The first full Ok block promotes one of them;
/// the other's `promote_binding` finds the claim taken and forgets its
/// binding - and forgetting never touched the gate. `engage` is
/// idempotent and `advance` is monotonic, so nothing lowers or clears
/// the stale finite cell, and `finish_slot_from` released it only for a
/// binding dropped AT FINISH (`dropped`), which this one is not. A chase
/// reader on that slot therefore ticked at 100 ms until `chase_finish`
/// released every gate after settle: not a hang, but the one-pass
/// extraction of that whole chase group is lost.
///
/// The fix is the widened finish-time arm below, NOT an in-stream
/// release: one landed on 1 Sep 2026 and was taken back out the same
/// day, because the frontier latches a released limit with `fetch_max`
/// and a slot with no binding can still rebind on a later article, which
/// would then run permanently ungated. So the two in-stream assertions
/// here pin the cell STAYING engaged, and the release lands at finish.
///
/// Which twin is CHASED and which one WINS are independent (`chase.rs`
/// admits the first to present bytes; the claim goes to the first to
/// complete an Ok block), so the chased slot can be the loser.
#[test]
fn a_nomination_that_loses_the_claim_race_releases_its_verify_gate() {
    let vol = data_of(20_000, 77);
    let v = LiveVerifier::new(2);
    let meta = par2_meta([9u8; 16], 1024, &[("vol.rar", &vol)], true);
    v.activate(&[meta.as_slice()]).expect("fixture parses");
    let g = VerifyGate::new(2);
    v.set_gate(g.clone());
    // The same volume twice under one name. Spans start PAST the 16 KiB
    // head, so the md5-16k tier never completes and the NAME is the only
    // tier with anything to say - which is what lets both slots nominate
    // the one descriptor. Neither first span completes a block, so
    // neither nomination is promoted before the other is made.
    v.on_data(0, "vol.rar", 20_000, 16_384, &vol[16_384..16_896]);
    v.on_data(1, "vol.rar", 20_000, 16_384, &vol[16_384..16_896]);
    assert_eq!(g.watermark(0), 0, "slot 0's nomination engaged the gate");
    assert_eq!(g.watermark(1), 0, "so did slot 1's");
    // Slot 0 completes blocks and takes the claim; slot 1 does the same
    // and loses.
    v.on_data(0, "vol.rar", 20_000, 16_896, &vol[16_896..]);
    v.on_data(1, "vol.rar", 20_000, 16_896, &vol[16_896..]);
    assert!(
        g.engaged_mark(0).is_some(),
        "the winner is still gated - it is the one being verified"
    );
    assert!(
        g.engaged_mark(1).is_some(),
        "the loser's cell stays engaged IN STREAM: releasing it here is \
         latched by the frontier's `fetch_max` cache, and this slot may \
         still rebind on a later article"
    );
    assert!(
        g.watermark(1) < u64::MAX,
        "so a chase parked on the loser is still gated for now"
    );
    // ...and finish is where it goes: the slot has no binding, so the
    // widened `engaged_mark` arm releases the reader rather than leaving
    // it to tick until `chase_finish`.
    assert!(
        finish_from(&v, 1, &vol).is_none(),
        "the descriptor belongs to slot 0"
    );
    assert_eq!(
        g.watermark(1),
        u64::MAX,
        "finish releases the engaged, unbound loser - the old `dropped` \
         test never fired for an in-stream drop"
    );
}

/// F13's other half, at finish: ANY slot that engaged the gate and has
/// no binding when it settles releases it, not only one whose binding
/// was taken away at finish.
///
/// The old test was `dropped`, which is true only for a drop taken
/// inside `finish_slot_from` itself - so every in-stream drop left its
/// cell stale. This is the backstop under the in-stream release above.
///
/// The `engaged_mark` half is load-bearing and pinned here too: `advance`
/// turns a None cell into Some(MAX), and `earlyfile.rs` reads
/// `Some(u64::MAX)` as "fully vouched" for the §296 early publish, so an
/// unconditional advance would publish a slot the verifier never claimed.
#[test]
fn an_engaged_slot_that_never_bound_releases_its_gate_at_finish() {
    let data = data_of(3000, 41);
    let v = LiveVerifier::new(2);
    let meta = par2_meta([9u8; 16], 1024, &[("a.bin", &data)], true);
    v.activate(&[meta.as_slice()]).expect("fixture parses");
    let g = VerifyGate::new(2);
    v.set_gate(g.clone());
    g.engage(1);
    assert_eq!(g.watermark(1), 0, "engaged and waiting");
    // Slot 1 has no name and no bytes: no tier binds it at finish.
    assert!(v.finish_slot(1, None).is_none());
    assert_eq!(
        g.watermark(1),
        u64::MAX,
        "an engaged slot nothing will ever verify must not park a chase \
         until chase_finish"
    );
    // Slot 0 was never engaged, and finish must not invent a verdict for
    // it - Some(u64::MAX) is what the early publish reads as vouched.
    assert!(v.finish_slot(0, None).is_none());
    assert_eq!(
        g.engaged_mark(0),
        None,
        "a slot the verifier never claimed is not 'fully vouched'"
    );
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
) -> (
    Vec<Option<usize>>,
    Vec<(Option<usize>, Option<u64>, bool, bool)>,
    Vec<bool>,
) {
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
        let r = if s.file.is_some() || s.refused(&active) {
            false
        } else if indexed {
            s.try_match(si, &active, true)
        } else {
            s.try_match_linear(si, &active, true)
        };
        rets.push(r);
    }
    let claimed = active.claimed.lock_ok().clone();
    // `confirmed` rides in the compared state: a tentative name binding
    // and a content-proved claim look identical through `file` alone, and
    // the two drains must not disagree about which one they made. So
    // does the refusal's ADOPTION GENERATION rather than just whether
    // there is one: a reference drain that latched against a different
    // population than production would agree here on every world with
    // one set and part company the moment a second activates, which is
    // exactly the case the parent's `refused` exists for.
    let state = slots
        .iter()
        .map(|s| (s.file, s.unmatchable, s.confirmed, s.head_nominated))
        .collect();
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
/// approximate in both impls whichever arrival order, and two
/// descriptors sharing one exact name must be split by the HEAD rather
/// than by FileDesc order (W4-02B).
///
/// Both leg shapes matter. WITH heads every claim is content-proved, so
/// the two drains must agree on which descriptor each slot took. WITHOUT
/// them nothing is proved and the drains must agree on the tentative
/// bindings instead - a sole exact candidate bound, a shared name bound
/// by neither.
#[test]
fn differential_exact_precedence_and_duplicates() {
    let d: Vec<Vec<u8>> = (0..4).map(|i| data_of(700, i as u8 + 40)).collect();
    let files: &[(&str, &[u8])] = &[
        ("a.txt", &d[0]),
        ("A.txt", &d[1]),
        ("dup.bin", &d[2]),
        ("dup.bin", &d[3]),
    ];
    // Slot i carries descriptor i's bytes under `names[i]`; the two
    // dup.bin slots are deliberately CROSSED against FileDesc order.
    let names = ["A.txt", "a.txt", "dup.bin", "dup.bin"];
    let heads = [&d[1], &d[0], &d[3], &d[2]];
    for order in [[0usize, 1, 2, 3], [3, 2, 1, 0], [1, 0, 3, 2]] {
        for with_heads in [false, true] {
            let steps: Vec<Step> = order
                .iter()
                .map(|&s| {
                    (
                        s,
                        Some(names[s]),
                        with_heads.then(|| (heads[s].as_slice(), 700u64)),
                    )
                })
                .collect();
            assert_matchers_agree(files, &steps);
        }
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

/// md5-16k ambiguity (matrix F1): a head matching TWO unclaimed
/// descriptors claims nothing and never latches - in both impls - and
/// once a twin's exact-name claim removes one candidate the retry
/// claims the survivor, again identically.
#[test]
fn differential_identical_head_twins_decline_then_resolve() {
    let mut a = vec![0u8; 17_000];
    let mut b = vec![0u8; 17_000];
    a[16_384..].copy_from_slice(&data_of(616, 81));
    b[16_384..].copy_from_slice(&data_of(616, 82));
    let files: &[(&str, &[u8])] = &[("twin.a", &a), ("twin.b", &b)];
    let steps: &[Step] = &[
        // Named slot, name misses, head matches BOTH: decline, NO latch.
        (0, Some("junk.nfo"), Some((&b, 17_000))),
        (1, Some("twin.a"), None), // exact claims descriptor 0
        (0, None, None),           // retry: md5 tier now unique
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

/// The fuzz pool above cannot reach the md5-16k tier's NOMINATION arm,
/// and this is the case that does (M4-103, 31 Aug 2026).
///
/// Every descriptor in that pool is a few hundred bytes, so
/// `f.length <= HEAD_LEN` holds for all of them and the head always
/// FINALIZES - which means the drains could have parted company on the
/// nomination rule with all 300 worlds still agreeing. A descriptor
/// LONGER than a 16 KiB head is the whole population of the arm, and it
/// takes one world to cover it. `run_world` compares `head_nominated`
/// beside `confirmed` for the same reason it compares `confirmed`
/// beside `file`: a claim and a revocable claim look identical through
/// the other two.
#[test]
fn differential_a_head_shorter_than_its_descriptor_nominates_in_both_drains() {
    let mut big = vec![0u8; 20_000];
    big[16_384..].copy_from_slice(&data_of(3_616, 71));
    let small = data_of(9_000, 17);
    let files: Vec<(&str, &[u8])> = vec![("big.vob", &big), ("small.bin", &small)];
    // Slot 0 is the long member reached by its head alone (obfuscated
    // name); slot 1 is the short one, whose head IS its whole file.
    let steps: Vec<Step> = vec![
        (0, Some("Wp3jibber"), Some((big.as_slice(), 20_000))),
        (1, Some("Kq7zzz"), Some((small.as_slice(), 9_000))),
    ];
    assert_matchers_agree(&files, &steps);
    // And the answers are the ones the rule names, so an agreement
    // between two drains that BOTH regressed is not mistaken for a pass.
    let (_, state, _) = run_world(&files, &steps, true);
    assert_eq!(
        (state[0].2, state[0].3),
        (false, true),
        "a head shorter than its descriptor NOMINATES"
    );
    assert_eq!(
        (state[1].2, state[1].3),
        (true, false),
        "a head that is the whole descriptor FINALIZES"
    );
}

/// F9's shape through both drains: a descriptor the head NAMES but
/// another slot HOLDS must suppress the `unmatchable` latch in the
/// reference matcher too.
///
/// `run_world` compares the refusal (generation included) beside `file`,
/// so a one-sided edit would part the drains here - but only on a world
/// that actually reaches the arm, and the fuzz pool above cannot: its
/// descriptors are a few hundred bytes, so a slot losing a race for one
/// is not the shape it generates. One world covers it.
#[test]
fn differential_a_head_naming_a_claimed_descriptor_does_not_latch_in_either_drain() {
    let mut member = vec![0u8; 20_000];
    member[16_384..].copy_from_slice(&data_of(3_616, 71));
    // Not in the set, same zero-filled head, longer - so it takes the
    // nomination first and the member arrives at a taken descriptor.
    let mut uncovered = vec![0u8; 40_000];
    uncovered[16_384..].copy_from_slice(&data_of(23_616, 99));
    let files: Vec<(&str, &[u8])> = vec![("member.vob", &member)];
    let steps: Vec<Step> = vec![
        (0, Some("Wp3jibber"), Some((uncovered.as_slice(), 40_000))),
        (1, Some("Zq8other"), Some((member.as_slice(), 20_000))),
    ];
    assert_matchers_agree(&files, &steps);
    // And the answer is the one the rule names, so two drains that BOTH
    // regressed are not mistaken for a pass.
    let (_, state, _) = run_world(&files, &steps, true);
    assert_eq!(
        state[1].1, None,
        "a descriptor merely TAKEN is not a head that matched nothing"
    );
}

// ===== W4-02 / W4-18 (30 Aug 2026): a NAME nominates, only CONTENT =====
// ===== finalizes. Three shapes the nomination rule exists for, and  =====
// ===== three it must NOT change - which is the half that priced it: =====
// ===== a truthfully-named member damaged inside its own first       =====
// ===== 16 KiB denies its descriptor exactly as an impostor does.    =====

/// Scratch directory for a test that needs its slots' bytes on disk
/// (the finish tiers read the file, not the in-memory head).
fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbkit-live-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// W4-02A: two intact payloads whose yEnc names are CROSSED must each
/// claim the descriptor their CONTENT names - in EITHER arrival order,
/// which is the half a name-first matcher could never give. Under
/// exact-first each slot claimed the other's descriptor, every
/// differing block read as damage, and an intact pair failed.
///
/// `head_last` is the case the tentative binding exists for: the
/// article carrying the first 16 KiB lands after another, so the name
/// is briefly the only evidence there is and the binding has to be
/// re-judged when the head completes.
#[test]
fn crossed_names_claim_by_content_in_either_arrival_order() {
    let a = data_of(20_000, 91);
    let b = data_of(20_000, 92);
    for head_last in [false, true] {
        let (v, _set) = active_verifier(&[("a.bin", &a), ("b.bin", &b)], 1024);
        // Slot 0 carries A under the name b.bin; slot 1 carries B as a.bin.
        if head_last {
            v.on_data(0, "b.bin", 20_000, 17_000, &a[17_000..]);
            v.on_data(1, "a.bin", 20_000, 17_000, &b[17_000..]);
        }
        v.on_data(0, "b.bin", 20_000, 0, &a[..17_000]);
        v.on_data(1, "a.bin", 20_000, 0, &b[..17_000]);
        if !head_last {
            v.on_data(0, "b.bin", 20_000, 17_000, &a[17_000..]);
            v.on_data(1, "a.bin", 20_000, 17_000, &b[17_000..]);
        }
        let dir = scratch(&format!("crossed-{head_last}"));
        let (p0, p1) = (dir.join("s0"), dir.join("s1"));
        std::fs::write(&p0, &a).unwrap();
        std::fs::write(&p1, &b).unwrap();
        let r0 = v.finish_slot(0, Some(&p0)).unwrap();
        let r1 = v.finish_slot(1, Some(&p1)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            (r0.par2_name.as_deref(), r1.par2_name.as_deref()),
            (Some("a.bin"), Some("b.bin")),
            "crossed names claimed by the NAME (head_last={head_last})"
        );
        assert!(
            r0.all_ok() && r1.all_ok(),
            "an intact crossed pair read as damage (head_last={head_last}): {r0:?} {r1:?}"
        );
    }
}

/// The fixture both F11 pins below are built on: one slot whose NAME
/// binds it to a long descriptor and whose HEAD, when it lands, denies
/// that descriptor and names a SHORTER one outright.
///
/// `(long, short, head, payload)`. The payload is the short file's
/// 16 KiB head over the long file's own body, which is what makes both
/// halves true at once: every block past the head verifies Ok against
/// the long descriptor (so the lock-free hash is a real MD5 pass over
/// megabytes, not a CRC32 that fails on the first word), and the head
/// itself is a unique unclaimed md5-16k match for the short one, which
/// is the only thing `rejudge_binding` drops a binding for.
fn crossed_length_fixture(long_len: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    const BS: usize = 16_384;
    let head = data_of(BS, 63);
    let long = data_of(long_len, 61);
    let mut short = data_of(20_000, 62);
    short[..BS].copy_from_slice(&head);
    let mut payload = long.clone();
    payload[..BS].copy_from_slice(&head);
    (long, short, head, payload)
}

/// F11's predicate, pinned on its own so it can never go quiet: dropping
/// a binding MOVES the generation that names which descriptor the block
/// grid was judged against.
///
/// `on_data_inner` snapshots `bind_gen` beside the block indices it
/// claimed, drops the slot lock to hash, and compares on the way back
/// in. Everything the guard does rests on this counter moving whenever
/// `blocks` is thrown away, and `unbind` is the only thing that throws
/// it away - so this is the whole of the invariant, tested where it is
/// deterministic rather than only where it is racy.
#[test]
fn dropping_a_binding_moves_the_generation_the_block_grid_is_named_by() {
    const BS: usize = 16_384;
    let (long, short, head, payload) = crossed_length_fixture(40_000);
    let v = LiveVerifier::new(1);
    let meta = par2_meta(
        [9u8; 16],
        BS,
        &[("long.bin", &long), ("short.bin", &short)],
        true,
    );
    v.activate(&[meta.as_slice()]).expect("fixture parses");
    // Head last: the name is briefly the only evidence there is, so the
    // slot binds tentatively to long.bin and claims ITS grid. A span
    // that completes no block, so nothing promotes the nomination to a
    // claim before the head lands - a promotion would put the binding
    // beyond `rejudge_binding`'s reach, which is the ordinary way this
    // race does NOT happen.
    v.on_data(0, "long.bin", 40_000, BS as u64, &payload[BS..BS + 512]);
    let (was, grid) = {
        let s = v.slots[0].lock_ok();
        assert!(s.file.is_some(), "the name nominated long.bin");
        (s.bind_gen, s.blocks.len())
    };
    assert_eq!(grid, 3, "long.bin is three blocks at this block size");
    // The head lands and re-judges: long.bin denied, short.bin named.
    v.on_data(0, "long.bin", 40_000, 0, &head);
    let s = v.slots[0].lock_ok();
    assert_ne!(
        s.bind_gen, was,
        "a dropped binding must move the generation - without it a hash \
         still in flight records its verdicts into the next binding's grid"
    );
    assert!(
        s.blocks.len() < grid,
        "the grid really did shrink under the rebind, which is what makes \
         the stale indices a panic rather than only a phantom: {} blocks",
        s.blocks.len()
    );
}

/// F11 (1 Sep 2026): verdicts computed outside the slot lock must be
/// DISCARDED when the binding moved while they were being computed.
///
/// `on_data_inner` claims its blocks under the lock, drops it to hash
/// (the module note says concurrent decode workers must not serialize),
/// and re-takes it to record. The decode consumers share ONE channel
/// with no keying by slot, so two articles of one file decode on two
/// threads - and since the tentative binding another thread can unbind
/// and rebind that slot inside the window, via `rejudge_binding` when a
/// head completes (this fixture) or via `promote_binding` losing the
/// claim race. Nothing re-read `s.file` or bounds-checked `s.blocks` on
/// the way back in, so the recording either panicked on a shorter grid -
/// inside the decode consumer, whose join is swallowed, so the job
/// silently loses a decoder and on a one-decoder box loses every
/// remaining article - or marked a phantom Bad on an intact file, which
/// settle never re-judges (it re-reads only `Pending`) and which rides
/// into the SlotReport as real damage.
///
/// THE HANDSHAKE IS THE MUTEX, not a sleep: the feeding thread holds the
/// slot lock from the top of `on_data_inner` until it drops it to hash,
/// so the FIRST time this thread can observe the long binding is that
/// exact instant. The head article then lands while the 4 MB MD5 pass is
/// still running. A miss is not a false alarm - it shows up as the final
/// binding assertion, which says the window was never entered.
///
/// IT HAS FLAKED, AND THE FAILING ASSERTION IS THE WHOLE DIAGNOSIS
/// (2 Sep 2026). It lost TRY 1 in two independent ci sweeps on one dev
/// box inside an hour, two different lanes, both green on retry. Before
/// anyone bisected: 30 runs alone under 12-way CPU load, 400 runs beside
/// a concurrently running full sweep, and two full sweeps at
/// `--retries 0` - 430 targeted runs, 0 failures. Both sightings fall
/// inside the hour that box's shared rustc toolchain was being wiped and
/// reinstalled repeatedly by competing lanes, which is filesystem and
/// process churn no ordinary load reproduces. A stall long enough for
/// the 4 MB hash to finish before the head lands is a BENIGN miss and
/// fails on the binding assertion below. Read WHICH assertion failed
/// before reading anything into it: only the join expectation and the
/// Bad-block count mean a production defect. Do not bisect this one on
/// the strength of a retried sweep line.
///
/// SO IT RETRIES ITS WINDOW (3 Sep 2026), because on Windows the benign
/// miss stopped being rare. `windows-one-process` runs nzbkit-base's
/// 1,190 tests in ONE libtest process with no `--test-threads=1`, and a
/// stall between observing the long binding and calling `on_data` long
/// enough for a 4 MB MD5 to finish is ordinary there rather than
/// exceptional - it took nightly red on 7ec5395d (run 33737735769), on
/// this test's binding assertion, which is the one the paragraph above
/// already says means nothing on its own. A miss now costs an attempt
/// instead of the run. What did NOT change is what the test is for: the
/// join expectation and the Bad-block count are checked on EVERY
/// attempt and a failure of either still fails immediately, and running
/// out of attempts without ever entering the window is itself a
/// failure - a window that never opens is a finding about the code
/// under test, not a licence to pass.
#[test]
fn a_binding_that_moves_mid_hash_discards_the_verdicts_it_computed() {
    const BS: usize = 16_384;
    const LONG: usize = 4_000_000;
    // Each attempt is one 4 MB MD5 pass, single-digit milliseconds of
    // work, so a generous count costs nothing against the ~120 s this
    // binary takes in one process.
    const ATTEMPTS: usize = 24;
    let (long, short, head, payload) = crossed_length_fixture(LONG);
    // Plan lock first, then the slot lock - the order `on_data_inner`
    // takes them in, so this observer can never invert it.
    let bound_name = |v: &LiveVerifier| -> Option<String> {
        let plan = v.plan.read_ok();
        let fi = v.slots[0].lock_ok().file;
        match (&*plan, fi) {
            (Plan::Active(a), Some(fi)) => Some(a.file(fi).name.clone()),
            _ => None,
        }
    };
    for attempt in 1..=ATTEMPTS {
        let v = LiveVerifier::new(1);
        let meta = par2_meta(
            [9u8; 16],
            BS,
            &[("long.bin", &long), ("short.bin", &short)],
            true,
        );
        v.activate(&[meta.as_slice()]).expect("fixture parses");
        std::thread::scope(|sc| {
            let t1 = sc.spawn(|| {
                v.on_data(0, "long.bin", LONG as u64, BS as u64, &payload[BS..]);
            });
            let t0 = std::time::Instant::now();
            while bound_name(&v).as_deref() != Some("long.bin") {
                assert!(
                    t0.elapsed() < std::time::Duration::from_secs(30),
                    "the feeding thread never took the long binding"
                );
                std::thread::yield_now();
            }
            // The head arrives on another decode thread, mid-hash.
            v.on_data(0, "long.bin", LONG as u64, 0, &head);
            // Load-bearing on every attempt, missed window or not: a
            // panic in the decode consumer is a production defect
            // whatever the timing did.
            t1.join().expect(
                "recording verdicts against a binding the slot no longer holds \
                 panicked inside the decode consumer",
            );
        });
        if bound_name(&v).as_deref() != Some("short.bin") {
            // Benign miss: the hash finished before the head landed, so
            // the race this test exists for never ran. Try again.
            continue;
        }
        let s = v.slots[0].lock_ok();
        assert_eq!(
            s.blocks.iter().filter(|b| **b == BlockState::Bad).count(),
            0,
            "a verdict judged against long.bin was recorded on short.bin's grid \
             (attempt {attempt})"
        );
        return;
    }
    panic!(
        "the head never re-judged the binding in {ATTEMPTS} attempts - the hash \
         window was never entered, so the race this test exists for did not run"
    );
}

/// W4-18: a file posted honestly under a name the recovery set also
/// uses, carrying an UNRELATED payload, must be left OUT of the set -
/// claiming it verified every block bad and failed the whole job. The
/// set's own member is absent here, so nothing outbids the name: the
/// only thing that can decline it is the file itself, and none of its
/// blocks is one of the descriptor's.
#[test]
fn a_stranger_wearing_a_set_members_name_is_left_out_of_the_set() {
    let real = data_of(20_000, 93);
    let stranger = data_of(20_000, 94); // same length, nothing in common
    let (v, _set) = active_verifier(&[("member.bin", &real)], 1024);
    v.on_data(0, "member.bin", 20_000, 0, &stranger);
    let dir = scratch("stranger");
    let p = dir.join("s0");
    std::fs::write(&p, &stranger).unwrap();
    let r = v.finish_slot(0, Some(&p));
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        r.is_none(),
        "a stranger wearing the name claimed the descriptor: {r:?}"
    );
    assert_eq!(
        v.unclaimed_files(),
        vec!["member.bin".to_string()],
        "the member is missing, not damaged - repair must recreate it"
    );
}

/// F12 (1 Sep 2026): W4-18 for the SMALL files W4-02's head arbiter
/// still let a name finalize. `head_says` calls a span mismatch
/// `Unknown`, and a sole `Unknown` candidate was CLAIMED outright - so
/// for any pairing where either the slot's declared size or the
/// descriptor's length is under 16 KiB, a poster-controlled name took a
/// descriptor with zero content evidence, exactly the pre-W4-02 answer
/// that row removed. The readme/nfo/sample shape reaches it every day:
/// one name shared by a set member and an uncovered file, with the two
/// lengths differing.
///
/// The head is NOT silent here and that is the whole correction. It
/// completed at 5,000 bytes, the descriptor's file is 3,000 bytes
/// whole, so this slot holds more bytes than that file has: it is
/// another file. Claiming reported an intact 3,000-byte member wholly
/// missing and demanded a full-file rebuild, which fails an otherwise
/// repairable job on a short-parity or verify-only set - and on a set
/// with parity to spend it OVERWRITES the uncovered file.
#[test]
fn a_stranger_longer_than_the_small_member_it_names_is_not_claimed_by_its_head() {
    let real = data_of(3_000, 101);
    let stranger = data_of(5_000, 102); // a different, longer file
    let (v, _set) = active_verifier(&[("readme.txt", &real)], 1024);
    v.on_data(0, "readme.txt", 5_000, 0, &stranger);
    assert!(
        !v.slots[0].lock_ok().confirmed,
        "the name finalized on a head that covers the descriptor whole"
    );
    let dir = scratch("f12-longer-stranger");
    let p = dir.join("s0");
    std::fs::write(&p, &stranger).unwrap();
    let r = v.finish_slot(0, Some(&p));
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        r.is_none(),
        "a longer stranger wearing the name claimed the descriptor: {r:?}"
    );
    assert_eq!(
        v.unclaimed_files(),
        vec!["readme.txt".to_string()],
        "the member is missing, not damaged - repair must recreate it"
    );
}

/// F12's second path, the one inside a single call: `finish_slot_from`
/// drops a name nomination its bytes DENIED, then runs `try_match`
/// twenty lines later, whose sole-`Unknown` arm re-claimed the very
/// descriptor the bytes had just refused - a self-contradiction in one
/// function.
///
/// Reached by arrival order rather than by size: the tail lands first,
/// so the name binds TENTATIVELY with no head to judge it. The head
/// then completes length-mismatched, which `rejudge_binding` leaves
/// alone (it moves a binding only on a `Deny` with a rival), so the
/// tentative binding survives to finish for `settle_binding` to deny.
#[test]
fn a_length_mismatched_head_does_not_reclaim_what_settle_just_dropped() {
    let real = data_of(3_000, 103);
    let stranger = data_of(5_000, 104);
    let (v, _set) = active_verifier(&[("readme.txt", &real)], 1024);
    v.on_data(0, "readme.txt", 5_000, 2_000, &stranger[2_000..]);
    assert!(
        v.slot_in_set(0) && !v.slots[0].lock_ok().confirmed,
        "a name with no head yet nominates, tentatively"
    );
    v.on_data(0, "readme.txt", 5_000, 0, &stranger[..2_000]);
    assert!(
        !v.slots[0].lock_ok().confirmed,
        "the completed head finalized a nomination it cannot compare"
    );
    let dir = scratch("f12-reclaim");
    let p = dir.join("s0");
    std::fs::write(&p, &stranger).unwrap();
    let r = v.finish_slot(0, Some(&p));
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        r.is_none(),
        "the re-match took back the descriptor settle had just denied: {r:?}"
    );
    assert_eq!(v.unclaimed_files(), vec!["readme.txt".to_string()]);
}

/// F12's control, and the reason the guard reads the DIRECTION of the
/// span mismatch rather than refusing every `Unknown`: W4-11's shape
/// through the NAME tier. The article under-declares `size=`, so the
/// head completes at 8 KiB where the descriptor's own `md5_16k` covers
/// 16 KiB and the two digests are incomparable - but the head is
/// genuinely SILENT there (it never reached the bytes the digest is
/// over), and this is a truthfully named member. It must still claim
/// and verify in-stream; declining would price a repairable file as
/// wholly missing.
#[test]
fn an_under_declared_size_still_claims_the_descriptor_its_name_gives() {
    let data = data_of(20_000, 105);
    let (v, _set) = active_verifier(&[("member.bin", &data)], 1024);
    v.on_data(0, "member.bin", 8_192, 0, &data[..8_192]);
    assert!(
        v.slots[0].lock_ok().confirmed,
        "a head shorter than the descriptor's own 16k span says nothing \
         against the name, so the sole candidate is still claimed"
    );
    assert_eq!(
        v.live_counts(),
        (8, 0),
        "and every delivered block verified in-stream"
    );
}

/// The regression guard the whole nomination rule is priced against: a
/// TRUTHFULLY named member damaged inside its own first 16 KiB denies
/// its descriptor's `md5_16k` exactly as an impostor does, and must
/// still claim, verify in-stream and be repaired in place. Declining it
/// would price a one-block repair as a wholly missing file.
#[test]
fn a_member_damaged_inside_its_own_head_still_claims_and_verifies_live() {
    let data = data_of(20_000, 95);
    let (v, _set) = active_verifier(&[("member.bin", &data)], 1024);
    let mut wrong = data.clone();
    wrong[500] ^= 0xFF; // damage block 0, which IS the md5-16k span
    v.on_data(0, "member.bin", 20_000, 0, &wrong);
    let (live, bad) = v.live_counts();
    assert_eq!(
        (live, bad),
        (20, 1),
        "a head-damaged member must still verify in-stream"
    );
    let r = v.finish_slot(0, None).unwrap();
    assert_eq!(r.par2_name.as_deref(), Some("member.bin"));
    assert_eq!(r.bad_blocks, vec![0], "{r:?}");
    assert_eq!(r.readback_blocks, 0, "no block was left for settle to read");
}

/// The other shape a denial cannot be told from: a member whose first
/// articles never arrived, so there is no head to judge the name by at
/// all. The nomination stands, the blocks that DID arrive verify
/// in-stream and promote it, and the slot is reported as the partially
/// damaged member it is - which is what the name-first matcher gave.
#[test]
fn a_member_missing_its_head_articles_keeps_its_nomination() {
    let data = data_of(20_000, 96);
    let (v, _set) = active_verifier(&[("member.bin", &data)], 1024);
    // Only the tail arrives - nothing covers the first 16 KiB.
    v.on_data(0, "member.bin", 20_000, 17_408, &data[17_408..]);
    let dir = scratch("headless");
    let p = dir.join("s0");
    let mut partial = vec![0u8; 20_000];
    partial[17_408..].copy_from_slice(&data[17_408..]);
    std::fs::write(&p, &partial).unwrap();
    let r = v.finish_slot(0, Some(&p));
    std::fs::remove_dir_all(&dir).unwrap();
    let r = r.expect("the member must still be claimed and priced as damaged");
    assert_eq!(r.par2_name.as_deref(), Some("member.bin"));
    assert!(
        !r.bad_blocks.is_empty() && r.bad_blocks.len() < r.total_blocks,
        "partially damaged, not wholly missing: {r:?}"
    );
}

/// W4-02B at the matcher: two descriptors sharing ONE exact name with
/// distinct content. FileDesc order must not decide which slot verifies
/// against which - the head does, and both must land clean whichever
/// slot arrives first.
#[test]
fn duplicate_exact_names_are_split_by_the_head_not_by_filedesc_order() {
    let one = data_of(20_000, 97);
    let two = data_of(20_000, 98);
    for reversed in [false, true] {
        let (v, _set) = active_verifier(&[("dup.bin", &one), ("dup.bin", &two)], 1024);
        let (first, second) = if reversed { (&two, &one) } else { (&one, &two) };
        v.on_data(0, "dup.bin", 20_000, 0, first);
        v.on_data(1, "dup.bin", 20_000, 0, second);
        let r0 = v.finish_slot(0, None).unwrap();
        let r1 = v.finish_slot(1, None).unwrap();
        assert!(
            r0.all_ok() && r1.all_ok(),
            "duplicate exact names crossed (reversed={reversed}): {r0:?} {r1:?}"
        );
        assert!(
            v.unclaimed_files().is_empty(),
            "both descriptors must be claimed (reversed={reversed})"
        );
    }
}

/// The evidence tier under all of it: a slot that reached finish having
/// verified NOTHING in-stream - every article landed before the set was
/// known - whose name is a member's and whose head is damaged, so the
/// name is denied and there is no live block to vouch for it. One
/// intact block of that descriptor in the bytes on disk is the proof,
/// and it is what separates this file from the stranger above.
#[test]
fn a_late_activated_member_with_a_damaged_head_claims_on_block_evidence() {
    let data = data_of(20_000, 99);
    let mut wrong = data.clone();
    wrong[300] ^= 0xFF; // block 0 only - the md5-16k span
    let v = LiveVerifier::new(1);
    // Every byte arrives BEFORE the set is known, so nothing is verified
    // in-stream and no block can promote a binding.
    v.on_data(0, "member.bin", 20_000, 0, &wrong);
    let meta = par2_meta([9u8; 16], 1024, &[("member.bin", &data)], true);
    v.activate(&[meta.as_slice()]).expect("fixture parses");
    let dir = scratch("lateblock");
    let p = dir.join("s0");
    std::fs::write(&p, &wrong).unwrap();
    let r = v.finish_slot(0, Some(&p));
    std::fs::remove_dir_all(&dir).unwrap();
    let r = r.expect("block evidence must claim the descriptor for its damaged member");
    assert_eq!(r.par2_name.as_deref(), Some("member.bin"));
    assert_eq!(
        r.bad_blocks,
        vec![0],
        "one damaged block, not a missing file: {r:?}"
    );
}

/// M4-41: a Reader source that is LONGER than the descriptor is not
/// that descriptor's file, and the two source kinds must say so alike.
///
/// [`src_md5`]'s `Path` arm refuses on `metadata().len() != expect_len`.
/// Its `Reader` arm hashes exactly `expect_len` bytes from offset 0 and
/// never asks the source how long it is, so a FileDesc for a PREFIX of
/// a longer mapped or chased buffer whole-file-MATCHES and the suffix
/// bytes vanish into a "verified" short file. Direct-extracted and
/// mapped volumes are precisely the slots that take the Reader arm
/// (`get/settle.rs`: `is_mapped(sidx) || is_chased(sidx)`), so the
/// M4-09 Path-slot prefix pair being green on the wave-4 verification
/// round says nothing about this half.
///
/// Both legs below run the SAME descriptor over the SAME 4096 bytes.
/// Whatever the verdict is, it may not depend on which arm served them.
#[test]
fn a_reader_source_longer_than_the_descriptor_is_refused_like_a_path() {
    let data = data_of(4096, 11);
    // One descriptor, 2048 bytes: a genuine prefix of `data`.
    let meta = par2_meta([9u8; 16], 4096, &[("prefix.bin", &data[..2048])], false);

    let v = LiveVerifier::new(1);
    v.activate(&[meta.as_slice()]).unwrap();
    v.set_name_hint(0, "prefix.bin");
    let reader = v
        .finish_slot_from(0, ReadAt::Reader(&|off, buf| read_span(&data, off, buf)))
        .unwrap();

    let dir = std::env::temp_dir().join(format!("nzbkit-live-prefix-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("mapped.bin");
    std::fs::write(&path, &data).unwrap();
    let v2 = LiveVerifier::new(1);
    v2.activate(&[meta.as_slice()]).unwrap();
    v2.set_name_hint(0, "prefix.bin");
    let disk = v2.finish_slot(0, Some(&path)).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();

    assert!(
        !disk.all_ok(),
        "control: the Path arm must refuse a 4096-byte file for a \
         2048-byte descriptor: {disk:?}"
    );
    assert!(
        !reader.all_ok(),
        "a 4096-byte Reader source verified as the 2048-byte descriptor \
         'prefix.bin' - the suffix vanished into a file the set now calls \
         proved: {reader:?}"
    );
}

/// M4-41's control: a Reader source that is EXACTLY the descriptor's
/// length still verifies. The length check added for the row above asks
/// the source for one byte past the end, and a source that legitimately
/// ends there must refuse it - if this ever goes red, the check has
/// started refusing healthy mapped and chased slots, which is a far
/// worse trade than the hole it closed.
#[test]
fn a_reader_source_of_exactly_the_descriptor_length_still_verifies() {
    let data = data_of(4096, 12);
    let meta = par2_meta([9u8; 16], 4096, &[("exact.bin", &data)], false);
    let v = LiveVerifier::new(1);
    v.activate(&[meta.as_slice()]).unwrap();
    v.set_name_hint(0, "exact.bin");
    let r = v
        .finish_slot_from(0, ReadAt::Reader(&|off, buf| read_span(&data, off, buf)))
        .unwrap();
    assert!(
        r.all_ok(),
        "an exact-length Reader source was refused: {r:?}"
    );
}

// ---------------------------------------------------------------- X5-18

/// The interval merge `Partial::fill` used to do: rebuild the whole
/// vector, absorbing anything the new span touches, then re-sort it.
/// Kept verbatim as the ORACLE for the test below - it is the definition
/// of what the cheap merge has to mean, so do not "tidy" it into a
/// paraphrase of the code it is checking.
fn reference_merge(filled: &[(usize, usize)], at: usize, len: usize) -> Vec<(usize, usize)> {
    let (mut s, mut e) = (at, at + len);
    let mut merged = Vec::with_capacity(filled.len() + 1);
    for &(fs, fe) in filled {
        if fe < s || fs > e {
            merged.push((fs, fe));
        } else {
            s = s.min(fs);
            e = e.max(fe);
        }
    }
    merged.push((s, e));
    merged.sort_unstable();
    merged
}

/// X5-18: `Partial::fill` now merges by binary-searching the two ends of
/// the run a fragment touches, where it rebuilt and re-SORTED the whole
/// interval list on every fragment before. The COST of that swap is
/// pinned by a ratio over geometric N in
/// `crates/nzbfast/tests/e2e_wave5_cost/`; this pins what a timing ratio
/// can never see, which is whether the cheaper merge still means the
/// same thing - the whole risk in replacing an algorithm under a hot
/// path.
///
/// Held to [`reference_merge`] after EVERY fragment rather than only at
/// the end, because the two agreeing on a completed block says nothing
/// about the states in between - and it is an intermediate state that
/// `complete()` reads. Spans are drawn to overlap freely, so every
/// relation two intervals can be in is exercised: disjoint, touching at
/// either end (the case `complete()` depends on, since a filled block is
/// only ever recognisable as the single span `[(0, len)]`), partially
/// overlapping, and one wholly containing the other.
#[test]
fn partial_fill_merges_exactly_as_the_rebuild_and_sort_it_replaced() {
    const BLEN: usize = 4096;
    let bytes = vec![7u8; BLEN];
    let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
    // Both halves of the hybrid store have to be walked, or this is a
    // green oracle over one representation - so the rounds alternate two
    // generators and BOTH outcomes are asserted below. DENSE draws spans
    // up to a quarter of the block, which is what puts every relation two
    // intervals can be in on the table (disjoint, touching at either end,
    // partially overlapping, one wholly containing the other) but merges
    // so hard that the run count never approaches the threshold. SPARSE
    // draws short spans on a coarse grid, which is what accumulates runs
    // past it - and the grid is why touching-at-a-shared-endpoint is
    // COMMON there rather than a 1-in-BLEN coincidence.
    let (mut saw_vec, mut saw_tree) = (false, false);
    for round in 0..300u32 {
        let dense = round % 2 == 0;
        let n = 1 + (next(&mut rng) % if dense { 24 } else { 160 }) as usize;
        let mut p = Partial::new(BLEN);
        let mut oracle: Vec<(usize, usize)> = Vec::new();
        for step in 0..n {
            let (s, e) = if dense {
                let a = (next(&mut rng) % BLEN as u64) as usize;
                let b = a + (next(&mut rng) % (BLEN as u64 / 4)) as usize;
                (a, (b + 1).min(BLEN))
            } else {
                const GRID: usize = 16;
                let a = GRID * (next(&mut rng) % (BLEN as u64 / GRID as u64)) as usize;
                let len = GRID * (1 + (next(&mut rng) % 2) as usize);
                (a, (a + len).min(BLEN))
            };
            p.fill(s, &bytes[s..e]);
            oracle = reference_merge(&oracle, s, e - s);
            assert_eq!(
                p.intervals(),
                oracle,
                "round {round} step {step}: fill({s}..{e}) diverged from the \
                 rebuild-and-sort merge"
            );
            assert_eq!(
                p.complete(),
                oracle == [(0, BLEN)],
                "round {round} step {step}: complete() disagrees with the oracle"
            );
        }
        saw_vec |= !p.uses_tree();
        saw_tree |= p.uses_tree();
    }
    assert!(
        saw_vec && saw_tree,
        "the differential never crossed RUNS_TREE_AT (vec={saw_vec} tree={saw_tree}), \
         so one half of the hybrid store went untested"
    );
}

/// xorshift64*, so the arrival orders below are wide but the failures are
/// reproducible: a flake nobody can re-run is not a pin.
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// The sorted-`Vec` `CrcParts::insert` the hybrid store replaced, kept
/// verbatim as the ORACLE for the test below - it is the definition of
/// what the new merge has to mean, so do not "tidy" it into a paraphrase
/// of the code it is checking. Same role, and the same standing warning,
/// as [`reference_merge`] above.
struct VecCrcParts {
    parts: Vec<(usize, usize, u32)>,
}

impl VecCrcParts {
    fn new() -> VecCrcParts {
        VecCrcParts {
            parts: Vec::with_capacity(2),
        }
    }

    fn insert(&mut self, s: usize, e: usize, crc: u32) -> bool {
        let at = self.parts.partition_point(|&(ps, _, _)| ps < s);
        if at > 0 && self.parts[at - 1].1 > s {
            return false;
        }
        if at < self.parts.len() && self.parts[at].0 < e {
            return false;
        }
        self.parts.insert(at, (s, e, crc));
        if at + 1 < self.parts.len() && self.parts[at].1 == self.parts[at + 1].0 {
            let (_, re, rc) = self.parts.remove(at + 1);
            let p = &mut self.parts[at];
            p.2 = crate::yenc_simd::crc32_combine(p.2, rc, (re - p.1) as u64);
            p.1 = re;
        }
        if at > 0 && self.parts[at - 1].1 == self.parts[at].0 {
            let (_, e2, c2) = self.parts.remove(at);
            let p = &mut self.parts[at - 1];
            p.2 = crate::yenc_simd::crc32_combine(p.2, c2, (e2 - p.1) as u64);
            p.1 = e2;
        }
        true
    }
}

/// X5-18: `CrcParts` is the DEFAULT path - a block claimed on composed
/// CRC32 alone - and it had no differential of its own, only the timing
/// ratio in `crates/nzbfast/tests/e2e_wave5_cost/`. A ratio cannot see
/// whether the cheaper merge still MEANS the same thing, which is the
/// whole risk in swapping a structure under a hot path, and the risk here
/// is sharper than on the byte path next door: `crc32_combine` is
/// order-sensitive, so a merge that joins the right pair in the wrong
/// order composes a CRC that is simply wrong and the block is then
/// reported Ok or Bad on it.
///
/// Held to [`VecCrcParts`] after EVERY fragment - the parts in order,
/// their CRCs, `complete()`, and the bool the caller spills on - because
/// the two agreeing on a finished block says nothing about the states in
/// between, and `complete()` reads exactly those.
///
/// Fragments TILE the block and are then shuffled, so every arrival order
/// is legal and the eager adjacency merge is exercised from both sides;
/// a second pass re-feeds fragments already in, which is the overlap the
/// refusal exists for.
#[test]
fn crc_parts_merges_exactly_as_the_sorted_vec_it_replaced() {
    const BLEN: usize = 8192;
    let mut rng: u64 = 0x2545_F491_4F6C_DD1D;
    let (mut saw_vec, mut saw_tree, mut saw_refusal) = (false, false, false);
    for round in 0..120u32 {
        // Shuffled TILES merge as they land, so the live run count peaks
        // far below the fragment count - measured at roughly n/7 - and a
        // range that merely passed RUNS_TREE_AT would never reach the tree
        // half. Hence 320: it puts the peak comfortably past the threshold
        // while the low end of the range stays on the Vec.
        let n = 1 + (next(&mut rng) % 320) as usize;
        // Cut BLEN into n non-empty pieces at n-1 distinct interior points.
        let mut cuts: Vec<usize> = (1..BLEN).step_by(BLEN / n.max(1)).take(n - 1).collect();
        cuts.push(BLEN);
        let mut frags: Vec<(usize, usize)> = Vec::with_capacity(n);
        let mut prev = 0;
        for c in cuts {
            if c > prev {
                frags.push((prev, c));
                prev = c;
            }
        }
        // Fisher-Yates on the same reproducible stream.
        for i in (1..frags.len()).rev() {
            frags.swap(i, (next(&mut rng) % (i as u64 + 1)) as usize);
        }
        // A second pass over a prefix of the same fragments: every one of
        // those is an exact re-feed, which must be REFUSED by both.
        let redeliver = (next(&mut rng) % (frags.len() as u64 + 1)) as usize;
        let feed: Vec<(usize, usize)> = frags
            .iter()
            .copied()
            .chain(frags.iter().copied().take(redeliver))
            .collect();

        let mut got = CrcParts::new();
        let mut want = VecCrcParts::new();
        for (step, &(s, e)) in feed.iter().enumerate() {
            // A per-fragment crc that depends on the span, so a merge that
            // combines the wrong pair cannot agree by accident.
            let crc = (s as u32).wrapping_mul(0x9E37_79B1) ^ (e as u32);
            let a = got.insert(s, e, crc);
            let b = want.insert(s, e, crc);
            saw_refusal |= !a;
            assert_eq!(
                a, b,
                "round {round} step {step}: insert({s}..{e}) answered {a}, \
                 the sorted Vec answered {b}"
            );
            assert_eq!(
                got.parts_in_order(),
                want.parts,
                "round {round} step {step}: insert({s}..{e}) diverged from \
                 the sorted-Vec merge"
            );
            let oracle_complete = match want.parts.as_slice() {
                [(0, e, crc)] if *e == BLEN => Some(*crc),
                _ => None,
            };
            assert_eq!(
                got.complete(BLEN),
                oracle_complete,
                "round {round} step {step}: complete() disagrees with the oracle"
            );
        }
        saw_vec |= !got.uses_tree();
        saw_tree |= got.uses_tree();
    }
    assert!(
        saw_vec && saw_tree && saw_refusal,
        "the differential missed a case (vec={saw_vec} tree={saw_tree} \
         overlap_refusal={saw_refusal}), so it is not testing what it says"
    );
}

/// X5-18 (composition arm): the arrival order the row is about, on the
/// path a default-mode download actually takes. The differential above
/// compares two implementations and would agree just as happily if both
/// composed nonsense; this says the composed CRC is the block's REAL
/// CRC32 after 256 fragments and 255 merges, which is the number the
/// verifier hands to `crc_matches`.
#[test]
fn crc_parts_composes_the_real_crc_after_an_every_other_delivery() {
    const BLEN: usize = 4096;
    const FRAGS: usize = 256;
    const STEP: usize = BLEN / FRAGS;
    let bytes: Vec<u8> = (0..BLEN).map(|i| (i % 251) as u8).collect();
    let whole = crc32fast::hash(&bytes);
    let mut c = CrcParts::new();
    for i in (0..FRAGS).step_by(2).chain((1..FRAGS).step_by(2)) {
        assert_eq!(
            c.complete(BLEN),
            None,
            "completed before every fragment landed"
        );
        let at = i * STEP;
        assert!(
            c.insert(at, at + STEP, crc32fast::hash(&bytes[at..at + STEP])),
            "fragment {i} was refused as an overlap"
        );
    }
    assert!(
        c.uses_tree(),
        "{FRAGS} disjoint fragments did not cross RUNS_TREE_AT, so this \
         never exercised the tree half of the store"
    );
    assert_eq!(
        c.complete(BLEN),
        Some(whole),
        "the composed CRC is not the block's own CRC32"
    );
}

/// The store promotes once, past [`runs::RUNS_TREE_AT`], and never goes
/// back - which is what keeps the ordinary boundary block (1-10 runs, and
/// one after an in-order merge) on the `Vec` it was measured on. Pinned
/// structurally rather than by timing: the whole point of the threshold
/// is a representation choice, and a timing test cannot see which
/// representation it got.
#[test]
fn the_run_store_promotes_only_past_its_threshold() {
    const BLEN: usize = 1 << 14;
    let bytes = vec![3u8; BLEN];
    // Disjoint, never-adjacent fragments, so the run count is the
    // fragment count and nothing merges it back down.
    let mut p = Partial::new(BLEN);
    for i in 0..runs::RUNS_TREE_AT {
        p.fill(i * 4, &bytes[..1]);
        assert!(
            !p.uses_tree(),
            "promoted at {} runs, before the threshold of {}",
            i + 1,
            runs::RUNS_TREE_AT
        );
    }
    p.fill(runs::RUNS_TREE_AT * 4, &bytes[..1]);
    assert!(p.uses_tree(), "never promoted past the threshold");
    // Merging every gap shut leaves ONE run and must not demote - a store
    // that oscillated across the boundary would allocate on each crossing.
    for i in 0..runs::RUNS_TREE_AT {
        p.fill(i * 4, &bytes[..4]);
    }
    assert_eq!(p.intervals(), [(0, runs::RUNS_TREE_AT * 4 + 1)]);
    assert!(p.uses_tree(), "demoted back to the Vec on merging down");
}

/// The belt in [`CrcParts::complete`]: a run past the block end sitting
/// beside a full `0..blen` must NOT read as complete. Production cannot
/// build that state - `on_data_inner` clips every fragment with `oe =
/// span.end.min(bend)` before it ever reaches the store - so it is pinned
/// here through the store's own door instead, because a guard nothing can
/// falsify is a guard nobody can tell has stopped working.
#[test]
fn crc_parts_will_not_complete_a_block_with_a_run_past_its_end() {
    const BLEN: usize = 1024;
    let mut c = CrcParts::new();
    assert!(c.insert(0, BLEN, 11));
    assert_eq!(c.complete(BLEN), Some(11), "the block itself must complete");
    // A gap, so this cannot merge into the run below it.
    assert!(c.insert(BLEN + 8, BLEN + 16, 22));
    assert_eq!(
        c.complete(BLEN),
        None,
        "a store holding bytes past the block end composed the block's CRC"
    );
}

/// A degenerate span is refused rather than stored, which is the ONE
/// deliberate difference from the sorted `Vec` this replaced (it stored a
/// second entry under a key some real run already owned, then composed a
/// CRC over both). Unreachable from a decoded span - `os < oe` by
/// construction - and pinned so the refusal is a decision rather than an
/// accident of the container.
#[test]
fn crc_parts_refuses_an_empty_span() {
    let mut c = CrcParts::new();
    assert!(c.insert(0, 100, 7));
    assert!(
        !c.insert(0, 0, 9),
        "an empty span at a live start was stored"
    );
    assert!(!c.insert(500, 500, 9), "an empty span in a gap was stored");
    assert_eq!(c.parts_in_order(), [(0, 100, 7)]);
}

/// X5-18 (coverage arm): the arrival order the row is actually about -
/// every other fragment, then the ones between - must still finish as
/// ONE span and answer `complete()`. The property test above compares
/// against an oracle and would pass just as happily if BOTH sides never
/// merged anything; this asserts the merge really closes.
#[test]
fn partial_fill_completes_a_block_delivered_every_other_fragment_first() {
    const BLEN: usize = 4096;
    const FRAGS: usize = 256;
    const STEP: usize = BLEN / FRAGS;
    let bytes: Vec<u8> = (0..BLEN).map(|i| (i % 251) as u8).collect();
    let mut p = Partial::new(BLEN);
    for i in (0..FRAGS).step_by(2).chain((1..FRAGS).step_by(2)) {
        assert!(!p.complete(), "completed before every fragment landed");
        let at = i * STEP;
        p.fill(at, &bytes[at..at + STEP]);
    }
    assert!(
        p.complete(),
        "a fully covered block did not close to one span: {:?}",
        p.intervals()
    );
    assert_eq!(p.buf, bytes, "the bytes must be the ones that were fed");
}

/// M4-03 / W4-04's ordering half, and the reason the row is closed:
/// two damaged identical-head twins land under their own names
/// whichever ORDER they settle in, by two different tiers.
///
/// `try_match_whole` is entered only when TWO or more UNCLAIMED
/// descriptors share the slot's head (`cands.len() < 2` returns), and
/// `cands` is filtered on the claim table - so the count depends on
/// WHEN the slot asks. Both twins asking before either claims is the
/// per-block IFSC pairing that sweep item 13 landed. The twin asking
/// SECOND, after its rival has already claimed, never reaches that arm
/// at all: by then the surviving descriptor is unique among the
/// unclaimed, and `try_match`'s md5-16k tier above it claims on that
/// uniqueness - which its own comment already anticipates ("a twin's
/// claim makes the remaining candidate unique on retry").
///
/// So the two tiers hand off, and the hand-off is what makes the pair
/// order-independent. It is pinned here because nothing pinned it: the
/// sibling `damaged_identical_head_twins_claim_on_per_block_evidence`
/// drives ONE order, and the e2e rows cannot drive either - settle is a
/// single post-download pass, so a wire stall staggers arrival without
/// staggering the tier (measured 30 Aug 2026: a 2 s `slow_ttfb` on
/// every article of one twin still had both slots snapshot two
/// candidates and both log the IFSC pairing).
///
/// A narrowing of the md5-16k uniqueness rule would therefore silently
/// price the LAST twin to settle as wholly missing, with the IFSC pin
/// next door still green.
#[test]
fn damaged_identical_head_twins_land_in_either_settle_order() {
    for first in [0usize, 1] {
        let mut a = vec![0u8; 20_000];
        let mut b = vec![0u8; 20_000];
        a[16_384..].copy_from_slice(&data_of(3_616, 71));
        b[16_384..].copy_from_slice(&data_of(3_616, 72));
        let (v, _set) = active_verifier(&[("twin.a.vob", &a), ("twin.b.vob", &b)], 1024);
        // Block 16 of each is damaged, past the shared 16 KiB head: the
        // heads still agree, so every candidate's whole-file MD5 fails
        // and neither slot can be named by content alone.
        let (mut da, mut db) = (a.clone(), b.clone());
        da[17_000] ^= 0xff;
        db[17_000] ^= 0xff;
        // Slot 0 carries b's bytes, so a pairing taken by position
        // rather than by evidence is crossed rather than merely lucky.
        v.on_data(0, "Xk1jibber", 20_000, 0, &db);
        v.on_data(1, "Qz2jibber", 20_000, 0, &da);
        let bytes = [&db, &da];
        let mut got: [Option<SlotReport>; 2] = [None, None];
        // Strictly sequential, and the far slot only after the near one
        // has taken its claim - which is the whole point of the row.
        got[first] = finish_from(&v, first, bytes[first]);
        let second = 1 - first;
        got[second] = finish_from(&v, second, bytes[second]);
        let r0 = got[0].as_ref().unwrap_or_else(|| {
            panic!("slot 0 declined when slot {first} settled first - the tier hand-off broke")
        });
        let r1 = got[1].as_ref().unwrap_or_else(|| {
            panic!("slot 1 declined when slot {first} settled first - the tier hand-off broke")
        });
        assert_eq!(
            r0.par2_name.as_deref(),
            Some("twin.b.vob"),
            "crossed claim with slot {first} settling first"
        );
        assert_eq!(
            r1.par2_name.as_deref(),
            Some("twin.a.vob"),
            "crossed claim with slot {first} settling first"
        );
        // The damaged block and nothing else: a slot priced WHOLLY
        // missing is what the hand-off failing looks like, and it would
        // read as 20 bad blocks rather than one.
        assert_eq!(r0.bad_blocks, vec![16], "{r0:?} (first={first})");
        assert_eq!(r1.bad_blocks, vec![16], "{r1:?} (first={first})");
    }
}

/// M4-103, FIXED 31 Aug 2026 - this replaces the pin that asserted the
/// gap (`an_uncovered_file_sharing_a_zero_head_claims_the_member_it_is_not`,
/// 30 Aug 2026), which went red on the fix exactly as its own comment
/// said it should.
///
/// The md5-16k tier in [`SlotState::try_match`] used to FINALIZE
/// identity - `claimed[fi] = Some(slot)`, `confirmed = true` - on 16 KiB
/// of head and nothing else, whenever that head was unique among the
/// unclaimed descriptors. Nothing after that re-read the file, so a file
/// the recovery set does not cover claimed a member's descriptor as soon
/// as it shared that member's first 16 KiB - the ordinary shape of a
/// zero-filled head, and the very thing the tier's own PLURAL decline
/// names ("padded VOBs, disk images"). It was the
/// `wave4-fix-exact-name-authority` rule - a weaker clue may NOMINATE,
/// only the strongest available evidence may FINALIZE - broken through
/// the CONTENT door rather than the name door it was written for, and
/// the W4-18 class by that route: the uncovered file was renamed onto
/// the member, verified AS the member, and failed the whole job.
///
/// The head now NOMINATES. It still takes the claim (that is what every
/// exclusion this tier depends on is built from, and what keeps the hot
/// path unchanged), but the claim is REVOCABLE: `settle_binding`
/// re-judges it at finish, and the evidence is the one thing the head
/// cannot manufacture - what this slot's OWN blocks said. Here they
/// match the shared zero head and then never match again, which is a
/// shared prefix and not damage, because damage is missing ARTICLES and
/// a block no article covered is `Pending` rather than `Bad`.
///
/// LENGTH ALONE WAS PRICED AND REFUSED, twice over, which is why this is
/// written against the blocks. The candidate filter compares
/// `f.length.min(HEAD_LEN) != want`, so every file of 16 KiB or more
/// falls in ONE bucket and this 40,000-byte slot reaches a 20,000-byte
/// descriptor; tightening THAT to an exact length denies the match
/// outright, including for the posts whose `size=` disagrees with the
/// FileDesc that `HeadSays::Unknown` exists for. And the seemingly
/// stronger spelling - the slot's SETTLED extent rather than its header -
/// collapses to the same comparison in production, because `get`
/// preallocates the output file at the declared size. See
/// `SlotState::head_nomination_holds`, which records both.
#[test]
fn an_uncovered_file_sharing_a_zero_head_is_left_out_of_the_set() {
    let mut member = vec![0u8; 20_000];
    member[16_384..].copy_from_slice(&data_of(3_616, 71));
    let (v, _set) = active_verifier(&[("member.vob", &member)], 1024);
    // Not a member of the set at all: same zero-filled 16 KiB head
    // (padded VOBs, disk images, container prefixes), different bytes
    // everywhere after it, posted under an obfuscated name so the name
    // tier has nothing to say.
    let mut uncovered = vec![0u8; 40_000];
    uncovered[16_384..].copy_from_slice(&data_of(23_616, 99));
    v.on_data(0, "Wp3jibber", 40_000, 0, &uncovered);
    // In-stream the nomination is held, blocks and all - that is what
    // keeps out-of-order arrival at zero read-back for the honest post,
    // and it is why the claim has to be revocable rather than never
    // taken.
    assert!(v.slot_in_set(0), "the head nominates in-stream");
    assert!(
        finish_from(&v, 0, &uncovered).is_none(),
        "an uncovered payload must not take a member's descriptor on a \
         shared 16 KiB head"
    );
    // And the claim goes back: left held by a slot that turned out not to
    // be its file, the member would be reported neither verified nor
    // missing, and the repair would still address this payload by that
    // name.
    assert_eq!(
        v.unclaimed_files(),
        vec!["member.vob".to_string()],
        "the descriptor is missing, which is what it is"
    );
}

/// F10 (1 Sep 2026): M4-103's guard shipped on top of an ERASER, and
/// nobody looked at the seam.
///
/// `settle` calls [`LiveVerifier::force_readback`] for every slot whose
/// writer saw an overlapping write, unconditionally and immediately
/// before `finish_slot_from`, and that resets EVERY block to `Pending`
/// (its own inline note is the authority - the doc paragraph saying Bad
/// verdicts are left alone had been stale since 75a78920f).
/// `head_nomination_holds` reads ONLY the block states, and
/// `finish_slot_from` settles the nomination BEFORE its read-back loop
/// runs, so the impostor's Bad blocks were gone before they were
/// consulted: `position(Bad)` found nothing, the nomination was
/// confirmed VACUOUSLY, and the uncovered payload was published under
/// the member's name and priced as a badly damaged member - the exact
/// pre-M4-103 outcome, with the guard in place and green.
///
/// It is not a hypothetical corner either: one poster controls both
/// halves. The same post that shares the member's zero-filled head can
/// include one of its own articles TWICE, which is the malformed-post
/// case `force_readback` exists for.
///
/// The fix restores the evidence rather than trusting the erased copy:
/// `force_readback` keeps WHICH blocks an article delivered, and those
/// are read back from disk before the nomination is settled. Note what
/// this fixture shares with the sibling above - the same member, head,
/// obfuscated name, tier and payload. The only difference is the
/// `force_readback` call.
#[test]
fn a_forced_readback_does_not_confirm_a_head_nomination_vacuously() {
    let mut member = vec![0u8; 20_000];
    member[16_384..].copy_from_slice(&data_of(3_616, 71));
    let (v, _set) = active_verifier(&[("member.vob", &member)], 1024);
    let mut uncovered = vec![0u8; 40_000];
    uncovered[16_384..].copy_from_slice(&data_of(23_616, 99));
    v.on_data(0, "Wp3jibber", 40_000, 0, &uncovered);
    assert!(v.slot_in_set(0), "the head nominates in-stream");
    // What settle.rs does for a slot whose writer saw an overlapping
    // write - a duplicated segment, two articles with overlapping
    // `=ypart` ranges, an unclaim-and-refetch under crc_steer.
    v.force_readback(0);
    assert!(
        finish_from(&v, 0, &uncovered).is_none(),
        "an overlapping write must not turn a head nomination into a \
         claim on erased evidence"
    );
    assert_eq!(
        v.unclaimed_files(),
        vec!["member.vob".to_string()],
        "the descriptor is missing, which is what it is"
    );
}

/// The half F10's fix must not cost, and the reason it reads back the
/// DELIVERED blocks rather than all of them: a truthfully nominated
/// member that is merely DAMAGED keeps its descriptor even when a
/// forced read-back has erased its in-stream verdicts.
///
/// Reading the whole grid back instead would settle this slot's
/// undelivered tail as Bad - production preallocates the output file at
/// the declared size, so the holes read back as zeros - and deny the
/// nomination on the prefix signature, pricing a repairable file WHOLLY
/// MISSING. Silence has to stay silence, which is `head_nomination_holds`'s
/// own rule; `readback_forced` is what carries it across the reset.
#[test]
fn a_forced_readback_does_not_cost_a_damaged_member_its_descriptor() {
    let mut member = vec![0u8; 20_000];
    member[16_384..].copy_from_slice(&data_of(3_616, 71));
    let (v, _set) = active_verifier(&[("member.vob", &member)], 1024);
    let landed = &member[..18_000];
    v.on_data(0, "Wp3jibber", 20_000, 0, landed);
    v.force_readback(0);
    let r = finish_from(&v, 0, landed)
        .expect("a member short of its own declared size is damaged, not an impostor");
    assert_eq!(r.par2_name.as_deref(), Some("member.vob"));
    assert!(
        !r.bad_blocks.is_empty() && r.bad_blocks.len() < 20,
        "repairable damage, not a wholly-missing file: {r:?}"
    );
    assert!(v.unclaimed_files().is_empty(), "the member is claimed");
}

/// F9 (1 Sep 2026), the residue M4-103 left behind it: the head
/// nomination's CLAIM became revocable, but the `unmatchable` latch it
/// inflicts on the RIVAL slot stayed permanent.
///
/// The md5-16k tier tested `claimed[fi].is_some()` BEFORE it compared
/// the head digest, so a slot whose head DID name that descriptor came
/// out of the loop indistinguishable from one whose head named nothing:
/// `hit` None and `head_ambiguous` false. With an obfuscated yEnc name
/// the name tier is silent too, so the latch fired on the real member.
/// Nothing in a run re-opens it - only a head LENGTH change
/// (`capture_head`) or a second recovery set activating do, and neither
/// happens here - so every later article returned at `on_data`'s
/// early-out and `finish_slot_from` skipped the whole last-chance
/// ladder. When the impostor's nomination was denied at ITS finish and
/// handed the claim back, the member was STILL refused: a byte-perfect
/// file on disk reported wholly missing, and then priced against parity
/// at 20 blocks rather than the zero it needs.
///
/// So a descriptor another slot merely HOLDS no longer feeds the latch.
/// Note what this fixture shares with
/// `an_uncovered_file_sharing_a_zero_head_is_left_out_of_the_set` above:
/// the same member, head, obfuscated name and tier. The only difference
/// is that the member is HERE, in a second slot, which is what turns the
/// impostor's momentary claim into a verdict about somebody else.
///
/// STATED RESIDUE, deliberately not closed at this site: this rescues
/// the settle order where the impostor finishes FIRST. `settle_slots` is
/// a work-stealing scope, so the reverse order still reaches the
/// member's finish while the claim is held, finds nothing, and returns
/// None. Closing that needs a second pass over still-unbound slots after
/// every `finish_slot_from` has returned, which is follow-up 1 of the
/// M4-03/M4-04 matrix lane and is still open.
#[test]
fn a_member_whose_descriptor_an_impostor_holds_is_not_latched_unmatchable() {
    let mut member = vec![0u8; 20_000];
    member[16_384..].copy_from_slice(&data_of(3_616, 71));
    let v = LiveVerifier::new(2);
    let meta = par2_meta([9u8; 16], 1024, &[("member.vob", &member)], true);
    v.activate(&[meta.as_slice()]).expect("fixture parses");
    // Slot 0: an uncovered payload sharing the member's zero-filled
    // 16 KiB head, listed first, so its head completes first and its
    // nomination takes the member's descriptor.
    let mut uncovered = vec![0u8; 40_000];
    uncovered[16_384..].copy_from_slice(&data_of(23_616, 99));
    v.on_data(0, "Wp3jibber", 40_000, 0, &uncovered);
    assert!(v.slot_in_set(0), "the impostor's head nominates in-stream");
    // Slot 1: the member itself, byte-perfect and obfuscated, so the
    // head tier is the only tier with anything to say.
    v.on_data(1, "Zq8other", 20_000, 0, &member);
    assert!(
        v.slots[1].lock_ok().unmatchable.is_none(),
        "a head that named a descriptor another slot merely HOLDS has \
         not matched nothing"
    );
    assert!(
        finish_from(&v, 0, &uncovered).is_none(),
        "the impostor is denied at finish and its claim goes back"
    );
    let r = finish_from(&v, 1, &member)
        .expect("the member's descriptor is free again and its head names it");
    assert_eq!(r.par2_name.as_deref(), Some("member.vob"));
    assert!(r.all_ok(), "{r:?}");
    assert!(
        v.unclaimed_files().is_empty(),
        "a byte-perfect member on disk is not a missing file"
    );
}

/// The other half of M4-103's fix, and the one it must not have cost: a
/// TRUTHFULLY nominated member that is merely DAMAGED keeps its
/// descriptor.
///
/// Dropping this one would price a repairable file WHOLLY MISSING, which
/// needs many times the recovery blocks the damage does and turns a
/// repairable job unrepairable - `try_match_named`'s own note is about
/// exactly that cost at the name door. So the rule denies only on a
/// POSITIVE contradiction: blocks that were DELIVERED and did not match.
/// A member whose tail articles never arrived leaves those blocks
/// `Pending`, which is silence, and silence is never a denial.
///
/// Note what this fixture shares with the one above: the same member,
/// the same zero head, the same obfuscated name, the same tier, and the
/// same 16 blocks of zeros matching first. The ONLY difference is that
/// what follows the shared run here never arrived, where there it
/// arrived and disagreed.
#[test]
fn a_damaged_member_keeps_the_descriptor_its_head_nominated() {
    let mut member = vec![0u8; 20_000];
    member[16_384..].copy_from_slice(&data_of(3_616, 71));
    let (v, _set) = active_verifier(&[("member.vob", &member)], 1024);
    let landed = &member[..18_000];
    v.on_data(0, "Wp3jibber", 20_000, 0, landed);
    let r = finish_from(&v, 0, landed)
        .expect("a member short of its own declared size is damaged, not an impostor");
    assert_eq!(r.par2_name.as_deref(), Some("member.vob"));
    assert!(
        !r.bad_blocks.is_empty() && r.bad_blocks.len() < 20,
        "repairable damage, not a wholly-missing file: {r:?}"
    );
    assert!(v.unclaimed_files().is_empty(), "the member is claimed");
}

/// The escalation behind the block rule, and the row it exists for: a
/// nomination whose blocks ALL refuse is still held when the whole file
/// is the descriptor's (M4-69, M4-103).
///
/// M4-69's two e2e rows are a byte-exact download whose set carries
/// FORGED block checksums - honest CRC32 beside a forged MD5, or the
/// reverse - so every block arrives and every one fails. To the block
/// rule that is the prefix signature with an empty prefix, and denying
/// it would take a file the FileDesc MD5 proves intact out of its own
/// recovery set, which is the exact harm those rows were opened for.
/// So the strongest evidence a settled file admits gets the last word,
/// which is also what `finish_slot_from`'s own all-blocks-bad
/// escalation does one seam later.
///
/// The fixture models the forged IFSC by feeding bytes that FAIL the
/// blocks in-stream and settling against the file the descriptor really
/// describes: the end state is the one that matters here - every block
/// `Bad`, and a source whose whole-file MD5 is the descriptor's.
/// Building real forged IFSC entries is the e2e rows' job
/// (`e2e_norar::packettrust::forged_block_{crcs,md5s}_*`), and this is
/// the arm underneath them.
#[test]
fn a_nomination_every_block_refuses_is_held_by_the_whole_file_md5() {
    let mut member = vec![0u8; 20_000];
    member[16_384..].copy_from_slice(&data_of(3_616, 71));
    let (v, _set) = active_verifier(&[("member.vob", &member)], 1024);
    // Same head (so the tier nominates), everything after it wrong (so
    // every delivered block past the shared run is Bad).
    let mut wrong = vec![0u8; 20_000];
    wrong[16_384..].copy_from_slice(&data_of(3_616, 99));
    v.on_data(0, "Wp3jibber", 20_000, 0, &wrong);
    // Settled against the descriptor's real bytes: the blocks say no and
    // the file says yes, and the file wins.
    let r = finish_from(&v, 0, &member)
        .expect("a file the FileDesc MD5 proves intact keeps its descriptor");
    assert_eq!(r.par2_name.as_deref(), Some("member.vob"));
    assert!(v.unclaimed_files().is_empty(), "the member is claimed");
}

/// A descriptor of 16 KiB or less is FINALIZED by the head, not
/// nominated by it, and that is not a concession - it is the rule.
///
/// `md5_16k` of a short file is its whole-file MD5 (short files are not
/// zero-padded), and the candidate filter has already required the slot
/// to declare exactly that length, so the head IS the strongest evidence
/// the file admits. Pinned because the cheap way to write M4-103's fix
/// is to nominate unconditionally, which would put every small file
/// through a finish-time settle for a question its head already answered.
#[test]
fn a_head_that_covers_the_whole_descriptor_still_claims_in_stream() {
    let small = data_of(9_000, 17);
    let (v, _set) = active_verifier(&[("small.bin", &small)], 1024);
    v.on_data(0, "Kq7zzz", 9_000, 0, &small);
    assert!(
        v.unclaimed_files().is_empty(),
        "the head covers the whole file, so it claims outright"
    );
    let r = finish_from(&v, 0, &small).expect("claimed in stream");
    assert_eq!(r.par2_name.as_deref(), Some("small.bin"));
    assert!(r.all_ok(), "{r:?}");
}

/// W4-11's own argument with the OTHER operand moving (31 Aug 2026): a
/// slot latched `unmatchable` against the descriptors live at download
/// time must be re-offered the match when a SECOND recovery set is
/// adopted.
///
/// `capture_head` already clears the latch when the head GROWS, because
/// "this head, hashed whole, matched no descriptor" is a statement about
/// a digest that no longer exists. It is equally a statement about a
/// DESCRIPTOR POPULATION, and a post carrying more than one recovery set
/// grows that population after the download: the in-stream sniff elects
/// one bootstrap volume for the whole job and defers the rest, and
/// `get::settle` activates the deferred ones from the bytes on disk
/// BEFORE it settles any slot. So the descriptors are live in time and
/// the latch was the only thing refusing the match.
///
/// Measured before the fix on a two-set post whose arriving payload was
/// named only by the deferred set: `verified 0 file(s)`, the member
/// reported missing entirely, and a repair sent to rebuild a file
/// present and byte-exact in `out_dir`.
#[test]
fn a_second_set_reopens_a_slot_the_first_one_latched() {
    let one = data_of(3000, 41);
    let two = data_of(3000, 42);
    let v = LiveVerifier::new(2);
    // The bootstrap set names `one.bin` and nothing else.
    let boot = par2_meta([1u8; 16], 1024, &[("one.bin", &one)], true);
    v.activate(&[boot.as_slice()]).unwrap();
    v.on_data(0, "one.bin", 3000, 0, &one);
    assert!(v.slot_in_set(0), "the bootstrap set claims its own member");
    // `two.bin` arrives WHOLE and truthfully named while only that set
    // is live. Its name matches no descriptor and its complete head
    // matches none either, with neither tier declining on ambiguity -
    // which is the latch, and is correct about the population it was
    // reached against.
    v.on_data(1, "two.bin", 3000, 0, &two);
    assert!(!v.slot_in_set(1), "nothing live names this member yet");
    assert!(
        !v.slot_undecided(1),
        "the matcher reached a verdict here - this is a refusal, not silence"
    );
    // The deferred set comes up at settle. It names the arriving member
    // AND a member the live set names too, which is what
    // `get::settle::activate_deferred_sets`' overlap gate admits.
    let deferred = par2_meta(
        [2u8; 16],
        1024,
        &[("one.bin", &one), ("two.bin", &two)],
        true,
    );
    v.activate(&[deferred.as_slice()]).unwrap();
    let dir = std::env::temp_dir().join(format!("nzbkit-live-2set-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("two.bin");
    std::fs::write(&p, &two).unwrap();
    let r = v
        .finish_slot(1, Some(&p))
        .expect("the deferred set's descriptor must be reachable at finish");
    assert!(r.all_ok(), "the bytes are intact and byte-exact: {r:?}");
    assert!(
        !v.unclaimed_files().contains(&"two.bin".to_string()),
        "a claimed member must not still be charged missing: {:?}",
        v.unclaimed_files()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half, and the one that keeps the fix from costing anything
/// on an ordinary post: a re-activation that adopts NO new set id must
/// leave every latch exactly where it was.
///
/// `LiveVerifier::activate` discards an already-live set deliberately -
/// the bound slots' block vectors were sized from the live copy - so
/// there is nothing new to match against, and re-opening every latched
/// slot would buy a whole-file read per slot in `try_match_whole` at
/// settle for an answer that cannot have changed. Read through the
/// generation directly rather than through an outcome: a slot that
/// re-ran the tiers and found nothing looks identical from outside to
/// one that never re-ran them.
#[test]
fn re_activating_a_live_set_leaves_the_latch_alone() {
    let one = data_of(3000, 43);
    let two = data_of(3000, 44);
    let v = LiveVerifier::new(2);
    let boot = par2_meta([7u8; 16], 1024, &[("one.bin", &one)], true);
    v.activate(&[boot.as_slice()]).unwrap();
    v.on_data(1, "two.bin", 3000, 0, &two);
    assert_eq!(
        v.slots[1].lock_ok().unmatchable,
        Some(0),
        "latched against the only population there has been"
    );
    // The same set id again, from the same bytes: an ordinary second
    // sniffed volume of the set already live.
    v.activate(&[boot.as_slice()]).unwrap();
    match &*v.plan.read_ok() {
        Plan::Active(a) => assert_eq!(
            a.adopted_gen, 0,
            "adopting nothing new must not move the generation"
        ),
        _ => panic!("a set is live"),
    }
    assert_eq!(
        v.slots[1].lock_ok().unmatchable,
        Some(0),
        "the refusal is still about the population it was reached against"
    );
}

/// The same re-opening, at the IN-STREAM door rather than at finish.
///
/// `on_data` gates its match on the refusal too and carries the same
/// generation test, and it needs its own probe because the finish-time
/// pin above never drives another article - a guard no mutation can
/// kill is not a guard.
///
/// WHAT THIS ARM IS FOR, said plainly rather than dressed up as a live
/// path. Today's callers cannot reach it: the in-stream sniff activates
/// exactly once (its `outstanding` countdown fires on the last captured
/// volume), and the only activation after that is the deferred one at
/// settle, by which time no article will arrive. Articles DO flow after
/// that first activation - `unpack::instream::reconcile_deferred_payload`
/// un-defers a slot the newly-live FileDesc table shows to be payload
/// and re-queues its articles - but nothing can have latched against an
/// earlier population, because there was no earlier population.
///
/// So it is a forward guard on the TYPE's contract rather than a fix
/// for a live path, and it is carried for two reasons. `LiveVerifier`
/// is a library door: `activate` is `pub` and says nothing about being
/// called at most twice, so any caller that adopts a set and then feeds
/// a span gets the answer that ordering deserves. And the alternative -
/// this one site reading the raw latch while `finish_slot` reads
/// `refused` - is a split a later reader cannot reconstruct a reason
/// for, which is how the asymmetry gets copied rather than questioned.
#[test]
fn a_second_set_reopens_the_in_stream_matcher_too() {
    let one = data_of(3000, 45);
    let two = data_of(3000, 46);
    let v = LiveVerifier::new(2);
    let boot = par2_meta([3u8; 16], 1024, &[("one.bin", &one)], true);
    v.activate(&[boot.as_slice()]).unwrap();
    v.on_data(1, "two.bin", 3000, 0, &two);
    assert!(
        !v.slot_in_set(1),
        "latched against the bootstrap population"
    );
    let deferred = par2_meta(
        [4u8; 16],
        1024,
        &[("one.bin", &one), ("two.bin", &two)],
        true,
    );
    v.activate(&[deferred.as_slice()]).unwrap();
    // A re-queued article for the same slot, after the adoption.
    v.on_data(1, "two.bin", 3000, 0, &two);
    assert!(
        v.slot_in_set(1),
        "the in-stream matcher must re-judge a slot whose refusal a new set staled"
    );
}

/// `ever_activated` is the lock-free, MONOTONIC anchor the chase's
/// no-parity drop rests on (`Extractor::parity_ruled_out`), so both
/// halves of that description are pinned here.
///
/// It is a separate answer from [`LiveVerifier::sets`] only because the
/// caller may not touch the `plan` lock: it asks from under the
/// extractor's routing lock, and `finish_slot_from` holds `plan` for
/// read and then reads through that same routing lock. The two must
/// still agree, which is what the parity with `sets()` below checks.
#[test]
fn ever_activated_is_a_lock_free_monotonic_mirror_of_the_plan() {
    const BS: usize = 4096;
    let v = LiveVerifier::new(1);
    assert!(!v.ever_activated(), "a Waiting verifier has no set");
    assert!(v.sets().is_empty(), "and the two answers agree");

    let body = data_of(BS, 7);
    let meta = par2_meta_declared([4u8; 16], BS, "one.bin", BS as u64, 0, &body);
    v.activate(&[meta.as_slice()]).expect("fixture parses");
    assert!(v.ever_activated());
    assert_eq!(v.sets().len(), 1, "and the two answers still agree");

    // A SECOND activation merges rather than replacing, so the flag
    // cannot be knocked back down by one - which is what makes a true
    // answer safe to act on irreversibly.
    let second = par2_meta_declared([5u8; 16], BS, "two.bin", BS as u64, 0, &body);
    v.activate(&[second.as_slice()]).expect("fixture parses");
    assert!(v.ever_activated());
    assert_eq!(v.sets().len(), 2);
}
