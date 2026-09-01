//! X5-21: how many times, and over how many bytes, the finish-time
//! whole-file tiers make the MAPPED reader re-read one slot.
//!
//! A sibling file rather than a block in `live/tests.rs`, by the rule
//! that file's own header gives - one subject per file, and live.rs and
//! its test module both sit near the size gate. Reached by `#[path]`
//! from live.rs, so `use super::*` names the verifier's own module.
//!
//! THE SUBJECT IS A COST, NOT A VERDICT, which is what makes it a row
//! nothing else here can stand in for. Every other test in this family
//! asserts WHICH descriptor a slot claims; this one asserts what asking
//! that question COSTS, because the cost is invisible today - a slot
//! that reads its own bytes fifty times still returns the right answer,
//! still passes every neighbouring assertion, and shows up only as a
//! job that took an unexplained hour.

use super::*;
use md5::{Digest, Md5};

const TYPE_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";

/// What one `finish_slot_from` cost the source behind it.
///
/// A `ReadAt::Reader` is the arm the mapped and chased slots take
/// (`get/settle.rs`: `is_mapped(sidx) || is_chased(sidx)`), and it is
/// the arm with no `metadata()` to answer a length question cheaply -
/// so it is the arm where a wrong declared length is paid for in bytes.
#[derive(Default)]
struct Counter {
    /// Every `read_at` call the tier made, the one-byte past-the-end
    /// length probes included - those are the cheap ones, and telling
    /// them apart from a whole-file pass is the whole point.
    calls: std::sync::atomic::AtomicU64,
    /// Bytes the source was actually asked to serve, whether or not the
    /// range was in range. This is the number a big post multiplies.
    bytes: std::sync::atomic::AtomicU64,
    /// Calls that asked for exactly one byte - the length probe's
    /// signature. `whole_passes` is `calls - probes`.
    probes: std::sync::atomic::AtomicU64,
}

impl Counter {
    fn calls(&self) -> u64 {
        self.calls.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn bytes(&self) -> u64 {
        self.bytes.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn probes(&self) -> u64 {
        self.probes.load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Reads that were not a one-byte length probe: the chunked passes
    /// of a whole-file or head hash.
    fn hash_reads(&self) -> u64 {
        self.calls() - self.probes()
    }
}

/// A counting `ReadAt::Reader` over `src`, ON THE CONTRACT `ReadAt`
/// documents: a range the source cannot FULLY serve is an `Err`, never
/// a short read, zero padding or a panic. That contract is why the
/// counter is honest about a refused range - the call happened and the
/// bytes were asked for, so both are counted before the range is
/// judged, which is what a real `Extractor::read_at` charges too.
fn counting<'a>(
    src: &'a [u8],
    c: &'a Counter,
) -> impl Fn(u64, &mut [u8]) -> std::io::Result<()> + Sync + 'a {
    use std::sync::atomic::Ordering::Relaxed;
    move |off, buf| {
        c.calls.fetch_add(1, Relaxed);
        c.bytes.fetch_add(buf.len() as u64, Relaxed);
        if buf.len() == 1 {
            c.probes.fetch_add(1, Relaxed);
        }
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
}

fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(crate::par2::MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

fn fid(i: usize) -> [u8; 16] {
    let mut f = [0u8; 16];
    f[0] = i as u8;
    f[1] = 0xA5;
    f
}

/// One descriptor: a name, the bytes it DECLARES, and nothing else. No
/// IFSC, deliberately - this row is about the whole-file tier's reads,
/// and a block grid would add the probe reads of a different tier to
/// every count.
struct Desc {
    name: String,
    data: Vec<u8>,
}

/// A recovery set of `descs`, IFSC-less. The descriptors are what a
/// PRODUCER declared; the source handed to `finish_slot_from` is what
/// actually landed, and the two are deliberately allowed to disagree -
/// that disagreement is the row.
fn meta(descs: &[Desc], block_size: usize) -> Vec<u8> {
    let set_id = [9u8; 16];
    let mut main = Vec::new();
    main.extend_from_slice(&(block_size as u64).to_le_bytes());
    main.extend_from_slice(&(descs.len() as u32).to_le_bytes());
    for i in 0..descs.len() {
        main.extend_from_slice(&fid(i));
    }
    let mut out = pkt(set_id, TYPE_MAIN, &main);
    for (i, d) in descs.iter().enumerate() {
        let mut desc = Vec::new();
        desc.extend_from_slice(&fid(i));
        desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&d.data)));
        let head = &d.data[..d.data.len().min(HEAD_LEN)];
        desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(head)));
        desc.extend_from_slice(&(d.data.len() as u64).to_le_bytes());
        let mut nb = d.name.as_bytes().to_vec();
        while nb.len() % 4 != 0 {
            nb.push(0);
        }
        desc.extend_from_slice(&nb);
        out.extend(pkt(set_id, TYPE_FILEDESC, &desc));
    }
    out
}

fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// `n` descriptors sharing a byte-identical 16 KiB head, each declaring
/// `tail(k)` bytes after it. An identical head is what puts them all in
/// one candidate group; what they declare after it is what the tier
/// then has to read to tell them apart.
fn head_twins(n: usize, tail: impl Fn(usize) -> usize) -> Vec<Desc> {
    let head = filler(HEAD_LEN, 3);
    (0..n)
        .map(|k| {
            let mut data = head.clone();
            data.extend(filler(tail(k), 100u8.wrapping_add(k as u8)));
            Desc {
                name: format!("twin{k:03}.vob"),
                data,
            }
        })
        .collect()
}

/// Settle slot 0 from `bytes` through a counting reader, and report
/// what the read cost.
fn finish_counted(v: &LiveVerifier, bytes: &[u8]) -> (Option<SlotReport>, Counter) {
    let c = Counter::default();
    let r = {
        let f = counting(bytes, &c);
        v.finish_slot_from(0, ReadAt::Reader(&f))
    };
    (r, c)
}

/// THE CONTROL, and it has to come first: the ordinary identical-head
/// twin pair the whole-file tier exists for reads the slot's bytes a
/// FIXED number of times, not once per candidate. Two descriptors, one
/// declared length, so the tier's length cache serves the second
/// candidate from the first candidate's hash.
///
/// TWO whole-file passes is the floor for an IFSC-less set and both are
/// named here so a later count can be read against them: one in
/// [`SlotState::try_match_whole`], which is the tier telling the twins
/// apart, and one in `finish_slot_from` itself, where a set with no
/// block grid has the whole-file MD5 as its only settle check. An IFSC
/// set pays the second in block reads instead; this row keeps the set
/// IFSC-less so every read it counts is a whole-file pass and the
/// arithmetic below is legible.
///
/// Without this row a count assertion elsewhere could be met by a tier
/// that had stopped reading at all, which is the failure mode a bare
/// "the number is small" test cannot tell from a fix.
#[test]
fn one_whole_file_read_serves_every_twin_of_one_declared_length() {
    let descs = head_twins(2, |_| 4_096);
    let len = descs[0].data.len();
    let bytes = descs[1].data.clone(); // slot 0 really holds twin001
    let v = LiveVerifier::new(1);
    v.activate(&[meta(&descs, 1024).as_slice()]).unwrap();
    v.on_data(0, "Xk1jibber", len as u64, 0, &bytes);
    assert!(
        !v.slot_in_set(0),
        "an identical head must decline in stream"
    );

    let (r, c) = finish_counted(&v, &bytes);
    assert_eq!(
        r.as_ref().and_then(|r| r.par2_name.as_deref()),
        Some("twin001.vob"),
        "the whole-file tier names the twin the bytes really are"
    );
    // The source is read in 1 MiB chunks and `len` is well under one,
    // so a whole-file pass is a single chunked read plus the one-byte
    // past-the-end length probe.
    assert_eq!(
        c.hash_reads(),
        2,
        "two twins of ONE declared length cost the tier one whole-file \
         read, plus the IFSC-less settle check - never one per candidate \
         (calls {}, probes {}, bytes {})",
        c.calls(),
        c.probes(),
        c.bytes()
    );
    assert!(
        c.bytes() < 3 * len as u64,
        "two whole-file reads is two files' worth of bytes, got {} over a \
         {len}-byte file",
        c.bytes()
    );
}

/// X5-21's own shape: an identical-head group whose members each
/// declare a DIFFERENT length. The tier has to tell them apart, and
/// before 31 Aug 2026 it did it by hashing the slot once per candidate
/// - the reads grew with the size of the group, and nothing anywhere
/// reported it.
///
/// The assertion that matters is not the constant, it is that the
/// constant does not MOVE with the group: 24 candidates cost what 4
/// cost. A count that tracked the group is the defect, whatever its
/// coefficient.
#[test]
fn distinct_declared_lengths_do_not_multiply_the_slots_whole_file_reads() {
    fn run(n: usize) -> (Option<String>, Counter, usize) {
        let descs = head_twins(n, |k| 4_096 + k * 512);
        let bytes = descs[n - 1].data.clone(); // the LAST candidate is the truth
        let len = bytes.len();
        let v = LiveVerifier::new(1);
        v.activate(&[meta(&descs, 1024).as_slice()]).unwrap();
        v.on_data(0, "Xk1jibber", len as u64, 0, &bytes);
        let (r, c) = finish_counted(&v, &bytes);
        (r.and_then(|r| r.par2_name), c, len)
    }
    let (small_name, small, _) = run(4);
    let (name, c, len) = run(24);
    assert_eq!(
        name.as_deref(),
        Some("twin023.vob"),
        "the tier must still name the twin the bytes really are"
    );
    assert_eq!(small_name.as_deref(), Some("twin003.vob"));
    assert_eq!(
        c.hash_reads(),
        small.hash_reads(),
        "24 candidates must cost what 4 cost - a whole-file read per \
         candidate is the amplification this row exists for \
         (24: calls {} bytes {}; 4: calls {} bytes {})",
        c.calls(),
        c.bytes(),
        small.calls(),
        small.bytes()
    );
    assert_eq!(
        c.hash_reads(),
        2,
        "the control's floor and no more: the tier's one whole-file read \
         plus the IFSC-less settle check (calls {}, probes {}, bytes {})",
        c.calls(),
        c.probes(),
        c.bytes()
    );
    assert!(
        c.bytes() < 3 * len as u64,
        "23 wrong-length candidates must cost one byte each, not a hash \
         each: {} bytes over a {len}-byte file",
        c.bytes()
    );
}

/// The shape that defeated the tier's length cache OUTRIGHT, and the
/// reason that cache now remembers a failure as well as a success: one
/// declared length, shared by every candidate exactly as an ordinary
/// twin post shares it, that is NOT the length of the bytes which
/// landed. Every candidate's read failed, nothing was cached, and the
/// next candidate re-read the same doomed length.
///
/// Nothing is hashed at all now - the length is settled by the two
/// one-byte probes in [`src_md5`] before a hash begins, and the memo
/// means it is settled ONCE. The slot still declines, which is the
/// answer: no descriptor here describes these bytes.
#[test]
fn one_wrong_declared_length_is_probed_once_not_once_per_candidate() {
    const N: usize = 24;
    let descs = head_twins(N, |_| 4_096);
    let declared = descs[0].data.len();
    let mut bytes = descs[0].data.clone();
    bytes.truncate(declared - 7); // shorter than every descriptor says
    let v = LiveVerifier::new(1);
    v.activate(&[meta(&descs, 1024).as_slice()]).unwrap();
    v.on_data(0, "Xk1jibber", declared as u64, 0, &bytes);
    let (r, c) = finish_counted(&v, &bytes);
    assert!(
        r.is_none(),
        "no descriptor describes these bytes, so the slot declines"
    );
    assert_eq!(
        c.hash_reads(),
        0,
        "a length the source cannot have is settled by probes, never by \
         hashing (calls {}, probes {}, bytes {})",
        c.calls(),
        c.probes(),
        c.bytes()
    );
    assert_eq!(
        c.calls(),
        2,
        "and it is settled ONCE for the whole group of {N}, not once per \
         candidate - the memo remembers the failure (bytes {})",
        c.bytes()
    );
}

/// The mirror of the distinct-lengths row, and the one the past-the-end
/// probe cannot answer on its own: candidates that over-declare. A
/// source SHORTER than the descriptor serves the probe's refusal at
/// `expect_len` exactly as a correct one does, so the read used to run,
/// hash the whole covered prefix, and fail only at the chunk that
/// crossed the end - the cost being the SOURCE's length, per candidate.
///
/// Sized past the 1 MiB read chunk on purpose: below it the first read
/// covers the whole declared span and is refused outright, which hides
/// the defect this row is about.
#[test]
fn over_declared_candidates_cost_one_byte_each_not_a_covered_prefix() {
    const N: usize = 12;
    // Descending, so the bytes that landed are the LAST candidate and
    // every one tried before it over-declares. Ordered the other way the
    // first candidate matches and nothing after it is ever read.
    let descs = head_twins(N, |k| (1 << 21) + (N - 1 - k) * (1 << 20));
    let bytes = descs[N - 1].data.clone();
    let len = bytes.len();
    let v = LiveVerifier::new(1);
    v.activate(&[meta(&descs, 1 << 16).as_slice()]).unwrap();
    v.on_data(0, "Xk1jibber", len as u64, 0, &bytes);
    let (r, c) = finish_counted(&v, &bytes);
    assert_eq!(
        r.as_ref().and_then(|r| r.par2_name.as_deref()),
        Some("twin011.vob"),
        "the tier must still name the twin the bytes really are"
    );
    assert!(
        c.bytes() < 3 * len as u64,
        "{N} over-declaring candidates must cost one byte each, not a \
         covered prefix each: {} bytes over a {len}-byte file (calls {}, \
         probes {})",
        c.bytes(),
        c.calls(),
        c.probes()
    );
    assert!(
        c.probes() as usize >= N,
        "every candidate's length must be settled by probe - {} probes \
         for {N} candidates reads as a scanner that stopped probing",
        c.probes()
    );
    // FLOORED, because every ceiling above it is met by a counter that
    // has stopped counting: the ONE candidate that matches still has to
    // have its whole file read, so a byte total under the file's own
    // length is an inert counter and not a fast tier.
    assert!(
        c.bytes() >= len as u64,
        "the matching candidate's whole file must still be read: {} bytes \
         over a {len}-byte file reads as a counter that stopped counting",
        c.bytes()
    );
}
