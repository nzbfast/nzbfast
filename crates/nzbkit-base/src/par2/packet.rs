//! The PAR2 framing walk and the packet-body parsers.
//!
//! Split out of `par2.rs` on 31 Aug 2026 under the size gate (TODO 106),
//! which the parent had reached EXACTLY - 3,000 of 3,000 lines, so the
//! next lane to append one line to it would have reddened main for
//! whoever pushed next. The seam is the one par2.rs's own layout already
//! suggested: what a packet SAYS is here, what is concluded from a whole
//! set of them stays in the parent, and what is then done with the
//! conclusion is `par2/verify.rs`.
//!
//! Two layers, in wire order. [`scan_packets`] LOCATES packets in a
//! buffer and verifies each one's own MD5, tolerating garbage and
//! damage; the `parse_*` functions read one already-verified packet's
//! BODY into fields. Neither layer decides anything about a recovery set
//! - a contradiction between two valid packets is `Par2Set::parse`'s to
//! resolve, and keeping that judgement out of here is what makes the
//! halves separable at all.
//!
//! Nothing about the public surface moved: par2.rs re-exports every name
//! below, so `crate::par2::scan_packets` (par2repair's catalog, slice
//! census and collector), `crate::par2::parse_main` (preflight) and
//! `crate::par2::parse_filedesc` / `parse_unifilen` (`get::settle`, the
//! e2e name suites) all still resolve exactly as they did.

use super::{BlockCheck, Desc, HEADER_LEN, MAGIC};
use crate::md5fast::{Digest, Md5};

/// A raw packet located inside an input buffer.
pub(crate) struct RawPacket<'a> {
    pub(crate) md5: [u8; 16],
    pub(crate) set_id: [u8; 16],
    pub(crate) ptype: [u8; 16],
    pub(crate) body: &'a [u8],
    /// Byte offset of `body` within the scanned input - lets the repair
    /// path record where recovery-slice data lives in a file and pread
    /// just the slices it needs later.
    pub(crate) body_offset: usize,
}

/// Scan `input` for structurally valid packets. Tolerates leading/trailing
/// garbage and corrupt packets: any packet whose own MD5 doesn't verify is
/// skipped (the scan resumes just past its magic, so a corrupt length field
/// can't make us jump over later good packets).
///
/// Buffers past [`PAR_SCAN_MIN`] take the parallel path: the structural
/// walk is the same, but the per-packet MD5s - the entire cost of scanning
/// a recovery volume, and until now a serial pass over ~all of its bytes -
/// verify across threads first. Any MD5 failure abandons the optimistic
/// walk and re-runs the sequential scan (its +1 resume can surface packets
/// the length-hopping walk never visited), so damaged volumes keep the
/// exact historical behavior and clean ones - the overwhelming case - scan
/// at aggregate hash speed.
pub(crate) fn scan_packets<'a>(input: &'a [u8], f: impl FnMut(RawPacket<'a>)) {
    scan_packets_counted(input, f);
}

/// [`scan_packets`], returning the total bytes fed to MD5 across both paths.
/// That total - not elapsed time - is what the serial scan's hash budget
/// bounds, so it is what the hostile-input test asserts on: a deterministic
/// figure that does not move when the machine running the test is loaded.
pub(super) fn scan_packets_counted<'a>(input: &'a [u8], f: impl FnMut(RawPacket<'a>)) -> u64 {
    let mut hashed = 0u64;
    if input.len() >= PAR_SCAN_MIN {
        match scan_packets_parallel(input, f, &mut hashed) {
            Ok(()) => return hashed,
            // The optimistic walk hashed its spans before abandoning; those
            // bytes count toward the total just as the serial scan's do.
            Err(f) => return hashed.saturating_add(scan_packets_serial(input, f)),
        }
    }
    scan_packets_serial(input, f)
}

/// Below this the thread fan-out costs more than the hashing it spreads.
pub(super) const PAR_SCAN_MIN: usize = 4 << 20;

/// `(start, end)` of every STRUCTURALLY valid packet, hopping
/// packet-to-packet by declared length: magic, a header-inclusive length
/// that is a multiple of 4 and lands inside the buffer. Nothing here is
/// MD5-verified, so this walk is a framing pass and not a trust
/// decision - it costs one scan of the bytes and no hashing at all.
///
/// Two callers, for two different reasons. [`scan_packets_parallel`]
/// takes these spans and hashes them concurrently, so the framing is
/// exactly what it always was. [`super::Par2Set::set_id_of`] only CLASSIFIES a
/// physical file - which set it mostly belongs to - and its answer is a
/// grouping hint that `Par2Set::parse` then re-decides authoritatively
/// with every MD5 checked, so paying a full hash pass to produce the
/// hint was three passes over a `.par2` where one is enough (the
/// classification cost X5-14 asked to bound).
///
/// A span whose LENGTH does not check resyncs at `start + 1`, matching
/// both other walks; a span whose MD5 would not check cannot be seen
/// from here, which is the whole difference and why this is never the
/// last word on anything.
pub(super) fn packet_spans(input: &[u8]) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut off = 0usize;
    while off + (HEADER_LEN as usize) <= input.len() {
        let Some(rel) = find_magic(&input[off..]) else {
            break;
        };
        let start = off + rel;
        if start + HEADER_LEN as usize > input.len() {
            break;
        }
        let len = u64::from_le_bytes(input[start + 8..start + 16].try_into().unwrap());
        let valid_len = len >= HEADER_LEN
            && len % 4 == 0
            && (start as u64)
                .checked_add(len)
                .is_some_and(|end| end <= input.len() as u64);
        if !valid_len {
            off = start + 1;
            continue;
        }
        spans.push((start, start + len as usize));
        off = start + len as usize;
    }
    spans
}

/// The optimistic walk behind [`scan_packets`]: hop packet-to-packet by
/// declared length (identical traversal to the serial scan whenever every
/// MD5 verifies), verify all packet MD5s in parallel, then emit in order.
/// The first bad MD5 returns `Err(f)` - the caller falls back to the
/// serial scan, because the serial +1 resume can find overlapping packets
/// inside a corrupt packet's claimed extent that this walk hops over.
fn scan_packets_parallel<'a, F: FnMut(RawPacket<'a>)>(
    input: &'a [u8],
    mut f: F,
    hashed: &mut u64,
) -> Result<(), F> {
    let spans = packet_spans(input);
    if spans.is_empty() {
        return Ok(());
    }
    // The serial scan's hash budget exists to stop crafted overlapping-magic
    // quadratics; this walk hashes each span exactly once and never overlaps,
    // so total hashing is already bounded by the input length.
    let threads = crate::mem::cpu_workers().min(spans.len());
    let ok = std::sync::atomic::AtomicBool::new(true);
    let next = std::sync::atomic::AtomicUsize::new(0);
    // Bytes actually digested, for the caller's running total. Spans never
    // overlap, so this cannot exceed `input.len()`; one relaxed add per
    // packet is noise beside the MD5 it accompanies.
    let bytes = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= spans.len() || !ok.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    let (start, end) = spans[i];
                    let stored: [u8; 16] = input[start + 16..start + 32].try_into().unwrap();
                    bytes.fetch_add(end - (start + 32), std::sync::atomic::Ordering::Relaxed);
                    if Md5::digest(&input[start + 32..end]).as_slice() != stored {
                        ok.store(false, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                }
            });
        }
    });
    *hashed = hashed.saturating_add(bytes.into_inner() as u64);
    if !ok.into_inner() {
        return Err(f);
    }
    for &(start, end) in &spans {
        f(RawPacket {
            md5: input[start + 16..start + 32].try_into().unwrap(),
            set_id: input[start + 32..start + 48].try_into().unwrap(),
            ptype: input[start + 48..start + 64].try_into().unwrap(),
            body: &input[start + 64..end],
            body_offset: start + 64,
        });
    }
    Ok(())
}

/// Returns the total bytes fed to MD5, which is the quantity `budget` below
/// bounds; callers other than [`scan_packets_counted`] may ignore it.
pub(super) fn scan_packets_serial<'a>(input: &'a [u8], mut f: impl FnMut(RawPacket<'a>)) -> u64 {
    // Budget on total bytes MD5'd, because the bad-MD5 resume below is
    // `start + 1`: a packet with a structurally valid length but a wrong MD5
    // costs a hash over its whole declared length and then advances one byte,
    // so overlapping magics with large lengths make this quadratic. A crafted
    // 16-byte cell (magic + a length reaching to EOF, whose stored-MD5 field is
    // the next cell's bytes and so never matches) gives ~n/16 packets each
    // hashing ~n bytes: a 16 MiB `.par2` is ~9 TB of MD5, i.e. hours, and
    // `.par2` files are read whole with no size cap straight off the wire.
    // A legitimate set hashes each packet exactly once, so its total is one
    // pass over the input - 4x leaves ample headroom for duplicate copies,
    // which is what the +1 resume exists to find.
    let budget = (input.len() as u64).saturating_mul(4).max(16 * 1024 * 1024);
    let mut hashed: u64 = 0;
    let mut off = 0usize;
    while off + (HEADER_LEN as usize) <= input.len() {
        let Some(rel) = find_magic(&input[off..]) else {
            break;
        };
        let start = off + rel;
        if start + HEADER_LEN as usize > input.len() {
            break;
        }
        let len = u64::from_le_bytes(input[start + 8..start + 16].try_into().unwrap());
        // Sanity: header-inclusive length, multiple of 4, fits in the buffer.
        let valid_len = len >= HEADER_LEN
            && len % 4 == 0
            && (start as u64)
                .checked_add(len)
                .is_some_and(|end| end <= input.len() as u64);
        if !valid_len {
            off = start + 1;
            continue;
        }
        let end = start + len as usize;
        let stored_md5: [u8; 16] = input[start + 16..start + 32].try_into().unwrap();
        let charge = (end - (start + 32)) as u64;
        if hashed.saturating_add(charge) > budget {
            // Hostile framing, not a real (even badly damaged) set. Stop with
            // whatever verified so far; the caller then sees an incomplete set
            // and declines, rather than burning hours on hashes. Charge only
            // for what is actually digested, so the returned total is a true
            // count and not budget + one unhashed packet.
            return hashed;
        }
        hashed = hashed.saturating_add(charge);
        let computed = Md5::digest(&input[start + 32..end]);
        if computed.as_slice() != stored_md5 {
            // Corrupt packet: resume the search right after this magic so a
            // duplicated copy elsewhere can still be found.
            off = start + 1;
            continue;
        }
        f(RawPacket {
            md5: stored_md5,
            set_id: input[start + 32..start + 48].try_into().unwrap(),
            ptype: input[start + 48..start + 64].try_into().unwrap(),
            body: &input[start + 64..end],
            body_offset: start + 64,
        });
        off = end;
    }
    hashed
}

fn find_magic(hay: &[u8]) -> Option<usize> {
    hay.windows(MAGIC.len()).position(|w| w == MAGIC)
}

/// Largest PAR2 slice size either side of this engine will accept. A crafted
/// value like 2^62 sails past a `% 4` check and drives the daemon into an
/// out-of-memory kill (the zeroed alloc is lazy, but the fill/hash touches
/// every byte). Real PAR2 slices are KB to low-MB, so this caps far above any
/// genuine set; beyond it the packet is treated as malformed and verification
/// is skipped - the download still completes, PAR2 being repair-only. The
/// CREATOR reads the same constant, so it can never write a set its own
/// parser would refuse.
pub(crate) const MAX_BLOCK_SIZE: u64 = 256 << 20;

/// Main packet body: `slice_size u64 | file_count u32 | recovery ids |
/// non-recovery ids`. Returns the slice size, the recovery-set ids and
/// the non-recovery ids (M4-21) as two separate lists - see
/// [`super::Par2Set::nonrecovery`] for why they must never be one.
pub(crate) fn parse_main(body: &[u8]) -> Option<(u64, Vec<[u8; 16]>, Vec<[u8; 16]>)> {
    if body.len() < 12 {
        return None;
    }
    let block_size = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let nfiles = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    let ids_bytes = &body[12..];
    // `block_size` is attacker-controlled (it comes straight off the wire
    // in the Main packet) and is later allocated and zero-filled per file
    // during verification (`verify_file_blocks`, `live::check_block`). A
    // crafted value like 2^62 sails past the `% 4` check and drives the
    // daemon into an out-of-memory kill (the zeroed alloc is lazy, but the
    // fill/hash touches every byte). Real PAR2 slices are KB to low-MB, so
    // cap far above any genuine set; beyond it the packet is treated as
    // malformed and verification is skipped - the download still completes
    // (PAR2 is repair-only).
    // `nfiles` is wire bytes too, and the bound is division rather than
    // `ids_bytes.len() < nfiles * 16` because that multiply is a usize:
    // on a 32-bit target `nfiles = 0x1000_0000` wraps it to 0, so a tiny
    // crafted Main packet passed the length test (and under
    // overflow-checks - dev, test, fuzz - it panics instead). 64-bit
    // targets could never wrap it; the division is the same test on
    // every width (Codex sweep 24 Aug, F-02).
    if block_size == 0
        || block_size % 4 != 0
        || block_size > MAX_BLOCK_SIZE
        || nfiles > ids_bytes.len() / 16
    {
        return None;
    }
    let file_ids: Vec<[u8; 16]> = ids_bytes
        .as_chunks::<16>()
        .0
        .iter()
        .take(nfiles)
        .copied()
        .collect();
    // Everything past the declared count. Bounded by the packet body,
    // exactly as the recovery list above is: `nfiles` was already held to
    // `ids_bytes.len() / 16`, so the two lists together cannot exceed the
    // ids the packet actually carries.
    let nonrecovery_ids: Vec<[u8; 16]> = ids_bytes
        .as_chunks::<16>()
        .0
        .iter()
        .skip(nfiles)
        .copied()
        .collect();
    Some((block_size, file_ids, nonrecovery_ids))
}

/// Body of a Unicode Filename packet: `16 bytes file id` then the name in
/// UTF-16 (M4-22, 30 Aug 2026).
///
/// # Why we read it at all
///
/// A FileDesc's name field is bytes with no declared encoding. MultiPar
/// and QuickPar write a transliterated or code-page spelling there for
/// readers that only understand the required packets, and put the real
/// name in this optional one. We skipped it as an unknown type, so a set
/// whose producer did exactly what the spec asks landed its files under
/// the lossy spelling - `Bjork - Vesperti.mkv` for `Björk -
/// Vespertine.mkv`, measured on the 30 Aug 2026 baseline.
///
/// # What it is allowed to do
///
/// NOMINATE, and nothing more. It replaces the FileDesc's spelling of the
/// name and touches no other field - not the file id, which every reader
/// keys packets by and nobody recomputes, and not a checksum. So the
/// authority machinery downstream is unchanged: a name still only
/// nominates a descriptor and content still finalizes it
/// (`live::SlotState::try_match`).
///
/// # Nothing is guessed
///
/// The same discipline as `get::sfvname::read_sidecar`, and for the same
/// reason - a wrong name that LOOKS landed is the one outcome neither
/// answer may produce. The spec's field is bare UTF-16 and every producer
/// on record writes little-endian, so LE is the reading; a BOM is two
/// bytes of unambiguous evidence and is honoured (and stripped) where one
/// is present. Anything that is not a whole number of code units, does
/// not decode (an unpaired surrogate), is empty, or carries an interior
/// NUL is REFUSED outright and the FileDesc name stands - never
/// half-taken, never lossily decoded.
pub(crate) fn parse_unifilen(body: &[u8]) -> Option<([u8; 16], String)> {
    if body.len() < 18 {
        return None; // file id plus at least one code unit
    }
    let fid: [u8; 16] = body[0..16].try_into().unwrap();
    let raw = &body[16..];
    // An odd trailing byte is half a code unit. `chunks_exact` would drop
    // it in silence, which is the half-take this refuses to do.
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    let (bytes, le) = match raw.get(..2) {
        Some([0xFF, 0xFE]) => (&raw[2..], true),
        Some([0xFE, 0xFF]) => (&raw[2..], false),
        _ => (raw, true),
    };
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            if le {
                u16::from_le_bytes(*c)
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    let decoded = String::from_utf16(&units).ok()?;
    // The packet body is padded to a multiple of 4 bytes, so a name of an
    // odd number of code units carries one trailing NUL unit.
    let name = decoded.trim_end_matches('\0');
    if name.is_empty() || name.contains('\0') {
        return None;
    }
    Some((fid, name.to_string()))
}

/// Body of a File Description packet: file id, whole-file MD5, 16k MD5,
/// length, then the name, null-padded to a multiple of 4.
///
/// # It keeps an interior NUL, and `parse_unifilen` refuses one
///
/// The asymmetry is deliberate and it is not about NULs, it is about
/// what a refusal COSTS at each packet. Recorded 31 Aug 2026 after
/// three separate lanes read the pair and asked.
///
/// [`parse_unifilen`] can afford to refuse anything it does not
/// understand because it is an OPTIONAL packet that only ever
/// NOMINATES a spelling: refusing it leaves the FileDesc name standing
/// and the set is exactly as usable as if the packet had never been
/// written. Nothing is lost, so M4-22 takes the strictest reading
/// available.
///
/// This packet is REQUIRED and carries the set's only copy of three
/// other fields - the whole-file MD5, the 16k MD5 and the length -
/// which are what verify, repair and adoption match on. Returning
/// `None` here does not drop a NAME, it drops the FILE from the set:
/// nothing can then be verified, repaired or claimed for it. So the
/// strict side is the WRONG side here, and a byte in the name is never
/// grounds to discard a descriptor.
///
/// Nor is the name REWRITTEN here, and that is the same argument once
/// more: the decoded name is a comparison key (`par2repair::catalog`
/// keys `Crit::FileDesc` by it, and [`super::filedesc_id`] hashes exactly what
/// this keeps), so a parser that quietly mapped a
/// byte would compute a different key from the one on the wire. The
/// mapping belongs at the filesystem boundary and is already there:
/// `disk::sanitize_filename_for` maps every `char::is_control` to `_`
/// before a name reaches a directory entry, which is what stops a Unix
/// `create` truncating at the NUL. Pinned end-to-end by
/// `hostile_filedesc_name_forms_land_contained_and_sanitized` (M4-15)
/// and at the parser by `the_two_name_packets_answer_an_interior_nul_differently`.
///
/// Only the spec's own TRAILING padding is trimmed. A name ending in
/// any other control byte keeps it and is sanitized downstream, which
/// is what M4-60 measured and pinned.
pub(crate) fn parse_filedesc(body: &[u8]) -> Option<([u8; 16], Desc)> {
    if body.len() < 56 {
        return None;
    }
    let fid: [u8; 16] = body[0..16].try_into().unwrap();
    let md5: [u8; 16] = body[16..32].try_into().unwrap();
    let md5_16k: [u8; 16] = body[32..48].try_into().unwrap();
    let length = u64::from_le_bytes(body[48..56].try_into().unwrap());
    // Name is ASCII/UTF-8, null-padded to a multiple of 4.
    let raw_name = &body[56..];
    let trimmed = raw_name
        .iter()
        .rposition(|&b| b != 0)
        .map_or(&raw_name[..0], |i| &raw_name[..=i]);
    let name = String::from_utf8_lossy(trimmed).into_owned();
    Some((
        fid,
        Desc {
            name,
            length,
            md5,
            md5_16k,
        },
    ))
}

pub(crate) fn parse_ifsc(body: &[u8]) -> Option<([u8; 16], Vec<BlockCheck>)> {
    if body.len() < 16 || !(body.len() - 16).is_multiple_of(20) {
        return None;
    }
    let fid: [u8; 16] = body[0..16].try_into().unwrap();
    let blocks = body[16..]
        .as_chunks::<20>()
        .0
        .iter()
        .map(|c| BlockCheck {
            md5: c[0..16].try_into().unwrap(),
            crc32: u32::from_le_bytes(c[16..20].try_into().unwrap()),
        })
        .collect();
    Some((fid, blocks))
}
