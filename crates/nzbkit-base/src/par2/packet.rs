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
    let ok = verify_spans_parallel(input, &spans, hashed);
    if !ok {
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

/// Every span's own MD5 checked across threads; `false` at the first
/// that does not verify. The hashing half of [`scan_packets_parallel`],
/// shared with [`scan_file_windowed`] so the two cannot drift.
fn verify_spans_parallel(input: &[u8], spans: &[(usize, usize)], hashed: &mut u64) -> bool {
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
    ok.into_inner()
}

/// [`scan_packets`] over a FILE, read through ONE WINDOW reused from its
/// first byte to its last, so no allocation the size of the file is ever
/// made. Emits exactly the packets `scan_packets` emits over the whole
/// file's bytes, in the same order, with `body_offset` a FILE offset.
///
/// **Why it exists.** The PAR2 catalog read every volume under 1 GiB
/// whole, scanned it and freed it, and macOS libmalloc keeps a freed
/// large region dirty in the process footprint: a repair that had
/// finished its scan still carried 335 MB of `Malloc Large (empty)` on a
/// 1 GiB / 64 KiB set and ~590 MB at 1 MiB blocks, which was the whole of
/// the 512 MB-class memory floor
/// (research/PARFAST-REPAIR-RSS-FLOOR-2026-09-14.md). A window of fixed
/// size lands in the same allocation for every read of a file.
///
/// **The I/O is the whole-read's I/O**: large sequential reads, one copy
/// out of the page cache, no per-packet seek (a seek per packet is
/// thousands of round trips on a network volume). The MD5s inside each
/// window verify across threads exactly as [`scan_packets_parallel`] does
/// once a window holds [`PAR_SCAN_MIN`] of packets.
///
/// **It only ever says yes to the case the parallel walk would have
/// accepted unchanged**: the file a contiguous run of packets from byte
/// 0, every declared length fitting the file, every MD5 verifying. Then
/// its spans are exactly [`packet_spans`]'s and its output exactly the
/// optimistic walk's. Anything else - a byte out of place, a length that
/// does not fit, a bad MD5, a read that comes back short because the file
/// shrank - returns `None`, and the caller reads the file whole and takes
/// the resyncing walks, so a damaged or odd volume keeps the historical
/// behaviour byte for byte. Trailing bytes too short to hold a header are
/// ignored, as both in-memory walks ignore them. `emit` may by then have
/// seen a PREFIX of the file's packets, which the caller must discard.
///
/// A packet larger than `window` grows the window to hold it - bounded
/// by the file length, which every declared length was checked against.
///
/// Test-only since 15 Sep 2026: the catalog reads through
/// [`scan_file_windowed_in`] with a pooled buffer, and this is the
/// one-shot face the equivalence tests pin.
#[cfg(test)]
pub(crate) fn scan_file_windowed(
    f: &std::fs::File,
    file_len: u64,
    window: usize,
    emit: impl FnMut(RawPacket<'_>),
) -> Option<()> {
    scan_file_windowed_in(f, file_len, window, &mut Vec::new(), emit)
}

/// [`scan_file_windowed`] reading through a buffer the CALLER owns, so a
/// scan of many files can land every file's reads in allocations that
/// already exist. What `buf` held before is never read: the window is
/// `buf[..filled]` and every byte of that came from the file in this call.
/// On return `buf` may have GROWN past `window` (a packet that did not fit
/// grows it), and a caller keeping it for later files should cap it.
pub(crate) fn scan_file_windowed_in(
    f: &std::fs::File,
    file_len: u64,
    window: usize,
    buf: &mut Vec<u8>,
    mut emit: impl FnMut(RawPacket<'_>),
) -> Option<()> {
    let hdr = HEADER_LEN as usize;
    let total = usize::try_from(file_len).ok()?;
    // Sized without zeroing what a previous file already touched: the
    // stale bytes sit past `filled` and are overwritten before use.
    let width = window.max(hdr).min(total);
    if buf.len() >= width {
        buf.truncate(width);
    } else {
        buf.resize(width, 0);
    }
    // `buf[..filled]` holds the file's bytes from offset `base`.
    let (mut base, mut filled) = (0usize, 0usize);
    let mut spans: Vec<(usize, usize)> = Vec::new();
    loop {
        let want = (buf.len() - filled).min(total - base - filled);
        crate::disk::read_exact_at(f, &mut buf[filled..filled + want], (base + filled) as u64)
            .ok()?;
        filled += want;
        let at_eof = base + filled == total;
        // Frame STRICTLY: a header exactly where the last packet ended.
        // The in-memory walks resync by searching for the magic, which a
        // window cannot do across its edge - so it declines instead.
        spans.clear();
        let mut off = 0usize;
        let mut short_by = None;
        while off + hdr <= filled {
            if buf[off..off + 8] != *MAGIC {
                return None;
            }
            let len = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap());
            let fits = ((base + off) as u64)
                .checked_add(len)
                .is_some_and(|end| end <= file_len);
            if len < HEADER_LEN || len % 4 != 0 || !fits {
                return None;
            }
            let end = off + len as usize;
            if end > filled {
                short_by = Some(len as usize);
                break;
            }
            spans.push((off, end));
            off = end;
        }
        if !spans.is_empty() {
            let mut hashed = 0u64;
            let checked = &buf[..off];
            let ok = if checked.len() >= PAR_SCAN_MIN {
                verify_spans_parallel(checked, &spans, &mut hashed)
            } else {
                spans.iter().all(|&(s, e)| {
                    Md5::digest(&checked[s + 32..e]).as_slice() == &checked[s + 16..s + 32]
                })
            };
            if !ok {
                return None;
            }
            for &(s, e) in &spans {
                emit(RawPacket {
                    md5: buf[s + 16..s + 32].try_into().unwrap(),
                    set_id: buf[s + 32..s + 48].try_into().unwrap(),
                    ptype: buf[s + 48..s + 64].try_into().unwrap(),
                    body: &buf[s + 64..e],
                    body_offset: base + s + 64,
                });
            }
        }
        // Every declared length was held to the file, so at EOF nothing
        // can be short: what is left is under a header and is ignored.
        if at_eof {
            return Some(());
        }
        // Slide the unfinished tail to the front and read on. A packet
        // that did not fit even from the front grows the window.
        buf.copy_within(off..filled, 0);
        base += off;
        filled -= off;
        if let Some(len) = short_by.filter(|&len| len > buf.len()) {
            buf.resize(len, 0);
        }
    }
}

/// [`scan_packets`] with the recovery packets DEFERRED: every packet
/// whose header names `PAR 2.0\0RecvSlic` is framed and handed to
/// `defer` as its `(start, end)` span WITHOUT its MD5 being computed;
/// every other packet is hashed and verified exactly as `scan_packets`
/// does, and reaches `f` in file order. The caller owes the deferred
/// spans a later [`verify_span`] before it trusts anything about them
/// beyond their existence - which is why this walk exists: `parfast`'s
/// verify has to read a set's volumes to learn the set, but for a
/// clean set it never needs to know whether the recovery data in them
/// is sound, and hashing it was ~10-15% of a clean verify's wall (M3
/// Ultra, 10 GiB / 1 GiB of parity, 6 Sep 2026).
///
/// The type is read off the UNVERIFIED header. A corrupt packet whose
/// bytes happen to say RecvSlic is deferred and fails its later
/// verification; a corrupt packet that says anything else fails its
/// MD5 here, exactly as before. Neither ends anywhere it could not have
/// ended under the hashing walk. Any bad MD5 among the hashed packets
/// falls back to the serial scan over the WHOLE input, hashing every
/// packet and deferring nothing (the +1 resume inside a corrupt extent
/// is the serial scan's, and it must see every byte).
pub(crate) fn scan_packets_deferring<'a>(
    input: &'a [u8],
    mut f: impl FnMut(RawPacket<'a>),
    mut defer: impl FnMut(usize, usize),
) {
    let spans = packet_spans(input);
    if spans.is_empty() {
        return;
    }
    let hashed: Vec<(usize, usize)> = spans
        .iter()
        .copied()
        .filter(|&(start, _)| &input[start + 48..start + 64] != super::TYPE_RECVSLIC)
        .collect();
    let ok = std::sync::atomic::AtomicBool::new(true);
    if !hashed.is_empty() {
        let threads = crate::mem::cpu_workers().min(hashed.len());
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if i >= hashed.len() || !ok.load(std::sync::atomic::Ordering::Relaxed) {
                            return;
                        }
                        let (start, end) = hashed[i];
                        let stored: [u8; 16] = input[start + 16..start + 32].try_into().unwrap();
                        if Md5::digest(&input[start + 32..end]).as_slice() != stored {
                            ok.store(false, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                    }
                });
            }
        });
    }
    if !ok.into_inner() {
        scan_packets_serial(input, f);
        return;
    }
    for &(start, end) in &spans {
        if &input[start + 48..start + 64] == super::TYPE_RECVSLIC {
            defer(start, end);
        } else {
            f(RawPacket {
                md5: input[start + 16..start + 32].try_into().unwrap(),
                set_id: input[start + 32..start + 48].try_into().unwrap(),
                ptype: input[start + 48..start + 64].try_into().unwrap(),
                body: &input[start + 64..end],
                body_offset: start + 64,
            });
        }
    }
}

/// A file framed by SEEKING rather than read whole: each packet's
/// 64-byte header is read at its offset, a recovery packet's span is
/// recorded (with its 4-byte exponent, one more small read) and its
/// payload skipped, and every other packet is read whole into `bytes`
/// - a valid packet stream of the file's critical packets, for
/// [`super::Par2Set::parse`]. On a set whose members prove clean the
/// recovery payloads, the bulk of every volume, are never read at all
/// (i5-10600KF, a clean 10 GiB set with 1 GiB of parity: the index
/// alone verifies in 1.61-1.67 s against 2.08-2.14 with the volumes
/// read and hashed, 6 Sep 2026).
///
/// `None` on any structural anomaly - a header not at the expected
/// offset, a length that does not fit - because the in-memory walks
/// resync by scanning for the magic byte by byte and this walk cannot;
/// the caller then reads the file whole and takes that path. Nothing
/// here is MD5-verified: the critical packets are verified by the
/// parse that follows, the recovery packets by `verify_span` over a
/// later read, the same two gates the whole-read path applies.
pub struct SparseFrame {
    /// Every non-recovery packet, whole, in file order.
    pub bytes: Vec<u8>,
    /// Every recovery packet's place and unverified header claims.
    pub recovery: Vec<SparseRecovery>,
}

/// One recovery packet a [`sparse_frame`] walk skipped.
pub struct SparseRecovery {
    /// Byte offset of the packet's 64-byte header in the file.
    pub offset: u64,
    /// Total packet length in bytes from the header, including that
    /// 64-byte header. Already checked to be a multiple of 4 and to fit
    /// inside the file, so `offset + len` is in range.
    pub len: u64,
    /// The packet's own MD5 field, as claimed by the header and NOT yet
    /// checked - the payload was skipped rather than read, so nothing
    /// has hashed it. `verify_span` over a later read is the gate.
    pub md5: [u8; 16],
    /// The Recovery Set ID claimed by the header, unverified for the
    /// same reason.
    pub set_id: [u8; 16],
    /// The recovery packet's exponent, the first 4 bytes of the body,
    /// which is what says which parity slice this is. `None` when the
    /// packet is too short to carry one or the extra read failed.
    pub exponent: Option<u32>,
}

/// Frame a PAR2 file by seeking: build a [`SparseFrame`] holding every
/// critical packet whole and only the place and header claims of each
/// recovery packet, without reading a byte of parity payload.
///
/// `file_len` must be the file's real length; it bounds every offset
/// the walk accepts. Returns `None` on any structural anomaly, which is
/// the caller's signal to fall back to reading the file whole - see the
/// type's own note on why this walk cannot resync.
pub fn sparse_frame(f: &std::fs::File, file_len: u64) -> Option<SparseFrame> {
    let mut bytes = Vec::new();
    let mut recovery = Vec::new();
    let mut off = 0u64;
    let mut hdr = [0u8; 64];
    while off + HEADER_LEN <= file_len {
        crate::disk::read_exact_at(f, &mut hdr, off).ok()?;
        if hdr[..8] != *MAGIC {
            return None;
        }
        let len = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        if len < HEADER_LEN || len % 4 != 0 || off.checked_add(len)? > file_len {
            return None;
        }
        if hdr[48..64] == *super::TYPE_RECVSLIC {
            let exponent = (len >= HEADER_LEN + 4)
                .then(|| {
                    let mut e = [0u8; 4];
                    crate::disk::read_exact_at(f, &mut e, off + HEADER_LEN)
                        .ok()
                        .map(|()| u32::from_le_bytes(e))
                })
                .flatten();
            recovery.push(SparseRecovery {
                offset: off,
                len,
                md5: hdr[16..32].try_into().unwrap(),
                set_id: hdr[32..48].try_into().unwrap(),
                exponent,
            });
        } else {
            let start = bytes.len();
            bytes.resize(start + usize::try_from(len).ok()?, 0);
            crate::disk::read_exact_at(f, &mut bytes[start..], off).ok()?;
        }
        off += len;
    }
    Some(SparseFrame { bytes, recovery })
}

/// A deferred span's MD5, checked: `Some(packet)` when the bytes
/// verify, `None` when they do not (or the span no longer fits the
/// input, which is what a file that changed underneath looks like).
pub(crate) fn verify_span(input: &[u8], start: usize, end: usize) -> Option<RawPacket<'_>> {
    if start + (HEADER_LEN as usize) > end || end > input.len() {
        return None;
    }
    let stored: [u8; 16] = input[start + 16..start + 32].try_into().unwrap();
    if Md5::digest(&input[start + 32..end]).as_slice() != stored {
        return None;
    }
    Some(RawPacket {
        md5: stored,
        set_id: input[start + 32..start + 48].try_into().unwrap(),
        ptype: input[start + 48..start + 64].try_into().unwrap(),
        body: &input[start + 64..end],
        body_offset: start + 64,
    })
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
    // every width (review sweep 24 Aug, F-02).
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
    // An odd trailing byte is half a code unit, and a BOM is two bytes of
    // unambiguous evidence: both are `decode_utf16_field`'s, which is the
    // one spelling of this decode the two optional UTF-16 packets share.
    // It refuses the odd byte rather than dropping it in silence, which
    // is the half-take this has always refused to do.
    let decoded = decode_utf16_field(&body[16..])?;
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

/// Body of an ASCII Text ("comment") packet: the comment text, padded
/// with NULs to a multiple of four. Optional, and carried by MultiPar,
/// QuickPar and MacPAR rather than by par2cmdline, which emits and
/// reads none.
///
/// # It accepts UTF-8, not only ASCII
///
/// The spec names the packet ASCII and every byte a conforming producer
/// writes is, so ASCII is what [`super::super::par2gen`] writes into one.
/// Reading is the looser half on purpose: a producer that put UTF-8 in
/// here has said something true about the set that the strict reading
/// would throw away, and there is no second field it could corrupt -
/// a comment nominates nothing and keys nothing. Bytes that are not
/// valid UTF-8 are refused rather than lossily mapped, under
/// [`parse_unifilen`]'s rule: this packet is OPTIONAL, so refusing it
/// leaves the set exactly as usable as if it had never been written,
/// and that is what buys the strict side.
pub(crate) fn parse_comm_ascii(body: &[u8]) -> Option<String> {
    clean_comment(std::str::from_utf8(body).ok()?)
}

/// Body of a Unicode Text ("comment") packet: 16 bytes that are the MD5
/// of the analogous ASCII packet's body where one exists and zeros
/// where it does not, then the comment as UTF-16.
///
/// The MD5 field is READ PAST and never checked. It is a cross-reference
/// between two optional packets, and the only thing a mismatch could
/// tell a reader is that a producer wrote two different comments - which
/// is what the `Claim` over both packet types already answers, in a way
/// that does not depend on which of them the walk reached first
/// (W4-10). Checking it here would make the ASCII packet's survival a
/// precondition for the Unicode one's, which is a worse answer for a
/// volume that carries only one of the pair.
pub(crate) fn parse_comm_uni(body: &[u8]) -> Option<String> {
    if body.len() < 18 {
        return None; // the MD5 field plus at least one code unit
    }
    clean_comment(&decode_utf16_field(&body[16..])?)
}

/// The one acceptance rule both comment packets answer to, so a set
/// carrying the pair cannot have one of them accepted and the other
/// refused over a byte they share.
///
/// Trailing NULs are the spec's own padding to a multiple of four and
/// are trimmed. What is left must be non-empty and must carry no
/// control character other than the three that make a comment a
/// comment - newline, carriage return and tab.
///
/// # Why a control byte is refused rather than stripped
///
/// A comment is written to a terminal by `parfast` and to a label by the
/// desktop app, and an ESC there is an escape sequence that rewrites
/// what the reader sees - the one thing in a PAR2 set that an attacker
/// can choose freely and that lands in front of a human unaltered. A
/// filename cannot take this answer, because the decoded name is a
/// comparison key and dropping a descriptor drops a FILE from the set
/// ([`parse_filedesc`]'s own note). A comment keys nothing and holds
/// nothing else, so the refusal costs exactly the comment - and
/// [`super::super::par2gen`] refuses to WRITE one of these, so the two
/// halves are the same rule and a set this engine created always reads
/// back.
///
/// `char::is_control` covers C0, DEL and C1, so the ESC forms and the
/// eight-bit CSI are all refused. WHAT IT DOES NOT COVER, stated so the
/// next reader does not have to re-derive it: the bidirectional
/// overrides (U+202E and friends), which can make displayed text read
/// in the wrong order but cannot rewrite a screen or move a cursor.
/// That is a rendering question for whatever draws the comment, and
/// widening this rule to answer it would refuse legitimate right-to-left
/// comments outright - which is the lossy half of exactly the trade this
/// function otherwise takes the strict side of.
fn clean_comment(text: &str) -> Option<String> {
    let text = text.trim_end_matches('\0');
    if text.is_empty()
        || text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    Some(text.to_string())
}

/// UTF-16 text with an optional BOM, as both optional packets that carry
/// a name or a comment spell it. `None` for a length that is not a whole
/// number of code units or a sequence that does not decode - never a
/// lossy mapping and never a half-take.
fn decode_utf16_field(raw: &[u8]) -> Option<String> {
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
    String::from_utf16(&units).ok()
}
