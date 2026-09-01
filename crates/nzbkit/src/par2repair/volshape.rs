//! The SHAPE test that stands between an eight-byte nomination and a
//! delete (wave-4 row M4-53, 30 Aug 2026).
//!
//! Its own file, and the reason is the size gate: par2repair.rs sits
//! against its ceiling, so a hundred lines of new prose and framing
//! walk cannot live there. Reachable through `super::*` like every
//! other child here.

use super::*;

/// Whether `path` has the SHAPE of a recovery volume, spent or partial:
/// its packet chain begins within [`par2::SNIFF_WINDOW`] bytes of the
/// start, and from there the file is nothing but packets - walked
/// header-to-header by each one's own declared length - and HOLES, the
/// zero runs an article that never arrived leaves behind.
///
/// Wave-4 row M4-53 (30 Aug 2026). [`sniffed_packet_files`] finds a
/// candidate on EIGHT BYTES, which is all it can afford to spend on a
/// whole directory and all it needs to: its job is to nominate. Its
/// callers then DELETE what it names, so eight bytes were the whole
/// evidence behind the strongest action the product takes. A payload
/// whose first bytes happen to be - or were made to be - `PAR2\0PKT`
/// was swept as a spent volume, at rc=0, with nothing in the log but a
/// leftover count.
///
/// WHY THE ZERO TAIL IS PART OF THE SHAPE, and it is not a hedge. A
/// `par2 create` volume really is a strict packet concatenation ending
/// exactly on EOF - measured over an r40 set on 30 Aug 2026, all
/// eleven files chain-exact. What is on DISK routinely is not: the
/// sniff DEFERS a volume, its still-queued articles are cancelled, and
/// the file keeps the full declared length with a hole where the body
/// was going to be. Every one of the ten leftovers
/// `an_undamaged_obfuscated_post_defers_its_sniffed_recovery_volumes`
/// produces is that shape, one of them a chain ending 104 bytes short
/// of EOF over the Creator packet that never arrived. An EOF-exact
/// rule would keep all ten forever, which is issue #9 back again. So
/// the rule is that nothing but packets and holes is in the file.
///
/// A polyglot fails it at the first step past its packet-shaped head,
/// because the bytes there are the payload somebody wants: DELIVERED
/// data, not a hole. That holds whatever the head is - the magic-only
/// shape row M4-53 posts, and the VALID-first-packet shape row M4-18
/// posts one seam over.
///
/// Framing only, deliberately: no packet MD5 is checked, because the
/// question is what the file IS and not whether its packets are sound.
/// A volume damaged in transit is still a volume, and sweeping it is
/// still right.
///
/// WHERE THE CHAIN IS ALLOWED TO BEGIN, and the whole of what row
/// M4-65's residue moved on 31 Aug 2026. It used to be offset 0
/// EXACTLY, while the sniff that nominates the file had already widened
/// to "the magic begins within [`par2::SNIFF_WINDOW`]". So the two
/// halves of one decision disagreed: a prefixed volume was FOUND, its
/// parity read and used, and then never swept.
///
/// The tempting reading of that is "the safe direction, leave it", and
/// it is wrong, because the file left behind is not the file that
/// arrived. The in-stream sniff (`get::workers`) reclassifies on the
/// same widened predicate and CANCELS the volume's remaining articles,
/// so what sits in the output directory is a deliberately truncated
/// file, under a hash name, that this engine holed itself and then
/// abandoned. Keeping that is issue #9, not caution about it.
///
/// WHAT DID NOT MOVE is the reason widening is affordable: every byte
/// from the chain's start to EOF is still accounted for as packet or
/// hole (which is what the paragraph below widened, not weakened), and a payload
/// carrying DELIVERED bytes past its packet-shaped head still fails at
/// the first of them. What is newly unexamined is at most
/// [`par2::SNIFF_WINDOW`] bytes of prefix - 64, one packet header - and
/// no file worth keeping is 64 bytes with a whole recovery volume behind
/// it. A file that IS 64 bytes of something plus a clean packet chain
/// ending on EOF or a hole is a recovery volume with a header stuck on
/// the front, which is precisely the shape M4-65 widened to find.
///
/// The bound is not a second copy of the sniff's: the start comes from
/// [`par2::packet_file_head_offset`], which is the function
/// `par2::head_is_packet_file` is defined in terms of. Narrowing one
/// narrows the other, and a lane that widens the sniff cannot leave this
/// behind again.
///
/// A HOLE IS NOT ONLY A TAIL, and this walk read one for a day as
/// though it were. The rule at the top is the rule M4-53 wrote down;
/// what it IMPLEMENTED was packets and then ONE trailing zero run,
/// which holds only while the articles that landed are a prefix. They
/// routinely are not: the deferral cancels a sniffed slot's
/// still-QUEUED articles and the ones already IN FLIGHT land, so an
/// article past the cancelled ones arrives and the file is packets,
/// hole, packets, hole. Measured 31 Aug 2026 on the leftover
/// `e2e_sniffedpar2::a_repaired_obfuscated_post_leaves_only_the_restored_payload`
/// kept twice in 180 loaded runs - a 535,988-byte volume, 134 packets
/// clean to 238,320, a 201,680-byte hole, then 36,640 bytes of a
/// straddling packet's tail, then more packets, then a trailing hole.
/// A trailing-hole-only rule reads that as payload and keeps it for
/// ever, which is issue #9's clutter back under a different cause, and
/// keeps it NONDETERMINISTICALLY, which is worse: the same post cleans
/// up correctly on an idle box.
///
/// STATED LIMITS, all of which fall on the safe side. A payload that
/// is packet-headed and then genuinely all zeros reads as a volume;
/// nothing can tell those apart, and a file of zeros is not the file
/// this row is about. A hole leaves exactly ONE span unaccounted - the
/// tail of the packet whose header fell inside it - and that span is
/// bounded by the longest packet this file has itself declared and
/// this walk has already stepped over, so a volume whose straddling
/// packet is longer than any before it reads as payload and is KEPT.
/// DELIVERED bytes with no hole in front of them are still the M4-53
/// polyglot and still read as payload: a resume is offered only across
/// a hole, which is the one thing a file being served to a user does
/// not have.
///
/// The chain walk seeks rather than reads, sixteen bytes per packet.
/// The zero scan stops at the FIRST non-zero byte, so a payload - the
/// case this exists to catch - costs one chunk. A genuine hole is read
/// in full, which is a linear pass over a file the job has just
/// finished writing at line rate, once per sniffed leftover. It is NOT
/// capped: a cap that answered "volume" past it would delete on less
/// evidence than the rule demands, and one that answered "payload"
/// would keep every large deferred volume for ever, which is issue #9.
/// The search for where the chain picks up again past a hole IS
/// capped, and by the same rule that judges it: it looks one longest
/// packet past the hole and no further, because past that bound the
/// answer would be "payload" whatever it found.
pub fn is_recovery_volume_shape(path: &Path) -> bool {
    /// Header length: magic (8) + packet length (8) + packet MD5 (16) +
    /// set id (16) + type (16). Spelled out because `par2::HEADER_LEN`
    /// is private to that module and this is a framing walk, not a
    /// parse.
    const HEADER: u64 = 64;
    /// One volume of a real set is packets in the hundreds. A file
    /// claiming more than a million is answering a different question,
    /// and the cap's answer - not a volume - keeps it.
    const MAX_PACKETS: usize = 1 << 20;
    /// One hole per gap in what arrived, so a real volume's count is
    /// its article count at worst. A runaway guard, not a property of
    /// any volume: each hole advances the walk, so this only bounds
    /// how long a hostile file may keep it walking.
    const MAX_HOLES: usize = 1 << 16;
    let Ok(f) = File::open(path) else {
        return false;
    };
    let Ok(end) = f.metadata().map(|m| m.len()) else {
        return false;
    };
    // The chain may begin behind a short prefix (M4-65 residue, 31 Aug
    // 2026) - the same window, read by the same function, as the sniff
    // that nominated this file.
    let mut window = [0u8; par2::SNIFF_WINDOW + 8];
    let want = crate::disk::chunk_len(end, window.len());
    if crate::disk::read_exact_at(&f, &mut window[..want], 0).is_err() {
        return false;
    }
    let Some(start) = par2::packet_file_head_offset(&window[..want]) else {
        return false;
    };
    let mut off = start as u64;
    let mut packets = 0usize;
    let mut holes = 0usize;
    // The longest packet this file has DECLARED and this walk has
    // stepped over. It is what bounds the unaccounted span a hole
    // leaves behind; see the limits above.
    let mut longest = 0u64;
    loop {
        // Walk the chain from `off` for as far as it stays contiguous.
        loop {
            if packets >= MAX_PACKETS {
                return false;
            }
            if end.saturating_sub(off) < HEADER {
                break;
            }
            let mut head = [0u8; 16];
            if crate::disk::read_exact_at(&f, &mut head, off).is_err() {
                return false;
            }
            if &head[..8] != par2::MAGIC {
                break;
            }
            let len = u64::from_le_bytes(head[8..16].try_into().unwrap());
            if len < HEADER || len % 4 != 0 {
                break;
            }
            let Some(next) = off.checked_add(len).filter(|&n| n <= end) else {
                break;
            };
            packets += 1;
            longest = longest.max(len);
            off = next;
            if off == end {
                return true;
            }
        }
        // Nothing was ever a packet - the magic the sniff saw was not
        // the head of one: not this shape, whatever follows.
        if packets == 0 {
            return false;
        }
        // The chain stopped. Past it a volume has a hole, and past the
        // hole either EOF or the chain picking up again.
        let Some(nz) = first_nonzero(&f, off, end) else {
            return true;
        };
        // Delivered bytes with no hole in front of them: the polyglot
        // this row exists to keep. Unchanged from M4-53.
        if nz == off {
            return false;
        }
        holes += 1;
        if holes > MAX_HOLES {
            return false;
        }
        // The packet whose header fell in the hole may straddle it, so
        // its tail is bytes this walk cannot account for. Look for the
        // chain within one such packet of the hole's end and no
        // further: past that bound the answer would be "payload"
        // anyway, so the search is bounded by the same rule.
        let Some(m) = next_magic(&f, nz, end.min(nz.saturating_add(longest)), end) else {
            return false;
        };
        off = m;
    }
}

/// Offset of the first non-zero byte in `[off, end)`, or `None` when
/// the span is all zeros. Stops at the first non-zero, so a payload -
/// the case this exists to catch - costs one chunk.
///
/// An unreadable span answers `Some(off)`, which the caller reads as
/// delivered bytes and so KEEPS the file: the same safe direction the
/// read error took when this was a `tail_is_zero`.
fn first_nonzero(f: &File, mut off: u64, end: u64) -> Option<u64> {
    let mut buf = vec![0u8; 1 << 20];
    while off < end {
        let want = crate::disk::chunk_len(end - off, buf.len());
        if crate::disk::read_exact_at(f, &mut buf[..want], off).is_err() {
            return Some(off);
        }
        if let Some(i) = buf[..want].iter().position(|&b| b != 0) {
            return Some(off + i as u64);
        }
        off += want as u64;
    }
    None
}

/// Offset of the first packet magic starting in `[off, last]`, reading
/// no further than `end`. `None` when there is none, or on a read
/// error - both of which KEEP the file.
///
/// Chunked with a seven-byte overlap, so a magic straddling two reads
/// is still found.
fn next_magic(f: &File, mut off: u64, last: u64, end: u64) -> Option<u64> {
    let mag = par2::MAGIC;
    let mut buf = vec![0u8; 1 << 20];
    while off <= last {
        // Read past `last` by up to the magic's own length: a match
        // may START at `last` and still needs its eight bytes.
        let span = (last - off).saturating_add(mag.len() as u64).min(end - off);
        let want = crate::disk::chunk_len(span, buf.len());
        if want < mag.len() {
            return None;
        }
        if crate::disk::read_exact_at(f, &mut buf[..want], off).is_err() {
            return None;
        }
        if let Some(i) = buf[..want]
            .windows(mag.len())
            .position(|w| w == mag)
            .filter(|&i| off + i as u64 <= last)
        {
            return Some(off + i as u64);
        }
        // Overlap so a magic split across the seam is not missed.
        off += (want - (mag.len() - 1)) as u64;
    }
    None
}
