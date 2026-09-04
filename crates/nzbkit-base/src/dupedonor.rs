//! PLAN M31 stage 1: borrow a lost segment's BYTES from a duplicate
//! posting of the same release.
//!
//! # The mechanism, and why it is cheap
//!
//! A yEnc article self-describes its placement: `=ybegin size=` is the
//! whole file's length and `=ypart begin=/end=` is the 1-based inclusive
//! byte range this part carries. So an article is not "segment 7 of this
//! NZB", it is "bytes 4,718,593..5,437,184 of a file 734,003,200 bytes
//! long". When an article fails on EVERY configured server, the
//! equivalent article of a DIFFERENT posting of the same file decodes to
//! the same byte range - and costs no PAR2 recovery block, because it is
//! the payload rather than parity.
//!
//! That is the whole of it. This module is the arithmetic; the fetching,
//! the donor NZB and the disk are the caller's.
//!
//! # What §282 already measured, and why this is still worth having
//!
//! `spare.rs` records a finding that reads, at
//! first, like a refutation: two indexer results for one release are
//! usually the SAME articles re-indexed, and when they are genuinely
//! different postings a different poster's upload is a different encode
//! that shares no byte range at all. It concludes "do NOT design for
//! resuming candidate A's 90% from candidate B", and that conclusion is
//! correct for the case it is about - a SEARCH RESULT standing in for a
//! failed grab.
//!
//! The population this module is for is the third one that note names in
//! passing: a REPOST. The same rar volumes, byte for byte, posted again
//! under new message-ids - which is exactly what happens to a release
//! after a takedown, and takedown damage is the case M31 exists to
//! lift. There the file content is identical and the message-ids are
//! not, so the donor articles are alive on the server precisely where
//! the target's are gone.
//!
//! So the identity test may NOT be "same release" in any sense a search
//! index can offer. It is byte identity, and the only thing that states
//! it is a digest: [`match_by_content`] pairs a target file with a donor
//! file when the two recovery sets agree on the file's LENGTH and its
//! whole-file MD5. That is the same evidence §305's whole-file adoption
//! demands before it skips a fetch (`crates/nzbfast-engine/src/get/donor.rs`),
//! for the same reason - a repack has the same names and lengths and
//! different bytes, and nothing weaker separates the two.
//!
//! # Correctness beats completion, twice over
//!
//! Byte identity licenses the borrow; it does not vouch for the bytes
//! that actually arrive. A donor article can be truncated, mis-declared,
//! or crafted. So every borrowed byte is re-verified against the
//! TARGET's own PAR2 block checksums before anything accepts it -
//! [`BlockHealer`] hands back a block only when that block's MD5 AND
//! CRC32 match what the target's set says they must be. A block that
//! fails is discarded whole - and, where another donor is still to be
//! asked, re-opened empty and tried against that one
//! ([`BlockHealer::reopen_rejected`]), so one donor's corrupt copy of a
//! block cannot poison it for the donors behind. A block no donor can
//! prove is left exactly as it was and the caller's repair ladder runs
//! for it as it would have.
//!
//! The gate that runs FIRST is cheaper and catches the ordinary case: a
//! donor article whose own account of itself does not fit the file we
//! are filling ([`placement_ok`]) is dropped without hashing anything.
//!
//! # Stage 1 scope
//!
//! Donors whose FILES are byte-identical. Borrowing across differently
//! packed postings - the same video re-encoded, or the same files rar'd
//! with a different volume size - is deliberately out, as PLAN M31 says:
//! there is no byte range to borrow, and the PAR2 sets disagree on every
//! digest, so [`match_by_content`] simply pairs nothing and the caller
//! does no work at all.

use crate::par2::{BlockCheck, Par2Set};

/// A byte range in a file: `off` is a zero-based file offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub off: u64,
    pub len: u64,
}

impl Span {
    pub fn end(&self) -> u64 {
        self.off.saturating_add(self.len)
    }

    /// The overlap of two spans, or `None` when they do not touch.
    pub fn intersect(&self, other: &Span) -> Option<Span> {
        let off = self.off.max(other.off);
        let end = self.end().min(other.end());
        // `then`, not `then_some`: the argument of `then_some` is
        // evaluated whether or not the condition holds, so the
        // subtraction would underflow on every pair that does NOT
        // overlap - which is most pairs this is asked about.
        (end > off).then(|| Span {
            off,
            len: end - off,
        })
    }
}

/// The byte ranges of the blocks a slot failed to verify, coalesced.
///
/// This is the gap oracle, and it is deliberately the PAR2 block grid
/// rather than an interval set of what the fetch placed. Three reasons,
/// and the third is the load-bearing one:
///
/// * The settle pass has already computed it ([`crate::live::SlotReport`]
///   `bad_blocks`), so nothing new has to be tracked during the download.
/// * A block is bad whether its bytes are MISSING or WRONG, and both are
///   equally borrowable - an interval set of placed spans sees only the
///   first.
/// * It is the granularity at which a borrow can be PROVED. A block is
///   the smallest unit the target's own set states a digest for, so
///   filling exactly whole blocks is what lets every borrowed byte be
///   checked before it is believed.
///
/// The last block of a file is short: it is stated here at its real
/// length, not `block_size` (the zero padding is the checksum's, not the
/// file's - see [`crate::live::check_block`]).
pub fn holes_from_bad_blocks(bad: &[usize], block_size: u64, length: u64) -> Vec<Span> {
    if block_size == 0 || length == 0 {
        return Vec::new();
    }
    let mut idx: Vec<usize> = bad.to_vec();
    idx.sort_unstable();
    idx.dedup();
    let mut out: Vec<Span> = Vec::new();
    for i in idx {
        let off = (i as u64).saturating_mul(block_size);
        if off >= length {
            // A bad-block index past the end of the file: the set and the
            // length disagree. Nothing to borrow for it.
            continue;
        }
        let len = block_size.min(length - off);
        match out.last_mut() {
            Some(prev) if prev.end() == off => prev.len += len,
            _ => out.push(Span { off, len }),
        }
    }
    out
}

/// A target file and the donor file that is byte-identical to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMatch {
    /// Index into `target.files`.
    pub target: usize,
    /// Index into `donor.files`.
    pub donor: usize,
    /// The length both sets agree on.
    pub length: u64,
}

/// A target file and the donor file that is byte-identical to it, in a
/// donor that ships more than one recovery set.
///
/// [`FileMatch`] with the set it was found in. Kept as its own type
/// rather than as an `Option` field on that one, because the two answer
/// different questions: a `FileMatch` names a member of the set it was
/// asked about, and a caller holding one has no set to look `donor` up
/// in but the one it passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetMatch {
    /// Index into the donor SETS slice this was matched against.
    pub set: usize,
    /// Index into `target.files`.
    pub target: usize,
    /// Index into `donors[set].files`.
    pub donor: usize,
    /// The length both sets agree on.
    pub length: u64,
}

/// Pair every target file with a donor file the two recovery sets agree
/// is byte-identical.
///
/// The key is `(length, whole-file MD5)`, and NOT the PAR2 File ID: that
/// id is a digest OF THE NAME as well as the content, so a donor that
/// posted the same bytes under a different filename - which is the norm
/// on an obfuscated repost - has a different id for the same file. The
/// name is not consulted at all here, deliberately: the
/// obfuscated-name ladder says the on-disk name is whatever the subject
/// said, and two postings of one file routinely disagree about it while
/// agreeing about every byte.
///
/// `md5_16k` is checked too. It is implied by the whole-file MD5 and
/// costs nothing, and it is the field a set built by a tool that
/// truncated its own hashing would disagree on.
///
/// A donor file is claimed at most once, so two identical files in one
/// set cannot both borrow from the same donor file - they get one each,
/// which is what a caller fetching per (file, span) wants. Ambiguity is
/// harmless either way: identical content is identical content.
///
/// The rule itself lives in [`match_by_content_multi`] and this is the
/// one-set door onto it, so the pairing is written once: a donor that
/// ships several independent sets needs a claim that spans them, and
/// two copies of a pairing rule are two rules the moment one is edited.
pub fn match_by_content(target: &Par2Set, donor: &Par2Set) -> Vec<FileMatch> {
    match_by_content_multi(target, std::slice::from_ref(donor))
        .into_iter()
        .map(|m| FileMatch {
            target: m.target,
            donor: m.donor,
            length: m.length,
        })
        .collect()
}

/// The same pairing over a donor that ships SEVERAL independent
/// recovery sets - one per file, which is GH #63's own shape - taken
/// as one decision rather than as one per set.
///
/// # Why this is not `match_by_content` in a loop
///
/// [`match_by_content`] keeps its claim bookkeeping inside one call, so
/// running it per donor set would let TWO of the donor's sets each pair
/// with the same target file: the caller then builds two asks for one
/// file's holes and fetches the same bytes twice. The claim that has to
/// span the sets is the TARGET's, and it is the reason this function
/// exists at all - it is what lets a caller widen past the "largest set
/// only" rule without paying for a hole twice.
///
/// Both claims are held, and they are different questions:
///
/// * A TARGET file is paired at most once across the whole donor. It is
///   claimed by the FIRST set that can serve it, and the search then
///   moves to the next target file.
/// * A DONOR file is claimed at most once WITHIN its own set, exactly
///   as [`match_by_content`] claims it - two identical target files get
///   one donor member each.
///
/// Set ORDER is the caller's and is honoured: `crate::live::pick_sets`
/// hands them back largest first with ties broken by set id, so which
/// set serves a file that appears in two of them does not depend on
/// which article came back first. Ambiguity is harmless either way -
/// identical content is identical content, and every borrowed block is
/// re-proved against the TARGET's own checksums regardless.
///
/// # What the target claim COSTS, measured rather than assumed
///
/// A second donor set that could also have served a file is never
/// tried, even where the first one only PARTLY served it - a donor
/// article that is itself dead leaves that hole to repair rather than
/// falling through to the twin. That fallback exists ACROSS donor
/// postings (`BlockHealer::reopen_rejected` plus the caller's donor
/// loop) and is deliberately not rebuilt inside one donor here, because
/// the claim is what stops a partly-served file re-asking for the holes
/// it has already filled: an ask is cut ONCE, against the holes as they
/// stood when it was built, so a second ask over the same file pulls
/// bodies for blocks that are no longer wanted and charges them to the
/// caller's byte ceiling.
///
/// The population that would benefit is a donor posting ONE file's
/// bytes twice, under two of its OWN recovery sets, with the first
/// copy's articles dead - which is not a shape any census here has
/// seen. Measured on `nzbfast`'s side while this landed: a duplicate
/// pairing is additionally absorbed by `fetch_and_offer`'s
/// already-satisfied guard whenever the first ask DOES satisfy the
/// file, so the wire cost the claim avoids is exactly the partial case
/// and nothing else.
pub fn match_by_content_multi(target: &Par2Set, donors: &[Par2Set]) -> Vec<SetMatch> {
    let mut taken: Vec<Vec<bool>> = donors.iter().map(|d| vec![false; d.files.len()]).collect();
    let mut out = Vec::new();
    for (ti, tf) in target.files.iter().enumerate() {
        if tf.length == 0 {
            continue;
        }
        let hit = donors.iter().enumerate().find_map(|(si, d)| {
            d.files
                .iter()
                .enumerate()
                .position(|(di, df)| {
                    !taken[si][di]
                        && df.length == tf.length
                        && df.md5 == tf.md5
                        && df.md5_16k == tf.md5_16k
                })
                .map(|di| (si, di))
        });
        if let Some((si, di)) = hit {
            taken[si][di] = true;
            out.push(SetMatch {
                set: si,
                target: ti,
                donor: di,
                length: tf.length,
            });
        }
    }
    out
}

/// A donor article's own account of where it belongs, read out of its
/// yEnc header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    /// `=ybegin size=` - the whole file's length.
    pub file_size: u64,
    /// Zero-based offset of this part (`=ypart begin=` minus one).
    pub off: u64,
    /// Decoded payload length actually in hand.
    pub len: u64,
    /// `=ypart end=`, the 1-based INCLUSIVE last byte. Zero when the
    /// article declared no part at all (a single-part post), in which
    /// case the payload covers the whole file and there is nothing to
    /// cross-check it against.
    pub declared_end: u64,
}

/// Does this donor article's self-description fit the file we are
/// filling, and is it internally consistent?
///
/// Four questions, and none of them is about the article's NAME. Two
/// postings of one file disagree about the name as a matter of course
/// (see [`match_by_content`]); they cannot disagree about the geometry
/// without one of them being wrong.
///
/// * The file it claims to be part of is `expect_len` bytes long.
/// * Its payload lands inside that file rather than off the end.
/// * The declared range and the bytes in hand agree, so a truncated
///   body cannot be written as if it were whole. (Skipped when the
///   article declared no `=ypart` at all: there is nothing to compare.)
/// * There are bytes at all.
pub fn placement_ok(p: &Placement, expect_len: u64) -> bool {
    if p.len == 0 || expect_len == 0 || p.file_size != expect_len {
        return false;
    }
    if p.off >= expect_len || p.off.saturating_add(p.len) > expect_len {
        return false;
    }
    // `end` is inclusive and 1-based, `off` is exclusive and 0-based:
    // a part covering [off, off+len) declares end = off + len.
    p.declared_end == 0 || p.declared_end == p.off.saturating_add(p.len)
}

/// A donor article's OBSERVED placement, out of its own yEnc header:
/// segment `index` of the donor file really began at byte `off`.
///
/// One of these is worth more than the estimate it corrects, because it
/// is a FACT about this file's geometry rather than a proportion
/// assumed of it - see [`candidate_segments_anchored`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegAnchor {
    /// Index into the same `seg_encoded` slice the estimate is over.
    pub index: usize,
    /// Zero-based file offset that segment's payload began at
    /// (`=ypart begin=` minus one).
    pub off: u64,
}

/// Which of a donor file's segments are worth asking for, to cover
/// `want`.
///
/// An NZB states each segment's ENCODED size and nothing else: no
/// offsets, and no decoded sizes (yEnc inflates by a per-article amount
/// that depends on how many bytes needed escaping). So a donor segment's
/// placement cannot be known before it is fetched - which is exactly why
/// [`placement_ok`] exists, and why this function is allowed to be an
/// estimate.
///
/// The estimate maps each segment's cumulative share of the ENCODED
/// total onto the file's real length. That is exact when every article
/// inflated by the same proportion (the usual case, and the identical
/// case when the donor is a repost of the same encode) and close
/// otherwise, because the inflation is a small fraction that varies
/// little across articles of one file.
///
/// `slack` widens both ends of the estimate; the caller pays for a wrong
/// guess in wasted bodies, never in wrong bytes, so it should be
/// generous - one segment's worth is the natural value. Returned indices
/// are ascending and unique.
///
/// This is the BLIND form, for the first ask against a donor file.
/// Once one of its articles has come back, use
/// [`candidate_segments_anchored`], which is the same arithmetic with
/// the guessing cut down to the gap between the hole and the article
/// that arrived.
pub fn candidate_segments(
    seg_encoded: &[u64],
    length: u64,
    want: &[Span],
    slack: u64,
) -> Vec<usize> {
    candidate_segments_anchored(seg_encoded, length, want, slack, None)
}

/// [`candidate_segments`], with the estimate CALIBRATED by an article
/// that has already come back.
///
/// # What one arrival is worth
///
/// The blind estimate above assumes one inflation ratio for the whole
/// file, taken from its totals. It is wrong by however far the true
/// cumulative decoded size has drifted from that straight line by the
/// segment in question, and that drift accumulates from the head of the
/// file - which is why `slack` has to be a whole article's worth, and
/// why a file SMALLER than `slack` degenerates to "ask for all of it".
///
/// An arrival pins the line. `=ypart begin=` states, exactly, the
/// offset segment `k` starts at, so the fit becomes piecewise-linear in
/// cumulative encoded bytes through THREE exact points, none of them
/// assumed:
///
/// * `(0, 0)` - the file starts where the file starts.
/// * `(cum[k], anchor.off)` - the arrival.
/// * `(total, length)` - the last segment ends at the end of the file.
///
/// The drift no longer accumulates from the head of the file; it
/// accumulates from the nearer of the anchor and the file's two ends.
/// So the bounds tighten with it, to the width `decoded <= encoded`
/// pins over that gap, plus one article's worth as a floor: nothing
/// here is a tuned constant, and a file whose encoded sizes ARE its
/// decoded sizes (`total == length`) calibrates to an exact fit with
/// zero slack, correctly.
///
/// # Why it cannot miss a segment that really covers a hole
///
/// The bounds are not an estimate widened by a slack; they are the
/// exact interval `decoded <= encoded` pins, applied to each stretch
/// the anchor cuts the file into, and that inequality holds for EVERY
/// inflation profile - so no homogeneity assumption is left anywhere in
/// the cut. On the far side of the anchor, the true offset at `c`
/// encoded bytes in can be no more than `c - cum[k]` past `anchor.off`
/// (the decoded bytes of that stretch fit inside its encoded bytes) and
/// no less than `length - (total - c)` (the decoded bytes after `c` fit
/// inside the encoded bytes after `c`); the near side is the mirror.
/// An earlier version widened a fitted line by the FILE-AVERAGE
/// inflation over the gap, capped at the caller's slack - which let a
/// far anchor prune harder than no anchor at all, and dropped a
/// covering segment whenever real region-scale inflation variation put
/// the true span outside the average's reach. The interval form has no
/// such step: a far anchor honestly proves little and prunes little,
/// while near the anchor the interval collapses, which is where the
/// measured saving lives.
///
/// # Where this is worth more than asking in a good order
///
/// On a healthy donor it often is not, and the test table says so: the
/// healer stops the ask as soon as the hole is covered, so a plan
/// ordered nearest-first ([`ask_order`]) usually stops before the
/// surplus candidates are reached at all. What calibration is for is
/// the donor that is ITSELF damaged - not exotic in a pass that exists
/// for damaged postings. There the short-circuit never fires, the whole
/// candidate list gets walked, and cutting it down is the only saving
/// available: eight bodies to four on the last row of that table, where
/// ordering alone saves nothing.
///
/// An anchor that CONTRADICTS the stated sizes - one whose offset is
/// past the encoded bytes before it, or that leaves less room after it
/// than the rest of the file needs - is ignored rather than believed,
/// and the blind estimate is used. That is the NZB and the article
/// disagreeing about the file, which is not something to calibrate on.
pub fn candidate_segments_anchored(
    seg_encoded: &[u64],
    length: u64,
    want: &[Span],
    slack: u64,
    anchor: Option<SegAnchor>,
) -> Vec<usize> {
    let total: u64 = seg_encoded.iter().copied().sum();
    if total == 0 || length == 0 || seg_encoded.is_empty() || want.is_empty() {
        return Vec::new();
    }
    let n = seg_encoded.len();
    // Encoded bytes BEFORE segment `i`, with `cum[n] == total`.
    let mut cum: Vec<u64> = Vec::with_capacity(n + 1);
    let mut acc = 0u64;
    cum.push(0);
    for &e in seg_encoded {
        acc = acc.saturating_add(e);
        cum.push(acc);
    }
    // The two conditions `decoded <= encoded` imposes on a truthful
    // anchor: the bytes before it fit in the encoded bytes before it,
    // and the bytes after it fit in the encoded bytes after it.
    let anchor = anchor.filter(|a| {
        a.index < n
            && a.off <= length
            && a.off <= cum[a.index]
            && length - a.off <= total - cum[a.index]
            && cum[a.index] < total
    });
    // The file's own stated inflation, and one article's share of it -
    // the unit the fit's residual is measured in, and its floor.
    let inflation = total - length.min(total);
    let one = inflation / n as u64;
    // Where the fit puts the file offset that `c` encoded bytes in.
    // Every ratio is taken in u128: `cum * length` overflows u64 on a
    // large file with a large encoded total, and a wrapped product would
    // put every estimate at the head of the file.
    let fit = |c: u64| -> u64 {
        match anchor {
            None => (c as u128 * length as u128 / total as u128) as u64,
            Some(a) => {
                let ca = cum[a.index];
                if c <= ca {
                    if ca == 0 {
                        0
                    } else {
                        (c as u128 * a.off as u128 / ca as u128) as u64
                    }
                } else {
                    a.off
                        + ((c - ca) as u128 * (length - a.off) as u128 / (total - ca) as u128)
                            as u64
                }
            }
        }
    };
    // The interval the true offset at `c` encoded bytes in MUST lie in.
    // With no anchor, the fitted line widened by the caller's slack, as
    // it is today. With one, `decoded <= encoded` on each stretch the
    // anchor cuts the file into: past the anchor the offset is at most
    // `gap` bytes on (that stretch's decoded bytes fit inside its
    // encoded bytes) and at least `length - (total - c)` (the bytes
    // after `c` fit inside the encoded bytes after `c`); before it, the
    // mirror. Those hold for EVERY inflation profile, so the cut is
    // sound unconditionally, where the fitted-line-plus-average-drift
    // this replaces was not (region-scale inflation variation put the
    // true span outside it, and its `.min(slack)` cap let a far anchor
    // prune harder than no anchor at all). Each edge keeps the one-
    // article floor so a boundary case cannot fall through.
    let bounds = |c: u64| -> (u64, u64) {
        let Some(a) = anchor else {
            let f = fit(c);
            return (f.saturating_sub(slack), f.saturating_add(slack));
        };
        let ca = cum[a.index];
        let (lo, hi) = if c >= ca {
            let gap = c - ca;
            (
                length.saturating_sub(total - c).max(a.off),
                a.off.saturating_add(gap).min(length),
            )
        } else {
            let gap = ca - c;
            (a.off.saturating_sub(gap), a.off.min(c))
        };
        (lo.saturating_sub(one), hi.saturating_add(one))
    };
    let mut out = Vec::new();
    for i in 0..n {
        let lo = bounds(cum[i]).0;
        let hi = bounds(cum[i + 1]).1.min(length.saturating_add(slack));
        let guess = Span {
            off: lo,
            len: hi.saturating_sub(lo),
        };
        if want.iter().any(|w| guess.intersect(w).is_some()) {
            out.push(i);
        }
    }
    out
}

/// Order a candidate list MOST-LIKELY-FIRST: the segment the blind
/// estimate puts nearest a hole, then outwards, ties by index.
///
/// This is the companion to [`candidate_segments_anchored`] and it is
/// worth its dozen lines for one reason: the FIRST article a donor file
/// gives up is the anchor every later cut of the plan is made against,
/// and both of the things you want from it are the same thing. An
/// article over the hole is the one the fill actually needs, and it is
/// also the anchor nearest to the segments still being decided about,
/// which is where the calibrated slack is tightest.
///
/// Ascending order gets neither. The blind estimate's slack is a whole
/// article wide at each end, so its lowest-indexed candidate is
/// reliably one the fill does not want AND the furthest usable anchor
/// from the hole - a body spent to learn the least.
///
/// Measured over eight file shapes, pinned in this module's tests: a
/// 700 MB file's single hole costs two donor bodies blind and ONE asked
/// in this order, a sub-1-MiB file's hole the same, and three holes far
/// apart in a 700 MB file cost twelve and five. Ordering is what
/// carries a HEALTHY donor, because [`BlockHealer::is_satisfied`] stops
/// the ask the moment every wanted byte is in hand - so asking for the
/// likely article first stops it a body or two sooner, and the
/// calibration behind it then has nothing left to prune. The division
/// of labour is the other way round on a donor that is itself damaged,
/// which is where [`candidate_segments_anchored`] earns its keep.
///
/// Distance is measured on the BLIND estimate, because at this point
/// nothing has arrived - a segment whose guess overlaps a hole is at
/// distance zero. `segs` is returned re-ordered, never re-judged: what
/// to ask for is [`candidate_segments`]'s answer and this changes only
/// the order it is asked in.
pub fn ask_order(seg_encoded: &[u64], length: u64, want: &[Span], segs: &[usize]) -> Vec<usize> {
    let total: u64 = seg_encoded.iter().copied().sum();
    let mut out = segs.to_vec();
    if total == 0 || length == 0 || want.is_empty() {
        return out;
    }
    let mut cum: Vec<u64> = Vec::with_capacity(seg_encoded.len() + 1);
    let mut acc = 0u64;
    cum.push(0);
    for &e in seg_encoded {
        acc = acc.saturating_add(e);
        cum.push(acc);
    }
    let est = |c: u64| -> u64 { (c as u128 * length as u128 / total as u128) as u64 };
    out.sort_by_key(|&i| {
        let (off, end) = match cum.get(i + 1) {
            // A segment index the list should never carry: sorted to
            // the back rather than dropped, because judging what to ask
            // for is not this function's job.
            None => return (u64::MAX, i),
            Some(&c) => (est(cum[i]), est(c)),
        };
        let d = want
            .iter()
            .map(|w| {
                if end > w.off && w.end() > off {
                    0
                } else {
                    w.off.saturating_sub(end).max(off.saturating_sub(w.end()))
                }
            })
            .min()
            .unwrap_or(u64::MAX);
        (d, i)
    });
    out
}

/// One block rebuilt from borrowed bytes and PROVED against the target's
/// own PAR2 checksums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Healed {
    /// Index into the file's block list.
    pub block: usize,
    /// Zero-based file offset to write `bytes` at.
    pub off: u64,
    pub bytes: Vec<u8>,
}

/// Assembly state for one wanted block.
struct Assembly {
    off: u64,
    buf: Vec<u8>,
    /// Coalesced `[start, end)` ranges of `buf` that have been filled.
    filled: Vec<(usize, usize)>,
}

/// The assembly for block `i` of a file, or `None` when that index is
/// not one this healer can ever fill.
///
/// The guards are the reason this is a function and not two copies:
/// [`BlockHealer::new`] and [`BlockHealer::reopen_rejected`] both open
/// blocks, and a retry that skipped one of them would open a buffer of
/// a length the check could never match.
fn assembly_for(i: usize, block_size: u64, length: u64, checks: usize) -> Option<Assembly> {
    let off = (i as u64).saturating_mul(block_size);
    if block_size == 0 || length == 0 || off >= length || i >= checks {
        return None;
    }
    let len = block_size.min(length - off);
    // A block that does not fit an in-memory buffer on THIS target is
    // refused rather than truncated: a 32-bit build (the armv7 shipped
    // one) narrows a > 4 GiB block size to a wrong length, and a
    // wrong-length buffer would be assembled, checked and rejected
    // forever. A real set's block size is kilobytes to megabytes, so
    // this only ever refuses a malformed one.
    let len = usize::try_from(len).ok()?;
    Some(Assembly {
        off,
        buf: vec![0u8; len],
        filled: Vec::new(),
    })
}

impl Assembly {
    /// Write the parts of `[at, at+data.len())` that are not already
    /// filled, and report how many bytes that was.
    ///
    /// FIRST BYTES WIN, and that is a decision rather than an
    /// optimisation. Two donors offering one range are offering the
    /// same bytes when both are honest, so a later write can only ever
    /// be a no-op or a corruption; letting it land would also make the
    /// block's verdict depend on arrival order, which is the one thing
    /// a proof must not do. A block whose first coverage was bad is
    /// rejected whole - and then, if another donor is still to be
    /// asked, re-opened as a FRESH assembly by
    /// [`BlockHealer::reopen_rejected`], which keeps this rule intact:
    /// the retry is a new proof from an empty buffer, never a later
    /// write landing over an earlier one.
    fn fill(&mut self, at: usize, data: &[u8]) -> usize {
        let end = (at + data.len()).min(self.buf.len());
        if end <= at {
            return 0;
        }
        // Walk the gaps between the already-filled runs; `filled` is
        // kept sorted and coalesced, so one pass covers them all.
        let mut wrote = 0;
        let mut cur = at;
        let mut added: Vec<(usize, usize)> = Vec::new();
        for &(s, e) in &self.filled {
            if s >= end {
                break;
            }
            if e <= cur {
                continue;
            }
            if s > cur {
                added.push((cur, s.min(end)));
            }
            cur = cur.max(e);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            added.push((cur, end));
        }
        for &(s, e) in &added {
            self.buf[s..e].copy_from_slice(&data[s - at..e - at]);
            wrote += e - s;
        }
        self.filled.extend(added);
        self.filled.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.filled.len());
        for &(s, e) in &self.filled {
            match merged.last_mut() {
                Some(prev) if s <= prev.1 => prev.1 = prev.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.filled = merged;
        wrote
    }

    fn complete(&self) -> bool {
        matches!(self.filled.as_slice(), [(0, e)] if *e == self.buf.len())
    }
}

/// Rebuild a damaged file's bad blocks out of donor bytes, accepting
/// only what the target's own recovery set vouches for.
///
/// The unit is the BLOCK and never the article, which is what makes the
/// borrow provable: a block is the smallest span the target's set states
/// an MD5 and a CRC32 for, so a rebuilt block is either exactly the
/// bytes the original had or it is discarded. Nothing partial is ever
/// handed out - a block the donors covered only half of stays bad, and
/// the caller's PAR2 repair runs for it exactly as it would have.
///
/// The healer is content-blind about SOURCE: [`BlockHealer::offer`] takes
/// donor bytes and locally-read bytes alike, because both are judged by
/// the same check. That is what lets a caller top up the good remainder
/// of a partly-covered block from the file already on disk.
pub struct BlockHealer {
    block_size: u64,
    length: u64,
    checks: Vec<BlockCheck>,
    open: std::collections::BTreeMap<usize, Assembly>,
    healed: usize,
    rejected: usize,
    /// Blocks rejected since the last [`BlockHealer::reopen_rejected`],
    /// in the order they were judged - the retry list.
    rejected_blocks: Vec<usize>,
    used: u64,
}

impl BlockHealer {
    /// A healer for `bad` blocks of a file `length` bytes long, holding
    /// the target set's own per-block checksums.
    ///
    /// Blocks with no checksum behind them are dropped rather than
    /// accepted unchecked: a set whose IFSC packet did not survive
    /// parsing states nothing about its blocks, and an unprovable borrow
    /// is worse than no borrow (see the module docs).
    pub fn new(checks: &[BlockCheck], block_size: u64, length: u64, bad: &[usize]) -> BlockHealer {
        let mut open = std::collections::BTreeMap::new();
        for &i in bad {
            if open.contains_key(&i) {
                continue;
            }
            if let Some(a) = assembly_for(i, block_size, length, checks.len()) {
                open.insert(i, a);
            }
        }
        BlockHealer {
            block_size,
            length,
            checks: checks.to_vec(),
            open,
            healed: 0,
            rejected: 0,
            rejected_blocks: Vec::new(),
            used: 0,
        }
    }

    /// The byte ranges still wanted, coalesced - what the caller fetches
    /// donor articles for. Shrinks as blocks are taken.
    pub fn wanted(&self) -> Vec<Span> {
        let mut out: Vec<Span> = Vec::new();
        for a in self.open.values() {
            let s = Span {
                off: a.off,
                len: a.buf.len() as u64,
            };
            match out.last_mut() {
                Some(prev) if prev.end() == s.off => prev.len += s.len,
                _ => out.push(s),
            }
        }
        out
    }

    /// Is there anything left to fill?
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Has every block still open been fully covered - so more donor
    /// bytes would be wasted, even though nothing has been PROVED yet?
    ///
    /// [`BlockHealer::is_empty`] cannot answer this: a block leaves
    /// `open` only when [`BlockHealer::take_healed`] judges it, and a
    /// caller that judges once at the end would otherwise keep pulling
    /// donor articles for blocks it already has every byte of. The
    /// answer for a healer with nothing open is `true` - there is
    /// nothing left to ask for either way.
    pub fn is_satisfied(&self) -> bool {
        self.open.values().all(Assembly::complete)
    }

    /// Offer `data`, which belongs at file offset `off`. Returns how many
    /// bytes landed in a block that still wants them; bytes outside every
    /// open block, and bytes over a range some earlier offer already
    /// filled, are ignored (see [`Assembly::fill`]).
    pub fn offer(&mut self, off: u64, data: &[u8]) -> u64 {
        if data.is_empty() || self.block_size == 0 {
            return 0;
        }
        let given = Span {
            off,
            len: data.len() as u64,
        };
        let mut took = 0u64;
        for a in self.open.values_mut() {
            let block = Span {
                off: a.off,
                len: a.buf.len() as u64,
            };
            let Some(hit) = block.intersect(&given) else {
                continue;
            };
            // Both narrowings are bounded by `data.len()` / the block's
            // own buffer, which are `usize` already.
            let src = (hit.off - given.off) as usize;
            let dst = (hit.off - block.off) as usize;
            let n = crate::disk::chunk_len(hit.len, data.len().saturating_sub(src));
            took = took.saturating_add(a.fill(dst, &data[src..src + n]) as u64);
        }
        self.used = self.used.saturating_add(took);
        took
    }

    /// Take every block that is now fully covered AND matches the
    /// target's own checksums. A fully covered block that does NOT
    /// match is dropped here - counted in [`BlockHealer::rejected`],
    /// never returned, and never repaired in place.
    ///
    /// It IS remembered: its index joins
    /// [`BlockHealer::rejected_blocks`], so a caller with another donor
    /// still to ask can re-open it from scratch with
    /// [`BlockHealer::reopen_rejected`]. That is the whole of the
    /// retry, and it keeps first-bytes-win intact - the second attempt
    /// is a NEW assembly over an empty buffer, judged on its own, and
    /// no accepted block is ever displaced by a later write.
    pub fn take_healed(&mut self) -> Vec<Healed> {
        let ready: Vec<usize> = self
            .open
            .iter()
            .filter(|(_, a)| a.complete())
            .map(|(i, _)| *i)
            .collect();
        let mut out = Vec::new();
        for i in ready {
            let Some(a) = self.open.remove(&i) else {
                continue;
            };
            // `block_size` is the padding width the checksum was taken
            // over, not the block's real length - see check_block.
            let bs = crate::disk::chunk_len(self.block_size, usize::MAX);
            if crate::live::check_block(&self.checks[i], bs, &a.buf) {
                self.healed += 1;
                out.push(Healed {
                    block: i,
                    off: a.off,
                    bytes: a.buf,
                });
            } else {
                self.rejected += 1;
                self.rejected_blocks.push(i);
            }
        }
        out
    }

    /// Open blocks a donor has PART-served: some bytes in, not enough
    /// to judge.
    ///
    /// The unit of proof here is the block, so a block a donor could
    /// only half-fill is never judged and never handed out - it stays
    /// open until some later offer completes it, and with no later
    /// offer it is simply abandoned to repair. That is the right answer
    /// whenever the missing half is missing everywhere; it is the wrong
    /// one when the TARGET's own download still holds it, which is the
    /// ordinary case as soon as the set's block is wider than an
    /// article.
    ///
    /// Measured on a real store-RAR switch
    /// (`research/DONOR-ADOPT-ZERO-ON-STORE-RAR-2026-08-28.md`): a
    /// 1,536,000-byte block over 768,000-byte articles is exactly two
    /// articles, so block `k` covers articles `2k` and `2k+1`, and a
    /// stride-2 article mask poisons one article of every pair in BOTH
    /// postings. Neither posting then holds one whole block of the
    /// damaged range, though between them they hold every byte.
    ///
    /// This is what a caller with the target's own bytes to hand needs
    /// in order to offer them, and it is deliberately NARROWER than
    /// "every open block": a block no donor touched at all is one whose
    /// gap the target cannot possibly close, since the target's copy of
    /// it is exactly the copy the recovery set already called bad.
    /// Offering into those would buy an MD5 and a CRC32 per block to be
    /// told so again.
    pub fn part_filled(&self) -> Vec<usize> {
        self.open
            .iter()
            .filter(|(_, a)| !a.filled.is_empty() && !a.complete())
            .map(|(i, _)| *i)
            .collect()
    }

    /// Blocks judged and REFUSED since the last
    /// [`BlockHealer::reopen_rejected`] - what a retry against the next
    /// donor would be for.
    pub fn rejected_blocks(&self) -> &[usize] {
        &self.rejected_blocks
    }

    /// Re-open every block [`BlockHealer::take_healed`] refused, as a
    /// FRESH empty assembly, and report how many that was.
    ///
    /// This is the one place a rejected block comes back, and what it
    /// restores is the block's IDENTITY rather than its bytes: nothing
    /// the bad donor wrote survives, so the next donor's coverage is
    /// judged alone and first-bytes-win is untouched (see
    /// [`Assembly::fill`]). A block that has already been PROVED never
    /// reaches this list at all, so no accepted block can be reopened
    /// and lost.
    ///
    /// Call it between donors. Calling it with no donor left to ask
    /// only re-opens blocks nothing will fill - they stay open, are
    /// never complete, and are never handed out.
    pub fn reopen_rejected(&mut self) -> usize {
        let mut n = 0;
        for i in std::mem::take(&mut self.rejected_blocks) {
            if self.open.contains_key(&i) {
                continue;
            }
            if let Some(a) = assembly_for(i, self.block_size, self.length, self.checks.len()) {
                self.open.insert(i, a);
                n += 1;
            }
        }
        n
    }

    /// Blocks proved and handed back so far.
    pub fn healed(&self) -> usize {
        self.healed
    }

    /// Judgements that were fully covered and failed their own set's
    /// checksums - borrowed bytes this refused. One block refused twice,
    /// from two donors, counts twice: this is attempts refused, not
    /// blocks lost, and a block can be refused and then healed.
    pub fn rejected(&self) -> usize {
        self.rejected
    }

    /// Bytes accepted into an open block (before proving).
    pub fn used(&self) -> u64 {
        self.used
    }

    /// The file length this healer was built for.
    pub fn length(&self) -> u64 {
        self.length
    }
}

#[cfg(test)]
mod tests;
