//! The finish-time TWIN tier: which of several identical-head
//! descriptors a slot's bytes actually are.
//!
//! `try_match`'s md5-16k tier declines when two or more unclaimed
//! descriptors share the slot's exact first 16 KiB, because a shared
//! head is not a shared file and taking the first hit made the pairing
//! a worker-thread race (matrix finding F1). What it defers to is here,
//! and it runs ONLY from `finish_slot_from`, because both of its
//! answers need bytes that do not exist before then:
//!
//!   * the whole-file MD5, which names the twin exactly when the slot
//!     is INTACT;
//!   * per-block IFSC evidence, which names it when the slot is
//!     DAMAGED - and a damaged slot is exactly the case the whole-file
//!     MD5 can never settle, since the difference between the slot and
//!     its own descriptor IS the damage.
//!
//! Split out of `live.rs` (TODO 106 size gate); a child module, so
//! `SlotState`'s private fields stay private to this file's parent and
//! its descendants.

use super::*;

impl SlotState {
    /// Whole-file tier behind the md5-16k ambiguity decline in
    /// [`try_match`](Self::try_match): with the slot's bytes complete
    /// (finish time), the whole-file MD5 tells identical-head twins
    /// apart deterministically where the 16 KiB head cannot. Only runs
    /// when TWO or more unclaimed descriptors share the slot's head key
    /// - a unique key claims in `try_match` exactly as before. Candidate
    /// hashes are computed with the claim lock RELEASED (a whole-file
    /// read must not stall every other slot's matching), then the claim
    /// re-checks under the lock; a candidate a twin raced us to falls
    /// through to the next, which is correct even for byte-identical
    /// twins (either pairing is the same bytes).
    ///
    /// Behind THAT sits the block-evidence tier ([`ifsc_pairing`]) for
    /// the damaged slot every whole-file hash refuses - see its own
    /// note for the rule and for what it still declines.
    pub(super) fn try_match_whole(
        &mut self,
        slot: usize,
        active: &Active,
        src: &ReadAt<'_>,
    ) -> bool {
        let want = self.head_want();
        if want == 0
            || !self
                .head
                .as_ref()
                .is_some_and(|h| h.buf.len() == want && h.complete())
        {
            return false;
        }
        let head_md5: [u8; 16] = Md5::digest(&self.head.as_ref().unwrap().buf).into();
        let cands: Vec<usize> = {
            let claimed = active.claimed.lock_ok();
            active
                .files()
                .filter(|(fi, f)| {
                    claimed[*fi].is_none()
                        && f.length.min(HEAD_LEN as u64) == want as u64
                        && f.md5_16k == head_md5
                })
                .map(|(fi, _)| fi)
                .collect()
        };
        // A SOLE CANDIDATE IS NOT A GAP HERE, and this early return is
        // what makes the tier a pairing question rather than the
        // elimination its own note forbids - so do not "fix" it. The
        // twin that settles SECOND never reaches this line: by then its
        // rival is claimed, so `try_match`'s md5-16k uniqueness above
        // finds a sole unclaimed candidate and takes it there. Claiming
        // by elimination HERE would be a different thing entirely, and
        // the objection to it is the one `ifsc_pairing` states below -
        // with two twins both damaged it picks arbitrarily, and a wrong
        // claim lets settle publish this slot's bytes under the other
        // file's name.
        if cands.len() < 2 {
            return false;
        }
        let n_cands = cands.len();
        // At most one read per distinct declared length (twins share
        // one, so normally a single read); a source that cannot serve a
        // candidate's length simply fails that candidate, never the run.
        //
        // THE MEMO REMEMBERS A FAILURE, and until X5-21 (31 Aug 2026) it
        // remembered only a success - which left the cache defeated in
        // exactly the shape it was written for. Every candidate here
        // shares this slot's 16 KiB head, so a group that also shares
        // ONE declared length is the ordinary twin post; when that one
        // length is not the length of the bytes that actually landed,
        // every candidate's read failed, nothing was cached, and the
        // next candidate re-read the same doomed length. Measured on the
        // row's own fixture, 24 candidates of one wrong length over one
        // 20 KiB slot: 24 whole-file reads for a question with ONE
        // answer. It is sound to remember because it is a fact about
        // (this source, this length) and both are fixed for this loop -
        // the same reasoning the positive half already ran on, which is
        // why the two belong in one memo rather than in two rules.
        //
        // `Vec` and not a map: the population is a candidate group, the
        // lookup is against a handful of lengths, and what this exists
        // to save is a whole-file hash rather than a comparison.
        let mut answered: Vec<(u64, Option<[u8; 16]>)> = Vec::new();
        for &fi in &cands {
            let f = active.file(fi);
            let known = answered
                .iter()
                .find(|(l, _)| *l == f.length)
                .map(|(_, h)| *h);
            let whole = match known {
                Some(Some(h)) => h,
                Some(None) => continue,
                None => {
                    let got = src_md5(src, f.length).ok();
                    answered.push((f.length, got));
                    match got {
                        Some(h) => h,
                        None => continue,
                    }
                }
            };
            if whole != f.md5 {
                continue;
            }
            let mut claimed = active.claimed.lock_ok();
            if claimed[fi].is_some() {
                continue;
            }
            claimed[fi] = Some(slot);
            self.file = Some(fi);
            self.confirmed = true;
            self.blocks = vec![BlockState::Pending; f.blocks.len()];
            return true;
        }
        // Every candidate failed its whole-file MD5, which for this tier
        // means the slot on disk is DAMAGED: the tier is only entered
        // when two-or-more unclaimed descriptors share this slot's exact
        // 16k head, so the file is one of them and the difference is the
        // damage. Left there, the slot stays unclaimed and the set prices
        // it as WHOLLY MISSING rather than as the partially-damaged
        // member it is - many more recovery blocks than the repair needs,
        // and a job that was repairable can read as Unrepairable.
        //
        // So the per-block IFSC evidence is asked next. Note what is NOT
        // asked: "exactly one candidate is left, so it must be ours" is
        // sound only when the others were claimed by their own exact
        // matches, and with two twins BOTH damaged it picks arbitrarily -
        // a wrong claim lets settle publish this slot's bytes under the
        // other file's name, which is strictly worse than the over-count
        // it would fix.
        let (pairing, scores) = ifsc_pairing(active, src, &cands);
        if let Some(fi) = pairing {
            let mut claimed = active.claimed.lock_ok();
            // A twin that raced us to it took it on evidence of its own;
            // ours says nothing about any OTHER descriptor, so there is
            // nothing to fall through to and the slot declines.
            if claimed[fi].is_none() {
                claimed[fi] = Some(slot);
                drop(claimed);
                let f = active.file(fi);
                tracing::info!(
                    target: "par2",
                    "slot {slot} is a damaged member of a {n} identical-head group: \
                     its surviving blocks carry {name}'s own PAR2 block checksums \
                     ({scores}), so it is repaired in place rather than counted missing",
                    n = n_cands,
                    name = f.name,
                );
                self.file = Some(fi);
                self.confirmed = true;
                self.blocks = vec![BlockState::Pending; f.blocks.len()];
                return true;
            }
        }
        // Said out loud because it is otherwise invisible: nothing else
        // reports a slot that silently declined every candidate.
        tracing::warn!(
            target: "par2",
            "slot {slot} matches {n} recovery-set entries on its first 16k but none \
             on the whole file, and its per-block PAR2 evidence does not separate \
             them ({scores}) - it is damaged, and is being counted as missing \
             rather than repaired in place",
            n = n_cands,
        );
        false
    }
}

/// How many blocks a probe may take, and how many bytes they may cost.
/// Shared with [`nametier::ifsc_evidence`](super::nametier::ifsc_evidence),
/// which calls [`probe_blocks`] rather than keeping its own copy of this
/// loop - both run on a damaged file that may be very large. ONE probe
/// serves however many candidates are on the table - they share a block
/// partition, so a block's real bytes are hashed once and compared
/// against every candidate's own IFSC entry at that index (one entry,
/// for `ifsc_evidence`'s single-candidate case).
const PROBES: usize = 32;
const BYTE_CAP: u64 = 64 << 20;

/// Which identical-head candidate this slot's DAMAGED bytes belong to,
/// on per-block IFSC evidence, plus a human-readable score line for the
/// log whichever way it goes.
///
/// THE RULE, and it is deliberately not "whoever scores highest". A
/// block index only carries information about WHICH twin these bytes are
/// when the twins declare different checksums there; two members of one
/// post routinely share long identical runs (a zero-padded head, a
/// common container prefix), and a block inside such a run matches both
/// descriptors while saying nothing. So the winner is the candidate with
/// strictly the most matched blocks, and it is claimed only when, for
/// EVERY rival:
///
///   * at least one DISTINGUISHING block - one the two declare
///     differently - was matched for the winner, and
///   * ZERO distinguishing blocks were matched for the rival.
///
/// One matched distinguishing block is the whole bar and the bar is not
/// arbitrary: a block matches on CRC32 **and** MD5 over the padded
/// slice, which is the same evidence settle read-back publishes a block
/// on and the same evidence adoption takes a block out of a foreign file
/// on. If it is good enough to publish the bytes it is good enough to
/// say whose bytes they are. What the rival clause adds is the case that
/// evidence alone cannot settle: a slot carrying blocks of BOTH is not a
/// pairing anybody may make, and it declines.
///
/// TWO SHAPES DECLINE BY CONSTRUCTION and both are correct. Twins that
/// differ ONLY where this slot is damaged have no matched distinguishing
/// block, so nothing separates them - which is the fixture
/// `two_identical_head_twins_damaged_in_their_only_distinguishing_block_still_decline`
/// pins. And descriptors that declare the SAME blocks throughout (one
/// file posted into two recovery sets) have no distinguishing block at
/// all; either pairing would in fact be right, and declining them is
/// exactly the answer this tier gave before the evidence arm existed.
///
/// The group must share ONE block size and ONE length, or the block
/// index does not name the same byte range for every candidate and the
/// comparison is not one. A mixed group declines rather than guessing.
fn ifsc_pairing(active: &Active, src: &ReadAt<'_>, cands: &[usize]) -> (Option<usize>, String) {
    let bs = active.block_size(cands[0]) as usize;
    let f0 = active.file(cands[0]);
    let nblocks = f0.blocks.len();
    let uniform = bs > 0
        && nblocks > 0
        && cands.iter().all(|&fi| {
            let f = active.file(fi);
            active.block_size(fi) as usize == bs
                && f.length == f0.length
                && f.blocks.len() == nblocks
        });
    if !uniform {
        return (None, "no comparable per-block checksums".to_string());
    }
    let decls: Vec<&[BlockCheck]> = cands
        .iter()
        .map(|&fi| &active.file(fi).blocks[..])
        .collect();
    // Never stop early: the distinguishing-block count below needs the
    // whole probe set, not just the first hit.
    let probe = probe_blocks(src, f0.length, bs, nblocks, &decls, |_hit| false);
    let totals: Vec<usize> = (0..cands.len())
        .map(|c| probe.iter().filter(|(_, hit)| hit[c]).count())
        .collect();
    let scores = cands
        .iter()
        .zip(&totals)
        .map(|(&fi, n)| format!("{}: {n}/{}", active.file(fi).name, probe.len()))
        .collect::<Vec<_>>()
        .join(", ");
    // Strictly the most matched blocks. A TIE can never be broken by the
    // distinguishing-block test either: a block the two declare alike is
    // matched for both or neither, so equal totals force equal
    // distinguishing counts, and the rival clause below would refuse it.
    let mut w = 0usize;
    for c in 1..totals.len() {
        if totals[c] > totals[w] {
            w = c;
        }
    }
    if totals[w] == 0 || totals.iter().filter(|&&n| n == totals[w]).count() > 1 {
        return (None, scores);
    }
    for c in 0..cands.len() {
        if c == w {
            continue;
        }
        let (mut for_w, mut for_c) = (0usize, 0usize);
        for (bi, hit) in &probe {
            if decls[w][*bi] == decls[c][*bi] {
                continue;
            }
            for_w += usize::from(hit[w]);
            for_c += usize::from(hit[c]);
        }
        // The winner having matched a distinguishing block is not a
        // second guard, it FOLLOWS from the strict maximum above: a
        // block the two declare alike is matched for both or neither,
        // so the winner's lead is entirely on distinguishing blocks.
        // Written as an assertion rather than as a test, because two
        // guards either of which is sufficient make both unfalsifiable.
        debug_assert!(for_w >= 1, "a strict lead with no distinguishing block");
        if for_c > 0 {
            return (None, scores);
        }
    }
    (Some(cands[w]), scores)
}

/// Read a strided sample of the slot's blocks and answer, per probed
/// block, which candidates declare the checksums its real bytes carry.
/// `(block index, one flag per candidate)`, in file order.
///
/// Strided rather than sequential for damage-clustering's sake - a
/// sequential probe of a file whose first articles failed reads nothing
/// but the damage - and bounded by both PROBES and BYTE_CAP, so one
/// damaged file the size of a disk image cannot turn this into an
/// unbounded read. A block that cannot be READ matches nobody, which is
/// the same answer damage gives and the right one: a hole in the file
/// is not evidence for any candidate.
///
/// `stop_early` is asked about each block's hit flags as they are
/// found, and a `true` ends the probe right there - the returned vec
/// still carries that last block's hits, so a caller answering "did
/// ANY block match" (`ifsc_evidence`'s single-candidate case) can pass
/// `|hit| hit[0]` and stop reading the moment its one bar is cleared.
/// [`ifsc_pairing`] needs the whole probe set to count distinguishing
/// blocks per rival, so it passes `|_| false` and never stops early.
pub(super) fn probe_blocks(
    src: &ReadAt<'_>,
    length: u64,
    bs: usize,
    nblocks: usize,
    decls: &[&[BlockCheck]],
    stop_early: impl Fn(&[bool]) -> bool,
) -> Vec<(usize, Vec<bool>)> {
    let f = match src {
        ReadAt::Path(p) => match std::fs::File::open(p) {
            Ok(f) => Some(f),
            Err(_) => return Vec::new(),
        },
        ReadAt::Reader(_) => None,
        ReadAt::Missing => return Vec::new(),
    };
    const PROBE_CHUNK: usize = 8 << 20;
    let mut buf = vec![0u8; bs.min(PROBE_CHUNK)];
    let step = nblocks.div_ceil(PROBES).max(1);
    let mut spent = 0u64;
    let mut out = Vec::new();
    let mut bi = 0usize;
    while bi < nblocks {
        let blen = block_len(length, bs, bi);
        if spent + blen as u64 > BYTE_CAP {
            break;
        }
        spent += blen as u64;
        let base = bi as u64 * bs as u64;
        let got = if bs <= PROBE_CHUNK {
            let read = match (src, &f) {
                (ReadAt::Path(_), Some(f)) => {
                    crate::disk::read_exact_at(f, &mut buf[..blen], base).is_ok()
                }
                (ReadAt::Reader(r), _) => r(base, &mut buf[..blen]).is_ok(),
                _ => false,
            };
            read.then(|| block_digest(bs, &buf[..blen]))
        } else {
            read_block_chunked(src, f.as_ref(), base, blen, &mut buf).map(|s| s.digest(bs))
        };
        if let Some(seen) = got {
            let hit: Vec<bool> = decls.iter().map(|d| d[bi] == seen).collect();
            let stop = stop_early(&hit);
            out.push((bi, hit));
            if stop {
                break;
            }
        }
        bi += step;
    }
    out
}
