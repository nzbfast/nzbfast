//! Boundary-block interval tracking - the two shapes a block that
//! straddles articles is held in, and the merged run list underneath
//! both.
//!
//! A sibling file rather than an inline module: live.rs sat at its
//! size-gate ceiling when this split was made (TODO 106; recalibrated
//! 31 Aug 2026), and one subject per file is how this
//! tree splits them. The subject here is narrow and self-contained -
//! nothing in it knows what a PAR2 set or a slot is.
//!
//! # Why the store is a hybrid, which is the only interesting thing here
//!
//! Both trackers keep a SORTED, MERGED, NON-OVERLAPPING run list and
//! merge one fragment into it per decoded span. Two properties are in
//! tension and the population is bimodal, so neither container wins
//! outright (all figures dev Mac, debug, min of 7, 31 Aug 2026):
//!
//!   * A sorted `Vec` is optimal for the REALISTIC case. A boundary
//!     block sees 1-10 fragments, and in-order arrival merges every one
//!     into the run before it, so the list stays at a single entry: 48
//!     heap bytes, and a whole 2-fragment `CrcParts` costs 116 ns. That
//!     is what [`CrcParts`]' own doc means by ~24 bytes per fragment,
//!     and it is the property that erased the partials RSS term (25.8 GB
//!     at 190 GB pre-cap) in default mode.
//!   * A sorted `Vec` is QUADRATIC on the hostile case, and this is
//!     X5-18. `Vec::insert` into the middle of it is an O(n) memmove per
//!     fragment however cheaply the two ends are found, so an arrival
//!     order that merges nothing until late - every other fragment, then
//!     the ones between - holds n/2 runs while the first half lands and
//!     moves half of them on each insert. One 1 MiB block, that order:
//!     0.22 / 2.3 / 36.0 / 660 / 1250 ms at 1,024 / 4,096 / 16,384 /
//!     65,536 fragments (the last two are the CRC arm), a per-doubling
//!     ratio marching to 4.0.
//!   * A `BTreeMap` is the mirror image. It is near-linear on the
//!     hostile case - 2.0-2.4x per doubling over that same sweep, and
//!     8.1 ms at 65,536 fragments where the Vec took 747 (release, one
//!     run, both arms measured together).
//!
//! **The hybrid is chosen on MEMORY, and it is worth being exact about
//! that, because the obvious speed argument does not survive being
//! measured in the build that ships.** A pure `BTreeMap` is 6.1x slower
//! on the 2-fragment common case in a DEBUG build (705 ns against 116) -
//! and in RELEASE it was not slower at all, measuring 51 ns against the
//! Vec's 61 in the same run, because what the debug figure is mostly
//! showing is generic code that has not been inlined. So speed does not
//! decide this. Memory does, and that measurement is exact rather than
//! timed (counting allocator, 31 Aug 2026, `usize -> (usize, u32)`):
//!
//! | live runs | `Vec` heap | `BTreeMap` heap | per run  |
//! |-----------|-----------:|----------------:|---------:|
//! | 1         |   48 B     |    280 B        | 5.8x     |
//! | 2         |   48 B     |    280 B        | 5.8x     |
//! | 32        |  768 B     |  1,496 B        | 1.9x     |
//! | 1,024     | 24,576 B   | 50,280 B        | 2.0x     |
//!
//! A tree is ~2x the Vec per run at EVERY size (nodes sit about half
//! full, so ~48 bytes a run against 24, not the ~25 a full eleven-slot
//! node would suggest) and 5.8x at the size that matters - because the
//! ordinary boundary block holds exactly ONE run, in-order arrival
//! having merged every fragment into the one before it. Paying 280 bytes
//! per live partial block to hold one run is the wrong trade on the
//! exact metric [`CrcParts`] exists for, and CRC partials are EXEMPT
//! from the global partials budget (`SlotState::partial_bytes` charges
//! byte partials only) precisely because they were cheap.
//!
//! So: `Vec` while short, `BTreeMap` past [`RUNS_TREE_AT`], one merge
//! algorithm over both. The common path keeps the container it was
//! measured on, in both senses, and the hostile path stops being
//! quadratic. Under the threshold a `Vec::insert` moves at most
//! [`RUNS_TREE_AT`] runs, which is a bounded constant and not an n.
//!
//! There is deliberately no DEMOTION back to `Vec`. A block whose run
//! list ever passed the threshold has already paid the node, the merges
//! that shrink it again are the ones that complete it, and a store that
//! could oscillate across the boundary would allocate on every crossing.
//!
//! `d5ad32c15`'s "the CRC arm was near-linear throughout" was inferred
//! from the single 4,096/8,192 pair its pin measures, and over a curve it
//! was false of BOTH arms: what that commit removed was the per-fragment
//! re-sort and its allocation - a large constant and a log factor - and
//! not the order. Corrected here, and in the wave-4 residue write-up the
//! row was raised from.

use std::collections::BTreeMap;

/// Run count at which a [`Runs`] store moves from a sorted `Vec` to a
/// `BTreeMap`, chosen from the measurement in this module's header.
///
/// It wants to sit ABOVE the whole realistic population (1-10 runs, and
/// in-order arrival never leaves more than one) and BELOW the count at
/// which the Vec's memmove starts to dominate. Both sides have room: at
/// 32 runs a Vec insert moves at most 32 entries - 768 bytes for the CRC
/// store, a single cache-line-ish memmove - while the measured crossover
/// where the tree overtakes the Vec outright is up in the thousands. It
/// is therefore not a tuning knob with a sharp optimum, and the tests
/// drive counts on both sides of it rather than pinning the number.
pub(super) const RUNS_TREE_AT: usize = 32;

/// A sorted, non-overlapping list of runs keyed by START, values carrying
/// whatever the tracker needs to know about `start..end`.
///
/// The operations below are all either tracker asks of it, and they are
/// exactly the ones a sorted `Vec` and a `BTreeMap` can both answer at
/// the same cost class - which is what lets ONE merge algorithm sit over
/// both. Writing the merge twice, once per container, is the shape this
/// module exists to avoid: this tree has lost days to hand-copied
/// siblings that then drifted, and CLAUDE.md's gate list is largely a
/// monument to it.
enum Runs<V> {
    Few(Vec<(usize, V)>),
    Many(BTreeMap<usize, V>),
}

impl<V: Copy> Runs<V> {
    fn new() -> Runs<V> {
        Runs::Few(Vec::with_capacity(2))
    }

    fn len(&self) -> usize {
        match self {
            Runs::Few(v) => v.len(),
            Runs::Many(m) => m.len(),
        }
    }

    /// The lowest-starting run, if any.
    fn first(&self) -> Option<(usize, V)> {
        match self {
            Runs::Few(v) => v.first().copied(),
            Runs::Many(m) => m.iter().next().map(|(&k, &v)| (k, v)),
        }
    }

    /// The greatest run starting STRICTLY BEFORE `k`.
    fn before(&self, k: usize) -> Option<(usize, V)> {
        match self {
            Runs::Few(v) => {
                let i = v.partition_point(|&(s, _)| s < k);
                (i > 0).then(|| v[i - 1])
            }
            Runs::Many(m) => m.range(..k).next_back().map(|(&s, &v)| (s, v)),
        }
    }

    /// The least run starting AT OR AFTER `k`.
    fn at_or_after(&self, k: usize) -> Option<(usize, V)> {
        match self {
            Runs::Few(v) => v.get(v.partition_point(|&(s, _)| s < k)).copied(),
            Runs::Many(m) => m.range(k..).next().map(|(&s, &v)| (s, v)),
        }
    }

    fn remove(&mut self, k: usize) {
        match self {
            Runs::Few(v) => {
                if let Ok(i) = v.binary_search_by_key(&k, |&(s, _)| s) {
                    v.remove(i);
                }
            }
            Runs::Many(m) => {
                m.remove(&k);
            }
        }
    }

    /// Insert or replace the run starting at `k`, promoting the store to
    /// a tree once it outgrows [`RUNS_TREE_AT`].
    fn insert(&mut self, k: usize, val: V) {
        match self {
            Runs::Few(v) => {
                match v.binary_search_by_key(&k, |&(s, _)| s) {
                    Ok(i) => v[i] = (k, val),
                    Err(i) => v.insert(i, (k, val)),
                }
                if v.len() > RUNS_TREE_AT {
                    *self = Runs::Many(v.drain(..).collect());
                }
            }
            Runs::Many(m) => {
                m.insert(k, val);
            }
        }
    }

    /// Keep the runs `f` answers true for, having let it edit the value.
    /// Never promotes: dropping runs cannot grow the store.
    fn retain(&mut self, mut f: impl FnMut(usize, &mut V) -> bool) {
        match self {
            Runs::Few(v) => v.retain_mut(|(s, val)| f(*s, val)),
            Runs::Many(m) => m.retain(|&s, val| f(s, val)),
        }
    }

    /// Is this store the TREE half of the hybrid? Test-only, and the
    /// only thing that can say a differential run actually crossed
    /// [`RUNS_TREE_AT`] rather than exercising the `Vec` twice - which
    /// would be a green oracle over an untested representation.
    #[cfg(test)]
    fn is_tree(&self) -> bool {
        matches!(self, Runs::Many(_))
    }

    /// The runs in start order. Test-only, and a VIEW rather than the
    /// representation on purpose: it is what the differential oracles in
    /// `live/tests.rs` compare, so changing the store again cannot
    /// quietly change what they are comparing.
    #[cfg(test)]
    fn in_order(&self) -> Vec<(usize, V)> {
        match self {
            Runs::Few(v) => v.clone(),
            Runs::Many(m) => m.iter().map(|(&k, &v)| (k, v)).collect(),
        }
    }
}

/// A boundary block accumulating BYTES from more than one article - the
/// full-MD5 mode, where the digest cannot be composed so the bytes have
/// to be kept. Also how a slot captures its first 16 KiB, which fills
/// interval-wise for the same reason: articles arrive out of order.
pub(super) struct Partial {
    /// Real bytes of this block (final block may be shorter than block_size).
    pub(super) buf: Vec<u8>,
    /// Filled intervals within `buf`: start -> end, merged.
    filled: Runs<usize>,
}

impl Partial {
    pub(super) fn new(len: usize) -> Partial {
        Partial {
            buf: vec![0; len],
            filled: Runs::new(),
        }
    }

    pub(super) fn fill(&mut self, at: usize, bytes: &[u8]) {
        self.buf[at..at + bytes.len()].copy_from_slice(bytes);
        let (s, mut e) = (at, at + bytes.len());
        // Absorb every run this fragment touches, then insert the one run
        // they became. `filled` is merged, so the runs a fragment touches
        // are CONTIGUOUS in key order: at most one predecessor (the
        // greatest start at or below `s`), then successors from the left
        // while their start is still within `e`.
        //
        // The merge condition is the one this has always had - a run is
        // absorbed when `fe >= s && fs <= e` - so TOUCHING runs merge as
        // well as overlapping ones, which is what lets `complete()`
        // recognise a filled block as the single run `0 -> len`. The
        // predecessor arm is that condition with `fs <= s <= e` already
        // known, and the loop arm is it with `fe >= s` already known.
        while let Some((ns, ne)) = self.filled.at_or_after(s) {
            if ns > e {
                break;
            }
            e = e.max(ne);
            self.filled.remove(ns);
        }
        if let Some((ps, pe)) = self.filled.before(s)
            && pe >= s
        {
            // Grow the predecessor IN PLACE. This is the in-order arrival
            // path - one run, each fragment extending it - and it must stay
            // free of any structural move, or the ordinary case pays for the
            // hostile one. It is also why the successors are absorbed FIRST:
            // `e` has to be final before the run that will carry it is
            // written.
            self.filled.insert(ps, e.max(pe));
            return;
        }
        self.filled.insert(s, e);
    }

    pub(super) fn complete(&self) -> bool {
        // Exactly the sorted `Vec`'s `filled == [(0, len)]`, with no
        // length check beside it, and that is a deletion rather than an
        // omission. `fill` indexes `buf` before it records anything, so
        // every run is inside `0..buf.len()`, and overlapping runs MERGE -
        // so a run reaching `buf.len()` from 0 leaves nothing a second run
        // could be. A `self.filled.len() == 1` conjunct would therefore be
        // a guard no test could ever falsify, which is the shape CLAUDE.md's
        // forty-sixth gate records as making BOTH guards unfalsifiable.
        // `CrcParts::complete` keeps its length check because there the
        // bound is the CALLER's (`oe` is clipped to the block end one file
        // over), and it is pinned.
        self.filled.first() == Some((0, self.buf.len()))
    }

    /// Clip to the first `want` bytes - what a head capture does when a
    /// later article's declared `size=` shrinks the window (M4-94).
    /// Clipping a merged run list to a prefix keeps it merged, so
    /// `complete()` still recognises a filled head as the single run.
    pub(super) fn truncate(&mut self, want: usize) {
        self.buf.truncate(want);
        self.filled.retain(|s, e| {
            *e = (*e).min(want);
            s < want
        });
    }

    /// The merged intervals in start order - see [`Runs::in_order`].
    #[cfg(test)]
    pub(super) fn intervals(&self) -> Vec<(usize, usize)> {
        self.filled.in_order()
    }

    /// Has this partial's store crossed [`RUNS_TREE_AT`]? See
    /// [`Runs::is_tree`].
    #[cfg(test)]
    pub(super) fn uses_tree(&self) -> bool {
        self.filled.is_tree()
    }
}

/// B1: a boundary block held as per-fragment CRC32s instead of bytes.
/// CRC32 composes over concatenation (`crc32_combine`), so fragments can
/// arrive in any order and merge whenever neighbors touch - ~24 bytes per
/// fragment against a block-sized buffer. Only valid when the block will
/// be claimed on CRC alone (fast/lean verify - the default); full-MD5
/// mode keeps byte buffers because MD5 cannot be composed.
///
/// This erases the partials RSS term entirely in default mode - the term
/// that grew linearly on big jobs (25.8 GB at 190 GB pre-cap) and that at
/// the 256 MB MemBudget floor forced constant spill → settle read-back on
/// exactly the boxes with the slowest disks. When the PAR2 block size
/// exceeds the article size, EVERY block straddles articles and the old
/// buffers approached a full copy of the in-flight file. That is the
/// property [`RUNS_TREE_AT`] exists to protect, and this module's header
/// says what it costs and where.
pub(super) struct CrcParts {
    /// Maps start -> (end, crc32 of `start..end`). Non-overlapping, with
    /// adjacent entries eagerly merged, so no two runs touch.
    parts: Runs<(usize, u32)>,
}

impl CrcParts {
    pub(super) fn new() -> CrcParts {
        CrcParts { parts: Runs::new() }
    }

    /// Merge a fragment. Returns false on overlap with an existing part -
    /// impossible for decoder-fresh spans (each article is fed once), so
    /// the caller treats it as "this block can't be tracked losslessly"
    /// and abandons the block to settle read-back.
    pub(super) fn insert(&mut self, s: usize, e: usize, crc: u32) -> bool {
        // A degenerate span is refused rather than stored. Unreachable for
        // a decoded span (`os < oe` by construction) and the safe answer
        // either way: an empty run keyed on a start some real run already
        // owns REPLACES it in a tree store, where the sorted Vec this grew
        // out of merely held two entries under one key and then composed a
        // wrong CRC over them.
        if s >= e {
            return false;
        }
        // ONE lookup per side, shared between the refusal and the merge,
        // because they ask about the same two neighbors: a predecessor
        // ENDING past `s` overlaps and one ending exactly AT `s` merges,
        // and once the successor is known not to start before `e`, the
        // successor IS the right-merge candidate (nothing can start
        // between `s` and it). Both are copies, so the right merge's
        // removal cannot stale the predecessor - it is a different key.
        let pred = self.parts.before(s);
        let succ = self.parts.at_or_after(s);
        if let Some((_, (pe, _))) = pred
            && pe > s
        {
            return false;
        }
        if let Some((ns, _)) = succ
            && ns < e
        {
            return false;
        }
        let (mut e, mut crc) = (e, crc);
        // Merge with the right neighbor, then the left. The ORDER is fixed
        // by the arithmetic: `crc32_combine(a, b, len_of_b)` appends b, so
        // the left part's crc has to LEAD and must therefore be combined
        // last, over the length the right merge may just have grown.
        if let Some((ns, (ne, nc))) = succ
            && ns == e
        {
            crc = crate::yenc_simd::crc32_combine(crc, nc, (ne - e) as u64);
            e = ne;
            self.parts.remove(ns);
        }
        if let Some((ps, (pe, pc))) = pred
            && pe == s
        {
            // Grow the predecessor IN PLACE - the in-order arrival path, and
            // the reason the right neighbor is taken first: `e` and `crc`
            // have to be final before the run that carries them is written.
            let joined = crate::yenc_simd::crc32_combine(pc, crc, (e - s) as u64);
            self.parts.insert(ps, (e, joined));
            return true;
        }
        self.parts.insert(s, (e, crc));
        true
    }

    /// CRC of the whole block's real bytes once every fragment landed.
    pub(super) fn complete(&self, blen: usize) -> Option<u32> {
        // The length check is a BELT and is pinned as one. Nothing here
        // bounds a run to the block: `insert` takes whatever offsets it is
        // given, and it is the caller that clips (`oe = span.end.min(bend)`
        // in `on_data_inner`). A run past `blen` beside a full `0..blen`
        // would otherwise compose the block's CRC out of a store that is
        // holding bytes the block does not own, and the sorted `Vec` this
        // replaced refused exactly that by matching a ONE-element slice.
        match self.parts.first() {
            Some((0, (e, crc))) if e == blen && self.parts.len() == 1 => Some(crc),
            _ => None,
        }
    }

    /// The merged parts in start order - see [`Runs::in_order`].
    #[cfg(test)]
    pub(super) fn parts_in_order(&self) -> Vec<(usize, usize, u32)> {
        self.parts
            .in_order()
            .into_iter()
            .map(|(s, (e, c))| (s, e, c))
            .collect()
    }

    /// Has this block's store crossed [`RUNS_TREE_AT`]? See
    /// [`Runs::is_tree`].
    #[cfg(test)]
    pub(super) fn uses_tree(&self) -> bool {
        self.parts.is_tree()
    }
}

/// A boundary block in flight: bytes (full-MD5 mode) or fragment CRCs
/// (fast/lean mode).
pub(super) enum PartialBuf {
    Bytes(Partial),
    Crc(CrcParts),
}
