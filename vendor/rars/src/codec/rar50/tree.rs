//! A binary-tree match finder for the RAR 5 writer (nzbfast-local change,
//! 7 Sep 2026; see VENDORING.md).
//!
//! The ring index in `codec::rar50` keeps the newest `depth` positions of
//! every four-byte hash bucket, so on dense buckets - "the " on a megabyte
//! of English, a record separator on fixed-width rows - its reach is the
//! last few hundred kilobytes, whatever the dictionary says. Measured over
//! the first 256 MiB of the mixed corpus at a 32 MiB dictionary (the
//! ratio round of 6 Sep 2026): rar 7.23
//! finds 2.2 M matches eight or more MiB back and copies 30 MB with them,
//! where the ring finds 60 K and copies 1.2 MB. Eight denser or wider
//! long-table variants were measured that day and none was worth 0.5%,
//! because a newest-wins table hands back the NEAR occurrence of a span
//! and the near occurrence is the one whose match is short.
//!
//! This is the structural answer, and it is 7-Zip's `bt4` (`GetMatchesSpec1`
//! in LzFind.c) and zstd's `ZSTD_insertBt1`: a binary search tree per hash
//! bucket, ordered by the suffix at each position. Every position is both
//! INSERTED into and SEARCHED in its bucket's tree by one descent, which
//! splits the tree into the positions whose suffix sorts below the current
//! one and those above; the longest match in the bucket is found in
//! O(log n) descents however dense the bucket is, and the nodes visited on
//! the way are the ones whose suffixes agree with the current position for
//! the most bytes - not merely the newest.
//!
//! ## What makes the result a function of the POSITION alone
//!
//! The encoder's blocks must compress the same bytes to the same output
//! whatever the machine's thread count and whichever writer drives them
//! (the in-memory pool, the streamed writer's windows), so a match finder
//! whose answers depend on the schedule is not usable here however good
//! its ratio. Two properties keep this one deterministic:
//!
//! - Positions enter their bucket's tree in increasing order, and the
//!   answer at `pos` is computed against a tree holding exactly the
//!   positions below `pos` in that bucket. Which THREAD did the work does
//!   not enter into it, and neither does how far ahead of the tokenizer
//!   the finder ran.
//! - A node's descendants are always OLDER than it is (a new position is
//!   spliced in at the root of its bucket), so cutting a branch at a
//!   position that has fallen out of the window drops only positions that
//!   are themselves out of the window. The live tree is therefore a
//!   function of the live positions' insertion order alone, and a finder
//!   that started `window` bytes before a block holds the same live tree
//!   there as one that has been running since the start of the member.
//!   That is what lets the streamed writer's windows produce the whole
//!   member's bytes: [`TreeMatchFinder::advance_range`] seeds a window's
//!   history exactly as the whole-member walk reached it.
//!
//! ## What it stores, and what it hands back
//!
//! Two `u32` per position of the window (the tree) plus a head per hash
//! bucket - 320 MiB at a 32 MiB dictionary, which is the shape rar's own
//! 305 MB of RSS at `-md32m` has. Per position it hands back ONE distance:
//! the one whose match was longest, capped at [`TREE_NICE_LENGTH`] as
//! LZMA caps its own comparisons at `numFastBytes`. The caller recomputes
//! the true length from the distance and prices it with everything else it
//! probes, so a 4,096-byte repeat found here as a 256-byte one is emitted
//! whole; and the ring stays alongside for the near matches whose distance
//! is cheap, which this finder does not rank. The cap decides only WHICH
//! position is handed back when several agree that far, and that choice
//! is worth bytes - see the constant, which also records why the depth
//! cannot be split from the anti-degeneracy exit it shares.

use std::ops::Range;
use std::sync::atomic::{AtomicU32, Ordering};

/// Comparisons stop here, as LZMA's stop at `numFastBytes`: the caller
/// recomputes the real length from the distance, so the only thing a
/// deeper comparison buys is a different ORDER among candidates that
/// already agree for this many bytes. That order is worth real bytes
/// where the content has long near-identical records: through the
/// production writer at `-m3 -mo -md33554432` the twelve Silesia files
/// total 52,781,726 bytes at 64 and 52,584,521 at 256 (-0.374%, no file
/// larger), `nci` alone 1,889,776 against 1,719,988 (-8.99%) and `xml`
/// 477,508 against 469,878 (-1.60%). Swept in the lab, `nci` is
/// 1,889,785 at 64, 1,752,618 at 128 and 1,720,004 at 256, so most but
/// not all of it is there by 128. The synthetic corpora and the poster's
/// own 400-file set are SHA256 identical at every cap, solid and not -
/// the shapes we benchmark on could not have found this, and would not
/// have caught a regression in it either.
///
/// ## Why the depth cannot be split away from the anti-degeneracy exit
///
/// The cap does a second job: on reaching it a position takes the
/// candidate's place in the tree wholesale and the descent STOPS, which
/// keeps a long run of identical bytes from turning a bucket into a
/// list. It is tempting to keep that exit shallow and let the comparison
/// run deeper for ranking only, so a repetitive payload keeps the cheap
/// exit. It does not work, because the exit IS the ranking decision:
/// ending the descent is what discards the candidates a deeper
/// comparison was meant to rank. Measured 7 Sep 2026 on `nci` with the
/// two depths split, comparing to 256 and replacing at 64: 1,889,785
/// bytes, the 64-byte figure to the byte, for more CPU than either flat
/// cap. Measured again after the parse's candidate list landed, on a
/// rebuilt binary: the same three figures. Do not re-derive this.
///
/// What the depth costs is therefore the comparison itself, and that is
/// answered in [`common_prefix`] rather than by a shallower cap: a word
/// at a time, 256 is cheaper than 64 was byte at a time. Paired on an
/// idle box over a 256 MiB slice of the repeated corpus, all arms
/// writing the same 1,058,474 bytes: 28.50 s at 64 and 57.39 s at 256
/// comparing byte at a time, against 26.41 s at 256 comparing a word at
/// a time. On `nci`, 15.40 s at 64 byte-wise against 13.75 s at 256
/// word-wise - deeper, smaller and faster at once, because taking a
/// longer match advances the parse further. Through the production
/// writer the twelve Silesia files go 100.41 to 93.29 user seconds and
/// every other shape is cheaper too, the solid 400-file set included.
/// Record: research/TREE-NICE-LENGTH-2026-09-07.md.
pub(super) const TREE_NICE_LENGTH: usize = 256;

/// How many nodes one descent may visit (7-Zip's `cutValue`). A dense
/// bucket is exactly what the tree is for, so this is generous; it is a
/// guard against pathological input, not the shape of the search.
const TREE_CUT_VALUE: u32 = 64;

/// Hash heads per byte of window, rounded to a power of two: half a head
/// per position, which is what LZMA's `hashSize` works out to for a bt4.
const TREE_HEADS_PER_WINDOW: usize = 2;

/// The tree never reaches farther back than this, whatever the dictionary
/// says: the structure is eight bytes per byte of window (two `u32` per
/// position), so a 64 MiB window is 512 MiB of tree and a dictionary past
/// that keeps its ring and long-table reach beyond this horizon rather
/// than growing the tree to match.
pub(super) const TREE_MAX_WINDOW: usize = 64 << 20;

/// The multiplier the ring index hashes with; the tree keeps the HIGH bits
/// of the same product, so a bucket here is not a bucket there.
const TREE_HASH_MULTIPLIER: u32 = 0x9E37_79B1;

/// No distance: an empty result slot, and an empty tree slot (slots hold
/// `position + 1`).
pub(super) const TREE_NO_MATCH: u32 = 0;

/// The most candidates one position's result may hold, and so the widest
/// stride a caller may ask for (nzbfast-local change, 7 Sep 2026).
pub(super) const TREE_MAX_CANDIDATE_SLOTS: usize = 8;

/// How many candidates the cost-based parse asks for at each position.
///
/// The descent already visits exactly the pairs a `bt4` yields (strictly
/// increasing length, and for each length the NEAREST distance reaching
/// it), because a node's descendants are older than it is, so the subtree
/// a step discards holds only positions that are both farther away and
/// agree for no more bytes. Keeping the whole list is what the parse
/// wants and the list is short; the bound is here because the result
/// costs four bytes per slot per position of the wave in flight.
///
/// When a descent records more pairs than this, the ones kept are the
/// first `TREE_CANDIDATE_SLOTS - 1` (the nearest, whose distance bits are
/// cheapest) and the LAST (the longest), which is what the parse prices
/// at the two ends. Swept on the 256 MiB mixed slice at `-md32m`; see the
/// table in the handoff.
pub(super) const TREE_CANDIDATE_SLOTS: usize = 4;

/// How far apart two walkers' positions may drift, and so how much of the
/// cyclic buffer is held back from the window.
///
/// The buffer gives position `p` the slot `p & mask`, so `p` and
/// `p + cyclic` share one. Serially that is safe: by the time
/// `p + cyclic` is inserted, `p` is farther back than the window, and a
/// descent that meets a position outside the window stops there WITHOUT
/// reading its slots. In parallel the walkers stand at different
/// positions, so one running ahead could overwrite the slots of a
/// position another walker still counts as live - and then the answers
/// would depend on the timing, which is the one thing they may not do.
/// So the walkers are barriered every `TREE_SKEW_BOUND` positions and the
/// window is held that far below the buffer: an overwriting position is
/// at least `cyclic - window` ahead of every walker, which the barrier
/// forbids. The comparison limit is passed separately from the chunk, so
/// the chunking changes no answer - it is scheduling and nothing else.
const TREE_SKEW_BOUND: usize = 1 << 18;

/// How far the suffixes at `candidate` and `pos` agree, resuming the
/// comparison at `start` bytes - which both ends of the descent's split
/// already agree on - and stopping at `limit`.
///
/// Eight bytes at a time, because this loop IS the descent's cost: at the
/// wholesale-replacement exit a position compares the full cap before it
/// stops, so a payload of one buffer replayed pays the cap on every
/// position for matches the parse takes through repeat distances anyway.
/// Byte-at-a-time that made the cap's depth the dominant term; a word at
/// a time makes a 256-byte cap cheaper than the 64-byte one was, which is
/// what pays for the depth [`TREE_NICE_LENGTH`] now has.
///
/// The answer is the byte-at-a-time answer: `from_le_bytes` puts array
/// byte `i` at bit `8 * i` on either endianness, so the first differing
/// byte is `trailing_zeros() / 8` wherever this runs.
#[inline]
fn common_prefix(span: &[u8], candidate: usize, pos: usize, start: usize, limit: usize) -> usize {
    let mut length = start;
    // `limit` never reaches past the span (it is capped at `limit - pos`
    // by the caller, and `candidate` is below `pos`), so a whole word at
    // `length` is in bounds whenever `length + 8` is within it.
    while length + 8 <= limit {
        let left = u64::from_le_bytes(span[candidate + length..][..8].try_into().unwrap());
        let right = u64::from_le_bytes(span[pos + length..][..8].try_into().unwrap());
        let difference = left ^ right;
        if difference != 0 {
            return length + (difference.trailing_zeros() >> 3) as usize;
        }
        length += 8;
    }
    while length != limit && span[candidate + length] == span[pos + length] {
        length += 1;
    }
    length
}

/// `count` empty slots. `AtomicU32` is not `Clone`, so `vec!` cannot.
pub(super) fn empty_slots(count: usize) -> Vec<AtomicU32> {
    let mut slots = Vec::new();
    slots.resize_with(count, || AtomicU32::new(TREE_NO_MATCH));
    slots
}

/// A binary tree per four-byte hash bucket over a sliding window of the
/// member's span, walked once per position.
///
/// ## Why the slots are atomic, and why that is not a lock
///
/// The walk is parallel BY BUCKET ([`TreeMatchFinder::advance_range`]):
/// bucket trees are independent, so a thread that owns a set of buckets
/// walks their positions in increasing order and never touches another
/// thread's nodes. Every node a descent reads belongs to the bucket it is
/// descending, so the answers are exactly the serial walk's, at any
/// thread count.
///
/// The one place two threads touch the same slot is the cyclic buffer's
/// own wrap: positions `p` and `p + cyclic` share a slot pair, and one of
/// them is always outside the window - a descent that meets a node
/// farther back than the window stops at it WITHOUT reading its slots, so
/// the stale half is never read. `Relaxed` is therefore the whole of the
/// ordering this needs (and compiles to a plain load and store); the
/// atomics are here to make that sharing well defined rather than to
/// synchronise anything.
pub(super) struct TreeMatchFinder {
    /// Two entries per window slot: the subtree of positions whose suffix
    /// sorts BELOW this one, and the subtree of those above. Both hold
    /// `position + 1`; zero is empty.
    son: Vec<AtomicU32>,
    /// The newest position of each hash bucket, `position + 1`.
    head: Vec<AtomicU32>,
    /// `position & cyclic_mask` is a position's slot pair in `son`.
    cyclic_mask: usize,
    /// The largest distance a candidate may be at: one less than the
    /// cyclic size, so two live positions never share a slot.
    window: usize,
    head_shift: u32,
    #[cfg(any(test, feature = "ratio-lab"))]
    sample_mask: u32,
    #[cfg(feature = "ratio-lab")]
    chain_depth: u32,
    #[cfg(feature = "ratio-lab")]
    hash8: bool,
    #[cfg(feature = "ratio-lab")]
    hash8_slots: usize,
    #[cfg(feature = "ratio-lab")]
    multi_hash: bool,
    #[cfg(feature = "ratio-lab")]
    multi_hash_short: bool,
    /// How many nodes one descent may visit.
    cut: u32,
    #[cfg(feature = "ratio-lab")]
    nice_length: usize,
    /// One position list per walker, refilled per chunk and kept between
    /// chunks so the walk allocates nothing. Only `advance_range`'s
    /// `parallel`-gated arm and `share_chunk` touch this.
    #[cfg(feature = "parallel")]
    shares: Vec<Vec<u32>>,
    /// The next position the finder expects; positions are presented in
    /// increasing order and every one of them is inserted.
    next: usize,
}

impl TreeMatchFinder {
    /// A finder over a window of `max_distance` bytes, capped at
    /// [`TREE_MAX_WINDOW`]. The window is rounded UP to a power of two and
    /// one position is kept back from it so no two live positions share a
    /// slot, which costs the single farthest distance of a power-of-two
    /// dictionary (33,554,431 rather than 33,554,432 at `-md32m`) and
    /// nothing at all otherwise.
    ///
    /// The size depends on the DICTIONARY alone and never on the span,
    /// because a window's answers must be the whole member's answers and a
    /// window is shorter than its member.
    pub(super) fn new(max_distance: usize) -> Self {
        // min-then-max rather than `clamp`: `clamp` PANICS when the
        // ceiling is below the floor, and these are two independent
        // constants. Saturating to the floor is the wanted behaviour if
        // they are ever set that way; a panic in a decoder is not.
        #[allow(clippy::manual_clamp)]
        let cyclic = max_distance
            .min(TREE_MAX_WINDOW)
            .max(4 * TREE_SKEW_BOUND)
            .next_power_of_two();
        let heads = (cyclic / TREE_HEADS_PER_WINDOW)
            .max(1 << 10)
            .next_power_of_two();
        #[cfg(feature = "ratio-lab")]
        let chain_depth = std::env::var("RARS_TREE_CHAIN_DEPTH")
            .map(|s| s.parse::<u32>().expect("RARS_TREE_CHAIN_DEPTH is 0..256"))
            .unwrap_or(0);
        #[cfg(feature = "ratio-lab")]
        assert!(chain_depth <= 256);
        #[cfg(feature = "ratio-lab")]
        let hash8 = std::env::var("RARS_TREE_HASH8")
            .map(|s| {
                assert_eq!(s, "1", "RARS_TREE_HASH8 is unset or 1");
                true
            })
            .unwrap_or(false);
        #[cfg(feature = "ratio-lab")]
        let hash8_slots = std::env::var("RARS_TREE_HASH8_SLOTS")
            .map(|s| {
                s.parse::<usize>()
                    .expect("RARS_TREE_HASH8_SLOTS is 1, 2, 4 or 8")
            })
            .unwrap_or(1);
        #[cfg(feature = "ratio-lab")]
        assert!(matches!(hash8_slots, 1 | 2 | 4 | 8));
        #[cfg(feature = "ratio-lab")]
        assert!(
            hash8 || hash8_slots == 1,
            "hash8 history requires RARS_TREE_HASH8=1"
        );
        // Keep total head storage fixed: more history per bucket uses
        // fewer buckets. All slots in a bucket still have one walker.
        #[cfg(feature = "ratio-lab")]
        let heads = if hash8 { heads / hash8_slots } else { heads };
        #[cfg(feature = "ratio-lab")]
        let (multi_hash, multi_hash_short) = std::env::var("RARS_TREE_MULTI_HASH")
            .map(|s| {
                assert!(
                    matches!(s.as_str(), "1" | "4,8,16" | "8,16"),
                    "RARS_TREE_MULTI_HASH is unset, 1, 4,8,16 or 8,16"
                );
                (true, s == "8,16")
            })
            .unwrap_or((false, false));
        #[cfg(feature = "ratio-lab")]
        assert!(
            usize::from(hash8) + usize::from(multi_hash) + usize::from(chain_depth != 0) <= 1,
            "select one research finder"
        );
        #[cfg(feature = "ratio-lab")]
        let slots_per_position = if hash8 || multi_hash {
            0
        } else if chain_depth == 0 {
            2
        } else {
            1
        };
        #[cfg(not(feature = "ratio-lab"))]
        let slots_per_position = 2;
        Self {
            son: empty_slots(slots_per_position * cyclic),
            #[cfg(feature = "ratio-lab")]
            chain_depth,
            #[cfg(feature = "ratio-lab")]
            hash8,
            #[cfg(feature = "ratio-lab")]
            hash8_slots,
            #[cfg(feature = "ratio-lab")]
            multi_hash,
            #[cfg(feature = "ratio-lab")]
            multi_hash_short,
            head: {
                #[cfg(feature = "ratio-lab")]
                let heads = heads
                    * if hash8 {
                        hash8_slots
                    } else if multi_hash {
                        if multi_hash_short { 2 } else { 3 }
                    } else {
                        1
                    };
                empty_slots(heads)
            },
            cyclic_mask: cyclic - 1,
            window: max_distance.min(cyclic - 1 - TREE_SKEW_BOUND),
            head_shift: 32 - heads.trailing_zeros(),
            #[cfg(any(test, feature = "ratio-lab"))]
            sample_mask: {
                #[cfg(feature = "ratio-lab")]
                let stride = std::env::var("RARS_TREE_SAMPLE_STRIDE")
                    .map(|s| {
                        s.parse::<u32>()
                            .expect("RARS_TREE_SAMPLE_STRIDE is 1, 2, 4 or 8")
                    })
                    .unwrap_or(1);
                #[cfg(not(feature = "ratio-lab"))]
                let stride = 1u32;
                assert!(matches!(stride, 1 | 2 | 4 | 8));
                stride - 1
            },
            cut: {
                #[cfg(feature = "ratio-lab")]
                let cut = std::env::var("RARS_TREE_CUT")
                    .map(|s| s.parse::<u32>().expect("RARS_TREE_CUT is 1..256"))
                    .unwrap_or(TREE_CUT_VALUE);
                #[cfg(not(feature = "ratio-lab"))]
                let cut = TREE_CUT_VALUE;
                assert!((1..=256).contains(&cut));
                cut
            },
            #[cfg(feature = "ratio-lab")]
            nice_length: TREE_NICE_LENGTH,
            #[cfg(feature = "parallel")]
            shares: Vec::new(),
            next: 0,
        }
    }

    /// Research-only comparison cap. Production keeps [`TREE_NICE_LENGTH`].
    #[cfg(feature = "ratio-lab")]
    pub(super) fn with_nice_length(mut self, bytes: usize) -> Self {
        assert!((4..=256).contains(&bytes));
        self.nice_length = bytes;
        self
    }

    /// A finder whose descents may visit `cut` nodes. The default is
    /// [`TREE_CUT_VALUE`]; the exactness test raises it to check the
    /// tree's own answer rather than the guard's.
    #[cfg(test)]
    fn with_cut(mut self, cut: u32) -> Self {
        self.cut = cut;
        self
    }

    /// Start the next walk at `pos`, the positions before it absent from
    /// the tree: a window's history begins where the caller says, not at
    /// the start of the span it is a window onto.
    pub(super) fn skip_to(&mut self, pos: usize) {
        debug_assert_eq!(self.next, 0);
        self.next = pos;
    }

    /// Whether a span's positions and this finder's slots fit the `u32`
    /// the tree stores. A span at or past `u32::MAX` positions takes the
    /// ring alone.
    pub(super) fn fits(span_len: usize) -> bool {
        u32::try_from(span_len).is_ok_and(|len| len != u32::MAX)
    }

    /// The window this finder reaches over: a candidate farther back than
    /// this is pruned, and the caller's own distance limit should not
    /// exceed it.
    pub(super) fn window(&self) -> usize {
        self.window
    }

    /// Walk `range` of `span`, inserting every position and writing the
    /// best distance found at it into `out[pos - range.start]` (zero where
    /// there is none). `out` is `range.len()` long, and `range.start` must
    /// be where the previous call left off. Passing `None` for `out`
    /// inserts without recording, which is how a window's history reaches
    /// the tree.
    ///
    /// COMPARISONS STOP AT `range.end`, and the caller's ranges are
    /// therefore part of the answer: a tokenizer whose matches may not
    /// reach past a block boundary hands the finder one range per block,
    /// so the tree ranks candidates by exactly the prefix the encoder can
    /// emit - and a window of a member, splitting on the same boundaries,
    /// builds the same tree the whole-member walk builds. The cost is the
    /// last three positions of every range, which have no four bytes
    /// within it and are not indexed.
    ///
    /// `threads` walkers split the range BY BUCKET, each taking the
    /// positions whose bucket is its own, in order. The answers do not
    /// depend on how many there are: see the note on the struct.
    pub(super) fn advance_range(
        &mut self,
        span: &[u8],
        range: Range<usize>,
        out: Option<&[AtomicU32]>,
        stride: usize,
        threads: usize,
    ) {
        debug_assert_eq!(self.next, range.start);
        debug_assert!((1..=TREE_MAX_CANDIDATE_SLOTS).contains(&stride));
        debug_assert!(out.is_none_or(|out| out.len() == range.len() * stride));
        self.next = range.end;
        let threads = threads.max(1);
        let limit = range.end;
        let base = range.start;
        if threads == 1 {
            self.walk_range(span, range, limit, base, out, stride);
            return;
        }
        #[cfg(feature = "parallel")]
        {
            self.shares.resize_with(threads, Vec::new);
            let mut at = range.start;
            while at < range.end {
                let chunk = at..(at + TREE_SKEW_BOUND).min(range.end);
                self.share_chunk(span, chunk.clone(), threads);
                let finder = &*self;
                rayon::in_place_scope(|scope| {
                    for share in &finder.shares {
                        scope.spawn(move |_| finder.walk(span, share, limit, base, out, stride));
                    }
                });
                at = chunk.end;
            }
        }
        #[cfg(not(feature = "parallel"))]
        self.walk_range(span, range, limit, base, out, stride);
    }

    /// Deal a chunk's positions out to the walkers, each keeping the ones
    /// whose bucket is its own, in order. One pass over the chunk's bytes
    /// deals every walker's share: the first cut had each walker scan the
    /// whole chunk and skip what was not its own, which is the same hash
    /// computed once per walker and measured 234 user seconds against the
    /// serial walk's 103 on the 256 MiB slice.
    #[cfg(feature = "parallel")]
    fn share_chunk(&mut self, span: &[u8], chunk: Range<usize>, threads: usize) {
        for share in &mut self.shares {
            share.clear();
        }
        let head_shift = self.head_shift;
        #[cfg(feature = "ratio-lab")]
        let tail = if self.hash8 { 7 } else { 3 };
        #[cfg(not(feature = "ratio-lab"))]
        let tail = 3;
        let end = chunk.end.min(span.len().saturating_sub(tail));
        for pos in chunk.start..end {
            let word = u32::from_le_bytes(span[pos..pos + 4].try_into().unwrap());
            let hash = word.wrapping_mul(TREE_HASH_MULTIPLIER);
            #[cfg(feature = "ratio-lab")]
            let hash = if self.hash8 {
                hash_eight(span, pos)
            } else {
                hash
            };
            let bucket = (hash >> head_shift) as usize;
            #[cfg(feature = "ratio-lab")]
            let bucket = if self.multi_hash { bucket & 63 } else { bucket };
            self.shares[bucket % threads].push(pos as u32);
        }
    }

    /// One walker's share of a range: the positions whose bucket is
    /// `walker` modulo `threads`. Every walker reads every position's four
    /// bytes to decide - a load and a multiply against the descent it
    /// saves, and the alternative (a partition pass) is a list of every
    /// position in memory.
    /// One walker's share of a chunk. Only called from `advance_range`'s
    /// `parallel`-gated arm.
    #[cfg(feature = "parallel")]
    fn walk(
        &self,
        span: &[u8],
        share: &[u32],
        limit: usize,
        base: usize,
        out: Option<&[AtomicU32]>,
        stride: usize,
    ) {
        let mut found = [TREE_NO_MATCH; TREE_MAX_CANDIDATE_SLOTS];
        for &pos in share {
            let pos = pos as usize;
            let kept = self.advance(span, pos, limit, &mut found, stride);
            if kept != 0 {
                if let Some(out) = out {
                    let at = (pos - base) * stride;
                    for (slot, &distance) in out[at..at + kept].iter().zip(&found[..kept]) {
                        slot.store(distance, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// The whole of a range, in order: the serial walk.
    fn walk_range(
        &self,
        span: &[u8],
        range: Range<usize>,
        limit: usize,
        base: usize,
        out: Option<&[AtomicU32]>,
        stride: usize,
    ) {
        let mut found = [TREE_NO_MATCH; TREE_MAX_CANDIDATE_SLOTS];
        for pos in range {
            let kept = self.advance(span, pos, limit, &mut found, stride);
            if kept != 0 {
                if let Some(out) = out {
                    let at = (pos - base) * stride;
                    for (slot, &distance) in out[at..at + kept].iter().zip(&found[..kept]) {
                        slot.store(distance, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Two or three independent prefix lookups. Each table preserves a common
    /// four-byte shard in its low six bucket bits, so the same walker owns
    /// every head written by a position, including at non-power-of-two widths.
    #[cfg(feature = "ratio-lab")]
    fn advance_multi_hash(
        &self,
        span: &[u8],
        pos: usize,
        limit: usize,
        hash4: u32,
        found: &mut [u32; TREE_MAX_CANDIDATE_SLOTS],
        keep: usize,
    ) -> usize {
        let heads = 1usize << (32 - self.head_shift);
        let bucket4 = (hash4 >> self.head_shift) as usize;
        let mut matches = [(0usize, 0usize); 3];
        let mut count = 0;
        let widths: &[usize] = if self.multi_hash_short {
            &[8, 16]
        } else {
            &[4, 8, 16]
        };
        for (table, &width) in widths.iter().enumerate() {
            if limit < width {
                break;
            }
            let hash = match width {
                4 => hash4,
                8 => hash_eight(span, pos),
                _ => hash_eight(span, pos) ^ hash_eight(span, pos + 8).rotate_left(13),
            };
            let bucket =
                table * heads + (((hash >> self.head_shift) as usize & !63) | (bucket4 & 63));
            let current = self.head[bucket].load(Ordering::Relaxed);
            self.head[bucket].store((pos + 1) as u32, Ordering::Relaxed);
            if current != TREE_NO_MATCH {
                let candidate = (current - 1) as usize;
                let distance = pos - candidate;
                if distance <= self.window {
                    let length = common_prefix(span, candidate, pos, 0, limit);
                    if length >= 4 {
                        matches[count] = (distance, length);
                        count += 1;
                    }
                }
            }
        }
        matches[..count].sort_unstable_by_key(|m| m.0);
        let mut best = 3;
        let mut kept = 0;
        for &(distance, length) in &matches[..count] {
            if length > best {
                best = length;
                if kept < keep {
                    found[kept] = distance as u32;
                    kept += 1;
                } else {
                    found[keep - 1] = distance as u32;
                }
            }
        }
        kept
    }

    /// Research control: the same hash heads and horizon with one previous
    /// link per position. Depth is bounded and candidates stay nearest first.
    #[cfg(feature = "ratio-lab")]
    fn advance_chain(
        &self,
        span: &[u8],
        pos: usize,
        limit: usize,
        mut current: u32,
        found: &mut [u32; TREE_MAX_CANDIDATE_SLOTS],
        keep: usize,
    ) -> usize {
        self.son[pos & self.cyclic_mask].store(current, Ordering::Relaxed);
        let mut best = 3;
        let mut kept = 0;
        for _ in 0..self.chain_depth {
            if current == TREE_NO_MATCH {
                break;
            }
            let candidate = (current - 1) as usize;
            let distance = pos - candidate;
            if distance > self.window {
                break;
            }
            let length = common_prefix(span, candidate, pos, 0, limit);
            if length > best {
                best = length;
                if kept < keep {
                    found[kept] = distance as u32;
                    kept += 1;
                } else {
                    found[keep - 1] = distance as u32;
                }
                if length == limit {
                    break;
                }
            }
            current = self.son[candidate & self.cyclic_mask].load(Ordering::Relaxed);
        }
        kept
    }

    /// One position: insert it into its bucket's tree, and record up to
    /// `keep` of the matches found on the way into `found`, returning how
    /// many were written.
    ///
    /// The descent visits its bucket's positions in increasing DISTANCE
    /// (a node's descendants are older than it is) and records a candidate
    /// only when it agrees for strictly more bytes than any before it, so
    /// what it writes is the frontier the cost-based parse consumes:
    /// increasing length, and the nearest distance reaching each. `keep`
    /// of 1 keeps only the longest, which is the lazy parser's single
    /// hint and what this returned before the parse consumed lists.
    #[inline]
    fn advance(
        &self,
        span: &[u8],
        pos: usize,
        limit: usize,
        found: &mut [u32; TREE_MAX_CANDIDATE_SLOTS],
        keep: usize,
    ) -> usize {
        // A position with fewer than four bytes ahead of it can neither be
        // matched against nor start a match, and is not indexed - the same
        // rule the ring index applies.
        debug_assert!(limit <= span.len());
        #[cfg(feature = "ratio-lab")]
        let nice_length = self.nice_length;
        #[cfg(not(feature = "ratio-lab"))]
        let nice_length = TREE_NICE_LENGTH;
        let len_limit = nice_length.min(limit - pos);
        #[cfg(feature = "ratio-lab")]
        if self.hash8 && len_limit < 8 {
            return 0;
        }
        if len_limit < 4 {
            return 0;
        }
        let word = u32::from_le_bytes(span[pos..pos + 4].try_into().unwrap());
        let scattered = word.wrapping_mul(TREE_HASH_MULTIPLIER);
        // Research sampling is content based: identical four-byte prefixes
        // participate at both occurrences, including odd match distances.
        // Fold high bits into low bits so all four bytes affect sampling,
        // rather than selecting positions by the first byte alone.
        #[cfg(any(test, feature = "ratio-lab"))]
        if (scattered ^ (scattered >> 24)) & self.sample_mask != 0 {
            return 0;
        }
        #[cfg(feature = "ratio-lab")]
        if self.multi_hash {
            return self.advance_multi_hash(span, pos, len_limit, scattered, found, keep);
        }
        #[cfg(feature = "ratio-lab")]
        let scattered = if self.hash8 {
            hash_eight(span, pos)
        } else {
            scattered
        };
        let bucket = (scattered >> self.head_shift) as usize;
        #[cfg(feature = "ratio-lab")]
        if self.hash8 {
            let mut previous = (pos + 1) as u32;
            let mut best_length = 7;
            let mut kept = 0;
            for slot in &self.head[bucket * self.hash8_slots..(bucket + 1) * self.hash8_slots] {
                let current = slot.load(Ordering::Relaxed);
                slot.store(previous, Ordering::Relaxed);
                previous = current;
                if current == TREE_NO_MATCH {
                    continue;
                }
                let candidate = (current - 1) as usize;
                let distance = pos - candidate;
                if distance <= self.window {
                    let length = common_prefix(span, candidate, pos, 0, len_limit);
                    if length > best_length {
                        best_length = length;
                        if kept < keep {
                            found[kept] = distance as u32;
                            kept += 1;
                        } else {
                            found[keep - 1] = distance as u32;
                        }
                    }
                }
            }
            return kept;
        }
        let mut current = self.head[bucket].load(Ordering::Relaxed);
        self.head[bucket].store((pos + 1) as u32, Ordering::Relaxed);
        #[cfg(feature = "ratio-lab")]
        if self.chain_depth != 0 {
            return self.advance_chain(span, pos, len_limit, current, found, keep);
        }
        let cyclic = pos & self.cyclic_mask;
        // The two ends of the split this descent performs: `low` collects
        // the positions whose suffix sorts below this one, `high` those
        // above. Each holds the slot to write the next such position into.
        let mut low = 2 * cyclic;
        let mut high = 2 * cyclic + 1;
        let mut low_len = 0usize;
        let mut high_len = 0usize;
        let mut best_length = 0usize;
        let mut kept = 0usize;
        let mut cut = self.cut;
        loop {
            if current == TREE_NO_MATCH || cut == 0 {
                self.son[low].store(TREE_NO_MATCH, Ordering::Relaxed);
                self.son[high].store(TREE_NO_MATCH, Ordering::Relaxed);
                break;
            }
            let candidate = (current - 1) as usize;
            let distance = pos - candidate;
            if distance > self.window {
                // Out of the window, and so is everything below it.
                self.son[low].store(TREE_NO_MATCH, Ordering::Relaxed);
                self.son[high].store(TREE_NO_MATCH, Ordering::Relaxed);
                break;
            }
            cut -= 1;
            let pair = 2 * (candidate & self.cyclic_mask);
            // Both branches already agree with this position for their own
            // count of bytes, so the compare starts at the smaller.
            let mut length = low_len.min(high_len);
            let matched = common_prefix(span, candidate, pos, length, len_limit);
            if matched > length {
                length = matched;
                if length > best_length {
                    best_length = length;
                    // A match shorter than four bytes is not emittable and
                    // is not reported, but it still routes the descent.
                    if length >= 4 {
                        // The first `keep - 1` recorded are the nearest,
                        // and the last slot always holds the newest and so
                        // the longest: a descent with more pairs than
                        // slots gives up the middle of its frontier, never
                        // an end of it.
                        if kept < keep {
                            found[kept] = distance as u32;
                            kept += 1;
                        } else {
                            found[keep - 1] = distance as u32;
                        }
                    }
                }
                if length == len_limit {
                    // Agreement to the comparison cap: this position takes
                    // the candidate's place in the tree wholesale, which is
                    // what keeps a long run of identical bytes from
                    // degenerating the bucket into a list.
                    self.son[low].store(self.son[pair].load(Ordering::Relaxed), Ordering::Relaxed);
                    self.son[high].store(
                        self.son[pair + 1].load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    break;
                }
            }
            if span[candidate + length] < span[pos + length] {
                self.son[low].store(current, Ordering::Relaxed);
                low = pair + 1;
                current = self.son[low].load(Ordering::Relaxed);
                low_len = length;
            } else {
                self.son[high].store(current, Ordering::Relaxed);
                high = pair;
                current = self.son[high].load(Ordering::Relaxed);
                high_len = length;
            }
        }
        kept
    }
}

#[cfg(feature = "ratio-lab")]
#[inline]
fn hash_eight(span: &[u8], pos: usize) -> u32 {
    let word = u64::from_le_bytes(span[pos..pos + 8].try_into().unwrap());
    (word.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampled_walks_keep_odd_distance_matches_and_agree_across_threads() {
        let mut state = 12345u32;
        let pattern: Vec<u8> = (0..8191)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect();
        let span = pattern.repeat(3);
        for sampling in [1, 2, 4, 8] {
            let mut serial = TreeMatchFinder::new(16384);
            serial.sample_mask = sampling - 1;
            let expected = empty_slots(span.len());
            serial.advance_range(&span, 0..span.len(), Some(&expected), 1, 1);
            assert!(expected.iter().any(|d| d.load(Ordering::Relaxed) == 8191));
            for pos in 0..span.len() - 3 {
                let word = u32::from_le_bytes(span[pos..pos + 4].try_into().unwrap());
                let hash = word.wrapping_mul(TREE_HASH_MULTIPLIER);
                if (hash ^ (hash >> 24)) & (sampling - 1) != 0 {
                    assert_eq!(expected[pos].load(Ordering::Relaxed), TREE_NO_MATCH);
                }
            }
            for threads in [2, 4] {
                let mut parallel = TreeMatchFinder::new(16384);
                parallel.sample_mask = sampling - 1;
                let actual = empty_slots(span.len());
                parallel.advance_range(&span, 0..span.len(), Some(&actual), 1, threads);
                assert!(
                    expected
                        .iter()
                        .zip(&actual)
                        .all(|(a, b)| a.load(Ordering::Relaxed) == b.load(Ordering::Relaxed))
                );
            }
        }
    }

    #[cfg(feature = "ratio-lab")]
    #[test]
    fn chain_control_matches_a_full_scan_and_parallel_wrap() {
        let mut state = 17u32;
        let span: Vec<u8> = (0..2048)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 28) as u8
            })
            .collect();
        let mut finder = TreeMatchFinder::new(511);
        finder.chain_depth = 256;
        let out = empty_slots(span.len());
        finder.advance_range(&span, 0..span.len(), Some(&out), 1, 1);
        for pos in 0..span.len() {
            let expected = longest_by_scan(&span, pos, finder.window());
            let distance = out[pos].load(Ordering::Relaxed) as usize;
            if distance == 0 {
                assert!(expected.is_none());
            } else {
                let length = common_prefix(
                    &span,
                    pos - distance,
                    pos,
                    0,
                    TREE_NICE_LENGTH.min(span.len() - pos),
                );
                assert_eq!(length, expected.unwrap().0);
            }
        }
        // Cross the actual cyclic wrap, with a live window just below it.
        let span = span.repeat(600);
        for depth in [8, 64] {
            let mut serial = TreeMatchFinder::new(1 << 20);
            serial.chain_depth = depth;
            let expected = empty_slots(span.len() * 4);
            serial.advance_range(&span, 0..span.len(), Some(&expected), 4, 1);
            let mut parallel = TreeMatchFinder::new(1 << 20);
            parallel.chain_depth = depth;
            let actual = empty_slots(span.len() * 4);
            parallel.advance_range(&span, 0..span.len(), Some(&actual), 4, 4);
            assert!(
                expected
                    .iter()
                    .zip(&actual)
                    .all(|(a, b)| a.load(Ordering::Relaxed) == b.load(Ordering::Relaxed))
            );
        }
    }

    #[cfg(feature = "ratio-lab")]
    #[test]
    fn direct_hash_eight_reports_valid_matches_at_any_walker_count() {
        let mut state = 4321u32;
        let pattern: Vec<u8> = (0..8191)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect();
        let span = pattern.repeat(150);
        let mut serial = TreeMatchFinder::new(1 << 20);
        serial.hash8 = true;
        let expected = empty_slots(span.len());
        serial.advance_range(&span, 0..span.len(), Some(&expected), 1, 1);
        assert!(expected.iter().any(|d| d.load(Ordering::Relaxed) == 8191));
        for (pos, distance) in expected.iter().enumerate() {
            let distance = distance.load(Ordering::Relaxed) as usize;
            if distance != 0 {
                assert!(distance <= pos && distance <= serial.window());
                assert_eq!(
                    &span[pos..pos + 8],
                    &span[pos - distance..pos - distance + 8]
                );
            }
        }
        for threads in [2, 4] {
            let mut parallel = TreeMatchFinder::new(1 << 20);
            parallel.hash8 = true;
            let actual = empty_slots(span.len());
            parallel.advance_range(&span, 0..span.len(), Some(&actual), 1, threads);
            assert!(
                expected
                    .iter()
                    .zip(&actual)
                    .all(|(a, b)| a.load(Ordering::Relaxed) == b.load(Ordering::Relaxed))
            );
        }
    }

    #[cfg(feature = "ratio-lab")]
    #[test]
    fn hash_eight_history_recovers_an_older_longer_match() {
        let mut first: Vec<u8> = (0..64).collect();
        first[..8].copy_from_slice(b"prefix!!");
        let mut second = vec![255; 64];
        second[..8].copy_from_slice(b"prefix!!");
        let span = [first.as_slice(), second.as_slice(), first.as_slice()].concat();
        for slots in [1usize, 2, 4, 8] {
            let mut finder = TreeMatchFinder::new(1 << 20);
            finder.hash8 = true;
            finder.hash8_slots = slots;
            finder.head_shift += slots.trailing_zeros();
            let head_bytes = finder.head.len() * std::mem::size_of::<AtomicU32>();
            assert_eq!(head_bytes, (1 << 20) / TREE_HEADS_PER_WINDOW * 4);
            let result = empty_slots(span.len());
            finder.advance_range(&span, 0..span.len(), Some(&result), 1, 1);
            assert_eq!(
                result[128].load(Ordering::Relaxed),
                if slots == 1 { 64 } else { 128 }
            );
            for threads in [2, 3, 4] {
                let mut parallel = TreeMatchFinder::new(1 << 20);
                parallel.hash8 = true;
                parallel.hash8_slots = slots;
                parallel.head_shift += slots.trailing_zeros();
                let actual = empty_slots(span.len());
                parallel.advance_range(&span, 0..span.len(), Some(&actual), 1, threads);
                assert!(
                    result
                        .iter()
                        .zip(&actual)
                        .all(|(a, b)| a.load(Ordering::Relaxed) == b.load(Ordering::Relaxed))
                );
            }
        }
    }

    #[cfg(feature = "ratio-lab")]
    #[test]
    fn multi_hash_shards_agree_with_three_and_four_walkers() {
        let mut state = 4321u32;
        let pattern: Vec<u8> = (0..8191)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect();
        let span = pattern.repeat(150);
        for short in [false, true] {
            let new_finder = || {
                let mut finder = TreeMatchFinder::new(1 << 20);
                finder.multi_hash = true;
                finder.multi_hash_short = short;
                finder.head = empty_slots(finder.head.len() * if short { 2 } else { 3 });
                finder
            };
            let mut serial = new_finder();
            let expected = empty_slots(span.len() * 4);
            serial.advance_range(&span, 0..span.len(), Some(&expected), 4, 1);
            assert!(expected.iter().any(|d| d.load(Ordering::Relaxed) == 8191));
            for (slot, distance) in expected.iter().enumerate() {
                let pos = slot / 4;
                let distance = distance.load(Ordering::Relaxed) as usize;
                if distance != 0 {
                    assert!(distance <= pos && distance <= serial.window());
                    assert_eq!(
                        &span[pos..pos + 4],
                        &span[pos - distance..pos - distance + 4]
                    );
                }
            }
            for threads in [3, 4] {
                let mut parallel = new_finder();
                let actual = empty_slots(span.len() * 4);
                parallel.advance_range(&span, 0..span.len(), Some(&actual), 4, threads);
                assert!(
                    expected
                        .iter()
                        .zip(&actual)
                        .all(|(a, b)| a.load(Ordering::Relaxed) == b.load(Ordering::Relaxed))
                );
            }
        }
    }

    /// The longest match at `pos` within `window`, by brute force.
    fn longest_by_scan(span: &[u8], pos: usize, window: usize) -> Option<(usize, usize)> {
        let len_limit = TREE_NICE_LENGTH.min(span.len() - pos);
        if len_limit < 4 {
            return None;
        }
        let mut best: Option<(usize, usize)> = None;
        for candidate in pos.saturating_sub(window)..pos {
            let mut length = 0;
            while length < len_limit && span[candidate + length] == span[pos + length] {
                length += 1;
            }
            if length >= 4 && best.is_none_or(|(best, _)| length > best) {
                best = Some((length, pos - candidate));
            }
        }
        best
    }

    fn load_all(slots: &[AtomicU32]) -> Vec<u32> {
        slots
            .iter()
            .map(|slot| slot.load(Ordering::Relaxed))
            .collect()
    }

    fn corpus(len: usize, alphabet: u8, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                (state >> 33) as u8 % alphabet
            })
            .collect()
    }

    #[test]
    #[cfg(feature = "ratio-lab")]
    fn comparison_caps_match_scan_and_remain_schedule_independent() {
        let seed = corpus(256, 17, 531);
        let mut span = Vec::new();
        for index in 0..16 {
            let start = span.len();
            span.extend_from_slice(&seed);
            span[start + 32] = 32 + index % 4;
            span[start + 64] = 32 + index % 8;
            span[start + 128] = 32 + index;
        }
        let mut answers = Vec::new();
        for cap in [32, 64, 128, 256] {
            let mut serial = TreeMatchFinder::new(4096)
                .with_cut(u32::MAX)
                .with_nice_length(cap);
            let slots = empty_slots(span.len());
            serial.advance_range(&span, 0..span.len(), Some(&slots), 1, 1);
            let values = load_all(&slots);
            for (pos, &distance) in values.iter().enumerate() {
                let limit = cap.min(span.len() - pos);
                let length = |candidate: usize| {
                    (0..limit)
                        .take_while(|&offset| span[candidate + offset] == span[pos + offset])
                        .count()
                };
                let best = (pos.saturating_sub(serial.window())..pos)
                    .map(length)
                    .max()
                    .unwrap_or(0);
                if best < 4 {
                    assert_eq!(distance, 0);
                } else {
                    assert!((1..=pos.min(serial.window())).contains(&(distance as usize)));
                    assert_eq!(length(pos - distance as usize), best);
                }
            }
            let mut parallel = TreeMatchFinder::new(4096)
                .with_cut(u32::MAX)
                .with_nice_length(cap);
            parallel.advance_range(&span, 0..span.len(), Some(&slots), 1, 4);
            assert_eq!(values, load_all(&slots));
            answers.push(values);
        }
        assert!(answers.windows(2).any(|pair| pair[0] != pair[1]));
    }

    /// Every candidate a descent records is the NEAREST distance reaching
    /// its own length, the first is the nearest four-byte match in the
    /// window, and the last is the longest - which is the frontier the
    /// cost-based parse consumes, checked against a full scan.
    /// (nzbfast-local change, 7 Sep 2026.)
    #[test]
    fn every_recorded_candidate_is_the_nearest_distance_for_its_length() {
        let mut positions_with_several = 0usize;
        for alphabet in [2u8, 3, 5, 17] {
            let span = corpus(12_000, alphabet, u64::from(alphabet) * 11 + 1);
            let window = 4096;
            let stride = TREE_MAX_CANDIDATE_SLOTS;
            let mut finder = TreeMatchFinder::new(window).with_cut(u32::MAX);
            let out = empty_slots(span.len() * stride);
            finder.advance_range(&span, 0..span.len(), Some(&out), stride, 1);
            let reach = finder.window();
            for pos in 0..span.len() {
                let len_limit = TREE_NICE_LENGTH.min(span.len() - pos);
                let length_at = |candidate: usize| {
                    (0..len_limit)
                        .take_while(|&offset| span[candidate + offset] == span[pos + offset])
                        .count()
                };
                let listed: Vec<usize> = out[pos * stride..(pos + 1) * stride]
                    .iter()
                    .map(|slot| slot.load(Ordering::Relaxed) as usize)
                    .take_while(|&distance| distance != TREE_NO_MATCH as usize)
                    .collect();
                let scanned = longest_by_scan(&span, pos, reach);
                let Some((longest, _)) = scanned else {
                    assert!(listed.is_empty(), "alphabet {alphabet} pos {pos}");
                    continue;
                };
                assert!(!listed.is_empty(), "alphabet {alphabet} pos {pos}");
                positions_with_several += usize::from(listed.len() > 1);
                let mut previous: Option<(usize, usize)> = None;
                for &distance in &listed {
                    assert!((1..=pos.min(reach)).contains(&distance));
                    let length = length_at(pos - distance);
                    assert!(
                        length >= 4,
                        "alphabet {alphabet} pos {pos} distance {distance}"
                    );
                    // The nearest distance reaching this length, by scan.
                    let nearest = (pos.saturating_sub(reach)..pos)
                        .rev()
                        .find(|&candidate| length_at(candidate) >= length)
                        .map(|candidate| pos - candidate);
                    assert_eq!(nearest, Some(distance), "alphabet {alphabet} pos {pos}");
                    if let Some((before, closer)) = previous {
                        assert!(before < length && closer < distance);
                    }
                    previous = Some((length, distance));
                }
                // The first slot is the nearest four-byte match there is,
                // and the last reaches as far as any match in the window.
                let nearest_four = (pos.saturating_sub(reach)..pos)
                    .rev()
                    .find(|&candidate| length_at(candidate) >= 4)
                    .map(|candidate| pos - candidate);
                assert_eq!(nearest_four, Some(listed[0]));
                assert_eq!(length_at(pos - listed[listed.len() - 1]), longest);
            }
        }
        // A list that is one entry everywhere would pass the loop above
        // while carrying none of what the wider stride is for. The count is
        // over the whole sweep: a 17-symbol alphabet has so few four-byte
        // matches that its frontier is one entry nearly everywhere, and it
        // is in the sweep for the correctness assertions, not this one.
        assert!(
            positions_with_several > 2_000,
            "only {positions_with_several} positions listed several candidates"
        );
    }

    /// A wider stride is a wider ANSWER, not a different one: the last
    /// filled slot of a wide walk is the single distance a stride-one walk
    /// records, and neither depends on the walkers.
    /// (nzbfast-local change, 7 Sep 2026.)
    #[test]
    fn a_wide_stride_keeps_the_single_distance_as_its_last_slot() {
        let span = corpus(60_000, 5, 909);
        let mut narrow = TreeMatchFinder::new(8192);
        let single = empty_slots(span.len());
        narrow.advance_range(&span, 0..span.len(), Some(&single), 1, 1);
        for stride in [2usize, 4, TREE_MAX_CANDIDATE_SLOTS] {
            let mut wide = TreeMatchFinder::new(8192);
            let listed = empty_slots(span.len() * stride);
            wide.advance_range(&span, 0..span.len(), Some(&listed), stride, 1);
            let mut parallel = TreeMatchFinder::new(8192);
            let threaded = empty_slots(span.len() * stride);
            parallel.advance_range(&span, 0..span.len(), Some(&threaded), stride, 4);
            assert_eq!(load_all(&listed), load_all(&threaded), "stride {stride}");
            for pos in 0..span.len() {
                let last = out_last(&listed[pos * stride..(pos + 1) * stride]);
                assert_eq!(
                    last,
                    single[pos].load(Ordering::Relaxed),
                    "stride {stride} pos {pos}"
                );
            }
        }
    }

    /// The last filled slot of one position's list, or [`TREE_NO_MATCH`].
    fn out_last(slots: &[AtomicU32]) -> u32 {
        let mut last = TREE_NO_MATCH;
        for slot in slots {
            match slot.load(Ordering::Relaxed) {
                TREE_NO_MATCH => break,
                distance => last = distance,
            }
        }
        last
    }

    /// The tree finds the longest match a full scan finds, at every
    /// position, on input dense enough that the buckets collide hard.
    #[test]
    fn tree_matches_a_full_scan_on_a_tiny_alphabet() {
        for alphabet in [2u8, 3, 5, 17] {
            let span = corpus(20_000, alphabet, u64::from(alphabet) * 7);
            let window = 4096;
            let mut finder = TreeMatchFinder::new(window).with_cut(u32::MAX);
            let out = empty_slots(span.len());
            finder.advance_range(&span, 0..span.len(), Some(&out), 1, 1);
            for pos in 0..span.len() {
                let scanned = longest_by_scan(&span, pos, finder.window());
                let found = out[pos].load(Ordering::Relaxed);
                match scanned {
                    None => assert_eq!(found, TREE_NO_MATCH, "alphabet {alphabet} pos {pos}"),
                    Some((length, _)) => {
                        assert_ne!(found, TREE_NO_MATCH, "alphabet {alphabet} pos {pos}");
                        let distance = found as usize;
                        let mut got = 0;
                        let limit = TREE_NICE_LENGTH.min(span.len() - pos);
                        while got < limit && span[pos - distance + got] == span[pos + got] {
                            got += 1;
                        }
                        assert_eq!(got, length, "alphabet {alphabet} pos {pos}");
                    }
                }
            }
        }
    }

    /// Long repeats far apart - what the ring index cannot reach - are
    /// found at their full comparison length.
    #[test]
    fn tree_reaches_a_repeat_the_whole_window_back() {
        let mut span = corpus(1 << 16, 200, 11);
        let phrase: Vec<u8> = (0..200u16).map(|i| (i % 251) as u8 + 3).collect();
        span[100..100 + phrase.len()].copy_from_slice(&phrase);
        let far = span.len() - 1_000;
        span[far..far + phrase.len()].copy_from_slice(&phrase);
        let mut finder = TreeMatchFinder::new(1 << 20);
        let out = empty_slots(span.len());
        finder.advance_range(&span, 0..span.len(), Some(&out), 1, 1);
        assert_eq!(out[far].load(Ordering::Relaxed) as usize, far - 100);
    }

    /// A finder seeded over the window before a range answers that range
    /// exactly as one that has walked the span from its start, when both
    /// split their walks on the same boundaries: the property the streamed
    /// writer's windows rest on, and the reason the caller's ranges follow
    /// the block grid.
    #[test]
    fn a_seeded_window_answers_as_the_whole_span_does() {
        let span = corpus(60_000, 6, 3);
        let window = 8_192;
        for start in [16_384usize, 32_768, 49_152] {
            let mut whole = TreeMatchFinder::new(window);
            let all = empty_slots(span.len() - start);
            whole.advance_range(&span, 0..start, None, 1, 1);
            whole.advance_range(&span, start..span.len(), Some(&all), 1, 1);

            let seed_from = start - window;
            let mut windowed = TreeMatchFinder::new(window);
            windowed.skip_to(seed_from);
            windowed.advance_range(&span, seed_from..start, None, 1, 1);
            let part = empty_slots(span.len() - start);
            windowed.advance_range(&span, start..span.len(), Some(&part), 1, 1);
            assert_eq!(load_all(&part), load_all(&all), "window from {start}");
        }
    }

    /// The walkers' answers do not depend on how many of them there are:
    /// a bucket's tree is one walker's, and every node a descent reads
    /// belongs to the bucket it is descending. A range long enough to
    /// clear [`TREE_PARALLEL_MIN_RANGE`], so the walkers really do run.
    #[test]
    fn a_parallel_walk_answers_as_the_serial_walk_does() {
        let span = corpus(1 << 20, 5, 41);
        let mut serial = TreeMatchFinder::new(1 << 16);
        let expected = empty_slots(span.len());
        serial.advance_range(&span, 0..span.len(), Some(&expected), 1, 1);
        for threads in [2usize, 3, 8] {
            let mut parallel = TreeMatchFinder::new(1 << 16);
            let out = empty_slots(span.len());
            parallel.advance_range(&span, 0..span.len(), Some(&out), 1, threads);
            assert_eq!(load_all(&out), load_all(&expected), "{threads} walkers");
        }
    }

    /// Every distance handed back is a real match of at least four bytes.
    #[test]
    fn every_distance_is_a_real_match() {
        let span = corpus(30_000, 40, 99);
        let mut finder = TreeMatchFinder::new(1 << 14);
        let out = empty_slots(span.len());
        finder.advance_range(&span, 0..span.len(), Some(&out), 1, 1);
        for (pos, distance) in out.iter().enumerate() {
            let distance = distance.load(Ordering::Relaxed);
            if distance == TREE_NO_MATCH {
                continue;
            }
            let distance = distance as usize;
            assert!(distance <= pos && distance <= finder.window());
            assert_eq!(
                span[pos - distance..pos - distance + 4],
                span[pos..pos + 4],
                "pos {pos}"
            );
        }
    }
}
