//! Earlier input positions by the hash of their first three bytes, for the
//! RAR 2.0 and RAR 2.9 planners' match searches.
//!
//! One list per hash, as before, but each list keeps only its newest
//! entries, so the index no longer grows with the member. The uncapped
//! lists held every input position - eight bytes per input byte plus growth
//! slack - which made a planner's heap a term in the size of what it was
//! packing.
//!
//! Dropping older entries costs nothing, because a search never reads them:
//! it walks a list newest first, counts the candidates it measures, and
//! stops at `candidates` of them. It breaks out one entry later at the
//! latest - on the first candidate further back than the search may reach -
//! and skips at most one more without counting it, so it never reads past
//! the `candidates + 2` newest. That is the cap, so every list answers
//! exactly as the uncapped one did and the planners' output is unchanged.
//!
//! The cap is the search's candidate limit, not the dictionary, so the index
//! is the same size for a 4 MiB window as for a 64 KiB one.
//!
//! A list holds up to twice the cap and is compacted by moving its newest
//! half to the front when it fills. That keeps the newest entries CONTIGUOUS
//! and at the end, so a search reads one slice in reverse exactly as it read
//! the uncapped list: a ring would have cost the walk its straight line, and
//! measured 12% of the RAR 2.0 planner's time.

/// Positions under one hash, oldest first; the live ones are the tail.
struct Bucket {
    entries: Vec<usize>,
}

pub(super) struct MatchIndex {
    buckets: Vec<Bucket>,
    /// The most positions one hash keeps.
    capacity: usize,
}

impl MatchIndex {
    /// An index whose searches measure at most `candidates` positions per
    /// hash, over an input of `span` bytes.
    pub(super) fn new(buckets: usize, span: usize, candidates: usize) -> Self {
        // Two beyond the candidate limit: the entry a search breaks out on,
        // and the one it may skip without counting.
        let capacity = candidates.saturating_add(2).min(span.max(1));
        Self {
            buckets: (0..buckets)
                .map(|_| Bucket {
                    entries: Vec::new(),
                })
                .collect(),
            capacity,
        }
    }

    /// Records `position`, which must be above every position already in.
    pub(super) fn insert(&mut self, position: usize, hash: usize) {
        let capacity = self.capacity;
        let entries = &mut self.buckets[hash].entries;
        if entries.len() == 2 * capacity {
            entries.copy_within(capacity.., 0);
            entries.truncate(capacity);
        } else if entries.len() == entries.capacity() {
            // Grow by doubling, but never past the room a list can use: a
            // `push` alone would leave it holding twice that.
            let want = entries
                .capacity()
                .saturating_mul(2)
                .max(4)
                .min(2 * capacity);
            entries.reserve_exact(want - entries.capacity());
        }
        entries.push(position);
    }

    /// The positions under `hash`, newest first.
    pub(super) fn candidates(&self, hash: usize) -> impl Iterator<Item = usize> + '_ {
        let entries = &self.buckets[hash].entries;
        let live = entries.len().min(self.capacity);
        entries[entries.len() - live..].iter().rev().copied()
    }
}
