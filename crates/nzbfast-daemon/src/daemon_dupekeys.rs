//! What this daemon already has - the key sets a wall verdict joins
//! against to say "you have this". A child module of `daemon` rather
//! than more lines of it (TODO 106, the code-quality refactor).
//!
//! Two key spaces over ONE corpus, which is why they are one module and
//! why the distinction is worth stating where both are written.
//! `owned_dupe_keys` (M30) answers in DUPE keys, which is what the
//! browse rows badge against. `owned_title_keys` (M31b) answers in
//! `title_key`s - the wall's grouping key, NOT dupe keys - so the
//! Affinity sort can sink owned titles with a plain `title_key IN
//! (...)`. Both walk the same thing: Completed history plus the live
//! queue. `owned_title_keys_uncached` is that walk, kept separate
//! because it is both what the cached answer is computed from on a miss
//! and the ground truth its tests check the cached answer against.
//!
//! A second `impl Daemon` in a child module of `daemon`, so `Daemon`'s
//! private fields (`queue`, `history`, `queue_rev`, `history_rev` and
//! the title-key cache) stay in scope exactly as they were inline.
//! `pub(super)` became `pub(crate)` here, because `super` is
//! `daemon` from inside a child.
//!
//! No cfg on the module; the per-item `indexer` gates move with the
//! items, the shape daemon_indexgate.rs already uses.

use super::*;

impl Daemon {
    /// M30: dupe keys of everything already in the library or on its
    /// way there - Completed history plus the current queue. The wall
    /// joins browse rows against this to badge "you have this".
    #[cfg(feature = "indexer")]
    pub fn owned_dupe_keys(&self) -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        for j in self.queue.lock_ok().iter() {
            if let Some(k) = j.lock_ok().dupe_key.clone() {
                set.insert(k);
            }
        }
        for j in self.history.lock_ok().iter() {
            let g = j.lock_ok();
            if g.state == JobState::Completed
                && let Some(k) = g.dupe_key.clone()
            {
                set.insert(k);
            }
        }
        set
    }

    /// M31b: the parse-key set of everything the user already has -
    /// completed history plus the live queue. These are `title_key`s (the
    /// wall's grouping key), NOT dupe keys, so the Affinity sort can sink
    /// owned titles with a plain `title_key IN (...)`.
    ///
    /// N12: cached against `(queue_rev, history_rev)`. Both consumers are
    /// per-poll - the Affinity wall sort through `affinity_ctx`, and the
    /// eviction pass through `protected_set` - and the walk below is a
    /// `parse_release` per job under that job's lock, ~14,500 of them at
    /// issue #38's history size.
    ///
    /// The revision pair rather than a TTL, deliberately: `protected_set`
    /// decides what eviction may NOT delete, so a key that went missing
    /// for a TTL's worth of seconds is a window in which the index can
    /// drop rows for a title the user has just finished. Both counters
    /// move at the persistence seams (`save_queue`, `histstore`), which
    /// every membership, state and name change comes through, and the
    /// house rule at those seams is store-before-bump (spelled out at
    /// `publish_hold`) - so a reader can see a change ahead of its bump,
    /// but never a bump ahead of its change.
    ///
    /// Which is why the revisions are read BEFORE the walk. A mutation
    /// landing mid-walk gets tagged with the pre-mutation revision and is
    /// discarded by the very next caller; reading them afterwards would
    /// instead stamp a pre-mutation answer as current and keep it.
    #[cfg(feature = "indexer")]
    pub(crate) fn owned_title_keys(&self) -> std::collections::HashSet<String> {
        let rev = (
            self.queue_rev.load(Ordering::Relaxed),
            self.history_rev.load(Ordering::Relaxed),
        );
        // A leaf lock taken twice, not held across the walk: the walk
        // takes the queue and history locks and then a job lock, and a
        // cache mutex outranking those would add a fourth edge to that
        // order to de-duplicate a miss only two callers can race.
        let hit = self
            .owned_keys_cache
            .lock_ok()
            .as_ref()
            .filter(|(q, h, _)| (*q, *h) == rev)
            .map(|(_, _, set)| Arc::clone(set));
        if let Some(set) = hit {
            return (*set).clone();
        }
        let fresh = Arc::new(self.owned_title_keys_uncached());
        *self.owned_keys_cache.lock_ok() = Some((rev.0, rev.1, Arc::clone(&fresh)));
        (*fresh).clone()
    }

    /// The walk itself: what `owned_title_keys` answers on a miss, and
    /// the ground truth its tests check the cached answer against.
    #[cfg(feature = "indexer")]
    pub(crate) fn owned_title_keys_uncached(&self) -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        let mut push = |name: &str| {
            let k = crate::wall::parse_release(name).key;
            if !k.is_empty() {
                set.insert(k);
            }
        };
        for j in self.queue.lock_ok().iter() {
            push(&j.lock_ok().name);
        }
        for j in self.history.lock_ok().iter() {
            let g = j.lock_ok();
            if g.state == JobState::Completed {
                push(&g.name);
            }
        }
        set
    }
}
