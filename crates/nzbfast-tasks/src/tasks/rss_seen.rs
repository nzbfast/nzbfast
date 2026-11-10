//! The RSS poller's dedupe set, out of `spawn_rss_poller` so its
//! eviction rule can be tested without a poller around it.

use super::*;

/// The RSS dedupe set: which guids have already been judged.
///
/// Insertion-ordered alongside the set, and capped. It used to be a bare
/// HashSet that never shrank under any configuration, and every single
/// marked item re-serialised the WHOLE set and durably wrote it -
/// `write_atomic` is write_all + sync_all + a directory fsync - so one
/// poll cost O(items x every-guid-ever) of durable I/O. A feed producing
/// a few hundred guids a day reaches a multi-MB file within a year, and
/// from then on each new item costs a multi-MB rewrite plus two fsyncs:
/// real flash wear on a NAS or Pi spool. Now it evicts the oldest and
/// writes once per pass.
///
/// Evicting the oldest, never clearing: a cleared set lets old items back
/// through the dedupe and re-grabs history, which is the one thing this
/// file exists to prevent.
///
/// Keys are `<feed scope>\u{1}<guid>`, not the bare guid. An RSS `guid`
/// and an Atom `id` are publisher-local arbitrary strings, and one global
/// set meant two feeds publishing different items under guid `123`
/// suppressed each other - including across restarts, so a rule-rejected
/// item in feed A permanently hid an accepted item in feed B (review
/// sweep 12 Aug F12).
///
/// EVICTION IS PER FEED, FROM THE BIGGEST. The cap used to be one
/// oldest-first queue across every feed, so a busy all-categories feed
/// (thousands of new guids a day) pushed a quiet feed's guids out within
/// a day or two while they were still inside that feed's rolling window,
/// and the next poll judged them again and re-grabbed them. Now the cap
/// is still one number, but an eviction takes the oldest entry of the
/// feed holding the MOST: a busy feed pays for its own volume, and a
/// quiet one is never evicted while a bigger one has entries to spare.
///
/// Reads still fall back to the bare guid, because every entry written
/// before scoping is unscoped and re-evaluating them would re-grab
/// whatever is still inside each feed's rolling window. Legacy entries
/// live in a bucket of their own (scope ""), keep suppressing (the old
/// behaviour, cross-feed collisions and all), and are the first to go,
/// because right after an upgrade that bucket is the biggest.
pub(super) struct SeenGuids {
    set: std::collections::HashSet<String>,
    order: std::collections::HashMap<String, VecDeque<String>>,
    len: usize,
    dirty: bool,
}

impl SeenGuids {
    const MAX: usize = 20_000;

    fn key(scope: &str, guid: &str) -> String {
        format!("{scope}\u{1}{guid}")
    }

    /// The bucket a stored key belongs to: its scope, or "" for a bare
    /// legacy guid.
    fn scope_of(key: &str) -> &str {
        key.split_once('\u{1}').map_or("", |(s, _)| s)
    }

    /// From the on-disk array, oldest first within each feed.
    pub(super) fn from_loaded(loaded: Vec<String>) -> Self {
        let mut me = Self {
            set: Default::default(),
            order: Default::default(),
            len: 0,
            dirty: false,
        };
        for k in loaded {
            if me.set.insert(k.clone()) {
                me.order
                    .entry(Self::scope_of(&k).to_string())
                    .or_default()
                    .push_back(k);
                me.len += 1;
            }
        }
        // A file written by a build with a different cap still loads
        // under this one, without marking anything to write.
        me.evict();
        me.dirty = false;
        me
    }

    pub(super) fn contains(&self, scope: &str, guid: &str) -> bool {
        self.set.contains(&Self::key(scope, guid)) || self.set.contains(guid)
    }

    pub(super) fn insert(&mut self, scope: &str, guid: &str) {
        let key = Self::key(scope, guid);
        if !self.set.insert(key.clone()) {
            return;
        }
        self.order
            .entry(scope.to_string())
            .or_default()
            .push_back(key);
        self.len += 1;
        self.evict();
        self.dirty = true;
    }

    /// Down to the cap, oldest-first out of whichever feed holds the most.
    fn evict(&mut self) {
        while self.len > Self::MAX {
            let Some(q) = self.order.values_mut().max_by_key(|q| q.len()) else {
                return;
            };
            let Some(old) = q.pop_front() else { return };
            self.set.remove(&old);
            self.len -= 1;
            self.dirty = true;
        }
        self.order.retain(|_, q| !q.is_empty());
    }

    /// The on-disk form: a JSON array, byte-compatible with what the bare
    /// HashSet wrote, so an existing rss-seen.json loads unchanged. Each
    /// feed's entries stay in their own order, which is all eviction
    /// reads. Clears the mark only once there are bytes to write: an
    /// encode failure keeps `dirty` set so the next pass tries again
    /// instead of silently forgetting the set until some later insert
    /// happens to re-mark it.
    pub(super) fn take_dirty(&mut self) -> Option<Vec<u8>> {
        if !self.dirty {
            return None;
        }
        let all: Vec<&String> = self.order.values().flatten().collect();
        match serde_json::to_vec(&all) {
            Ok(b) => {
                self.dirty = false;
                Some(b)
            }
            Err(e) => {
                warn!(target: "rss", "rss seen set could not be encoded ({e})");
                None
            }
        }
    }

    /// The write's failure path: the bytes never landed, so the mark goes
    /// back up and the next pass retries.
    pub(super) fn unpersisted(&mut self) {
        self.dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sweep C (tasks.rs): a busy feed must not push a quiet feed's guids
    /// out of the set while a bigger feed still has entries to spare.
    /// One global oldest-first queue evicted the quiet feed's 50 within
    /// the busy feed's first 20,000, and its next poll re-grabbed them.
    #[test]
    fn a_busy_feed_does_not_evict_a_quiet_one() {
        let mut s = SeenGuids::from_loaded(Vec::new());
        for i in 0..50 {
            s.insert("quiet", &format!("q{i}"));
        }
        for i in 0..(SeenGuids::MAX * 2) {
            s.insert("busy", &format!("b{i}"));
        }
        assert!((0..50).all(|i| s.contains("quiet", &format!("q{i}"))));
        assert!(
            !s.contains("busy", "b0"),
            "the busy feed evicts its own oldest"
        );
        assert!(s.contains("busy", &format!("b{}", SeenGuids::MAX * 2 - 1)));
        assert_eq!(s.set.len(), SeenGuids::MAX);
    }

    /// The file round-trips, bare legacy guids still suppress, and they
    /// are the first to go once the cap bites.
    #[test]
    fn legacy_guids_round_trip_and_go_first() {
        let mut s = SeenGuids::from_loaded(vec!["old".into(), "feed\u{1}g1".into()]);
        assert!(s.contains("any feed", "old"));
        assert!(s.contains("feed", "g1"));
        s.insert("feed", "g2");
        let back: Vec<String> = serde_json::from_slice(&s.take_dirty().unwrap()).unwrap();
        let mut s = SeenGuids::from_loaded(back);
        assert!(s.contains("feed", "g1") && s.contains("feed", "g2") && s.contains("x", "old"));
        assert!(s.take_dirty().is_none(), "a load writes nothing");
        // Fill the legacy bucket past everything else, then overflow.
        let mut s = SeenGuids::from_loaded((0..SeenGuids::MAX).map(|i| format!("l{i}")).collect());
        s.insert("feed", "new");
        assert!(!s.contains("x", "l0"));
        assert!(s.contains("feed", "new"));
    }
}
