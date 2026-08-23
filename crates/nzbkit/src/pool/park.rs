//! Held-bytes backpressure, the pool half (TODO 94 item E, 22 Aug 2026).
//!
//! A chased archive whose articles arrive faster than its engine decodes
//! them fills the held-bytes budget with bytes nobody can release yet,
//! and the breach ladder (drop-behind trim, forfeit, demote) then pays
//! for a whole second pass over the set. The extractor now governs the
//! group's arrivals instead: once its holds near the cap it PARKS the
//! group's files here with a byte ALLOWANCE - the room left under the
//! cap - and refreshes that allowance on every arrival and every engine
//! progress mark. `next_work` admits a parked group's articles while
//! its in-flight estimate is under the allowance and steps past them
//! otherwise, rotating them to the back exactly like an article this
//! server has 430'd, so every other file in the job (PAR2, the other
//! groups, a plain payload) takes the connections meanwhile. Released
//! when the group stops chasing.
//!
//! An allowance rather than an on/off park, because a binary release at
//! a low-water mark let the whole fleet burst at once: the pool's wire
//! cap is a quarter of the budget against a holds slice of 45%, so the
//! burst alone was 55% of the cap, and on the 22 Aug loopback rig it
//! breached one leg in three however the band was placed. The
//! allowance IS the room, so the group can never be admitted past it.
//!
//! Two rules keep this a throughput dip and never a deadlock:
//!
//! - A parked group with NOTHING in flight is always admitted one
//!   article, whatever its allowance. The engine consumes the frontier
//!   buffer from the bottom, and the article it is blocked on is the
//!   group's lowest pending one. Each arrival, and each engine progress
//!   mark, re-runs the extractor's check, so the moment the engine has
//!   consumed enough for the trim to release a prefix the allowance
//!   reopens; a park can therefore stall only while the engine is
//!   itself stalled, and the existing breach ladder still governs that.
//! - A promoted article (a seek, the offset-0 probe, a 7z tail
//!   prefetch) is never parked: somebody is blocked on it by name.
//!
//! The counters here are per GROUP of files ([`Work::file`] is the
//! extractor slot; a park call names a group's slots and a later call
//! naming any of them joins the same group), kept beside the in-flight
//! map rather than derived from it so the per-candidate test in
//! `next_work` is two map lookups under one lock and never a scan of
//! every article in flight. An article is counted at the PICK, under
//! the queue lock (`next_work`), and uncounted wherever a picked
//! original leaves a worker's pipeline: `deregister_inflight`,
//! `deregister_inflight_done`, and the one 430 path that removes its
//! own map entry (`handle_missing`). Counting at registration instead
//! - a socket write after the pick - let every idle worker pass the
//! one-in-flight floor in that window at once: 60 x 700 KB on the
//! 22 Aug rig, the whole margin, and the cap broke. The pairing is
//! audited by the pops from the pipeline deque (there are five); a
//! missed one would leak the count UP, starve the floor and hang the
//! parked group, so a new retirement path MUST call `note_left`.

use super::*;

/// One parked group: its byte allowance and what it has in flight.
struct GroupPark {
    /// Bytes the group may have in flight ([`EST_BODY_BYTES`] each).
    allow: u64,
    /// In-flight originals (dups ride their original's entry). Seeded
    /// from the in-flight map when a file is first parked - the
    /// articles already on the wire for it land whatever the allowance
    /// says, and a park that ignored them admitted the whole room on
    /// top (four legs in four breached on the 22 Aug rig). From then on
    /// it moves with pick/retire, PAIRED BY ARTICLE ID through
    /// [`FilePark::counted`]: an article the seed did not see and the
    /// pick did not count (it was picked before the park existed and
    /// was still inside its send await when the seed scanned) subtracts
    /// NOTHING when it lands. An anonymous saturating decrement ate a
    /// post-park sibling's increment instead, so a one-body group read
    /// empty while that sibling was live and the allowance admitted
    /// another body on top - permanently, since nothing re-seeds.
    inflight: u32,
}

impl GroupPark {
    /// Is the allowance binding right now?
    fn full(&self) -> bool {
        self.inflight > 0 && u64::from(self.inflight).saturating_mul(EST_BODY_BYTES) >= self.allow
    }
}

pub(super) struct FilePark {
    /// Parked file -> its group id.
    files: std::sync::Mutex<HashMap<u32, u32>>,
    /// Fast-path mirror of `!files.is_empty()`: one relaxed load per
    /// candidate while nothing is parked, which is nearly always.
    any: AtomicBool,
    groups: std::sync::Mutex<HashMap<u32, GroupPark>>,
    /// Article id -> the group its dispatch was counted against, so a
    /// retirement decrements the increment it made and nobody else's.
    /// `next_group` is monotonic, so the group id is a generation too:
    /// an article that outlives its group's release finds no entry to
    /// decrement rather than one belonging to a later park of the same
    /// file.
    counted: std::sync::Mutex<HashMap<Arc<str>, u32>>,
    /// Next group id.
    next_group: AtomicU64,
    /// Candidates stepped past because their group was at its
    /// allowance (diagnostics; monotonic).
    deferred: AtomicU64,
}

impl FilePark {
    pub(super) fn new() -> FilePark {
        FilePark {
            files: std::sync::Mutex::new(HashMap::new()),
            any: AtomicBool::new(false),
            groups: std::sync::Mutex::new(HashMap::new()),
            counted: std::sync::Mutex::new(HashMap::new()),
            next_group: AtomicU64::new(1),
            deferred: AtomicU64::new(0),
        }
    }

    /// Park the given files with `allow` bytes in flight between them
    /// (`Some`), or release them (`None`). Idempotent either way. A park
    /// joins the group of any file in it that is already parked (a slot
    /// that joined a chased set late, or a refreshed allowance), else
    /// opens a new one. `inflight_of` answers WHICH originals of a file
    /// are on the wire right now, by article id; it is asked once per
    /// file, the first time that file is parked. Ids rather than a
    /// count so a seeded article's own retirement decrements the seed
    /// it made - a count alone left them unowned, and a pick-time flag
    /// would leave them undecrementable and leak the count upward.
    pub(super) fn set(
        &self,
        files: &[u32],
        allow: Option<u64>,
        inflight_of: impl Fn(u32) -> Vec<Arc<str>>,
    ) {
        let mut f = self.files.lock_ok();
        let mut g = self.groups.lock_ok();
        match allow {
            Some(allow) => {
                let group = files
                    .iter()
                    .find_map(|file| f.get(file).copied())
                    .unwrap_or_else(|| self.next_group.fetch_add(1, Ordering::Relaxed) as u32);
                let entry = g.entry(group).or_insert(GroupPark { allow, inflight: 0 });
                entry.allow = allow;
                let mut seeded: Vec<Arc<str>> = Vec::new();
                for &file in files {
                    if f.insert(file, group).is_none() {
                        let ids = inflight_of(file);
                        entry.inflight += ids.len() as u32;
                        seeded.extend(ids);
                    }
                }
                if !seeded.is_empty() {
                    let mut c = self.counted.lock_ok();
                    for id in seeded {
                        c.insert(id, group);
                    }
                }
            }
            None => {
                let mut gone: Vec<u32> = Vec::new();
                for file in files {
                    if let Some(group) = f.remove(file)
                        && !f.values().any(|&x| x == group)
                    {
                        g.remove(&group);
                        gone.push(group);
                    }
                }
                if !gone.is_empty() {
                    // The ownership map is otherwise drained by
                    // retirement; a released group's stragglers would
                    // sit in it until they land, so drop them here and
                    // keep it bounded by what is actually parked.
                    self.counted.lock_ok().retain(|_, g| !gone.contains(g));
                }
            }
        }
        self.any.store(!f.is_empty(), Ordering::Release);
    }

    /// Is anything parked right now?
    pub(super) fn is_on(&self) -> bool {
        self.any.load(Ordering::Acquire)
    }

    /// Is any group's allowance binding right now? The signal an idle
    /// worker reads: the queue is not dry, it is governed.
    pub(super) fn is_throttling(&self) -> bool {
        self.is_on() && self.groups.lock_ok().values().any(GroupPark::full)
    }

    pub(super) fn deferred(&self) -> u64 {
        self.deferred.load(Ordering::Relaxed)
    }

    /// Should `next_work` step past this candidate? True only for an
    /// unpromoted article of a parked group that is at its allowance.
    pub(super) fn defers(&self, w: &Work) -> bool {
        if !self.is_on() || w.promoted || w.file == u32::MAX {
            return false;
        }
        let Some(group) = self.files.lock_ok().get(&w.file).copied() else {
            return false;
        };
        let busy = self
            .groups
            .lock_ok()
            .get(&group)
            .is_some_and(GroupPark::full);
        if busy {
            self.deferred.fetch_add(1, Ordering::Relaxed);
        }
        busy
    }

    /// The group `file` is parked under, if it is.
    fn group_of(&self, file: u32) -> Option<u32> {
        if !self.is_on() || file == u32::MAX {
            return None;
        }
        self.files.lock_ok().get(&file).copied()
    }

    /// `next_work` picked this original (under the queue lock).
    pub(super) fn note_pick(&self, w: &Work) {
        if w.dup {
            return;
        }
        if let Some(group) = self.group_of(w.file)
            && let Some(g) = self.groups.lock_ok().get_mut(&group)
        {
            g.inflight += 1;
            self.counted.lock_ok().insert(w.id.clone(), group);
        }
    }

    /// An original left the in-flight map, however it left. Decrements
    /// only the group this very dispatch was counted against: a pick
    /// taken before its file was parked counted nothing and must
    /// subtract nothing, or it steals a live sibling's increment.
    pub(super) fn note_left(&self, w: &Work) {
        // Bound in its own statement so the `counted` guard is dropped
        // before `groups` is taken: `set` holds `groups` and reaches
        // for `counted`, so holding them the other way round is AB/BA.
        let owed = self.counted.lock_ok().remove(&w.id);
        if let Some(group) = owed
            && let Some(g) = self.groups.lock_ok().get_mut(&group)
        {
            g.inflight = g.inflight.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(file: u32, promoted: bool) -> Work {
        named("<x@mock>", file, promoted)
    }

    fn named(id: &str, file: u32, promoted: bool) -> Work {
        Work {
            id: Arc::from(id),
            attempts: 0,
            promoted,
            tried_430: 0,
            tried_fail: 0,
            dup: false,
            prebyte_expiries: 0,
            soft_430: 0,
            fenced: false,
            rearms: 0,
            ladder: false,
            probe: false,
            age_days: 0,
            part: 0,
            file,
            ord: 0,
        }
    }

    #[test]
    fn a_parked_group_is_admitted_to_its_allowance_and_never_below_one() {
        let p = FilePark::new();
        let a = named("<a@mock>", 3, false);
        let b = named("<b@mock>", 5, false);
        assert!(!p.defers(&work(3, false)), "nothing parked: never defers");
        // Room for two bodies.
        p.set(&[3, 5], Some(2 * EST_BODY_BYTES), |_| Vec::new());
        assert!(p.is_on());
        assert!(!p.is_throttling());
        assert!(!p.defers(&work(3, false)));
        p.note_pick(&a);
        assert!(
            !p.defers(&work(5, false)),
            "one body in flight, room for two"
        );
        p.note_pick(&b);
        assert!(p.defers(&work(3, false)), "at the allowance: stepped past");
        assert!(p.is_throttling());
        assert_eq!(p.deferred(), 1);
        // Other files and promoted articles are never parked.
        assert!(!p.defers(&work(4, false)));
        assert!(!p.defers(&work(3, true)));
        assert!(!p.defers(&work(u32::MAX, false)));
        // A refreshed allowance reopens admission; a zero allowance
        // still admits one when nothing is in flight.
        p.set(&[3, 5], Some(3 * EST_BODY_BYTES), |_| Vec::new());
        assert!(!p.defers(&work(3, false)));
        p.set(&[3, 5], Some(0), |_| Vec::new());
        assert!(p.defers(&work(3, false)));
        p.note_left(&a);
        p.note_left(&b);
        assert!(
            !p.defers(&work(3, false)),
            "nothing in flight: the liveness floor"
        );
        // A late joiner lands in the same group and shares its count.
        p.note_pick(&named("<c@mock>", 3, false));
        p.set(&[7, 3], Some(0), |_| Vec::new());
        assert!(p.defers(&work(7, false)));
        // Release clears everything.
        p.set(&[3, 5, 7], None, |_| Vec::new());
        assert!(!p.is_on());
        assert!(!p.defers(&work(3, false)));
        assert!(p.groups.lock_ok().is_empty());
        assert!(p.counted.lock_ok().is_empty(), "release drains ownership");
    }

    #[test]
    fn a_park_counts_what_is_already_on_the_wire() {
        let p = FilePark::new();
        // Two bodies of room, but two of file 3's articles are already
        // in flight when it parks: nothing more is admitted until one
        // lands.
        p.set(&[3], Some(2 * EST_BODY_BYTES), |file| {
            if file == 3 {
                vec![Arc::from("<s1@mock>"), Arc::from("<s2@mock>")]
            } else {
                Vec::new()
            }
        });
        assert!(p.defers(&work(3, false)));
        p.note_left(&named("<s1@mock>", 3, false));
        assert!(!p.defers(&work(3, false)));
        // Re-parking the same file does not seed it twice.
        p.set(&[3], Some(2 * EST_BODY_BYTES), |_| {
            vec![Arc::from("<never@mock>")]
        });
        assert!(!p.defers(&work(3, false)));
        // The other seeded article still owns its own decrement, so the
        // count comes all the way back to zero and the group cannot
        // hang behind a leaked increment.
        p.note_left(&named("<s2@mock>", 3, false));
        assert_eq!(p.groups.lock_ok()[&1].inflight, 0);
    }

    #[test]
    fn leaving_without_a_dispatch_never_underflows() {
        let p = FilePark::new();
        let a = named("<a@mock>", 7, false);
        p.note_left(&a);
        p.note_pick(&a); // unparked: not counted
        p.set(&[7], Some(0), |_| Vec::new());
        p.note_left(&a);
        let b = named("<b@mock>", 7, false);
        p.note_pick(&b);
        p.note_left(&b);
        p.note_left(&b);
        assert_eq!(p.groups.lock_ok()[&1].inflight, 0);
    }

    /// F-13: an article picked BEFORE its file parked was never
    /// counted, and the seed cannot see it either - it is still inside
    /// its send await when `park_files` scans the in-flight map. Its
    /// retirement must therefore subtract nothing. The anonymous
    /// decrement it had instead ate a post-park sibling's increment, so
    /// a one-body group read empty while that sibling was live and the
    /// allowance admitted a second body on top.
    #[test]
    fn a_pre_park_pick_never_subtracts_a_post_park_sibling() {
        let p = FilePark::new();
        let a = named("<a@mock>", 3, false);
        let b = named("<b@mock>", 3, false);
        p.note_pick(&a); // before the park: uncounted
        p.set(&[3], Some(EST_BODY_BYTES), |_| Vec::new()); // A is not on the map yet
        p.note_pick(&b); // after the park: counted
        assert!(p.defers(&work(3, false)), "one body of room, B holds it");
        p.note_left(&a);
        assert!(
            p.defers(&work(3, false)),
            "A was never counted and must not subtract B"
        );
        assert_eq!(p.groups.lock_ok()[&1].inflight, 1);
        // B's own retirement still reopens the floor.
        p.note_left(&b);
        assert!(!p.defers(&work(3, false)));
    }

    /// The mirror of the pin above, and the reason the fix is an
    /// identity rather than a pick-time flag: a SEEDED article was
    /// picked before the park by construction, so a flag would leave it
    /// undecrementable, the count would leak upward and the group would
    /// hang behind its own allowance - worse than the over-admission.
    #[test]
    fn a_seeded_article_still_owns_an_exact_decrement() {
        let p = FilePark::new();
        p.set(&[3], Some(EST_BODY_BYTES), |_| {
            vec![Arc::from("<seed@mock>")]
        });
        assert!(p.defers(&work(3, false)), "the seed fills the allowance");
        // A stranger's retirement leaves the seed's count alone.
        p.note_left(&named("<other@mock>", 3, false));
        assert!(p.defers(&work(3, false)));
        p.note_left(&named("<seed@mock>", 3, false));
        assert_eq!(p.groups.lock_ok()[&1].inflight, 0);
        assert!(!p.defers(&work(3, false)), "the floor reopens");
        // And a second landing of the same id cannot underflow it back
        // into an over-admitting state it has already paid for.
        p.note_left(&named("<seed@mock>", 3, false));
        assert_eq!(p.groups.lock_ok()[&1].inflight, 0);
    }
}
