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

/// Count one dispatch of `id` against `group`, EXACTLY once.
///
/// The books here are an identity, not a tally: `GroupPark::inflight` is
/// by construction the number of ids [`FilePark::counted`] maps to that
/// group. Both increments go through here so neither can break it.
///
/// A second increment for an id the group already owns is the failure
/// this exists to refuse. It leaves a count no retirement can ever
/// match - `note_left` decrements once per id, because that is where the
/// ownership entry is removed - so the group's `inflight` never comes
/// back to zero, `GroupPark::full` is true forever whatever the
/// allowance says, and the one-article liveness floor at the top of it
/// never fires again. The group starves for the rest of the run. That is
/// the 3 Sep 2026 wedge, measured on a loopback rig at a holds cap 37x
/// under the set: one leg in thirty ran 195 s, exited 1 with no payload,
/// and its dump showed `inflight=0` in the POOL's own in-flight map with
/// the park still stepping past every candidate.
///
/// The reachable double is the re-seed: [`FilePark::set`] seeds a file
/// from the in-flight map the first time that file is parked, and a file
/// released from a group that SURVIVES (a partial release - the other
/// files keep it alive, so `counted` is not drained) is seeded again if
/// it later rejoins. Its articles are still owned by that same group, so
/// the seed counted them twice.
///
/// An id owned by a DIFFERENT live group moves with its ownership rather
/// than being left stranded there: `counted` is the only record of which
/// increment a retirement will pay off, so the two must not disagree.
fn count_one(
    groups: &mut HashMap<u32, GroupPark>,
    counted: &mut HashMap<Arc<str>, u32>,
    id: Arc<str>,
    group: u32,
) {
    if !groups.contains_key(&group) {
        return;
    }
    match counted.insert(id, group) {
        // Already this group's: its increment is already standing.
        Some(prev) if prev == group => {}
        Some(prev) => {
            if let Some(g) = groups.get_mut(&prev) {
                g.inflight = g.inflight.saturating_sub(1);
            }
            if let Some(g) = groups.get_mut(&group) {
                g.inflight += 1;
            }
        }
        None => {
            if let Some(g) = groups.get_mut(&group) {
                g.inflight += 1;
            }
        }
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
    /// Deferrals the pool-idle floor refused (diagnostics; monotonic).
    floor_rescues: AtomicU64,
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
            floor_rescues: AtomicU64::new(0),
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
                g.entry(group)
                    .or_insert(GroupPark { allow, inflight: 0 })
                    .allow = allow;
                let mut seeded: Vec<Arc<str>> = Vec::new();
                for &file in files {
                    if f.insert(file, group).is_none() {
                        seeded.extend(inflight_of(file));
                    }
                }
                if !seeded.is_empty() {
                    // Through `count_one` and NOT a `+= ids.len()`: a
                    // file that rejoins a group it was released from
                    // (the group outlived the release, so `counted`
                    // still owns its articles) is seeded a second time,
                    // and the flat add counted those articles twice -
                    // the increment that can never be paid off. See
                    // `count_one`.
                    let mut c = self.counted.lock_ok();
                    for id in seeded {
                        count_one(&mut g, &mut c, id, group);
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
    ///
    /// `pool_idle` is the pool's OWN in-flight map being empty, read once
    /// per scan by the caller. It is the authoritative form of the
    /// liveness floor `GroupPark::full` estimates with a paired counter,
    /// and it has the last word over it. The module header states that
    /// floor as a rule - "a parked group with NOTHING in flight is
    /// always admitted one article, whatever its allowance" - and a rule
    /// that keeps a whole download alive must not rest on an estimate:
    /// one unpaired increment makes the estimate permanently non-zero
    /// and turns a throughput dip into a deadlock (3 Sep 2026: a leg ran
    /// 195 s and exited with no payload, `inflight=0` in the map with
    /// this predicate still true). `count_one` is what keeps the
    /// estimate exact; this is what stops an exactness bug ever costing
    /// a download again. The map cannot lie, and a snapshot that goes
    /// stale can only admit ONE extra article - which is the floor
    /// itself.
    pub(super) fn defers(&self, w: &Work, pool_idle: bool) -> bool {
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
        if busy && pool_idle {
            // LOUD, once per run. A rescue means this park's own count
            // and the pool's in-flight map disagree about whether
            // anything is on the wire, which is a pairing bug and never
            // a tuning question - and the 3 Sep 2026 wedge cost a day
            // precisely because the same disagreement was silent.
            if self.floor_rescues.fetch_add(1, Ordering::Relaxed) == 0 {
                warn!(
                    target: "pool",
                    "held-bytes park: admitted a parked article the allowance refused -                      the pool has nothing in flight, so the park's own count is stale"
                );
            }
            return false;
        }
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
        if let Some(group) = self.group_of(w.file) {
            // `groups` then `counted`, the same order `set` takes them
            // in - `note_left` is the one that must take neither while
            // holding the other (see its own note).
            let mut g = self.groups.lock_ok();
            let mut c = self.counted.lock_ok();
            count_one(&mut g, &mut c, w.id.clone(), group);
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

    /// THE BOOKS ARE AN IDENTITY: every group's `inflight` is the number
    /// of ids `counted` maps to it. `count_one` is what enforces it and
    /// this is what the rig checks after every path - a drift either way
    /// is a real defect, and the UPWARD one wedges the group for the
    /// rest of the run (see `count_one`).
    fn books_balance(p: &FilePark) {
        let g = p.groups.lock_ok();
        let c = p.counted.lock_ok();
        for (&group, park) in g.iter() {
            let owned = c.values().filter(|&&x| x == group).count() as u32;
            assert_eq!(
                park.inflight, owned,
                "group {group}: inflight {} against {owned} owned id(s)",
                park.inflight
            );
        }
        // And nothing may be owned by a group that no longer exists -
        // a release drains ownership, so a straggler entry would give
        // some later group a decrement it never earned.
        for (id, group) in c.iter() {
            assert!(
                g.contains_key(group),
                "{id} still owned by the departed group {group}"
            );
        }
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
            recheck_430: 0,
            recheck_at: 0,
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
        assert!(
            !p.defers(&work(3, false), false),
            "nothing parked: never defers"
        );
        // Room for two bodies.
        p.set(&[3, 5], Some(2 * EST_BODY_BYTES), |_| Vec::new());
        assert!(p.is_on());
        assert!(!p.is_throttling());
        assert!(!p.defers(&work(3, false), false));
        p.note_pick(&a);
        assert!(
            !p.defers(&work(5, false), false),
            "one body in flight, room for two"
        );
        p.note_pick(&b);
        assert!(
            p.defers(&work(3, false), false),
            "at the allowance: stepped past"
        );
        assert!(p.is_throttling());
        assert_eq!(p.deferred(), 1);
        // Other files and promoted articles are never parked.
        assert!(!p.defers(&work(4, false), false));
        assert!(!p.defers(&work(3, true), false));
        assert!(!p.defers(&work(u32::MAX, false), false));
        // A refreshed allowance reopens admission; a zero allowance
        // still admits one when nothing is in flight.
        p.set(&[3, 5], Some(3 * EST_BODY_BYTES), |_| Vec::new());
        assert!(!p.defers(&work(3, false), false));
        p.set(&[3, 5], Some(0), |_| Vec::new());
        assert!(p.defers(&work(3, false), false));
        p.note_left(&a);
        p.note_left(&b);
        assert!(
            !p.defers(&work(3, false), false),
            "nothing in flight: the liveness floor"
        );
        // A late joiner lands in the same group and shares its count.
        p.note_pick(&named("<c@mock>", 3, false));
        p.set(&[7, 3], Some(0), |_| Vec::new());
        assert!(p.defers(&work(7, false), false));
        // Release clears everything.
        p.set(&[3, 5, 7], None, |_| Vec::new());
        assert!(!p.is_on());
        assert!(!p.defers(&work(3, false), false));
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
        assert!(p.defers(&work(3, false), false));
        p.note_left(&named("<s1@mock>", 3, false));
        assert!(!p.defers(&work(3, false), false));
        // Re-parking the same file does not seed it twice.
        p.set(&[3], Some(2 * EST_BODY_BYTES), |_| {
            vec![Arc::from("<never@mock>")]
        });
        assert!(!p.defers(&work(3, false), false));
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
        assert!(
            p.defers(&work(3, false), false),
            "one body of room, B holds it"
        );
        p.note_left(&a);
        assert!(
            p.defers(&work(3, false), false),
            "A was never counted and must not subtract B"
        );
        assert_eq!(p.groups.lock_ok()[&1].inflight, 1);
        // B's own retirement still reopens the floor.
        p.note_left(&b);
        assert!(!p.defers(&work(3, false), false));
    }

    /// THE WEDGE (3 Sep 2026). A file released from a group that
    /// SURVIVES the release - its siblings keep it alive, so `counted`
    /// is not drained - and then rejoining it is seeded from the
    /// in-flight map a SECOND time. Before `count_one` the seed's flat
    /// `+= ids.len()` counted those articles twice, and only one
    /// retirement per id can ever come back: the group's count never
    /// reached zero again, `full()` stayed true whatever the allowance,
    /// and the one-article liveness floor never fired. Measured as a
    /// 195 s leg that exited 1 with no payload, `inflight=0` in the
    /// pool's own map, the chase parked 100% at a hole.
    #[test]
    fn a_file_rejoining_a_surviving_group_is_not_seeded_twice() {
        let p = FilePark::new();
        let on_the_wire = |file: u32| {
            if file == 3 {
                vec![Arc::from("<a@mock>")]
            } else {
                Vec::new()
            }
        };
        p.set(&[3, 5], Some(EST_BODY_BYTES * 4), on_the_wire);
        assert_eq!(p.groups.lock_ok()[&1].inflight, 1);
        books_balance(&p);
        // File 3 stops chasing: a PARTIAL release. File 5 keeps group 1
        // alive, so file 3's article is still owned by it.
        p.set(&[3], None, |_| Vec::new());
        assert_eq!(p.groups.lock_ok()[&1].inflight, 1, "the group survives");
        books_balance(&p);
        // ... and rejoins. The refresh always names the WHOLE parked
        // set, so the rejoin finds group 1 through file 5.
        p.set(&[5, 3], Some(EST_BODY_BYTES * 4), on_the_wire);
        books_balance(&p);
        p.note_left(&named("<a@mock>", 3, false));
        assert_eq!(
            p.groups.lock_ok()[&1].inflight,
            0,
            "one article, one increment, one decrement"
        );
        assert!(
            !p.defers(&work(5, false), false),
            "and the liveness floor is back"
        );
        books_balance(&p);
    }

    /// The same identity from the other side: a second PICK of an id the
    /// group already owns cannot double-count it either. No production
    /// path re-picks a counted original today (every requeue deregisters
    /// first), which is exactly why this is a pin and not a bug report -
    /// a new requeue path that forgot its `note_left` would otherwise
    /// wedge the group instead of merely over-admitting.
    #[test]
    fn a_second_pick_of_a_counted_article_counts_once() {
        let p = FilePark::new();
        let a = named("<a@mock>", 3, false);
        p.set(&[3], Some(0), |_| Vec::new());
        p.note_pick(&a);
        p.note_pick(&a);
        assert_eq!(p.groups.lock_ok()[&1].inflight, 1);
        books_balance(&p);
        p.note_left(&a);
        assert_eq!(p.groups.lock_ok()[&1].inflight, 0);
        books_balance(&p);
    }

    /// THE RIG the wedge asked for: drive a parked group through every
    /// path that can put an article into the pool's in-flight map or
    /// take it out again, and assert the count comes back to zero after
    /// each. The pool-side pairing is audited in
    /// `crates/nzbkit/src/pool/hedge.rs` (`deregister_inflight`,
    /// `deregister_inflight_done`) and `session.rs` (the 430 path in
    /// `handle_missing`); all three funnel into `note_left`, which is
    /// what this drives - a dup is never counted at all, so its own
    /// retirement is a no-op here by construction.
    #[test]
    fn every_retirement_path_returns_the_count_to_zero() {
        let p = FilePark::new();
        // Seeded (the articles already on the wire when the file parks).
        p.set(&[3], Some(EST_BODY_BYTES * 8), |_| {
            vec![Arc::from("<seed@mock>")]
        });
        // Picked after the park.
        let picked = named("<pick@mock>", 3, false);
        p.note_pick(&picked);
        // A dup rides its original's entry and is never counted.
        let mut dup = named("<pick@mock>", 3, false);
        dup.dup = true;
        p.note_pick(&dup);
        assert_eq!(p.groups.lock_ok()[&1].inflight, 2);
        books_balance(&p);
        // A late joiner: same group, seeded from its own wire.
        p.set(&[3, 4], Some(EST_BODY_BYTES * 8), |file| {
            if file == 4 {
                vec![Arc::from("<join@mock>")]
            } else {
                Vec::new()
            }
        });
        assert_eq!(p.groups.lock_ok()[&1].inflight, 3);
        books_balance(&p);
        // Retire all three, once each, however they left the map.
        for id in ["<seed@mock>", "<pick@mock>", "<join@mock>"] {
            p.note_left(&named(id, 3, false));
            books_balance(&p);
        }
        assert_eq!(p.groups.lock_ok()[&1].inflight, 0);
        // A dup's retirement subtracts nothing (its pick added nothing).
        p.note_left(&dup);
        assert_eq!(p.groups.lock_ok()[&1].inflight, 0);
        // And a release drains the ownership map with the group.
        p.set(&[3, 4], None, |_| Vec::new());
        assert!(p.groups.lock_ok().is_empty());
        assert!(p.counted.lock_ok().is_empty());
        books_balance(&p);
    }

    /// The authoritative floor: whatever the estimate says, a pool with
    /// NOTHING in flight admits the candidate. This is what turns any
    /// future counting bug back into a throughput dip instead of the
    /// 195 s deadlock.
    #[test]
    fn an_empty_pool_map_always_overrides_a_full_group() {
        let p = FilePark::new();
        p.set(&[3], Some(0), |_| Vec::new());
        p.note_pick(&named("<a@mock>", 3, false));
        assert!(p.defers(&work(3, false), false), "the estimate says full");
        assert!(
            !p.defers(&work(3, false), true),
            "the pool's own map has the last word"
        );
        assert_eq!(p.floor_rescues.load(Ordering::Relaxed), 1);
        // The estimate's own deferral count is not charged for a
        // rescued candidate: it is answering a different question.
        assert_eq!(p.deferred(), 1);
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
        assert!(
            p.defers(&work(3, false), false),
            "the seed fills the allowance"
        );
        // A stranger's retirement leaves the seed's count alone.
        p.note_left(&named("<other@mock>", 3, false));
        assert!(p.defers(&work(3, false), false));
        p.note_left(&named("<seed@mock>", 3, false));
        assert_eq!(p.groups.lock_ok()[&1].inflight, 0);
        assert!(!p.defers(&work(3, false), false), "the floor reopens");
        // And a second landing of the same id cannot underflow it back
        // into an over-admitting state it has already paid for.
        p.note_left(&named("<seed@mock>", 3, false));
        assert_eq!(p.groups.lock_ok()[&1].inflight, 0);
    }
}
