//! TODO 205: what the DISK unpack ladder is doing, while it does it.
//!
//! The in-stream one-pass path has had a real progress lane since M11:
//! `get/vrig.rs` installs its extractor on the hub, `api/queue.rs`
//! reads `writers_snapshot()` off it, and the dashboard draws
//! `lane('extract', …)` from the written/size pairs. The DISK ladder in
//! `get/tail.rs` - where an obfuscated volume set goes, and where issue
//! #47's 130-volume set lands - had nothing: one `note_activity(
//! "extracting")` at the top and silence for however many minutes the
//! unpack ran. On a NAS that is several minutes of a queue row saying
//! one static word, which reads as a hang (the same failure U1 fixed
//! for the write-out tail).
//!
//! # Why this rather than the writers the in-stream path publishes
//!
//! `hub.extractor` is a SINGLE slot, and the daemon clears it and
//! re-points it at the NEXT job the moment `net_done` fires
//! (`tasks/runner.rs`) - which is BEFORE this ladder runs, since
//! the whole point of the tail/fetch overlap is that job N unpacks
//! while job N+1 downloads. Writers registered there by this ladder
//! would be wiped by the next job, or worse, appear inside the lane the
//! page is drawing for it. `hub.activity` is keyed per nzo_id precisely
//! because a tail outlives its own download, so this rides beside it
//! with the same ownership.
//!
//! # Why bytes rather than "volume 47 of 130"
//!
//! rars CAN report the walk leaving each volume -
//! `extract_volumes_to_with_progress`, which §101's volume-eating mode
//! already uses. Arming it DISABLES the RAR5 parallel member pool
//! (`rar50::extract::extract_volumes_to_impl`: the pool reads members
//! across the whole set at once, so a consumption watermark would stop
//! being true), and a compressed multi-member set would pay real
//! parallelism for a progress line. The byte counter the bomb guard
//! already keeps costs nothing and is finer-grained anyway - a
//! 130-volume set holding ONE split member reports 130 times either
//! way, and the bytes move continuously between those points.
//!
//! The volume COUNT is the other half of what #47 asked for ("whether
//! there is 1 volume or 130"), and that is known exactly at ladder
//! entry: the set is fully on disk by then.
//!
//! # Scope
//!
//! The COUNT covers the whole ladder: it is taken at the top of
//! `unpack_tail`, before any arm runs, so every route says how big a
//! set it is working through.
//!
//! The BYTES cover every arm of it, and did not at first. The original
//! change took `rarfix::write_archives_to_spending` alone - every RAR
//! volume-set unpack the ladder does: the obfuscated route (issue #47's
//! own shape), `try_rars_native` for a named demoted set, and the eating
//! and header-encrypted arms of the resumed-run re-extract - and left
//! two routes showing the volume count with no lane under it, which its
//! own scope note called out as small follow-ups. They are done (23 Aug
//! 2026), and neither could reuse the shape the RAR arms did:
//!
//!  - `repair::reextract_dir_outcome`'s PLAIN branch feeds the volumes
//!    to nzbkit's own [`nzbkit::extract::Extractor`] rather than to
//!    `write_archives_to_spending`, so there is no `written`
//!    accumulator to hand over - and no header total either, because
//!    that extractor learns each member as the feed reaches its header.
//!    It reports through [`raise_total`], sampling the extractor's own
//!    output writers (`writers_snapshot`, the very ones the IN-STREAM
//!    lane reads) rather than counting anything a second time.
//!  - the nested 7z and zip arms report from
//!    `rarfix::extract_one_zip` / `sevenz::extract_one_sevenz`, whose
//!    `written` accumulator is the same bomb-guard counter the RAR arm
//!    publishes. Both are password-CANDIDATE loops, which is why
//!    [`attempt`] exists apart from [`watch`]: a zip that takes three
//!    harvested candidates makes three passes at ONE set, and folding
//!    each into the running total the way a new set is folded would
//!    leave the lane stuck at a third of a total that never happens.
//!
//! # Retries
//!
//! Every one of those arms can have ANOTHER go at a set it has already
//! reported: the mismatch rewind inside `write_archives_to_spending`,
//! `unpack::unpack_named_rar`'s `.rev` and recovery-record rungs,
//! `sfx::extract_sfx`'s carve fallback, and
//! `repair::reextract_dir_outcome` falling through from its native
//! shortcut to the plain feed. A retry is not a new set and must not be
//! banked as one, or the row reports twice the bytes the extraction can
//! ever produce. [`mark`] is what puts the lane back between two goes.

use crate::tools::MutexExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// One job's live disk-unpack progress. Read by the queue payload on
/// every poll, so the ladder advances it in place rather than by
/// publishing a snapshot somebody has to remember to take.
#[derive(Default, Debug)]
pub struct UnpackProgress {
    /// Volume files of the downloaded set on disk when the ladder
    /// started. Fixed for its life - the set has fully landed by now.
    volumes: u64,
    /// Unpacked bytes from sets this ladder has already finished with.
    base: AtomicU64,
    /// Header totals of those same sets.
    base_total: AtomicU64,
    /// The set being extracted right now, and the attempt at it.
    cur: std::sync::Mutex<CurSet>,
}

/// The set in flight. Separate from the two `base` counters above, and
/// not folded into them until the ladder moves on, because an arm may
/// make several ATTEMPTS at one set - the zip and 7z arms walk a
/// password shortlist - and only the last of them is what the set
/// produced.
#[derive(Default, Debug, Clone)]
struct CurSet {
    /// The live counter of the attempt in flight - the very `written`
    /// accumulator the extractor hands its bomb guard, so nothing extra
    /// is written on the hot path.
    written: Option<Arc<AtomicU64>>,
    /// Unpacked bytes this set is expected to produce. Known before the
    /// first byte flows wherever a parsed header declares it, so `done`
    /// can never lead it; discovered as the extraction runs on the one
    /// route whose extractor parses as it feeds (see [`raise_total`]).
    total: u64,
    /// Output a forfeited chase already wrote and this pass will decode
    /// past without writing (see [`crate::resumeout`]). In `total` like
    /// every other byte of the set, so it has to be in the numerator
    /// too or the row would climb to a ceiling short of 100% and sit
    /// there.
    resumed: u64,
}

impl CurSet {
    /// Bytes this attempt has put on disk, its resumed prefix included.
    fn done(&self) -> u64 {
        self.written
            .as_ref()
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
            .saturating_add(self.resumed)
    }
}

impl UnpackProgress {
    /// Volume files this ladder started with. 0 when nothing was
    /// countable, which the page reads as "say nothing about volumes".
    pub fn volumes(&self) -> u64 {
        self.volumes
    }

    /// Unpacked bytes expected, or 0 while no set has been parsed yet.
    pub fn total(&self) -> u64 {
        self.base_total
            .load(Ordering::Relaxed)
            .saturating_add(self.cur.lock_ok().total)
    }

    /// Unpacked bytes produced so far, across every set this ladder has
    /// run. Clamped to `total`: a set that fails part-way still wrote
    /// the bytes it wrote, and a fraction over 1 reads as a bug.
    pub fn done(&self) -> u64 {
        let cur = self.cur.lock_ok();
        self.base
            .load(Ordering::Relaxed)
            .saturating_add(cur.done())
            .min(
                self.base_total
                    .load(Ordering::Relaxed)
                    .saturating_add(cur.total),
            )
    }
}

/// The live ladders a hub is publishing, keyed by owning nzo_id.
///
/// Named here rather than spelled out in `StreamHub`'s field, since the
/// crate-split prep (step 1 of
/// research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md): [`arm`] used to
/// take the HUB, which had this module reaching into `streamhub` while
/// `streamhub` named `UnpackProgress` back - a 2-cycle over one
/// `HashMap`. Taking the map keeps every field of [`UnpackProgress`]
/// private to this module, which handing the type to `streamhub` would
/// not have.
pub(crate) type UnpackMap =
    std::sync::Mutex<std::collections::HashMap<String, Arc<UnpackProgress>>>;

thread_local! {
    /// The ladder running on THIS thread, if any. A thread-local for the
    /// same reason `eatvol::ARMED` is one, and safe for the same reason:
    /// `finish_run` runs the tail through `lanegate::off_worker`, which
    /// is `block_in_place` rather than `spawn_blocking`, so the whole
    /// ladder - arm, extract, drop - stays on one thread.
    static LIVE: std::cell::RefCell<Option<Arc<UnpackProgress>>> =
        const { std::cell::RefCell::new(None) };
}

/// The ladder's registration: live for as long as the guard is held,
/// both on this thread and in the hub map the queue payload reads.
///
/// Restores whatever was armed before (nested ladders do not exist
/// today, but a guard that only ever clears is a trap waiting for the
/// first one), and takes the hub entry back down with it - so a job that
/// finishes, fails or panics its way out of the tail leaves no row
/// claiming to be unpacking.
pub struct UnpackArm {
    prev: Option<Arc<UnpackProgress>>,
    map: Option<Arc<UnpackMap>>,
    owner: String,
}

/// Arm progress reporting for the ladder about to run on this thread.
///
/// `volumes` is what the caller counted on disk. No map means nobody is
/// listening (a CLI run, or a prefetch sidecar whose hub the queue
/// payload never reads), and the arm is inert - `watch` below then does
/// nothing at all, which is what keeps this free for the CLI.
///
/// The MAP and not the hub it hangs off: see [`UnpackMap`].
pub fn arm(map: Option<&Arc<UnpackMap>>, owner: &str, volumes: u64) -> UnpackArm {
    let Some(m) = map else {
        return UnpackArm {
            prev: None,
            map: None,
            owner: String::new(),
        };
    };
    let p = Arc::new(UnpackProgress {
        volumes,
        ..Default::default()
    });
    m.lock_ok().insert(owner.to_string(), p.clone());
    UnpackArm {
        prev: LIVE.with(|l| l.borrow_mut().replace(p)),
        map: Some(m.clone()),
        owner: owner.to_string(),
    }
}

impl Drop for UnpackArm {
    fn drop(&mut self) {
        if let Some(m) = &self.map {
            m.lock_ok().remove(&self.owner);
        }
        LIVE.with(|l| *l.borrow_mut() = self.prev.take());
    }
}

/// Report the set that is about to be extracted: `written` is the
/// accumulator its output writers feed, and `archives` the parsed
/// volumes it will be built from.
///
/// Called once per set, immediately before extraction - the RAR arms'
/// entry point, and [`begin_set`] plus [`attempt`] in one call because
/// those arms parse the whole set before the first byte moves. An arm
/// that walks a password shortlist, or that learns its total as it
/// feeds, wants the two halves separately.
pub fn watch(written: &Arc<AtomicU64>, archives: &[rars::Archive], resumed: u64) {
    begin_set();
    attempt(written, unpacked_total(archives), resumed);
}

/// The ladder moves on to a NEW set: fold what the last one produced
/// into the running totals and start the next one empty.
///
/// The previous set's final count is folded here rather than at its own
/// end, so a ladder that runs several sets (an obfuscated post holding
/// two releases, a RAR set beside a 7z) accumulates instead of
/// restarting at zero on each - and so an arm that never reaches its
/// extraction leaves nothing half-folded behind it.
pub fn begin_set() {
    with_live(|p| {
        let mut cur = p.cur.lock_ok();
        p.base.fetch_add(cur.done(), Ordering::Relaxed);
        p.base_total.fetch_add(cur.total, Ordering::Relaxed);
        *cur = CurSet::default();
    });
}

/// The attempt now starting at the current set: `written` is the
/// accumulator its output writers feed, `total` the bytes its parsed
/// headers say it will produce, and `resumed` the prefix a forfeited
/// chase already wrote.
///
/// REPLACES any earlier attempt at the same set rather than adding to
/// it. That is the whole reason this is not folded into [`watch`]: the
/// zip and 7z arms walk a password shortlist and call this once per
/// candidate, so three tries at one container must publish one total,
/// not three. Only [`begin_set`] banks what an attempt produced.
pub fn attempt(written: &Arc<AtomicU64>, total: u64, resumed: u64) {
    with_live(|p| {
        *p.cur.lock_ok() = CurSet {
            written: Some(written.clone()),
            total,
            resumed,
        };
    });
}

/// The progress state as it stands right now, so a RETRY of the work
/// about to run can be put back to it.
///
/// The ladder's arms retry. `write_archives_to_spending` runs its pass a
/// second time when a resumed prefix fails its verification (TODO 217),
/// `unpack::unpack_named_rar` re-enters the whole named ladder after a
/// `.rev` reconstruction and again for the recovery-record rung,
/// `sfx::extract_sfx` falls back to a carved copy of the archive it just
/// failed on, and `repair::reextract_dir_outcome` falls through from its
/// native shortcut to the plain feed. Every one of those is another go
/// at the SAME set, and without this each go was banked by [`begin_set`]
/// as though it were a new one - so a set that needed two tries reported
/// twice the bytes it will ever produce, and the lane under it read at
/// half the progress it had really made.
///
/// A REWIND rather than a "do not bank this time" flag, because what
/// retries is a LADDER and not a call: one re-entry of
/// `try_unrar_outcome` walks a whole group loop, banking one set per
/// group legitimately as it goes. Only restoring the state as a whole
/// can undo that, and restoring it lets the second run redo the same
/// banking from the same start - which is why [`Mark::rewind`] at the
/// TOP of a retry loop's body is correct rather than merely harmless:
/// on the first pass it restores the state to what it already is.
///
/// Inert when no ladder is armed (a CLI run, a hubless prefetch
/// sidecar), like every other reporting call in this module.
pub fn mark() -> Mark {
    let mut m = Mark(None);
    with_live(|p| {
        m = Mark(Some(Snapshot {
            base: p.base.load(Ordering::Relaxed),
            base_total: p.base_total.load(Ordering::Relaxed),
            cur: p.cur.lock_ok().clone(),
        }));
    });
    m
}

/// What [`mark`] took, and the retry's way back to it.
///
/// Not a `Drop` guard: the LAST attempt is the one that stands, so
/// rewinding on the way out would throw away the try that worked.
pub struct Mark(Option<Snapshot>);

/// The three fields [`UnpackProgress`] keeps that an attempt can move.
/// `volumes` is fixed for the ladder's life and so is not among them.
struct Snapshot {
    base: u64,
    base_total: u64,
    cur: CurSet,
}

impl Mark {
    /// Put the ladder back to where [`mark`] found it: the attempt that
    /// ran in between is about to be made again, and only its last try
    /// counts.
    pub fn rewind(&self) {
        let Some(s) = &self.0 else {
            return;
        };
        with_live(|p| {
            p.base.store(s.base, Ordering::Relaxed);
            p.base_total.store(s.base_total, Ordering::Relaxed);
            *p.cur.lock_ok() = s.cur.clone();
        });
    }
}

/// The current set expects at least `total` unpacked bytes after all.
///
/// For the arms that cannot declare a figure up front:
/// `repair::reextract_dir_outcome`'s plain branch feeds its volumes to
/// nzbkit's own extractor, which learns each member as the feed reaches
/// its header, and `rarfix::tar` walks a container whose format keeps
/// nothing at its tail, so neither total is parsed ahead of the
/// extraction the way a zip's central directory or a 7z's end header
/// lets those two arms parse theirs. Monotonic
/// HERE rather than in the caller - a total that goes backwards, or
/// that double-counts a figure sampled twice, reads on the page as an
/// unpack that lost ground, and the next arm shaped this way would have
/// to re-derive the bookkeeping to get it right.
pub fn raise_total(total: u64) {
    with_live(|p| {
        let mut cur = p.cur.lock_ok();
        cur.total = cur.total.max(total);
    });
}

/// Run `f` against the ladder armed on this thread, if there is one.
/// No ladder means nobody is listening (a CLI run, or a hubless
/// prefetch sidecar), and every reporting call above is inert.
fn with_live(f: impl FnOnce(&UnpackProgress)) {
    LIVE.with(|l| {
        if let Some(p) = l.borrow().as_ref() {
            f(p);
        }
    });
}

/// Bytes a parsed volume set will produce.
///
/// A member SPLIT across volumes repeats its whole-file header in every
/// volume it spans - measured on RAR5 (a 3,000,000-byte member across
/// six volumes reports `unpacked_size` 3,000,000 six times) and on RAR
/// 1.5-4 (`tests/fixtures/rar15_40/rar300/stored_multivol_rar300.*`
/// reports 3,360 four times) - so counting every member would multiply
/// the commonest shape of all by its volume count. Each file is counted
/// once, at the fragment that starts it.
///
/// `pub(crate)` for a second reader with more riding on that rule than a
/// progress bar has: `rarfix::preflight` weighs this figure against free
/// disk before handing a set to the external `unrar`, so a per-fragment
/// fold would call the commonest multi-volume shape there is twice its
/// real size and refuse an archive that fits.
pub fn unpacked_total(archives: &[rars::Archive]) -> u64 {
    archives
        .iter()
        .flat_map(|a| a.members())
        .filter(|m| !m.meta.is_directory && !m.meta.is_split_before)
        .fold(0u64, |acc, m| acc.saturating_add(m.meta.unpacked_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn armed(volumes: u64) -> (Arc<crate::streamhub::StreamHub>, UnpackArm) {
        let hub = Arc::new(crate::streamhub::StreamHub::default());
        let arm = arm(Some(&hub.unpack), "nzo-1", volumes);
        (hub, arm)
    }

    #[test]
    fn a_ladder_with_no_hub_registers_nothing_and_watch_is_inert() {
        let a = arm(None, "nzo-1", 130);
        let w = Arc::new(AtomicU64::new(7));
        watch(&w, &[], 0);
        assert!(LIVE.with(|l| l.borrow().is_none()));
        drop(a);
    }

    #[test]
    fn the_hub_entry_appears_with_the_arm_and_leaves_with_it() {
        let hub = Arc::new(crate::streamhub::StreamHub::default());
        {
            let _a = arm(Some(&hub.unpack), "nzo-1", 130);
            let g = hub.unpack.lock_ok();
            assert_eq!(g.get("nzo-1").map(|p| p.volumes()), Some(130));
        }
        assert!(hub.unpack.lock_ok().is_empty());
    }

    #[test]
    fn done_accumulates_across_sets_and_never_leads_the_total() {
        let (hub, _a) = armed(4);
        let p = hub.unpack.lock_ok().get("nzo-1").cloned().expect("armed");
        // No set parsed yet: the count is known, the bytes are not.
        assert_eq!((p.volumes(), p.total(), p.done()), (4, 0, 0));
        // Set one. `watch` cannot raise a total from an empty archive
        // list, so drive the counters the way the ladder does.
        let first = Arc::new(AtomicU64::new(0));
        watch(&first, &[], 0);
        raise_total(100);
        first.store(60, Ordering::Relaxed);
        assert_eq!(p.done(), 60);
        // Set two: set one's bytes fold into the base rather than
        // restarting at zero.
        let second = Arc::new(AtomicU64::new(0));
        watch(&second, &[], 0);
        raise_total(50);
        second.store(20, Ordering::Relaxed);
        assert_eq!((p.total(), p.done()), (150, 80));
        // A set that overruns its header total (a failed set's partial
        // bytes, say) still reports a fraction the page can draw.
        second.store(999, Ordering::Relaxed);
        assert_eq!(p.done(), 150);
    }

    /// A resumed set's prefix is in the header total but is never
    /// written, so `watch` credits it up front - without that the row
    /// climbs to a ceiling short of its own total and sits there.
    #[test]
    fn resumed_bytes_are_credited_so_the_row_can_still_reach_its_total() {
        let (hub, _a) = armed(4);
        let p = hub.unpack.lock_ok().get("nzo-1").cloned().unwrap();
        let w = Arc::new(AtomicU64::new(0));
        watch(&w, &[], 70);
        raise_total(100);
        assert_eq!(p.done(), 70, "the prefix already on disk counts as done");
        w.store(30, Ordering::Relaxed);
        assert_eq!((p.total(), p.done()), (100, 100));
    }

    /// Three password candidates at ONE zip is three attempts at one
    /// set, and the set's total must be the container's - not three
    /// times it. Folding each attempt the way a new set is folded would
    /// leave the lane parked at a third of a figure the extraction can
    /// never reach.
    #[test]
    fn retrying_a_set_republishes_its_total_instead_of_adding_to_it() {
        let (hub, _a) = armed(1);
        let p = hub.unpack.lock_ok().get("nzo-1").cloned().expect("armed");
        begin_set();
        for _wrong_password in 0..2 {
            // Each attempt takes a fresh staging dir and so a fresh
            // counter, and writes nothing before the password is
            // refused.
            attempt(&Arc::new(AtomicU64::new(0)), 100, 0);
        }
        let good = Arc::new(AtomicU64::new(0));
        attempt(&good, 100, 0);
        good.store(100, Ordering::Relaxed);
        assert_eq!((p.total(), p.done()), (100, 100));
    }

    /// A rewind puts back everything the attempt it marked did - a
    /// whole LOOP of banked sets included, which is what one re-entry
    /// of the named-RAR ladder is - and replaying it at the top of the
    /// first pass restores the state to what it already is, which is
    /// what makes the retry loops able to call it unconditionally.
    #[test]
    fn a_rewind_undoes_every_set_the_attempt_it_marked_banked() {
        let (hub, _a) = armed(3);
        let p = hub.unpack.lock_ok().get("nzo-1").cloned().expect("armed");
        // A set the ladder finished with before the retrying arm ran.
        let done_before = Arc::new(AtomicU64::new(0));
        watch(&done_before, &[], 0);
        raise_total(10);
        done_before.store(10, Ordering::Relaxed);

        let mark = mark();
        for _try in 0..2 {
            // Unconditional, exactly as the arms call it: on the first
            // pass there is nothing yet to undo.
            mark.rewind();
            // One pass of a group loop: two sets, banked as it goes.
            for (n, produced) in [(100u64, 100u64), (50, 20)] {
                let w = Arc::new(AtomicU64::new(0));
                watch(&w, &[], 0);
                raise_total(n);
                w.store(produced, Ordering::Relaxed);
            }
            assert_eq!(
                (p.total(), p.done()),
                (160, 130),
                "one pass reports the set before it plus its own two"
            );
        }
    }

    /// The mark is inert with no ladder armed, like every other call in
    /// this module - and a rewind taken while unarmed must not touch a
    /// ladder that arms later.
    #[test]
    fn a_mark_taken_with_no_ladder_armed_rewinds_nothing() {
        let mark = mark();
        let (hub, _a) = armed(1);
        let p = hub.unpack.lock_ok().get("nzo-1").cloned().expect("armed");
        let w = Arc::new(AtomicU64::new(0));
        watch(&w, &[], 0);
        raise_total(70);
        w.store(70, Ordering::Relaxed);
        mark.rewind();
        assert_eq!((p.total(), p.done()), (70, 70));
    }

    /// The plain feed route learns its total as the extractor reaches
    /// each member's header, so the figure only ever climbs - and a
    /// sample that repeats, or that comes back short because a writer
    /// has yet to appear, must not move it.
    #[test]
    fn a_discovered_total_only_ever_climbs() {
        let (hub, _a) = armed(2);
        let p = hub.unpack.lock_ok().get("nzo-1").cloned().expect("armed");
        let w = Arc::new(AtomicU64::new(0));
        watch(&w, &[], 0);
        raise_total(40);
        raise_total(40);
        raise_total(10);
        assert_eq!(p.total(), 40);
        raise_total(90);
        assert_eq!(p.total(), 90);
    }
}
