//! The bounded wait on files that are not payload.
//!
//! A download finishes when its pool run does, and the pool run ends
//! when EVERY article is terminal. For a payload article that is the
//! right rule and the ladder that decides it (every serving server has
//! refused it, or a set's parity covers it) is deliberately patient: a
//! 430 on one server is not proof the post is dead. For a `.nfo` the
//! same patience is a defect. The file cannot change the result - it is
//! optional furniture the recovery set does not cover, so
//! `census::SpareRule` already completes the job without it and
//! `tail::drop_spared_metadata` already deletes the partial - and yet
//! its one missing article held the whole run open, with every payload
//! byte on disk, for as long as its own ladder took to reach a verdict:
//! each level waiting on every serving server, and a server that holds
//! no session for `NZBFAST_CONN_DARK_SECS` (120 s) blocking that verdict
//! until the window closes. From the queue that is a job parked at 99%
//! with a countdown that never reaches zero.
//!
//! The rule here bounds the WAITING and never the verdict on payload.
//! It fires only when EVERY article the pool still owes belongs to a
//! file the spare rule would drop anyway - furniture by name, in a post
//! that carries payload, that no adopted recovery set covers - and then
//! only after the count of those articles has stood still for
//! [`META_TAIL_GRACE`]. One payload article, one recovery volume
//! article, one file with an unclassifiable name, one file a set covers:
//! any of them anywhere in the pool's pending set and this arm stays
//! shut, so the full ladder, the tail give-up's parity trade and repair
//! are exactly what they were. What it gives up is time spent asking for
//! something the job is already defined to finish without.
//!
//! The give-up is accounted as a terminal MISSING article, the same
//! books `Consumer::article_lost` keeps for a verdict the ladder reached
//! by itself, so census, settle and the job's messages read it through
//! the paths they already have.

use super::*;
use std::time::{Duration, Instant};

/// How long the count of still-owed metadata articles must stand still,
/// with nothing else outstanding, before they are given up. 20 s is
/// several times what one article's whole ladder costs on a healthy
/// fleet (a refusal is one round trip per server, measured 13-15 s for
/// SIXTY serial walkers) and far short of the 120 s dark-server window
/// and the multi-minute waits a connection-starved account produces.
/// `NZBFAST_META_TAIL_GRACE_SECS` overrides it; `0` switches the bound
/// off, which is the behaviour before 21 Sep 2026.
pub(super) const META_TAIL_GRACE: Duration = Duration::from_secs(20);

/// `None` is "the bound is off" (`NZBFAST_META_TAIL_GRACE_SECS=0`). An
/// unset or unparsable value is the default, so a typo never silently
/// switches a safety bound off (`NZBFAST_CONN_DARK_SECS` reads its own
/// the same way).
pub(super) fn meta_tail_grace() -> Option<Duration> {
    let grace = std::env::var("NZBFAST_META_TAIL_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(META_TAIL_GRACE, Duration::from_secs);
    (!grace.is_zero()).then_some(grace)
}

/// Every article, by the id the pool knows it by, of every slot the
/// spare rule would drop at finish: `(slot index, declared bytes)`.
/// A SUPERSET of what may be given up - coverage by a recovery set is
/// judged again at claim time ([`claimable`]), because a set can be
/// adopted after this is built - and `None` when the post has no such
/// slot at all, so the arm costs nothing on a job without furniture.
pub(super) fn candidates(
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Nzb,
) -> Option<std::collections::HashMap<Arc<str>, (usize, u64)>> {
    let rule = crate::get::census::SpareRule::of(slots);
    let mut out = std::collections::HashMap::new();
    for (sidx, s) in slots.iter().enumerate() {
        if s.is_par2() || !rule.spares(&s.hint) {
            continue;
        }
        let Some(&fi) = slot_file.get(sidx) else {
            continue;
        };
        for seg in &nzb.files[fi].segments {
            let id: Arc<str> = format!("<{}>", seg.message_id).into();
            out.insert(id, (sidx, seg.bytes));
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The stillness clock: `true` once the count of pending articles has
/// stood unchanged for `grace`. Any change - an article settling, the
/// census closing because a payload article appeared - restarts it, so
/// a poster image still arriving article by article is never cut off
/// and only a tail that has stopped moving is.
#[derive(Default)]
pub(super) struct Stillness {
    since: Option<(usize, Instant)>,
}

impl Stillness {
    pub(super) fn expired(
        &mut self,
        pending: Option<usize>,
        now: Instant,
        grace: Duration,
    ) -> bool {
        let Some(n) = pending else {
            self.since = None;
            return false;
        };
        match self.since {
            Some((seen, at)) if seen == n => now.saturating_duration_since(at) >= grace,
            _ => {
                self.since = Some((n, now));
                false
            }
        }
    }
}

/// Re-check, at the moment of claiming, that every article in the
/// census still belongs to a slot the spare rule drops: not recovery
/// data, still furniture in a post with payload, and not named by any
/// adopted recovery set. All or nothing - a single article that fails
/// keeps the whole tail on its ladder, because the point of the arm is
/// that NOTHING but furniture is left waiting.
pub(super) fn claimable(
    walkers: Vec<nzbkit::pool::Walker>,
    slots: &[Arc<FileSlot>],
    set_names: Option<&std::collections::HashSet<String>>,
    cands: &std::collections::HashMap<Arc<str>, (usize, u64)>,
) -> Option<Vec<nzbkit::pool::Walker>> {
    let rule = crate::get::census::SpareRule::of(slots);
    for w in &walkers {
        let &(sidx, _) = cands.get(&*w.id)?;
        let s = &slots[sidx];
        let covered = set_names
            .is_some_and(|n| n.contains(&nzbkit::disk::sanitize_out_name(&s.hint).to_lowercase()));
        if s.is_par2() || covered || !rule.spares(&s.hint) {
            return None;
        }
    }
    Some(walkers)
}

/// Book the given-up articles as terminal MISSING, exactly as
/// `Consumer::article_lost` does for a verdict the ladder reached: the
/// declared bytes are credited to the progress bar, `missing` goes up
/// and `remaining` down. Returns the file names touched, once each and
/// in slot order, for the log line. Ids the candidate map does not know
/// are charged to nobody.
pub(super) fn charge_missing(
    claimed: &[Arc<str>],
    cands: &std::collections::HashMap<Arc<str>, (usize, u64)>,
    slots: &[Arc<FileSlot>],
    fetch_done: &AtomicU64,
) -> Vec<String> {
    let mut touched = std::collections::BTreeSet::new();
    for id in claimed {
        let Some(&(sidx, bytes)) = cands.get(&**id) else {
            continue;
        };
        fetch_done.fetch_add(bytes, Ordering::Relaxed);
        slots[sidx].missing.fetch_add(1, Ordering::Relaxed);
        slots[sidx].remaining.fetch_sub(1, Ordering::AcqRel);
        touched.insert(sidx);
    }
    touched.into_iter().map(|i| slots[i].hint.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn slot(hint: &str, remaining: usize) -> Arc<FileSlot> {
        Arc::new(FileSlot {
            hint: hint.into(),
            hint_is_posted_name: nzbkit::release::stem_is_a_name(hint),
            yenc_votes: Default::default(),
            name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
            // What the NZB classifier stamps on a recovery file's slot.
            is_par2_main: hint.ends_with(".par2"),
            sample_skipped: false,
            par2_name_demoted: Default::default(),
            par2_sniffed: AtomicBool::new(false),
            total_segments: 1,
            posted_bytes: 0,
            remaining: AtomicUsize::new(remaining),
            missing: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            deferred: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(None),
        })
    }

    fn nzb() -> Nzb {
        Nzb::parse(
            r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"movie.mkv" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="5000" number="1">m1@t</segment>
   <segment bytes="5000" number="2">m2@t</segment>
  </segments>
 </file>
 <file subject='"movie.nfo" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="700" number="1">n1@t</segment>
  </segments>
 </file>
 <file subject='"movie.par2" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="900" number="1">p1@t</segment>
  </segments>
 </file>
</nzb>"#
                .as_bytes(),
        )
        .expect("test NZB parses")
    }

    fn walker(id: &str, ord: u32) -> nzbkit::pool::Walker {
        nzbkit::pool::Walker { id: id.into(), ord }
    }

    /// Only the furniture slot is a candidate: the payload and the
    /// recovery volume never enter the map, so a pool that still owes
    /// either can never be answered "yes" by the census predicate.
    #[test]
    fn only_furniture_is_a_candidate() {
        let n = nzb();
        let slots = vec![
            slot("movie.mkv", 2),
            slot("movie.nfo", 1),
            slot("movie.par2", 1),
        ];
        let c = candidates(&slots, &[0, 1, 2], &n).expect("an .nfo beside a video");
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("<n1@t>"), Some(&(1, 700)));
    }

    /// A post whose only file is furniture has no payload for the
    /// furniture to sit beside (row M4-33), so the arm has no candidate
    /// and can never touch a text release that IS its `.txt`.
    #[test]
    fn a_text_release_has_no_candidates() {
        let n = nzb();
        let slots = vec![
            slot("release.txt", 2),
            slot("movie.nfo", 1),
            slot("movie.par2", 1),
        ];
        assert!(candidates(&slots, &[0, 1, 2], &n).is_none());
    }

    /// The clock restarts on ANY change of the count and on the census
    /// closing, and fires only after a full grace of stillness.
    #[test]
    fn stillness_needs_a_full_grace_of_a_constant_count() {
        let g = Duration::from_secs(20);
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut st = Stillness::default();
        assert!(!st.expired(Some(3), at(0), g));
        assert!(!st.expired(Some(3), at(19), g));
        // An article settled: stillness starts over from here.
        assert!(!st.expired(Some(2), at(20), g));
        assert!(!st.expired(Some(2), at(39), g));
        // A payload article shows up (census closed) and goes again.
        assert!(!st.expired(None, at(40), g));
        assert!(!st.expired(Some(2), at(41), g));
        assert!(!st.expired(Some(2), at(60), g));
        assert!(st.expired(Some(2), at(61), g));
    }

    /// Coverage by an adopted recovery set, a sniffed-recovery slot, or
    /// any id the map does not know each veto the WHOLE claim.
    #[test]
    fn one_covered_or_unknown_article_vetoes_the_whole_claim() {
        let n = nzb();
        let slots = vec![
            slot("movie.mkv", 0),
            slot("movie.nfo", 1),
            slot("movie.par2", 0),
        ];
        let c = candidates(&slots, &[0, 1, 2], &n).unwrap();
        let ws = || vec![walker("<n1@t>", 7)];

        assert_eq!(claimable(ws(), &slots, None, &c).map(|v| v.len()), Some(1));

        // A set that names movie.nfo can rebuild it: the ladder keeps it.
        let names: std::collections::HashSet<String> =
            ["movie.nfo".to_string()].into_iter().collect();
        assert!(claimable(ws(), &slots, Some(&names), &c).is_none());
        // A set that names only the video does not.
        let other: std::collections::HashSet<String> =
            ["movie.mkv".to_string()].into_iter().collect();
        assert!(claimable(ws(), &slots, Some(&other), &c).is_some());

        // An id outside the candidate map (a payload article).
        let mixed = vec![walker("<n1@t>", 7), walker("<m2@t>", 3)];
        assert!(claimable(mixed, &slots, None, &c).is_none());

        // The slot turned out to be recovery data.
        slots[1]
            .par2_sniffed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(claimable(ws(), &slots, None, &c).is_none());
    }

    /// The books: bytes credited to the bar, the slot's article counted
    /// as MISSING (so the census reads it through the spare path) and
    /// removed from `remaining`; nothing charged to `abandoned`, which
    /// settle reads as "repair will rebuild it".
    #[test]
    fn a_given_up_article_is_booked_as_missing_not_abandoned() {
        let n = nzb();
        let slots = vec![
            slot("movie.mkv", 0),
            slot("movie.nfo", 1),
            slot("movie.par2", 0),
        ];
        let c = candidates(&slots, &[0, 1, 2], &n).unwrap();
        let done = AtomicU64::new(0);
        let ids: Vec<Arc<str>> = vec!["<n1@t>".into(), "<zz@t>".into()];
        let names = charge_missing(&ids, &c, &slots, &done);
        assert_eq!(names, ["movie.nfo"]);
        assert_eq!(done.load(Ordering::Relaxed), 700);
        assert_eq!(slots[1].missing.load(Ordering::Relaxed), 1);
        assert_eq!(slots[1].remaining.load(Ordering::Relaxed), 0);
        assert_eq!(slots[1].abandoned.load(Ordering::Relaxed), 0);
        assert_eq!(slots[0].missing.load(Ordering::Relaxed), 0);
    }
}
