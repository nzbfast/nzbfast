//! TODO 282 section B: the ranked SPARES a grab holds against its own
//! failure, and the admission test that refuses one which is the same
//! post.
//!
//! The promote-on-failure machinery is not here and is not new. `dupe.rs`
//! parks a duplicate paused at [`DUPE_PRIORITY`] with `held_for` naming
//! the row it is an alternative OF, and `daemon_park::park_gen` promotes
//! the BEST of those when that row fails (M14f). All this module does is
//! populate that set ON PURPOSE, at grab time, from the search that
//! produced the grab - so the existing failure path fires with no new
//! failure logic behind it.
//!
//! **A spare is an NZB and never a byte of payload.** It is enqueued
//! paused at [`DUPE_PRIORITY`], which `pick_job` never takes, and nothing
//! in this file may be talked into starting one: the only thing that
//! unpauses a spare is a promotion, and the only thing that promotes one
//! is the original failing. NZB files are kilobytes; that is the whole
//! reason this is affordable, and it stops being true the moment
//! something here fetches articles.
//!
//! # Segment overlap is effectively BINARY, and the corollary
//!
//! Two indexer results for one release are very often the SAME articles
//! re-indexed under a different NZB. Such a spare is worthless: it fails
//! identically, article for article, because it IS the failed post. That
//! is what [`admits`] refuses.
//!
//! The other half of that finding is the one worth writing down where it
//! will be read. When two candidates are NOT the same post, their
//! overlap is not "small", it is zero - a different poster's upload of
//! the same film is a different encode, chunked differently, yEnc'd
//! differently, and shares no article with the first. So there is no
//! middle: same ids means useless as a backup, different ids means no
//! partial reuse is possible either. **Do NOT design for "resume
//! candidate A's 90% from candidate B".** That case barely exists, and
//! §282 records it as measured and rejected. The threshold below is a
//! threshold rather than an equality test only because a REPOST may
//! carry part of an earlier set; its exact value is not load-bearing,
//! because there is nothing for it to sit between.

use super::*;

/// How many spares one grab holds WITH NO SETTING SAVED - the default
/// `alt_hold_count` is initialised from, and no longer a second answer
/// beside it.
///
/// §282 item 13's setting is the live surface and item 19 decided its
/// value; this constant is where that value is written down.
/// `altcand::AltSettings::default` reads it, the grab-time hold reads
/// the SETTING, and so the two cannot disagree - which is the whole
/// reason this stayed a constant rather than becoming a literal at
/// either end. Two is cheap: two NZB files, no payload, and two rows the
/// queue already knows how to render.
///
/// NOT `#[cfg(feature = "indexer")]`, though the only thing that ACTS on
/// it is the indexer-only grab-time hold. `AltSettings` is not gated -
/// the setting is readable and settable on a slim build like every other
/// key - so gating this would take the slim build's default with it.
pub(in crate::serve) const SPARE_HOLD_COUNT: usize = 2;

/// How many candidate NZBs one grab may FETCH while trying to fill those
/// slots.
///
/// Every fetch spends one grab from the user's metered indexer budget,
/// so this is a cost ceiling and not a retry count: a search whose next
/// six results are all re-indexes of the one post stops at six rather
/// than walking five hundred rows to find nothing. The walk says so in
/// the log when it stops early - a silent cap reads as "there were no
/// other candidates", which is a different and wrong statement.
#[cfg(feature = "indexer")]
const SPARE_FETCH_BUDGET: usize = 6;

/// Overlap at or above which two NZBs are judged to be the same post.
///
/// See the module note: the measured distribution is bimodal at 0 and 1,
/// so anything inside the open interval works and nothing sits near the
/// line. 0.30 is low enough to refuse a partial repost and high enough
/// that a handful of shared filler articles cannot condemn an
/// independent post.
const SAME_POST_OVERLAP: f64 = 0.30;

/// The message-id set of one post.
///
/// Hashed rather than kept as strings purely for size: a 23,000-segment
/// NZB is a real shape (the §282 incident's own S02E08 had 22,920), and
/// 64-bit hashes hold that in ~180 KB where the ids themselves are
/// megabytes. The hash is never persisted and never crosses a process,
/// so `DefaultHasher`'s fixed-key determinism inside one build is all it
/// has to promise. Collision risk over 23,000 ids is ~1e-11.
#[derive(Default)]
pub(in crate::serve) struct PostIds {
    ids: std::collections::HashSet<u64>,
}

impl PostIds {
    fn len(&self) -> usize {
        self.ids.len()
    }
}

fn hash_id(id: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut h);
    h.finish()
}

/// Every article the NZB declares, recovery volumes INCLUDED.
///
/// The recovery set is deliberately not skipped the way
/// `tasks/health.rs::sample_ids` skips it. That skip is right for a
/// PAYLOAD verdict and wrong here: the question this set answers is "is
/// this the same post", and §282's incident is a job that died on its
/// recovery set while its payload was 99.8% intact. Two NZBs that share
/// a payload and differ only in their par2 volumes are still the same
/// post, and would still die the same way.
pub(in crate::serve) fn post_ids(nzb: &nzbkit::nzb::Nzb) -> PostIds {
    PostIds {
        ids: nzb
            .files
            .iter()
            .flat_map(|f| f.segments.iter())
            .map(|s| hash_id(&s.message_id))
            .collect(),
    }
}

/// Read a spooled NZB back and parse it. `None` for anything that is not
/// readable as an NZB right now - see [`admits`] for what each caller
/// does about not knowing.
pub(in crate::serve) fn nzb_at(path: &std::path::Path) -> Option<nzbkit::nzb::Nzb> {
    let bytes = std::fs::read(path).ok()?;
    nzbkit::nzb::Nzb::parse(&bytes).ok()
}

/// How much of the SMALLER post the two share, 0.0 to 1.0. `None` when
/// either side declares no articles at all, which is not an overlap of
/// zero - it is not knowing.
///
/// Containment of the smaller in the larger, rather than Jaccard: a
/// repost of half a set is still the same articles for the half it
/// carries, and a spare that is a strict subset of the failed post is
/// exactly as useless as an identical one.
fn overlap(a: &PostIds, b: &PostIds) -> Option<f64> {
    let floor = a.len().min(b.len());
    if floor == 0 {
        return None;
    }
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let shared = small.ids.iter().filter(|h| large.ids.contains(h)).count();
    Some(shared as f64 / floor as f64)
}

/// May `cand` be held as a spare for `primary`?
///
/// `unknown` is the answer for a pair we cannot compare - an unreadable
/// spool file, an NZB with no segments - and the two callers pass
/// DIFFERENT values for it, on purpose.
///
/// At ADMISSION the answer is `false`: we are creating a queue row the
/// user never asked for, so it has to be justified, and an unjustified
/// one is §4b's junk-queue class arriving by a new road. At PROMOTION
/// the answer is `true`: the rows already exist, the user could see them
/// and could promote one by hand, and refusing every candidate because a
/// spool file has gone missing would take away a promotion that worked
/// before this test existed.
pub(in crate::serve) fn admits(primary: &PostIds, cand: &PostIds, unknown: bool) -> bool {
    match overlap(primary, cand) {
        Some(o) => o < SAME_POST_OVERLAP,
        None => unknown,
    }
}

/// Where a post was PUT: its newsgroups and its posters, lowercased.
#[derive(Default)]
pub(in crate::serve) struct PostOrigin {
    groups: std::collections::BTreeSet<String>,
    posters: std::collections::BTreeSet<String>,
}

pub(in crate::serve) fn post_origin(nzb: &nzbkit::nzb::Nzb) -> PostOrigin {
    let mut o = PostOrigin::default();
    for f in &nzb.files {
        for g in &f.groups {
            o.groups.insert(g.to_ascii_lowercase());
        }
        if !f.poster.is_empty() {
            o.posters.insert(f.poster.to_ascii_lowercase());
        }
    }
    o
}

/// §282 item 7: does this spare look like an INDEPENDENT post rather
/// than the same uploader's second go at the same one?
///
/// A weak signal and treated as one - it only ever breaks a tie between
/// two candidates the ranker scores equally, and it never admits or
/// refuses anything on its own. Sharing neither a group nor a poster is
/// evidence that the two uploads travelled different routes, which is
/// what makes a spare worth holding at all; sharing one is not evidence
/// of anything, because half of Usenet posts to the same four groups.
///
/// Unknown on either side (a post that declares no groups, or none that
/// names a poster) reads as NOT independent, so an absent field can
/// never win a tiebreak it has said nothing about.
pub(in crate::serve) fn looks_independent(a: &PostOrigin, b: &PostOrigin) -> bool {
    let disjoint = |x: &std::collections::BTreeSet<String>,
                    y: &std::collections::BTreeSet<String>| {
        !x.is_empty() && !y.is_empty() && x.intersection(y).next().is_none()
    };
    disjoint(&a.groups, &b.groups) && disjoint(&a.posters, &b.posters)
}

/// One result the spare-holder may fetch, as the caller describes it.
///
/// `token` is opaque here on purpose: this module knows nothing about
/// indexer origins, enclosure links or grab budgets, and the closure the
/// caller passes to [`Daemon::hold_spares_with`] is what turns a token
/// into bytes. That is also what makes the walk testable without a
/// network.
#[cfg(feature = "indexer")]
pub(in crate::serve) struct SpareCandidate {
    /// The release name the source listed it under.
    pub(in crate::serve) title: String,
    /// Who offered it, for the log line.
    pub(in crate::serve) source: String,
    /// Whatever the caller's fetch closure needs to get the NZB.
    pub(in crate::serve) token: String,
}

/// Pick the best held alternative of a job that just failed.
///
/// Returns an index into `cands` and the rank it won on. `cands` is
/// `(release name, spooled NZB path)` in the order park collected them,
/// and ties keep the earliest - which is the behaviour that was there
/// before §282 and is as good a tiebreak as any.
///
/// Two things are new here and both are §282 section B applied to the
/// EXISTING promote path rather than to the spares this module holds:
///
/// 1. **Item 6.** A candidate that is the same post as the failed job is
///    skipped. Before this, a byte-different NZB of an identical post
///    could be promoted, and it fails identically - the user watches the
///    same 135 missing articles arrive as the same failure, twice.
/// 2. **Item 7.** A candidate on a different group AND a different
///    poster wins a rank tie.
///
/// If the failed job's own NZB cannot be read, no candidate NZB is read
/// either and the pick degrades exactly to the pre-§282 rank order. That
/// is the `unknown = true` side of [`admits`], and it is deliberate: a
/// missing spool file must not cost the user a promotion.
pub(in crate::serve) fn best_alternative(
    failed_nzb: &std::path::Path,
    cands: &[(String, std::path::PathBuf)],
) -> Option<(usize, u32)> {
    let failed = nzb_at(failed_nzb);
    let failed_ids = failed.as_ref().map(post_ids);
    let failed_origin = failed.as_ref().map(post_origin);
    let mut best: Option<(usize, u32, bool)> = None;
    for (i, (name, path)) in cands.iter().enumerate() {
        let rank = crate::watchlist::quality_rank(&crate::wall::parse_release(name));
        // Only read the candidate when there is something to compare it
        // with; with no failed-job fingerprint this stays a pure rank
        // pick and touches no disk at all.
        let cand = failed_ids.as_ref().and_then(|_| nzb_at(path));
        if let (Some(f), Some(c)) = (failed_ids.as_ref(), cand.as_ref())
            && !admits(f, &post_ids(c), true)
        {
            info!(
                target: "queue",
                "{name:?} is not promoted - it is the same post as the job that \
                 just failed, so it would fail the same way"
            );
            continue;
        }
        let indep = match (failed_origin.as_ref(), cand.as_ref()) {
            (Some(f), Some(c)) => looks_independent(f, &post_origin(c)),
            _ => false,
        };
        if best.is_none_or(|(_, r, ind)| rank > r || (rank == r && indep && !ind)) {
            best = Some((i, rank, indep));
        }
    }
    best.map(|(i, r, _)| (i, r))
}

/// The search-fed half. A spare comes out of a search this daemon ran,
/// so the slim build - which has no indexer and no search - compiles
/// none of it; what it DOES compile is everything above, because
/// `best_alternative` is on the promote path and that path is not
/// optional.
#[cfg(feature = "indexer")]
impl Daemon {
    /// What this install would rather have, when two spares are otherwise
    /// equal.
    fn spare_rank(&self, p: &crate::wall::Parsed) -> i64 {
        crate::watchlist::preference_score(p, &self.quality_prefs.lock_ok())
    }

    /// §282 item 5: hold the next ranked candidates of the search that
    /// produced `primary_id`, as paused alternatives of that job.
    ///
    /// Returns how many were actually held. `fetch` turns a candidate's
    /// token into NZB bytes and owns whatever budget accounting the
    /// caller's source needs; failing it is never fatal, it just costs
    /// that candidate its slot.
    ///
    /// **Identity is the gate before anything is fetched.** A candidate
    /// whose `dupe_key` is not the primary's is not a spare for it, it is
    /// a different film, and promoting one would hand the user something
    /// they never asked for. A primary with no derivable key holds
    /// nothing at all rather than guessing - the same rule `dupe.rs`
    /// applies to a hold it did not choose.
    pub(in crate::serve) fn hold_spares_with(
        &self,
        primary_id: &str,
        cands: &[SpareCandidate],
        want: usize,
        fetch: impl Fn(&SpareCandidate) -> std::result::Result<Vec<u8>, String>,
    ) -> usize {
        if want == 0 || cands.is_empty() {
            return 0;
        }
        let primary = self.queue.lock_ok().iter().find_map(|j| {
            let g = j.lock_ok();
            (g.nzo_id == primary_id).then(|| {
                (
                    g.name.clone(),
                    g.dupe_key.clone(),
                    g.nzb_path.clone(),
                    g.category.clone(),
                )
            })
        });
        let Some((name, Some(key), nzb_path, category)) = primary else {
            info!(
                target: "queue",
                "{primary_id}: no spares held - the grab is gone, or its name \
                 carries no episode or year to identify it by"
            );
            return 0;
        };
        let Some(primary_ids) = nzb_at(&nzb_path).as_ref().map(post_ids) else {
            info!(target: "queue", "{primary_id}: no spares held - its own NZB could not be re-read");
            return 0;
        };
        let primary_group = nzbkit::release::group_of(&name).map(str::to_ascii_lowercase);
        // Same target only, then best first. `seq` keeps the order a
        // total one, so the same search grabbed twice holds the same two.
        let mut ranked: Vec<(i64, bool, usize)> = cands
            .iter()
            .enumerate()
            .filter(|(_, c)| dupe_key(&c.title).as_deref() == Some(key.as_str()))
            .map(|(seq, c)| {
                let parsed = crate::wall::parse_release(&c.title);
                // Item 7, as much of it as a NAME can carry: the poster
                // is only in the NZB, which has not been fetched yet, so
                // the group tag is the whole of the pre-fetch signal.
                // Unknown on either side reads as NOT independent, the
                // same rule `looks_independent` applies to the full form.
                let indep = match (
                    nzbkit::release::group_of(&c.title).map(str::to_ascii_lowercase),
                    primary_group.as_ref(),
                ) {
                    (Some(g), Some(p)) => g != *p,
                    _ => false,
                };
                (self.spare_rank(&parsed), indep, seq)
            })
            .collect();
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));
        let mut held = 0usize;
        let mut accepted: Vec<PostIds> = Vec::new();
        // The loop index IS the fetch count, and has to stay that way:
        // every candidate that reaches the body is fetched before it can
        // be judged, and the walk leaves by `break` rather than skipping
        // ahead. A `continue` added above the fetch below would quietly
        // turn a cost ceiling into a retry count.
        for (fetched, (_, _, seq)) in ranked.into_iter().enumerate() {
            if held >= want {
                break;
            }
            if fetched >= SPARE_FETCH_BUDGET {
                info!(
                    target: "queue",
                    "{primary_id}: stopped after {fetched} candidate NZB(s) - \
                     {held} spare(s) held, the rest of the search was not tried"
                );
                break;
            }
            let c = &cands[seq];
            let bytes = match fetch(c) {
                Ok(b) => b,
                Err(e) => {
                    info!(target: "queue", "{primary_id}: spare {:?} not fetched - {e}", c.title);
                    continue;
                }
            };
            let Ok(nzb) = nzbkit::nzb::Nzb::parse(&bytes) else {
                info!(target: "queue", "{primary_id}: spare {:?} is not a readable NZB", c.title);
                continue;
            };
            let ids = post_ids(&nzb);
            // The admission test, against the grab AND against every
            // spare already held: two re-indexes of one post are as
            // useless to each other as either is to the original.
            if !admits(&primary_ids, &ids, false) {
                info!(
                    target: "queue",
                    "{primary_id}: {:?} ({}) refused as a spare - it is the same \
                     post as the grab, so it would fail the same way",
                    c.title, c.source
                );
                continue;
            }
            if accepted.iter().any(|a| !admits(a, &ids, false)) {
                info!(
                    target: "queue",
                    "{primary_id}: {:?} ({}) refused as a spare - it is the same \
                     post as a spare already held",
                    c.title, c.source
                );
                continue;
            }
            match self.enqueue_as(
                None,
                &bytes,
                &c.title,
                &category,
                SAB_DEFAULT_PRIORITY,
                None,
                None,
                SPARE_ORIGIN,
                false,
                Some(primary_id),
            ) {
                Ok(e) => {
                    info!(
                        target: "queue",
                        "{} held as a SPARE for {primary_id}: {:?} from {}",
                        e.nzo_id, c.title, c.source
                    );
                    accepted.push(ids);
                    held += 1;
                }
                Err(e) => {
                    info!(target: "queue", "{primary_id}: spare {:?} not held - {e}", c.title);
                }
            }
        }
        held
    }
}

impl Daemon {
    /// The job that owned these spares is done with them: drop every one
    /// this daemon added for it.
    ///
    /// Runs when the owner COMPLETED, and when the user deleted it. Both
    /// are "there is nothing left for a spare to be a spare for", and a
    /// row nobody asked for that outlives its reason is §4b's junk queue
    /// - four held copies of an episode the user already has, reappearing
    /// after every restart because the spooled NZB is re-adopted.
    ///
    /// Only rows this daemon added: a duplicate the USER added is theirs,
    /// carries a different origin, and keeps the behaviour it had before
    /// §282 existed. Only rows still HELD: one that was promoted is a
    /// download in its own right.
    pub(in crate::serve) fn drop_spares_for(&self, owner: &str) {
        let dropped: Vec<(String, PathBuf, String)> = {
            let mut q = self.queue.lock_ok();
            let mut out = Vec::new();
            q.retain(|j| {
                let g = j.lock_ok();
                let mine =
                    g.held_for == owner && is_spare_origin(&g.origin) && is_held_alternative(&g);
                if mine {
                    out.push((g.nzo_id.clone(), g.nzb_path.clone(), g.name.clone()));
                }
                !mine
            });
            out
        };
        if dropped.is_empty() {
            return;
        }
        for (id, path, name) in &dropped {
            // The spool copy goes with the row. `recover_orphaned_spool`
            // adopts any spooled NZB no record names, so leaving it
            // behind would put the dropped spare back in the queue at the
            // next start - with nothing to hold it against.
            let _ = std::fs::remove_file(path);
            info!(target: "queue", "{id} dropped - the job it was a spare for is done ({name:?})");
        }
        self.save_queue_soon();
    }

    /// A spare was just promoted: point the ones still held at IT.
    ///
    /// Without this a grab that held two spares only ever tries one. The
    /// remaining rows name the ORIGINAL in `held_for`, and the original
    /// has left the queue, so `held_against` can never match them again
    /// and they sit paused for good - which is the shape §282 is trying
    /// to end, not reproduce one level down.
    ///
    /// Spares only. A duplicate the user added keeps naming what it was
    /// added against, exactly as it did before.
    pub(in crate::serve) fn repoint_spares(&self, from: &str, to: &str) {
        let mut moved = 0;
        for j in self.queue.lock_ok().iter() {
            let mut g = j.lock_ok();
            if g.held_for == from && is_spare_origin(&g.origin) && is_held_alternative(&g) {
                g.held_for = to.to_string();
                moved += 1;
            }
        }
        if moved > 0 {
            info!(target: "queue", "{moved} spare(s) now held against {to}");
            self.save_queue_soon();
        }
    }
}
