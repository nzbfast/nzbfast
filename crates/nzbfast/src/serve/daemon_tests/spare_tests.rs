//! TODO 282 section B: the spares a grab holds against its own failure.
//!
//! The one that matters most is
//! `a_candidate_that_is_the_same_post_is_refused_admission`. Everything
//! else here is plumbing around it - what gets held, what gets promoted,
//! what gets cleaned up - but the admission test is the difference
//! between a feature and a decoration: two indexer results for one
//! release are very often the SAME articles re-indexed, and holding one
//! of those buys the user a second identical failure.
//!
//! A child of daemon_tests on the `#[path]` convention, so size-gate.py
//! reads it as test code; `use super::*` brings `with_daemon` and
//! everything daemon.rs's test module already has in scope.

use super::*;
use crate::serve::testutil::flat_rate_config;

/// An NZB declaring exactly `ids` as its articles, posted by `poster` to
/// `group`. Everything §282 item 6 and item 7 judge is in that triple.
fn nzb_of(poster: &str, group: &str, ids: &[&str]) -> String {
    let segs: String = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            format!(
                "<segment bytes=\"1000\" number=\"{}\">{id}</segment>",
                i + 1
            )
        })
        .collect();
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"{poster}\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/{})\">\
         <groups><group>{group}</group></groups><segments>{segs}</segments></file></nzb>",
        ids.len()
    )
}

fn ids_of(bytes: &str) -> spare::PostIds {
    spare::post_ids(&nzbkit::nzb::Nzb::parse(bytes.as_bytes()).expect("parse"))
}

/// The grabbed release every hold test adds. Slim carries no search, so
/// nothing there holds a spare and nothing there names this.
#[cfg(feature = "indexer")]
const PRIMARY: &str = "Show.Name.S01E01.1080p.WEB-GRPA";

fn queue_rows(d: &Arc<Daemon>) -> Vec<(String, String, bool, i32, String, String)> {
    d.queue
        .lock_ok()
        .iter()
        .map(|j| {
            let g = j.lock_ok();
            (
                g.nzo_id.clone(),
                g.name.clone(),
                g.paused,
                g.priority,
                g.held_for.clone(),
                g.origin.clone(),
            )
        })
        .collect()
}

/// Add the grabbed job, then run the spare walk over `cands` with an
/// in-memory fetcher. Returns (primary id, how many were held, the
/// tokens the walk actually asked for).
#[cfg(feature = "indexer")]
fn grab_and_hold(
    d: &Arc<Daemon>,
    primary_nzb: &str,
    cands: &[(&str, String)],
    want: usize,
) -> (String, usize, Vec<String>) {
    let e = d
        .enqueue(
            primary_nzb.as_bytes(),
            PRIMARY,
            "",
            -100,
            None,
            None,
            "indexer",
            false,
        )
        .expect("the grab itself");
    let list: Vec<spare::SpareCandidate> = cands
        .iter()
        .map(|(title, _)| spare::SpareCandidate {
            title: (*title).to_string(),
            source: "testdexer".into(),
            token: (*title).to_string(),
        })
        .collect();
    let asked = Mutex::new(Vec::new());
    let held = d.hold_spares_with(&e.nzo_id, &list, want, |c| {
        asked.lock_ok().push(c.token.clone());
        cands
            .iter()
            .find(|(t, _)| *t == c.title)
            .map(|(_, nzb)| nzb.as_bytes().to_vec())
            .ok_or_else(|| "no such candidate".to_string())
    });
    let asked = asked.lock_ok().clone();
    (e.nzo_id, held, asked)
}

// -- item 6: the admission test --------------------------------------------

/// The whole point. A candidate whose articles are the grabbed job's
/// articles is worthless as a backup - it fails identically - and must be
/// refused however good its release name looks.
///
/// The refused one is deliberately the BEST-ranked candidate (2160p
/// against the grab's 1080p), so a walk that admitted it would take it
/// first and this test would see it held rather than merely present.
#[cfg(feature = "indexer")]
#[test]
fn a_candidate_that_is_the_same_post_is_refused_admission() {
    with_daemon("spare-admission", |d| {
        let same = ["a1@x", "a2@x", "a3@x", "a4@x"];
        let other = ["b1@x", "b2@x", "b3@x", "b4@x"];
        let primary = nzb_of("poster-a", "alt.binaries.one", &same);
        let cands = [
            // Same articles, re-indexed under a better-looking name.
            (
                "Show.Name.S01E01.2160p.WEB-GRPA",
                nzb_of("poster-a", "alt.binaries.one", &same),
            ),
            // A genuinely different post of the same episode.
            (
                "Show.Name.S01E01.1080p.BluRay-GRPB",
                nzb_of("poster-b", "alt.binaries.two", &other),
            ),
            // A different episode entirely: never a spare for this job,
            // and the walk must not even pay to fetch it.
            (
                "Show.Name.S01E02.2160p.BluRay-GRPC",
                nzb_of("poster-c", "alt.binaries.three", &["c1@x"]),
            ),
        ];
        let (id, held, asked) = grab_and_hold(d, &primary, &cands, 2);

        assert_eq!(held, 1, "only the independent post is admissible");
        assert!(
            asked.contains(&"Show.Name.S01E01.2160p.WEB-GRPA".to_string()),
            "the same-post candidate is fetched before it can be judged: {asked:?}"
        );
        assert!(
            !asked.iter().any(|t| t.contains("S01E02")),
            "a different episode is filtered on identity, never fetched: {asked:?}"
        );
        let rows = queue_rows(d);
        assert_eq!(rows.len(), 2, "the grab plus one spare: {rows:?}");
        let spare = rows.iter().find(|r| r.0 != id).expect("the spare row");
        assert_eq!(spare.1, "Show.Name.S01E01.1080p.BluRay-GRPB");
        assert!(spare.2, "a spare is paused");
        assert_eq!(spare.3, DUPE_PRIORITY, "and held at Duplicate priority");
        assert_eq!(spare.4, id, "and names the job it is a spare for");
        assert_eq!(spare.5, "spare", "and is marked as one this daemon added");
    });
}

/// §282 items 13/19: `alt_hold_count = 0` means HOLD NOTHING, and the
/// walk must reach that answer without spending a grab to get there.
///
/// The count became a live setting when item 19 wired
/// `alt_hold_count` to this walk, and 0 is a value the user can
/// actually set - the number input goes down to it and the settings
/// copy offers it ("0 keeps none"). A `want` of 0 that still fetched
/// the first candidate before discovering it had nowhere to put it
/// would spend one metered indexer grab per download on a feature the
/// user has switched OFF, which is the one cost this whole section is
/// careful about.
///
/// So the assertion that matters is the THIRD one: not merely that
/// nothing is held, but that nothing was ASKED FOR. Held-but-not-fetched
/// and not-fetched-at-all look identical from the queue.
#[cfg(feature = "indexer")]
#[test]
fn a_hold_count_of_zero_holds_nothing_and_fetches_nothing() {
    with_daemon("spare-zero", |d| {
        let primary = nzb_of("poster-a", "alt.binaries.one", &["a1@x", "a2@x", "a3@x"]);
        let cands = [
            (
                "Show.Name.S01E01.2160p.WEB-GRPB",
                nzb_of("poster-b", "alt.binaries.two", &["b1@x", "b2@x", "b3@x"]),
            ),
            (
                "Show.Name.S01E01.720p.WEB-GRPC",
                nzb_of("poster-c", "alt.binaries.three", &["c1@x", "c2@x", "c3@x"]),
            ),
        ];
        let (primary_id, held, asked) = grab_and_hold(d, &primary, &cands, 0);
        assert_eq!(held, 0, "a zero hold count holds nothing");
        assert!(
            asked.is_empty(),
            "and must not spend a metered indexer grab to find that out: {asked:?}"
        );
        let rows = queue_rows(d);
        assert_eq!(
            rows.len(),
            1,
            "the grab itself and nothing beside it: {rows:?}"
        );
        assert_eq!(rows[0].0, primary_id);
    });
}

/// Two spares that are the same post as EACH OTHER are as useless as two
/// copies of the grab, so the second is refused too.
#[cfg(feature = "indexer")]
#[test]
fn two_spares_that_are_one_post_do_not_both_get_held() {
    with_daemon("spare-siblings", |d| {
        let primary = nzb_of("poster-a", "alt.binaries.one", &["a1@x", "a2@x", "a3@x"]);
        let twins = ["b1@x", "b2@x", "b3@x"];
        let cands = [
            (
                "Show.Name.S01E01.2160p.WEB-GRPB",
                nzb_of("poster-b", "alt.binaries.two", &twins),
            ),
            (
                "Show.Name.S01E01.2160p.HDTV-GRPB",
                nzb_of("poster-b", "alt.binaries.two", &twins),
            ),
            (
                "Show.Name.S01E01.720p.WEB-GRPC",
                nzb_of("poster-c", "alt.binaries.three", &["c1@x", "c2@x", "c3@x"]),
            ),
        ];
        let (_, held, _) = grab_and_hold(d, &primary, &cands, 2);
        assert_eq!(held, 2, "the twin is refused, the third fills the slot");
        let names: Vec<String> = queue_rows(d).into_iter().map(|r| r.1).collect();
        assert!(
            names.contains(&"Show.Name.S01E01.2160p.WEB-GRPB".to_string())
                && names.contains(&"Show.Name.S01E01.720p.WEB-GRPC".to_string())
                && !names.contains(&"Show.Name.S01E01.2160p.HDTV-GRPB".to_string()),
            "{names:?}"
        );
    });
}

/// Containment of the SMALLER post, not Jaccard: a repost carrying half
/// the original's articles is still the same articles for that half, and
/// is exactly as useless a backup.
#[test]
fn a_partial_repost_counts_as_the_same_post() {
    let full = nzb_of("p", "g", &["a1@x", "a2@x", "a3@x", "a4@x"]);
    let half = nzb_of("p", "g", &["a1@x", "a2@x", "z9@x", "z8@x"]);
    let none = nzb_of("p", "g", &["z1@x", "z2@x", "z3@x", "z4@x"]);
    assert!(
        !spare::admits(&ids_of(&full), &ids_of(&half), false),
        "half the set shared is well over the threshold"
    );
    assert!(spare::admits(&ids_of(&full), &ids_of(&none), false));
    // An empty side is NOT an overlap of zero, it is not knowing - and
    // the two callers answer that differently on purpose.
    let empty = spare::PostIds::default();
    assert!(!spare::admits(&ids_of(&full), &empty, false), "admission");
    assert!(spare::admits(&ids_of(&full), &empty, true), "promotion");
}

// -- item 7: the independence tiebreak -------------------------------------

/// Same rank, different group AND poster: the one that looks like an
/// independent post wins. A weak signal, and it only ever breaks a tie.
#[test]
fn a_different_group_and_poster_breaks_a_rank_tie() {
    let a = post_origin_of(&nzb_of("uploader-a", "alt.binaries.one", &["a1@x"]));
    let same_group = post_origin_of(&nzb_of("uploader-b", "alt.binaries.one", &["b1@x"]));
    let same_poster = post_origin_of(&nzb_of("uploader-a", "alt.binaries.two", &["c1@x"]));
    let independent = post_origin_of(&nzb_of("uploader-b", "alt.binaries.two", &["d1@x"]));
    assert!(spare::looks_independent(&a, &independent));
    assert!(!spare::looks_independent(&a, &same_group));
    assert!(!spare::looks_independent(&a, &same_poster));
    // Nothing said is never evidence.
    let anon = post_origin_of(&nzb_of("", "alt.binaries.three", &["e1@x"]));
    assert!(!spare::looks_independent(&a, &anon));
}

fn post_origin_of(bytes: &str) -> spare::PostOrigin {
    spare::post_origin(&nzbkit::nzb::Nzb::parse(bytes.as_bytes()).expect("parse"))
}

// -- the promote path ------------------------------------------------------

/// §282 item 6 applied to the EXISTING promote path: the best-ranked
/// candidate is skipped when it is the same post as the job that failed,
/// and the next one down is promoted instead. Before this, park promoted
/// a byte-different NZB of identical articles and the user watched the
/// same failure twice.
#[test]
fn the_promote_path_will_not_promote_the_same_post_again() {
    with_daemon("spare-promote-pick", |d| {
        let dir = d.spool.clone();
        let write = |name: &str, body: String| {
            let p = dir.join(format!("{name}.nzb"));
            std::fs::write(&p, body).expect("spool copy");
            p
        };
        let same = ["a1@x", "a2@x", "a3@x"];
        let failed = write("failed", nzb_of("p", "g", &same));
        let clone = write("clone", nzb_of("p", "g", &same));
        let real = write("real", nzb_of("q", "h", &["b1@x", "b2@x", "b3@x"]));
        let cands = [
            ("Show.Name.S01E01.2160p.BluRay-GRPA".to_string(), clone, 1),
            ("Show.Name.S01E01.720p.WEB-GRPB".to_string(), real, 1),
        ];
        let (i, _) = spare::best_alternative(&failed, &cands).expect("a promotable candidate");
        assert_eq!(i, 1, "the 2160p is the same post, so the 720p wins");

        // And with the failed job's own NZB unreadable, the pick degrades
        // to the pre-282 rank order rather than refusing everything.
        let gone = dir.join("nothing-here.nzb");
        let (i, _) = spare::best_alternative(&gone, &cands).expect("still promotable");
        assert_eq!(i, 0, "no fingerprint to compare: highest rank wins");
    });
}

/// §295, and the A/B is both legs of one pick. Two held spares: X
/// outranks Y on quality (2160p over 720p), and the prober has watched
/// X's post go red. Leg A - the pre-§295 pick, which is exactly what
/// equal bands produce - promotes X, and the user pays a full download
/// to rediscover what the probe already knew. Leg B - the bands the
/// prober actually wrote - promotes Y first. Within a band nothing
/// moved: the baseline leg IS the old ordering, pinned here so the A/B
/// is two measured outcomes of the same fixture rather than a claim
/// about history.
#[test]
fn a_probed_dead_spare_is_promoted_after_a_live_one() {
    with_daemon("spare-health-band", |d| {
        let dir = d.spool.clone();
        let write = |name: &str, body: String| {
            let p = dir.join(format!("{name}.nzb"));
            std::fs::write(&p, body).expect("spool copy");
            p
        };
        let failed = write("hb-failed", nzb_of("p", "g", &["ha1@x", "ha2@x"]));
        let x = write("hb-x", nzb_of("q", "h", &["hb1@x", "hb2@x"]));
        let y = write("hb-y", nzb_of("r", "i", &["hc1@x", "hc2@x"]));
        let name_x = "Show.Name.S01E01.2160p.BluRay-GRPX".to_string();
        let name_y = "Show.Name.S01E01.720p.WEB-GRPY".to_string();

        // Leg A: no probe has run (band 1 everywhere) - the quality
        // rank decides, X wins. This is the pre-§295 behaviour.
        let blind = [
            (name_x.clone(), x.clone(), 1),
            (name_y.clone(), y.clone(), 1),
        ];
        let (i, _) = spare::best_alternative(&failed, &blind).expect("promotable");
        assert_eq!(i, 0, "leg A (unprobed): quality rank picks the 2160p");
        println!("§295 A/B leg A (no probe): promotion picks {}", blind[i].0);

        // Leg B: the prober marked X red - the band overrules the rank.
        let probed = [(name_x.clone(), x, 3), (name_y.clone(), y, 0)];
        let (i, _) = spare::best_alternative(&failed, &probed).expect("promotable");
        assert_eq!(
            i, 1,
            "leg B (X probed red): the live 720p is promoted first"
        );
        println!(
            "§295 A/B leg B (X probed red): promotion picks {}",
            probed[i].0
        );

        // The band never REFUSES: an all-red ladder still promotes its
        // best rung rather than leaving everything parked.
        let allred = [
            (name_x, probed[0].1.clone(), 3),
            (name_y, probed[1].1.clone(), 3),
        ];
        let (i, _) = spare::best_alternative(&failed, &allred).expect("still promotable");
        assert_eq!(i, 0, "equal bands fall back to the old order exactly");
    });
}

/// §295's other half: the numbers the bands come from.
/// `promote_band` orders green ahead of unprobed ahead of amber ahead
/// of red, and the worse of payload and recovery decides - a spare
/// whose recovery set is dead fails exactly like one whose payload is.
#[test]
fn promote_band_orders_green_unprobed_amber_red() {
    use crate::health::{Bucket, promote_band};
    let verdict = |b: Bucket, rec: Option<Bucket>| crate::health::PostHealth {
        bucket: b,
        reason: String::new(),
        sampled: 8,
        present: 8,
        absent: 0,
        answered: 1,
        servers: 1,
        per_server: Vec::new(),
        age_days: 1,
        checked_at: 0,
        probes: 1,
        waived: false,
        completable: None,
        recovery: rec.map(|rb| crate::health::RecoveryHealth {
            bucket: rb,
            reason: String::new(),
            sampled: 4,
            present: 4,
            absent: 0,
            answered: 1,
            servers: 1,
            per_server: Vec::new(),
            volumes: 2,
            fetched: None,
        }),
    };
    assert_eq!(
        promote_band(None),
        1,
        "unprobed sits between green and amber"
    );
    assert_eq!(promote_band(Some(&verdict(Bucket::Green, None))), 0);
    assert_eq!(promote_band(Some(&verdict(Bucket::Amber, None))), 2);
    assert_eq!(promote_band(Some(&verdict(Bucket::Red, None))), 3);
    assert_eq!(
        promote_band(Some(&verdict(Bucket::Green, Some(Bucket::Red)))),
        3,
        "a dead recovery set is §282's founding incident - it must weigh \
         exactly as much as a dead payload"
    );
    assert_eq!(
        promote_band(Some(&verdict(Bucket::Green, Some(Bucket::Green)))),
        0
    );
}

/// End to end, and the shape the feature is FOR: a grab holds two
/// spares, the grab fails, the best surviving spare is promoted, and the
/// one that did not win is re-pointed at it so the ladder has a second
/// rung.
#[cfg(feature = "indexer")]
#[test]
fn the_best_spare_is_promoted_when_the_grab_fails() {
    with_daemon("spare-promote", |d| {
        // The promotion runs on the AUTOMATIC road, so it reads the
        // metered guard - see `flat_rate_config`. Without this the
        // winner stays held at -3 on any host with no SABnzbd install,
        // which is every CI runner and no machine on this fleet.
        flat_rate_config(d);
        let primary = nzb_of("poster-a", "alt.binaries.one", &["a1@x", "a2@x"]);
        let cands = [
            (
                "Show.Name.S01E01.2160p.BluRay-GRPB",
                nzb_of("poster-b", "alt.binaries.two", &["b1@x", "b2@x"]),
            ),
            (
                "Show.Name.S01E01.720p.WEB-GRPC",
                nzb_of("poster-c", "alt.binaries.three", &["c1@x", "c2@x"]),
            ),
        ];
        let (id, held, _) = grab_and_hold(d, &primary, &cands, 2);
        assert_eq!(held, 2);

        let job = d
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == id)
            .cloned()
            .expect("the grab");
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "articles never arrived".into();
            g.finished_unix = Some(1);
        }
        d.park_gen(job, None);

        let rows = queue_rows(d);
        assert_eq!(rows.len(), 2, "the grab has left the queue: {rows:?}");
        let winner = rows
            .iter()
            .find(|r| r.1.contains("2160p"))
            .expect("the best spare");
        assert!(
            !winner.2 && winner.3 == 0,
            "promoted and running: {winner:?}"
        );
        let other = rows
            .iter()
            .find(|r| r.1.contains("720p"))
            .expect("the other spare");
        assert!(other.2 && other.3 == DUPE_PRIORITY, "still held: {other:?}");
        assert_eq!(
            other.4, winner.0,
            "and now held against the row that replaced the grab"
        );
    });
}

/// Sweep 9, finding 5: the failure a promotion is ABOUT can be deleted
/// from history while park is still inside the park that filed it.
///
/// `park_gen` emits `job.failed` (the dashboard pairs that emit with
/// the replacement one, so the order is deliberate) and only then
/// promotes. A subscriber acting on the event - an *arr script, a
/// dashboard `mode=history&name=delete` - can remove the record in
/// between, and park went on to unpause a spare on the strength of a
/// `tombstone` flag snapshotted long before. `tombstone` is a statement
/// about the QUEUE row and cannot answer this; the user who dismissed a
/// failure watched the same title start downloading.
///
/// "The owner is in neither store" is precisely what
/// `drop_stranded_spares` sweeps, so the spares go now rather than at
/// the next sweep - and a promoted row would be past that sweep's reach
/// anyway, being a download in its own right rather than a held one.
#[cfg(feature = "indexer")]
#[test]
fn a_history_delete_inside_the_park_drops_the_spare_instead_of_starting_it() {
    with_daemon("spare-promote-race", |d| {
        // As above: the drop asserted below has to be the tombstone
        // re-check's answer, not the metered guard's.
        flat_rate_config(d);
        let primary = nzb_of("poster-a", "alt.binaries.one", &["a1@x", "a2@x"]);
        let cands = [(
            "Show.Name.S01E01.2160p.BluRay-GRPB",
            nzb_of("poster-b", "alt.binaries.two", &["b1@x", "b2@x"]),
        )];
        let (id, held, _) = grab_and_hold(d, &primary, &cands, 2);
        assert_eq!(held, 1);

        let job = d
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == id)
            .cloned()
            .expect("the grab");
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "articles never arrived".into();
            g.finished_unix = Some(1);
        }
        // Item 8's other road out of the same decision: with nothing
        // held, park asks the hunt worker for a replacement. That is
        // the promotion's bug wearing a different hat, so it is pinned
        // from the same window rather than left for the next sweep.
        d.alt.auto_search.store(true, Ordering::Relaxed);
        // The webhook's delete, at the one instant it races: the record
        // is filed and announced, nothing is unpaused yet.
        let doomed = id.clone();
        crate::serve::storecut::on_promote_gap(move |d| {
            d.history.lock_ok().retain(|j| j.lock_ok().nzo_id != doomed);
        });
        d.park_gen(job, None);
        crate::serve::storecut::disarm();

        let rows = queue_rows(d);
        assert!(
            rows.iter().all(|r| r.2 && r.3 == DUPE_PRIORITY),
            "a dismissed failure started its alternative anyway: {rows:?}"
        );
        assert!(
            rows.is_empty(),
            "the owner is in neither store, so park should have cleared it: {rows:?}"
        );
        assert!(
            d.hunt.q.lock_ok().is_empty(),
            "a dismissed failure was sent to the hunt worker for a replacement"
        );
    });
}

/// A spare exists to catch a failure. When the job it was held for is
/// done with - completed, or deleted by the user - the row goes, and its
/// spooled NZB with it. Leaving either behind is §4b's junk queue: rows
/// nobody asked for, re-adopted from the spool at every restart.
#[cfg(feature = "indexer")]
#[test]
fn spares_are_dropped_when_the_grab_no_longer_needs_them() {
    with_daemon("spare-cleanup", |d| {
        let primary = nzb_of("poster-a", "alt.binaries.one", &["a1@x", "a2@x"]);
        let cands = [(
            "Show.Name.S01E01.2160p.BluRay-GRPB",
            nzb_of("poster-b", "alt.binaries.two", &["b1@x", "b2@x"]),
        )];
        let (id, held, _) = grab_and_hold(d, &primary, &cands, 2);
        assert_eq!(held, 1);
        let spool: Vec<PathBuf> = d
            .queue
            .lock_ok()
            .iter()
            .filter(|j| j.lock_ok().nzo_id != id)
            .map(|j| j.lock_ok().nzb_path.clone())
            .collect();
        assert!(spool[0].exists());

        // Through park, not through the helper: the wiring is the half
        // that can be forgotten, and a job that COMPLETED takes the same
        // exit as one that failed.
        let job = d
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == id)
            .cloned()
            .expect("the grab");
        {
            let mut g = job.lock_ok();
            g.state = JobState::Completed;
            g.finished_unix = Some(1);
        }
        d.park_gen(job, None);
        assert!(
            queue_rows(d).is_empty(),
            "the grab has parked and its spare went with it: {:?}",
            queue_rows(d)
        );
        assert!(
            !spool[0].exists(),
            "the spool copy goes too, or recover_orphaned_spool puts the row back"
        );
    });
}

/// A duplicate the USER added is theirs. It looks identical to a spare -
/// paused, Duplicate priority, `held_for` set - and the only thing that
/// tells them apart is the origin, which is why the cleanup asks.
#[test]
fn a_user_added_duplicate_is_never_dropped_as_a_spare() {
    with_daemon("spare-not-mine", |d| {
        d.queue.lock_ok().push_back(jv(
            "nzo-theirs",
            "Show.Name.S01E01.1080p.WEB-GRPB",
            serde_json::json!({
                "paused": true, "priority": DUPE_PRIORITY,
                "held_for": "nzo-owner", "origin": "dashboard",
            }),
        ));
        d.queue.lock_ok().push_back(jv(
            "nzo-mine",
            "Show.Name.S01E01.720p.WEB-GRPC",
            serde_json::json!({
                "paused": true, "priority": DUPE_PRIORITY,
                "held_for": "nzo-owner", "origin": "spare",
            }),
        ));
        d.drop_spares_for("nzo-owner");
        let left: Vec<String> = queue_rows(d).into_iter().map(|r| r.0).collect();
        assert_eq!(left, vec!["nzo-theirs".to_string()]);
    });
}

/// §282 item 5's residue: a spare whose owner has left BOTH stores is
/// dropped, and one whose owner is still findable is not.
///
/// The state this pins is the one `drop_spares_for`'s single caller
/// cannot reach. `daemon_park::park_gen` fires it when the owner
/// completes or is deleted while the park can still see it; a history
/// row retired by retention, deleted through the SAB or dashboard API,
/// or a queued row deleted with no park behind it all leave the spare
/// paused at Duplicate priority naming an id nothing can resolve -
/// unpromotable, unofferable and, until this sweep, undroppable, with
/// `recover_orphaned_spool` putting it back after every restart.
///
/// Four rows, and each of the three survivors is a different reason to
/// leave one alone.
#[test]
fn a_spare_whose_owner_left_both_stores_is_dropped_and_the_others_are_not() {
    with_daemon("spare-stranded", |d| {
        let spool =
            std::env::temp_dir().join(format!("nzbfast-282-stranded-{}.nzb", std::process::id()));
        std::fs::write(&spool, b"<nzb></nzb>").expect("write spool fixture");
        // The owner that is still QUEUED, and its spare.
        d.queue
            .lock_ok()
            .push_back(jv("owner-live", "Show.S01E01-A", serde_json::json!({})));
        let held = |id: &str, owner: &str, origin: &str, path: &std::path::Path| {
            jv(
                id,
                "Show.S01E01-B",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": owner, "origin": origin,
                    "nzb_path": path.to_string_lossy(),
                }),
            )
        };
        {
            let mut q = d.queue.lock_ok();
            q.push_back(held("keep-queued", "owner-live", "spare", &spool));
            q.push_back(held("keep-filed", "owner-filed", "spare", &spool));
            q.push_back(held("keep-inflight", "owner-moving", "spare", &spool));
            // The user's own duplicate of the same dead job: identical in
            // every field the sweep can see except the origin, which is
            // the only thing that tells them apart.
            q.push_back(held("keep-theirs", "owner-gone", "dashboard", &spool));
            q.push_back(held("drop-me", "owner-gone", "spare", &spool));
        }
        d.history.lock_ok().push(jv(
            "owner-filed",
            "Show.S02E01-A",
            serde_json::json!({"state": "Failed"}),
        ));
        // In transit between the two stores: absent from both, and NOT
        // stranded. Every mover registers here before it touches either.
        d.hist_inflight.lock_ok().insert("owner-moving".to_string());

        d.drop_stranded_spares();

        let left: Vec<String> = queue_rows(d).into_iter().map(|r| r.0).collect();
        assert_eq!(
            left,
            vec![
                "owner-live".to_string(),
                "keep-queued".to_string(),
                "keep-filed".to_string(),
                "keep-inflight".to_string(),
                "keep-theirs".to_string(),
            ],
            "only the spare held for a job in neither store may go"
        );
        // The spool copy goes with the row, or `recover_orphaned_spool`
        // re-adopts it at the next start with nothing to hold it against.
        assert!(
            !spool.is_file(),
            "the dropped spare's spooled NZB is still on disk"
        );
        let _ = std::fs::remove_file(&spool);
    });
}

/// A spare with no `held_for` at all is never touched by the sweep.
///
/// That is the pre-`held_for` shape `altcand::HeldSpare::held_against`
/// matches by `dupe_key`: there is no owner id in it to ask about, so
/// "is that job still around" has no answer here and the sweep does not
/// guess one.
#[test]
fn a_spare_with_no_owner_id_is_left_alone_by_the_sweep() {
    with_daemon("spare-stranded-legacy", |d| {
        d.queue.lock_ok().push_back(jv(
            "old-shape",
            "Show.S01E01-B",
            serde_json::json!({
                "paused": true, "priority": DUPE_PRIORITY,
                "origin": "spare", "dupe_key": "show/s1e1",
            }),
        ));
        d.drop_stranded_spares();
        assert_eq!(d.queue.lock_ok().len(), 1, "the legacy hold was dropped");
    });
}

/// The sweep's three reads NOMINATE; the drop re-asks under one hold.
///
/// The reads are taken and released one at a time, so a mover that
/// writes its destination store AND drops its `hist_inflight`
/// registration inside the gap between two of them is in none of the
/// three samples - a retry whose guard drops between the history read
/// and the inflight read, a park whose history push lands there too.
/// Nothing re-verified before the rows went, and the drop unlinks the
/// spooled NZB, so the answer could not be taken back: the alternatives
/// had to be searched for again at fresh indexer cost.
///
/// Each arm here is one store answering "it came back" on its own.
#[test]
fn a_drop_refuses_an_owner_that_came_back_after_it_was_nominated() {
    with_daemon("spare-nominate-recheck", |d| {
        let spool =
            std::env::temp_dir().join(format!("nzbfast-282-recheck-{}.nzb", std::process::id()));
        let hold = |path: &std::path::Path| {
            jv(
                "spare-row",
                "Show.S01E01-B",
                serde_json::json!({
                    "paused": true, "priority": DUPE_PRIORITY,
                    "held_for": "owner-back", "origin": "spare",
                    "nzb_path": path.to_string_lossy(),
                }),
            )
        };
        // Landed in the QUEUE (a retry's push), in HISTORY (a park's
        // file), and still REGISTERED (either mover mid-flight).
        for back in ["queue", "history", "inflight"] {
            std::fs::write(&spool, b"<nzb></nzb>").expect("write spool fixture");
            d.queue.lock_ok().clear();
            d.history.lock_ok().clear();
            d.hist_inflight.lock_ok().clear();
            d.queue.lock_ok().push_back(hold(&spool));
            match back {
                "queue" => d.queue.lock_ok().push_back(jv(
                    "owner-back",
                    "Show.S01E01-A",
                    serde_json::json!({}),
                )),
                "history" => d.history.lock_ok().push(jv(
                    "owner-back",
                    "Show.S01E01-A",
                    serde_json::json!({"state": "Failed"}),
                )),
                _ => {
                    d.hist_inflight.lock_ok().insert("owner-back".to_string());
                }
            }
            d.drop_spares_if_still_stranded("owner-back");
            assert!(
                d.queue
                    .lock_ok()
                    .iter()
                    .any(|j| j.lock_ok().nzo_id == "spare-row"),
                "the spare was dropped for an owner that is alive in the {back}"
            );
            assert!(
                spool.is_file(),
                "the spare's spooled NZB was unlinked for an owner alive in the {back}"
            );
        }
        // And with the owner gone from all three, the drop still fires:
        // the re-test must not have turned the sweep into a no-op.
        d.queue.lock_ok().clear();
        d.history.lock_ok().clear();
        d.hist_inflight.lock_ok().clear();
        d.queue.lock_ok().push_back(hold(&spool));
        d.drop_spares_if_still_stranded("owner-back");
        assert!(
            d.queue.lock_ok().is_empty(),
            "a genuinely stranded spare was left behind"
        );
        assert!(
            !spool.is_file(),
            "the dropped spare's spool copy is still on disk"
        );
        let _ = std::fs::remove_file(&spool);
    });
}
