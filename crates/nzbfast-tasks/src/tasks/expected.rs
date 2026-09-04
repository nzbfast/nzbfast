//! The expectation oracle: the release calendar says which TV episodes
//! AIRED (TVmaze) and which movies landed AT HOME (the keyless
//! digital-release calendars in `wall::digital`, TMDB first when a key
//! is set), and the confirm lane then goes and GETS them - one search
//! against the reference indexer, one grab, and the message-id join
//! names whatever dark rows that post left in our index.
//!
//! This is deliberately the TARGETING use of the calendar and not the
//! correlation use. research/AIRDATE-CORRELATION-2026-09-01.md measured
//! correlation on the same calendar and found the blocker: the
//! calendar carries no sizes, so the one axis that discriminates
//! (size, to 0.05%) cannot join to it, and date alone is a median 563
//! candidates. The targeting use routes around that entirely - the
//! calendar only picks WHAT to search for, and the msgid join replaces
//! the size join. A join is proof where a size band was the guess that
//! measured 0% precision (research/NAMECORR-PRECISION-2026-09-01.md).
//!
//! Also deliberately: the sweep enqueues episodes that aired 12 to 36
//! HOURS ago, never today's. An episode is popped exactly once and
//! rung (the seed lane's discipline), so searching before the post and
//! its listing exist would ring it forever as a miss; by 12 hours the
//! listing exists if it ever will, and the two-sweep window means each
//! episode is offered exactly one well-timed shot.
//!
//! State lives in index kv as JSON, NOT a new table - the expectation
//! list is a few hundred rows refreshed twice a day, which is the
//! standing reason. The second reason was schedule and has since gone
//! away: `additive_migrations` sat 5 lines under the 500-line fn
//! ceiling when this landed, so adding a table's DDL to it would have
//! reddened main. It was split into three ordered steps on 1 Sep 2026
//! (claim `size-ceiling-additive-migrations`) and now has room. A table
//! would still be the wrong shape for a few hundred rows - do not read
//! the split as an invitation to add one.

use super::*;

/// Titles (episodes and movies) waiting for their one targeted
/// attempt (index kv, JSON array of [`ExpectedPick`]).
const EXPECTED_QUEUE_KEY: &str = "expected_queue_v1";
/// Ring of titles already offered their shot, so a miss is never
/// retried. Keyed by `ring_key`, capped.
const EXPECTED_DONE_KEY: &str = "expected_done_v1";
/// When the last schedule sweep ran (index kv, unix seconds).
const EXPECTED_AT_KEY: &str = "expected_at";
/// Two sweeps a day: paired with the 12-36 h enqueue window below,
/// every aired episode falls into exactly one sweep's net (the movie
/// window is wider - see the sweep).
const EXPECTED_EVERY: i64 = 12 * 3_600;
/// Ceiling on queued titles per sweep. A full day of TV plus web is
/// several hundred; the queue drains at the daily confirm budget
/// (`confirm_budget`, 24 at minimum), so a cap far above the drain
/// rate only defers the same drop to staleness.
const EXPECTED_QUEUE_CAP: usize = 200;
const EXPECTED_DONE_CAP: usize = 1_000;

/// One thing the oracle wants confirmed: an aired TV episode or a
/// newly-at-home movie. Externally tagged, so a queue blob written by
/// a TV-only build (the first deploy of this lane) simply fails to
/// deserialize and the queue refills - which is why the queue is
/// disposable state and the done-ring below is a flat `Vec<String>`
/// that is unaffected by the shape change.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum ExpectedPick {
    Tv {
        show: String,
        season: u32,
        episode: u32,
    },
    Movie {
        title: String,
        year: u32,
    },
}

impl ExpectedPick {
    /// The free-text search query, the exact fallback `plan_query`
    /// itself uses: show plus `SxxEyy` for TV, title plus year for a
    /// movie.
    pub(crate) fn query(&self) -> String {
        match self {
            ExpectedPick::Tv {
                show,
                season,
                episode,
            } => format!("{show} S{season:02}E{episode:02}"),
            ExpectedPick::Movie { title, year } if *year > 0 => {
                format!("{title} {year}")
            }
            ExpectedPick::Movie { title, .. } => title.clone(),
        }
    }

    /// Does this listing title carry the identity? A TV pick needs the
    /// show AND the `SxxEyy` token (the token alone is not identity); a
    /// movie needs the title AND the year (the title alone collides
    /// across remakes) - both inside the listing's `match_key`.
    pub(crate) fn matches(&self, listing_key: &str) -> bool {
        match self {
            ExpectedPick::Tv {
                show,
                season,
                episode,
            } => {
                let show_key = nzbkit::predb::match_key(show);
                let code = format!("s{season:02}e{episode:02}");
                listing_key.contains(&show_key) && listing_key.contains(&code)
            }
            ExpectedPick::Movie { title, year } => {
                let title_key = nzbkit::predb::match_key(title);
                listing_key.contains(&title_key)
                    && (*year == 0 || listing_key.contains(&year.to_string()))
            }
        }
    }

    /// Display form for logs.
    pub(crate) fn label(&self) -> String {
        match self {
            ExpectedPick::Tv {
                show,
                season,
                episode,
            } => format!("{show} S{season:02}E{episode:02}"),
            ExpectedPick::Movie { title, year } => format!("{title} ({year})"),
        }
    }
}

/// TVmaze encodes a DAILY show's episodes as season = the calendar
/// year (Morning Joe S2026E173). The scene names dailies by DATE,
/// never by episode code, so an SxxEyy query can never match one -
/// and the broadcast day is dominated by cable news that never
/// reaches usenet at all. Measured within 25 minutes of the oracle
/// going live: 13 picks, 13 daily news shows, 0 listings (daemon.log
/// 16:24-16:40Z, 1 Sep 2026). Dailies are skipped at enqueue AND
/// discarded at pop, so a queue written before this filter drains
/// without spending attempts on them. The date-format query for the
/// late-night subset that IS posted is a follow-up once the cleaned
/// queue's hit rate is measured.
/// TWO encodings, both live-measured: season = the calendar year
/// (Morning Joe S2026E173), and a plausible season with the EPISODE
/// counter in the hundreds (First Take S20E237, TODAY S01E166 - both
/// slipped past the first arm within a minute of it deploying). No
/// weekly scripted show reaches E100 in a season - runs top out
/// around 26 - and the long-running anime that do cross 100 are
/// posted with absolute E-only numbering the SxxEyy query would not
/// match anyway.
fn is_daily(p: &ExpectedPick) -> bool {
    matches!(p, ExpectedPick::Tv { season, episode, .. }
        if *season >= 1900 || *episode >= 100)
}

fn ring_key(p: &ExpectedPick) -> String {
    match p {
        ExpectedPick::Tv {
            show,
            season,
            episode,
        } => format!(
            "tv{}s{season:02}e{episode:02}",
            nzbkit::predb::match_key(show)
        ),
        ExpectedPick::Movie { title, year } => {
            format!("mv{}{year}", nzbkit::predb::match_key(title))
        }
    }
}

/// "YYYY-MM-DD" for a unix timestamp, via the logging module's own
/// civil-calendar copy rather than a third one.
fn iso_day(ts: i64) -> String {
    let (y, m, d) = crate::logging::civil_from_days(ts.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Pop the next queued title, refreshing the queue from the release
/// calendars when the sweep is due. The schedule fetch is keyless
/// TVmaze, so it spends no indexer quota and none of the confirm
/// budget; the attempt the caller then makes is budgeted exactly like
/// a corr or seed pick.
#[cfg(test)]
pub(crate) fn expected_next(d: &Arc<Daemon>, now: i64) -> Option<ExpectedPick> {
    expected_next_at(d, now, d.index_era())
}

pub(crate) fn expected_next_at(
    d: &Arc<Daemon>,
    now: i64,
    selection_era: u64,
) -> Option<ExpectedPick> {
    maybe_refresh(d, now);
    pop_at(d, selection_era)
}

/// Put a popped pick back when the account, enclosure fetch, or durable seed
/// inbox failed transiently. `pop` records the pick in the done ring before
/// any network work, so retry must undo both halves or a paid proof can be
/// lost without another chance to acquire it.
#[cfg(test)]
pub(crate) fn expected_retry(d: &Arc<Daemon>, pick: &ExpectedPick) -> bool {
    expected_retry_at(d, d.index_era(), pick) == Some(true)
}

/// `Some(true)` restored the pick, `Some(false)` retired an old-generation
/// pick, and `None` means the same generation is temporarily unavailable.
pub(crate) fn expected_retry_at(
    d: &Arc<Daemon>,
    selection_era: u64,
    pick: &ExpectedPick,
) -> Option<bool> {
    d.with_index(|ix| {
        if d.index_era() != selection_era {
            return Some(false);
        }
        expected_retry_on_index(ix, pick, false)
    })
}

/// Upgrade bridge for the era-only v1 sidecar. An era is process-local and
/// cannot identify a database after restart, so accept the old record only
/// when this catalogue still carries the queue or done-ring ownership witness
/// written by the original pop.
pub(crate) fn expected_retry_legacy(d: &Arc<Daemon>, pick: &ExpectedPick) -> Option<bool> {
    d.with_index(|ix| expected_retry_on_index(ix, pick, true))
}

fn expected_retry_on_index(
    ix: &nzbkit::index::Index,
    pick: &ExpectedPick,
    require_witness: bool,
) -> Option<bool> {
    let key = ring_key(pick);
    let mut queue: Vec<ExpectedPick> = ix
        .kv_get(EXPECTED_QUEUE_KEY)
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default();
    let mut done: Vec<String> = ix
        .kv_get(EXPECTED_DONE_KEY)
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default();
    let queued = queue.iter().any(|candidate| ring_key(candidate) == key);
    if require_witness && !queued && !done.iter().any(|old| old == &key) {
        return Some(false);
    }
    if !queued {
        queue.insert(0, pick.clone());
    }
    done.retain(|old| old != &key);
    let queue = serde_json::to_string(&queue).ok()?;
    let done = serde_json::to_string(&done).ok()?;
    ix.retry_kv_set_durable(&[
        (EXPECTED_QUEUE_KEY, queue.as_str()),
        (EXPECTED_DONE_KEY, done.as_str()),
    ])
    .ok()?;
    Some(true)
}

fn maybe_refresh(d: &Arc<Daemon>, now: i64) {
    // The spawn ticker is gated, but tests drive corr_confirm_once
    // DIRECTLY, and this is the one step in that whole path that dials
    // the open internet - so the gate has to live here too, or every
    // test of the confirm lane makes a live TVmaze call (found the hard
    // way twice: the seed-pick test did, and then 1dbcca3c2 moved this
    // pick to the FRONT and three more did).
    //
    // Asked of `may_call_out` rather than of the environment: this
    // spelling read `== "1"` where the network boundary reads "set at
    // all", and in a unit-test build it is off by construction.
    if !crate::identity::may_call_out() {
        return;
    }
    let last: i64 = d
        .with_index(|ix| ix.kv_get(EXPECTED_AT_KEY).and_then(|v| v.parse().ok()))
        .unwrap_or(0);
    if now - last < EXPECTED_EVERY {
        return;
    }
    // Stamped before the requests, the seed sweep's rule: a sweep that
    // errors must still wait out the throttle.
    d.with_index(|ix| ix.kv_set(EXPECTED_AT_KEY, &now.to_string()).ok());
    // The 12-36 h window: both TV feeds for both days, deduped by the
    // done-ring so the overlap between consecutive sweeps costs
    // nothing.
    let mut picks: Vec<ExpectedPick> = Vec::new();
    for ts in [now - 12 * 3_600, now - 36 * 3_600] {
        let date = iso_day(ts);
        for feed in [false, true] {
            for e in crate::wall::tvmaze_schedule(&date, feed) {
                picks.push(ExpectedPick::Tv {
                    show: e.show,
                    season: e.season,
                    episode: e.episode,
                });
            }
        }
    }
    // The movie half: digital (at-home) releases over the last three
    // days, since a home release is a single day rather than a daily
    // broadcast and the wider window catches weekend drops. KEYLESS
    // since 2 Sep 2026: the calendar comes from dvdsreleasedates.com
    // (bingebase.com behind it) so an install with no TMDB key gets the
    // movie half too; a TMDB key, if set, is still asked first.
    // research/KEYLESS-MOVIE-DATES-2026-09-02.md has the probe of ten
    // sources and why these two.
    {
        let tmdb = d.tmdb_key.lock_ok().clone();
        let gte = iso_day(now - 3 * 86_400);
        let lte = iso_day(now - 12 * 3_600);
        let (movies, source) = crate::wall::digital::digital_releases(tmdb.as_deref(), &gte, &lte);
        tracing::debug!(
            target: "expected",
            "movie calendar {gte}..{lte}: {} titles via {source:?}",
            movies.len()
        );
        for m in movies {
            picks.push(ExpectedPick::Movie {
                title: m.title,
                year: m.year,
            });
        }
    }
    let done: Vec<String> = d
        .with_index(|ix| {
            ix.kv_get(EXPECTED_DONE_KEY)
                .and_then(|v| serde_json::from_str(&v).ok())
        })
        .unwrap_or_default();
    let mut queue: Vec<ExpectedPick> = d
        .with_index(|ix| {
            ix.kv_get(EXPECTED_QUEUE_KEY)
                .and_then(|v| serde_json::from_str(&v).ok())
        })
        .unwrap_or_default();
    let mut seen: std::collections::HashSet<String> = queue
        .iter()
        .map(ring_key)
        .chain(done.iter().cloned())
        .collect();
    let total = picks.len();
    for p in picks {
        if queue.len() >= EXPECTED_QUEUE_CAP {
            break;
        }
        if !is_daily(&p) && seen.insert(ring_key(&p)) {
            queue.push(p);
        }
    }
    if !queue.is_empty() {
        info!(
            target: "confirm",
            "expected sweep: {total} aired/released title(s) seen, {} queued for a targeted attempt",
            queue.len()
        );
    }
    d.with_index(|ix| {
        ix.kv_set(
            EXPECTED_QUEUE_KEY,
            &serde_json::to_string(&queue).unwrap_or_default(),
        )
        .ok()
    });
}

#[cfg(test)]
fn pop(d: &Arc<Daemon>) -> Option<ExpectedPick> {
    pop_at(d, d.index_era())
}

fn pop_at(d: &Arc<Daemon>, selection_era: u64) -> Option<ExpectedPick> {
    d.with_index(|ix| {
        if d.index_era() != selection_era {
            return None;
        }
        let mut queue: Vec<ExpectedPick> = ix
            .kv_get(EXPECTED_QUEUE_KEY)
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default();
        if queue.is_empty() {
            return None;
        }
        let mut done: Vec<String> = ix
            .kv_get(EXPECTED_DONE_KEY)
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default();
        // Dailies are rung and DISCARDED, never returned: the queue
        // the live daemon wrote before the filter existed still holds
        // them, and each must cost zero attempts on the way out.
        let mut picked = None;
        while !queue.is_empty() {
            let p = queue.remove(0);
            done.push(ring_key(&p));
            if !is_daily(&p) {
                picked = Some(p);
                break;
            }
        }
        if done.len() > EXPECTED_DONE_CAP {
            let cut = done.len() - EXPECTED_DONE_CAP;
            done.drain(..cut);
        }
        // Publish the suppression record before removing the queue entry.
        // If the process stops between these autocommit writes, the pick may
        // run twice after restart, but it is never silently lost.
        if ix
            .kv_set(
                EXPECTED_DONE_KEY,
                &serde_json::to_string(&done).unwrap_or_default(),
            )
            .is_err()
        {
            return None;
        }
        let _ = ix.kv_set(
            EXPECTED_QUEUE_KEY,
            &serde_json::to_string(&queue).unwrap_or_default(),
        );
        picked
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transient_failure_puts_a_popped_pick_back_and_clears_done() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-expected-retry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = crate::testutil::test_daemon(&dir);
        d.index_enabled.store(true, Ordering::Relaxed);
        let pick = ExpectedPick::Tv {
            show: "Retry Show".into(),
            season: 1,
            episode: 2,
        };
        d.with_index(|ix| {
            ix.kv_set(
                EXPECTED_QUEUE_KEY,
                &serde_json::to_string(&vec![pick.clone()]).unwrap(),
            )
            .ok()
        })
        .unwrap();

        let popped = pop(&d).unwrap();
        assert_eq!(popped.query(), pick.query());
        expected_retry(&d, &popped);
        let retried = pop(&d).unwrap();
        assert_eq!(retried.query(), pick.query());

        drop(d);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_republished_retry_remains_popppable_if_done_cleanup_did_not_commit() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-expected-retry-boundary-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = crate::testutil::test_daemon(&dir);
        d.index_enabled.store(true, Ordering::Relaxed);
        let pick = ExpectedPick::Movie {
            title: "Retry Boundary".into(),
            year: 2026,
        };
        let key = ring_key(&pick);
        d.with_index(|ix| {
            ix.kv_set(
                EXPECTED_QUEUE_KEY,
                &serde_json::to_string(&vec![pick.clone()]).unwrap(),
            )
            .ok()?;
            ix.kv_set(
                EXPECTED_DONE_KEY,
                &serde_json::to_string(&vec![key]).unwrap(),
            )
            .ok()
        })
        .unwrap();

        let recovered = pop(&d).expect("the queue row is the durable owner");
        assert_eq!(recovered.query(), pick.query());

        drop(d);
        let _ = std::fs::remove_dir_all(dir);
    }
}
