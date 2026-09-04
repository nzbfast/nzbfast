//! Parity scoreboard (research R1 / red-team build-order #8): once a
//! day, sample the newest releases per category from the user's OWN
//! reference newznab indexer and score each against our index - do we
//! have the post, is it NAMED (exact title/episode parity), and how
//! many hours behind were we? The per-category coverage% / named% /
//! lag numbers are the yardstick every naming lane (Spotnet, Pesto,
//! B3, RAR, NZB ingestion, correlation) is measured by.
//!
//! Source policy, per the red-team's correction of R1: there is NO
//! default source. The one keyless candidate (AnimeTosho) measured ~92
//! days stale, and a shipped key would tie the anonymous project to a
//! named account - so the only sources are the user's own: either one
//! of their already-configured indexer accounts (`scoreboard_source`,
//! a name resolved against `indexers` at run time) or a reference
//! URL + API key pasted just for this. Reusing an account the user
//! already entered is still the user's own credentials on their own
//! quota - it just stops asking them to type the key twice. The task
//! is inert until the switch is on AND a reference resolves.
//!
//! Manners are predb_seed's, and constants for the same reason: one
//! request per category per day with a fixed pace between them, an
//! honest User-Agent via the shared indexer agent, and any 403/429 or
//! quota answer ends the run on the spot with a 6 h cooling stamp.

use super::*;

/// One request per this many milliseconds, everywhere, no exceptions.
const PACE_MS: u64 = 2_000;
/// A refusal (403/429/quota) marks the source cooling for this long.
const COOL_SECS: i64 = 6 * 3_600;
/// Runs are a day apart, minus slack so a slow tick cannot push the
/// run past the next day's poll and skip a day outright.
const RUN_EVERY_SECS: i64 = 23 * 3_600;
/// Newest releases sampled per category - one API page.
const PAGE_LIMIT: u32 = 100;
/// NZB fetches a calibration pass may spend per run. This is the
/// user's metered grab quota, which is why the whole pass is opt-in
/// (`scoreboard_calibrate`) and the budget is small: the free tiers
/// this is sized for allow 5 grabs a day.
const CAL_MAX: usize = 5;
/// The zero-cost recheck pass: how far back unproven verdicts are
/// re-matched against today's index, and how many per run. A post our
/// scanner reached after the sample upgrades from missing to a hit
/// with its lag on record; a week covers any realistic catch-up.
const RECHECK_WINDOW_SECS: i64 = 7 * 86_400;
const RECHECK_MAX: usize = 2_000;
/// Rows per lock hold within the recheck pass (see the chunk loop).
const RECHECK_CHUNK: usize = 200;

/// The daily driver. Polls cheap gates every few minutes and hands the
/// actual run to a blocking thread, predb_seed style.
///
/// The sampled categories are `SCOREBOARD_CATEGORIES` narrowed by the
/// user's `scoreboard_cats` pick - resolved per run through
/// `Daemon::scoreboard_categories()`, because indexers meter every call
/// and the user is allowed to spend fewer than four a day. That filter
/// can only ever REMOVE a category, so this run is never more than one
/// request per built-in category and never fewer than one in total.
#[cfg(feature = "indexer")]
pub fn spawn_scoreboard(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        // CLAUDE.md invariant 5: the gate that fences every other
        // outbound enrichment call fences this one, and it is asked of
        // `may_call_out` so there is one copy of the rule. Checked once
        // - the variable is process-wide and static - so a test daemon
        // can never put a request on the wire.
        if !crate::identity::may_call_out() {
            *d.scoreboard.status.lock_ok() = "disabled by NZBFAST_NO_ENRICH".to_string();
            return;
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            if !d.scoreboard.enabled.load(Ordering::Relaxed)
                || d.offline.load(Ordering::Relaxed)
                || d.indexer_off()
            {
                continue;
            }
            // A reference that does not resolve (nothing configured, or
            // the chosen account was renamed / deleted / turned off)
            // parks the task with the reason on the status line.
            if let Err(why) = d.scoreboard_reference() {
                *d.scoreboard.status.lock_ok() = why;
                continue;
            }
            let now = unix_now();
            // Both gates in ONE index visit, and "could not read" is
            // NOT "never ran": with the index unopenable (disk full,
            // corruption) the gates would read as clear, the run would
            // proceed to the wire, and the last-run stamp write would
            // fail just as silently - turning the one-visit-a-day
            // promise into ~288 requests/day against the user's
            // indexer, with even the 403 cooldown unable to stick.
            let Some((cooling, last_run)) = d.with_index(|ix| {
                Some((
                    ix.kv_get("scoreboard_cooling"),
                    ix.kv_get("scoreboard_last_run"),
                ))
            }) else {
                continue;
            };
            let num = |v: Option<String>| v.and_then(|v| v.parse::<i64>().ok());
            if num(cooling).is_some_and(|until| now < until) {
                continue;
            }
            if num(last_run).is_some_and(|at| now - at < RUN_EVERY_SECS) {
                continue;
            }
            if d.scoreboard.running.swap(true, Ordering::SeqCst) {
                continue;
            }
            let d2 = d.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let out = run(&d2);
                d2.scoreboard.running.store(false, Ordering::SeqCst);
                out
            })
            .await;
            match outcome {
                Ok(Ok(msg)) => {
                    info!(target: "scoreboard", "sample run done: {msg}");
                    *d.scoreboard.status.lock_ok() = msg;
                }
                Ok(Err(e)) => {
                    warn!(target: "scoreboard", "sample run stopped: {e}");
                    *d.scoreboard.status.lock_ok() = format!("stopped: {e}");
                }
                // The blocking task panicked; the running flag was left
                // set, so clear it rather than wedging forever.
                Err(_) => d.scoreboard.running.store(false, Ordering::SeqCst),
            }
            // A failed attempt costs the DAY, success or not: without
            // this stamp a source that answers but answers badly (empty
            // categories, parse trouble) would be re-asked every five
            // minutes all day, which is not the one-visit-a-day profile
            // this task promises. The status line says what went wrong.
            let stamp = unix_now();
            d.with_index_mut(|ix| ix.kv_set("scoreboard_last_run", &stamp.to_string()).ok());
        }
    });
}

/// A calibration candidate remembered from the run: enough to re-store
/// the corrected row. The NZB link is held in memory only - it carries
/// the user's API key and is never written anywhere.
#[cfg(feature = "indexer")]
struct CalPick {
    sample: nzbkit::index::ScoreboardSample,
    link: String,
}

/// `pub(super)` so the lane-proof test (tasks/lane_proof_tests.rs) can
/// drive one whole run without the daily poll loop in front of it.
#[cfg(feature = "indexer")]
pub(super) fn run(d: &Arc<Daemon>) -> Result<String, String> {
    let say = |what: &str| *d.scoreboard.status.lock_ok() = what.to_string();
    // Resolved again here (the gate checked minutes ago): the run must
    // use whatever the chosen account says NOW, and a reference that
    // stopped resolving in between ends the run with the reason.
    let (ref_url, ref_key) = d.scoreboard_reference()?;
    let cfg = crate::newznab::IndexerConfig {
        name: "scoreboard".to_string(),
        url: ref_url,
        apikey: ref_key,
        // Newznab, and `scoreboard_reference` refuses any other kind
        // before we get here: this lane samples by CATEGORY with an
        // empty query, which nzbindex has no answer for (TODO 297).
        kind: crate::newznab::SourceKind::Newznab,
        nzbindex: Default::default(),
        enabled: true,
        priority: 0,
        hits_per_day: 0,
        grabs_per_day: 0,
    };
    // The stored source is the HOST: enough to key samples per far end,
    // and never the URL, which can carry the key.
    let source = host_of(&cfg.endpoint());
    if source.is_empty() {
        return Err("the reference URL does not look like a URL".to_string());
    }
    let now = unix_now();
    // The free half first: yesterday's unproven verdicts re-matched
    // against today's index, so sampling ahead of our scanner reads as
    // lag rather than a permanent coverage hole. Costs no API hit.
    // Chunked across separate lock holds: each row can cost a full
    // band scan (thousands of parse_release calls), and one hold over
    // the whole window parks every other index user - scan folds, spot
    // promotion, API side-writes - behind this daily nicety.
    let mut improved = 0usize;
    let mut after = 0i64;
    for _ in 0..RECHECK_MAX.div_ceil(RECHECK_CHUNK) {
        let Some((n, last)) = d.with_index_mut(|ix| {
            ix.scoreboard_recheck(now - RECHECK_WINDOW_SECS, after, RECHECK_CHUNK)
                .ok()
        }) else {
            break;
        };
        improved += n;
        let Some(last) = last else { break };
        after = last;
    }
    if improved > 0 {
        info!(target: "scoreboard", "recheck: {improved} earlier verdict(s) improved");
    }
    let mut samples: Vec<nzbkit::index::ScoreboardSample> = Vec::new();
    let mut cal_pool: Vec<CalPick> = Vec::new();
    // Set by every category that answers; a `cal_pool` entry can only
    // come from a search that succeeded, so a pool worth calibrating
    // always has an origin behind it.
    let mut origin: Option<SourceOrigin> = None;
    let mut requests = 0u32;
    // Read once, so a mid-run settings change cannot make the run cost
    // more than the figure the card quoted when it started.
    let categories = d.scoreboard_categories();
    for (cat, label) in &categories {
        say(&format!("sampling {label} from {source}"));
        std::thread::sleep(std::time::Duration::from_millis(PACE_MS));
        requests += 1;
        let q = crate::newznab::SearchQuery {
            cats: vec![*cat],
            limit: PAGE_LIMIT,
            ..Default::default()
        };
        let items = match indexer_search_one(&cfg, &q) {
            Ok((items, from)) => {
                // The calibration fetches are bound to whatever the
                // reference indexer answered THIS run from, not to a
                // fresh resolution of its name (M9).
                origin = Some(from);
                items
            }
            Err(e @ crate::newznab::NewznabError::Limit(..))
            | Err(e @ crate::newznab::NewznabError::Auth(..)) => {
                // Told to go away (quota, 429, bad key): stamp the
                // cooldown and end the whole run - a client that keeps
                // asking is how polite budgets get revoked.
                let until = now + COOL_SECS;
                d.with_index_mut(|ix| ix.kv_set("scoreboard_cooling", &until.to_string()).ok());
                return Err(format!(
                    "{} - cooling off for 6 h",
                    redact_apikey(&e.to_string())
                ));
            }
            Err(e) => {
                // A transient category failure costs that category's
                // day, not the run.
                warn!(
                    target: "scoreboard",
                    "{label}: {}",
                    redact_apikey(&e.to_string())
                );
                continue;
            }
        };
        for item in items {
            let Some(m) = d.with_index(|ix| {
                ix.scoreboard_match(&item.title, item.size, item.posted)
                    .ok()
            }) else {
                return Err("the index is unavailable".to_string());
            };
            let sample = nzbkit::index::ScoreboardSample {
                source: source.clone(),
                category: label.to_string(),
                ref_guid: item.guid.clone(),
                ref_name: item.title.clone(),
                ref_size: item.size,
                ref_posted: item.posted,
                ref_group: String::new(),
                verdict: m.verdict.to_string(),
                matched_release_id: m.release_id,
                key_used: m.key_used.to_string(),
                lag_secs: m.lag_secs,
            };
            // Band and missing verdicts are the ones a subject-stem
            // check can still teach us about; a stem hit is already
            // exact.
            if m.key_used != "stem" && !item.link.is_empty() {
                cal_pool.push(CalPick {
                    sample: sample.clone(),
                    link: item.link.clone(),
                });
            }
            samples.push(sample);
        }
    }
    if samples.is_empty() {
        return Err("the reference answered no results in any category".to_string());
    }
    let stored = d
        .with_index_mut(|ix| ix.scoreboard_store(&samples, now).ok())
        .ok_or_else(|| "the index was unavailable while storing".to_string())?;
    let calibrated = match (d.scoreboard.calibrate.load(Ordering::Relaxed), &origin) {
        (true, Some(origin)) => calibrate(d, &source, origin, &categories, cal_pool, now),
        _ => 0,
    };
    // scoreboard_last_run is stamped by the caller, success or failure.
    let named = samples.iter().filter(|s| s.verdict == "have_named").count();
    let have = samples.iter().filter(|s| s.verdict != "missing").count();
    Ok(format!(
        "{stored} sample(s) stored ({requests} request(s)): {named} named, \
         {have} present of {} - {calibrated} calibrated",
        samples.len()
    ))
}

/// Spend up to [`CAL_MAX`] NZB fetches proving presence exactly: the
/// article subjects inside a reference NZB reduce to the same stems
/// the scanner indexed under, so a stem hit is presence regardless of
/// obfuscation. Corrects the day's rows in place and keeps two kv
/// counters from which the API reports the band's measured precision -
/// the error bar the coverage estimate is quoted with.
#[cfg(feature = "indexer")]
fn calibrate(
    d: &Arc<Daemon>,
    source: &str,
    origin: &SourceOrigin,
    categories: &[(u32, &'static str)],
    pool: Vec<CalPick>,
    now: i64,
) -> usize {
    // Spread the budget across the categories THIS run sampled rather
    // than burning it all on whichever was sampled first. A category
    // the user turned off contributed nothing to the pool, so it takes
    // no share of the grab budget either.
    let mut picks: Vec<CalPick> = Vec::new();
    let mut round = 0usize;
    while picks.len() < CAL_MAX {
        let before = picks.len();
        for (_, label) in categories {
            if picks.len() >= CAL_MAX {
                break;
            }
            if let Some(p) = pool
                .iter()
                .filter(|p| p.sample.category == *label)
                .nth(round)
            {
                picks.push(CalPick {
                    sample: p.sample.clone(),
                    link: p.link.clone(),
                });
            }
        }
        if picks.len() == before {
            break;
        }
        round += 1;
    }
    let mut done = 0usize;
    let mut band_agree = 0u64;
    for p in &picks {
        std::thread::sleep(std::time::Duration::from_millis(PACE_MS));
        // fetch_url_from: p.link came out of the reference indexer's own
        // search response, so bind it to that indexer's origin (M12).
        let fetched = match fetch_url_from(&p.link, origin) {
            Ok(f) => f,
            Err(e) => {
                // The error can carry the link, and the link carries
                // the user's key.
                warn!(target: "scoreboard", "calibration fetch: {}", redact_url_creds(&e.to_string()));
                continue;
            }
        };
        let Ok(nzb) = nzbkit::nzb::Nzb::parse(&fetched.bytes) else {
            continue;
        };
        // The distinct subject stems (usually exactly one) looked up
        // exactly; a hit is proof of presence. What each stem is
        // ALLOWED to prove is Index::scoreboard_stem_lookup's call -
        // an NZB carries its set's furniture too, and `Subs` matching
        // somewhere in the index is not evidence about this release.
        let mut stems: Vec<String> = nzb
            .files
            .iter()
            .filter_map(|f| f.filename_hint())
            .map(nzbkit::extract::release_stem)
            .filter(|s| !s.is_empty())
            .collect();
        stems.sort_unstable();
        stems.dedup();
        let hit = d.with_index(|ix| {
            stems.iter().find_map(|s| {
                ix.scoreboard_stem_lookup(s, p.sample.ref_posted)
                    .ok()
                    .flatten()
            })
        });
        let was_present = p.sample.verdict != "missing";
        let mut corrected = p.sample.clone();
        corrected.key_used = "subject_stem".to_string();
        match hit {
            Some((id, seen)) => {
                // Present for certain. Named stays as the band decided:
                // a subject stem proves the bytes, not the name.
                if corrected.verdict == "missing" {
                    corrected.verdict = "have_unnamed".to_string();
                }
                corrected.matched_release_id = id;
                corrected.lag_secs = if p.sample.ref_posted > 0 && seen > p.sample.ref_posted {
                    seen - p.sample.ref_posted
                } else {
                    0
                };
                if was_present {
                    band_agree += 1;
                }
            }
            None => {
                corrected.verdict = "missing".to_string();
                corrected.matched_release_id = 0;
                corrected.lag_secs = 0;
                if !was_present {
                    band_agree += 1;
                }
            }
        }
        d.with_index_mut(|ix| ix.scoreboard_store(&[corrected], now).ok());
        done += 1;
    }
    if done > 0 {
        d.with_index_mut(|ix| {
            let bump = |ix: &mut nzbkit::index::Index, k: &str, by: u64| {
                let cur: u64 = ix.kv_get(k).and_then(|v| v.parse().ok()).unwrap_or(0);
                ix.kv_set(k, &(cur + by).to_string()).ok()
            };
            bump(ix, "scoreboard_cal_total", done as u64)?;
            bump(ix, "scoreboard_cal_band_ok", band_agree)
        });
        info!(
            target: "scoreboard",
            "calibration: {done} NZB(s) checked against {source}, band agreed on {band_agree}"
        );
    }
    done
}

/// `scheme://host[:port]/...` -> `host` (no port, no creds, no path).
fn host_of(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or("");
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    authority
        .rsplit_once(':')
        .map(|(h, p)| {
            if p.parse::<u16>().is_ok() {
                h
            } else {
                authority
            }
        })
        .unwrap_or(authority)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::host_of;

    /// The stored source must be the bare host: never a scheme, port,
    /// path, or anything that could carry a credential.
    #[test]
    fn host_of_strips_everything_but_the_host() {
        assert_eq!(
            host_of("https://api.example.org/api?apikey=k"),
            "api.example.org"
        );
        assert_eq!(
            host_of("http://user:pass@idx.example:8080/x"),
            "idx.example"
        );
        assert_eq!(host_of("https://IDX.Example"), "idx.example");
        assert_eq!(host_of("ftp://nope"), "");
        assert_eq!(host_of("not a url"), "");
    }
}
