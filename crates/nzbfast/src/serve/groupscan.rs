//! Newsgroup discovery and profiling: the ISC description catalogue, the
//! server's own LIST ACTIVE, per-group sampling and the hourly burst that
//! makes the content filters useful, plus the one-off system probe.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Where ISC publishes the community's newsgroup descriptions: about
/// 45,000 of them, refreshed hourly, one `group<TAB>description` per line.
#[cfg(feature = "indexer")]
pub(super) const ISC_NEWSGROUPS_URL: &str = "https://ftp.isc.org/pub/usenet/CONFIG/newsgroups";

/// Cap on the descriptions file. It is around 3 MB; this is a ceiling on
/// a fetch from a host we do not control, not a size estimate.
#[cfg(feature = "indexer")]
pub(super) const ISC_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Fetch the ISC newsgroup descriptions.
///
/// Opt-in, and off by default, because it is the daemon's only outbound
/// request to a host that is not the user's news provider. It exists
/// because most binary providers answer LIST NEWSGROUPS with nothing at
/// all - measured on a real provider, 0 of 111,330 groups came back with
/// a description - which leaves the browser's search matching names only.
///
/// Goes through the SSRF-guarded agent like every other outbound fetch.
#[cfg(feature = "indexer")]
pub(super) fn fetch_isc_descriptions() -> std::result::Result<Vec<(String, String)>, String> {
    let resp = ssrf_safe_agent(3, 30)
        .get(ISC_NEWSGROUPS_URL)
        .call()
        .map_err(|e| format!("ISC descriptions: {e}"))?;
    // Bytes, then a lossy decode. The file is decades old and is NOT
    // valid UTF-8 - read_to_string on it fails outright with "stream did
    // not contain valid UTF-8", which is how this was found. Group names
    // are ASCII; only the odd description carries a stray Latin-1 byte,
    // and a replacement character in one description is a fair trade for
    // the other 45,000.
    let mut raw = Vec::new();
    use std::io::Read as _;
    resp.into_reader()
        .take(ISC_MAX_BYTES)
        .read_to_end(&mut raw)
        .map_err(|e| format!("ISC descriptions: {e}"))?;
    let body = String::from_utf8_lossy(&raw);
    let out: Vec<(String, String)> = body
        .lines()
        .filter_map(|l| {
            // Tab-separated, but the file has historically used runs of
            // whitespace too, so split on the first whitespace span.
            let (name, desc) = l.split_once(|c: char| c.is_whitespace())?;
            let desc = desc.trim();
            // "?" is the file's placeholder for "no description".
            if name.is_empty() || desc.is_empty() || desc == "?" {
                return None;
            }
            Some((name.to_string(), desc.to_string()))
        })
        .collect();
    if out.is_empty() {
        return Err("ISC descriptions: no usable lines".into());
    }
    Ok(out)
}

/// Fetch the full newsgroup catalogue from the primary server: LIST
/// ACTIVE (mandatory) + LIST NEWSGROUPS (optional descriptions - many
/// binary providers reject it, which just means blank descriptions).
#[cfg(feature = "indexer")]
pub(super) async fn fetch_group_catalog(
    config: &Path,
    prev: Option<&crate::groups::Catalog>,
    isc: bool,
) -> std::result::Result<crate::groups::Catalog, String> {
    let server = crate::load_server(config).map_err(|e| e.to_string())?;
    let (mut conn, _) = nzbkit::nntp::Connection::connect(&server)
        .await
        .map_err(|e| e.to_string())?;
    let active = conn.list_active().await.map_err(|e| e.to_string())?;
    let mut descs = conn.list_newsgroups().await.unwrap_or_default();
    conn.quit().await;
    if active.is_empty() {
        return Err("server returned an empty group list".into());
    }
    if isc {
        // ISC goes FIRST and the provider's own list is appended on top.
        // Catalog::build collects these into a HashMap, so the last entry
        // for a name wins - which has to be the user's own server, since
        // it is authoritative about what it actually carries.
        match tokio::task::spawn_blocking(fetch_isc_descriptions).await {
            Ok(Ok(mut merged)) => {
                info!(target: "groups", "ISC descriptions: {} fetched", merged.len());
                // Drop the provider's non-descriptions FIRST. Some servers
                // answer LIST NEWSGROUPS by echoing each group's own name
                // back as its description; Catalog::build already discards
                // those as junk, but because the provider list is applied
                // last they would first overwrite every real ISC entry.
                // Measured: without this, 45,006 fetched descriptions
                // produced a catalogue with zero.
                descs.retain(|(n, d)| !d.eq_ignore_ascii_case(n));
                merged.extend(descs);
                descs = merged;
            }
            Ok(Err(e)) => info!(target: "groups", "{e}"),
            Err(e) => info!(target: "groups", "ISC descriptions: {e}"),
        }
    }
    Ok(crate::groups::Catalog::build(
        epoch_secs() as i64,
        active,
        descs,
        prev,
    ))
}

/// How many of a group's newest articles one sample covers. 200 is
/// enough for a stable mean and a usable content mix, and small enough
/// that a sample is one quick OVER rather than a scan.
#[cfg(feature = "indexer")]
pub(super) const GROUP_SAMPLE_N: u64 = 200;

/// How far back the rate baseline reaches, widened until it spans at
/// least an hour. A quiet group is answered by the first step; the
/// busiest groups on a big provider need the last one.
#[cfg(feature = "indexer")]
pub(super) const RATE_BASELINE_STEPS: &[u64] = &[50_000, 1_000_000, 20_000_000];

/// Sample one group: select it, pull OVER across its newest articles,
/// and reduce that to a profile. One connection, one round trip, closed
/// immediately - this must never compete with the download pool.
#[cfg(feature = "indexer")]
pub(super) async fn sample_one_group(
    config: &Path,
    group: &str,
    posts: u64,
) -> std::result::Result<crate::groupstats::GroupStats, String> {
    let server = crate::load_server(config).map_err(|e| e.to_string())?;
    let (mut conn, _) = nzbkit::nntp::Connection::connect(&server)
        .await
        .map_err(|e| e.to_string())?;
    let info = conn.group(group).await.map_err(|e| e.to_string())?;
    // An empty group has nothing to sample. Also guards the subtraction
    // below, where high < GROUP_SAMPLE_N is the common case for a quiet
    // group and must not wrap.
    if info.high == 0 || info.high < info.low {
        conn.quit().await;
        return Ok(crate::groupstats::GroupStats {
            sampled_at: epoch_secs() as i64,
            ..Default::default()
        });
    }
    let from = info.high.saturating_sub(GROUP_SAMPLE_N).max(info.low);
    let entries = conn
        .over(from, info.high)
        .await
        .map_err(|e| e.to_string())?;
    let mut stats =
        crate::groupstats::GroupStats::from_sample(epoch_secs() as i64, posts, &entries);

    // Second, tiny probe far back in the article range, purely to date a
    // wide baseline for the posting rate. The newest-200 window spans
    // seconds on a busy group, which is unusable as a divisor; this turns
    // the rate into an honest "N articles between these two dates".
    //
    // The step has to ADAPT, because "far back" is a property of the
    // group, not a constant: 50k articles is weeks on a quiet group and
    // about a minute on alt.binaries.teevee, which is why a fixed
    // baseline measured nothing at all on the busiest group tested.
    // Widen until the baseline spans an hour, or until we run out of
    // group. Two extra round trips at worst, and only for the fast ones.
    for step in RATE_BASELINE_STEPS {
        let back = info.high.saturating_sub(*step).max(info.low);
        if back >= from {
            break; // the sample already covers this far back
        }
        // A few articles, not one: any individual number may be missing.
        let Ok(old) = conn.over(back, back.saturating_add(20).min(from)).await else {
            break;
        };
        let Some(oldest) = old.iter().map(|e| e.date).filter(|d| *d > 0).min() else {
            continue;
        };
        stats.set_rate_from_baseline(info.high.saturating_sub(back), oldest);
        if stats.per_day > 0.0 {
            break; // the baseline was wide enough to be a measurement
        }
        if back == info.low {
            break; // no more group to reach back into
        }
    }
    conn.quit().await;
    Ok(stats)
}

/// Sample `group` in the background unless a sample is already in flight
/// for it. `Some(handle)` when THIS call started one, `None` when one was
/// already running.
///
/// Per-group single-flight rather than one global flag: opening two rows
/// in the browser should sample both, but opening the same row twice
/// should not go to the provider twice.
///
/// The handle is the caller's choice of concurrency, and the two callers
/// want opposite things. An API request DROPS it - a click must not block
/// a request worker on a provider round trip. The steady background pass
/// AWAITS it, which is the only thing that makes that pass sequential;
/// dropping it there is what put seven concurrent sockets on one account
/// in the 23 Aug 2026 incident.
///
/// The handle resolves to true when the sample was refused for the
/// ACCOUNT being out of connections (§275 item 4). The idle gate can
/// only see this daemon's own downloads; a bench leg or another machine
/// on the same account is invisible to it, and when that is what is
/// holding the slots, every remaining group in the pass fails the same
/// way. The 23-24 Aug 2026 log carried 301 `502 Too many connections`
/// lines from exactly that - the pass marched the whole group list
/// against an account a bench round was using. The awaiting caller
/// breaks instead; the API caller drops the handle and never reads it.
#[cfg(feature = "indexer")]
pub(super) fn kick_group_sample(
    d: &Arc<Daemon>,
    config: PathBuf,
    group: String,
    posts: u64,
) -> Option<tokio::task::JoinHandle<bool>> {
    {
        let mut inflight = d.group_sampling.lock_ok();
        if !inflight.insert(group.clone()) {
            return None;
        }
    }
    let d = d.clone();
    Some(tokio::spawn(async move {
        // Hard ceiling: a black-holed provider must not pin an entry in
        // the in-flight set forever, which would make that group
        // permanently unsampleable until a restart.
        let res = match tokio::time::timeout(
            std::time::Duration::from_secs(45),
            sample_one_group(&config, &group, posts),
        )
        .await
        {
            Err(_) => Err("timed out".to_string()),
            Ok(r) => r,
        };
        match res {
            Ok(stats) => {
                let next = {
                    let cur = d.group_stats.lock_ok().clone();
                    let mut m = (*cur).clone();
                    m.map.insert(group.clone(), stats);
                    Arc::new(m)
                };
                if let Err(e) = next.save(&d.groupstats_cache_path()) {
                    info!(target: "groups", "sample cache write failed: {e}");
                }
                *d.group_stats.lock_ok() = next;
            }
            Err(e) => {
                info!(target: "groups", "sample of {group} failed: {e}");
                let limit = is_conn_limit_err(&e);
                d.group_sampling.lock_ok().remove(&group);
                return limit;
            }
        }
        d.group_sampling.lock_ok().remove(&group);
        false
    }))
}

/// Does this sample failure mean the ACCOUNT is out of connections?
///
/// NNTP 502 is the refusal providers use for a connection cap
/// ("502 Too many connections."), and it surfaces here wrapped as
/// "authentication failed: 502 ...". Matched on the code rather than
/// the phrase because the phrase is the provider's own copy; 502 also
/// covers "access denied" shapes, which is accepted - a pass that backs
/// off an hour on a misclassified refusal costs 150 samples of
/// housekeeping, where marching on against a capped account costs a
/// refused dial per group.
#[cfg(feature = "indexer")]
pub(super) fn is_conn_limit_err(e: &str) -> bool {
    e.contains("502")
}

/// Groups profiled per hourly tick by the background pass.
///
/// The content and freshness filters can only see profiled groups, so
/// this governs how quickly those filters become useful. 150 an hour
/// covers the ~2000 groups worth profiling inside a day or so, and costs
/// a few minutes of one sequential connection per hour, only while idle.
#[cfg(feature = "indexer")]
pub(super) const SAMPLE_BUDGET_PER_TICK: usize = 150;

/// Below this many profiles the install counts as unprofiled, and the
/// first-run burst runs. An established install is far above it (the
/// steady pass alone reaches ~2000 within a day), so it never bursts.
#[cfg(feature = "indexer")]
pub(super) const BURST_PROFILE_TARGET: usize = 500;

/// Hard bound 1: samples the burst may start in one process lifetime.
/// This is a bound on ATTEMPTS, not on successes, so a provider that
/// fails or times out every sample is contacted a bounded number of
/// times and then dropped back to the hourly pass. At the >=1s spacing
/// below, this is also a floor of ~25 minutes on how long it can last.
#[cfg(feature = "indexer")]
pub(super) const BURST_MAX_SAMPLES: usize = 1_500;

/// Hard bound 2: wall-clock window from daemon start. Covers the cases
/// the sample bound cannot - no provider configured, no group catalogue
/// yet, or a catalogue so small that the burst finishes it and would
/// otherwise sit in its short tick forever.
#[cfg(feature = "indexer")]
pub(super) const BURST_WINDOW_SECS: u64 = 60 * 60;

/// Seconds between burst ticks. Short, because a burst tick that finds
/// nothing to do (the catalogue has not been fetched yet, which is the
/// normal state for the first minute of a first run) should retry soon
/// rather than an hour later.
#[cfg(feature = "indexer")]
pub(super) const BURST_TICK_SECS: u64 = 60;

/// Should the fresh-install profile burst run?
///
/// All three conditions are load-bearing, and the two bounds exist
/// because the first one alone would let a permanently-unprofilable
/// install (bad credentials, a provider that rejects OVER) retry at the
/// burst cadence forever, which is the ban-shaped traffic the pool's
/// reconnect pacing was written to stop.
#[cfg(feature = "indexer")]
pub(super) fn should_burst_profiles(
    profiled: usize,
    burst_samples: usize,
    since_start_secs: u64,
) -> bool {
    profiled < BURST_PROFILE_TARGET
        && burst_samples < BURST_MAX_SAMPLES
        && since_start_secs < BURST_WINDOW_SECS
}

#[cfg(all(test, feature = "indexer"))]
mod conn_limit_tests {
    use super::is_conn_limit_err;

    /// §275 item 4: the shapes the pass must break on are the ones the
    /// 23-24 Aug 2026 log actually carried, wrapped exactly as
    /// `sample_one_group` surfaces them.
    #[test]
    fn the_pass_breaks_on_an_account_out_of_connections() {
        assert!(is_conn_limit_err(
            "authentication failed: 502 Too many connections."
        ));
        assert!(is_conn_limit_err("502 Access denied"));
        // Everything else keeps the pass marching: these are per-group
        // or transient, and the next group can still succeed.
        assert!(!is_conn_limit_err("timed out"));
        assert!(!is_conn_limit_err("411 no such newsgroup"));
        assert!(!is_conn_limit_err("connection reset by peer"));
        assert!(!is_conn_limit_err(
            "authentication failed: 481 wrong password"
        ));
    }
}

#[cfg(all(test, feature = "indexer"))]
mod group_burst_tests {
    use super::{
        BURST_MAX_SAMPLES, BURST_PROFILE_TARGET, BURST_WINDOW_SECS, should_burst_profiles,
    };

    /// The gate this whole feature turns on: a fresh install bursts, an
    /// install that already has profiles never does. The second half is
    /// the one that matters - bursting on an established install means
    /// re-profiling groups that are already known, at a cadence the
    /// provider has no reason to tolerate.
    #[test]
    fn bursts_only_while_the_profile_cache_is_empty() {
        assert!(
            should_burst_profiles(0, 0, 0),
            "a brand new install must burst"
        );
        assert!(
            should_burst_profiles(BURST_PROFILE_TARGET - 1, 0, 0),
            "just under the target still counts as unprofiled"
        );
        assert!(
            !should_burst_profiles(BURST_PROFILE_TARGET, 0, 0),
            "at the target the steady hourly pass takes over"
        );
        assert!(
            !should_burst_profiles(2_000, 0, 0),
            "an established install must never burst"
        );
    }

    /// Both bounds are hard: an install that stays empty because every
    /// sample fails must still stop bursting. Without these it would
    /// retry at the burst cadence for as long as the daemon runs.
    #[test]
    fn an_install_that_never_fills_still_stops_bursting() {
        assert!(
            !should_burst_profiles(0, BURST_MAX_SAMPLES, 0),
            "the sample budget must stop a burst that fills nothing"
        );
        assert!(
            !should_burst_profiles(0, 0, BURST_WINDOW_SECS),
            "the wall-clock window must stop a burst that samples nothing"
        );
        assert!(
            should_burst_profiles(0, BURST_MAX_SAMPLES - 1, BURST_WINDOW_SECS - 1),
            "one short of either bound is still inside the window"
        );
    }
}

/// Fill in sampled profiles for the groups a user is most likely to look
/// at: the ones they already scan, then the busiest binary groups.
/// Returns how many samples this pass started.
///
/// Sequential - it awaits each sample before starting the next, and that
/// is load-bearing rather than incidental (see the await below). One
/// connection at a time is gentle, but a provider account has a hard
/// connection limit and the download pool is entitled to all of it, so
/// the steady pass ALSO stands down entirely while anything is
/// downloading rather than risking a rejected connection on the hot path.
///
/// `burst` lifts only the idle gate, and only for the fresh-install
/// window (see `should_burst_profiles`). A brand new install whose first
/// action is to queue something would otherwise profile nothing at all
/// while it downloads, which is exactly when the user is first looking at
/// the content and "still active" filters. It stays one sample at a time,
/// and spaces them further apart while the pool is busy, so the extra
/// load is a single connection opened every few seconds - not a new
/// concurrency tier.
#[cfg(feature = "indexer")]
pub(super) async fn sample_top_groups(d: &Arc<Daemon>, config: &Path, burst: bool) -> usize {
    if !burst && d.started_at.lock_ok().is_some() {
        return 0; // downloading: the pool owns the connections
    }
    let Some(cat) = d.group_catalog.lock_ok().clone() else {
        return 0;
    };
    let now = epoch_secs() as i64;
    let subscribed: std::collections::HashSet<String> =
        d.index_groups.lock_ok().iter().cloned().collect();

    // Subscribed first, then busiest-binary. `posts` rides along because
    // it is what turns a mean article size into an estimated group size.
    let mut want: Vec<(String, u64)> = cat
        .groups
        .iter()
        .filter(|g| subscribed.contains(&g.name))
        .map(|g| (g.name.clone(), g.posts))
        .collect();
    let mut busiest: Vec<&crate::groups::CatGroup> = cat
        .groups
        .iter()
        .filter(|g| crate::groups::is_binary(&g.name) && !subscribed.contains(&g.name))
        .collect();
    busiest.sort_by_key(|b| std::cmp::Reverse(b.posts));
    want.extend(
        busiest
            .into_iter()
            .take(2_000)
            .map(|g| (g.name.clone(), g.posts)),
    );

    let mut done = 0usize;
    for (name, posts) in want {
        if done >= SAMPLE_BUDGET_PER_TICK {
            break;
        }
        // Re-check per group: a download may have started mid-pass, and
        // an already-fresh profile costs nothing to skip.
        let downloading = d.started_at.lock_ok().is_some();
        if downloading && !burst {
            return done;
        }
        if !d.group_stats.lock_ok().is_stale(&name, now) {
            continue;
        }
        let Some(sample) = kick_group_sample(d, config.to_path_buf(), name, posts) else {
            continue; // already in flight from an on-demand request
        };
        // AWAIT it. `kick_group_sample` spawns, so letting the handle drop
        // here made this loop fire-and-forget at one sample a second: with
        // samples lasting D seconds, D of them are on the wire at once. On
        // 23 Aug 2026 that was seven concurrent sockets against an account
        // another machine's benchmark round was already using, and the tail of
        // the pass was still reporting "502 Too many connections" four
        // seconds after this loop had printed its summary.
        //
        // Bounded: the spawned body carries its own 45 s ceiling, so this
        // await cannot wedge the tick. The worst case is a slower pass,
        // not a stuck one - and the tick loop sleeps its hour AFTER this
        // returns, so a long pass delays the next one rather than
        // stacking on it.
        // §275 item 4: a connection-limit refusal ends the PASS, not
        // just the sample. The account has no free slots and the idle
        // gate cannot see who holds them (a bench leg, another machine),
        // so the remaining groups would fail identically - 301 logged
        // `502` lines across 23-24 Aug 2026 were this loop marching on.
        // The next hourly tick retries; nothing is marked unsampleable.
        if sample.await.unwrap_or(false) {
            info!(
                target: "groups",
                "the account is out of connections (something else is using it); \
                 ending this sampling pass, the next one retries in an hour"
            );
            break;
        }
        done += 1;
        // Space them out. This is housekeeping, not a job - and when the
        // pool is downloading through the same account, housekeeping that
        // yields: five times the gap, so the burst is a trickle beside it.
        let gap = if downloading { 5 } else { 1 };
        tokio::time::sleep(std::time::Duration::from_secs(gap)).await;
    }
    if done > 0 {
        info!(target: "groups", "sampling {done} group profiles in the background");
    }
    done
}

/// Turn the user's chosen interests into scanned groups, once.
///
/// Called when the setting changes, at startup, and whenever a
/// catalogue fetch lands - because at first run there is no catalogue
/// yet: the wizard runs before the daemon has ever spoken to the
/// provider, so "sport" cannot be resolved to group names at the moment
/// it is chosen. The choice is recorded either way and applied when the
/// group list arrives.
///
/// Three properties this has to keep, all of them the point of the
/// feature:
///  * nothing is subscribed for an empty interest string - there is no
///    fallback list;
///  * a group the user removed by hand does not come back (the applied
///    marker makes this one-shot per change);
///  * only groups the provider actually carries are subscribed, so a
///    preset can never point the scan loop at a name that will never
///    answer.
#[cfg(feature = "indexer")]
pub(super) fn apply_interests(d: &Arc<Daemon>) {
    let want = d.index_interests.lock_ok().clone();
    if want == *d.index_interests_applied.lock_ok() {
        return;
    }
    let keys = crate::interests::parse(&want);
    let was = crate::interests::parse(&d.index_interests_applied.lock_ok().clone());
    // Switching an interest OFF has to stop scanning what switching it on
    // started, or the only way back would be to edit the group list by
    // hand - and not having to know newsgroup names is the point.
    let dropped_keys: Vec<String> = was.iter().filter(|k| !keys.contains(k)).cloned().collect();
    let stale = crate::interests::groups(&dropped_keys);
    let still_wanted = crate::interests::groups(&keys);
    let stale: Vec<String> = stale
        .into_iter()
        .filter(|g| !still_wanted.iter().any(|w| w == g))
        .collect();
    if keys.is_empty() && stale.is_empty() {
        // "Nothing" is a real answer, and recording it stops this from
        // being reconsidered on every catalogue refresh.
        if save_settings(
            &d.settings_path,
            &[("index_interests_applied", json!(&want))],
        ) {
            *d.index_interests_applied.lock_ok() = want;
        }
        return;
    }
    // Removal needs no catalogue - the names are known either way - but
    // ADDING does, so a still-catalogue-less daemon takes the removal now
    // and leaves the marker for the fetch to finish.
    let cat = d.group_catalog.lock_ok().clone();
    if cat.is_none() && !keys.is_empty() {
        if !stale.is_empty() {
            let have = d.index_groups.lock_ok().clone();
            let owned = d.index_interest_groups.lock_ok().clone();
            let (groups, next_owned, dropped, _) =
                crate::interests::reconcile(&have, &owned, &stale, &[]);
            if dropped > 0
                && save_settings(
                    &d.settings_path,
                    &[
                        ("index_groups", json!(&groups)),
                        ("index_interest_groups", json!(&next_owned)),
                    ],
                )
            {
                *d.index_groups.lock_ok() = groups;
                *d.index_interest_groups.lock_ok() = next_owned;
            }
        }
        return;
    }
    let resolved = match &cat {
        Some(c) => {
            let carried: std::collections::HashSet<&str> =
                c.groups.iter().map(|g| g.name.as_str()).collect();
            crate::interests::resolve(&keys, |g| carried.contains(g))
        }
        None => Vec::new(),
    };
    let have = d.index_groups.lock_ok().clone();
    let owned = d.index_interest_groups.lock_ok().clone();
    let (groups, next_owned, dropped, added) =
        crate::interests::reconcile(&have, &owned, &stale, &resolved);
    // Groups, provenance and completion marker are one persisted state
    // transition. Writing the marker first used to make a crash or second
    // write failure suppress this choice forever on restart.
    if !save_settings(
        &d.settings_path,
        &[
            ("index_groups", json!(&groups)),
            ("index_interest_groups", json!(&next_owned)),
            ("index_interests_applied", json!(&want)),
        ],
    ) {
        return;
    }
    *d.index_groups.lock_ok() = groups;
    *d.index_interest_groups.lock_ok() = next_owned;
    *d.index_interests_applied.lock_ok() = want.clone();
    if added == 0 && dropped == 0 {
        return;
    }
    info!(
        target: "groups",
        "interests ({}): {added} group(s) added, {dropped} removed",
        if want.is_empty() { "none" } else { &want },
    );
    if added > 0 {
        d.scan_now.notify_one();
    }
}

/// Start a background catalogue fetch unless one is already running
/// (single-flight). Returns whether THIS call started it.
#[cfg(feature = "indexer")]
pub(super) fn kick_group_fetch(d: &Arc<Daemon>, config: PathBuf) -> bool {
    if d.group_fetching.swap(true, Ordering::SeqCst) {
        return false;
    }
    let d = d.clone();
    tokio::spawn(async move {
        let prev = d.group_catalog.lock_ok().clone();
        let isc = d.group_desc_isc.load(Ordering::Relaxed);
        match fetch_group_catalog(&config, prev.as_deref(), isc).await {
            Ok(cat) => {
                if let Err(e) = cat.save(&d.groups_cache_path()) {
                    info!(target: "groups", "catalogue cache write failed: {e}");
                }
                let new_count = cat
                    .groups
                    .iter()
                    .filter(|g| g.first_seen == cat.fetched_at)
                    .count();
                info!(
                    target: "groups",
                    "catalogue fetched: {} groups ({} with descriptions, {} newly created)",
                    cat.groups.len(),
                    cat.groups.iter().filter(|g| !g.desc.is_empty()).count(),
                    new_count,
                );
                *d.group_fetch_err.lock_ok() = None;
                *d.group_catalog.lock_ok() = Some(Arc::new(cat));
                // First run orders these the other way round: the user
                // picks interests in the wizard, before this daemon has
                // ever seen a group list. This is where that choice
                // becomes a scan list.
                apply_interests(&d);
            }
            Err(e) => {
                info!(target: "groups", "catalogue fetch failed: {e}");
                *d.group_fetch_err.lock_ok() = Some(e);
            }
        }
        d.group_fetching.store(false, Ordering::SeqCst);
    });
    true
}

/// The newsgroup every diagnostic probe (system bench, connection ladder,
/// pool burst, diversity sweep) selects to find sample articles with: big,
/// busy, and carried by every provider.
///
/// Deliberately a constant and NOT `ServerConfig.group`. That field is a
/// MIRROR LABEL - servers sharing it are backbone twins, and the pool uses
/// it to dedup 430s across them - and the dashboard collects it as freeform
/// text ("Backbone group"). Sent as an NNTP GROUP argument it answers 411,
/// which the probes reported as a 0.00 Gbps network or a failed sweep.
pub(super) const PROBE_GROUP: &str = "alt.binaries.boneless";

/// One full system measurement (compute + disk + live network probe on
/// the first configured server). Shared by the mode=sysbench handler and
/// the scheduled-benchmark loop - both run on plain threads, hence the
/// runtime handle for the async probe. A failed probe must SAY SO -
/// collapsing errors to 0.0 Gbps used to yield "expected max 0.00,
/// network is your limit", which is worse than useless.
pub(super) fn measure_system(
    d: &Arc<Daemon>,
    cfg_path: &std::path::Path,
    rt: &tokio::runtime::Handle,
) -> std::result::Result<nzbkit::sysbench::SystemReport, String> {
    let _busy = d.busy.hold("measuring");
    let compute = nzbkit::sysbench::compute(128);
    let disk = nzbkit::sysbench::disk_write(&d.out_dir(), 512).unwrap_or(0.0);
    // Every enabled server, at the connection counts downloads actually
    // use - NOT a fixed 8, and NOT just the first server.
    //
    // A single Usenet connection is worth tens of Mbps, so eight of them
    // measure a few hundred Mbps whatever the line is capable of (issue
    // #12). And one server's figure reads far below what several
    // accounts deliver together - the reporter's five providers do 3x
    // what their first one shows alone (issue #12, round 2). SABnzbd's
    // own test pulls from a CDN over HTTP and measures the line, not the
    // providers; ours is the number that predicts a real download.
    //
    // Metered servers sit this leg out (M7b.2 §5.7). The probe pulls
    // real article bodies for up to 45 s across the whole fleet, and
    // the three-layer gap round established what that figure actually
    // is: the PROVIDERS' rate, not the line's - so on a per-byte
    // account it is money spent measuring someone else's plan.
    let all_enabled: Vec<nzbkit::config::ServerConfig> = nzbkit::config::Config::load(cfg_path)
        .map(|c| c.servers.into_iter().filter(|s| s.enabled).collect())
        .unwrap_or_default();
    if all_enabled.is_empty() {
        return Err("no servers configured".into());
    }
    let servers: Vec<_> = all_enabled
        .iter()
        .filter(|s| s.may_spend_on_measurement())
        .cloned()
        .collect();
    if servers.is_empty() {
        // Say which rule stopped it. Silently probing anyway would
        // spend the money the flag exists to protect, and silently
        // reporting 0.00 Gbps would read as a dead link.
        return Err(
            "every enabled server is marked as billed per byte, so there is nothing to \
             measure the network with - this test downloads real articles. Untick \"Every \
             byte is billed\" on a server to include it."
                .into(),
        );
    }
    let conns_total: usize = servers
        .iter()
        .map(|s| (s.connections as usize).clamp(1, 100))
        .sum::<usize>()
        .min(200);
    // The card names what the figure came from; keep it locale-neutral
    // (the note around it is translated, this string is substituted in).
    let hosts = {
        let names: Vec<&str> = servers.iter().map(|s| s.host.as_str()).take(3).collect();
        let mut h = names.join(", ");
        if servers.len() > 3 {
            h.push_str(", …");
        }
        h
    };
    let probed = (hosts.clone(), conns_total);
    // Hard cap: a black-holed connect must not wedge the caller
    // (it did, via the Run button, on a filtered uplink).
    let net = rt.block_on(async {
        match tokio::time::timeout(
            std::time::Duration::from_secs(45),
            nzbkit::sysbench::network_probe_multi(&servers, PROBE_GROUP, 8),
        )
        .await
        {
            Err(_) => Err(format!(
                "network probe timed out ({hosts}: slow link or filtered port?)"
            )),
            Ok(Err(e)) => Err(format!("network probe ({hosts}): {e}")),
            Ok(Ok((g, per_server))) => {
                let billed: Vec<(String, u64)> = servers
                    .iter()
                    .zip(&per_server)
                    .map(|(s, &b)| (s.host.clone(), b))
                    .collect();
                d.add_usage(&billed);
                Ok(g)
            }
        }
    })?;
    let mut v = nzbkit::sysbench::verdict(net, &compute, disk);
    (v.network_host, v.network_conns) = probed;
    // §210 (b): which network is short. Only when the network row IS
    // the limit - that is when the card tells the reader to add
    // connections or a provider, and it is the reading this corrects.
    // The link speaks for itself or not at all (`measured_note` is
    // empty unless the figure actually reached its ceiling), so this
    // never puts a second opinion beside a healthy row.
    if v.bottleneck == "network" {
        v.network_link = d
            .local_link
            .lock_ok()
            .as_ref()
            .map(|l| l.measured_note((net * 1e9 / 8.0) as u64))
            .unwrap_or_default();
    }
    Ok(v)
}

/// Regression test for the 23 Aug 2026 incident: a server switched OFF in
/// config held seven live TLS sockets to the provider, while a benchmark
/// round on another machine was using that same account.
///
/// The hourly group-profile sampler reaches the provider through
/// `crate::load_server`, which was `cfg.servers[0].clone()` and consulted
/// `enabled` nowhere. On that box `servers[0]` WAS the disabled account, so
/// every sample in the pass dialled the one server the user had switched
/// off. Nothing named the host in the log, because only the download
/// planner prints "<host> disabled - not in the pool" and no download ran.
///
/// Drives the real lane against two local listeners rather than asserting
/// on `load_server` in isolation: the defect only bites because a
/// background task reaches it, and a test on the helper alone would still
/// pass if this caller later grew its own unfiltered pick.
#[cfg(all(test, feature = "indexer"))]
mod sampler_stays_sequential {
    use nzbkit::sync::MutexExt as _;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// One listener that records the HIGH-WATER mark of simultaneously
    /// open connections.
    ///
    /// `HOLD_MS` must EXCEED the pass's own one-second spacing or this
    /// test is a rubber stamp: at a 400 ms hold the broken, spawn-and-
    /// forget version also scores a peak of 1, because each sample is
    /// already finished before the next is launched. Verified by
    /// reverting the await - at 400 ms the test passed on the defect, at
    /// 1500 ms it fails on it. That, plus the two-group corpus, is what
    /// sets this test's ~5 s runtime; do not trim either to speed it up.
    const HOLD_MS: u64 = 1_500;

    fn counting_listener(peak: Arc<AtomicUsize>, live: Arc<AtomicUsize>) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for sock in l.incoming().take(8).flatten() {
                let (peak, live) = (peak.clone(), live.clone());
                std::thread::spawn(move || {
                    let n = live.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(n, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(HOLD_MS));
                    live.fetch_sub(1, Ordering::SeqCst);
                    let _ = sock.shutdown(std::net::Shutdown::Both);
                });
            }
        });
        port
    }

    fn group(name: &str) -> crate::groups::CatGroup {
        crate::groups::CatGroup {
            name: name.to_string(),
            posts: 1_000,
            desc: String::new(),
            cat: crate::groups::Category::Other,
            status: 'y',
            first_seen: 0,
        }
    }

    /// The 23 Aug 2026 incident's OTHER half. `kick_group_sample`
    /// spawns, so a pass that drops the handle puts one socket per second
    /// of sample duration on a single account - seven of them that day,
    /// against an account another machine's benchmark round was using. This
    /// pass
    /// has always DOCUMENTED itself sequential; nothing enforced it.
    #[tokio::test]
    async fn the_steady_pass_holds_one_connection_at_a_time() {
        let peak = Arc::new(AtomicUsize::new(0));
        let port = counting_listener(peak.clone(), Arc::new(AtomicUsize::new(0)));

        let dir =
            std::env::temp_dir().join(format!("nzbfast-groupscan-serial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        std::fs::write(
            &cfg,
            format!(
                r#"{{"servers":[{{"host":"127.0.0.1","port":{port},"tls":false,
                    "enabled":true,"connections":8}}]}}"#
            ),
        )
        .unwrap();

        let d = crate::serve::testutil::test_daemon(&dir);
        // Subscribed groups are sampled first and skip the is-binary
        // test, so two names are all this needs - one to be in flight
        // and one to collide with it. Any more just pays the pass's own
        // one-second spacing again.
        let names = ["alt.binaries.one", "alt.binaries.two"];
        *d.index_groups.lock_ok() = names.iter().map(|n| n.to_string()).collect();
        *d.group_catalog.lock_ok() = Some(std::sync::Arc::new(crate::groups::Catalog {
            fetched_at: 0,
            groups: names.iter().map(|n| group(n)).collect(),
        }));

        let done = super::sample_top_groups(&d, &cfg, false).await;

        assert_eq!(done, 2, "every subscribed group should have been sampled");
        assert_eq!(
            peak.load(Ordering::Relaxed),
            1,
            "the steady profile pass opened more than one provider \
             connection at once - it must await each sample, not spawn \
             and move on (23 Aug 2026)"
        );
        // The same defect seen from the other side, and the shape the
        // incident log actually showed: the pass printed its summary at
        // 19:03:19Z with six samples still running, which reported "502
        // Too many connections" for another ten seconds. A pass that has
        // returned must own nothing on the wire.
        assert!(
            d.group_sampling.lock_ok().is_empty(),
            "sample_top_groups returned with samples still in flight"
        );
    }
}

#[cfg(all(test, feature = "indexer"))]
mod disabled_server_never_dialled {
    use std::io::Write as _;
    use std::sync::mpsc;

    /// A listener that reports the moment it accepts, then hangs up.
    ///
    /// Hanging up rather than going silent matters: the sampler's own
    /// ceiling is 45 s, and a listener that accepts and says nothing makes
    /// every run of this test pay a network timeout it is not measuring.
    fn spy(tx: mpsc::Sender<&'static str>, tag: &'static str) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((s, _)) = l.accept() {
                let _ = tx.send(tag);
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        });
        port
    }

    fn two_server_config(off_port: u16, on_port: u16) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-groupscan-enabled-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.local.json");
        let mut f = std::fs::File::create(&p).unwrap();
        // The incident's shape exactly: the DISABLED account is first in
        // the array, which is the position `load_server` used to take
        // unconditionally.
        write!(
            f,
            r#"{{"servers":[
                 {{"host":"127.0.0.1","port":{off_port},"tls":false,
                   "enabled":false,"connections":1}},
                 {{"host":"127.0.0.1","port":{on_port},"tls":false,
                   "enabled":true,"connections":1}}]}}"#
        )
        .unwrap();
        p
    }

    #[tokio::test]
    async fn the_group_sampler_skips_a_server_the_user_switched_off() {
        let (tx, rx) = mpsc::channel();
        let off_port = spy(tx.clone(), "disabled");
        let on_port = spy(tx, "enabled");
        let cfg = two_server_config(off_port, on_port);

        // The sample itself cannot succeed against a socket that hangs up
        // on the greeting, and does not need to: the question is only
        // which account the lane reached for.
        let _ = super::sample_one_group(&cfg, "alt.binaries.test", 0).await;

        let reached: Vec<&str> = rx.try_iter().collect();
        assert!(
            !reached.contains(&"disabled"),
            "the hourly profile sampler dialled a server with \
             `\"enabled\": false` - this is the 23 Aug 2026 defect"
        );
        assert_eq!(
            reached,
            ["enabled"],
            "the sampler must fall through to the first ENABLED server"
        );
    }
}
