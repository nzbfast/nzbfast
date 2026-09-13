//! The confirm lane's PICK SIDE: where the next thing to confirm comes
//! from, and what happens to a pick that does not settle.
//!
//! Two sources feed it - the seed queue, sampled from the reference
//! indexer's own newest listings, and the correlation suggestions it
//! stands in for - and one durable retry catalogue keeps a pick that
//! failed transiently eligible without letting it be re-picked forever.
//! Everything here is bookkeeping over index kv and one JSON file; the
//! attempt itself (`corr_confirm_once`, the search, the fetch, the
//! staging) stays in `indexer.rs`.
//!
//! Cut out of `tasks/indexer.rs` on 7 Sep 2026 (claim
//! `debt-split-hot-files-7sep`) at 3,281 of the size gate's 4,000-line
//! file ceiling. Verbatim move, banner comments included; every item
//! keeps its own `#[cfg(feature = "indexer")]`, and the `mod` line
//! carries it too so the slim build sees nothing new.

use super::*;

// ---- Indexer-confirm lane: correlation suggestions -> proven names ----

// ---- the seed pick: sampling the reference indexer directly ---------
//
// research/SEEDJOIN-PROBE-2026-09-01.md's build item 1. The confirm
// lane's grab-and-join tail is proof-grade (a message-id match IS the
// post), but its pick source was correlation suggestions, which
// research/NAMECORR-PRECISION-2026-09-01.md measured at 0% precision -
// a proven pipeline fed by a refuted one. The seed pick samples the
// reference indexer's own newest listings instead: every listed title
// is a NAME the indexer was handed with an uploaded NZB, and grabbing
// that NZB joins those names onto the wire posts we already hold. Same
// dial, same daily budget, same quota discipline as the corr picks it
// stands in for when none exist.

/// Titles harvested from the reference's newest listings, waiting for
/// a grab attempt (index kv, JSON array).
#[cfg(feature = "indexer")]
pub(super) const SEED_QUEUE_KEY: &str = "seed_queue_v1";
/// match_keys this lane already attempted, ring-capped - a listing
/// whose NZB joined nothing must not be re-grabbed every sweep.
#[cfg(feature = "indexer")]
pub(super) const SEED_RECENT_KEY: &str = "seed_recent_v1";
/// When the last listing sweep ran (index kv, unix seconds).
#[cfg(feature = "indexer")]
pub(super) const SEED_LISTING_AT_KEY: &str = "seed_listing_at";

/// One newest-listing sweep per hour at most: a sweep is one API hit
/// buying up to [`SEED_QUEUE_CAP`] candidates, and the queue drains at
/// the confirm lane's own budgeted pace anyway.
#[cfg(feature = "indexer")]
pub(super) const SEED_LISTING_EVERY: i64 = 3_600;
#[cfg(feature = "indexer")]
pub(super) const SEED_QUEUE_CAP: usize = 40;
#[cfg(feature = "indexer")]
pub(super) const SEED_RECENT_CAP: usize = 500;

/// Ring of titles the confirm lane settled recently, whatever the
/// pick source (index kv, JSON array of match_keys). The corr stamp
/// already makes each suggestion once-ever, but SEVERAL rows can
/// suggest one title, and each would buy the identical search and the
/// identical NZB minutes apart - measured live on beta 4's first hour:
/// one title, three grabs, three minutes. A ring hit is stamped
/// without a lookup, because the exact lookup just ran.
pub(super) const CONFIRM_RECENT_KEY: &str = "confirm_recent_v1";
pub(super) const CONFIRM_RECENT_CAP: usize = 200;

/// Pop the next queued seed title, recording it in the attempted ring
/// so a joinless grab is never repeated.
#[cfg(feature = "indexer")]
#[cfg(test)]
pub(super) fn seed_pop(d: &Arc<Daemon>) -> Option<String> {
    seed_pop_at(d, d.index_era())
}

#[cfg(feature = "indexer")]
pub(super) fn seed_pop_at(d: &Arc<Daemon>, selection_era: u64) -> Option<String> {
    d.with_index(|ix| {
        if d.index_era() != selection_era {
            return None;
        }
        seed_pop_from_index(ix)
    })
}

#[cfg(feature = "indexer")]
pub(super) fn seed_pop_from_index(ix: &nzbkit::index::Index) -> Option<String> {
    let mut queue: Vec<String> = ix
        .kv_get(SEED_QUEUE_KEY)
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default();
    if queue.is_empty() {
        return None;
    }
    let title = queue.remove(0);
    let mut recent: Vec<String> = ix
        .kv_get(SEED_RECENT_KEY)
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default();
    recent.push(nzbkit::predb::match_key(&title));
    if recent.len() > SEED_RECENT_CAP {
        let cut = recent.len() - SEED_RECENT_CAP;
        recent.drain(..cut);
    }
    // Record suppression before removing the queue entry. A crash between
    // these autocommit writes can repeat one pick, but cannot lose it.
    if ix
        .kv_set(
            SEED_RECENT_KEY,
            &serde_json::to_string(&recent).unwrap_or_default(),
        )
        .is_err()
    {
        return None;
    }
    let _ = ix.kv_set(
        SEED_QUEUE_KEY,
        &serde_json::to_string(&queue).unwrap_or_default(),
    );
    Some(title)
}

#[cfg(feature = "indexer")]
pub(super) fn seed_retry_at(d: &Arc<Daemon>, selection_era: u64, title: &str) -> Option<bool> {
    d.with_index(|ix| {
        if d.index_era() != selection_era {
            return Some(false);
        }
        seed_retry_on_index(ix, title, false)
    })
}

#[cfg(feature = "indexer")]
pub(super) fn seed_retry_legacy(d: &Arc<Daemon>, title: &str) -> Option<bool> {
    d.with_index(|ix| seed_retry_on_index(ix, title, true))
}

#[cfg(feature = "indexer")]
pub(super) fn seed_retry_on_index(
    ix: &nzbkit::index::Index,
    title: &str,
    require_witness: bool,
) -> Option<bool> {
    let key = nzbkit::predb::match_key(title);
    let mut queue: Vec<String> = ix
        .kv_get(SEED_QUEUE_KEY)
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default();
    let mut recent: Vec<String> = ix
        .kv_get(SEED_RECENT_KEY)
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default();
    let queued = queue
        .iter()
        .any(|candidate| nzbkit::predb::match_key(candidate) == key);
    if require_witness && !queued && !recent.iter().any(|old| old == &key) {
        return Some(false);
    }
    if !queued {
        queue.insert(0, title.to_string());
    }
    recent.retain(|old| old != &key);
    let queue = serde_json::to_string(&queue).ok()?;
    let recent = serde_json::to_string(&recent).ok()?;
    ix.retry_kv_set_durable(&[
        (SEED_QUEUE_KEY, queue.as_str()),
        (SEED_RECENT_KEY, recent.as_str()),
    ])
    .ok()?;
    Some(true)
}

#[cfg(feature = "indexer")]
pub(super) const CONFIRM_RETRY_FILE: &str = "confirm-retry-v1.json";
#[cfg(feature = "indexer")]
pub(super) const CONFIRM_RETRY_CATALOG_KEY: &str = "confirm_retry_catalog_v1";

#[cfg(feature = "indexer")]
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) enum ConfirmRetry {
    Expected {
        catalog_id: String,
        pick: super::expected::ExpectedPick,
    },
    Seed {
        catalog_id: String,
        title: String,
    },
}

#[cfg(feature = "indexer")]
#[derive(serde::Deserialize)]
pub(super) enum LegacyConfirmRetry {
    Expected {
        era: u64,
        pick: super::expected::ExpectedPick,
    },
    Seed {
        era: u64,
        title: String,
    },
}

#[cfg(feature = "indexer")]
#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(super) enum ConfirmRetryRecord {
    Current(ConfirmRetry),
    Legacy(LegacyConfirmRetry),
}

#[cfg(feature = "indexer")]
impl LegacyConfirmRetry {
    fn era(&self) -> u64 {
        match self {
            Self::Expected { era, .. } | Self::Seed { era, .. } => *era,
        }
    }
}

#[cfg(feature = "indexer")]
impl ConfirmRetry {
    fn catalog_id(&self) -> &str {
        match self {
            Self::Expected { catalog_id, .. } | Self::Seed { catalog_id, .. } => catalog_id,
        }
    }
}

#[cfg(feature = "indexer")]
pub(super) fn confirm_catalog_fence(d: &Arc<Daemon>) -> Option<(u64, String)> {
    let era = d.index_era();
    d.with_index(|index| {
        if d.index_era() != era {
            return None;
        }
        let catalog_id = match index.kv_get(CONFIRM_RETRY_CATALOG_KEY) {
            Some(value)
                if value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
            {
                value
            }
            _ => {
                let mut random = [0u8; 32];
                getrandom::fill(&mut random).ok()?;
                let value = hex::encode(random);
                index
                    .retry_kv_set_durable(&[(CONFIRM_RETRY_CATALOG_KEY, value.as_str())])
                    .ok()?;
                value
            }
        };
        Some((era, catalog_id))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn confirm_retry_path(d: &Daemon) -> PathBuf {
    d.spool.join(CONFIRM_RETRY_FILE)
}

#[cfg(feature = "indexer")]
pub(super) fn clear_confirm_retry(d: &Daemon) -> std::io::Result<()> {
    let path = confirm_retry_path(d);
    match std::fs::remove_file(&path) {
        Ok(()) => crate::smart::sync_dir(&d.spool),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "indexer")]
pub(super) fn save_confirm_retry(d: &Daemon, retry: &ConfirmRetry) -> std::io::Result<()> {
    let encoded = serde_json::to_vec(retry)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if encoded.len() > 64 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "confirm retry record exceeds 64 KiB",
        ));
    }
    crate::persist::write_atomic(&confirm_retry_path(d), &encoded)?;
    crate::smart::sync_dir(&d.spool)
}

#[cfg(feature = "indexer")]
pub(super) fn flush_confirm_retry(d: &Arc<Daemon>) -> bool {
    let path = confirm_retry_path(d);
    let encoded = match std::fs::read(&path) {
        Ok(encoded) if encoded.len() <= 64 * 1024 => encoded,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Ok(_) | Err(_) => {
            let hold = path.with_extension("hold");
            let _ = std::fs::rename(&path, &hold);
            let _ = crate::smart::sync_dir(&d.spool);
            warn!(target: "confirm", "quarantined unreadable confirm retry record");
            return true;
        }
    };
    let retry: ConfirmRetryRecord = match serde_json::from_slice(&encoded) {
        Ok(retry) => retry,
        Err(_) => {
            let hold = path.with_extension("hold");
            let _ = std::fs::rename(&path, &hold);
            let _ = crate::smart::sync_dir(&d.spool);
            warn!(target: "confirm", "quarantined invalid confirm retry record");
            return true;
        }
    };
    let ConfirmRetryRecord::Current(retry) = retry else {
        let ConfirmRetryRecord::Legacy(retry) = retry else {
            unreachable!();
        };
        let legacy_era = retry.era();
        let restored = match &retry {
            LegacyConfirmRetry::Expected { pick, .. } => {
                super::expected::expected_retry_legacy(d, pick)
            }
            LegacyConfirmRetry::Seed { title, .. } => seed_retry_legacy(d, title),
        };
        return match restored {
            Some(true) => clear_confirm_retry(d).is_ok(),
            Some(false) => {
                warn!(
                    target: "confirm",
                    "retired legacy confirm retry from era {legacy_era}: catalogue ownership witness is absent"
                );
                clear_confirm_retry(d).is_ok()
            }
            None => false,
        };
    };
    // `index_era` fences one open connection and changes on both a harmless
    // source-off close and a destructive wipe. The durable catalog identity
    // survives the former and changes with a recreated database, preserving
    // the one-shot retry without injecting old work after a wipe.
    for _ in 0..2 {
        let Some((era, catalog_id)) = confirm_catalog_fence(d) else {
            return false;
        };
        if catalog_id != retry.catalog_id() {
            return clear_confirm_retry(d).is_ok();
        }
        let restored = match &retry {
            ConfirmRetry::Expected { pick, .. } => super::expected::expected_retry_at(d, era, pick),
            ConfirmRetry::Seed { title, .. } => seed_retry_at(d, era, title),
        };
        match restored {
            Some(true) => return clear_confirm_retry(d).is_ok(),
            Some(false) => continue,
            None => return false,
        }
    }
    false
}

#[cfg(feature = "indexer")]
pub(super) fn retry_confirm_pick(
    d: &Arc<Daemon>,
    selection_era: u64,
    catalog_id: &str,
    seeded: bool,
    expected: Option<&super::expected::ExpectedPick>,
    title: &str,
) {
    let retry = if let Some(expected) = expected {
        ConfirmRetry::Expected {
            catalog_id: catalog_id.to_string(),
            pick: expected.clone(),
        }
    } else if seeded {
        ConfirmRetry::Seed {
            catalog_id: catalog_id.to_string(),
            title: title.to_string(),
        }
    } else {
        return;
    };
    // Take durable custody before touching the SQLite queue. This closes the
    // power-loss cut before the FULL-synchronous transaction begins.
    let journaled = match save_confirm_retry(d, &retry) {
        Ok(()) => true,
        Err(error) => {
            warn!(target: "confirm", "could not preserve one-shot retry: {error}");
            false
        }
    };
    let restored = match &retry {
        ConfirmRetry::Expected { pick, .. } => {
            super::expected::expected_retry_at(d, selection_era, pick)
        }
        ConfirmRetry::Seed { title, .. } => seed_retry_at(d, selection_era, title),
    };
    match restored {
        Some(true) => {
            if journaled {
                let _ = clear_confirm_retry(d);
            }
        }
        Some(false) | None => {
            if !journaled {
                warn!(
                    target: "confirm",
                    "one-shot retry has neither journal nor SQLite custody"
                );
            }
        }
    }
}

/// Which of the three pickers bought this attempt, for the log. Both
/// flags already reach every retire/retry call here; this spells them.
#[cfg(feature = "indexer")]
pub(super) fn pick_kind(seeded: bool, expected: bool) -> &'static str {
    match (expected, seeded) {
        (true, _) => "expected",
        (_, true) => "seeded",
        _ => "suggestion",
    }
}

#[cfg(feature = "indexer")]
pub(super) fn retire_confirm_pick(
    d: &Arc<Daemon>,
    selection_era: u64,
    seeded: bool,
    expected: bool,
    rid: i64,
    pid: i64,
    title: &str,
    now: i64,
) {
    d.with_index(|ix| {
        if d.index_era() != selection_era {
            return None;
        }
        let mut recent: Vec<String> = ix
            .kv_get(CONFIRM_RECENT_KEY)
            .and_then(|value| serde_json::from_str(&value).ok())
            .unwrap_or_default();
        recent.push(nzbkit::predb::match_key(title));
        if recent.len() > CONFIRM_RECENT_CAP {
            let cut = recent.len() - CONFIRM_RECENT_CAP;
            recent.drain(..cut);
        }
        let _ = ix.kv_set(
            CONFIRM_RECENT_KEY,
            &serde_json::to_string(&recent).unwrap_or_default(),
        );
        if !seeded && !expected {
            ix.corr_confirm_stamp(rid, pid, now).ok()
        } else {
            Some(())
        }
    });
}

/// The seed pick: pop a queued title, refilling the queue from one
/// newest-listing sweep when it is empty and the hourly throttle
/// allows. The sweep is an ordinary API hit and is counted against the
/// same per-account quota and daily budget as everything else this
/// lane does; `spent` is bumped here and persisted by the caller.
#[cfg(feature = "indexer")]
pub(super) fn seed_next(
    d: &Arc<Daemon>,
    cfg: &crate::newznab::IndexerConfig,
    selection_era: u64,
    now: i64,
    spent: &mut u32,
) -> Option<String> {
    if let Some(t) = seed_pop_at(d, selection_era) {
        return Some(t);
    }
    // Only a newznab-kind reference can list "newest" with no free-text
    // query - the nzbindex client refuses an empty `q` by design, and
    // `indexer_search_one` turns that into an error rather than a
    // firehose.
    if !matches!(cfg.kind, crate::newznab::SourceKind::Newznab) {
        return None;
    }
    // And being newznab-kind is not enough. A site may refuse the
    // request shape outright, and this one is on an hourly timer that
    // charges a quota hit BEFORE it asks - so an unlatched refusal is a
    // standing daily cost with nothing on the other side of it. Checked
    // before the throttle and before the charge, so a stood-down source
    // costs the tick nothing at all.
    if d.indexer_rt.lock_ok().no_listing.contains(&cfg.identity()) {
        return None;
    }
    let last: i64 = d
        .with_index(|ix| ix.kv_get(SEED_LISTING_AT_KEY).and_then(|v| v.parse().ok()))
        .unwrap_or(0);
    if now - last < SEED_LISTING_EVERY || *spent >= confirm_budget(cfg) {
        return None;
    }
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(now);
        // TWO hits, not one (F25, 1 Sep 2026). The sweep below is one
        // API hit and its whole product is a POPPED title - `seed_pop`
        // takes it out of the queue and rings its key in
        // `SEED_RECENT_KEY` so the hourly sweep will not offer it
        // again - and the confirm search the caller then runs for that
        // title needs a hit of its own. With exactly one left, the old
        // single-hit test let this spend it, pop a title, and hand it
        // to a caller whose authoritative wall then refused: the title
        // was consumed with no search behind it and never came back.
        // Asking for both up front costs a tick that could not have
        // finished anyway.
        if !rt.usage.hits_left(cfg, 2) {
            return None;
        }
        rt.usage.count_hit(&cfg.name);
    }
    crate::save_indexer_usage(d);
    *spent += 1;
    // Stamped before the request, not after: a sweep that errors must
    // still wait out the throttle, or a broken account is hammered
    // once a minute forever.
    d.with_index(|ix| ix.kv_set(SEED_LISTING_AT_KEY, &now.to_string()).ok());
    // Screen the sweep by the user's own stated interests (6c and
    // 6c-BUILT of research/SEED-LANE-LIVE-2026-09-02.md). Part of an
    // unscreened newest-listing feed is category 6000, and this index
    // holds 123 `adult` rows in 67 million because it scans none of the
    // groups that content is posted to - so those grabs cannot join,
    // ever, by construction. The two measurements of how big that part
    // is disagree wildly (48% across a 247-grab day, 7% in one live
    // snapshot) and the disagreement does not matter: the request costs
    // the same single hit either way, and every listing the screen
    // drops is one the join could never have answered.
    //
    // `newznab_cats` walks the built-in table and keeps what the
    // setting names, so no stored value can WIDEN this. An unanswered
    // or unrecognised setting leaves it empty, which sends no `cat=` at
    // all and is exactly the request that shipped before: a user who
    // never chose is not narrowed on their behalf.
    let cats = crate::interests::newznab_cats(&crate::interests::parse(
        &d.index_interests.lock_ok().clone(),
    ));
    let q = crate::newznab::SearchQuery {
        q: String::new(),
        cats,
        limit: 100,
        ..Default::default()
    };
    let (results, _origin) = match crate::indexer_search_one(cfg, &q) {
        Ok(pair) => pair,
        // A refusal of the request SHAPE is a verdict, not weather: the
        // same ask gets the same answer next hour and the hour after,
        // so latch it and say so ONCE. Everything else - auth, quota,
        // transport - recovers on its own and keeps its hourly retry.
        Err(e) if e.is_unsupported_request() => {
            // The lock is dropped before the log line: `warn!` reaches a
            // file writer, and the indexer lock is on the pull-search
            // path every dashboard keystroke takes.
            let first = d.indexer_rt.lock_ok().no_listing.insert(cfg.identity());
            if first {
                warn!(
                    target: "confirm",
                    "{} cannot list newest ({e}) - standing the seed sweep down for it \
                     until restart; the confirm lane keeps its other pick sources",
                    cfg.name
                );
            }
            return None;
        }
        Err(e) => {
            warn!(target: "confirm", "seed sweep against {} failed: {e}", cfg.name);
            return None;
        }
    };
    let total = results.len();
    // Scoped to the groups the SCAN covers, which is the only place a
    // message-id join can ever fire. Over the whole table this number
    // was 2009-07-30 on the live index - one stray repost in a group
    // nothing scans - and the screen below therefore rejected nothing at
    // all. See `oldest_first_posted` for what the scoped number is worth
    // and why it is an exact minimum rather than a percentile.
    let groups = d.index_groups.lock_ok().clone();
    let min_fp: i64 = d
        .with_index(|ix| ix.oldest_first_posted(&groups).ok())
        .unwrap_or(0);
    let recent: Vec<String> = d
        .with_index(|ix| {
            ix.kv_get(SEED_RECENT_KEY)
                .and_then(|v| serde_json::from_str(&v).ok())
        })
        .unwrap_or_default();
    let mut queue: Vec<String> = Vec::new();
    let mut mix: Vec<(u32, u32)> = Vec::new();
    for r in results {
        if queue.len() >= SEED_QUEUE_CAP {
            break;
        }
        // Older than anything we hold IN A SCANNED GROUP: the join has
        // nothing to hit and the grab is quota spent on nothing (the
        // live probe lost one of its two grabs exactly this way).
        if r.posted > 0 && min_fp > 0 && r.posted < min_fp {
            continue;
        }
        let key = nzbkit::predb::match_key(&r.title);
        if key.is_empty() || recent.contains(&key) {
            continue;
        }
        // Already posted READABLY under this very name: the index has
        // it and needs no grab. One probe of idx_rel_stem.
        if d.with_index(|ix| ix.stem_exists(&r.title).ok())
            .unwrap_or(false)
        {
            continue;
        }
        match mix.iter_mut().find(|(c, _)| *c == r.cat) {
            Some((_, n)) => *n += 1,
            None => mix.push((r.cat, 1)),
        }
        queue.push(r.title);
    }
    if !queue.is_empty() {
        // The screen's own before/after instrument, counted AFTER the
        // queue filters so it is the mix actually queued for the join.
        // Without it in the log, a change to the screen can only be
        // asserted, never measured.
        mix.sort_unstable();
        let mix: Vec<String> = mix.iter().map(|(c, n)| format!("{c}x{n}")).collect();
        let cats: Vec<String> = q.cats.iter().map(u32::to_string).collect();
        let screen = if cats.is_empty() {
            String::new()
        } else {
            format!(" (cat={})", cats.join(","))
        };
        info!(
            target: "confirm",
            "seed sweep{screen}: {total} listing(s), {} queued for the join [{}]",
            queue.len(),
            mix.join(" ")
        );
    }
    d.with_index(|ix| {
        if d.index_era() != selection_era {
            return None;
        }
        ix.kv_set(
            SEED_QUEUE_KEY,
            &serde_json::to_string(&queue).unwrap_or_default(),
        )
        .ok()?;
        seed_pop_from_index(ix)
    })
}

/// Checks `indexer_inbox_room` and logs why not, distinguishing three
/// causes that used to read as one "full or unavailable" sentence. Split out
/// of `corr_confirm_once` to stay clear of its 500-line size-gate ceiling
/// (indexer.rs runs the narrowest headroom in the tree).
#[cfg(feature = "indexer")]
pub(super) fn confirm_inbox_room_or_log(d: &Arc<Daemon>) -> bool {
    match crate::seed_harvest::indexer_inbox_room(d) {
        crate::seed_harvest::IndexerInboxRoom::Available => true,
        crate::seed_harvest::IndexerInboxRoom::Busy => {
            // Self-clearing: the advisory `.lock` file contends within one
            // process too (each `OpenOptions::open` is its own file
            // description), so this daemon's own harvest worker draining the
            // inbox is the usual holder, not a second daemon. A skipped tick
            // spends nothing from the daily budget and the next confirm tick
            // (a minute away) retries for free, so stand down quietly rather
            // than at WARN, which would misread a routine handoff as a fault.
            tracing::debug!(
                target: "confirm",
                "commercial NZB seed inbox lock is busy (most likely this daemon's own harvest worker draining it) - standing down this tick, retrying next minute"
            );
            false
        }
        crate::seed_harvest::IndexerInboxRoom::AtCapacity(detail) => {
            warn!(
                target: "confirm",
                "commercial NZB seed inbox is at capacity ({detail}) - standing down before spending quota"
            );
            false
        }
        crate::seed_harvest::IndexerInboxRoom::Unreadable(error) => {
            // Fails closed deliberately (better to skip a tick than spend
            // quota into an inbox we cannot even inspect), but that used to
            // collapse into the same "full" wording as a real capacity hold.
            // Name the io error so a broken spool reads as broken, not full.
            warn!(
                target: "confirm",
                "commercial NZB seed inbox could not be read ({error}) - standing down before spending quota"
            );
            false
        }
    }
}
