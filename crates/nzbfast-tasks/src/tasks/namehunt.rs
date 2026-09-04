//! F5 item 2, wired: the confirm lane's NAME HUNTS.
//!
//! `namehunt`, not `hunt`, because `serve::hunt` beside this is
//! §282's REPLACEMENT hunt - looking for another copy of a job that
//! cannot complete. This one hunts NAMES for rows already held.
//! Nothing is shared between them.
//!
//! `corr_confirm_once` beside this searches for a title something else
//! already suggested (a correlation, the release calendar, the
//! reference's own newest listings). This module is the other half -
//! the two query shapes that come off the INDEX ITSELF and were
//! measured live on 1 Sep 2026 to hit real commercial listings:
//!
//! * **Leftover as title.** A dark row whose cluster stem already
//!   reads as a release title. Sent as `q=`, the listing that comes
//!   back is an already-named release, and its NZB message-id-joins
//!   back onto the dark row. Coverage of 64 unique leftovers: Geek and
//!   DrunkenSlug 33 each (51.6%), Geek+Slug union 39 (61%), all five
//!   configured Newznab accounts 46 (72%) - so this one is worth every
//!   account, and walks them all.
//! * **Next episode.** From a row we PROVED a name for, the next
//!   episode's `q=`. Coverage 29 of 32 on Geek or Slug alone (90.6%),
//!   30 of 32 for the union (93.8%), and the other three accounts
//!   recover ZERO on top of that - so this one uses the reference
//!   account only, because the extra four searches would buy nothing
//!   and are somebody else's rate limit.
//!
//! Both are `q=` and nothing else. All five configured accounts
//! advertise no size or age parameters in their caps, so growing
//! `SearchQuery` for them is a measured no-op against this fleet
//! (research/NAMING-QUALITY-INDEXER-PROBES-2026-09-01.md), and the
//! size+date `HuntQuery` shapes that `deobf.rs` also builds are
//! unsendable here - an empty `q=` on Geek is an 11-million-row
//! firehose. `hunt_for_dark`'s hash-leftover arm is a DUMP-SITE query
//! (Geek and DrunkenSlug both answer `total=0` on leftover hex,
//! research/LEFTOVER-Q-LIVE-CENSUS-2026-09-01.md) and is deliberately
//! not wired here at all; whether nzbfast should speak to a dump site
//! for it is a source-split decision, not this lane's.
//!
//! # A leftover hunt does not rename the row it was FOR
//!
//! Measured while wiring this (2 Sep 2026), and it is the thing to
//! understand before reading the yields: `leftover_is_a_title`, which
//! picks a row for a leftover hunt, and `release::stem_is_a_name`,
//! which `apply_proven_name` asks before it will write a name, are the
//! SAME predicate wearing two names - both are "this stem does not
//! look obfuscated". So a row selected for a leftover hunt is by
//! construction a row the claims layer refuses to rename: a readable
//! stem is the poster's own name for the post and usually MORE
//! specific than a joined claim (the measured shape being a
//! season-pack NZB whose msgid quorum joins its own per-episode rows).
//! The join comes back `Conflict` or, when the stem is that same name
//! wearing sibling-file noise, `Recorded`.
//!
//! That is not a defect and must not be "fixed" by applying over the
//! stem. It means the leftover hunt's product effect is the OTHER
//! rows: one commercial NZB routinely covers several posts, and the
//! genuinely dark ones among them - the hash-stemmed files - are what
//! this lane names, with the readable row serving as the way to FIND
//! that NZB. It also means the stop rule differs by pick, below. The
//! published coverage figures are LISTING-hit rates and were never
//! name rates; this is one of the reasons the two are not the same
//! number.
//!
//! THE NAME APPLIED IS THE LISTING'S OWN TITLE, never the leftover
//! token that found it. A leftover is a filename, and
//! `leftover_token_is_never_applied_as_the_name` in nzbkit refuses the
//! other reading. The next-episode query is likewise only a way to
//! CHOOSE what to search for: what names a row is the message-id
//! quorum join on the NZB that comes back, exactly as every other
//! proof in this daemon, so nothing here copies a neighbour's title
//! onto a neighbour (that would be `NameEvidence::Adjacency`, which
//! ranks 0 and may never name).

use super::*;

/// Ring of hunt queries already bought, keyed by `match_key`, so two
/// dark rows that cluster to the same stem do not each buy the same
/// search. Capped at [`HUNT_RECENT_CAP`].
const HUNT_RECENT_KEY: &str = "namehunt_recent_v1";
const HUNT_RECENT_CAP: usize = 200;

/// Descending `releases.id` cursor for the leftover-as-title walk, and
/// the descending `name_claims.id` cursor for the next-episode walk.
/// Both reset to "start again from the newest" when their lap ends,
/// which is also how rows ingested since the lap began get seen.
const HUNT_DARK_CURSOR: &str = "namehunt_dark_cursor";
const HUNT_NEXT_CURSOR: &str = "namehunt_next_cursor";

/// Which source gets this attempt. Flipped every time one is taken, so
/// neither starves: the dark-leftover population is in the hundreds of
/// thousands and the proven-name population is tens of thousands, and
/// a "cheapest first" rule would let the big one never run.
const HUNT_TURN_KEY: &str = "namehunt_turn";

/// Rows examined per pick. Both walks filter in Rust after the SQL
/// prefilter, so this is candidates READ, not attempts bought.
const HUNT_PICK_WINDOW: usize = 200;

/// NZB fetches one hunt may spend before giving up on the listing.
///
/// Measured over the live listings that answered a leftover `q=`: the
/// wanted release was inside the first 1-3 hits on NZBGeek (worst 9)
/// and the first 2-6 on DrunkenSlug (worst 12). Five covers the bulk
/// of both without buying the tail, and the msgid join - not the
/// ranking - is what actually discriminates, so a miss here costs
/// quota rather than correctness.
const HUNT_FETCH_BUDGET: u32 = 5;

/// What one hunt is: a query, and who to ask.
enum HuntPick {
    /// Dark row, its stem sent as a title. Every enabled Newznab
    /// account, because the extra accounts measurably recover 7 of 64
    /// leftovers the two big ones miss.
    Leftover { rid: i64, q: String },
    /// Next episode after a proven name. Reference account only - the
    /// other four recover zero.
    NextEpisode { q: String },
}

impl HuntPick {
    fn query(&self) -> &str {
        match self {
            HuntPick::Leftover { q, .. } | HuntPick::NextEpisode { q } => q,
        }
    }

    /// Log form. The leftover pick names the row it is FOR; a
    /// next-episode pick is for whatever the join finds, which is not
    /// knowable until the NZB is open.
    fn label(&self) -> String {
        match self {
            HuntPick::Leftover { rid, q } => format!("leftover \"{q}\" (release {rid})"),
            HuntPick::NextEpisode { q } => format!("next episode \"{q}\""),
        }
    }
}

/// Read a kv cursor, defaulting to "newest" when unset or unparseable.
fn cursor(d: &Arc<Daemon>, key: &str) -> i64 {
    d.with_index(|ix| ix.kv_get(key).and_then(|v| v.parse().ok()))
        .unwrap_or(i64::MAX)
}

fn set_cursor(d: &Arc<Daemon>, key: &str, v: i64) {
    d.with_index(|ix| ix.kv_set(key, &v.to_string()).ok());
}

/// Has this query already been bought? Same discipline as the confirm
/// lane's own recent ring: identity is `match_key`, not the raw string.
fn ringed(recent: &[String], q: &str) -> bool {
    recent.contains(&nzbkit::predb::match_key(q))
}

fn ring_push(d: &Arc<Daemon>, q: &str) {
    d.with_index(|ix| {
        let mut recent: Vec<String> = ix
            .kv_get(HUNT_RECENT_KEY)
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default();
        recent.push(nzbkit::predb::match_key(q));
        if recent.len() > HUNT_RECENT_CAP {
            let cut = recent.len() - HUNT_RECENT_CAP;
            recent.drain(..cut);
        }
        ix.kv_set(
            HUNT_RECENT_KEY,
            &serde_json::to_string(&recent).unwrap_or_default(),
        )
        .ok()
    });
}

/// One leftover-as-title candidate, or None when this lap is done (the
/// cursor is reset so the next call starts again from the newest row,
/// which is also how rows ingested since the lap began get seen).
fn pick_leftover(d: &Arc<Daemon>, recent: &[String]) -> Option<HuntPick> {
    let before = cursor(d, HUNT_DARK_CURSOR);
    let (rows, examined) = d
        .with_index(|ix| ix.dark_title_leftovers(before, HUNT_PICK_WINDOW).ok())
        .unwrap_or_default();
    // Advance on what was EXAMINED, not on what passed: the title
    // filter runs after the SQL LIMIT, so a window can pass nothing
    // with millions of rows still below it. Only a window that
    // returned no SQL rows at all is the bottom of the lap.
    match examined {
        Some(id) => set_cursor(d, HUNT_DARK_CURSOR, id),
        None => {
            set_cursor(d, HUNT_DARK_CURSOR, i64::MAX);
            return None;
        }
    }
    rows.into_iter()
        .find(|(_, stem)| !ringed(recent, stem))
        .map(|(rid, stem)| HuntPick::Leftover { rid, q: stem })
}

/// One next-episode candidate, or None when this lap is done.
fn pick_next_episode(d: &Arc<Daemon>, recent: &[String]) -> Option<HuntPick> {
    let before = cursor(d, HUNT_NEXT_CURSOR);
    let rows = d
        .with_index(|ix| ix.named_for_next_episode(before, HUNT_PICK_WINDOW).ok())
        .unwrap_or_default();
    let lowest = rows.iter().map(|(id, _, _)| *id).min();
    match lowest {
        Some(id) => set_cursor(d, HUNT_NEXT_CURSOR, id),
        None => {
            set_cursor(d, HUNT_NEXT_CURSOR, i64::MAX);
            return None;
        }
    }
    // `hunt_next_episode` returns None for anything without a season
    // and an episode, which is how movies fall out: a movie has no
    // next episode and must not invent a `q=`.
    rows.into_iter()
        .filter_map(|(_, title, _)| nzbkit::index::hunt_next_episode(&title))
        .map(|h| h.q)
        .find(|q| !ringed(recent, q))
        .map(|q| HuntPick::NextEpisode { q })
}

/// Take the next hunt, alternating sources so neither starves.
fn next_pick(d: &Arc<Daemon>) -> Option<HuntPick> {
    let recent: Vec<String> = d
        .with_index(|ix| {
            ix.kv_get(HUNT_RECENT_KEY)
                .and_then(|v| serde_json::from_str(&v).ok())
        })
        .unwrap_or_default();
    let leftover_first = d
        .with_index(|ix| ix.kv_get(HUNT_TURN_KEY))
        .is_none_or(|v| v != "leftover");
    let pick = if leftover_first {
        pick_leftover(d, &recent).or_else(|| pick_next_episode(d, &recent))
    } else {
        pick_next_episode(d, &recent).or_else(|| pick_leftover(d, &recent))
    }?;
    let turn = match pick {
        HuntPick::Leftover { .. } => "leftover",
        HuntPick::NextEpisode { .. } => "next",
    };
    d.with_index(|ix| ix.kv_set(HUNT_TURN_KEY, turn).ok());
    Some(pick)
}

/// The accounts this pick asks, in priority order.
///
/// Leftover-as-title asks every enabled Newznab account; next-episode
/// asks only the reference. `SourceKind::Nzbindex` is deliberately not
/// in the fan-out: the coverage that justifies asking five accounts
/// was measured on the five configured NEWZNAB accounts, and an
/// nzbindex account is a different question (the dump-site source
/// split, which is not this lane's to decide).
fn accounts(d: &Arc<Daemon>, pick: &HuntPick) -> Vec<crate::newznab::IndexerConfig> {
    match pick {
        HuntPick::NextEpisode { .. } => d.corr_confirm_reference().ok().into_iter().collect(),
        HuntPick::Leftover { .. } => d
            .indexers
            .lock_ok()
            .iter()
            .filter(|i| i.enabled && i.kind == crate::newznab::SourceKind::Newznab)
            .cloned()
            .collect(),
    }
}

/// One hunt: pick a query off the index, search the accounts it is
/// worth asking, and fetch listings until a message-id join NAMES a
/// dark row or the budget is gone. Returns how much budget was spent.
///
/// The budget arithmetic is `hunt_until_quota`'s, which the nzbkit
/// prototype tests against a mock catalog: several hunts share ONE
/// remaining daily quota, each hunt stops on `Applied`/`Replaced`, and
/// an already-named neighbour's NZB is a miss rather than a stop. That
/// loop cannot be called here because its catalog is a slice of rows
/// carrying their own XML and this one is behind HTTP and somebody
/// else's rate limit, so the STOP RULE is shared instead of copied -
/// `nzbkit::index::joins_named` is the single definition both use.
///
/// Blocking (ureq plus index writes) - call from `spawn_blocking`.
#[cfg(feature = "indexer")]
pub(crate) fn hunt_once(d: &Arc<Daemon>, now: i64, daily_left: u32) -> u32 {
    if daily_left == 0 {
        return 0;
    }
    let Some(pick) = next_pick(d) else {
        return 0;
    };
    let cfgs = accounts(d, &pick);
    if cfgs.is_empty() {
        return 0;
    }
    // Searches and grabs are budgeted SEPARATELY, because they are
    // separate costs: an indexer meters hits and grabs on their own
    // counters, and [`HUNT_FETCH_BUDGET`] was measured over NZB
    // FETCHES, not searches. Charging both to one number would let a
    // five-account leftover fan-out spend the whole allowance on its
    // five searches and open no NZB at all - the one thing this lane
    // exists to do. The searches are additionally capped so they can
    // never take the last of the day's allowance, for the reason the
    // confirm lane states above its own pre-check: a search whose grab
    // can never follow is quota spent on nothing.
    let search_cap = search_cap(daily_left, cfgs.len());
    let mut spent = 0u32;
    let mut hits: Vec<(crate::newznab::SearchResult, crate::SourceOrigin, usize)> = Vec::new();
    for (i, cfg) in cfgs.iter().enumerate() {
        if spent >= search_cap {
            break;
        }
        // Both halves gate up front, as the confirm lane does.
        {
            let mut rt = d.indexer_rt.lock_ok();
            rt.usage.roll(now);
            if !rt.usage.hit_allowed(cfg) || !rt.usage.grab_allowed(cfg) {
                continue;
            }
            rt.usage.count_hit(&cfg.name);
        }
        crate::save_indexer_usage(d);
        spent += 1;
        let q = crate::newznab::SearchQuery {
            q: pick.query().to_string(),
            limit: 50,
            ..Default::default()
        };
        // The origin AND the account travel with each result. The
        // origin binds the enclosure grab to the socket THIS search
        // answered from (M9 / TODO 135); the account index is what the
        // grab is METERED against, which is not `cfgs[0]` - these hits
        // come from up to five different accounts and charging them
        // all to the first would overspend one user quota while
        // leaving another's counter untouched.
        match crate::indexer_search_one(cfg, &q) {
            Ok((results, origin)) => {
                hits.extend(results.into_iter().map(|r| (r, origin.clone(), i)))
            }
            Err(e) => warn!(target: "confirm", "hunt search against {} failed: {e}", cfg.name),
        }
    }
    if spent == 0 {
        // Every account was out of quota, so nothing was asked. The
        // pick is NOT rung: the ring records an attempt, and burning a
        // candidate with no search behind it is how a queue empties
        // itself into a ring that then refuses to re-offer it. The
        // cursor has moved, so the next tick simply picks the next row.
        return 0;
    }
    // The ring records the ATTEMPT, not the win: a query that was
    // actually sent and found nothing must not be bought again
    // tomorrow either.
    ring_push(d, pick.query());
    if hits.is_empty() {
        info!(
            target: "confirm",
            "{}: no listing on {} account(s) - unresolved",
            pick.label(),
            cfgs.len()
        );
        return spent;
    }
    // A leftover hunt searched BY NAME for a row it can identify, so a
    // quorum join onto THAT row means this was the right post and
    // there is nothing further to buy - whatever the outcome, which
    // for a readable stem is `Conflict` or `Recorded` rather than an
    // apply (see the module note). A next-episode hunt has no such
    // target: what it is for is not knowable until an NZB is open, so
    // it keeps the prototype's rule and spends until something is
    // NAMED.
    let target = match &pick {
        HuntPick::Leftover { rid, .. } => Some(*rid),
        HuntPick::NextEpisode { .. } => None,
    };
    let mut named_any = false;
    let mut found_target = false;
    let mut grabs = 0u32;
    for (hit, origin, account) in hits {
        if grabs >= HUNT_FETCH_BUDGET || spent >= daily_left {
            break;
        }
        // Metered against the account this listing actually came from.
        {
            let mut rt = d.indexer_rt.lock_ok();
            if !rt.usage.grab_allowed(&cfgs[account]) {
                continue;
            }
            rt.usage.count_grab(&cfgs[account].name);
        }
        crate::save_indexer_usage(d);
        spent += 1;
        grabs += 1;
        // fetch_url_from, not the plain fetch: `hit.link` is an
        // enclosure URL the far end CHOSE, and the plain SSRF guard
        // permits loopback and the LAN so a self-hosted indexer stays
        // reachable. Same pivot every other link-following lane here
        // closed.
        let xml = match crate::fetch_url_from(&hit.link, &origin) {
            Ok(f) => String::from_utf8_lossy(&f.bytes).into_owned(),
            Err(e) => {
                // redact_url_creds: the enclosure link carries the
                // account credential, spelled `apikey`, `r`, `i` or
                // simply built into the path, and logtee mirrors this
                // into the dashboard log and support bundles.
                warn!(
                    target: "confirm",
                    "hunt NZB fetch failed: {}",
                    crate::redact_url_creds(&e.to_string())
                );
                continue;
            }
        };
        // Parsed OUTSIDE the index lock, then joined inside it: the
        // index mutex's write side is the one measured starving the
        // download runner, and an NZB is megabytes of XML.
        let ident = match nzbkit::nzbimport::nzb_identity(xml.as_bytes()) {
            Ok(i) => i,
            Err(e) => {
                warn!(target: "confirm", "hunt NZB did not parse: {e:?}");
                continue;
            }
        };
        // THE LISTING'S OWN TITLE is the name, never `pick.query()`.
        // For a leftover hunt the query is a filename; for a
        // next-episode hunt it is a guess at a title that the indexer
        // has just answered properly. The join below is what decides
        // WHICH rows get it.
        let joins = d.with_index_mut(|ix| {
            Some(ix.name_from_indexer_ident(&hit.title, &ident, now, "nzb-hunt"))
        });
        let joins = match joins {
            Some(Ok(j)) => j,
            Some(Err(e)) => {
                warn!(target: "confirm", "hunt NZB did not join: {e:?}");
                continue;
            }
            None => continue,
        };
        for j in &joins {
            if matches!(
                j.outcome,
                nzbkit::index::ProvenOutcome::Applied | nzbkit::index::ProvenOutcome::Replaced
            ) {
                info!(
                    target: "confirm",
                    "release {}: hunt NZB joined ({} ids, {}) - named \"{}\"",
                    j.release_id,
                    j.matched,
                    pick.label(),
                    hit.title
                );
            }
        }
        named_any |= nzbkit::index::joins_named(&joins);
        found_target |= target.is_some_and(|rid| joins.iter().any(|j| j.release_id == rid));
        if named_any || found_target {
            break;
        }
    }
    if found_target && !named_any {
        info!(
            target: "confirm",
            "{}: the listing's NZB is this row's own post, and its readable \
             stem stands - claim recorded, nothing renamed",
            pick.label()
        );
    } else if !named_any {
        info!(
            target: "confirm",
            "{}: {spent} attempt(s), no NZB joined at quorum - unresolved",
            pick.label()
        );
    }
    spent
}

/// How many of this pick's accounts may be SEARCHED, given what is
/// left of the day.
///
/// One search per account, but never the last of the allowance: a
/// search whose grab can never follow is quota spent on nothing, and a
/// five-account leftover fan-out against a five-attempt remainder
/// would otherwise open no NZB at all - which is the only thing this
/// lane is for.
#[cfg(feature = "indexer")]
fn search_cap(daily_left: u32, accounts: usize) -> u32 {
    daily_left.saturating_sub(1).min(accounts as u32)
}

/// Spend the hunts' share of today's confirm budget, if the lane has
/// reached it. `Some(new_spent)` when something was actually bought.
///
/// The last quarter of the day's budget belongs to the hunts - the two
/// query shapes that come off the index itself, a dark row's
/// scene-shaped stem as a title and the next episode after a proven
/// name. It is a SHARE rather than "whatever is left when the pick
/// sources run dry", because the correlation backlog is unbounded and
/// that would mean never. [`hunt_floor`] has why the share is the one
/// it is.
///
/// `None` covers both "not the hunts' turn yet" and "both laps had
/// nothing to offer", which the caller treats the same way: fall
/// through and let the measured lanes use the tick rather than idle
/// it. The hunts get first refusal again next tick.
#[cfg(feature = "indexer")]
pub(crate) fn spend_hunt_share(d: &Arc<Daemon>, now: i64, budget: u32, spent: u32) -> Option<u32> {
    if spent < hunt_floor(budget) {
        return None;
    }
    let used = hunt_once(d, now, budget - spent);
    (used > 0).then(|| spent + used)
}

/// The share of the day's confirm budget the hunts get: the last
/// quarter of it.
///
/// The hunts run only once the measured lanes beside them have had
/// three quarters of the day's attempts, which is what "the remaining
/// `CONFIRM_PER_DAY`" means and is deliberately conservative - the
/// expectation oracle's premise is proven and this lane's yield has
/// only ever been measured as LISTING hits, never as names. It is a
/// share rather than a leftover because the correlation backlog is
/// unbounded: "run when the others are finished" would be "never".
///
/// This number is the daemon's, not nzbkit's, and is the dial to move
/// once the hunts have been scored as namers through the frozen
/// snapshot benchmark.
#[cfg(feature = "indexer")]
pub(crate) fn hunt_floor(budget: u32) -> u32 {
    budget.saturating_sub(budget / 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunts_get_the_last_quarter_of_the_budget() {
        // The floor is where hunting STARTS, so the share is what is
        // left above it.
        assert_eq!(hunt_floor(24), 18);
        assert_eq!(24 - hunt_floor(24), 6);
        assert_eq!(hunt_floor(400), 300);
        assert_eq!(400 - hunt_floor(400), 100);
    }

    #[test]
    fn a_tiny_budget_still_leaves_the_measured_lanes_first() {
        // Below 4 the quarter rounds to nothing and the hunts simply
        // do not run, which is the right way round: a user whose
        // account allows almost nothing should spend it on the lane
        // whose precision is proven.
        assert_eq!(hunt_floor(0), 0);
        assert_eq!(hunt_floor(3), 3);
        assert_eq!(hunt_floor(4), 3);
    }

    #[test]
    fn searches_never_take_the_last_of_the_days_allowance() {
        // Five accounts and five attempts left: four searches, so at
        // least one NZB can still be opened. Without this the fan-out
        // spends the lot on listings and names nothing.
        assert_eq!(search_cap(5, 5), 4);
        // Room to spare: every account is asked.
        assert_eq!(search_cap(100, 5), 5);
        // Nothing to spare: no search at all, rather than one that
        // could not be followed up.
        assert_eq!(search_cap(1, 5), 0);
        assert_eq!(search_cap(0, 5), 0);
        // Fewer accounts than allowance is bounded by the accounts.
        assert_eq!(search_cap(100, 1), 1);
    }

    #[test]
    fn the_ring_matches_on_identity_not_spelling() {
        let ring = vec![nzbkit::predb::match_key("Some.Show.S01E02.1080p.WEB-GRP")];
        assert!(ringed(&ring, "some show s01e02 1080p web grp"));
        assert!(!ringed(&ring, "Some.Show.S01E03.1080p.WEB-GRP"));
    }
}
