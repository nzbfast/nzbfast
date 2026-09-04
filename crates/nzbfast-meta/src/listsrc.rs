//! TODO 151 (issue #36): list sources - filling the watchlist from a
//! list the user keeps somewhere else.
//!
//! This is a SOURCE SEAM in front of the M23 watchlist, not a second
//! watchlist and not a second grab path. A source has an address, a
//! refresh interval, and the defaults it stamps on the entries it
//! creates; a sync turns the list it fetched into ordinary
//! [`WatchItem`]s and stops there. `watchlist_pass` still makes every
//! decision, so the quality ladder, upgrades, season packs, the
//! duplicate hold, the age window and the instant grab all apply to a
//! synced entry exactly as they do to a hand-typed one.
//!
//! This module is the pure half - the source model, the entry model, and
//! the merge that decides what a fetch does to the list it owns - so it
//! is unit-testable without a daemon or a network. The fetching, the
//! Plex account link and the sync loop live in `crates/nzbfast-daemon/src/listsrc.rs`;
//! Plex's own wire formats live in `plex.rs`.
//!
//! Two properties here are load-bearing and are why the merge is a
//! function of its own:
//!
//! 1. **Synced entries live in their own list.** `set_watchlist` rewrites
//!    the WHOLE `watchlist` array from the dashboard editor, so a sync
//!    that appended into that array would be destroyed by the next save
//!    from a browser tab that loaded before it (and vice versa). The
//!    daemon keeps the source-owned items separately and
//!    [`union_watchlist`] joins the two at pass time, so neither writer
//!    can lose the other's rows.
//! 2. **A fetch that failed or came back empty is "no news".** It is
//!    never "the list is now empty": Plex's RSS truncates at the most
//!    recent 50 entries, so falling off the end of a feed looks exactly
//!    like being removed from the list, and one bad afternoon at Plex
//!    must not quietly unwatch everything. See [`SyncOutcome`].

use serde::{Deserialize, Serialize};

use crate::watchlist::WatchItem;

fn default_true() -> bool {
    true
}
fn default_kind() -> String {
    "plex".into()
}
fn default_mode() -> String {
    "rss".into()
}
fn default_target() -> String {
    "1080p".into()
}
fn default_scope() -> String {
    SCOPE_NEW.into()
}
fn default_interval() -> u64 {
    DEFAULT_INTERVAL_SECS
}

/// Series scope: only take episodes posted from now on.
pub const SCOPE_NEW: &str = "new";
/// Series scope: take everything on the list that has been posted.
pub const SCOPE_ALL: &str = "all";

/// How the "new episodes from now on" scope is EXPRESSED: a `max_age` on
/// the created item, which is all it has ever needed to be - the
/// watchlist already skips a candidate older than an item's ceiling
/// (`watchlist::age_ok`), so there is no new concept here and no new
/// field on `WatchItem`.
///
/// A rolling fortnight rather than "posted after the sync": the window
/// has to be wide enough that a daemon which was off over a holiday
/// still catches the episodes it missed, and narrow enough that adding a
/// long-running series does not queue several hundred back episodes -
/// which is the whole reason the scope exists. A user who wants the back
/// catalogue picks "everything on the list that is posted", which blanks
/// this.
pub const SCOPE_NEW_MAX_AGE: &str = "14d";

/// Floor on a source's refresh interval, and the default.
///
/// 6 h is what Sonarr and Radarr enforce on their own Plex watchlist
/// import (`MinRefreshInterval`), and a watchlist is not a thing that
/// changes by the minute: the cost of polling harder is entirely borne
/// by somebody else's service. The floor is 15 min so an impatient
/// setting cannot turn into a hammer; "Sync now" is the answer to
/// impatience and it is one click.
pub const DEFAULT_INTERVAL_SECS: u64 = 6 * 3600;
/// Floor for [`ListSource::interval_secs`].
pub const MIN_INTERVAL_SECS: u64 = 900;

/// One external list the watchlist may fill itself from.
///
/// `url` and `token` are CREDENTIALS - a Plex watchlist RSS url is a
/// bearer capability, not a public address, and the account token is the
/// account. Neither is ever echoed to a browser (the settings row ships
/// `has_url` / `has_token` instead), neither is ever logged, and a blank
/// one arriving from an edit means "keep the stored one" exactly as an
/// indexer's apikey does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSource {
    /// Stable id assigned by the UI. The items this source owns are
    /// keyed on it, so renaming a source does not orphan them.
    pub id: u64,
    /// What the user calls this list.
    #[serde(default)]
    pub name: String,
    /// Which service this is. Only "plex" today; the seam exists so
    /// Trakt / IMDb / Letterboxd / MDBList are cheap later, and an
    /// unknown kind is refused rather than fetched blindly.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// How it is reached: "rss" (a pasted Watchlist RSS url) or
    /// "account" (the plex.tv PIN link, which holds a token).
    #[serde(default = "default_mode")]
    pub mode: String,
    /// The RSS url, for `mode = "rss"`. A credential - see the type doc.
    #[serde(default)]
    pub url: String,
    /// The account token, for `mode = "account"`. A credential.
    #[serde(default)]
    pub token: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Floor stamped on entries this source creates.
    #[serde(default)]
    pub min_quality: String,
    /// Ceiling stamped on entries this source creates.
    #[serde(default = "default_target")]
    pub target_quality: String,
    /// Category stamped on entries this source creates.
    #[serde(default)]
    pub category: String,
    /// Do entries this source creates keep upgrading?
    #[serde(default = "default_true")]
    pub upgrade: bool,
    /// How much of a series to take: [`SCOPE_NEW`] or [`SCOPE_ALL`]. A
    /// Plex series entry carries no season, so this is the per-source
    /// answer to "which episodes did you mean" - and it compiles down to
    /// the `max_age` on the created item, not to any new field.
    #[serde(default = "default_scope")]
    pub series_scope: String,
    /// Stop watching a title once it leaves the list.
    ///
    /// `None` means "whatever this mode's default is", which is the
    /// asymmetry the issue comment promises publicly: OFF for RSS,
    /// because a 50-entry feed truncates and truncation is
    /// indistinguishable from removal; ON for a linked account, which
    /// returns the whole list. Read it through
    /// [`ListSource::removes_missing`], never directly.
    #[serde(default)]
    pub remove_missing: Option<bool>,
}

impl ListSource {
    /// Does a title leaving this list stop it being watched? See the
    /// field doc: the default differs per mode, and that is deliberate.
    ///
    /// It never deletes a DOWNLOAD either way. Removal only stops future
    /// grabbing.
    pub fn removes_missing(&self) -> bool {
        self.remove_missing
            .unwrap_or_else(|| Self::remove_missing_default(&self.mode))
    }

    /// The default for this source's mode, for a UI that is drawing the
    /// checkbox fresh (a new row, or one whose mode just changed).
    pub fn remove_missing_default(mode: &str) -> bool {
        mode == "account"
    }

    /// This source's poll cadence, floored - see [`MIN_INTERVAL_SECS`].
    pub fn interval(&self) -> u64 {
        self.interval_secs.max(MIN_INTERVAL_SECS)
    }

    /// Is this source reachable at all right now? A source with no
    /// address (an account row nobody has linked yet, an RSS row with an
    /// empty url) is not broken, it is unfinished - the card says so and
    /// the sync leaves it alone.
    pub fn ready(&self) -> bool {
        match self.mode.as_str() {
            "account" => !self.token.is_empty(),
            _ => !self.url.is_empty(),
        }
    }

    /// Everything about this source that decides what a fetch means: the
    /// address it reads, the credential it reads with, and the rules
    /// stamped on the items it creates.
    ///
    /// A sync clones a source, awaits a slow network fetch, and only then
    /// writes items, health and the spool. The user can delete or edit the
    /// source in that window, and nothing rechecked - so a deleted account
    /// reinserted its items, persisted them and resumed auto-grabbing, and
    /// survived a restart doing it. Comparing this fingerprint after the
    /// await is what revokes that authority (Codex sweep 12 Aug F6).
    ///
    /// Deliberately NOT the whole struct: `name` is cosmetic and
    /// `interval_secs` only decides WHEN the next poll is, so neither
    /// should throw away a fetch that already happened.
    pub fn fetch_fingerprint(&self) -> String {
        format!(
            "{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{}\u{1}{:?}",
            self.kind,
            self.mode,
            self.url,
            self.token,
            self.enabled,
            self.min_quality,
            self.target_quality,
            self.category,
            self.upgrade,
            self.series_scope,
            self.remove_missing,
        )
    }
}

/// One title as an external list hands it over.
///
/// `ids` are the imdb / tmdb / tvdb guids Plex carries, kept because
/// they cost nothing to keep and are the obvious way to make matching
/// precise later. Nothing sends them anywhere today: matching stays on
/// title + year, and a tvdbid in particular must NEVER be sent to a
/// Newznab indexer - M35 deliberately sends none, because our only TV id
/// is a TVmaze show id living in a different namespace.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ListEntry {
    pub title: String,
    pub year: Option<u32>,
    /// "tv" or "movie".
    pub kind: String,
    pub ids: Vec<String>,
}

/// A watchlist item a source owns, as persisted to the spool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedItem {
    /// The [`ListSource::id`] that created it.
    pub src: u64,
    pub item: WatchItem,
}

/// What one fetch of one source produced.
///
/// The three arms exist so the difference between them can never be
/// flattened again: a broken source parks with a visible error and
/// leaves the list exactly as it was, and a fetch that came back with
/// nothing is "no news", not "the list is empty".
#[derive(Debug, Clone, PartialEq)]
pub enum SyncOutcome {
    /// The list as fetched. Only this arm may remove anything, and only
    /// when the source asks for it.
    Fetched(Vec<ListEntry>),
    /// The fetch worked and the list came back with nothing in it. Kept
    /// apart from `Fetched(vec![])` on purpose - see the type doc.
    Empty,
    /// The fetch failed. The message is already redacted by the caller.
    Failed(String),
}

/// What the last sync of one source did. In memory only: it describes
/// this daemon's run, and the first pass after a restart refills it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SourceHealth {
    /// Unix seconds when the last attempt finished (0 = never tried).
    pub last_sync: i64,
    /// Unix seconds when a fetch last SUCCEEDED. The pair is what lets
    /// the card say "broken since Tuesday" rather than just "broken".
    pub last_ok: i64,
    /// The last failure, url and token taken out. Empty when the last
    /// fetch worked.
    pub last_error: String,
    /// Titles the last successful fetch carried.
    pub items_seen: usize,
    /// Titles this source is currently watching.
    pub watching: usize,
}

impl SourceHealth {
    /// A fetch that worked.
    pub fn ok(now: i64, items_seen: usize, watching: usize) -> SourceHealth {
        SourceHealth {
            last_sync: now,
            last_ok: now,
            last_error: String::new(),
            items_seen,
            watching,
        }
    }

    /// A fetch that did not. `last_ok` and `items_seen` survive: they
    /// describe the last time this source DID answer, which is the fact
    /// a parked row is trying to convey.
    pub fn failed(prev: &SourceHealth, now: i64, err: &str) -> SourceHealth {
        SourceHealth {
            last_sync: now,
            last_ok: prev.last_ok,
            // Bounded: a service that answers a 500 with a whole HTML
            // error page would otherwise put all of it in get_config.
            last_error: err.trim().chars().take(200).collect(),
            items_seen: prev.items_seen,
            watching: prev.watching,
        }
    }
}

/// The id a source's entry gets, derived from what the entry IS rather
/// than from when it was first seen.
///
/// Slot state is keyed on the item id, so a deterministic id is what
/// makes a title that leaves the list and comes back resume where it
/// left off instead of re-downloading everything it already has. The top
/// bit is always set, which puts every synced id above 2^63 and so
/// permanently out of reach of the dashboard editor's own ids (those are
/// `Date.now()`-based, around 1.7e12) - two id spaces that can never
/// collide, in a state map they share.
pub fn entry_id(source_id: u64, kind: &str, title: &str, year: Option<u32>) -> u64 {
    // FNV-1a over the identity, which is all this needs to be: it is a
    // spreading function for a key space of a few hundred entries, not a
    // security primitive.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for b in bytes {
            h ^= *b as u64;
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
    };
    eat(&source_id.to_le_bytes());
    eat(kind.as_bytes());
    eat(crate::wall::norm_title(title).as_bytes());
    eat(&year.unwrap_or(0).to_le_bytes());
    h | (1 << 63)
}

/// Turn one fetched entry into an ordinary watchlist item, stamped with
/// the source's defaults.
///
/// Everything about the result is a shape `watchlist_pass` already
/// understands. The series scope is the only thing that needs saying
/// twice: "new episodes from now on" is a `max_age`, "everything posted"
/// is a blank one, and a film gets neither because a film has one slot
/// and no back catalogue to accidentally hoover up.
pub fn to_watch_item(src: &ListSource, e: &ListEntry) -> WatchItem {
    let tv = e.kind == "tv";
    WatchItem {
        id: entry_id(src.id, &e.kind, &e.title, e.year),
        kind: e.kind.clone(),
        title: e.title.clone(),
        year: e.year,
        seasons: String::new(),
        episodes: String::new(),
        min_quality: src.min_quality.clone(),
        target_quality: src.target_quality.clone(),
        upgrade: src.upgrade,
        // Never: an upgrade deleting the copy it supersedes is a
        // destructive choice, and a list the user keeps somewhere else
        // is not where they made it. They can still turn it on per item
        // in the editor, and the sync leaves that alone (see `merge`).
        delete_old: false,
        category: src.category.clone(),
        min_age: String::new(),
        max_age: if tv && src.series_scope != SCOPE_ALL {
            SCOPE_NEW_MAX_AGE.into()
        } else {
            String::new()
        },
        enabled: true,
    }
}

/// What one source's item list becomes after a sync.
///
/// `have` is what this source already owned; `outcome` is what the fetch
/// produced. The rules, in the order they matter:
///
/// - A failed or empty fetch changes NOTHING. Not one item is added,
///   removed, or edited.
/// - A fetched list adds what is new and refreshes the source defaults
///   on what it already had - except `delete_old` and `enabled`, which a
///   sync must not overwrite: those are the two things a user can change
///   on a synced row by hand, and a refresh that reset them would undo
///   the edit every six hours.
/// - Anything no longer on the list is dropped only when the source asks
///   for it ([`ListSource::removes_missing`]). Dropping an item stops
///   future grabbing and nothing else: no download is ever deleted.
pub fn merge(src: &ListSource, have: &[WatchItem], outcome: &SyncOutcome) -> Vec<WatchItem> {
    let SyncOutcome::Fetched(entries) = outcome else {
        return have.to_vec();
    };
    if entries.is_empty() {
        return have.to_vec();
    }
    let mut out: Vec<WatchItem> = Vec::with_capacity(entries.len());
    let mut seen: Vec<u64> = Vec::with_capacity(entries.len());
    for e in entries {
        if e.title.trim().is_empty() {
            continue;
        }
        let mut item = to_watch_item(src, e);
        if seen.contains(&item.id) {
            continue; // the same title twice in one feed
        }
        if let Some(old) = have.iter().find(|o| o.id == item.id) {
            item.delete_old = old.delete_old;
            item.enabled = old.enabled;
        }
        seen.push(item.id);
        out.push(item);
    }
    if !src.removes_missing() {
        // Keep what fell off the list. Order: what is on the list now
        // first, then the survivors, so the newest additions lead.
        for old in have {
            if !out.iter().any(|n| n.id == old.id) {
                out.push(old.clone());
            }
        }
    }
    out
}

/// The list `watchlist_pass` actually walks: the user's own items, then
/// every synced one that does not duplicate them.
///
/// The user's row always wins a duplicate. Two items for one title would
/// each take a slot and each grab, and the second grab would land on the
/// M14f duplicate hold - a parked row per pass, for ever, for a title
/// that is already being watched properly. Matching a duplicate is the
/// same normalised-title test the watchlist matches releases with, plus
/// the year when both sides pin one.
pub fn union_watchlist(user: &[WatchItem], synced: &[SyncedItem]) -> Vec<WatchItem> {
    let mut out = user.to_vec();
    for s in synced {
        let dupe = user.iter().any(|u| {
            u.kind == s.item.kind
                && crate::wall::norm_title(&u.title) == crate::wall::norm_title(&s.item.title)
                && match (u.year, s.item.year) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                }
        });
        if !dupe {
            out.push(s.item.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(mode: &str) -> ListSource {
        ListSource {
            id: 7,
            name: "my plex".into(),
            kind: "plex".into(),
            mode: mode.into(),
            url: String::new(),
            token: String::new(),
            interval_secs: DEFAULT_INTERVAL_SECS,
            enabled: true,
            min_quality: "720p".into(),
            target_quality: "1080p".into(),
            category: "tv".into(),
            upgrade: true,
            series_scope: SCOPE_NEW.into(),
            remove_missing: None,
        }
    }

    fn entry(kind: &str, title: &str, year: Option<u32>) -> ListEntry {
        ListEntry {
            title: title.into(),
            year,
            kind: kind.into(),
            ids: Vec::new(),
        }
    }

    #[test]
    fn the_delete_sync_default_differs_per_mode() {
        // The public promise: off for a feed that truncates, on for an
        // account that returns the whole list.
        assert!(!src("rss").removes_missing());
        assert!(src("account").removes_missing());
        // ...and an explicit answer wins in either direction.
        let mut s = src("account");
        s.remove_missing = Some(false);
        assert!(!s.removes_missing());
        let mut s = src("rss");
        s.remove_missing = Some(true);
        assert!(s.removes_missing());
    }

    #[test]
    fn a_series_scope_is_a_max_age_and_a_film_never_gets_one() {
        let s = src("rss");
        let tv = to_watch_item(&s, &entry("tv", "The Bear", None));
        assert_eq!(tv.max_age, SCOPE_NEW_MAX_AGE);
        let film = to_watch_item(&s, &entry("movie", "Dune", Some(2021)));
        assert_eq!(film.max_age, "");
        let mut all = src("rss");
        all.series_scope = SCOPE_ALL.into();
        assert_eq!(
            to_watch_item(&all, &entry("tv", "The Bear", None)).max_age,
            ""
        );
    }

    #[test]
    fn source_defaults_are_stamped_on_created_items() {
        let it = to_watch_item(&src("rss"), &entry("tv", "The Bear", None));
        assert_eq!(it.min_quality, "720p");
        assert_eq!(it.target_quality, "1080p");
        assert_eq!(it.category, "tv");
        assert!(it.upgrade);
        assert!(it.enabled);
        // A sync never asks for the destructive one.
        assert!(!it.delete_old);
    }

    #[test]
    fn ids_are_stable_across_syncs_and_never_meet_the_editors_own() {
        let a = entry_id(7, "tv", "The Bear", None);
        assert_eq!(a, entry_id(7, "tv", "the bear", None));
        assert_ne!(a, entry_id(8, "tv", "The Bear", None));
        assert_ne!(a, entry_id(7, "movie", "The Bear", None));
        assert_ne!(a, entry_id(7, "tv", "The Bear", Some(2022)));
        // Every synced id is above the dashboard's Date.now() space.
        assert!(a > 1 << 62);
    }

    #[test]
    fn a_failed_or_empty_fetch_is_no_news() {
        let s = src("account"); // delete-sync ON, the dangerous side
        let have = vec![to_watch_item(&s, &entry("tv", "The Bear", None))];
        assert_eq!(
            merge(&s, &have, &SyncOutcome::Failed("HTTP 401".into())).len(),
            1
        );
        assert_eq!(merge(&s, &have, &SyncOutcome::Empty).len(), 1);
        // ...and a fetch that parsed to nothing is the same thing.
        assert_eq!(merge(&s, &have, &SyncOutcome::Fetched(Vec::new())).len(), 1);
    }

    #[test]
    fn removal_only_happens_when_the_source_asks_for_it() {
        let rss = src("rss");
        let have = vec![
            to_watch_item(&rss, &entry("tv", "The Bear", None)),
            to_watch_item(&rss, &entry("movie", "Dune", Some(2021))),
        ];
        let shorter = SyncOutcome::Fetched(vec![entry("tv", "The Bear", None)]);
        // RSS truncates, so a title that fell off the end stays watched.
        let kept = merge(&rss, &have, &shorter);
        assert_eq!(kept.len(), 2);
        // A linked account returns the whole list, so it may prune.
        let acct = src("account");
        let have = vec![
            to_watch_item(&acct, &entry("tv", "The Bear", None)),
            to_watch_item(&acct, &entry("movie", "Dune", Some(2021))),
        ];
        let pruned = merge(&acct, &have, &shorter);
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].title, "The Bear");
    }

    #[test]
    fn a_refresh_keeps_the_two_fields_a_user_may_edit() {
        let s = src("rss");
        let mut have = to_watch_item(&s, &entry("tv", "The Bear", None));
        have.delete_old = true;
        have.enabled = false;
        let out = merge(
            &s,
            &[have],
            &SyncOutcome::Fetched(vec![entry("tv", "The Bear", None)]),
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].delete_old);
        assert!(!out[0].enabled);
        // ...but the source's own defaults ARE refreshed.
        assert_eq!(out[0].target_quality, "1080p");
    }

    #[test]
    fn one_title_twice_in_a_feed_becomes_one_item() {
        let s = src("rss");
        let out = merge(
            &s,
            &[],
            &SyncOutcome::Fetched(vec![
                entry("tv", "The Bear", None),
                entry("tv", "the  bear", None),
            ]),
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn the_users_own_row_wins_a_duplicate() {
        let s = src("rss");
        let mut mine = to_watch_item(&s, &entry("tv", "The Bear", None));
        mine.id = 1_700_000_000_001;
        mine.min_quality = "2160p".into();
        let synced = vec![SyncedItem {
            src: 7,
            item: to_watch_item(&s, &entry("tv", "The  Bear!", None)),
        }];
        let all = union_watchlist(&[mine], &synced);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].min_quality, "2160p");
        // A title the user does NOT have comes through.
        let synced = vec![SyncedItem {
            src: 7,
            item: to_watch_item(&s, &entry("movie", "Dune", Some(2021))),
        }];
        assert_eq!(union_watchlist(&[], &synced).len(), 1);
    }

    #[test]
    fn a_pinned_year_tells_two_films_of_one_name_apart() {
        let s = src("rss");
        let mut mine = to_watch_item(&s, &entry("movie", "Dune", Some(1984)));
        mine.id = 1_700_000_000_002;
        let synced = vec![SyncedItem {
            src: 7,
            item: to_watch_item(&s, &entry("movie", "Dune", Some(2021))),
        }];
        assert_eq!(union_watchlist(&[mine], &synced).len(), 2);
    }

    #[test]
    fn health_keeps_the_last_good_answer_across_a_failure() {
        let good = SourceHealth::ok(100, 12, 12);
        let bad = SourceHealth::failed(&good, 200, "HTTP 401");
        assert_eq!(bad.last_ok, 100);
        assert_eq!(bad.items_seen, 12);
        assert_eq!(bad.last_sync, 200);
        assert_eq!(bad.last_error, "HTTP 401");
    }
}
