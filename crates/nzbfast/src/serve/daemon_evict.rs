//! M34 index size cap + eviction, the daemon half: the vocabularies
//! the `index_evict_*` and `scoreboard_cats` settings may name, the
//! validators that turn one of those strings into something the engine
//! understands, and the opened-log that records deliberate user
//! attention so the cap does not evict what someone just looked at.
//!
//! Split out of daemon.rs rather than added to it (TODO 106 code
//! motion, size gate): that file sits at its ceiling and the numbers
//! only go down. Same seam the protected-set trio already moved along
//! to daemon_index.rs, and for the same reason - this is one subject
//! with no reference to `Daemon` itself, so it moves whole. Every
//! item is re-exported from daemon.rs, so all existing `daemon::` and
//! `super::` paths still resolve.

/// The eviction orders the `index_evict_order` setting accepts, in the
/// order the UI lists them. Kept as strings here because that is what
/// crosses the settings/API boundary; `parse_evict_order` is the single
/// place that turns one into the engine's enum.
#[cfg(feature = "indexer")]
pub const EVICT_ORDERS: [&str; 5] = ["ladder", "oldest", "newest", "largest", "smallest"];

/// The built-in release kinds the index stores. Mirrors
/// `categories::RESERVED_KINDS` by definition so the two cannot drift:
/// `kind_str` (index/mod.rs) writes exactly these six into
/// `releases.kind`, plus a custom category's slug verbatim - so this
/// list is the RESERVED half of the vocabulary `index_evict_kinds` and
/// `index_keep_kinds` may name, and `parse_evict_kinds` accepts a
/// slug-shaped token beside it. It was the four-entry list until 27 Aug
/// 2026, so music, book and every custom kind could be neither kept nor
/// targeted while the eviction ladder deleted their rows.
#[cfg(feature = "indexer")]
pub const EVICT_KINDS: [&str; 6] = nzbkit::categories::RESERVED_KINDS;

/// The scopes `index_evict_scope` accepts, in the order the UI lists
/// them. "junk_incomplete" is the union - never delete real, complete
/// content, whatever the cap says.
#[cfg(feature = "indexer")]
pub const EVICT_SCOPES: [&str; 4] = ["all", "junk", "incomplete", "junk_incomplete"];

/// The parity scoreboard's sampling menu: newznab's standard top-level
/// thousands, paired with the label the samples are stored and reported
/// under. The daily run makes ONE request per category in this list, so
/// its length is the scoreboard's whole cost, and `scoreboard_cats` can
/// only ever pick a subset of it - four requests a day is the ceiling
/// and one is the floor.
///
/// Not indexer-gated: the sampler that walks it is, but the setting
/// that trims it, its validator and the API readout are not.
pub const SCOREBOARD_CATEGORIES: [(u32, &str); 4] = [
    (2000, "movies"),
    (5000, "tv"),
    (3000, "audio"),
    (7000, "books"),
];

/// How long a deliberate touch (detail sheet, /getnzb, queue add) keeps a
/// release safe from the size cap. The user asked for "recently opened"
/// to be protected; a month is long enough that a title you browsed
/// before the weekend is still there on Monday, short enough that a
/// year of idle curiosity does not pin the whole database.
#[cfg(feature = "indexer")]
pub const OPENED_PROTECT_DAYS: i64 = 30;

/// Don't rewrite index-opened.json for a key already touched this
/// recently - browsing a card repeatedly is one signal, not fifty.
#[cfg(feature = "indexer")]
pub(crate) const OPENED_COALESCE_SECS: i64 = 3_600;

/// Ceiling on either half of the touch log, so a scripted crawl of the
/// wall cannot grow the file without bound. Oldest touches drop first,
/// which is exactly the order the protection window would have expired
/// them in anyway.
#[cfg(feature = "indexer")]
pub(crate) const OPENED_MAX_ENTRIES: usize = 5_000;

/// There is deliberately NO ceiling on the protected set.
///
/// This used to refuse to evict at all past 30_000 protected keys, out of
/// a fear that SQLite's 32_766-variable statement limit would silently
/// truncate the list and delete something the user asked us to keep. That
/// fear was misplaced: `Index::evict_to` binds at most 10_000 protected
/// entries into the candidate query as an OPTIMISATION, and then re-checks
/// every surviving candidate in Rust against the full, uncapped set before
/// deleting it. Overflowing the bind cap costs a little scan work, nothing
/// else, and `evict_protected_set_past_the_bind_limit_still_protects_everything`
/// in index.rs pins that at 30_000 ids plus 30_000 keys.
///
/// So the ceiling only ever produced the worse outcome: a user with a
/// large history got a cap that was never enforced, which is the failure
/// mode the cap exists to prevent. Hand the engine the whole set.
///
/// Bound the pass count instead. The engine's byte estimator is
/// deliberately conservative and can stop a little short of the target
/// (its own doc calls the undershoot self-correcting, on the assumption
/// that the next scan pass finishes the job). A user who pressed a button
/// should not have to wait for a scan pass, so an on-demand eviction
/// re-runs while it is still making progress, up to this many times. Each
/// pass re-seeds its estimate from the measured file, so convergence is
/// fast; the bound is only there so a pathological fixture cannot spin.
#[cfg(feature = "indexer")]
pub(in crate::serve) const EVICT_MAX_PASSES: usize = 8;

/// Rows the dry-run preview may examine before it stops and reports
/// itself truncated. The preview holds the same lock the real eviction
/// would and each candidate page is a scan-and-sort of `releases` (no
/// index serves the ladder's CASE - the measured figure is in the
/// engine's EVICT_PAGE note), so on a many-million-row index an
/// unbounded walk is minutes inside the write lock for an answer whose
/// tail nobody reads. 200k rows is a hundred pages: enough to answer
/// every plausible cap on an index that size honestly, and the report
/// says `truncated` past it rather than pretending it finished.
#[cfg(feature = "indexer")]
pub(in crate::serve) const EVICT_PREVIEW_MAX_EXAMINE: usize = 200_000;

/// Deliberate user attention, remembered. See `Daemon::index_opened`.
#[cfg(feature = "indexer")]
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct OpenedLog {
    /// Wall title_key → unix seconds of the last detail-sheet open.
    #[serde(default)]
    pub titles: std::collections::HashMap<String, i64>,
    /// Index release id → unix seconds of the last /getnzb or queue add.
    #[serde(default)]
    pub releases: std::collections::HashMap<i64, i64>,
}

#[cfg(feature = "indexer")]
impl OpenedLog {
    /// Record a touch. Returns true when the caller should persist -
    /// i.e. this is new information, not the same card opened twice in a
    /// row. Trims to `OPENED_MAX_ENTRIES`, oldest first.
    pub(in crate::serve) fn touch_title(&mut self, key: &str, now: i64) -> bool {
        if key.is_empty() {
            return false;
        }
        let fresh = self
            .titles
            .get(key)
            .is_some_and(|t| now - *t < OPENED_COALESCE_SECS);
        self.titles.insert(key.to_string(), now);
        Self::trim(&mut self.titles);
        !fresh
    }

    pub(in crate::serve) fn touch_release(&mut self, id: i64, now: i64) -> bool {
        if id < 0 {
            return false;
        }
        let fresh = self
            .releases
            .get(&id)
            .is_some_and(|t| now - *t < OPENED_COALESCE_SECS);
        self.releases.insert(id, now);
        Self::trim(&mut self.releases);
        !fresh
    }

    pub(in crate::serve) fn trim<K: Clone + std::hash::Hash + Eq>(
        m: &mut std::collections::HashMap<K, i64>,
    ) {
        if m.len() <= OPENED_MAX_ENTRIES {
            return;
        }
        let mut by_age: Vec<(K, i64)> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
        by_age.sort_by_key(|(_, t)| *t);
        for (k, _) in by_age.into_iter().take(m.len() - OPENED_MAX_ENTRIES) {
            m.remove(&k);
        }
    }

    /// Drop touches that have aged out of the protection window. Called
    /// before every save so the file self-limits.
    pub(in crate::serve) fn expire(&mut self, now: i64, window_secs: i64) {
        self.titles.retain(|_, t| now - *t <= window_secs);
        self.releases.retain(|_, t| now - *t <= window_secs);
    }
}

/// The `index_evict_order` string → the engine's enum. `None` for
/// anything else, which `apply_setting` refuses to store in the first
/// place; the fallback at read time is Ladder.
#[cfg(feature = "indexer")]
pub fn parse_evict_order(s: &str) -> Option<nzbkit::index::EvictOrder> {
    use nzbkit::index::EvictOrder as O;
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "ladder" => O::Ladder,
        "oldest" => O::Oldest,
        "newest" => O::Newest,
        "largest" => O::Largest,
        "smallest" => O::Smallest,
        _ => return None,
    })
}

/// The `index_evict_scope` string → the engine's enum. `None` for
/// anything else, which `apply_setting` refuses to store; the fallback
/// at read time is All, matching the engine's own default.
#[cfg(feature = "indexer")]
pub fn parse_evict_scope(s: &str) -> Option<nzbkit::index::EvictScope> {
    use nzbkit::index::EvictScope as S;
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "all" | "" => S::All,
        "junk" => S::Junk,
        "incomplete" => S::Incomplete,
        "junk_incomplete" => S::JunkOrIncomplete,
        _ => return None,
    })
}

/// The `index_evict_kinds` comma list → validated lowercase kinds.
/// `Err` names the offender: a typo here would restrict eviction to a
/// kind no row carries, and the user would be left staring at a cap that
/// never frees anything.
///
/// A token is valid when it is a reserved kind OR shaped like a custom
/// category slug (the `categories::validate` charset), because
/// `kind_str` stores `Custom(slug)` verbatim in `releases.kind`. Shape
/// only, deliberately: rows keep the kind of a category deleted since,
/// and those rows still need naming here. What remains refusable is a
/// malformed token - punctuation, interior whitespace, non-ASCII.
#[cfg(feature = "indexer")]
pub fn parse_evict_kinds(s: &str) -> std::result::Result<Vec<String>, String> {
    let slug_shaped = |k: &str| {
        !k.is_empty()
            && k.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    };
    let mut out: Vec<String> = Vec::new();
    for raw in s.split(',') {
        let k = raw.trim().to_ascii_lowercase();
        if k.is_empty() {
            continue;
        }
        if !EVICT_KINDS.contains(&k.as_str()) && !slug_shaped(&k) {
            return Err(format!(
                "unknown kind {k:?} (expected {}, or a custom category slug)",
                EVICT_KINDS.join(", ")
            ));
        }
        if !out.contains(&k) {
            out.push(k);
        }
    }
    Ok(out)
}

/// The `scoreboard_cats` comma list → validated category labels.
///
/// The list may only ever REDUCE what the scoreboard asks for: every
/// name has to be one of [`SCOREBOARD_CATEGORIES`], so there is no
/// spelling of this setting that adds a request to the day. Empty is
/// the default and means every category - the ceiling, not a hole - so
/// the only way to spend less is to name the subset you want.
///
/// An unknown name is an error rather than a silent drop: the whole
/// point of the control is that the user knows what they are paying
/// for, and a typo that quietly halved the sample would be the exact
/// opposite of that.
pub fn parse_scoreboard_cats(s: &str) -> std::result::Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for raw in s.split(',') {
        let c = raw.trim().to_ascii_lowercase();
        if c.is_empty() {
            continue;
        }
        if !SCOREBOARD_CATEGORIES.iter().any(|(_, l)| *l == c) {
            return Err(format!(
                "unknown category {c:?} (expected {})",
                SCOREBOARD_CATEGORIES
                    .iter()
                    .map(|(_, l)| *l)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !out.contains(&c) {
            out.push(c);
        }
    }
    Ok(out)
}
