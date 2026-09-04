//! Built-in header indexer (design: M12): scan groups via OVER, cluster
//! posts into releases, store in SQLite, search, and synthesize an NZB on
//! demand - browse Usenet like a catalogue instead of pasting NZBs.
//!
//! Clustering is the proven make-release-nzb logic generalized: files
//! group by (poster, release stem); a release is complete when every seen
//! file has all its parts. Incremental scans resume from each group's
//! stored high-water mark.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use tracing::warn;

use rusqlite::{Connection, OptionalExtension};

/// SQLite's per-CONNECTION cancellation handle, re-exported so callers
/// outside this crate (the daemon's maintenance watchers) can hold one
/// without taking a direct rusqlite dependency.
pub use rusqlite::InterruptHandle;

use crate::names::release_stem;
use crate::nntp::OverEntry;

mod aggregates;
mod albumfold;
#[cfg(test)]
mod albumfold_tests;
mod browse;
mod cards;
mod claims;
mod deadline;
mod deobf;
#[cfg(test)]
mod deobf_tests;
mod encrypted;
mod evict;
mod fold;
mod ingest;
#[cfg(test)]
mod ingest_diff_tests;
mod maintenance;
mod nzbimport;
mod pesto;
#[cfg(test)]
mod plan_tests;
mod predb;
#[cfg(test)]
mod predb_tests;
mod probe;
mod query;
mod retry;
mod schema;
mod scoreboard;
mod searchlog;
mod seed;
mod seed_collection;
#[cfg(test)]
mod seed_tests;
pub mod segcodec;
mod segmig;
mod session;
mod sessionfold;
#[cfg(test)]
mod sessionfold_tests;
mod spots;
mod summaries;
#[cfg(test)]
mod testutil;
mod titles;

pub use browse::*;
pub use cards::*;
pub use claims::{MSGID_KEYS_PER_FILE, NameClaim, NameEvidence, ProvenOutcome, msgid_set_key};
pub use deobf::{
    CatalogRow, CollectionKey, HUNT_MIN_SLACK, HUNT_SIZE_SLACK_DIV, HUNT_TIGHT_WINDOW,
    HUNT_TIME_WINDOW, HitRank, HuntQuery, IndexerJoin, NameFromNzbError, coarsen_age_days,
    coarsen_size_mb, group_by_leftover, group_by_session, hunt_cascade_for_dark,
    hunt_cascade_with_poster, hunt_catalog, hunt_catalog_mapped_then_filter,
    hunt_catalog_newznab_then_size, hunt_for_dark, hunt_from_dark, hunt_from_dark_with_poster,
    hunt_next_episode, hunt_next_episode_sized, hunt_until_named, hunt_until_named_queries,
    hunt_until_quota, hunt_wanted, joins_named, leftover_as_query, leftover_boosts,
    leftover_hex_prefix, leftover_hex_prefix_with_window, leftover_hex_suffix,
    leftover_hex_suffix_with_window, leftover_hex8_suffix, leftover_hex8_suffix_with_window,
    leftover_is_a_title, leftover_posted_lcp, leftover_posted_lcs, leftover_stem,
    leftover_stem_with_window, leftover_token, leftover_with_tight_window, leftover_with_window,
    rank_hits, rank_hits_exact_then_poster, rank_hits_exact_then_rare_then_poster,
    rank_hits_lcp_then_rare_then_poster, rank_hits_lcs_then_rare_then_poster,
    rank_hits_newest_then_poster, rank_hits_prefer_poster, rank_hits_rare_title,
    rank_hits_rare_title_then_poster, rank_hits_with_leftover,
};
pub use encrypted::{ENC_CLASS, EncKind};
pub use evict::*;
pub use ingest::*;
pub use maintenance::*;
pub use nzbimport::*;
pub use pesto::*;
pub use probe::*;
pub use query::{FilenameFallback, filename_fallback_stats, reset_filename_fallback_stats};
pub use schema::WAL_SIZE_LIMIT;
pub use scoreboard::*;
pub use searchlog::*;
pub use seed::*;
pub use seed_collection::*;
pub use segcodec::{Seg, SegList, SegRaw};
pub use segmig::*;
pub use session::{SessionLink, SessionSibling, TitleSibling};
pub use spots::*;
pub use titles::*;

pub struct Index {
    db: Connection,
    /// Ingest gate: release stem → keep? None = keep everything. Policy
    /// (year/kind/quality/language rules) lives in the caller; the index
    /// only applies the verdict, once per cluster.
    gate: Option<Box<dyn Fn(&str) -> bool + Send>>,
    /// FTS5 available and rel_fts created - search/browse take the
    /// index path; false falls back to the LIKE scans.
    fts: bool,
    /// pre_fts created - the small FTS index over pre-feed names. Its own
    /// flag rather than riding on `fts`: it is created later than
    /// `rel_fts`, so an index built before this feature existed has one
    /// and not the other until the next open.
    pre_fts: bool,
    /// people_fts created. Tracked separately from `fts` on purpose: the
    /// name-search leg is an OR inside the main browse predicate, so if
    /// that table were missing every search on the wall would fail, not
    /// just the people half.
    people_fts: bool,
    /// TODO 24D user categories, installed by the daemon (empty = off).
    /// Every ingest-time classification runs through these ahead of the
    /// built-in kinds; `reclassify_custom` reconciles stored rows after
    /// a config change.
    custom: Vec<crate::categories::CustomCategory>,
    /// Does the pre feed hold anything? Read once at open so that on the
    /// overwhelmingly common install - the feed is off, the table is
    /// empty - ingest pays nothing at all for the naming lookup. An
    /// install that switches the feed on gets the lookup from the next
    /// re-open, which the scan loop does after every pass.
    predb: bool,
    /// Names the caller wants told about the moment a release gains or
    /// changes one: release name → interesting? None = tell me nothing,
    /// which costs a single null check per touched release. Same
    /// arrangement as `gate` - the index applies a verdict it does not
    /// author (here it is the daemon's watchlist).
    watch: Option<Box<dyn Fn(&str) -> bool + Send>>,
    /// What `watch` said yes to since the caller last drained it. Behind
    /// a RefCell because the naming legs run on `&self`; the index is
    /// single-threaded behind the daemon's mutex either way.
    hits: std::cell::RefCell<WatchHits>,
    /// SQLITE_SCHEMA bookkeeping for this connection: how many queries
    /// failed with a stale statement even after re-preparing, plus the
    /// injector that gives that path a deterministic test. See `retry`.
    retry: retry::SchemaRetry,
    /// Set when THIS connection just ran a piece of runtime DDL (the
    /// named-feed partial index, built lazily on first feed activity,
    /// and the §26c A5 `files` rebuild's staging triggers, swap and
    /// drop). Drained via [`Self::take_schema_ddl`] so the daemon
    /// can retire its pooled read-only connections exactly when the
    /// schema actually changed, instead of flushing them after every
    /// scan pass. A Cell because one of the creation sites
    /// (`predb_named_count`'s self-heal) runs on `&self`.
    ddl: std::cell::Cell<bool>,
    /// C3 prototype: the one-row-per-title wall summaries are installed
    /// on this database (`title_summaries` + the `releases` triggers
    /// that keep `title_dirty`). Off unless `NZBFAST_TITLE_SUMMARIES=1`
    /// was set at open, or the table was already there from a previous
    /// run with it on - the schema is the flag's persistent half, so a
    /// read-only handle detects it the same way it detects FTS.
    summaries: bool,
    /// How long the current query on this connection may run, and how
    /// many have been abandoned for outrunning that. Installed as a
    /// progress callback by `open_read_only` and by nothing else - see
    /// [`deadline`], which is where the wall-side measurement that
    /// motivates it lives.
    deadline: deadline::QueryDeadline,
    /// TTL memo for [`Index::stats_cached`]: when the figures were
    /// computed and what they were. Per connection like everything
    /// else here (a Cell, because the index is single-threaded behind
    /// its owner's mutex); callers that need the exact answer use
    /// [`Index::stats`].
    stats_cache: std::cell::Cell<Option<(std::time::Instant, (u64, u64))>>,
    /// TODO 300: the wall page's window fast path is armed on this
    /// handle. True everywhere in production - the field exists because
    /// a fast path whose whole contract is "same answer, less work" can
    /// only be tested by asking ONE database both ways, and the
    /// eligibility test is otherwise entangled with the request shape
    /// (see `cards::Index::wall_page_keys`). Same lever `summaries`
    /// gives the C3 differential tests, for the same reason.
    pub(crate) wall_window: bool,
    /// TTL memo for the card wall's `total` - `(computed at, the count
    /// statement it answers, the answer)`. Per connection, like
    /// [`Self::stats_cache`] next door and for the same reason, and a
    /// `RefCell` rather than a `Cell` only because the key is a
    /// `String`. Written by [`Index::cards_total`], which is also where
    /// the rule for when a count is worth memoizing at all lives.
    cards_total_memo: std::cell::RefCell<Option<(std::time::Instant, String, u64)>>,
}

/// A release a batch just touched that [`Index::set_watch_names`] said
/// the caller cares about. Deliberately thin: it answers "is this worth
/// waking the watchlist for", and every decision that follows is made by
/// the watchlist pass against the database, not against this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchHit {
    pub id: i64,
    /// The name the release is known by NOW - the fed name where one has
    /// been applied, the posted stem otherwise.
    pub name: String,
    /// Every file seen has all its parts. A fresh arrival is usually
    /// false for its first few batches: the post is still going up.
    pub complete: bool,
}

/// The journal behind [`Index::take_watch_hits`], with the cap that
/// keeps a backfill from growing it without bound.
#[derive(Default)]
struct WatchHits {
    list: Vec<WatchHit>,
    /// Hits thrown away because the journal was full. Reported so a
    /// dropped arrival is a number somebody can see rather than silence.
    dropped: u32,
}

/// How many un-drained hits the journal holds. A tip tick drains after
/// every chunk, so this is only ever reached by a leg that names
/// thousands of releases at once (a correlation backlog sweep over a
/// freshly seeded pre corpus). Losing the overflow costs latency, never
/// coverage: the periodic watchlist pass sees the same releases.
const WATCH_HITS_CAP: usize = 512;

/// One indexed release (search result row).
#[derive(Debug, Clone)]
pub struct Release {
    pub id: i64,
    pub stem: String,
    pub poster: String,
    pub grp: String,
    pub total_bytes: u64,
    pub files: u32,
    pub has_par2: bool,
    pub complete: bool,
    /// Unix time of the earliest article seen (upload date).
    pub first_posted: i64,
    /// Unix time we first indexed it.
    pub first_seen: i64,
    /// Parsed classification, stored at ingest: "movie" / "tv" /
    /// "software" / "other" ('' on rows the backfill hasn't touched).
    pub kind: String,
    /// Parsed resolution ("2160p", "1080p", …; '' = unknown).
    pub res: String,
    /// Exact segment tally across the release's files - the browse
    /// view's completeness percentage (complete is the binary verdict).
    pub have_parts: u64,
    pub need_parts: u64,
    /// Parsed video codec / strongest audio track / dynamic range
    /// ('' = the name didn't say). What tells two encodes of the same
    /// film apart once resolution has tied.
    pub vcodec: String,
    pub acodec: String,
    pub hdr: String,
    /// The real release name a pre feed gave this post ('' = never
    /// named that way). When set, this is what the UI should show: the
    /// stem beside it is the obfuscated string it was posted under.
    pub pre_title: String,
    /// Where that name came from, so the claim can be attributed rather
    /// than presented as something we read off the wire.
    pub pre_source: String,
}

/// Column list every Release row read shares (search + browse).
const REL_COLS: &str = "id, stem, poster, grp, total_bytes, files, has_par2, complete,
     first_posted, first_seen, kind, res, have_parts, need_parts,
     vcodec, acodec, hdr, pre_title, pre_source";

/// How many candidate rows an NZBLNK header lookup will look at per
/// rung before giving up. Bounds both the FTS verification pass and the
/// unindexed filename scan; a header that matches this many things was
/// never distinctive enough to identify one posting.
const FIND_SCAN_CAP: u32 = 500;

fn release_from_row(r: &rusqlite::Row) -> rusqlite::Result<Release> {
    Ok(Release {
        id: r.get(0)?,
        stem: r.get(1)?,
        poster: r.get(2)?,
        grp: r.get(3)?,
        total_bytes: r.get::<_, i64>(4)? as u64,
        files: r.get(5)?,
        has_par2: r.get(6)?,
        complete: r.get(7)?,
        first_posted: r.get(8)?,
        first_seen: r.get(9)?,
        kind: r.get(10)?,
        res: r.get(11)?,
        have_parts: r.get::<_, i64>(12)? as u64,
        need_parts: r.get::<_, i64>(13)? as u64,
        vcodec: r.get(14)?,
        acodec: r.get(15)?,
        hdr: r.get(16)?,
        pre_title: r.get(17)?,
        pre_source: r.get(18)?,
    })
}

impl Release {
    /// What to show a person: the fed name when we have one, otherwise
    /// the posted stem. One function so the API, the classifier and
    /// anything else that renders a release agree on which string is the
    /// name.
    pub fn display_name(&self) -> &str {
        if self.pre_title.is_empty() {
            &self.stem
        } else {
            &self.pre_title
        }
    }
}

/// M30: readable form of a raw parse key - "m:barclays premier league
/// 2011:2012" → "Barclays Premier League 2011 (2012)". Used wherever an
/// unenriched title would otherwise surface its key.
fn pretty_key(key: &str) -> String {
    // Custom keys are "c:<slug>:<title>[:<year>][:<extra>]" - drop the
    // prefix AND the slug, space the rest out ("formula1 2026 round11
    // hungary qualifying"), title-cased below like any other key.
    let custom_owned;
    let base = if let Some(rest) = key.strip_prefix("c:") {
        custom_owned = rest
            .split_once(':')
            .map_or(rest, |(_, t)| t)
            .replace(':', " ");
        custom_owned.as_str()
    } else {
        key.strip_prefix("t:")
            .or_else(|| key.strip_prefix("m:"))
            .unwrap_or(key)
    };
    let (name, yr) = match base.rsplit_once(':') {
        Some((w, y)) if !y.is_empty() && y.chars().all(|c| c.is_ascii_digit()) => (w, Some(y)),
        _ => (base, None),
    };
    let mut t = name
        .split_whitespace()
        .map(|w| {
            let mut cs = w.chars();
            match cs.next() {
                Some(c) => c.to_uppercase().collect::<String>() + cs.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(y) = yr {
        t.push_str(&format!(" ({y})"));
    }
    t
}

/// One enricher lane. Each runs on its own thread against its own set
/// of providers, because the rate limits are per provider: a serial loop
/// made every TV title queue behind the movie crawl, and adding music
/// and books to the TV lane would have put a 1-request-per-second
/// MusicBrainz backlog in front of every new episode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lane {
    /// Wikidata / Wikipedia / OMDb.
    Movies,
    /// TVmaze, plus the junk and custom-category rows that touch no
    /// provider at all and are only stamped.
    Shows,
    /// MusicBrainz / Cover Art Archive / OpenLibrary.
    MusicBooks,
}

impl Lane {
    /// This lane's slice of `titles`, as a SQL fragment. Static text
    /// only - it is interpolated into the query, so it must never carry
    /// a caller-supplied value.
    fn sql(self) -> &'static str {
        match self {
            Lane::Movies => "kind = 'movie'",
            Lane::MusicBooks => "kind IN ('music','book')",
            // Everything the other two lanes do not claim, so a kind
            // added later still gets enriched by SOMETHING rather than
            // falling down a gap between lanes and never being looked at.
            Lane::Shows => "kind NOT IN ('movie','music','book')",
        }
    }
}

/// SQL value for a parsed kind (lowercase, stable - stored in the db).
/// A custom category stores its slug directly; slugs can never shadow
/// the built-in four (`categories::validate` reserves them).
pub fn kind_str(k: &crate::release::Kind) -> &str {
    match k {
        crate::release::Kind::Movie => "movie",
        crate::release::Kind::Tv => "tv",
        crate::release::Kind::Software => "software",
        crate::release::Kind::Music => "music",
        crate::release::Kind::Book => "book",
        crate::release::Kind::Other => "other",
        crate::release::Kind::Custom(slug) => slug,
    }
}

/// The gapfill band, as LITERAL terms - the WHERE prefix of
/// `gapfill_pick` and, verbatim, the predicate of `idx_rel_gapfill`
/// (schema.rs). One constant feeds both so they cannot drift, and the
/// terms are literals because a partial index is reachable only when
/// the statement's own WHERE implies its predicate, proven from literal
/// terms and never from a bound parameter (the N1 rule). `first_seen`
/// stays out: its cutoff is a moving clock.
pub(crate) const GAPFILL_BAND_SQL: &str = "complete=0 AND junk < 50 AND first_posted > 0";

/// The pick's rotation order, verbatim in `idx_rel_gapfill`'s columns:
/// least-recently-tried first, then a multiplicative hash of the id so
/// never-tried rows (gapfill_at=0, the standing majority) are visited
/// in a scattered order rather than oldest-first. The index carries the
/// expression itself; ORDER BY must match it byte for byte or the temp
/// B-tree comes back silently - plan_tests.rs holds the line.
pub(crate) const GAPFILL_ORDER_SQL: &str = "gapfill_at ASC, (id * 2654435761) % 4294967296";

/// The pick's full SQL, shared with plan_tests.rs so the plan gate
/// asserts the statement the daemon actually runs. Pinned to the band
/// index (the cards.rs `INDEXED BY` rationale - a background statement
/// whose wrong plan is a per-pass temp sort of the whole incomplete
/// band does not get left to the cost model); the unpinned form is the
/// fallback for a database the maintenance backfill has not reached
/// yet, where INDEXED BY would fail to prepare.
pub(crate) fn gapfill_pick_sql() -> String {
    gapfill_pick_sql_with("INDEXED BY idx_rel_gapfill")
}

pub(crate) fn gapfill_pick_sql_unpinned() -> String {
    gapfill_pick_sql_with("")
}

fn gapfill_pick_sql_with(pin: &str) -> String {
    format!(
        "SELECT id, grp, first_posted FROM releases {pin}
         WHERE {GAPFILL_BAND_SQL}
           AND first_seen < ?2
         ORDER BY {GAPFILL_ORDER_SQL} LIMIT ?1"
    )
}

impl Index {
    // ---- M29 availability oracle -------------------------------------

    /// Fold a batch of hit/miss samples into the oracle ledger.
    pub fn oracle_ingest(
        &self,
        samples: &[crate::oracle::Sample],
        now: i64,
    ) -> rusqlite::Result<()> {
        crate::oracle::ingest(&self.db, samples, now)
    }

    /// The whole ledger (tiny by construction) for verdict computation.
    pub fn oracle_snapshot(&self) -> rusqlite::Result<crate::oracle::Snapshot> {
        crate::oracle::Snapshot::load(&self.db)
    }

    /// Releases the idle STAT sampler should probe next: never-sampled
    /// first, then stalest verdict, newest post first within a tier.
    /// Returns (id, group, first_posted).
    ///
    /// Drawn by SEEKING to pseudo-random posting instants, exactly as
    /// [`Self::oracle_backtest_pick`] below does, and for the reason
    /// stated there: an `ORDER BY` over this table is fine on a fresh
    /// index and ruinous on a real one. This used to be
    ///
    /// ```sql
    /// SELECT id, grp, first_posted FROM releases WHERE junk < 50
    ///  ORDER BY oracle_at ASC, (id * 2654435761) % 4294967296 LIMIT ?1
    /// ```
    ///
    /// and no index covers `oracle_at`, so SQLite answered it with
    /// `SCAN releases` plus a `TEMP B-TREE` - the whole table read and
    /// all of its rows sorted, to return one. On a long-running install
    /// (16 Aug 2026: 38 M releases, a 55.9 GB database) that statement
    /// ran over forty minutes, and the sampler takes it under `with_index`,
    /// which holds the index write mutex for the whole closure. One
    /// tick therefore froze every other index user: the scan pass could
    /// not hand back `index_pass_gate`, so watch-folder adds waited out
    /// the runner's full rendezvous bound before starting, and the
    /// prefetch sidecar's finish tail never completed, which parked the
    /// runner in `stop_sidecar` with the finished job stuck reading
    /// "Extracting" at 100% and the rest of the queue behind it.
    ///
    /// The seek costs three `idx_rel_posted` range probes (measured at
    /// 5 ms against that same database). What it gives up is strict
    /// stalest-first ordering over the whole table: the sample is
    /// uniform over POSTING TIME, and the freshest verdict among the
    /// drawn candidates wins. That is the same honest bias
    /// `oracle_backtest_pick` documents - and it serves the original
    /// intent better than the sort did, because the random tiebreak
    /// existed to spread picks across post ages in the first place.
    pub fn oracle_pick(&self, limit: u32) -> rusqlite::Result<Vec<(i64, String, i64)>> {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        self.oracle_pick_seeded(limit, seed)
    }

    /// [`Self::oracle_pick`] with the draw seed supplied, so a test can
    /// replay the same candidates.
    pub fn oracle_pick_seeded(
        &self,
        limit: u32,
        seed: u64,
    ) -> rusqlite::Result<Vec<(i64, String, i64)>> {
        let want = limit as usize;
        if want == 0 {
            return Ok(Vec::new());
        }
        /// Matches taken per seek - neighbours in posting time, which is
        /// the price of the cheap seek (`oracle_backtest_pick`'s note).
        const PER_SEEK: usize = 3;
        // Both bounds are single aggregates over an indexed column, so
        // each is one index-endpoint seek. Asked separately: SQLite only
        // applies that optimization to a query with exactly ONE
        // aggregate, and `SELECT MIN(x), MAX(x)` would scan.
        //
        // NOT filtered by `junk < 50`, though matching the seeks below
        // is the obvious-looking change and it was tried. It breaks the
        // sampler. The backward seek runs ONLY as a fallback when the
        // forward one comes back empty (`if hit.is_empty()` below), so
        // the draw has to be able to land ABOVE the newest visible row
        // for it to fire at all - and an unfiltered `hi`, which junk
        // rows routinely push up, is what makes that happen. Filter it
        // and the forward seek always matches the topmost visible row,
        // the backward arm never runs, and the sampler stops reaching
        // anything older than the draw. `oracle_pick_prefers_the_
        // unsampled_and_skips_junk` catches it, which is how this is
        // known.
        //
        // So the population mismatch is left standing deliberately: it
        // is a bias in which rows get drawn, and the fix for it is a
        // real change to the seek strategy, not a WHERE clause. The
        // defect actually filed here was the per-row table fetch, and
        // that is fixed in `idx_rel_visible_posted` (sweep 4, L3b).
        let lo: i64 = self.db.query_row(
            "SELECT COALESCE(MIN(first_posted), 0) FROM releases",
            [],
            |r| r.get(0),
        )?;
        let hi: i64 = self.db.query_row(
            "SELECT COALESCE(MAX(first_posted), 0) FROM releases",
            [],
            |r| r.get(0),
        )?;
        if hi <= 0 {
            return Ok(Vec::new());
        }
        // Sample what users can actually SEE (junk < 50): probing the
        // endless stream of freshly-scanned obfuscated rows meant every
        // probe was a 0-day article, bucket 0 was the only bucket that
        // ever learned, and old-post availability - the interesting
        // question - stayed unknown forever.
        let mut fwd = self.db.prepare_cached(
            "SELECT id, grp, first_posted, COALESCE(oracle_at, 0) FROM releases
             WHERE first_posted >= ?1 AND junk < 50
             ORDER BY first_posted LIMIT ?2",
        )?;
        let mut back = self.db.prepare_cached(
            "SELECT id, grp, first_posted, COALESCE(oracle_at, 0) FROM releases
             WHERE first_posted <= ?1 AND junk < 50
             ORDER BY first_posted DESC LIMIT ?2",
        )?;
        let span = (hi - lo).max(0) as u64;
        let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
        let mut cands: Vec<(i64, String, i64, i64)> = Vec::new();
        let mut seen: std::collections::HashSet<i64> = Default::default();
        let seeks = want.saturating_mul(4).clamp(4, 32);
        for _ in 0..seeks {
            // SplitMix64, the generator `oracle_backtest_pick` uses.
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let t = lo + (z % span.max(1)) as i64;
            let rows = |st: &mut rusqlite::Statement<'_>, at: i64| {
                st.query_map(rusqlite::params![at, PER_SEEK as i64], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                })
                .and_then(|m| m.collect::<rusqlite::Result<Vec<_>>>())
                .unwrap_or_default()
            };
            // Past the last match, the nearest rows BEFORE the instant,
            // so a draw near the top of the window is not wasted.
            let mut hit = rows(&mut fwd, t);
            if hit.is_empty() {
                hit = rows(&mut back, t);
            }
            for row in hit {
                if seen.insert(row.0) {
                    cands.push(row);
                }
            }
        }
        // Never-sampled first (oracle_at 0), then stalest verdict, then
        // newest post inside a tier - the documented order, applied to
        // the drawn candidates instead of to the whole table.
        cands.sort_by_key(|&(id, _, posted, at)| (at, std::cmp::Reverse(posted), id));
        Ok(cands
            .into_iter()
            .take(want)
            .map(|(id, grp, posted, _)| (id, grp, posted))
            .collect())
    }

    /// Up to `max` probe message-ids for a release, spread evenly across
    /// its files' segments (bracketed, STAT-ready).
    pub fn oracle_msgids(&self, release_id: i64, max: usize) -> rusqlite::Result<Vec<String>> {
        if max == 0 {
            return Ok(Vec::new());
        }
        // How many segments the release HAS, without materialising one
        // of them: sampling a dozen ids used to build the whole
        // release's id list first, which on a 50 GB pack is hundreds of
        // thousands of Strings for a handful of STATs. `nsegs` is the
        // stored count, in the nsegs-or-count shape every other site
        // uses (pre-migration rows carry nsegs=0 until the backfill
        // converges).
        let total: i64 = self
            .db
            .prepare_cached(
                "SELECT COALESCE(SUM(CASE WHEN nsegs > 0 THEN nsegs
                          ELSE COALESCE(seg_count(segments), 0) END), 0)
                   FROM files WHERE release_id=?1",
            )?
            .query_row([release_id], |r| r.get(0))?;
        let total = total.max(0) as usize;
        if total == 0 {
            return Ok(Vec::new());
        }
        // Even spread over the whole release - head-only sampling would
        // miss partial takedowns of the tail. Walked file by file in the
        // same `ORDER BY filename` order, so the sample is the one the
        // materialising version drew; only one file's segment list is
        // ever held at a time, and a stored count that disagrees with
        // what parses just yields fewer ids ("up to `max`").
        let step = (total as f64 / max.min(total) as f64).max(1.0);
        let mut out = Vec::with_capacity(max.min(total));
        let mut stmt = self
            .db
            .prepare_cached("SELECT segments FROM files WHERE release_id=?1 ORDER BY filename")?;
        let mut rows = stmt.query([release_id])?;
        // `base` is the global index of this file's first segment; `at`
        // the next sampling position, both in that same global space.
        let mut base = 0usize;
        let mut at = 0.0f64;
        while let Some(row) = rows.next()? {
            if out.len() >= max {
                break;
            }
            let parsed = row.get::<_, SegList>(0)?.0;
            while out.len() < max && (at as usize) < base + parsed.len() {
                let id = &parsed[(at as usize).saturating_sub(base)].1;
                out.push(if id.starts_with('<') {
                    id.clone()
                } else {
                    format!("<{id}>")
                });
                at += step;
            }
            base += parsed.len();
        }
        Ok(out)
    }

    /// Backtest sampler (M29 scoreboard): up to `want` releases posted
    /// inside the half-open window `[lo, hi)`, junk-gated exactly like
    /// [`Index::oracle_pick`] so the scoreboard scores the same
    /// population routing decisions are made about.
    ///
    /// Draws by seeking to pseudo-random instants in the window rather
    /// than sorting the table: `oracle_pick`'s `ORDER BY` is fine over
    /// a fresh index and ruinous over a real one (a long-running
    /// install reaches 32M rows / 42 GB, and this tool reads it while
    /// the daemon is serving from it).
    /// Each draw is one `idx_rel_posted` range seek, taking up to three
    /// consecutive matches so twelve releases cost four seeks, not
    /// twelve. Those three are neighbours in posting time, which is the
    /// price of the cheap seek; they are still distinct postings, which
    /// is what the scoreboard needs.
    ///
    /// The sample is uniform over POSTING TIME, not over rows: an hour
    /// that carried 900 posts is as likely to be drawn from as an hour
    /// that carried 9. That is the honest bias to have here - it
    /// spreads the sample across the bucket's whole age range instead
    /// of concentrating it in whichever hours the scanner ingested most
    /// heavily - but it is a bias, and a caller comparing rates across
    /// cells should know it exists.
    ///
    /// `grp_like` is an optional SQL LIKE narrowing on the group name
    /// (`%hdtv%`); it is a prefilter only, callers still have to check
    /// the exact family, because no index covers `grp` and a group
    /// family is not a substring match. It is also why `budget` exists:
    /// when the window holds no rows of that family at all, every seek
    /// scans the window to its end before answering nothing (measured
    /// at 2.8 s for one 23-day window), so the draw loop is bounded by
    /// wall clock, not only by attempts. Returning a short sample is
    /// correct here; the caller reports what it got.
    ///
    /// Returns (id, group, first_posted), ids distinct, oldest first.
    pub fn oracle_backtest_pick(
        &self,
        lo: i64,
        hi: i64,
        grp_like: Option<&str>,
        seed: u64,
        want: usize,
        budget: std::time::Duration,
    ) -> rusqlite::Result<Vec<(i64, String, i64)>> {
        if want == 0 || hi <= lo {
            return Ok(Vec::new());
        }
        /// Matches taken per seek - see the clustering note above.
        const PER_SEEK: usize = 3;
        let like = grp_like.unwrap_or("%");
        // Next releases at or after an instant, then (when the draw
        // landed past the last match) the nearest ones before it, so
        // instants near the top of the window are not wasted draws.
        let mut fwd = self.db.prepare(
            "SELECT id, grp, first_posted FROM releases
             WHERE first_posted >= ?1 AND first_posted < ?2
               AND junk < 50 AND grp LIKE ?3
             ORDER BY first_posted LIMIT ?4",
        )?;
        let mut back = self.db.prepare(
            "SELECT id, grp, first_posted FROM releases
             WHERE first_posted >= ?1 AND first_posted < ?2
               AND junk < 50 AND grp LIKE ?3
             ORDER BY first_posted DESC LIMIT ?4",
        )?;
        let mut out: Vec<(i64, String, i64)> = Vec::new();
        let mut seen: std::collections::HashSet<i64> = Default::default();
        let span = (hi - lo) as u64;
        let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
        // `checked_add`, because `budget` is whatever the caller was
        // handed: `nzbfast oracle-backtest --sample-secs` takes any u64,
        // and a bare `Instant::now() + Duration::from_secs(u64::MAX)`
        // panics with "overflow when adding duration to instant" instead
        // of returning a sample. None means "no time bound", which is
        // the honest reading of a budget that large - the loop is still
        // bounded by `seeks` below, so it always terminates.
        let deadline = std::time::Instant::now().checked_add(budget);
        let seeks = want.div_ceil(PER_SEEK).saturating_mul(3).clamp(4, 64);
        for _ in 0..seeks {
            if out.len() >= want || deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                break;
            }
            // SplitMix64 - a named, reproducible generator, so a
            // scoreboard run can be replayed against the same releases.
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let t = lo + (z % span.max(1)) as i64;
            let rows = |st: &mut rusqlite::Statement<'_>, a: i64, b: i64| {
                st.query_map(rusqlite::params![a, b, like, PER_SEEK as i64], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })
                .and_then(|m| m.collect::<rusqlite::Result<Vec<_>>>())
                .unwrap_or_default()
            };
            let mut hit = rows(&mut fwd, t, hi);
            if hit.is_empty() {
                hit = rows(&mut back, lo, t);
            }
            for row in hit {
                if out.len() >= want {
                    break;
                }
                if seen.insert(row.0) {
                    out.push(row);
                }
            }
        }
        out.sort_by_key(|r| r.2);
        Ok(out)
    }

    /// Stamp a release as sampled now (rotates the pick order).
    pub fn oracle_mark(&self, release_id: i64, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE releases SET oracle_at=?2 WHERE id=?1",
            rusqlite::params![release_id, now],
        )?;
        Ok(())
    }

    /// A8 targeted gap-fill: incomplete releases worth re-hunting on the
    /// other backbones, least-recently-tried first (gapfill_at 0 =
    /// never). Junk-gated like the sampler - the endless obfuscated
    /// stream must not eat the budget users could see spent on real
    /// cards. Releases first seen in the last hour are skipped: their
    /// missing parts are usually still propagating (or still uploading),
    /// and the next tip pass gets them for free.
    /// Returns (id, group, first_posted).
    pub fn gapfill_pick(&self, limit: u32, now: i64) -> rusqlite::Result<Vec<(i64, String, i64)>> {
        // Pinned form first, unpinned for a pre-backfill database -
        // see probe7z_pick.
        let mut stmt = match self.db.prepare(&gapfill_pick_sql()) {
            Ok(s) => s,
            Err(_) => self.db.prepare(&gapfill_pick_sql_unpinned())?,
        };
        let rows = stmt.query_map(rusqlite::params![limit, now - 3600], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
        rows.collect()
    }

    /// Stamp a release as gap-fill-tried now (rotates the pick order).
    pub fn gapfill_mark(&self, release_id: i64, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE releases SET gapfill_at=?2 WHERE id=?1",
            rusqlite::params![release_id, now],
        )?;
        Ok(())
    }

    /// Is this release complete? (gap-fill measures its own success by
    /// the flip.)
    pub fn is_complete(&self, release_id: i64) -> bool {
        self.db
            .query_row(
                "SELECT complete FROM releases WHERE id=?1",
                [release_id],
                |r| r.get(0),
            )
            .unwrap_or(false)
    }

    /// Tiny persisted key/value pairs (dataset refresh stamps and such).
    pub fn kv_get(&self, k: &str) -> Option<String> {
        self.db
            .query_row("SELECT v FROM kv WHERE k=?1", [k], |r| r.get(0))
            .ok()
    }

    pub fn kv_set(&self, k: &str, v: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO kv(k, v) VALUES(?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            [k, v],
        )?;
        Ok(())
    }

    /// Replace the whole IMDb ratings snapshot (nightly dataset ingest).
    /// One transaction; returns rows kept.
    pub fn imdb_ratings_replace(
        &mut self,
        rows: impl Iterator<Item = (String, f64, u64)>,
    ) -> rusqlite::Result<u64> {
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM imdb_ratings", [])?;
        let mut n = 0u64;
        {
            let mut ins =
                tx.prepare("INSERT INTO imdb_ratings(tconst, rating, votes) VALUES(?1, ?2, ?3)")?;
            for (t, r, v) in rows {
                ins.execute(rusqlite::params![t, r, v as i64])?;
                n += 1;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// (rating, votes) for an IMDb tconst, if the snapshot holds it.
    pub fn imdb_rating(&self, tconst: &str) -> Option<(f64, u64)> {
        self.db
            .query_row(
                "SELECT rating, votes FROM imdb_ratings WHERE tconst=?1",
                [tconst],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)),
            )
            .ok()
    }

    /// Install an ingest gate (see the `gate` field).
    pub fn set_gate(&mut self, gate: Box<dyn Fn(&str) -> bool + Send>) {
        self.gate = Some(gate);
    }

    /// Install the user's custom categories (see the `custom` field).
    pub fn set_custom(&mut self, cats: Vec<crate::categories::CustomCategory>) {
        self.custom = cats;
    }

    /// Install the arrival watch (see the `watch` field): a cheap
    /// name test the index runs over every release a batch touches, so
    /// the caller learns about the ones it cares about AS THEY LAND
    /// rather than by re-scanning the table on a timer.
    ///
    /// The predicate must be cheap and permissive - it runs once per
    /// touched release inside the ingest transaction, and its only job is
    /// to keep the journal short. Saying yes too often costs a wasted
    /// look; saying no wrongly loses the arrival entirely.
    pub fn set_watch_names(&mut self, watch: Option<Box<dyn Fn(&str) -> bool + Send>>) {
        self.watch = watch;
        if self.watch.is_none() {
            *self.hits.borrow_mut() = Default::default();
        }
    }

    /// Take everything the arrival watch has collected since the last
    /// call, plus how many hits were dropped for want of room.
    pub fn take_watch_hits(&self) -> (Vec<WatchHit>, u32) {
        let mut h = self.hits.borrow_mut();
        (std::mem::take(&mut h.list), std::mem::take(&mut h.dropped))
    }

    /// True once, right after this connection ran runtime DDL (see the
    /// `ddl` field). The daemon reads it after the write that could have
    /// built the named-feed index and retires its read-only pool on
    /// true - the one freshness event WAL visibility does not cover is
    /// a schema change a pooled statement was prepared before.
    pub fn take_schema_ddl(&self) -> bool {
        self.ddl.replace(false)
    }

    /// Offer one touched release to the arrival watch. Costs a null check
    /// when nothing is installed, which is every install that has no
    /// watchlist.
    fn note_watch(&self, id: i64, name: &str, complete: bool) {
        let Some(watch) = &self.watch else { return };
        if watch(name) {
            self.push_watch_hit(WatchHit {
                id,
                name: name.to_string(),
                complete,
            });
        }
    }

    /// Journal a hit the predicate has already accepted, dropping it (and
    /// counting the drop) once the journal is full.
    fn push_watch_hit(&self, hit: WatchHit) {
        let mut h = self.hits.borrow_mut();
        if h.list.len() >= WATCH_HITS_CAP {
            h.dropped = h.dropped.saturating_add(1);
            return;
        }
        h.list.push(hit);
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{entry, teardown};
    use super::*;

    const DAY_SECS: i64 = 86_400;

    /// The probe sampler draws the SAME spread it always did, and does
    /// it without building the release's whole message-id list first -
    /// a 50 GB pack is hundreds of thousands of ids for a dozen STATs.
    /// Covers the three shapes the walk has to survive: a stored
    /// `nsegs`, a pre-migration row still carrying 0, and ids that
    /// arrive already bracketed.
    #[test]
    fn oracle_msgids_spreads_across_files_without_listing_them_all() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-msgids-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, files, complete, first_posted,
                                      first_seen)
                 VALUES('Big.Pack','p@x','alt.binaries.misc',3,1,50,50)",
                [],
            )
            .unwrap();
        let rid = ix.db.last_insert_rowid();
        // Uneven files, so a per-file quota that ignored the global
        // position would drift off the reference spread.
        let files: [(&str, usize, i64, bool); 3] = [
            ("a.part1.rar", 40, 40, false),
            ("b.part2.rar", 7, 0, false), // pre-migration: nsegs still 0
            ("c.part3.rar", 13, 13, true), // already bracketed
        ];
        let mut all: Vec<String> = Vec::new();
        for (fi, (name, n, nsegs, bracketed)) in files.iter().enumerate() {
            let ids: Vec<String> = (0..*n)
                .map(|i| {
                    if *bracketed {
                        format!("<seg-{fi}-{i}@news>")
                    } else {
                        format!("seg-{fi}-{i}@news")
                    }
                })
                .collect();
            let segs = format!(
                "[{}]",
                ids.iter()
                    .enumerate()
                    .map(|(i, id)| format!("[{},{},500]", i + 1, serde_json::json!(id)))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            all.extend(ids);
            ix.db
                .execute(
                    "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                     VALUES(?1, ?2, ?3, 500, ?4, ?5)",
                    rusqlite::params![rid, name, *n as i64, segs, nsegs],
                )
                .unwrap();
        }

        // The reference: what the materialising sampler produced.
        let reference = |want: usize| -> Vec<String> {
            if want == 0 || all.is_empty() {
                return Vec::new();
            }
            let step = (all.len() as f64 / want.min(all.len()) as f64).max(1.0);
            let mut out = Vec::new();
            let mut at = 0.0f64;
            while (at as usize) < all.len() && out.len() < want {
                let id = &all[at as usize];
                out.push(if id.starts_with('<') {
                    id.clone()
                } else {
                    format!("<{id}>")
                });
                at += step;
            }
            out
        };

        for want in [1usize, 9, 12, 60] {
            assert_eq!(
                ix.oracle_msgids(rid, want).unwrap(),
                reference(want),
                "the sample moved at max={want}"
            );
        }
        // A budget of nothing asks for nothing; an unknown release has
        // nothing to sample.
        assert!(ix.oracle_msgids(rid, 0).unwrap().is_empty());
        assert!(ix.oracle_msgids(rid + 999, 8).unwrap().is_empty());
        // The spread reaches the tail - a takedown of the last file is
        // exactly what head-only sampling would miss.
        let ids = ix.oracle_msgids(rid, 9).unwrap();
        assert!(
            ids.iter().any(|i| i.starts_with("<seg-2-")),
            "no probe landed in the last file: {ids:?}"
        );
        teardown(&dir, ix);
    }

    /// `--sample-secs` is a bare `u64` on the CLI, so the draw budget
    /// arrives here unbounded. Building the deadline with a plain
    /// `Instant::now() + budget` panicked with "overflow when adding
    /// duration to instant" on the absurd end of that range, aborting
    /// `nzbfast oracle-backtest` instead of returning a sample. An
    /// un-representable budget means "no time bound"; the seek count
    /// still bounds the loop.
    #[test]
    fn backtest_pick_survives_an_unrepresentable_budget() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-index-backtest-budget-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let base: i64 = 1_700_000_000;
        ix.ingest(
            "alt.binaries.teevee",
            &[
                entry(
                    "\"Budget.Show.S01E01.1080p-A.mkv\" yEnc (1/1)",
                    "a@a",
                    "b1",
                    4 << 30,
                ),
                entry(
                    "\"Budget.Show.S01E02.1080p-A.mkv\" yEnc (1/1)",
                    "a@a",
                    "b2",
                    4 << 30,
                ),
            ],
            base,
        )
        .unwrap();

        let got = ix
            .oracle_backtest_pick(
                base - DAY_SECS,
                base + DAY_SECS,
                None,
                1,
                4,
                std::time::Duration::from_secs(u64::MAX),
            )
            .unwrap();
        // Non-empty keeps this from passing vacuously if an early-out
        // above the deadline is ever widened: the point is that the
        // call returns at all, having actually reached the draw loop.
        assert!(!got.is_empty(), "the draw loop never ran");
        teardown(&dir, ix);
    }
}
