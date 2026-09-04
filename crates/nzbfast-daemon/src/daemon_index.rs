//! `Daemon`'s index-handle and index-size-cap methods (TODO 106 code motion
//! out of daemon.rs).
//!
//! Two groups that only ever get read together: the M34 size cap (the
//! recently-opened log, the protected set, the eviction passes and the taste
//! profile that ranks what may go) and the handle discipline that every one
//! of them goes through - `with_index` for writers, the read-connection pool
//! for interactive handlers, and the era stamp that makes a wipe safe.
//!
//! A second `impl Daemon` in a child module of `daemon`, so `Daemon`'s
//! private fields and daemon.rs's private types (`LadderPermit`,
//! `OpenedLog`) stay in scope exactly as they were inline.
//!
//! The pool's own types - `IndexReadPool`, `IndexReadState`,
//! `IndexReader` and the `Reader` verdict - are declared HERE rather
//! than in daemon.rs (25 Aug 2026). `index_read_acquire` below is the
//! only code in the tree that constructs any of them, so keeping them
//! next to it makes them module-private instead of daemon-private.
//! `IndexReadPool` alone is re-exported from daemon.rs, because
//! `Daemon`'s field is typed on it.

use super::*;

/// The index space ledger: when the database was last compacted and what
/// that handed back, plus how much eviction has removed over the life of
/// the FILE. Two facts the space readout was designed around and which
/// nothing recorded - a user could see the cap, the file size and the
/// free pages inside it, but not whether the reclaim had ever run or
/// what the cap had cost them so far.
///
/// Kept in two places on purpose. It is mirrored in `Daemon` so the
/// stats poll can read it without touching the index mutex (TODO 166 -
/// that poll runs every couple of seconds on every open dashboard), and
/// persisted in the index's own `kv` so a restart does not answer "never
/// compacted" about a file that was compacted last night. The database
/// outlives the process, so facts about the database have to as well.
///
/// `evicted_bytes` is the LIVE-bytes delta, not the file delta: deleting
/// rows hands pages to the freelist without shortening the file, so the
/// file delta of an eviction is zero and would report every trim as
/// having saved nothing.
#[cfg(feature = "indexer")]
#[derive(Default, Clone, Copy)]
pub struct IndexLedger {
    /// Has the persisted half been read back yet? False until the
    /// maintenance loop's first successful `sync_index_ledger`.
    pub loaded: bool,
    /// Something happened that has not reached the database yet.
    pub dirty: bool,
    /// Unix seconds of the last completed compaction, or None if this
    /// database has never had one.
    pub last_compact_at: Option<i64>,
    /// Bytes that compaction returned to the volume. Can legitimately be
    /// 0 for a compaction that found nothing to reclaim.
    pub last_compact_freed: u64,
    /// Releases eviction has removed, all passes, all runs.
    pub evicted_rows: u64,
    /// Live bytes those removals freed inside the file.
    pub evicted_bytes: u64,
}

#[cfg(feature = "indexer")]
impl IndexLedger {
    /// One key per fact rather than a blob: these are read by hand when
    /// a user's index is being diagnosed, and a half-written blob would
    /// lose all four where a missing key loses one.
    const K_AT: &'static str = "idxspace_last_compact_at";
    const K_FREED: &'static str = "idxspace_last_compact_freed";
    const K_ROWS: &'static str = "idxspace_evicted_rows";
    const K_BYTES: &'static str = "idxspace_evicted_bytes";

    /// Whatever the database has. An unreadable or unparseable key is
    /// simply absent - a ledger is a narration, and refusing to answer
    /// the whole card over one bad row would be the wrong trade.
    fn read(ix: &nzbkit::index::Index) -> Self {
        let n = |k: &str| ix.kv_get(k).and_then(|v| v.parse::<u64>().ok());
        Self {
            loaded: true,
            dirty: false,
            last_compact_at: ix.kv_get(Self::K_AT).and_then(|v| v.parse::<i64>().ok()),
            last_compact_freed: n(Self::K_FREED).unwrap_or(0),
            evicted_rows: n(Self::K_ROWS).unwrap_or(0),
            evicted_bytes: n(Self::K_BYTES).unwrap_or(0),
        }
    }

    fn write(&self, ix: &nzbkit::index::Index) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(at) = self.last_compact_at {
            ix.kv_set(Self::K_AT, &at.to_string())?;
            ix.kv_set(Self::K_FREED, &self.last_compact_freed.to_string())?;
        }
        ix.kv_set(Self::K_ROWS, &self.evicted_rows.to_string())?;
        ix.kv_set(Self::K_BYTES, &self.evicted_bytes.to_string())?;
        Ok(())
    }
}

/// Why a pooled read could not produce a trustworthy answer. The name is
/// about the CALLER's options rather than the cause: either way the
/// honest reply is "not right now, ask again", and every endpoint
/// handles both the same - keep what is on screen and let the next poll
/// get the real answer. Drawing either as an empty result is how a
/// working index comes to be reported as a broken one.
#[cfg(feature = "indexer")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexBusy {
    /// Every read connection is in use. Nothing failed in the database
    /// sense - the answer just is not available cheaply right now.
    Saturated,
    /// The query failed with SQLITE_SCHEMA and was still failing after
    /// re-preparing: a writer changed the schema under this reader and
    /// the fts5 constructor lost the race twice. Something DID fail,
    /// which is exactly why it must not be flattened into "no rows" -
    /// see `nzbkit::index::Index::schema_faults`.
    SchemaChanged,
    /// The query outran the read budget and was abandoned so the
    /// connection could go back to the pool (TODO 300). Unlike the two
    /// above, this one is a property of the REQUEST rather than of the
    /// moment: asking again runs the same plan over the same rows and
    /// takes the same time, so the message must not say "try again".
    /// See `serve::daemon::index_read_budget`.
    TooSlow,
}

#[cfg(feature = "indexer")]
impl IndexBusy {
    /// What to tell the user. The first two are transient and ask for
    /// the same thing, so they differ only in naming the cause - which
    /// is what makes a schema fault greppable in a support report rather
    /// than indistinguishable from a busy pool. The third is not
    /// transient and says something else entirely.
    pub fn message(self) -> &'static str {
        match self {
            Self::Saturated => "the index is busy - try again in a moment",
            Self::SchemaChanged => "the index schema changed mid-query - try again in a moment",
            // Deliberately says nothing about the wall's own controls,
            // though the wall is what provoked it: this seam also
            // answers search, browse and the *arr-facing newznab
            // facade, and "leave the matched-only toggle on" is not
            // advice Sonarr can take. What is true everywhere is that
            // the ask was too wide.
            Self::TooSlow => {
                "that is too much of the index to search at once - \
                 narrow it with a filter or a search term"
            }
        }
    }

    /// The JSON body every API handler answers a refusal with.
    ///
    /// ONE COPY, because the `busy` flag is the only thing that tells a
    /// caller "the ask was fine, the moment was not" from "the ask was
    /// wrong", and hand-written refusal bodies had already lost it
    /// everywhere it was not a read. Measured 3 Sep 2026 over
    /// `api/wall.rs`, `api/index.rs` and `api/index/pull.rs`: every
    /// READ refusal carried `busy`, and every WRITE refusal carried
    /// only `{"status": false, "error": <message>}` - the same shape
    /// `m_wall_art` answers an unknown title key with. A client could
    /// separate them only by matching the message text, which is prose
    /// nobody promised to keep.
    ///
    /// A refused write is safe to repeat by construction and that is
    /// why the flag belongs on it: `index_write_checked`'s `Err` means
    /// the mutex was never taken, so nothing was written (see its own
    /// doc - "the edit did NOT happen"). Retrying it is the click the
    /// user would make.
    ///
    /// `TooSlow` carries the flag too, matching what the read handlers
    /// have always sent. It is not transient and its message says so;
    /// the flag says "this is the index seam refusing", which is true
    /// of all three, and a caller that retries it learns the same thing
    /// in the same words rather than reading a narrowed search as an
    /// empty one.
    ///
    /// Caller-specific fields are added to the returned object rather
    /// than to a second literal - see `m_debug_slow_index_read`, which
    /// stamps its own `ms`.
    pub fn refusal(self) -> serde_json::Value {
        serde_json::json!({
            "status": false,
            "busy": true,
            "error": self.message(),
        })
    }
}

/// How long a query may run on a borrowed read connection before it is
/// abandoned and the caller told so (TODO 300).
///
/// It sits beside `INDEX_READ_CONNS` and `INDEX_READ_WAIT` below, which
/// is where a reader looks for it first. It did not always: this went
/// to the module that USES it because `daemon.rs` was size-gate
/// BASELINED and two lanes' growth landed that file 11 lines over on
/// 25 Aug 2026, and the pool followed it here the same day. That
/// baseline entry is gone (deleted later the same day, after six
/// splits) and the file is held to the flat ceiling now, so do not read
/// this as a live constraint. Nothing
/// about the three is a daemon.rs subject - they are the read path's
/// own dimensions, and the only code that reads any of them is
/// `index_read_acquire`, forty lines further down.
///
/// `INDEX_READ_WAIT` bounds the QUEUE for a connection; this bounds the
/// query already inside. Nothing did, and that is the hole
/// `matched=0&all=1` on the wall falls through: measured 25 Aug 2026 on
/// the live 50 GB index, the default wall answers a card page in
/// 0.7-1.2 s and show-all takes 57.8 s warm and over 120 s cold, because
/// dropping `junk < 50` takes the plan off a partial index over 65k visible
/// releases and onto all 33.4M. Four of those pin every connection and
/// the daemon stops answering - which is the 2 Aug wedge, arriving
/// through the wall rather than through a lock. `nzbkit::index::deadline`
/// carries the measurement and the mechanism.
///
/// 20 s, which is ~20x the slowest healthy page and far under every
/// measured broken one. It is not a latency target: nobody watches a
/// wall for twenty seconds, and a request that reaches this has already
/// disappointed whoever made it. It is the promise that the connection
/// comes BACK. `NZBFAST_INDEX_READ_BUDGET_SECS` overrides it for a box
/// where cold reads are genuinely slower (a NAS, a spinning volume), and
/// 0 restores the old unbounded behaviour.
#[cfg(feature = "indexer")]
pub(super) fn index_read_budget() -> Option<std::time::Duration> {
    static BUDGET: std::sync::OnceLock<Option<std::time::Duration>> = std::sync::OnceLock::new();
    *BUDGET.get_or_init(|| {
        let secs = std::env::var("NZBFAST_INDEX_READ_BUDGET_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(20);
        (secs > 0).then(|| std::time::Duration::from_secs(secs))
    })
}

/// How many index reads may be in flight at once.
///
/// The point is the gap between this and the HTTP worker count (8): a
/// query surface that has gone slow can occupy at most this many
/// workers, so `/`, `mode=version`, the queue and the *arr endpoints
/// keep answering out of the remainder no matter what the index is
/// doing. WAL readers run concurrently, so these are real parallelism
/// as well as a ceiling - the single shared read connection they
/// replace serialized every query handler behind whichever one was
/// slowest.
#[cfg(feature = "indexer")]
pub(super) const INDEX_READ_CONNS: usize = 4;

/// How long a request may wait for a free read connection before it is
/// told the index is busy.
///
/// A healthy read against this database is sub-millisecond, so this is
/// two orders of magnitude of headroom for an ordinary burst - and a
/// hard promise that a saturated index costs an HTTP worker a tenth of
/// a second rather than however long the slowest query runs.
#[cfg(feature = "indexer")]
pub(super) const INDEX_READ_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

/// The read-only connection pool behind [`Daemon::with_index_read`].
///
/// Deliberately hand-rolled rather than a channel: `drop_index_read`
/// has to invalidate connections that are LENT OUT right now (index_wipe
/// deletes the file under them), which the generation stamp does without
/// waiting for their queries to end.
#[cfg(feature = "indexer")]
#[derive(Default)]
pub struct IndexReadPool {
    // `pub(super)`, not private, and only because this module is no
    // longer the file the pool was declared in: a handback test in
    // `daemon_tests` reads the generation stamp directly to prove a
    // schema-changing batch retires the warm readers. That reach is
    // what these had inline in daemon.rs, so this restores it rather
    // than widening it - `super` here is `daemon`, and every daemon
    // child could always see them.
    pub inner: Mutex<IndexReadState>,
    /// Signalled every time a connection is handed back.
    pub handed_back: std::sync::Condvar,
}

#[cfg(feature = "indexer")]
#[derive(Default)]
pub struct IndexReadState {
    /// Open connections nobody is using.
    pub idle: Vec<nzbkit::index::Index>,
    /// How many exist at all - idle plus lent out. The ceiling is
    /// [`INDEX_READ_CONNS`].
    pub live: usize,
    /// Bumped by `drop_index_read`. A connection handed back carrying an
    /// older stamp is closed instead of pooled, so a handle opened
    /// against a since-deleted database can never be served from again.
    pub generation: u64,
}

/// A borrowed read-only connection, returned to the pool on drop - including
/// on the unwind out of a panicking handler, which is why this is a guard and
/// not a matched pair of calls. A leaked connection would shrink the pool by
/// one permanently, and four panics would close the read path for good.
#[cfg(feature = "indexer")]
pub(super) struct IndexReader<'a> {
    pool: &'a IndexReadPool,
    /// `Some` until dropped.
    conn: Option<nzbkit::index::Index>,
    generation: u64,
}

#[cfg(feature = "indexer")]
impl std::ops::Deref for IndexReader<'_> {
    type Target = nzbkit::index::Index;
    fn deref(&self) -> &Self::Target {
        // Some until Drop runs, and Drop is the only thing that takes it.
        self.conn.as_ref().expect("reader used after drop")
    }
}

#[cfg(feature = "indexer")]
impl Drop for IndexReader<'_> {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else { return };
        // Here rather than beside the arm, for the reason this is a
        // guard at all: a stamp left on a pooled connection is measured
        // against the NEXT borrower's query, and it is already in the
        // past, so that query would be abandoned before it did anything.
        // The unwind out of a panicking handler must clear it too.
        conn.set_query_deadline(None);
        let mut st = self.pool.inner.lock_ok();
        if self.generation == st.generation {
            st.idle.push(conn);
        } else {
            // Retired mid-query. Closing it here is what keeps `live`
            // honest; the drop happens under the lock, which is a
            // sqlite3_close on an idle connection.
            st.live = st.live.saturating_sub(1);
            drop(conn);
        }
        drop(st);
        self.pool.handed_back.notify_one();
    }
}

/// What [`Daemon::index_read_acquire`] could do for the caller.
#[cfg(feature = "indexer")]
enum Reader<'a> {
    Got(IndexReader<'a>),
    /// Every connection is in use and none came free in time. The caller
    /// must NOT fall back to the read-write handle: parking on that mutex
    /// is the exact failure this path exists to prevent.
    Busy,
    /// No read-only connection could be opened at all (no database file
    /// yet). Startup-shaped, and the caller falls back to `with_index`.
    Unavailable,
}

/// The bound on `index_read_checked`'s pre-migration fallback to the
/// write mutex (TODO 143). Whoever holds that mutex while
/// `index_migrated` is still false is opening the database and running
/// its migrations, so this only has to cover an open - it is not the
/// budget for waiting out an ingest, which is precisely what this path
/// refuses to do.
#[cfg(feature = "indexer")]
const PREMIGRATION_INDEX_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

impl Daemon {
    // -- M34 index size cap ------------------------------------------------

    /// Where the "recently opened" touch log lives (spool, beside the
    /// watchlist state - same lifecycle, same crash-safe writer).
    #[cfg(feature = "indexer")]
    pub(crate) fn opened_path(&self) -> PathBuf {
        self.spool.join("index-opened.json")
    }

    /// Note that the user opened a card's detail sheet.
    #[cfg(feature = "indexer")]
    pub fn touch_opened_title(&self, title_key: &str) {
        let now = epoch_secs() as i64;
        let dirty = self.index_opened.lock_ok().touch_title(title_key, now);
        if dirty {
            self.save_opened();
        }
    }

    /// Note that the user pulled an indexed release - /getnzb, or
    /// queueing it from the wall.
    #[cfg(feature = "indexer")]
    pub fn touch_opened_release(&self, id: i64) {
        let now = epoch_secs() as i64;
        let dirty = self.index_opened.lock_ok().touch_release(id, now);
        if dirty {
            self.save_opened();
        }
    }

    #[cfg(feature = "indexer")]
    pub(crate) fn save_opened(&self) {
        let now = epoch_secs() as i64;
        let snapshot = {
            let mut log = self.index_opened.lock_ok();
            log.expire(now, OPENED_PROTECT_DAYS * 86_400);
            log.clone()
        };
        if let Ok(text) = serde_json::to_string(&snapshot) {
            let _ = crate::persist::write_atomic(&self.opened_path(), text.as_bytes());
        }
    }

    /// The eviction policy the current settings describe. An
    /// unrecognised order can only get here through a hand-edited
    /// settings.json (`apply_setting` validates), and falls back to the
    /// default rather than refusing to run.
    #[cfg(feature = "indexer")]
    pub(crate) fn evict_policy(&self) -> nzbkit::index::EvictPolicy {
        let order_s = self.index_evict_order.lock_ok().clone();
        let scope_s = self.index_evict_scope.lock_ok().clone();
        nzbkit::index::EvictPolicy {
            order: parse_evict_order(&order_s).unwrap_or(nzbkit::index::EvictOrder::Ladder),
            kinds: self.index_evict_kinds.lock_ok().clone(),
            keep_kinds: self.index_keep_kinds.lock_ok().clone(),
            scope: parse_evict_scope(&scope_s).unwrap_or_default(),
            // Always explicit: the setting defaults to the engine's own
            // 10 and the setter clamps to 0..=50, so the min here only
            // guards a hand-edited settings.json.
            headroom_pct: Some(self.index_evict_headroom.load(Ordering::Relaxed).min(50) as u32),
        }
    }

    /// Everything the size cap must not touch. All four protections the
    /// user asked for:
    ///
    ///  1. watchlisted titles - the shows and films they told us to keep
    ///     hunting for; evicting those rows makes the watcher blind;
    ///  2. anything queued or downloading right now;
    ///  3. anything already downloaded (completed history) - same
    ///     title_key set the wall's "you have this" badge is built from;
    ///  4. anything opened, fetched or queued in the last
    ///     `OPENED_PROTECT_DAYS` days.
    ///
    /// Cost is one clone of the queue/history/watchlist name lists, one
    /// pass over the touch log, and - for watchlist films with no pinned
    /// year, and for every custom-category entry - one card query each to
    /// resolve the keys the index actually holds. It is called at most
    /// once per eviction pass.
    ///
    /// `None` = the set could not be FULLY assembled (index unavailable
    /// or a resolver query failed). The caller must treat that as "do
    /// not evict", never as an empty set: a transient SQLITE_BUSY here
    /// used to shrink the protected set silently, and evict_to then
    /// deleted watchlisted releases irreversibly.
    #[cfg(feature = "indexer")]
    pub fn protected_set(&self) -> Option<nzbkit::index::Protected> {
        // §151: a synced title is watched, so the size cap must not
        // evict what it is waiting for either.
        let items = self.watch_items();
        let mut watchlisted: Vec<String> = Vec::new();
        for item in &items {
            // Disabled items still count: switching a show off is not
            // the same as saying "throw away what you found".
            watchlisted.extend(watch_item_keys(item));
        }
        // An empty-title custom item deliberately means "watch the whole
        // category". It has no single identity key, so enumerate every
        // classified key instead of letting the empty title fall out of
        // the per-title resolver below.
        let whole_custom: Vec<String> = items
            .iter()
            .filter(|i| {
                nzbfast_meta::watchlist::is_custom_kind(&i.kind)
                    && nzbkit::release::norm_title(&i.title).is_empty()
            })
            .map(|i| i.kind.clone())
            .collect();
        if !whole_custom.is_empty() {
            // A failed resolver query fails the WHOLE assembly: dropping
            // just this category's keys would hand evict_to a set that
            // no longer protects it.
            // index-lock-gate: TODO 166 - assembling the protected set is
            // part of the evict/shrink/preview admin actions, and its only
            // callers are `evict_to`, `evict_preview_at` and the background
            // maintenance pass. The user asked for the work; waiting for it
            // is the honest answer.
            self.with_index(|ix| {
                for kind in &whole_custom {
                    match ix.title_keys_for_kind(kind) {
                        Ok(keys) => watchlisted.extend(keys),
                        Err(_) => return None,
                    }
                }
                Some(())
            })?;
        }
        // A film watchlisted without a year matches every year the index
        // holds under that title (that is exactly what the watcher does
        // when it matches), so ask the index which those are instead of
        // guessing. Bounded work: only year-less film entries, one FTS
        // card query each, capped page.
        //
        // A custom-category entry needs the same treatment for the same
        // reason, and always: its releases key on
        // "c:<slug>:<title>:<year>:<identity tail>", which the entry
        // alone cannot spell. Query per (kind, title) pair either way.
        let yearless: Vec<(String, String)> = items
            .iter()
            .filter(|i| {
                nzbfast_meta::watchlist::is_custom_kind(&i.kind)
                    || (i.kind != "tv" && i.year.is_none())
            })
            .map(|i| {
                let kind = if nzbfast_meta::watchlist::is_custom_kind(&i.kind) {
                    i.kind.clone()
                } else {
                    "movie".into()
                };
                (kind, nzbkit::release::norm_title(&i.title))
            })
            .filter(|(_, n)| !n.is_empty())
            .collect();
        if !yearless.is_empty() {
            // index-lock-gate: TODO 166 - the other half of the same
            // protected-set assembly. See the note above.
            self.with_index(|ix| {
                for (kind, norm) in &yearless {
                    let q = nzbkit::index::BrowseQuery {
                        q: norm.clone(),
                        kind: Some(kind.clone()),
                        limit: 200,
                        curated: false,
                        ..Default::default()
                    };
                    // Err fails the whole assembly, same as above - a
                    // `continue` silently un-protected this title.
                    let Ok((cards, _)) = ix.browse_cards(
                        &q,
                        // "" parses to Latest - the sort is irrelevant,
                        // only the keys on the page matter.
                        nzbkit::index::CardSort::parse(""),
                        false,
                        false,
                        None,
                    ) else {
                        return None;
                    };
                    let prefix = if kind == "movie" {
                        format!("m:{norm}:")
                    } else {
                        format!("c:{kind}:{norm}")
                    };
                    for c in cards {
                        if c.title_key.starts_with(&prefix) {
                            watchlisted.push(c.title_key);
                        }
                    }
                }
                Some(())
            })?;
        }

        let now = epoch_secs() as i64;
        let window = OPENED_PROTECT_DAYS * 86_400;
        let (opened_titles, opened_releases) = {
            let log = self.index_opened.lock_ok();
            (
                log.titles
                    .iter()
                    .filter(|(_, t)| now - **t <= window)
                    .map(|(k, _)| k.clone())
                    .collect::<Vec<_>>(),
                log.releases
                    .iter()
                    .filter(|(_, t)| now - **t <= window)
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>(),
            )
        };
        Some(assemble_protected(
            watchlisted,
            // Queue + completed history, keyed the way the index groups
            // releases. Already the daemon's notion of "the user has, or
            // is getting, this".
            self.owned_title_keys().into_iter().collect(),
            opened_titles,
            opened_releases,
        ))
    }

    /// Record a completed compaction. Memory only - the trip to the
    /// database is `sync_index_ledger`, on the maintenance loop.
    ///
    /// Call this AFTER the index handle has been released. Everything
    /// in this pair takes the ledger mutex and then, later, the index
    /// mutex; taking them the other way round is the one thing that
    /// could invert the order.
    #[cfg(feature = "indexer")]
    pub fn note_compact(&self, freed: u64) {
        let mut g = self.index_ledger.lock_ok();
        g.last_compact_at = Some(unix_now());
        g.last_compact_freed = freed;
        g.dirty = true;
    }

    /// Record what an eviction pass removed. Cumulative over the life of
    /// the database, not of this process - see `IndexLedger`.
    #[cfg(feature = "indexer")]
    pub fn note_evicted(&self, rows: u64, bytes: u64) {
        if rows == 0 && bytes == 0 {
            return;
        }
        let mut g = self.index_ledger.lock_ok();
        g.evicted_rows = g.evicted_rows.saturating_add(rows);
        g.evicted_bytes = g.evicted_bytes.saturating_add(bytes);
        g.dirty = true;
    }

    /// The ledger as the stats poll should see it. A plain mutex read:
    /// no index handle, so this cannot park an HTTP worker behind a scan
    /// batch, which is the whole reason the facts are mirrored here.
    #[cfg(feature = "indexer")]
    pub fn index_ledger_snapshot(&self) -> IndexLedger {
        *self.index_ledger.lock_ok()
    }

    /// A wipe deletes the database, so every fact in the ledger is about
    /// a file that no longer exists. Reset rather than carry them over -
    /// "3.2M releases evicted" beside an empty index is the kind of
    /// number that makes a user distrust the whole card.
    #[cfg(feature = "indexer")]
    pub fn reset_index_ledger(&self) {
        *self.index_ledger.lock_ok() = IndexLedger {
            // The kv rows went with the file; nothing to read back.
            loaded: true,
            ..Default::default()
        };
    }

    /// The shutdown flush. `sync_index_ledger` runs once a minute, which
    /// is soon enough for a fact nobody is waiting on and too late for a
    /// daemon that stops inside that minute: a compaction stamp lost
    /// there is lost for good, and the card then says "it has not been
    /// compacted yet" about a file that has - permanently, not for a
    /// minute, because nothing raises the fact again until the NEXT
    /// compaction.
    ///
    /// BOUNDED, and it has to be. `wind_down` is reached from
    /// `mode=shutdown` and `mode=restart`, so this is on an HTTP path
    /// (TODO 166); and the exit cannot queue behind a whole ingest pass
    /// whatever door it uses - that is the hazard `close_index_for_exit`
    /// spends a try_lock timer avoiding one step later. So it is
    /// best-effort by construction: busy or unavailable means the record
    /// waits for the next run's loop, which is exactly where it was
    /// before this existed.
    #[cfg(feature = "indexer")]
    pub(crate) fn flush_index_ledger_for_exit(&self) {
        let out = {
            let mut g = self.index_ledger.lock_ok();
            if !g.dirty {
                return;
            }
            g.dirty = false;
            *g
        };
        if !matches!(
            self.index_write_checked(|ix| out.write(ix).ok()),
            Ok(Some(_))
        ) {
            self.index_ledger.lock_ok().dirty = true;
        }
    }

    /// The ledger's only trip to disk: load the persisted half once, then
    /// write back whatever this run has added.
    ///
    /// Rides the index maintenance loop because that is already the
    /// index's background tick, and it takes the index handle - which is
    /// exactly why no HTTP handler may call it (TODO 166). The stats poll
    /// reads `index_ledger_snapshot` instead.
    ///
    /// The load MERGES rather than overwrites: a compaction or an
    /// eviction can land before the first tick, and taking the stored
    /// totals wholesale would throw that away, while skipping the load
    /// would throw away everything before this restart.
    #[cfg(feature = "indexer")]
    pub fn sync_index_ledger(&self) {
        let snap = self.index_ledger_snapshot();
        if snap.loaded && !snap.dirty {
            return;
        }
        if !snap.loaded {
            // None = the database is not open (or not wanted) right now.
            // Leave `loaded` false and try again on the next tick: a
            // half-loaded ledger would then be written back over the
            // stored one.
            let Some(saved) = self.with_index(|ix| Some(IndexLedger::read(ix))) else {
                return;
            };
            let mut g = self.index_ledger.lock_ok();
            g.evicted_rows = g.evicted_rows.saturating_add(saved.evicted_rows);
            g.evicted_bytes = g.evicted_bytes.saturating_add(saved.evicted_bytes);
            if g.last_compact_at.is_none() {
                g.last_compact_at = saved.last_compact_at;
                g.last_compact_freed = saved.last_compact_freed;
            }
            g.loaded = true;
            g.dirty = true;
        }
        // Cleared BEFORE the write, the same way `compact_pending` is:
        // a `note_*` landing mid-write re-raises it and comes back next
        // tick, whereas clearing afterwards would swallow that record.
        // Every write is the FULL running total, so a repeat is a no-op
        // and a delayed one loses nothing.
        let out = {
            let mut g = self.index_ledger.lock_ok();
            g.dirty = false;
            *g
        };
        if self.with_index(|ix| out.write(ix).ok()).is_none() {
            self.index_ledger.lock_ok().dirty = true;
        }
    }

    /// Prune the index down to `target` bytes under the current policy,
    /// protecting the four categories above. Returns the engine's report
    /// plus how many protected keys/ids stood in the way, or None when
    /// the index cannot be opened. Never compacts - it only raises
    /// `compact_pending` for the idle-window VACUUM.
    ///
    /// The caller decides WHETHER to evict (the `index_evict` toggle);
    /// this decides only HOW.
    #[cfg(feature = "indexer")]
    pub fn evict_to(&self, target: u64) -> EvictOutcome {
        let policy = self.evict_policy();
        // A partial protected set must never reach the engine: eviction
        // is irreversible, so "could not fully assemble" means "do not
        // evict this pass", not "protect what we managed to list".
        let Some(protected) = self.protected_set() else {
            return EvictOutcome::Unavailable;
        };
        let n_prot = protected.title_keys.len() + protected.release_ids.len();
        // The whole set, uncapped - see EVICT_MAX_PASSES for why there is
        // no longer a ceiling here.
        // index-lock-gate: TODO 166 - eviction itself, reached from
        // `index_shrink_to` and `index_evict_now`, both of which that
        // section classifies as explicit admin actions. This one cannot be
        // bounded anyway: the engine holds the write handle for the whole
        // pass, so refusing to wait would refuse the action.
        let Some(mut rep) = self.with_index(|ix| ix.evict_to(target, &policy, &protected).ok())
        else {
            return EvictOutcome::Unavailable;
        };
        // Keep going while the engine is still making progress and has not
        // told us it was stopped. `live_after` is the honest size (see the
        // note in evict_pass); `bytes_after` cannot fall before a compact,
        // so testing progress with it would loop until the bound every
        // single time.
        for _ in 1..EVICT_MAX_PASSES {
            if rep.blocked || rep.live_after <= target {
                break;
            }
            // index-lock-gate: TODO 166 - the continuation passes of the
            // same admin eviction. See the note above.
            let Some(more) = self.with_index(|ix| ix.evict_to(target, &policy, &protected).ok())
            else {
                break;
            };
            if more.removed == 0 {
                rep.blocked = more.blocked;
                rep.live_after = more.live_after;
                break;
            }
            rep.removed += more.removed;
            rep.bytes_after = more.bytes_after;
            rep.live_after = more.live_after;
            rep.needs_compact |= more.needs_compact;
            rep.blocked = more.blocked;
        }
        if rep.needs_compact {
            self.compact_pending.store(true, Ordering::Relaxed);
        }
        // The one choke point for eviction: `evict_pass` delegates here
        // and both admin doors reach it, so the ledger is charged once,
        // here, rather than at three call sites that would drift. The
        // LIVE delta, for the reason `IndexLedger` gives - the file
        // cannot shrink until the compact runs, so its own delta is zero.
        self.note_evicted(
            rep.removed as u64,
            rep.live_before.saturating_sub(rep.live_after),
        );
        let mb = |b: u64| b as f64 / (1u64 << 20) as f64;
        if rep.live_after > target {
            // Protection is absolute: the engine stops rather than delete
            // a row from the protected set, and that is the right outcome
            // even though the cap is still exceeded. Say so plainly - a
            // silently-still-too-big database is how a user concludes the
            // feature is broken. And be honest about WHICH wall we hit:
            // with nothing protected, the remainder is the database's own
            // floor (schema, indexes, rows no policy selects), not the
            // user's data being defended.
            // Sizes here are the LIVE figures, not the file size: the file
            // cannot shrink until the deferred compact runs, so logging
            // that would print the same number twice and read as a no-op.
            info!(
                target: "index",
                "size cap: removed {} rows, {:.0} MB → {:.0} MB of live content, \
                 still over the {:.0} MB target - {}",
                rep.removed,
                mb(rep.live_before),
                mb(rep.live_after),
                mb(target),
                shrink_shortfall_reason(n_prot),
            );
        } else if rep.removed > 0 {
            info!(
                target: "index",
                "size cap: removed {} rows, {:.0} MB → {:.0} MB of live content \
                 (target {:.0} MB){}",
                rep.removed,
                mb(rep.live_before),
                mb(rep.live_after),
                mb(target),
                if rep.needs_compact {
                    ", the file stays at its current size until the compact runs at idle"
                } else {
                    ""
                }
            );
        }
        EvictOutcome::Ran(rep, n_prot)
    }

    /// What an eviction to `target` WOULD remove, without removing it -
    /// the engine's `evict_preview` under the daemon's current policy
    /// and full protected set, so the answer can never disagree with
    /// what the evict button would then do. `None` when the index is
    /// unavailable or the protected set could not be fully assembled
    /// (same rule as eviction itself: a partial set must not shape an
    /// answer, even a read-only one - it would promise less deletion
    /// than the real pass performs).
    ///
    /// Returns the preview plus the protected-set size, which is the
    /// half of "why so little" the engine cannot see.
    #[cfg(feature = "indexer")]
    pub fn evict_preview_at(&self, target: u64) -> Option<(nzbkit::index::EvictPreview, usize)> {
        let policy = self.evict_policy();
        let protected = self.protected_set()?;
        let n_prot = protected.title_keys.len() + protected.release_ids.len();
        // index-lock-gate: TODO 166 - the preview is the evict/shrink
        // admin family's dry run, reached only from mode=index_evict_preview,
        // and it walks the same candidate pages the real eviction would
        // hold the lock for. The user asked; waiting is the honest answer,
        // and EVICT_PREVIEW_MAX_EXAMINE bounds the walk itself.
        let pv = self.with_index(|ix| {
            ix.evict_preview(target, &policy, &protected, EVICT_PREVIEW_MAX_EXAMINE)
                .ok()
        })?;
        Some((pv, n_prot))
    }

    /// One automatic eviction pass, exactly as the scan loop runs it.
    /// `Nothing` when the feature is off, unconfigured, or the database
    /// is already under its cap - the common case, and the reason this is
    /// cheap to call after every pass.
    #[cfg(feature = "indexer")]
    pub fn evict_pass(&self) -> EvictOutcome {
        if !self.index_evict.load(Ordering::Relaxed) {
            return EvictOutcome::Nothing;
        }
        let cap = self.index_max_bytes.load(Ordering::Relaxed);
        if cap == 0 {
            return EvictOutcome::Nothing;
        }
        // live_bytes, NOT db_bytes. SQLite DELETE hands pages to the
        // freelist without shortening the file, so db_bytes cannot fall
        // until the deferred compact runs - and this check fires after
        // every scan pass. Testing the cap against the file size meant an
        // index that had just been evicted was still "over cap" on the
        // very next pass, so eviction re-ran forever, taking the write
        // lock and re-arming the compact each time, until the index was
        // empty and even then never settling. live_bytes is what
        // eviction can actually move, and is the size the file WOULD have
        // once compacted, so it is the honest thing to hold to a promise
        // about disk. The user-facing readout still shows the file size;
        // see index_stats.
        // index-lock-gate: TODO 166 - the readout that decides whether the
        // admin eviction has anything to do, on the action's own path.
        match self.with_index(|ix| ix.live_bytes().ok()) {
            None => EvictOutcome::Unavailable,
            Some(now) if now <= cap => EvictOutcome::Nothing,
            Some(_) => self.evict_to(cap),
        }
    }

    /// M31b: build (or return the cached) taste profile - the genre/kind/
    /// decade distribution of what the user has downloaded and watchlisted.
    /// Cached for ~60 s; the affinity wall sort calls this per page.
    #[cfg(feature = "indexer")]
    pub fn taste_profile(&self) -> TasteProfile {
        {
            let g = self.taste_cache.lock_ok();
            if let Some((at, tp)) = g.as_ref()
                && at.elapsed() < std::time::Duration::from_secs(60)
            {
                return tp.clone();
            }
        }
        // Each source signal contributes 1.0. Repeated title_keys (e.g.
        // many episodes of one show) accumulate, which reads as stronger
        // affinity - intentional.
        let mut freq: std::collections::HashMap<String, f32> = std::collections::HashMap::new();
        let mut n_signals: u32 = 0;
        for j in self.history.lock_ok().iter() {
            let g = j.lock_ok();
            if g.state == JobState::Completed {
                let key = crate::wall::parse_release(&g.name).key;
                if !key.is_empty() {
                    *freq.entry(key).or_default() += 1.0;
                    n_signals += 1;
                }
            }
        }
        for w in self.watch_items().iter() {
            let norm = nzbkit::release::norm_title(&w.title);
            if norm.is_empty() {
                continue;
            }
            // Build the parse key exactly as the parser does so it joins
            // to the titles table.
            let key = if w.kind == "tv" {
                format!("t:{norm}")
            } else if let Some(y) = w.year {
                format!("m:{norm}:{y}")
            } else {
                format!("m:{norm}")
            };
            *freq.entry(key).or_default() += 1.0;
            n_signals += 1;
        }
        // One batched lookup of the enriched rows for the distinct keys.
        let keys: Vec<String> = freq.keys().cloned().collect();
        // Checked, not flattened: a saturated read pool answers no rows,
        // and a profile built from no rows has no genres and no kinds.
        // Cached, that ranks the wall by nothing for the next 60 s - so
        // the empty answer is used once and not remembered.
        let answered = self.index_read_checked(|ix| ix.titles_for_keys(&keys).ok());
        // `Some(rows)` is the ONLY shape that means the index answered:
        // `titles_for_keys` returns Ok for a total miss too, so the
        // closure hands back Some even for an empty map. `Ok(None)` is a
        // failed query or a declined try_lock (a missing db file during a
        // wipe), never "no rows" - and caching it ranks the wall by
        // nothing for 60 s (Fable sweep 15 Aug). With the database
        // switched off there is no answer to wait for, so that stays
        // cacheable.
        let index_answered = matches!(answered, Ok(Some(_))) || !self.index_db_wanted();
        let rows = answered.unwrap_or_default().unwrap_or_default();
        let mut genre_w: std::collections::HashMap<String, f32> = std::collections::HashMap::new();
        let mut kind_w: std::collections::HashMap<String, f32> = std::collections::HashMap::new();
        let mut year_sum = 0f64;
        let mut year_wt = 0f64;
        for (key, w) in &freq {
            let Some(tr) = rows.get(key) else { continue };
            let genres: Vec<&str> = tr
                .genres
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            if !genres.is_empty() {
                let share = w / genres.len() as f32;
                for g in genres {
                    *genre_w.entry(g.to_string()).or_default() += share;
                }
            }
            if !tr.kind.is_empty() {
                *kind_w.entry(tr.kind.clone()).or_default() += w;
            }
            if tr.year > 0 {
                year_sum += tr.year as f64 * *w as f64;
                year_wt += *w as f64;
            }
        }
        let norm_top = |m: std::collections::HashMap<String, f32>, keep: usize| {
            let sum: f32 = m.values().sum();
            let mut v: Vec<(String, f32)> = if sum > 0.0 {
                m.into_iter().map(|(k, w)| (k, w / sum)).collect()
            } else {
                Vec::new()
            };
            v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            v.truncate(keep);
            v
        };
        let tp = TasteProfile {
            genres: norm_top(genre_w, 8),
            kinds: norm_top(kind_w, 4),
            decade_center: (year_wt > 0.0).then(|| (year_sum / year_wt).round() as i32),
            n_signals,
        };
        if index_answered {
            *self.taste_cache.lock_ok() = Some((std::time::Instant::now(), tp.clone()));
        }
        tp
    }

    /// M31b: turn a taste profile + owned set into the SQL-side scoring
    /// context, or None when there is nothing to rank by (cold start).
    /// Weights are pre-scaled so genre dominates, kind is secondary, and
    /// decade is a light nudge; owned titles get a -1000 sink in SQL.
    #[cfg(feature = "indexer")]
    pub fn affinity_ctx(&self, tp: &TasteProfile) -> Option<nzbkit::index::AffinityCtx> {
        if tp.n_signals == 0
            || (tp.genres.is_empty() && tp.kinds.is_empty() && tp.decade_center.is_none())
        {
            return None;
        }
        Some(nzbkit::index::AffinityCtx {
            genres: tp
                .genres
                .iter()
                .map(|(g, w)| (g.clone(), w * 10.0))
                .collect(),
            fav_kind: tp.kinds.first().map(|(k, w)| (k.clone(), w * 2.0)),
            decade_center: tp.decade_center,
            decade_weight: 1.0,
            owned: self.owned_title_keys(),
        })
    }

    /// The show id the enricher recorded for a TV title key, with the
    /// provider whose numbering it is in - the duplicate check's alias
    /// oracle (see `Index::tv_show_id`, which explains why the pair and
    /// not the bare number). Read-only path on purpose:
    /// `dupe_collision` sits on the add path, and an add must never park
    /// behind an ingest.
    #[cfg(feature = "indexer")]
    pub(crate) fn tv_show_id(&self, title_key: &str) -> Option<(String, i64)> {
        self.with_index_read(|ix| ix.tv_show_id(title_key).ok().flatten())
    }

    /// Slim builds carry no index, so no title ever has a known show id
    /// and the alias arm of the duplicate check simply never fires.
    #[cfg(not(feature = "indexer"))]
    pub(crate) fn tv_show_id(&self, _title_key: &str) -> Option<(String, i64)> {
        None
    }

    /// How long a finished job's tail will wait for the index write
    /// mutex before giving up on its telemetry and finishing anyway.
    ///
    /// Generous enough that an ordinary ingest transaction (a busy
    /// scan's batch, the 10 s SQLite busy_timeout behind it) is simply
    /// waited out, so the samples are kept in every normal case; short
    /// enough that it is not a stall anybody reports.
    #[cfg(feature = "indexer")]
    pub(crate) const TAIL_INDEX_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

    /// [`Self::with_index`] for a finished job's tail: it gives up
    /// rather than waiting for ever, and the job's queue row says where
    /// the time went. `None` covers both "the index is switched off" and
    /// "it was busy for the whole budget" - callers have nothing to do
    /// differently, and the one that matters says so in the log itself.
    ///
    /// The bound exists because of what an unbounded wait cost on 20 Aug
    /// 2026. An index scan lane wedged mid-I/O against a provider that
    /// had stopped answering (the same host delivered 0.0 MB to the
    /// download running beside it), and it held this mutex while it sat
    /// there. The download itself was fine - `index_gate_rendezvous`
    /// bounds the RUNNER's wait for exactly this shape, issue #38's
    /// second wedge - but the post-processing tail's M29 oracle fold
    /// took the mutex with no bound at all and sat on it for 8m46s,
    /// with the row reading as a finishing job the whole time. The
    /// runner had been taught to give up and the tail had not.
    ///
    /// The label exists because of TODO 200: two of Gary's jobs
    /// downloaded in seconds and then sat 14 and 27 minutes behind this
    /// mutex while a retention reap held it - and the row said
    /// "unpacking" the whole time, because the last activity token
    /// anyone had written was the pipeline's. A bounded wait under a
    /// stale label still reads as a broken unpacker; so the token flips
    /// to `indexwait` the first time the mutex is found held, and flips
    /// back to whatever it was once the wait is over (the stage the
    /// caller set, or the engine's own word). A wait that never blocks
    /// never changes the row: the token only moves on contention, so an
    /// idle index costs the reader nothing.
    ///
    /// Polled rather than parked: `std::sync::Mutex` has no timed
    /// acquire, and the poll interval only has to be short against a
    /// budget measured in seconds.
    #[cfg(feature = "indexer")]
    pub(crate) fn with_index_for_tail<T>(
        &self,
        nzo_id: &str,
        f: impl FnOnce(&mut nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
        self.with_index_for_tail_within(nzo_id, Self::TAIL_INDEX_WAIT, f)
    }

    /// [`Self::with_index_for_tail`] with the budget as a parameter, so
    /// a test can hold the mutex and watch the label without sitting
    /// through the production wait.
    #[cfg(feature = "indexer")]
    pub(crate) fn with_index_for_tail_within<T>(
        &self,
        nzo_id: &str,
        wait: std::time::Duration,
        f: impl FnOnce(&mut nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
        let flipped = std::cell::Cell::new(false);
        let prior = self.hub.activity.lock_ok().get(nzo_id).copied();
        let out = self.with_index_bounded_on(
            wait,
            || {
                flipped.set(true);
                self.note_tail_stage(nzo_id, "indexwait");
            },
            f,
        );
        if flipped.get() {
            let mut act = self.hub.activity.lock_ok();
            // Only undo our own write: the job may have parked meanwhile,
            // and a cleared entry must stay cleared.
            if act.get(nzo_id).copied() == Some("indexwait") {
                match prior {
                    Some(tok) => {
                        act.insert(nzo_id.to_string(), tok);
                    }
                    None => {
                        act.remove(nzo_id);
                    }
                }
            }
        }
        out
    }

    /// The loop behind the bounded wait, with the timeout folded into
    /// `None` - for the callers that have nothing to do differently
    /// when the budget runs out. `on_block` runs once, the first time
    /// the mutex is found held - never when the first `try_lock`
    /// succeeds.
    #[cfg(feature = "indexer")]
    fn with_index_bounded_on<T>(
        &self,
        wait: std::time::Duration,
        on_block: impl FnOnce(),
        f: impl FnOnce(&mut nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
        self.with_index_bounded_checked(wait, on_block, f)
            .unwrap_or(None)
    }

    /// The loop itself, with the timeout REPORTED. `Err(Saturated)` is
    /// "the budget elapsed with somebody else holding the write mutex"
    /// and nothing else: an index that is switched off is `Ok(None)`,
    /// exactly as it is on every other door, and a closure that ran and
    /// found nothing is `Ok(None)` too.
    ///
    /// Poison is never fatal here (nzbkit::sync's whole point) and a
    /// poisoned mutex is not busy - it is taken, run under, and
    /// answered from, the same as a clean one.
    #[cfg(feature = "indexer")]
    fn with_index_bounded_checked<T>(
        &self,
        wait: std::time::Duration,
        on_block: impl FnOnce(),
        f: impl FnOnce(&mut nzbkit::index::Index) -> Option<T>,
    ) -> Result<Option<T>, IndexBusy> {
        if !self.index_db_wanted() {
            return Ok(None);
        }
        crate::persist::blocking_db(|| {
            let deadline = Instant::now() + wait;
            let mut on_block = Some(on_block);
            loop {
                // `try_lock` reports poison as an error like any other,
                // so it has to be unpacked rather than retried. Left as
                // "busy", one panic under this mutex would make every
                // caller of this door fail for the life of the process.
                match self.index.try_lock() {
                    Ok(mut guard) => {
                        self.open_locked(&mut guard);
                        return Ok(guard.as_mut().and_then(f));
                    }
                    Err(std::sync::TryLockError::Poisoned(e)) => {
                        let mut guard = e.into_inner();
                        self.open_locked(&mut guard);
                        return Ok(guard.as_mut().and_then(f));
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {
                        if let Some(cb) = on_block.take() {
                            cb();
                        }
                    }
                }
                if Instant::now() >= deadline {
                    return Err(IndexBusy::Saturated);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
    }

    /// How long a user's index WRITE waits for the write mutex before
    /// it answers "busy, try again". TODO 166.
    ///
    /// The wait is the whole point: every caller is a button somebody
    /// pressed, and `try_with_index_mut` would turn "succeeded after a
    /// wait" into "failed" whenever a scan batch happened to hold the
    /// mutex. Long enough that an ordinary ingest batch - and the 10 s
    /// SQLite busy_timeout inside it - is usually just waited out;
    /// short enough that the HTTP worker is back in the pool long
    /// before a tip ingest's whole transaction (~80 s, measured on the
    /// live daemon 14 Aug 2026) is done with it. Four workers queued
    /// behind a 62 s hold is how one dashboard tab wedged the daemon on
    /// 28 Jul; five seconds each cannot build that queue.
    #[cfg(feature = "indexer")]
    pub(crate) const HTTP_INDEX_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Bounded-wait WRITE access, with the timeout reported: the
    /// write-side sibling of [`Self::index_read_checked`], and the
    /// remedy TODO 166 asked for.
    ///
    /// Three answers, and the caller owes the user a different one for
    /// each. `Ok(Some(_))` is the write; `Ok(None)` is the index
    /// switched off or the write itself failing, which every one of
    /// these handlers already reports as "index unavailable"; and
    /// `Err(IndexBusy)` is the mutex still held when the budget ran out
    /// - the edit did NOT happen and the honest reply is
    /// [`IndexBusy::message`], so the UI can offer the click again.
    ///
    /// What it must never become is a `try_`: the user's edit is not a
    /// sample to be dropped, and losing it silently is worse than a
    /// wait. What it must never stay is `with_index_mut`: an unbounded
    /// park on this mutex is the 28 Jul wedge, whichever handler does
    /// it.
    ///
    /// `&mut Index` because the two doors it replaces disagreed -
    /// `api/wall.rs` wrote through `with_index`'s `&Index` and
    /// `api/index.rs` through `with_index_mut` - and the mutable form
    /// accepts both.
    #[cfg(feature = "indexer")]
    pub fn index_write_checked<T>(
        &self,
        f: impl FnOnce(&mut nzbkit::index::Index) -> Option<T>,
    ) -> Result<Option<T>, IndexBusy> {
        self.with_index_bounded_checked(Self::HTTP_INDEX_WAIT, || {}, f)
    }

    /// Run `f` against the shared index, opening it lazily. Returns the
    /// closure's value, or `None` if the index can't be opened (feature
    /// effectively off) - callers treat that as "no results".
    #[cfg(feature = "indexer")]
    pub fn with_index<T>(&self, f: impl FnOnce(&nzbkit::index::Index) -> Option<T>) -> Option<T> {
        if !self.index_db_wanted() {
            return None;
        }
        // blocking_db: both the mutex WAIT (up to another writer's
        // whole transaction, 10 s busy_timeout included) and the
        // closure's own synchronous SQLite run off the async workers.
        // Measured 2026-08-05: three inline deepen ingests plus the tip
        // ingest and a predb fold occupied every tokio worker at once,
        // and the download runner - a ready task with an expired 500 ms
        // poll timer - had no thread to resume on for 38 s.
        crate::persist::blocking_db(|| {
            let mut guard = self.index.lock_ok();
            self.open_locked(&mut guard);
            guard.as_ref().and_then(f)
        })
    }

    /// Open the shared read-write connection into a guard the caller
    /// already holds - and only if the daemon still wants the database.
    ///
    /// Asking `index_db_wanted` again HERE, and not only at the caller's
    /// gate, is the whole point. The wind-down stores `exiting`, then
    /// takes the handle out of this mutex and checkpoints and closes it
    /// with the mutex FREE (see `close_index_for_exit`), so a caller that
    /// passed the gate a moment before that store and then parked on the
    /// lock - behind a whole ingest pass, 62 s on 28 Jul - would wake onto
    /// an empty mutex and lazily reopen the database behind the close.
    /// That reopen is no cheap no-op: it runs the migrations, so the
    /// process exits leaving a fresh -wal and -shm on disk and the next
    /// start pays a recovery pass, which is exactly the residue the close
    /// path was written to remove.
    ///
    /// Taking the mutex is the ordering edge, so one question under it
    /// settles the race both ways: a caller that wins the lock first
    /// opens a handle the close then takes and closes properly, and one
    /// that gets it after the close sees `exiting` and declines. Only the
    /// lazy OPEN is guarded - a closure running against a handle that is
    /// still `Some` holds the mutex, so the close cannot be mid-checkpoint
    /// underneath it, and there is nothing to gain by aborting it.
    #[cfg(feature = "indexer")]
    fn open_locked(&self, guard: &mut std::sync::MutexGuard<'_, Option<nzbkit::index::Index>>) {
        if guard.is_some() || !self.index_db_wanted() {
            return;
        }
        **guard = nzbkit::index::Index::open(&self.index_db).ok();
        if guard.is_some() {
            self.index_migrated.store(true, Ordering::Release);
        }
    }

    /// Borrow one of the pooled read-only connections, opening another
    /// if the pool has not reached [`INDEX_READ_CONNS`] yet.
    ///
    /// Waits at most [`INDEX_READ_WAIT`] and then gives up. Giving up is
    /// the feature: the caller is an HTTP worker, and a worker that
    /// waits without a bound is a worker the next slow query removes
    /// from the pool.
    #[cfg(feature = "indexer")]
    fn index_read_acquire(&self) -> Reader<'_> {
        let deadline = std::time::Instant::now() + INDEX_READ_WAIT;
        let mut st = self.index_read.inner.lock_ok();
        loop {
            // Rechecked on every pass round the loop, under the pool
            // lock, for the reason `open_locked` records - and this side
            // is not merely possible, it is invited: `drop_index_read`
            // wakes every waiter precisely so they open fresh connections
            // now, and the wind-down calls it as its FIRST act. A waiter
            // admitted before `exiting` was stored would answer that wake
            // by opening a read-only connection behind the close, and the
            // writer's own close would then no longer be the last one, so
            // SQLite would keep both the -wal and the -shm.
            //
            // `Unavailable`, not `Busy`: the caller's fallback is
            // `try_with_index`, which declines for the same reason, and
            // that is a quiet empty answer. `Busy` would surface
            // "index busy" on the wall and in search during a shutdown
            // nobody is going to see the end of.
            if !self.index_db_wanted() {
                return Reader::Unavailable;
            }
            if let Some(conn) = st.idle.pop() {
                return Reader::Got(IndexReader {
                    pool: &self.index_read,
                    conn: Some(conn),
                    generation: st.generation,
                });
            }
            if st.live < INDEX_READ_CONNS {
                // Reserve the slot BEFORE releasing the lock, or every
                // waiter racing here opens its own connection and the
                // ceiling means nothing.
                st.live += 1;
                let generation = st.generation;
                drop(st);
                match nzbkit::index::Index::open_read_only(&self.index_db) {
                    Ok(conn) => {
                        // Ask AGAIN, now that the open is done. The gate
                        // above was read before the lock went, and the
                        // open itself is unbounded (a cold file on a
                        // network volume), so the exit signal can land
                        // in the middle of it - and a reader handed out
                        // afterwards outlives the writer's close, which
                        // is what leaves the WAL behind that the close
                        // path exists to truncate (Fable sweep 15 Aug).
                        // The same arm the Err branch below writes.
                        if !self.index_db_wanted() {
                            drop(conn);
                            self.index_read.inner.lock_ok().live -= 1;
                            self.index_read.handed_back.notify_one();
                            return Reader::Unavailable;
                        }
                        return Reader::Got(IndexReader {
                            pool: &self.index_read,
                            conn: Some(conn),
                            generation,
                        });
                    }
                    Err(_) => {
                        self.index_read.inner.lock_ok().live -= 1;
                        // The slot just came back; a waiter parked on
                        // the condvar would otherwise sleep out its
                        // whole budget and answer Busy despite it.
                        self.index_read.handed_back.notify_one();
                        return Reader::Unavailable;
                    }
                }
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                // Say so, at most once a minute. The 2 Aug wedge was
                // diagnosed by timing endpoints by hand against a live
                // daemon; a saturated read pool is the one symptom that
                // names this failure directly, and it belongs in the log
                // rather than in whoever happens to be curling.
                let last = self.index_read_warned.load(Ordering::Relaxed);
                let secs = epoch_secs();
                if secs.saturating_sub(last) >= 60
                    && self
                        .index_read_warned
                        .compare_exchange(last, secs, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                {
                    warn!(
                        target: "index",
                        "all {INDEX_READ_CONNS} index read connections busy for \
                         {INDEX_READ_WAIT:?} - query endpoints are answering \"busy\". \
                         A query has gone slow; the rest of the API is unaffected."
                    );
                }
                return Reader::Busy;
            }
            let (guard, _) = self
                .index_read
                .handed_back
                .wait_timeout(st, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            st = guard;
        }
    }

    /// Read-only access for the interactive query endpoints (wall2,
    /// search, browse, make_nzb, the newznab facade). Runs on a pooled
    /// read-only connection, so a long ingest batch or maintenance pass
    /// holding the read-write connection cannot park an HTTP worker
    /// here: WAL readers run concurrently with the writer.
    ///
    /// `None` when the index is off, when the read failed, and - since
    /// the 2 Aug wedge - when every read connection is busy and none
    /// came free within [`INDEX_READ_WAIT`]. Callers already render an
    /// absent index as an empty answer, which is the right shape for
    /// "ask again in a moment" too; what matters is that the worker goes
    /// back to the pool instead of queueing. Use
    /// [`Self::index_read_checked`] where the difference is worth showing
    /// the user.
    ///
    /// Falls back to the write mutex until a read-write open has run
    /// the migrations - a startup-shaped moment where nothing holds a
    /// long lock - but on a BOUNDED wait, never `with_index`'s
    /// unbounded one (TODO 143). When the read-only open itself FAILS
    /// after migration (the file was just wiped, fd exhaustion), the
    /// fallback is `try_with_index`: post-wipe is not startup-shaped -
    /// a chunked compaction or ANALYZE can be holding the write mutex
    /// for real time, and parking every query worker on it is the
    /// 2 Aug wedge. Saturation deliberately does not fall back at all:
    /// that mutex is exactly what this path exists to stay off.
    #[cfg(feature = "indexer")]
    pub fn with_index_read<T>(
        &self,
        f: impl FnOnce(&nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
        self.index_read_checked(f).unwrap_or(None)
    }

    /// Arm [`DEBUG_READ_BUDGET`]: `n` further pooled reads succeed, then
    /// every read reports the pool busy. Reachable only through the
    /// NZBFAST_DEBUG_HOOKS-gated `mode=debug_index_read_busy`.
    #[cfg(feature = "indexer")]
    pub fn arm_debug_read_budget(n: i64) {
        DEBUG_READ_BUDGET.store(n.max(0), Ordering::Relaxed);
    }

    /// As [`Self::with_index_read`], with a read that could not produce a
    /// trustworthy answer reported rather than flattened into "nothing
    /// found". [`IndexBusy::Saturated`] means every read connection was
    /// busy; [`IndexBusy::SchemaChanged`] means the query itself failed
    /// with SQLITE_SCHEMA and was still failing after nzbkit re-prepared
    /// it - a writer changed the schema under this reader (the first
    /// `ANALYZE` creating sqlite_stat1, a version upgrade's migrations)
    /// and the fts5 constructor lost the race twice.
    ///
    /// The query surfaces a user watches while they run (the wall,
    /// search) and the *arr-facing newznab facade say so instead of
    /// blanking, which is the honest answer and stops a working index
    /// reading as an empty one.
    #[cfg(feature = "indexer")]
    pub fn index_read_checked<T>(
        &self,
        f: impl FnOnce(&nzbkit::index::Index) -> Option<T>,
    ) -> Result<Option<T>, IndexBusy> {
        if !self.index_db_wanted() {
            return Ok(None);
        }
        if !self.index_migrated.load(Ordering::Acquire) {
            // TODO 143's second half. This branch is only reachable
            // before the first read-write open, where "nothing holds a
            // long lock" is fair - but it was an UNBOUNDED park on the
            // write mutex, which is the same shape that made the read
            // pool dead code for two weeks and reopened the 28 Jul and
            // 2 Aug wedges. Whoever holds the mutex here is doing that
            // open, so the budget only has to cover an open and its
            // migrations; past it, a query says "busy" like any other,
            // which is the answer this whole path exists to give
            // instead of queueing a worker.
            return self.with_index_bounded_checked(PREMIGRATION_INDEX_WAIT, || {}, |ix| f(ix));
        }
        if debug_read_budget_spent() {
            return Err(IndexBusy::Saturated);
        }
        match self.index_read_acquire() {
            // The fault stamp, read either side of the closure. `f`
            // returns an Option, so every caller's `.ok()` has already
            // thrown the error away by the time it gets here and a real
            // failure is indistinguishable from a query that legitimately
            // matched nothing - retrying on `None` would be wrong AND
            // would double the work of every miss. nzbkit counts the
            // queries that failed with SQLITE_SCHEMA even after
            // re-preparing, on THIS connection, which survives the
            // flattening. Exact rather than approximate: the pool lends
            // this connection to nobody else while `f` runs, so a move in
            // the counter is this closure's own.
            Reader::Got(ix) => {
                let before = (ix.schema_faults(), ix.deadline_trips());
                // TODO 300. Read the same way and for the same reason as
                // the fault stamp above: the closure's `.ok()` has
                // already turned SQLITE_INTERRUPT into `None`, and "the
                // wall is empty" is the wrong answer to "that view is
                // too big to build". Disarming is `IndexReader::drop`'s
                // job, which is what covers a panicking handler too.
                ix.set_query_deadline(index_read_budget());
                let out = f(&ix);
                if ix.deadline_trips() != before.1 {
                    // Checked first: an abandoned query names its own
                    // cause, and a statement cut off mid-step is not
                    // evidence about the schema.
                    Err(IndexBusy::TooSlow)
                } else if ix.schema_faults() != before.0 {
                    Err(IndexBusy::SchemaChanged)
                } else {
                    Ok(out)
                }
            }
            Reader::Busy => Err(IndexBusy::Saturated),
            // The fallbacks run on the read-WRITE connection, which is
            // the one doing the changing - its own statements are never
            // stale under it - so there is nothing to check there.
            Reader::Unavailable => Ok(self.try_with_index(f)),
        }
    }

    /// Best-effort write access: run `f` on the read-write connection if
    /// it is free RIGHT NOW, skip entirely if anything holds it. For
    /// side-writes an interactive endpoint can shrug off (the grab
    /// path's spot-NZB cache line; wall2's title seeding takes the
    /// `_mut` sibling) - the point of the read-only path is that those
    /// handlers never park behind an ingest, so their embedded writes
    /// must not park either.
    ///
    /// try_lock for the handle, `blocking_db` for the closure - the same
    /// split [`Self::try_with_index_mut`] documents: the WAIT is what
    /// this refuses, not the work. Winning the try_lock still buys a
    /// synchronous SQLite run, and that belongs off the async workers
    /// for the reason `with_index` records.
    ///
    /// Note what winning the try_lock does NOT win: the SQLite WRITE
    /// lock. A closure that autocommits row by row still takes that once
    /// per row, and each one can wait out the full `busy_timeout` behind
    /// another connection's transaction - so a loop of writes belongs in
    /// one transaction even through this door. wall2's title seeding is
    /// the worked example (`title_seed_many`).
    #[cfg(feature = "indexer")]
    pub fn try_with_index<T>(
        &self,
        f: impl FnOnce(&nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
        if !self.index_db_wanted() {
            return None;
        }
        crate::persist::blocking_db(|| {
            let Ok(mut guard) = self.index.try_lock() else {
                return None;
            };
            self.open_locked(&mut guard);
            guard.as_ref().and_then(f)
        })
    }

    /// Mutable sibling of [`Self::try_with_index`]: run `f` on the
    /// read-write connection if it is free RIGHT NOW, skip entirely if
    /// anything holds it.
    ///
    /// For a best-effort write that sits on a latency-critical path and
    /// has a later surface to fall back on. `with_index_mut` would park
    /// the caller for the holder's whole transaction - a tip ingest runs
    /// ~80 s - and the callers that describe themselves as best-effort
    /// mean "skip when contended", not "wait for it".
    ///
    /// try_lock for the handle, `blocking_db` for the closure: the wait
    /// is what we refuse, not the work. Winning the lock still buys a
    /// synchronous SQLite run, which belongs off the async workers for
    /// the reason `blocking_db` documents.
    #[cfg(feature = "indexer")]
    pub fn try_with_index_mut<T>(
        &self,
        f: impl FnOnce(&mut nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
        if !self.index_db_wanted() {
            return None;
        }
        crate::persist::blocking_db(|| {
            let Ok(mut guard) = self.index.try_lock() else {
                return None;
            };
            self.open_locked(&mut guard);
            guard.as_mut().and_then(f)
        })
    }

    /// Retire every read-only connection so the next `with_index_read`
    /// opens fresh ones. Called on the IDENTITY and SCHEMA events only:
    /// wipe (the file is deleted under the pooled handles - a read-only
    /// handle would otherwise serve the deleted inode forever),
    /// source-off, shutdown, and the named-feed index's first creation
    /// (see `with_index_mut_retiring_ddl`). NOT called at the end of an
    /// ordinary pass any more (B4): for committed data a WAL reader
    /// picks up every commit on its next query anyway, so the per-pass
    /// flush bought nothing and threw away up to four warmed 64 MB page
    /// caches each time.
    ///
    /// Connections lent out right now are retired by the generation
    /// bump: their query finishes on the old handle and the guard closes
    /// it instead of pooling it, so this never waits on a running query.
    #[cfg(feature = "indexer")]
    pub fn drop_index_read(&self) {
        let mut st = self.index_read.inner.lock_ok();
        st.generation = st.generation.wrapping_add(1);
        st.live = st.live.saturating_sub(st.idle.len());
        st.idle.clear();
        drop(st);
        // Every retired idle connection is a freed slot; wake the
        // waiters so they open fresh ones now instead of sleeping out
        // their budget and answering Busy.
        self.index_read.handed_back.notify_all();
    }

    /// index_stats' database figures (releases, complete, db_bytes,
    /// live_bytes) without ever parking the caller on the index mutex.
    /// A4: a real TTL cache, not a busy-fallback - a fresh snapshot is
    /// served without touching ANY index lock, even when the writer
    /// mutex is free (this used to recompute the full `SCAN releases`
    /// on every poll the moment try_lock succeeded). On expiry, one
    /// caller recomputes (singleflight) while everyone else keeps the
    /// stale figures; a wipe or source-off bumps the era, which orphans
    /// the snapshot instantly. A TTL-stale count is fine for a status
    /// pill - four HTTP workers queued behind a 62s lock hold is how
    /// one dashboard tab wedged the whole daemon.
    ///
    /// None means "no figures yet", not "empty index": every read path
    /// was busy and nothing has seeded the cache since this daemon came
    /// up. The API forwards that as a cold flag so the dashboard can say
    /// it is still reading instead of claiming a populated index holds
    /// zero releases. Zeros stay reserved for what is actually zero: an
    /// indexer that is off, a database that will not open, or a genuinely
    /// empty index.
    #[cfg(feature = "indexer")]
    pub fn index_stats_snapshot(&self) -> Option<(u64, u64, u64, u64)> {
        const TTL: std::time::Duration = std::time::Duration::from_secs(45);
        if !self.index_db_wanted() {
            return Some((0, 0, 0, 0));
        }
        let era = self.index_era();
        // Sweep 8, L8: the cache generation this flight is answering
        // for. An explicit refresh bumps it, so a flight that started
        // before one may not stamp itself fresh over what the refresher
        // committed.
        let started_gen = {
            let mut c = self.index_stats_cache.lock_ok();
            if c.era == era
                && let Some(snap) = c.snap
                && c.at.is_some_and(|at| at.elapsed() < TTL)
            {
                return Some(snap);
            }
            if c.refreshing {
                // Singleflight: another caller is already paying for
                // the recompute. Same-era stale figures beat queueing
                // a second table scan; a cross-era snapshot (the index
                // was just wiped or switched) must not be served.
                return if c.era == era { c.snap } else { None };
            }
            c.refreshing = true;
            c.generation
        };
        let computed = self.index_stats_compute();
        let mut c = self.index_stats_cache.lock_ok();
        c.refreshing = false;
        if self.index_era() != era {
            // Wiped or switched off while we computed: the figures
            // describe a database that no longer exists. Answer cold
            // and let the next poll recompute under the new era.
            return None;
        }
        if c.generation != started_gen {
            // An explicit refresh landed while this flight was reading.
            // The figures in hand predate whatever it committed, so
            // publishing them as fresh is exactly the bug: leave the
            // cache EXPIRED and answer with what we computed, and the
            // next caller (or the refresher's own retry) recomputes.
            c.at = None;
            return computed.filter(|_| self.index_era() == era);
        }
        match computed {
            Some(snap) => {
                c.snap = Some(snap);
                c.at = Some(std::time::Instant::now());
                c.era = era;
                Some(snap)
            }
            // Every read path was busy: serve same-era stale figures
            // if any exist, cold otherwise. A failed compute must not
            // seed the cache - the next poll should try the real read
            // paths again, not replay a placeholder.
            None => {
                if c.era == era {
                    c.snap
                } else {
                    None
                }
            }
        }
    }

    /// The expensive half of [`Self::index_stats_snapshot`]: one full
    /// read of the figures, off the writer connection when it is free,
    /// off a pooled read-only connection when a scan batch holds it
    /// (a scan batch that reclaims the write connection straight away
    /// used to make a 19 GB index report zero releases to every
    /// dashboard load until the batch finished). Busy/Unavailable on
    /// both paths answers None: "could not read" must not be dressed
    /// up as a count.
    #[cfg(feature = "indexer")]
    fn index_stats_compute(&self) -> Option<(u64, u64, u64, u64)> {
        let read = |ix: &nzbkit::index::Index| {
            let (total, complete) = ix.stats().unwrap_or((0, 0));
            (
                total,
                complete,
                ix.db_bytes().unwrap_or(0),
                ix.live_bytes().unwrap_or(0),
            )
        };
        if let Ok(mut guard) = self.index.try_lock() {
            self.open_locked(&mut guard);
            return match guard.as_ref() {
                Some(ix) => Some(read(ix)),
                // Wanted but would not open: genuinely zero.
                None => Some((0, 0, 0, 0)),
            };
        }
        if let Reader::Got(ix) = self.index_read_acquire() {
            return Some(read(&ix));
        }
        None
    }

    /// Force the next figures out of [`Self::index_stats_snapshot`] to
    /// be freshly computed, and compute them now. Called once per scan
    /// pass, after the whole multi-group JoinSet - the one exact
    /// recompute that replaces the per-group scans (A4) - so the
    /// dashboard pill shows the pass's result without waiting out the
    /// TTL.
    #[cfg(feature = "indexer")]
    pub fn refresh_index_stats(&self) {
        {
            // Sweep 8, L8: expiring `at` is not enough. A flight that
            // began before this call is reading a database that does
            // not yet hold what we just committed, and the singleflight
            // below would hand its pre-commit snapshot straight back -
            // stamped fresh for the whole TTL, over the one call whose
            // entire job is to make the cache reflect this write. The
            // bump makes that flight leave the cache expired instead.
            self.expire_index_stats();
        }
        let _ = self.index_stats_snapshot();
    }

    /// Expire the stats cache AND fence out any flight already in the
    /// air. Clearing `at` alone is not an invalidation: an in-flight
    /// `index_stats_snapshot` stamps its pre-event figures fresh unless
    /// `generation` moved under it, so every site that expires the
    /// cache after a write (evict, shrink, the scan parking on a
    /// download) must bump it too (bug sweep 22 Aug 2026, F-18).
    #[cfg(feature = "indexer")]
    pub fn expire_index_stats(&self) {
        let mut c = self.index_stats_cache.lock_ok();
        c.at = None;
        c.generation = c.generation.wrapping_add(1);
    }

    /// Mutable variant for the odd transaction-shaped call (IMDb
    /// snapshot ingest). Same lazy-open, same single connection.
    #[cfg(feature = "indexer")]
    pub fn with_index_mut<T>(
        &self,
        f: impl FnOnce(&mut nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
        if !self.index_db_wanted() {
            return None;
        }
        // blocking_db: see `with_index` - the write side is the one
        // that actually starved the runner.
        crate::persist::blocking_db(|| {
            let mut guard = self.index.lock_ok();
            self.open_locked(&mut guard);
            guard.as_mut().and_then(f)
        })
    }

    /// [`Self::with_index_mut`] for the writes that can run runtime DDL
    /// (the pre-feed store paths, whose first activity builds the
    /// named-count index). Drains the connection's DDL stamp inside the
    /// same lock hold and retires the read-only pool when the schema
    /// actually changed - the one freshness event a pooled reader's
    /// prepared statements can predate. This is what preserves the
    /// dynamic-DDL half of the old per-pass reader flush now that
    /// ordinary passes no longer retire anything (B4).
    #[cfg(feature = "indexer")]
    pub fn with_index_mut_retiring_ddl<T>(
        &self,
        f: impl FnOnce(&mut nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
        let (r, ddl) = self.with_index_mut(|ix| {
            let r = f(ix)?;
            Some((r, ix.take_schema_ddl()))
        })?;
        if ddl {
            self.drop_index_read();
        }
        Some(r)
    }

    /// Non-waiting sibling for optional background writes. It preserves the
    /// runtime-DDL reader retirement contract, but yields when another index
    /// pass owns the connection instead of parking a low-priority worker.
    #[cfg(feature = "indexer")]
    pub fn try_with_index_mut_retiring_ddl<T>(
        &self,
        f: impl FnOnce(&mut nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
        let (result, ddl) = self.try_with_index_mut(|index| {
            let result = f(index)?;
            Some((result, index.take_schema_ddl()))
        })?;
        if ddl {
            self.drop_index_read();
        }
        Some(result)
    }

    /// Every path to the index database goes through `with_index` or its
    /// read-only sibling `with_index_read` (which checks the same switches,
    /// and can never create the file - its open is READ_ONLY), so the
    /// switches above are the whole "no disk" story: with both sources
    /// off, the file is never opened - never CREATED, on a fresh install
    /// - and every caller (wall, browse, watchlist, oracle, the newznab
    /// facade) sees the same empty answer it would see before a first
    /// scan. The `Index::open` calls in the scan loops are not
    /// exceptions: they only run inside a pass, which the matching pause
    /// predicate has already stopped.
    ///
    /// Turning a switch off also drops the handle we are holding - once
    /// the OTHER source no longer wants it - so the connection, its page
    /// cache and the WAL go with it rather than sitting resident until
    /// restart.
    #[cfg(feature = "indexer")]
    pub fn close_index(&self) {
        // Still wanted by the other source: nothing to close.
        if self.index_db_wanted() {
            return;
        }
        self.drop_index_read();
        // Retire the generation under the same lock the republish takes:
        // a scan task that reads it after this point sees the new one
        // and declines, and one that read the old one is already waiting
        // on the lock we hold.
        let mut guard = self.index.lock_ok();
        self.index_generation.fetch_add(1, Ordering::SeqCst);
        if guard.take().is_some() {
            info!(target: "index", "closed the database - no content source is switched on");
        }
    }

    /// The generation a scan pass must still be running under to publish
    /// its connection. See [`Self::index_generation`].
    #[cfg(feature = "indexer")]
    pub fn index_era(&self) -> u64 {
        self.index_generation.load(Ordering::SeqCst)
    }

    /// Hand a pass's connection back as the shared one, on behalf of a
    /// pass that started at `era` - unless the index was switched off or
    /// wiped while that pass ran, in which case the pass's connection is
    /// simply dropped and the index stays closed. When a shared
    /// connection already exists it is KEPT and the offered one dropped:
    /// see `publish_locked` for why that is enough.
    #[cfg(feature = "indexer")]
    pub fn publish_index(&self, era: u64, fresh: nzbkit::index::Index) {
        let mut guard = self.index.lock_ok();
        self.publish_locked(&mut guard, era, fresh);
    }

    /// §74: republish the shared connection AND stage this pass's
    /// arrivals in one hold of the `index` mutex, so the two cannot be
    /// observed apart. Returns whether the hint was staged - the caller
    /// wakes `watch_now` on true, once it has finished invalidating.
    ///
    /// Atomic because the two halves raced. `publish_index` then
    /// `instant_kick` leaves a window where the arriving release is
    /// already visible to `watchlist_pass` (which reads this same
    /// handle through `with_index`) while `instant_hint` is still
    /// empty: a pass that starts in that window takes an empty hint,
    /// grabs the release anyway, and never records it as an instant
    /// grab - so the badge under-reports and the kick that follows
    /// spends one of the hour's allowance waking a pass that finds the
    /// slot already filled.
    ///
    /// **This narrows the race, it does not close it, and the stronger
    /// claim is false.** "No pass can see the fresh index without also
    /// seeing the hint" does NOT follow from this, for two reasons that
    /// are plain in the code (see
    /// `nzbfast-scan-leg-swallows-arrivals`): `watchlist_pass` takes
    /// the hint once at the top and searches per item much later, so
    /// its own two reads are not atomic with each other; and the
    /// release is visible well before anything here runs, because
    /// `Index::ingest` commits internally and journals its watch hits
    /// after the commit. A pass can grab the arrival before this
    /// function is even called. What is bought is that a pass can no
    /// longer slip between the republish and the hint - pinned by the
    /// two ordering tests in `daemon_tests/instant_tests.rs`, which is
    /// the only level this is observable at: `watchlist_instant`'s
    /// scan-leg case cannot see the difference either way.
    ///
    /// Staging is still never moved EARLIER than the republish, but
    /// that ordering is defensive rather than load-bearing - the
    /// "searched the stale snapshot" story §74 told for it does not
    /// survive a read of `Index::ingest`.
    ///
    /// Staged even when the publish is declined (index wiped or
    /// switched off mid-pass), which is what the unconditional
    /// `instant_arrivals` call this replaced did. There is nothing left
    /// to grab in that case, but deciding that is the pass's job.
    ///
    /// Lock order: `index` -> `instant_kicks` / `instant_hint`. Safe
    /// because both of those are only ever held in leaf scopes that
    /// never reach back for `index`.
    #[cfg(feature = "indexer")]
    pub fn publish_index_with_arrivals(
        &self,
        era: u64,
        fresh: nzbkit::index::Index,
        arrivals: &[String],
        now: i64,
    ) -> bool {
        let mut guard = self.index.lock_ok();
        self.publish_locked(&mut guard, era, fresh);
        self.stage_instant_hint(arrivals, now)
    }

    /// The body of [`Self::publish_index`], for callers that are already
    /// holding the mutex because they have more to do under it.
    #[cfg(feature = "indexer")]
    fn publish_locked(
        &self,
        guard: &mut std::sync::MutexGuard<'_, Option<nzbkit::index::Index>>,
        era: u64,
        mut fresh: nzbkit::index::Index,
    ) {
        // `index_db_wanted`, not `index_enabled`: a spot pass republishes
        // the same shared connection, and on a spots-only install the
        // indexer switch is off by definition. Asking the narrower
        // question would leave that install publishing nothing.
        if !may_publish_index(self.index_era(), era, self.index_db_wanted()) {
            return;
        }
        // An existing shared connection is KEPT, not replaced (B4). The
        // database is WAL, so a connection outside a transaction begins
        // a fresh read snapshot on every statement and sees whatever the
        // pass's own connection committed - the replacement bought no
        // freshness, and on a many-group install it cost a full
        // `Index::open` migration-ladder run per group per pass. What a
        // handover CANNOT carry is connection-local state, which is why
        // the tip watcher re-installs its gate/watch hooks on every use
        // rather than assuming they survive (see
        // `install_live_ingest_policy`). Replacement stays reserved for
        // the identity events - wipe and source-off `take()` the guard,
        // so the next publish or lazy open installs against the new
        // file.
        if guard.is_none() {
            // The caller may hand over a scan-pass scratch connection
            // wholesale. Its arrival watch is that PASS's matcher over
            // that pass's journal - the pass drained the journal before
            // handing over, and every shared-connection ingest installs
            // its own watch - so clear it rather than let a stale
            // predicate journal hits nobody will drain.
            let (leftover, _) = fresh.take_watch_hits();
            debug_assert!(
                leftover.is_empty(),
                "a pass handed over its connection without draining its watch hits"
            );
            fresh.set_watch_names(None);
            **guard = Some(fresh);
        }
        // The connection in the guard came from a read-write
        // `Index::open` (this pass's, or an earlier install), so the
        // migrations HAVE run - which is the whole question
        // `index_migrated` answers.
        //
        // Setting it here is load-bearing, not tidiness. The other four
        // writers of this mutex only set the flag on the branch where
        // THEY open the connection (`guard.is_none()`), so once a scan
        // pass has published one, that branch never runs again and the
        // flag would stay false for the life of the process. False sends
        // every query endpoint down `with_index`'s UNBOUNDED wait on this
        // mutex instead of the read-only pool - which is the 28 Jul and
        // 2 Aug wedges exactly: parked HTTP workers, then a daemon that
        // answers nothing at all, `mode=version` included. The pool was
        // effectively dead code on any install whose scan loop published
        // before the first `with_index` call (TODO 143).
        self.index_migrated.store(true, Ordering::Release);
    }

    /// The master switch, for the workers that are not scan passes.
    ///
    /// `with_index` already makes these threads harmless - their queries
    /// come back empty and they fall into their idle sleeps - but "does
    /// no work" and "does not run" are different claims, and the switch
    /// promises the second. The enrichers would still call out to the
    /// art cache and the photo lane would still walk `.spool/art` on
    /// disk, so each one asks this before its first move of the cycle.
    #[cfg(feature = "indexer")]
    pub fn indexer_off(&self) -> bool {
        !self.index_enabled.load(Ordering::Relaxed)
    }

    /// Slim build: there is no built-in indexer, so it is always off.
    #[cfg(not(feature = "indexer"))]
    pub fn indexer_off(&self) -> bool {
        true
    }

    /// Park a metadata lane while it has no business running: the
    /// indexer is off, or the user has paused metadata lookups. Returns
    /// true when it slept, so callers read as
    /// `if d.park_metadata_lanes(30) { continue }`.
    ///
    /// A poll rather than a condvar. Switching the indexer on is a
    /// once-in-an-install event, and even the pause - which someone may
    /// well flip twice in a minute from the header chip - costs at most
    /// `secs` before the lanes notice, which is invisible next to the
    /// provider round-trips that follow. A condvar here would buy that
    /// latency at the price of a wake path on every setting write.
    ///
    /// The park does wake on a stop request, though. The caller's own
    /// `RunStop` decides what that means; this only makes sure a lane
    /// parked for ten minutes is not still parked long after the
    /// embedded host has reported stopped.
    ///
    /// Named for the lanes rather than for the condition because there
    /// are now two conditions and there may be a third: every caller is
    /// a metadata lane, and none of them wants to enumerate the reasons
    /// it should be idle.
    #[cfg(feature = "indexer")]
    pub fn park_metadata_lanes(&self, secs: u64) -> bool {
        if self.indexer_off() || self.enrich_paused.load(Ordering::Relaxed) {
            crate::sleep_until_stop_bump(std::time::Duration::from_secs(secs));
            return true;
        }
        false
    }
}

/// Everything the size cap must never delete, assembled from the four
/// sources the user picked. Pure so the assembly can be tested without a
/// daemon; `Daemon::protected_set` gathers the inputs.
///
/// Over-protection is the safe direction here and the code takes it
/// wherever the two sides are ambiguous: a watchlisted film with no
/// pinned year contributes both the bare `m:<title>` key and every
/// `m:<title>:<year>` the index resolved for it, because the watcher
/// would grab any of them.
/// Arguments, in order: title_keys of watchlisted shows/films;
/// title_keys of everything queued, downloading or completed; the touch
/// log's title_keys and release ids, already filtered to the protection
/// window.
#[cfg(feature = "indexer")]
pub fn assemble_protected(
    watchlisted: Vec<String>,
    owned: Vec<String>,
    opened_titles: Vec<String>,
    opened_releases: Vec<i64>,
) -> nzbkit::index::Protected {
    let mut keys: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for k in watchlisted.into_iter().chain(owned).chain(opened_titles) {
        if !k.is_empty() && seen.insert(k.clone()) {
            keys.push(k);
        }
    }
    let mut ids = opened_releases;
    ids.sort_unstable();
    ids.dedup();
    nzbkit::index::Protected {
        title_keys: keys,
        release_ids: ids,
    }
}

/// The title_keys one watchlist entry stands for, from the entry alone.
/// TV keys carry no year so they are exact; a film pinned to a year also
/// matches the year-less form, because a stem without a year in it
/// parses to `m:<title>`.
#[cfg(feature = "indexer")]
pub fn watch_item_keys(item: &nzbfast_meta::watchlist::WatchItem) -> Vec<String> {
    let norm = nzbkit::release::norm_title(&item.title);
    if norm.is_empty() {
        return Vec::new();
    }
    if item.kind == "tv" {
        return vec![format!("t:{norm}")];
    }
    // 24D: a custom category's key is "c:<slug>:<title>" plus whatever
    // identity tail the release carried, so the bare form is exact only
    // for the episodic and daily shapes. The tailed keys (one per F1
    // session) cannot be enumerated from the item alone - `protected_set`
    // asks the index for those, as it does for a year-less film.
    if nzbfast_meta::watchlist::is_custom_kind(&item.kind) {
        return vec![format!("c:{}:{norm}", item.kind)];
    }
    match item.year {
        Some(y) => vec![format!("m:{norm}:{y}"), format!("m:{norm}")],
        None => vec![format!("m:{norm}")],
    }
}

/// Why a prune stopped short of the size it was asked for. Two very
/// different situations wear the same symptom, and telling the user the
/// wrong one sends them hunting for protected releases that do not exist.
#[cfg(feature = "indexer")]
pub fn shrink_shortfall_reason(protected_keys: usize) -> String {
    if protected_keys == 0 {
        "nothing is protected, so this is the database's own floor - the schema, its \
         indexes, and whatever the eviction order does not select. Nothing more can be \
         removed at this target."
            .to_string()
    } else {
        format!(
            "the rest is protected ({protected_keys} keys: watchlisted, queued, already \
             downloaded, or opened in the last {OPENED_PROTECT_DAYS} days). Raise the \
             target, or remove some of those first."
        )
    }
}

/// The handle discipline around the exit, tested here rather than in
/// daemon_tests.rs because it is about this module's lazy opens and the
/// private read pool they share.
#[cfg(all(test, feature = "indexer"))]
mod exit_tests {
    use super::*;

    /// A Daemon with the indexer switched on, over a scratch directory.
    fn indexed_daemon(name: &str) -> (Arc<Daemon>, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-idxexit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::testutil::test_daemon(&dir);
        d.index_enabled.store(true, Ordering::Relaxed);
        (d, dir)
    }

    /// `an_exiting_daemon_does_not_reopen_the_index` (daemon_tests.rs)
    /// pins the ENTRY gate: a caller that arrives after `exiting` is set
    /// declines. This pins the window the gate cannot cover - a caller
    /// admitted a moment BEFORE the store, parked on the index mutex
    /// behind an ingest, waking up after the close has taken the handle
    /// out of it. Before `open_locked` it reopened the database there,
    /// ran the migrations, and the daemon exited leaving a fresh -wal and
    /// -shm behind: the exact residue the close path exists to remove.
    #[test]
    fn a_caller_admitted_before_the_exit_does_not_reopen_the_index() {
        let (d, dir) = indexed_daemon("reopen");
        // Open it once first, so this is about the REopen rather than
        // about a first open.
        assert!(
            d.with_index(|ix| ix.kv_set("probe", "1").ok()).is_some(),
            "fixture could not open the index - the assertions below would prove nothing"
        );

        // The test thread stands in for the ingest pass this mutex is
        // documented as being held by for whole passes (62 s on 28 Jul).
        let mut guard = d.index.lock_ok();
        let admitted = Arc::new(AtomicBool::new(false));
        let reader = {
            let d = d.clone();
            let admitted = admitted.clone();
            std::thread::spawn(move || {
                admitted.store(true, Ordering::SeqCst);
                d.with_index(|ix| ix.kv_get("probe"))
            })
        };
        while !admitted.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // Between that flag and the park sits one atomic load and a
        // `blocking_db` hop, so a beat is enough for it to be through the
        // gate and waiting on the mutex we hold.
        std::thread::sleep(std::time::Duration::from_millis(150));

        // The close's exact move: `exiting`, the handle out of the mutex,
        // then the mutex released and the connection closed outside it.
        d.exiting.store(true, Ordering::Relaxed);
        let taken = guard.take();
        drop(guard);
        drop(taken);

        assert!(
            reader
                .join()
                .expect("the admitted caller panicked")
                .is_none(),
            "the admitted caller answered from an index the close had already taken"
        );
        assert!(
            d.index.lock_ok().is_none(),
            "a caller admitted before the exit reopened the index behind the close - \
             the daemon goes on to exit leaving a fresh -wal and -shm on disk"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The read pool's side of the same window, and the wider one: the
    /// close calls `drop_index_read` first, and that wakes every waiter
    /// precisely so they open fresh connections. A woken caller that
    /// opened one would stop the writer's close from being the last
    /// connection, so SQLite would keep both the -wal and the -shm.
    #[test]
    fn the_read_pool_opens_nothing_once_the_daemon_is_exiting() {
        let (d, dir) = indexed_daemon("readpool");
        assert!(
            d.with_index(|ix| ix.kv_set("probe", "1").ok()).is_some(),
            "fixture could not open the index"
        );
        // One borrow and back, so the pool is warm and the path is known
        // to work on this fixture.
        assert!(
            matches!(d.index_read_acquire(), Reader::Got(_)),
            "the read pool would not open a connection at all"
        );
        assert_eq!(d.index_read.inner.lock_ok().live, 1);

        // The wind-down, as far as its first act.
        d.exiting.store(true, Ordering::Relaxed);
        d.drop_index_read();
        assert_eq!(
            d.index_read.inner.lock_ok().live,
            0,
            "the retire left a read connection open"
        );

        // A query handler admitted before that store is past its own gate
        // already, so this call is exactly what it does next.
        assert!(
            matches!(d.index_read_acquire(), Reader::Unavailable),
            "the read pool served an exiting daemon (and Busy would put \
             \"index busy\" on the wall during a shutdown, which is why this \
             asks for Unavailable specifically)"
        );
        assert_eq!(
            d.index_read.inner.lock_ok().live,
            0,
            "a read-only connection was opened behind the close - the writer's \
             close is no longer the last one, so the -wal and -shm stay"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// NZBFAST_DEBUG_HOOKS fault injection for the read pool
/// (`mode=debug_index_read_busy`): let the next N pooled reads through,
/// then report the pool saturated from there on.
///
/// A handler that reads the index TWICE is the shape this exists for.
/// Saturating the pool from outside can only make the FIRST read busy -
/// the window between one handler's two reads is microseconds wide, so
/// the case where an early read succeeds and a later one does not is
/// unreachable from a test and reachable every day on a live daemon.
/// `rar_name` answered "no such release" in exactly that window
/// (read-only sweep 2, 15 Aug 2026, L5).
///
/// Off by default and process-global: -1 is "no injection", and the
/// daemon under test is its own process, so arming it cannot reach any
/// other daemon.
#[cfg(feature = "indexer")]
static DEBUG_READ_BUDGET: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(-1);

/// Spend one unit of the injected budget. `false` - the only answer a
/// daemon that never armed it can get - means "carry on".
#[cfg(feature = "indexer")]
fn debug_read_budget_spent() -> bool {
    if DEBUG_READ_BUDGET.load(Ordering::Relaxed) < 0 {
        return false;
    }
    if DEBUG_READ_BUDGET.fetch_sub(1, Ordering::Relaxed) > 0 {
        return false;
    }
    // Pin at zero rather than letting it run negative into the
    // "not armed" sentinel.
    DEBUG_READ_BUDGET.store(0, Ordering::Relaxed);
    true
}
