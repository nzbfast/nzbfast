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
//! private fields and daemon.rs's private types (`Reader`, `IndexReader`,
//! `LadderPermit`, `OpenedLog`) stay in scope exactly as they were inline.

use super::*;

/// Why a pooled read could not produce a trustworthy answer. The name is
/// about the CALLER's options rather than the cause: either way the
/// honest reply is "not right now, ask again", and every endpoint
/// handles both the same - keep what is on screen and let the next poll
/// get the real answer. Drawing either as an empty result is how a
/// working index comes to be reported as a broken one.
#[cfg(feature = "indexer")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::serve) enum IndexBusy {
    /// Every read connection is in use. Nothing failed in the database
    /// sense - the answer just is not available cheaply right now.
    Saturated,
    /// The query failed with SQLITE_SCHEMA and was still failing after
    /// re-preparing: a writer changed the schema under this reader and
    /// the fts5 constructor lost the race twice. Something DID fail,
    /// which is exactly why it must not be flattened into "no rows" -
    /// see `nzbkit::index::Index::schema_faults`.
    SchemaChanged,
}

#[cfg(feature = "indexer")]
impl IndexBusy {
    /// What to tell the user. Both are transient and both ask for the
    /// same thing, so they differ only in naming the cause - which is
    /// what makes a schema fault greppable in a support report rather
    /// than indistinguishable from a busy pool.
    pub(in crate::serve) fn message(self) -> &'static str {
        match self {
            Self::Saturated => "the index is busy - try again in a moment",
            Self::SchemaChanged => "the index schema changed mid-query - try again in a moment",
        }
    }
}

impl Daemon {
    // -- M34 index size cap ------------------------------------------------

    /// Where the "recently opened" touch log lives (spool, beside the
    /// watchlist state - same lifecycle, same crash-safe writer).
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn opened_path(&self) -> PathBuf {
        self.spool.join("index-opened.json")
    }

    /// Note that the user opened a card's detail sheet.
    #[cfg(feature = "indexer")]
    pub fn touch_opened_title(&self, title_key: &str) {
        let now = epoch_secs() as i64;
        let dirty = self
            .index_opened
            .lock()
            .unwrap()
            .touch_title(title_key, now);
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
    pub(in crate::serve) fn save_opened(&self) {
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
    pub(in crate::serve) fn evict_policy(&self) -> nzbkit::index::EvictPolicy {
        let order_s = self.index_evict_order.lock_ok().clone();
        nzbkit::index::EvictPolicy {
            order: parse_evict_order(&order_s).unwrap_or(nzbkit::index::EvictOrder::Ladder),
            kinds: self.index_evict_kinds.lock_ok().clone(),
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
    #[cfg(feature = "indexer")]
    /// `None` = the set could not be FULLY assembled (index unavailable
    /// or a resolver query failed). The caller must treat that as "do
    /// not evict", never as an empty set: a transient SQLITE_BUSY here
    /// used to shrink the protected set silently, and evict_to then
    /// deleted watchlisted releases irreversibly.
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
                crate::watchlist::is_custom_kind(&i.kind)
                    && nzbkit::release::norm_title(&i.title).is_empty()
            })
            .map(|i| i.kind.clone())
            .collect();
        if !whole_custom.is_empty() {
            // A failed resolver query fails the WHOLE assembly: dropping
            // just this category's keys would hand evict_to a set that
            // no longer protects it.
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
                crate::watchlist::is_custom_kind(&i.kind) || (i.kind != "tv" && i.year.is_none())
            })
            .map(|i| {
                let kind = if crate::watchlist::is_custom_kind(&i.kind) {
                    i.kind.clone()
                } else {
                    "movie".into()
                };
                (kind, nzbkit::release::norm_title(&i.title))
            })
            .filter(|(_, n)| !n.is_empty())
            .collect();
        if !yearless.is_empty() {
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

    /// Prune the index down to `target` bytes under the current policy,
    /// protecting the four categories above. Returns the engine's report
    /// plus how many protected keys/ids stood in the way, or None when
    /// the index cannot be opened. Never compacts - it only raises
    /// `compact_pending` for the idle-window VACUUM.
    ///
    /// The caller decides WHETHER to evict (the `index_evict` toggle);
    /// this decides only HOW.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn evict_to(&self, target: u64) -> EvictOutcome {
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

    /// One automatic eviction pass, exactly as the scan loop runs it.
    /// `Nothing` when the feature is off, unconfigured, or the database
    /// is already under its cap - the common case, and the reason this is
    /// cheap to call after every pass.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn evict_pass(&self) -> EvictOutcome {
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
    pub(in crate::serve) fn taste_profile(&self) -> TasteProfile {
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
    pub(in crate::serve) fn affinity_ctx(
        &self,
        tp: &TasteProfile,
    ) -> Option<nzbkit::index::AffinityCtx> {
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
    pub(in crate::serve) fn tv_show_id(&self, title_key: &str) -> Option<(String, i64)> {
        self.with_index_read(|ix| ix.tv_show_id(title_key).ok().flatten())
    }

    /// Slim builds carry no index, so no title ever has a known show id
    /// and the alias arm of the duplicate check simply never fires.
    #[cfg(not(feature = "indexer"))]
    pub(in crate::serve) fn tv_show_id(&self, _title_key: &str) -> Option<(String, i64)> {
        None
    }

    /// Run `f` against the shared index, opening it lazily. Returns the
    /// closure's value, or `None` if the index can't be opened (feature
    /// effectively off) - callers treat that as "no results".
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn with_index<T>(
        &self,
        f: impl FnOnce(&nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
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
    /// Falls back to `with_index` until a read-write open has run the
    /// migrations - a startup-shaped moment where nothing holds a long
    /// lock. When the read-only open itself FAILS after migration (the
    /// file was just wiped, fd exhaustion), the fallback is
    /// `try_with_index`: post-wipe is not startup-shaped - a chunked
    /// compaction or ANALYZE can be holding the write mutex for real
    /// time, and parking every query worker on it is the 2 Aug wedge.
    /// Saturation deliberately does not fall back at all: that mutex is
    /// exactly what this path exists to stay off.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn with_index_read<T>(
        &self,
        f: impl FnOnce(&nzbkit::index::Index) -> Option<T>,
    ) -> Option<T> {
        self.index_read_checked(f).unwrap_or(None)
    }

    /// Arm [`DEBUG_READ_BUDGET`]: `n` further pooled reads succeed, then
    /// every read reports the pool busy. Reachable only through the
    /// NZBFAST_DEBUG_HOOKS-gated `mode=debug_index_read_busy`.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn arm_debug_read_budget(n: i64) {
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
    pub(in crate::serve) fn index_read_checked<T>(
        &self,
        f: impl FnOnce(&nzbkit::index::Index) -> Option<T>,
    ) -> Result<Option<T>, IndexBusy> {
        if !self.index_db_wanted() {
            return Ok(None);
        }
        if !self.index_migrated.load(Ordering::Acquire) {
            return Ok(self.with_index(f));
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
                let before = ix.schema_faults();
                let out = f(&ix);
                if ix.schema_faults() == before {
                    Ok(out)
                } else {
                    Err(IndexBusy::SchemaChanged)
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
    /// side-writes an interactive endpoint can shrug off (wall2's title
    /// seeding) - the point of the read-only path is that those handlers
    /// never park behind an ingest, so their embedded writes must not
    /// park either.
    ///
    /// try_lock for the handle, `blocking_db` for the closure - the same
    /// split [`Self::try_with_index_mut`] documents: the WAIT is what
    /// this refuses, not the work. Winning the try_lock still buys a
    /// synchronous SQLite run, and that belongs off the async workers
    /// for the reason `with_index` records. Not a hypothetical closure
    /// either: the wall's title seeding loops `title_seed` over a whole
    /// page of cards.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn try_with_index<T>(
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
    pub(in crate::serve) fn try_with_index_mut<T>(
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
    /// opens fresh ones. Called wherever the write side republishes or
    /// drops its own connection. For committed data this is
    /// belt-and-braces (a WAL reader picks up every commit on its next
    /// query anyway), but it is what keeps the readers correct across
    /// index_wipe deleting the file out from under them - a read-only
    /// handle would otherwise serve the deleted inode forever.
    ///
    /// Connections lent out right now are retired by the generation
    /// bump: their query finishes on the old handle and the guard closes
    /// it instead of pooling it, so this never waits on a running query.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn drop_index_read(&self) {
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
    /// try_lock: when the connection is free, compute fresh and refresh
    /// the cache; when a scan batch or maintenance pass holds it, serve
    /// the last known figures. A few-seconds-stale count is fine for a
    /// status pill - four HTTP workers queued behind a 62s lock hold
    /// is how one dashboard tab wedged the whole daemon.
    ///
    /// None means "no figures yet", not "empty index": every read path
    /// was busy and nothing has seeded the cache since this daemon came
    /// up. The API forwards that as a cold flag so the dashboard can say
    /// it is still reading instead of claiming a populated index holds
    /// zero releases. Zeros stay reserved for what is actually zero: an
    /// indexer that is off, a database that will not open, or a genuinely
    /// empty index.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn index_stats_snapshot(&self) -> Option<(u64, u64, u64, u64)> {
        if !self.index_db_wanted() {
            return Some((0, 0, 0, 0));
        }
        if let Ok(mut guard) = self.index.try_lock() {
            self.open_locked(&mut guard);
            if let Some(ix) = guard.as_ref() {
                let (total, complete) = ix.stats().unwrap_or((0, 0));
                let snap = (
                    total,
                    complete,
                    ix.db_bytes().unwrap_or(0),
                    ix.live_bytes().unwrap_or(0),
                );
                *self.index_stats_cache.lock_ok() = Some(snap);
                return Some(snap);
            }
            return Some((0, 0, 0, 0));
        }
        if let Some(snap) = *self.index_stats_cache.lock_ok() {
            return Some(snap);
        }
        // The cache is only empty before the first successful read - the
        // restart window. A scan batch that reclaims the write connection
        // straight away used to make a 19 GB index report zero releases
        // to every dashboard load until the batch finished; the pooled
        // read-only connections run concurrently with that writer, so
        // ask one of them instead. Busy/Unavailable answer None: the
        // pool's bounded wait is the whole point of it, and "could not
        // read" must not be dressed up as a count.
        if let Reader::Got(ix) = self.index_read_acquire() {
            let (total, complete) = ix.stats().unwrap_or((0, 0));
            let snap = (
                total,
                complete,
                ix.db_bytes().unwrap_or(0),
                ix.live_bytes().unwrap_or(0),
            );
            *self.index_stats_cache.lock_ok() = Some(snap);
            return Some(snap);
        }
        None
    }

    /// Mutable variant for the odd transaction-shaped call (IMDb
    /// snapshot ingest). Same lazy-open, same single connection.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn with_index_mut<T>(
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
    pub(in crate::serve) fn close_index(&self) {
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
    pub(in crate::serve) fn index_era(&self) -> u64 {
        self.index_generation.load(Ordering::SeqCst)
    }

    /// Publish a freshly-opened shared connection on behalf of a scan
    /// pass that started at `era` - unless the index was switched off or
    /// wiped while that pass ran, in which case the pass's connection is
    /// simply dropped and the index stays closed.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn publish_index(&self, era: u64, fresh: nzbkit::index::Index) {
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
    pub(in crate::serve) fn publish_index_with_arrivals(
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
        fresh: nzbkit::index::Index,
    ) {
        // `index_db_wanted`, not `index_enabled`: a spot pass republishes
        // the same shared connection, and on a spots-only install the
        // indexer switch is off by definition. Asking the narrower
        // question would leave that install publishing nothing.
        if !may_publish_index(self.index_era(), era, self.index_db_wanted()) {
            return;
        }
        **guard = Some(fresh);
        // `fresh` came from a read-write `Index::open`, so the migrations
        // HAVE run - which is the whole question `index_migrated` answers.
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
    pub(in crate::serve) fn indexer_off(&self) -> bool {
        !self.index_enabled.load(Ordering::Relaxed)
    }

    /// Slim build: there is no built-in indexer, so it is always off.
    #[cfg(not(feature = "indexer"))]
    pub(in crate::serve) fn indexer_off(&self) -> bool {
        true
    }

    /// Park a worker thread while the indexer is off. Returns true when
    /// it slept, so callers read as `if d.park_if_off(30) { continue }`.
    /// A poll rather than a condvar: switching the indexer on is a
    /// once-in-an-install event, and up to `secs` of extra latency
    /// before the metadata lanes wake is invisible next to the scan pass
    /// that has to run first anyway.
    ///
    /// The park does wake on a stop request, though. The caller's own
    /// `RunStop` decides what that means; this only makes sure a lane
    /// parked for ten minutes is not still parked long after the
    /// embedded host has reported stopped.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn park_if_off(&self, secs: u64) -> bool {
        if self.indexer_off() {
            crate::serve::sleep_until_stop_bump(std::time::Duration::from_secs(secs));
            return true;
        }
        false
    }

    /// C4-4 (§131 identity substrate): every NZB the daemon accepts -
    /// watch folder, dashboard add, *arr handoff, RSS, spot grab - is a
    /// (name, payload message-id set) pairing. When those message-ids
    /// are rows we scanned, that is EXACT identity for what the user
    /// just downloaded, so record it as a provenance-tagged MsgidSet
    /// claim. Message-id identity only - never time/size.
    ///
    /// Quorum: [`nzbkit::nzbimport::MIN_MSGID_QUORUM`] distinct ids per
    /// row, because a single id can be seeded (the NZB is untrusted
    /// regardless of which surface delivered it). The reverse map keys
    /// a bounded per-file sample in ascending part order, so the probe
    /// set takes the LEADING ids of each file - and more than the
    /// map's three per file, because a row scanned mid-post keys later
    /// parts first and keeps them (append-only).
    ///
    /// Best-effort by design: it runs after the job is queued and
    /// published, and a contended or closed index just means this
    /// pairing waits for a future surface (the download tail names it
    /// again at PAR2/CRC strength anyway).
    ///
    /// `try_with_index_mut`, never the blocking form. This runs INSIDE
    /// `enqueue`, so whatever it waits on, the caller waits on too - and
    /// the watch folder's scan loop calls `enqueue` serially. Measured
    /// 14 Aug 2026: four NZBs dropped in together, and because the first
    /// `enqueue` parked here behind a tip ingest, the other three were
    /// not even picked up for 40 s. "Waits for a future surface" is what
    /// this comment always claimed; with the blocking form it waited for
    /// THIS one instead, on the user's critical path.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn record_nzb_pairing(
        &self,
        name: &str,
        origin: &str,
        nzb: &nzbkit::nzb::Nzb,
    ) {
        use nzbkit::index::msgid_set_key;
        // The probe bounds are the lane-shared ones so this pairing and
        // the posted-NZB rung mean the same thing by "quorum".
        use nzbkit::nzbimport::{MIN_MSGID_QUORUM, PROBE_CAP, PROBES_PER_FILE};
        let mut probes: Vec<&str> = Vec::new();
        let mut seen: std::collections::HashSet<&str> = Default::default();
        let mut total_ids = 0usize;
        for f in &nzb.files {
            for (i, s) in f.segments.iter().enumerate() {
                total_ids += 1;
                if i < PROBES_PER_FILE
                    && probes.len() < PROBE_CAP
                    && seen.insert(s.message_id.as_str())
                {
                    probes.push(&s.message_id);
                }
            }
        }
        if total_ids < MIN_MSGID_QUORUM {
            return;
        }
        debug_assert!(MIN_MSGID_QUORUM >= nzbkit::index::MSGID_KEYS_PER_FILE);
        let source = if origin.is_empty() {
            "nzb-add".to_string()
        } else {
            format!("nzb-{origin}")
        };
        let now = epoch_secs() as i64;
        let applied = self.try_with_index_mut(|ix| {
            // Probed one id at a time (same cost as the batch form,
            // which loops internally) so each release's MATCHED id set
            // is known: the canonical MsgidSet key digests the matched
            // set per join - any other lane proving the same join then
            // produces the same key and the claims dedupe instead of
            // reading as independent evidence.
            let mut per: std::collections::HashMap<i64, Vec<&str>> = Default::default();
            for id in &probes {
                for (rid, _) in ix
                    .find_releases_by_msgids(std::iter::once(*id))
                    .unwrap_or_default()
                {
                    per.entry(rid).or_default().push(id);
                }
            }
            let mut out = Vec::new();
            for (rid, mids) in per {
                if mids.len() < MIN_MSGID_QUORUM {
                    continue;
                }
                // Displacement policy lives IN apply_proven_name: a
                // readable stem is a name the layer respects, so a
                // season-pack add quorum-joining its per-episode rows
                // comes back ProvenOutcome::Conflict (recorded, never
                // applied) - expected for pack-shaped joins, not an
                // error.
                let claim = nzbkit::index::NameClaim {
                    name: name.to_string(),
                    evidence: nzbkit::index::NameEvidence::MsgidSet,
                    key: msgid_set_key(&mids),
                    source: source.clone(),
                };
                if let Ok(o) = ix.apply_proven_name(rid, &claim, now) {
                    out.push((rid, mids.len(), o));
                }
            }
            Some(out)
        });
        for (rid, matched, outcome) in applied.into_iter().flatten() {
            info!(
                target: "claims",
                "release {rid}: msgid-set pairing ({matched} ids) from {source} \
                 names it {name:?} -> {outcome:?}"
            );
        }
    }

    /// Slim build: accepting an NZB records nothing.
    #[cfg(not(feature = "indexer"))]
    pub(in crate::serve) fn record_nzb_pairing(
        &self,
        _name: &str,
        _origin: &str,
        _nzb: &nzbkit::nzb::Nzb,
    ) {
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
pub fn watch_item_keys(item: &crate::watchlist::WatchItem) -> Vec<String> {
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
    if crate::watchlist::is_custom_kind(&item.kind) {
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
        let d = crate::serve::testutil::test_daemon(&dir);
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
