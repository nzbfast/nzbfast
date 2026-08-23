//! §131 workstream D item D3: the never-parking half of the
//! search-miss log. Design note
//! `research/DESIGN-D3-search-log-2026-08-11.md`; the table, the
//! readout queries and the retention caps live in
//! `nzbkit::index::searchlog`.
//!
//! The whole reason this module exists rather than a `with_index`
//! write at each search handler: every interactive query runs on a
//! pooled READ-ONLY index connection (`PRAGMA query_only=ON`), which
//! is what keeps an HTTP worker off the write mutex while an ingest
//! batch or a compaction holds it. That connection physically cannot
//! take this write, and reaching past it for the read-write handle is
//! the http_wedge class of bug - one held index connection once parked
//! the entire HTTP pool.
//!
//! So [`Daemon::note_search`] takes one plain in-process mutex, merges
//! counters, and returns. No SQLite, no file I/O, no index handle, no
//! await. [`Daemon::flush_search_log`] does the writing, from the 60 s
//! task in tasks.rs, on the writer, under `blocking_db` - where every
//! other index write already runs.

use super::*;
// TODO 166's busy verdict, named in `clear_search_log`'s signature.
// `daemon_index` is a SIBLING child module of daemon.rs rather than
// something serve/mod.rs re-exports, so it needs the path.
use super::daemon_index::IndexBusy;

/// Identity of one bucket: the same query under a different kind
/// filter is a different hole (a movie search that misses says
/// nothing about the TV half), and the same query from an *arr is a
/// different problem from one a human typed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SearchLogKey {
    pub surface: &'static str,
    pub q: String,
    pub kind: String,
}

/// Counters merged so far for one bucket.
#[derive(Debug, Clone, Default)]
pub struct SearchLogPending {
    pub n: u32,
    pub zero_n: u32,
    pub last_hits: u32,
    pub best_hits: u32,
    pub at: i64,
}

/// Distinct pending buckets held before a flush. Past this, new keys
/// are dropped rather than the map grown: the surfaces feeding it are
/// driven by whoever can reach the API, and an unbounded in-memory
/// buffer behind that is its own bug. 4,000 is comfortably more than
/// one flush window's worth of real traffic (an *arr fleet re-asks
/// tens of queries a minute, not thousands) while costing well under
/// a megabyte if it ever does fill.
pub(in crate::serve) const SEARCH_LOG_BUFFER: usize = 4_000;

/// How long a bucket survives without being asked again.
pub(in crate::serve) const SEARCH_LOG_DAYS: i64 = 30;

/// Distinct queries kept, least-recently-asked evicted first. The age
/// cap alone does not bound a client that invents a query per title -
/// a Radarr pointed at a 10,000-film library is exactly that, and it
/// is a normal setup rather than an attack.
pub(in crate::serve) const SEARCH_LOG_ROWS: u32 = 5_000;

/// Longest query recorded. Past this it is not a search anyone will
/// act on, and the row is only ever storage.
const SEARCH_LOG_MAX_Q: usize = 200;

impl Daemon {
    /// Note that a search ran against our own index and what it
    /// returned. Called from the query handlers, so it must stay
    /// exactly this cheap - see the module note.
    ///
    /// `surface` is `"wall"` or `"newznab"`; `kind` is the kind filter
    /// in force, empty when none. Only searches that actually queried
    /// OUR index belong here: pull search (M35) asks somebody else's
    /// indexer, so its result count would make the miss rate lie.
    #[cfg(feature = "indexer")]
    pub fn note_search(&self, surface: &'static str, q: &str, kind: &str, hits: usize) {
        if !self.index_search_log.load(Ordering::Relaxed) || !self.index_db_wanted() {
            return;
        }
        let q = nzbkit::index::norm_query(q);
        if q.is_empty() || q.len() > SEARCH_LOG_MAX_Q {
            return;
        }
        let now = epoch_secs() as i64;
        let hits = hits.min(u32::MAX as usize) as u32;
        let key = SearchLogKey {
            surface,
            q,
            kind: kind.to_string(),
        };
        let mut buf = self.search_log_buf.lock_ok();
        if buf.len() >= SEARCH_LOG_BUFFER && !buf.contains_key(&key) {
            return;
        }
        let e = buf.entry(key).or_default();
        e.n += 1;
        if hits == 0 {
            e.zero_n += 1;
        }
        e.last_hits = hits;
        e.best_hits = e.best_hits.max(hits);
        e.at = now;
    }

    /// Drain the buffer into the table. Returns buckets written.
    ///
    /// Runs off the query path (the 60 s task, or a test calling it
    /// directly). A flush that cannot get the index simply leaves the
    /// buffer alone and the next tick tries again - the counters are
    /// already merged, so nothing is lost by waiting.
    #[cfg(feature = "indexer")]
    pub fn flush_search_log(&self) -> usize {
        let batch = self.take_search_log_batch();
        if batch.is_empty() {
            return 0;
        }
        // with_index, not try_with_index: this is not on an HTTP
        // worker, so waiting for the writer is the right thing rather
        // than dropping the window's counters on a busy index.
        let wrote = self
            .with_index_mut(|ix| ix.search_log_record(&batch).ok())
            .unwrap_or(0);
        if wrote == 0 && !batch.is_empty() {
            // The index was unavailable (switched off between the
            // note and the flush, or a failed open). Put the counters
            // back rather than losing them - the merge is additive,
            // so a bucket that meanwhile got new hits just keeps them.
            self.return_search_log_batch(batch);
        }
        wrote
    }

    /// Take everything pending, collapsing as-you-type prefixes.
    ///
    /// The wall's search box fires 250 ms after each keystroke, so
    /// typing "kill bill" issues nine searches, eight of which are
    /// fragments that missed only because they were half-typed. A
    /// pending query that is a strict prefix of another pending query
    /// from the same surface is dropped: what survives is the string
    /// the user actually settled on.
    ///
    /// The cost is that a genuine short search followed, inside the
    /// same 60 s window, by a longer one starting with the same text
    /// loses its count. That is the right trade against a readout that
    /// is 90% keystroke fragments, which is a readout nobody can act
    /// on.
    #[cfg(feature = "indexer")]
    fn take_search_log_batch(&self) -> Vec<nzbkit::index::SearchRecord> {
        let pending: Vec<(SearchLogKey, SearchLogPending)> =
            self.search_log_buf.lock_ok().drain().collect();
        let longer: Vec<(&'static str, &str)> = pending
            .iter()
            .map(|(k, _)| (k.surface, k.q.as_str()))
            .collect();
        pending
            .iter()
            .filter(|(k, _)| {
                !longer
                    .iter()
                    .any(|(s, q)| *s == k.surface && q.len() > k.q.len() && q.starts_with(&k.q))
            })
            .map(|(k, p)| nzbkit::index::SearchRecord {
                surface: k.surface.to_string(),
                q: k.q.clone(),
                kind: k.kind.clone(),
                n: p.n,
                zero_n: p.zero_n,
                last_hits: p.last_hits,
                best_hits: p.best_hits,
                at: p.at,
            })
            .collect()
    }

    /// Merge a failed flush's batch back into the buffer.
    #[cfg(feature = "indexer")]
    fn return_search_log_batch(&self, batch: Vec<nzbkit::index::SearchRecord>) {
        let mut buf = self.search_log_buf.lock_ok();
        for r in batch {
            if buf.len() >= SEARCH_LOG_BUFFER {
                break;
            }
            let surface = if r.surface == "newznab" {
                "newznab"
            } else {
                "wall"
            };
            let e = buf
                .entry(SearchLogKey {
                    surface,
                    q: r.q,
                    kind: r.kind,
                })
                .or_default();
            e.n += r.n;
            e.zero_n += r.zero_n;
            e.best_hits = e.best_hits.max(r.best_hits);
            // The buffer may have taken newer searches since the flush
            // started; only an older record is allowed to fill in a
            // last answer nobody has restated.
            if r.at >= e.at {
                e.at = r.at;
                e.last_hits = r.last_hits;
            }
        }
    }

    /// Stop recording and forget what was recorded. Both halves, in
    /// that order, because a privacy switch that leaves the history
    /// behind is not one.
    ///
    /// TODO 166: `index_write_checked`, not `with_index`. This is the
    /// only door in this module a user can knock on, and it reached the
    /// write mutex through exactly the unbounded park the module note
    /// above exists to keep every OTHER search-log write off - so a
    /// Clear clicked while the realtime tip watcher held that mutex sat
    /// an HTTP worker on it for the whole ingest transaction (~80 s on
    /// the live daemon). The bounded wait KEEPS the delete rather than
    /// dropping it - it is the user's edit, not a sample - and reports
    /// the timeout instead of waiting it out.
    ///
    /// The buffer half goes first and unconditionally. It holds only
    /// counters that are not in the table yet, so clearing it is
    /// idempotent, and a retry after a busy verdict simply finds it
    /// already empty.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn clear_search_log(&self) -> Result<usize, IndexBusy> {
        self.search_log_buf.lock_ok().clear();
        Ok(self
            .index_write_checked(|ix| ix.search_log_clear().ok())?
            .unwrap_or(0))
    }

    /// The SWITCH's half of the same clear, which must not be possible
    /// to lose.
    ///
    /// TODO 166's rule is that a user write survives a busy index -
    /// queued, retried, or waited for, never best-effort. The Clear
    /// button satisfies it by reporting the busy index and offering the
    /// click again. This caller cannot: by the time it runs, the switch
    /// has already been stored and answered, and there is no second
    /// button to press. So a busy index latches instead of reporting,
    /// and [`Self::search_log_tick`] runs it on the writer's own
    /// thread, where waiting for the mutex is the right answer.
    #[cfg(feature = "indexer")]
    pub(in crate::serve) fn clear_search_log_deferred(&self) {
        if self.clear_search_log().is_err() {
            self.search_log_clear_pending.store(true, Ordering::Relaxed);
        }
    }

    /// The searchlog's 60 s tick: run a deferred clear first, then
    /// flush. Returns what the flush wrote, as `flush_search_log` does.
    ///
    /// The order is only belt - a latch is set with recording OFF, so
    /// there is nothing arriving in the buffer to flush over a table
    /// that was just emptied - but the clear is the promise this module
    /// owes the user, so it goes first regardless.
    #[cfg(feature = "indexer")]
    pub fn search_log_tick(&self) -> usize {
        if self.search_log_clear_pending.swap(false, Ordering::Relaxed) {
            self.search_log_buf.lock_ok().clear();
            // with_index_mut, not index_write_checked: this is the
            // writer's own blocking thread, so parking on the mutex is
            // exactly what it is for. The bounded wait exists to keep
            // HTTP workers off it, and there is no worker here.
            if self
                .with_index_mut(|ix| ix.search_log_clear().ok())
                .is_none()
            {
                // The index is switched off or the delete failed. Put
                // the latch back rather than forgetting the promise: an
                // index that is off has no table to hold anything, and
                // one switched back on gets the clear then.
                self.search_log_clear_pending.store(true, Ordering::Relaxed);
            }
        }
        self.flush_search_log()
    }
}

#[cfg(all(test, feature = "indexer"))]
mod tests {
    use super::*;

    fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
        let dir = std::env::temp_dir().join(format!("nzbfast-slog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);
        // test_daemon leaves the index off; these tests are about the
        // logging path, which only runs when the index is wanted.
        d.index_enabled.store(true, Ordering::Relaxed);
        f(&d);
        drop(d);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The load-bearing property of this whole module.**
    ///
    /// Recording a search runs on an HTTP worker whose index handle is
    /// the READ-ONLY pool, and the write connection may be held for
    /// minutes by an ingest batch, a compaction or an ANALYZE. If
    /// `note_search` ever reaches for that connection, every search
    /// endpoint queues behind whatever is holding it and the HTTP pool
    /// goes with them - the http_wedge failure, rebuilt from scratch.
    ///
    /// So: hold the index mutex, and require the call to complete
    /// anyway. The channel timeout is what makes this FAIL rather than
    /// hang if someone later "simplifies" the buffer away.
    #[test]
    fn note_search_never_touches_the_index() {
        with_daemon("noindexlock", |d| {
            let held = d.index.lock_ok();

            let (tx, rx) = std::sync::mpsc::channel();
            let d2 = d.clone();
            let t = std::thread::spawn(move || {
                d2.note_search("wall", "Kill.Bill", "", 0);
                let _ = tx.send(());
            });
            assert!(
                rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok(),
                "note_search parked on the index write connection - \
                 that is the http_wedge bug, not a slow test"
            );
            t.join().unwrap();

            // And it did the job: buffered, normalized, counted empty.
            let buf = d.search_log_buf.lock_ok();
            let e = buf
                .get(&SearchLogKey {
                    surface: "wall",
                    q: "kill bill".into(),
                    kind: String::new(),
                })
                .expect("the search was buffered under its normalized form");
            assert_eq!((e.n, e.zero_n, e.last_hits), (1, 1, 0));
            drop(held);
        });
    }

    /// A flush writes the merged counters through, and the buffer comes
    /// out empty. The prefix collapse is what keeps the readout
    /// readable: nine keystrokes of "kill bill" are one search.
    #[test]
    fn a_flush_writes_the_window_and_collapses_the_keystrokes() {
        with_daemon("flush", |d| {
            for frag in ["ki", "kil", "kill", "kill b", "kill bill"] {
                d.note_search("wall", frag, "", 0);
            }
            // A different query in the same window survives untouched,
            // and so does the same prefix from a DIFFERENT surface -
            // an *arr is not typing.
            d.note_search("wall", "the expanse", "", 0);
            d.note_search("newznab", "kill", "movie", 0);

            assert_eq!(d.flush_search_log(), 3);
            assert!(d.search_log_buf.lock_ok().is_empty());

            let rows = d
                .with_index(|ix| ix.search_misses(0, 0, None, 50).ok())
                .unwrap();
            let mut got: Vec<(String, String)> = rows
                .iter()
                .map(|m| (m.surface.clone(), m.q.clone()))
                .collect();
            got.sort();
            assert_eq!(
                got,
                [
                    ("newznab".to_string(), "kill".to_string()),
                    ("wall".to_string(), "kill bill".to_string()),
                    ("wall".to_string(), "the expanse".to_string()),
                ]
            );

            // A second window on the same query accumulates rather
            // than replacing - that count is the whole ranking signal.
            d.note_search("wall", "kill bill", "", 0);
            d.note_search("wall", "kill bill", "", 0);
            d.flush_search_log();
            let rows = d
                .with_index(|ix| ix.search_misses(0, 0, None, 50).ok())
                .unwrap();
            let kb = rows.iter().find(|m| m.q == "kill bill").unwrap();
            assert_eq!((kb.n, kb.zero_n), (3, 3));
        });
    }

    /// The privacy posture, end to end: off means nothing is recorded,
    /// and clearing leaves nothing behind - in the buffer OR the table.
    #[test]
    fn the_switch_stops_recording_and_clearing_forgets_both_halves() {
        with_daemon("privacy", |d| {
            d.note_search("wall", "something", "", 0);
            d.flush_search_log();
            d.note_search("wall", "pending", "", 0);

            d.index_search_log.store(false, Ordering::Relaxed);
            d.note_search("wall", "after the switch", "", 0);
            assert!(
                !d.search_log_buf
                    .lock_ok()
                    .keys()
                    .any(|k| k.q == "after the switch"),
                "recording continued after the switch went off"
            );

            assert_eq!(d.clear_search_log(), Ok(1));
            assert!(
                d.search_log_buf.lock_ok().is_empty(),
                "the buffer kept a search"
            );
            assert!(
                d.with_index(|ix| ix.search_misses(0, 0, None, 50).ok())
                    .unwrap()
                    .is_empty()
            );
        });
    }

    /// An index that cannot be opened must not silently eat the
    /// window's counters - the flush hands them back and the next tick
    /// tries again.
    #[test]
    fn a_failed_flush_hands_the_counters_back() {
        with_daemon("retry", |d| {
            d.note_search("wall", "dune part three", "", 0);
            // Both switches off: with_index refuses, and must not
            // create the database file either.
            d.index_enabled.store(false, Ordering::Relaxed);
            d.spot_enabled.store(false, Ordering::Relaxed);
            assert_eq!(d.flush_search_log(), 0);
            assert!(!d.index_db.exists(), "a flush created the index database");

            let buf = d.search_log_buf.lock_ok();
            let e = buf
                .get(&SearchLogKey {
                    surface: "wall",
                    q: "dune part three".into(),
                    kind: String::new(),
                })
                .expect("the counters were dropped instead of retried");
            assert_eq!(e.n, 1);
        });
    }

    /// TODO 166: the deferred clear lands on the tick, and a tick that
    /// still cannot reach the index puts the promise BACK.
    ///
    /// The integration leg in `tests/daemon_indexbusy/` covers the
    /// ordinary path - busy mutex, latch, tick, gone - through real
    /// HTTP. What it cannot reach is the arm where the index is switched
    /// OFF under the latch: silently consuming the latch there would
    /// mean the rows survive the moment the index comes back, which is
    /// the same lost edit by a slower route.
    #[test]
    fn a_deferred_clear_lands_on_the_tick_and_survives_an_index_that_is_off() {
        with_daemon("deferred", |d| {
            d.note_search("wall", "the thing", "", 0);
            d.flush_search_log();
            assert_eq!(
                d.with_index(|ix| ix.search_misses(0, 0, None, 50).ok())
                    .unwrap()
                    .len(),
                1
            );

            // The index is off, so this tick cannot honour the latch -
            // and must not pretend it did.
            d.search_log_clear_pending.store(true, Ordering::Relaxed);
            d.index_enabled.store(false, Ordering::Relaxed);
            d.spot_enabled.store(false, Ordering::Relaxed);
            d.search_log_tick();
            assert!(
                d.search_log_clear_pending.load(Ordering::Relaxed),
                "the tick consumed a clear it could not run"
            );

            // Back on, and the row the switch asked to forget is gone.
            d.index_enabled.store(true, Ordering::Relaxed);
            d.search_log_tick();
            assert!(
                !d.search_log_clear_pending.load(Ordering::Relaxed),
                "a clear that landed must not stay latched"
            );
            assert!(
                d.with_index(|ix| ix.search_misses(0, 0, None, 50).ok())
                    .unwrap()
                    .is_empty(),
                "the deferred clear never reached the table"
            );
        });
    }
}
