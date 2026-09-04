use super::super::*;
use super::ApiCtx;

/// Correlation hints for a page of rows, keyed by release id. One
/// read-lock pass; an unavailable index is an empty map, exactly like
/// every other decoration on these pages.
fn corr_hints(
    d: &Arc<Daemon>,
    ids: impl Iterator<Item = i64>,
) -> std::collections::HashMap<i64, Value> {
    let ids: Vec<i64> = ids.collect();
    if ids.is_empty() {
        return Default::default();
    }
    d.with_index_read(|ix| ix.pre_hints(&ids).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|(id, name, score, delta, ratio, status)| {
            (
                id,
                json!({
                    "name": name, "score": score, "delta": delta,
                    "ratio": ratio as f64 / 1000.0, "status": status,
                }),
            )
        })
        .collect()
}

/// Poster URLs for a page of release rows, keyed by title key.
///
/// Reddit feedback (u/Zimmster2020, 31 Aug 2026): posters existed on
/// the wall GRID and nowhere else, so the Releases table and the
/// dashboard's Browse card showed the same titles as bare text. The
/// grid gets its art free - `browse_cards` joins `titles` per card -
/// and a release list has no such join, so this is the extra question
/// those two pages ask. One read-lock pass; an unavailable index is an
/// empty map, exactly like `corr_hints` above and every other
/// decoration on these pages.
///
/// The URL is only handed out when the cache file is really there.
/// `titles.poster` records what enrichment WROTE, and art eviction
/// (`maint.rs`) can take the file away underneath it - a row is better
/// with no picture than with a broken one. The `?v=<checked>` query is
/// the grid's own cache-buster, and the `/art/` route strips the query
/// before it joins the name, so a replaced poster is not served out of
/// the browser's copy of the old one.
///
/// `hide_adult` is passed down to the SQL rather than decided here -
/// see [`nzbkit::index::Index::title_art`] for why art is gated on a
/// path where the ROW is not.
fn row_art(
    d: &Arc<Daemon>,
    keys: Vec<String>,
    hide_adult: bool,
) -> std::collections::HashMap<String, String> {
    if keys.is_empty() {
        return Default::default();
    }
    let art_dir = d.spool.join("art");
    d.with_index_read(|ix| ix.title_art(&keys, hide_adult).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, a)| art_dir.join(&a.poster).is_file())
        .map(|(k, a)| (k, format!("/art/thumb_{}?v={}", a.poster, a.checked)))
        .collect()
}

fn m_index_stats(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Never blocks: served from a try_lock + cache, so
        // this poll cannot park an HTTP worker behind a long
        // scan batch (the 28 Jul all-workers-wedged hang).
        // None = every read path was busy and nothing has
        // seeded the cache yet (the restart window). The
        // zeros below are placeholders then, and stats_cold
        // tells the dashboard to say "reading" instead of
        // presenting them as counts.
        let snap = d.index_stats_snapshot();
        let stats_cold = snap.is_none();
        let (total, complete, db_bytes, live_bytes) = snap.unwrap_or((0, 0, 0, 0));
        // Several groups can scan at once (M28): report the
        // set joined + headers summed (dashboard shows one
        // status line either way).
        let (scanning, sgroup, sdone) = {
            let ps = d.scan_progress.lock_ok();
            (
                !ps.is_empty(),
                ps.iter()
                    .map(|p| p.group.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                ps.iter()
                    .map(|p| p.done.load(Ordering::Relaxed))
                    .sum::<u64>(),
            )
        };
        // "" when running. An index that has silently stopped
        // growing is otherwise unexplainable from the UI, and
        // the two causes need opposite actions from the user.
        let paused = d.indexing_pause_reason().unwrap_or("");
        // M34: how big has it actually grown? Until now
        // nothing in the API answered that, so a user could
        // not see the database filling their disk, let alone
        // judge what to cap it at. db_bytes is the engine's
        // page-accounted size; file_bytes is what the volume
        // sees - they diverge after a prune, until the
        // deferred compact returns the free pages.
        //
        // live_bytes is the third figure and the one the CAP
        // is held against: db_bytes minus the freelist, i.e.
        // the size the file would have if it were compacted
        // right now. The gap between it and db_bytes is
        // exactly what a pending compact would hand back, so
        // the dashboard shows db_bytes as "the file" and
        // quotes live_bytes as what it will become.
        let file_bytes = std::fs::metadata(&d.index_db).map(|m| m.len()).unwrap_or(0);
        let ledger = d.index_ledger_snapshot();
        let cap = d.index_max_bytes.load(Ordering::Relaxed);
        json!({
            // The master switch, separate from `paused`: the
            // dashboard hides the whole indexer half of the
            // UI on this rather than rendering it empty, and
            // it must not need the settings block to do it.
            "enabled": !d.indexer_off(),
            "paused": paused,
            "stats_cold": stats_cold,
            "releases": total,
            "complete": complete,
            "groups": d.index_groups.lock_ok().clone(),
            "interval_secs": d.index_interval_secs.load(Ordering::Relaxed),
            "scanning": scanning,
            "group": sgroup,
            "headers_done": sdone,
            "db_bytes": db_bytes,
            "live_bytes": live_bytes,
            "file_bytes": file_bytes,
            "index_max_bytes": cap,
            // Same quantity evict_pass tests, so the badge and
            // the daemon can never disagree about whether the
            // index is over its limit.
            "over_cap": cap > 0 && live_bytes > cap,
            "index_evict": d.index_evict.load(Ordering::Relaxed),
            "index_evict_order": d.index_evict_order.lock_ok().clone(),
            "index_evict_kinds": d.index_evict_kinds.lock_ok().clone(),
            "index_keep_kinds": d.index_keep_kinds.lock_ok().clone(),
            "index_evict_scope": d.index_evict_scope.lock_ok().clone(),
            "index_evict_headroom": d.index_evict_headroom.load(Ordering::Relaxed),
            "compact_pending": d.compact_pending.load(Ordering::Relaxed),
            // Truth-audit I: the hourly trim, narrated. The manual
            // button reports exactly what it removed; the automatic
            // pass doing the same work said nothing at all, so a
            // shrinking index had no explanation anywhere in the UI.
            // Null until this daemon run has actually trimmed
            // something.
            "last_auto_trim": d.last_auto_trim.lock_ok().map(|(at, removed)| json!({
                "at": at, "removed": removed,
            })),
            // The two facts the space readout was designed around and
            // which nothing recorded until now: has the reclaim ever
            // actually run, and what has the cap cost so far. Read from
            // the in-memory mirror - a poll may never take the index
            // mutex (TODO 166) - and persisted in the database's own kv,
            // so a restart does not report "never compacted" about a
            // file that was compacted last night.
            //
            // `last_compact` is null when this database has never been
            // compacted, which the dashboard says in words rather than
            // drawing as a zero. `evicted` is null before either figure
            // has moved, for the same reason: "0 releases removed" and
            // "nothing has ever needed removing" read very differently
            // beside a size limit.
            // The `stats_cold` of the ledger: its stored half has not
            // been read back yet, so a null below means "not known"
            // rather than "never happened". Only the never-compacted
            // sentence needs it - the others degrade to silence - but
            // that one is an assertion, and it must not be made out of
            // a figure the daemon has not fetched.
            "ledger_cold": !ledger.loaded,
            "last_compact": ledger.last_compact_at.map(|at| json!({
                "at": at, "freed_bytes": ledger.last_compact_freed,
            })),
            "evicted": (ledger.evicted_rows > 0).then(|| json!({
                "rows": ledger.evicted_rows,
                "live_bytes": ledger.evicted_bytes,
            })),
        })
    })
}

fn m_predb_stats(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let counts = d.with_index_read(|ix| {
            let (lines, nameable) = ix.predb_stats().ok()?;
            Some((lines, nameable, ix.predb_named_count().unwrap_or(0)))
        });
        json!({
            "enabled": d.predb.enabled.load(Ordering::Relaxed),
            // Both switches are needed; the UI says which one
            // is missing rather than showing a feed that
            // silently does nothing.
            "index_enabled": d.index_enabled.load(Ordering::Relaxed),
            "server": d.predb.server.lock_ok().clone(),
            "channels": d.predb.channels.lock_ok().clone(),
            "status": d.predb.status.lock_ok().clone(),
            "pending": d.predb.pending.lock_ok().len(),
            "lines": counts.map(|c| c.0),
            "nameable": counts.map(|c| c.1),
            "named": counts.map(|c| c.2),
            // Phase 2 correlation: switches, the precision meter
            // (confirmed:rejected is the number that earns or
            // loses the auto tier), and the seed importer's state.
            "corr_enabled": d.predb.corr_enabled.load(Ordering::Relaxed),
            "corr_auto": d.predb.corr_auto.load(Ordering::Relaxed),
            "corr": d.with_index_read(|ix| ix.predb_corr_stats().ok())
                .map(|counts| {
                    counts.into_iter()
                        .map(|(k, v)| (k, json!(v)))
                        .collect::<serde_json::Map<String, Value>>()
                }),
            "seed_running": d.predb.seed_running.load(Ordering::Relaxed),
            "seed_status": d.predb.seed_status.lock_ok().clone(),
        })
    })
}

/// The byte-probe naming lane's readout (TODO 131 B3). Its own mode for
/// the same reason predb_stats is: index_stats is polled every few
/// seconds by every open dashboard, and this is read when someone is
/// looking at the lane. The daily numbers are the point - this band is
/// one automated reposter's output, and a cadence stop or header
/// encryption appearing must be visible the day it happens.
fn m_probe7z_stats(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    Some(json!({
        "enabled": d.index_probe7z.load(Ordering::Relaxed),
        "index_enabled": d.index_enabled.load(Ordering::Relaxed),
        "budget": d.index_probe7z_budget.load(Ordering::Relaxed),
        "stats": d.with_index_read(|ix| Some(ix.probe7z_stats(now))),
    }))
}

/// The shatter fold's census plus the indexer-confirm lane's budget
/// readout (TODO 161). One mode for both because the second is gated
/// on the first: a scattered fragment carries no believable size, and
/// the confirm lane only ever sees suggestions strong enough to have
/// one. Same polled-settings-card contract as probe7z_stats.
fn m_corr_confirm_stats(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let today = (epoch_secs() as i64).div_euclid(86_400);
    // The picker deliberately keeps a vanished account listed so the
    // box shows the truth, which means the card needs the daemon's live
    // verdict alongside the string.
    let source = d.corr_confirm_source.lock_ok().clone();
    let source_state = d.corr_confirm_source_state();
    // index_read_checked, not with_index_read: a saturated read pool
    // must report busy, or known-nonzero fold totals and daily spend
    // render as exact zeroes until the next poll.
    let census = d.index_read_checked(|ix| {
        // Read-only view of the day budget: a stale day reads as 0
        // spent, the reset itself belongs to the lane.
        let day: i64 = ix
            .kv_get("corr_confirm_day")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let spent = if day == today {
            ix.kv_get("corr_confirm_spent")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0)
        } else {
            0
        };
        Some((spent, ix.shatter_fold_stats()))
    });
    let (busy, spent_today, fold) = match census {
        Ok(Some((spent, fold))) => (false, Some(spent), Some(fold)),
        Ok(None) => (false, None, None),
        Err(_) => (true, None, None),
    };
    // The budget the lane will ACTUALLY spend, not the floor constant.
    // This reported `CONFIRM_PER_DAY` until 2 Sep 2026, which was right
    // while 24 WAS the ceiling; the 1 Sep ruling made the ceiling
    // derived from the reference account's own quotas
    // (`confirm_budget`, up to 400 on an unmetered account) and this
    // line was not moved with it. An operator watching `spent_today`
    // against it therefore saw the lane sail past its stated limit by
    // up to 16x - found the same day by reading this surface after
    // switching the lane on and comparing it with the daemon's own
    // "up to 400 lookup(s)/day" line, which was already correct.
    //
    // `null` when no account resolves, matching `source_state`: the
    // lane is inert then, and a number would name a budget nothing can
    // spend. That is the same reason the reference is resolved here
    // rather than defaulted - a broken setting must read as broken.
    let per_day = d
        .corr_confirm_reference()
        .ok()
        .map(|cfg| crate::indexers::confirm_budget(&cfg));
    Some(json!({
        "index_enabled": d.index_enabled.load(Ordering::Relaxed),
        "enabled": d.corr_confirm_enabled.load(Ordering::Relaxed),
        "source": source,
        "source_state": source_state,
        "per_day": per_day,
        "busy": busy,
        "spent_today": spent_today,
        "fold": fold,
    }))
}

/// What ingest THREW AWAY, as running `kv` totals (the drop census).
///
/// Its own mode, for the reason `predb_stats` and `probe7z_stats` have
/// theirs: `index_stats` is polled every few seconds by every open
/// dashboard, and this is read when somebody is asking a question about
/// the band, not continuously. It is not on `/metrics` either - that
/// endpoint may not touch the index at all, a scrape being a poll loop,
/// and these totals live in the index's `kv` table.
///
/// The counters have been written since 31 Aug 2026 and NOTHING outside
/// a unit test read one until this existed. On the live index that is
/// 5.8M no-filename drops - the whole fully-subject-obfuscated band,
/// which is the number the no-filename admission decision was taken to
/// answer and could not be read from any shipped surface.
///
/// `index_read_checked`, not `with_index_read`, exactly as
/// `corr_confirm_stats` does it: on a saturated read pool this has to
/// say `busy`, or known-nonzero lifetime totals render as confident
/// zeroes and the answer looks like "nothing was dropped".
fn m_index_drops(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    // Three distinguishable answers, and they must stay distinguishable:
    // a saturated read pool is `busy`, an indexer that is off has no
    // census at all, and a scan that FAILED says so - a census of
    // confident zeroes would read as "nothing was dropped".
    // Both censuses in ONE read, and one error path: they are two scans
    // of the same kv table, so a database that cannot answer the first
    // cannot answer the second either, and two `error` fields would be
    // a distinction nothing can produce. `gen_depth` sits BESIDE
    // `dropped` and `over_budget`, never inside them - `slots` is not a
    // drop and `rows` (generation rows MINTED) is the opposite of one,
    // so `dropped_total` must keep summing exactly the three
    // outright-drop counters. It carries its own `since` / `window_known`
    // because the two censuses are stamped independently.
    let read = d.index_read_checked(|ix| {
        Some(ix.ingest_drop_census().and_then(|mut c| {
            let g = ix.gen_depth_census()?;
            if let Some(o) = c.as_object_mut() {
                o.insert("gen_depth".to_string(), g);
            }
            Ok(c)
        }))
    });
    let (busy, census, error) = match read {
        Err(_) => (true, None, None),
        Ok(None) => (false, None, None),
        Ok(Some(Ok(v))) => (false, Some(v), None),
        Ok(Some(Err(e))) => (false, None, Some(e.to_string())),
    };
    Some(json!({
        "index_enabled": d.index_enabled.load(Ordering::Relaxed),
        "busy": busy,
        "census": census,
        "error": error,
    }))
}

/// The pesto tiny-PAR2 rung's readout (TODO 131 red-team 5a). Same
/// rationale as probe7z_stats: the band is one poster tool's output,
/// and the daily numbers ARE the early warning - `parsefail` rising
/// means the tool changed shape (its own canary, distinct from
/// `notpar2` noise), `named` falling to zero means the sidecars
/// stopped or the MID grammar moved and the lane needs re-derivation.
fn m_pesto_stats(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    Some(json!({
        "enabled": d.index_pesto.load(Ordering::Relaxed),
        "index_enabled": d.index_enabled.load(Ordering::Relaxed),
        "budget": d.index_pesto_budget.load(Ordering::Relaxed),
        "stats": d.with_index_read(|ix| Some(ix.pesto_stats(now))),
    }))
}

/// §131 D3 search-miss readout: the queries this index was asked for
/// and answered with nothing (or with almost nothing), worst first.
///
/// The point of the list is that it tells the scanner what to deepen
/// or backfill next, and it tells the naming lanes which vocabulary
/// they are short of. Acting on it is a human's job - nothing here
/// starts a scan.
///
/// `with_index_read`, like every other settings-card readout: this is
/// polled by whoever has the page open, and parking an HTTP worker
/// behind a scan batch for a counter is the 28 Jul wedge.
fn m_search_misses(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let days = params
            .get("days")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(30)
            .clamp(1, 365);
        // How few results still counts as a miss. 0 is only the true
        // zeroes; 3 is the useful "we technically matched something,
        // but not what they wanted" setting.
        let thin = params
            .get("thin")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0)
            .min(1_000);
        let limit = params
            .get("limit")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(50)
            .clamp(1, 500);
        let surface = params
            .get("surface")
            .map(String::as_str)
            .filter(|s| matches!(*s, "wall" | "newznab"))
            .map(String::from);
        let now = epoch_secs() as i64;
        let since = now - days * 86_400;
        let rows = d
            .with_index_read(|ix| {
                ix.search_misses(since, thin, surface.as_deref(), limit)
                    .ok()
            })
            .unwrap_or_default();
        let summary = d
            .with_index_read(|ix| ix.search_log_summary(since, thin).ok())
            .unwrap_or_default();
        json!({
            "enabled": d.index_search_log.load(Ordering::Relaxed),
            "index_enabled": d.index_enabled.load(Ordering::Relaxed),
            "window_days": days,
            "thin": thin,
            "surface": surface,
            // Retention, echoed so the readout can say what it is a
            // window ONTO rather than implying it holds everything.
            "keep_days": crate::SEARCH_LOG_DAYS,
            "keep_rows": crate::SEARCH_LOG_ROWS,
            "searches": summary.searches,
            "distinct": summary.distinct,
            "zero_searches": summary.zero_searches,
            // Distinct queries still unanswered, and the ones the
            // scanner has since caught up with - the second number is
            // what says whether deepening is working.
            "missing": summary.missing,
            "resolved": summary.resolved,
            "miss_pct": if summary.searches > 0 {
                (summary.zero_searches as f64 * 100.0 / summary.searches as f64 * 10.0)
                    .round() / 10.0
            } else { 0.0 },
            "misses": rows.iter().map(|m| json!({
                "q": m.q,
                "surface": m.surface,
                "kind": m.kind,
                "n": m.n,
                "zero_n": m.zero_n,
                "first_at": m.first_at,
                "last_at": m.last_at,
                "last_hits": m.last_hits,
                "best_hits": m.best_hits,
            })).collect::<Vec<_>>(),
        })
    })
}

/// Forget every recorded search, without touching the setting. The
/// switch itself clears too (see `apply_setting`); this is the "clear
/// it but keep recording" half.
fn m_search_log_clear(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(match d.clear_search_log() {
        Ok(cleared) => json!({"status": true, "cleared": cleared}),
        // TODO 166: the delete did NOT happen, so say so and let the
        // user click again - never park this worker on the write mutex
        // for a whole ingest, and never report a clear that was not.
        Err(why) => why.refusal(),
    })
}

fn m_scoreboard(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Rolling window, default 30 days of samples.
        let days = params
            .get("days")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(30)
            .clamp(1, 365);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        let since = now - days * 86_400;
        let stats = d.with_index_read(|ix| ix.scoreboard_stats(since).ok());
        let kv_num = |k: &str| {
            d.with_index_read(|ix| ix.kv_get(k))
                .and_then(|v| v.parse::<i64>().ok())
        };
        // The band's measured precision, from the opt-in calibration
        // subset: how often the size+time presence estimate agreed
        // with a subject-stem exact check. This is the error bar the
        // coverage estimate must be quoted with - have_unnamed is an
        // ESTIMATE, never a hard number.
        let cal_total = kv_num("scoreboard_cal_total").unwrap_or(0);
        let cal_ok = kv_num("scoreboard_cal_band_ok").unwrap_or(0);
        // The chosen indexer-account reference, by name, and whether it
        // resolves RIGHT NOW - the dashboard's instant answer, since the
        // sampler's status line only updates on its five-minute poll.
        // Truth lives in Daemon::scoreboard_reference; this mirrors its
        // named-entry rule (exists AND enabled) for display.
        let sb_source = d.scoreboard.source.lock_ok().clone();
        let sb_source_ok = !sb_source.is_empty()
            && d.indexers
                .lock_ok()
                .iter()
                .any(|i| i.enabled && i.name == sb_source);
        // What the day actually costs, and the menu it was picked from.
        // `cats` is the resolved subset (never wider than `all_cats`,
        // never empty), `requests_per_day` is its length said plainly -
        // the card must be able to quote the cost without re-deriving
        // it, and a category left out of `cats` must be drawn as NOT
        // MEASURED rather than as zero coverage.
        let sb_cats: Vec<&str> = d
            .scoreboard_categories()
            .into_iter()
            .map(|(_, label)| label)
            .collect();
        json!({
            "enabled": d.scoreboard.enabled.load(Ordering::Relaxed),
            "cats": sb_cats,
            "all_cats": SCOREBOARD_CATEGORIES.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            "requests_per_day": sb_cats.len(),
            "index_enabled": d.index_enabled.load(Ordering::Relaxed),
            // The URL is safe to echo (the key is not, and never is).
            "url": d.scoreboard.url.lock_ok().clone(),
            "has_key": d.scoreboard.key.lock_ok().is_some(),
            "source": sb_source,
            "source_ok": sb_source_ok,
            "calibrate": d.scoreboard.calibrate.load(Ordering::Relaxed),
            "running": d.scoreboard.running.load(Ordering::Relaxed),
            "status": d.scoreboard.status.lock_ok().clone(),
            "last_run": kv_num("scoreboard_last_run"),
            "cooling_until": kv_num("scoreboard_cooling").filter(|t| *t > now),
            "window_days": days,
            "categories": stats.map(|cats| cats.into_iter().map(|c| json!({
                "category": c.category,
                "total": c.total,
                "have_named": c.have_named,
                "have_unnamed": c.have_unnamed,
                "missing": c.missing,
                // Convenience percentages; the raw counts are above.
                "named_pct": if c.total > 0 {
                    (c.have_named as f64 * 100.0 / c.total as f64 * 10.0).round() / 10.0
                } else { 0.0 },
                "coverage_pct": if c.total > 0 {
                    ((c.have_named + c.have_unnamed) as f64 * 100.0
                        / c.total as f64 * 10.0).round() / 10.0
                } else { 0.0 },
                "lag_median_secs": c.lag_median_secs,
            })).collect::<Vec<_>>()),
            "calibration": json!({
                "checked": cal_total,
                "band_agreed": cal_ok,
            }),
        })
    })
}

fn m_pre_candidates(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id = params.get("id").and_then(|v| v.parse::<i64>().ok())?;
        // index_read_checked, not with_index_read: a busy pool must not
        // answer an empty candidates list as success.
        let cands = match d.index_read_checked(|ix| ix.pre_candidates(id, 8).ok()) {
            Err(why) => {
                return Some(why.refusal());
            }
            Ok(cands) => cands.unwrap_or_default(),
        };
        json!({"candidates": cands.into_iter().map(
                |(pid, name, score, delta, ratio, nuked, source)| json!({
                    "predb_id": pid, "name": name, "score": score,
                    "delta": delta, "ratio": ratio as f64 / 1000.0,
                    "nuked": nuked, "source": source,
                })).collect::<Vec<_>>()})
    })
}

fn m_pre_assign(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id = params.get("id").and_then(|v| v.parse::<i64>().ok())?;
        let pid = params.get("predb_id").and_then(|v| v.parse::<i64>().ok())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        match d.index_write_checked(|ix| ix.pre_assign(id, pid, now).ok()) {
            Ok(w) => json!({"status": w.unwrap_or(false)}),
            // TODO 166: the pairing was not stored. "That did not
            // stick" is true either way, but only this arm can tell the
            // user it is worth pressing again.
            Err(why) => why.refusal(),
        }
    })
}

fn m_pre_reject(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id = params.get("id").and_then(|v| v.parse::<i64>().ok())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        match d.index_write_checked(|ix| ix.pre_reject(id, now).ok()) {
            Ok(w) => json!({"status": w.is_some()}),
            Err(why) => why.refusal(),
        }
    })
}

fn m_predb_seed_start(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let days = params
            .get("days")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or_else(|| d.predb.seed_days.load(std::sync::atomic::Ordering::Relaxed) as u32)
            .clamp(1, 366);
        let started = super::super::predb_seed::spawn_seed_import(d.clone(), days);
        json!({
            "status": started,
            "seed_status": d.predb.seed_status.lock_ok().clone(),
        })
    })
}

fn m_index_scan_now(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        if let Some(n) = params.get("value").and_then(|v| v.parse::<u64>().ok())
            && n > 0
        {
            d.scan_deep.store(n, Ordering::Relaxed);
        }
        d.scan_now.notify_one();
        json!({"status": true})
    })
}

fn m_debug_hold_index(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let secs = params
            .get("value")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30)
            .min(120);
        // index-lock-gate: TODO 166 - the `debug_hold_index` test
        // fixture, whose entire purpose is to hold the write mutex
        // so the daemon_indexbusy legs can prove the bounded doors
        // report busy rather than parking.
        let held = d
            .with_index(|_| {
                std::thread::sleep(std::time::Duration::from_secs(secs));
                Some(true)
            })
            .unwrap_or(false);
        json!({"held": held, "secs": secs})
    })
}

fn m_debug_hold_index_read(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let secs = params
            .get("value")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30)
            .min(120);
        match d.index_read_checked(|_| {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            Some(true)
        }) {
            Ok(held) => json!({"held": held.unwrap_or(false), "secs": secs}),
            Err(_) => json!({"held": false, "busy": true, "secs": secs}),
        }
    })
}

/// Run a query with no end on a pooled read connection, so a test can
/// prove what TODO 300's budget does to one.
///
/// The third of these fixtures and the only one that is actually inside
/// SQLite. `debug_hold_index_read` above SLEEPS on a borrowed
/// connection, which is the right shape for "the pool is occupied" and
/// the wrong one here: a progress callback runs between VM
/// instructions, so a sleeping handler is not something a budget can
/// interrupt, and a test built on it would pass against a daemon that
/// had lost the mechanism entirely.
fn m_debug_slow_index_read(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let started = std::time::Instant::now();
        match d.index_read_checked(|ix| {
            // Discarded on purpose: this is the `.ok()` every query
            // endpoint does, and the whole point of the trip stamp is
            // that it survives the flattening.
            let _ = ix.debug_endless_query();
            Some(true)
        }) {
            Ok(_) => json!({"status": true, "ran": true, "ms": started.elapsed().as_millis()}),
            // The refusal body plus this fixture's own stamp: the
            // extra field is ADDED to the one copy rather than made a
            // second literal of it.
            Err(why) => {
                let mut v = why.refusal();
                v["ms"] = json!(started.elapsed().as_millis());
                v
            }
        }
    })
}

/// Arm the read-pool fault injector: the next `value` pooled index
/// reads succeed, every read after that reports the pool busy.
///
/// The sibling of `debug_hold_index_read`, for the case holding
/// connections cannot reach: a handler whose FIRST index read succeeds
/// and whose SECOND is refused. Holding the pool from another request
/// can only ever make the first one busy.
fn m_debug_index_read_busy(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let n = params
            .get("value")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        Daemon::arm_debug_read_budget(n);
        json!({"status": true, "armed": n})
    })
}

fn m_index_wipe(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        if params.get("value").map(String::as_str) != Some("wipe") {
            json!({"status": false, "error": "pass value=wipe to confirm"})
        } else {
            // Retire the generation FIRST. A scan pass holds a
            // dedicated connection and reopens the shared one
            // when it exits; without this it recreated the
            // database we just deleted, moments after the API
            // said it was gone.
            let mut failed: Vec<String> = Vec::new();
            {
                let mut guard = d.index.lock_ok();
                d.index_generation.fetch_add(1, Ordering::SeqCst);
                *guard = None;
                for suffix in ["", "-wal", "-shm"] {
                    let p = PathBuf::from(format!("{}{suffix}", d.index_db.display()));
                    // Report what did not go. On Windows an
                    // open handle makes this fail outright,
                    // and answering `true` over a database
                    // still sitting on disk is the one thing
                    // a corruption-recovery button must not
                    // do.
                    if let Err(e) = std::fs::remove_file(&p)
                        && e.kind() != std::io::ErrorKind::NotFound
                    {
                        failed.push(format!("{}: {e}", p.display()));
                    }
                }
                // AFTER the removes: a query re-opening the
                // read-only handle a beat earlier would pin
                // the deleted inode and keep serving the
                // wiped rows; dropping it last closes any
                // such straggler too.
                d.drop_index_read();
                // A4: the generation bump above already
                // orphans the cached stats, but install the
                // truth - zero - synchronously so the next
                // poll serves it instead of paying a
                // recompute against the recreated file. A
                // refresh in flight keeps its flag; its
                // result fails the era check and is dropped.
                let mut c = d.index_stats_cache.lock_ok();
                c.snap = Some((0, 0, 0, 0));
                c.at = Some(std::time::Instant::now());
                c.era = d.index_era();
                drop(c);
                // A logical-capacity marker describes the generation just
                // deleted. Reactivate it before releasing the same index lock
                // so an old worker verdict cannot latch the fresh database.
                if let Err(error) = crate::seed_harvest::reactivate_indexer_generation_holds(d) {
                    failed.push(format!(
                        "commercial NZB seed capacity reactivation: {error}"
                    ));
                }
            }
            let art = d.spool.join("art");
            if let Err(e) = std::fs::remove_dir_all(&art)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                failed.push(format!("{}: {e}", art.display()));
            }
            if failed.is_empty() {
                // The ledger's facts were about the file that just went.
                // Memory only, so this takes no index handle.
                d.reset_index_ledger();
                info!(
                    target: "index",
                    "{} wiped by request - rescan starts next cycle",
                    d.index_db.display()
                );
                json!({"status": true})
            } else {
                let why = failed.join("; ");
                warn!(target: "index", "wipe incomplete: {why}");
                json!({
                    "status": false,
                    "error": format!("the index was not fully removed - {why}"),
                })
            }
        }
    })
}

fn m_index_compact(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Jobs in flight rather than started_at, which reads None
        // between queued jobs while the pipeline is still busy -
        // the same trap c69eb45a closed for the idle loop.
        if d.index_jobs_active.load(Ordering::Acquire) > 0 || !d.scan_progress.lock_ok().is_empty()
        {
            json!({"status": false,
                               "error": "busy - retry when no download or scan is running"})
        } else {
            let before = std::fs::metadata(&d.index_db).map(|m| m.len()).unwrap_or(0);
            // index-lock-gate: TODO 166 - an explicit admin compact. The
            // user asked for the work; waiting for it is the honest answer.
            let ok = d.with_index(|ix| ix.compact().ok()).is_some();
            let after = std::fs::metadata(&d.index_db).map(|m| m.len()).unwrap_or(0);
            let freed = before.saturating_sub(after);
            if ok {
                // Memory only, and no index handle - so this adds no
                // reach to a handler that TODO 166's gate already
                // classifies as an explicit admin action.
                d.note_compact(freed);
                info!(target: "index", "compacted - {} MB reclaimed", freed / (1 << 20));
                // An explicit compact answers whatever a prune
                // deferred, so the idle loop has nothing left to do.
                d.compact_pending.store(false, Ordering::Relaxed);
            } else {
                warn!(target: "index", "manual compact failed");
            }
            json!({"status": ok, "freed_bytes": freed})
        }
    })
}

fn m_index_shrink_to(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        match params.get("value").and_then(|v| parse_size(v)) {
            None => json!({"status": false,
                                       "error": "pass value=<size>, e.g. value=20G"}),
            Some(target) => {
                // The target is a promise about disk, so it is
                // measured against live_bytes - the size the
                // file takes once compacted. bytes_* below
                // still report the file itself, which is what
                // the user sees in Finder.
                // index-lock-gate: TODO 166 - an explicit admin shrink, and
                // these two readouts are part of the same action, reporting
                // on work that blocks anyway.
                let live = d.with_index(|ix| ix.live_bytes().ok()).unwrap_or(0);
                let before = d.with_index(|ix| ix.db_bytes().ok()).unwrap_or(0);
                if live <= target {
                    json!({
                        "status": true, "removed": 0,
                        "bytes_before": before, "bytes_after": before,
                        "live_bytes_before": live, "live_bytes_after": live,
                        "target_bytes": target, "reached": true,
                        "blocked": false,
                        "compact_pending":
                            d.compact_pending.load(Ordering::Relaxed),
                    })
                } else {
                    match d.evict_to(target) {
                        EvictOutcome::Unavailable | EvictOutcome::Nothing => {
                            json!({"status": false,
                                               "error": "index unavailable"})
                        }
                        EvictOutcome::Ran(rep, n_prot) => {
                            // A4: the stats cache still holds the
                            // pre-shrink counts; expire it so the
                            // dashboard's follow-up poll recomputes
                            // instead of serving them out the TTL.
                            d.expire_index_stats();
                            let reached = rep.live_after <= target;
                            json!({
                                "status": true,
                                "removed": rep.removed,
                                "bytes_before": rep.bytes_before,
                                "bytes_after": rep.bytes_after,
                                "live_bytes_before": rep.live_before,
                                "live_bytes_after": rep.live_after,
                                "target_bytes": target,
                                "reached": reached,
                                // Stopped on purpose rather
                                // than short of the estimate:
                                // another pass would not help.
                                "blocked": rep.blocked,
                                "protected_keys": n_prot,
                                "compact_pending":
                                    d.compact_pending.load(Ordering::Relaxed),
                                // Protection is absolute: we
                                // stop short rather than take
                                // a watchlisted, queued,
                                // downloaded or recently
                                // opened release. Say which.
                                "error": (!reached)
                                    .then(|| shrink_shortfall_reason(n_prot)),
                            })
                        }
                    }
                }
            }
        }
    })
}

/// The dry run: what WOULD an eviction at the current cap (or an
/// explicit `value=<size>`) remove? Deletes nothing - the engine walks
/// the same candidate order and stops where the real pass would.
fn m_index_evict_preview(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let target = match params.get("value").map(String::as_str) {
            Some(v) => match parse_size(v) {
                Some(t) => t,
                None => {
                    return Some(json!({"status": false,
                        "error": "pass value=<size>, e.g. value=20G"}));
                }
            },
            None => d.index_max_bytes.load(Ordering::Relaxed),
        };
        if target == 0 {
            json!({"status": false,
                "error": "index_max_bytes is 0 (unlimited) - set a cap, \
                          or ask with an explicit value=<size>"})
        } else {
            match d.evict_preview_at(target) {
                None => json!({"status": false, "error": "index unavailable"}),
                Some((pv, n_prot)) => json!({
                    "status": true,
                    "target_bytes": pv.target_bytes,
                    "low_bytes": pv.low_bytes,
                    "live_bytes": pv.live_bytes,
                    "rows": pv.rows,
                    "est_bytes": pv.est_bytes,
                    "by_kind": pv.by_kind.iter().map(|(k, n, b)| json!({
                        "kind": k, "rows": n, "est_bytes": b,
                    })).collect::<Vec<_>>(),
                    "reachable": pv.reachable,
                    "truncated": pv.truncated,
                    "protected_keys": n_prot,
                    "protected_skipped": pv.protected_skipped,
                }),
            }
        }
    })
}

fn m_index_evict_now(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        if !d.index_evict.load(Ordering::Relaxed) {
            json!({"status": false,
                               "error": "automatic eviction is off - turn on index_evict, \
                                         or use index_shrink_to with an explicit size"})
        } else if d.index_max_bytes.load(Ordering::Relaxed) == 0 {
            json!({"status": false,
                               "error": "index_max_bytes is 0 (unlimited) - set a cap first"})
        } else {
            let cap = d.index_max_bytes.load(Ordering::Relaxed);
            // index-lock-gate: TODO 166 - an explicit admin eviction, and
            // these two readouts are part of the same action, reporting on
            // work that blocks anyway.
            let before = d.with_index(|ix| ix.db_bytes().ok()).unwrap_or(0);
            let live = d.with_index(|ix| ix.live_bytes().ok()).unwrap_or(0);
            match d.evict_pass() {
                // Already under the cap: nothing to do, and
                // that is a success, not an error.
                EvictOutcome::Nothing => json!({
                    "status": true, "removed": 0,
                    "bytes_before": before, "bytes_after": before,
                    "live_bytes_before": live, "live_bytes_after": live,
                    "index_max_bytes": cap, "reached": live <= cap,
                    "blocked": false,
                    "compact_pending":
                        d.compact_pending.load(Ordering::Relaxed),
                }),
                EvictOutcome::Unavailable => {
                    json!({"status": false, "error": "index unavailable"})
                }
                EvictOutcome::Ran(rep, n_prot) => {
                    // A4: same cache expiry as index_shrink_to above.
                    d.expire_index_stats();
                    let reached = rep.live_after <= cap;
                    json!({
                        "status": true,
                        "removed": rep.removed,
                        "bytes_before": rep.bytes_before,
                        "bytes_after": rep.bytes_after,
                        "live_bytes_before": rep.live_before,
                        "live_bytes_after": rep.live_after,
                        "index_max_bytes": cap,
                        "reached": reached,
                        "blocked": rep.blocked,
                        "protected_keys": n_prot,
                        "compact_pending":
                            d.compact_pending.load(Ordering::Relaxed),
                        "error": (!reached)
                            .then(|| shrink_shortfall_reason(n_prot)),
                    })
                }
            }
        }
    })
}

fn m_groups(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");
        let cat = d.group_catalog.lock_ok().clone();
        let err = d.group_fetch_err.lock_ok().clone();
        match cat {
            None => {
                // Only auto-kick while there's no error to
                // show: a dead server must not turn every
                // poll into a reconnect storm.
                if err.is_none() {
                    kick_group_fetch(d, ctx.cfg_path.to_path_buf());
                }
                json!({
                    "status": true,
                    "fetching": d.group_fetching.load(Ordering::Relaxed),
                    "fetched_at": 0, "total": 0, "count": 0,
                    "groups": [], "error": err,
                })
            }
            Some(cat) => {
                let subscribed: std::collections::HashSet<String> =
                    d.index_groups.lock_ok().iter().cloned().collect();
                let stats = d.group_stats.lock_ok().clone();
                let q = crate::groups::Query {
                    q: get("q"),
                    new_only: get("new") == "1",
                    binaries_only: get("bin") == "1",
                    min_posts: get("minposts").parse().unwrap_or(0),
                    only: (get("sub") == "1").then_some(&subscribed),
                    cat: crate::groups::Category::parse(get("cat")),
                    stats: Some(&stats),
                    kind: crate::groupstats::Kind::parse(get("kind")),
                    active_days: get("activedays").parse().unwrap_or(0),
                    with_desc: get("desc") == "1",
                    sort: crate::groups::Sort::parse(get("sort")),
                    desc_order: get("dir") != "asc",
                    offset: get("offset").parse().unwrap_or(0),
                    limit: get("limit").parse().unwrap_or(50),
                };
                // Subscribed-only view (tin's `y`): one toggle
                // between "the groups I scan" and the whole
                // server, rather than a separate screen. The
                // restriction rides in the query (see
                // Query::only) so paging stays correct.
                let (total, page) = cat.query(&q);
                let is_new =
                    |fs: i64| fs > 0 && cat.fetched_at - fs < crate::groups::NEW_WINDOW_SECS;
                let new_total = cat.groups.iter().filter(|g| is_new(g.first_seen)).count();
                json!({
                    "status": true,
                    "fetching": d.group_fetching.load(Ordering::Relaxed),
                    "fetched_at": cat.fetched_at,
                    "total": total,
                    "count": cat.groups.len(),
                    "error": err,
                    "new_total": new_total,
                    "sampled": stats.map.len(),
                    "groups": page.iter().map(|g| {
                        // Sampled facts ride along when we have
                        // them; absent keys mean "not sampled
                        // yet", which the UI renders as a dash
                        // rather than as a zero.
                        let s = stats.get(&g.name);
                        json!({
                            "name": g.name, "posts": g.posts,
                            "desc": g.desc, "cat": g.cat.key(),
                            "sub": subscribed.contains(&g.name),
                            "new": is_new(g.first_seen),
                            "status": g.status.to_string(),
                            "avg_bytes": s.map(|s| s.avg_bytes),
                            "est_bytes": s.map(|s| s.est_bytes),
                            "last_post": s.map(|s| s.last_post),
                            "per_day": s.map(|s| s.per_day),
                            "kind": s.and_then(|s| s.dominant()).map(|k| k.key()),
                            "sampled_at": s.map(|s| s.sampled_at),
                        })
                    }).collect::<Vec<_>>(),
                })
            }
        }
    })
}

fn m_interests(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let chosen = crate::interests::parse(&d.index_interests.lock_ok().clone());
        let cat = d.group_catalog.lock_ok().clone();
        let carried: Option<std::collections::HashSet<&str>> = cat
            .as_ref()
            .map(|c| c.groups.iter().map(|g| g.name.as_str()).collect());
        let subscribed: std::collections::HashSet<String> =
            d.index_groups.lock_ok().iter().cloned().collect();
        json!({
            "status": true,
            // Whether a provider group list is known yet. The
            // wizard runs before one exists, so the UI has to
            // be able to say "these will be checked against
            // your provider" rather than promise a count.
            "resolved": carried.is_some(),
            "chosen": chosen,
            "options": crate::interests::INTERESTS.iter().map(|i| json!({
                "key": i.key,
                "groups": i.groups,
                // Which of them this provider actually has,
                // once we know. Absent = not checked yet.
                "carried": carried.as_ref().map(|c| i.groups.iter()
                    .filter(|g| c.contains(**g))
                    .collect::<Vec<_>>()),
                "scanning": i.groups.iter()
                    .filter(|g| subscribed.contains(**g)).count(),
            })).collect::<Vec<_>>(),
        })
    })
}

fn m_groups_add_matching(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");
        let catalog = d.group_catalog.lock_ok().clone();
        // Same `sub=1` ("Only groups I scan") restriction the
        // list itself applies - the dashboard builds both
        // requests from one query string, so ignoring it here
        // made the button act on a WIDER set than the rows the
        // user was looking at when they pressed it.
        let subscribed: std::collections::HashSet<String> =
            d.index_groups.lock_ok().iter().cloned().collect();
        // The sampled filters have to ride along for the same
        // reason `sub=1` does: the content-kind and
        // still-active filters narrow the rows on screen, so
        // omitting them here would again make the button act
        // on a wider set than the user was looking at.
        let stats = d.group_stats.lock_ok().clone();
        let q = crate::groups::Query {
            q: get("q"),
            new_only: get("new") == "1",
            binaries_only: get("bin") == "1",
            min_posts: get("minposts").parse().unwrap_or(0),
            only: (get("sub") == "1").then_some(&subscribed),
            cat: crate::groups::Category::parse(get("cat")),
            stats: Some(&stats),
            kind: crate::groupstats::Kind::parse(get("kind")),
            active_days: get("activedays").parse().unwrap_or(0),
            with_desc: get("desc") == "1",
            sort: crate::groups::Sort::Posts,
            desc_order: true,
            offset: 0,
            limit: usize::MAX,
        };
        const MAX_BULK: usize = 200;
        match catalog {
            None => json!({"status": false, "error": "no group list yet"}),
            Some(_) if get("q").is_empty() && q.cat.is_none() && !q.new_only => {
                // An unfiltered bulk add would enqueue the whole
                // server into the scan loop. Make the user narrow.
                json!({"status": false,
                               "error": "refusing to add every group - narrow it first"})
            }
            Some(cat) => {
                let (total, hits) = cat.query(&q);
                let mut groups = d.index_groups.lock_ok().clone();
                let before = groups.len();
                for g in hits.iter().take(MAX_BULK) {
                    if !groups.contains(&g.name) {
                        groups.push(g.name.clone());
                    }
                }
                let added = groups.len() - before;
                // apply_setting only updates the LIVE daemon; the
                // mode=config arm pairs it with save_setting, and
                // this one used to drop the returned value on the
                // floor. The scan list was rewritten in memory,
                // the UI said "Added N groups", and the whole bulk
                // subscribe vanished on the next restart.
                //
                // The clone above releases its guard at the end of
                // its own statement: holding it across this call
                // would deadlock on the same Mutex.
                match apply_and_save(d, "index_groups", &groups.join(",")) {
                    Err(e) => json!({"status": false, "error": e}),
                    // saved=false is "live now, reverts at restart" -
                    // dropping it reported a durable subscription over
                    // an unwritable settings dir (Codex sweep 5 Aug L1).
                    Ok((_, saved)) => json!({"status": true, "added": added,
                               "matched": total, "capped": total > MAX_BULK,
                               "warning": (!saved).then(|| format!(
                                   "the scan list could not be written to {} - the added \
                                    groups work now but revert at the next restart",
                                   d.settings_path.display()))}),
                }
            }
        }
    })
}

fn m_group_sample(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let name = params.get("group").cloned().unwrap_or_default();
        let catalog = d.group_catalog.lock_ok().clone();
        // Only groups the server actually carries: `name` is
        // user input that becomes an NNTP GROUP command, and
        // the catalogue is the allowlist.
        let known = catalog
            .as_ref()
            .and_then(|c| c.groups.iter().find(|g| g.name == name))
            .map(|g| g.posts);
        match known {
            None => json!({"status": false, "error": "unknown group"}),
            Some(posts) => {
                let force = params.get("refresh").map(String::as_str) == Some("1");
                let now = epoch_secs() as i64;
                let cached = d.group_stats.lock_ok().get(&name).cloned();
                let stale = force || d.group_stats.lock_ok().is_stale(&name, now);
                if stale {
                    // Handle dropped on purpose: the task detaches and
                    // writes the cache itself. A click must not park an
                    // API worker on a provider round trip - the steady
                    // background pass is the caller that awaits.
                    let _ = kick_group_sample(d, ctx.cfg_path.to_path_buf(), name.clone(), posts);
                }
                let sampling = d.group_sampling.lock_ok().contains(&name);
                match cached {
                    Some(s) => json!({
                        "status": true, "sampling": sampling,
                        "group": name,
                        "sample_n": s.sample_n,
                        "avg_bytes": s.avg_bytes,
                        "est_bytes": s.est_bytes,
                        "last_post": s.last_post,
                        "per_day": s.per_day,
                        "sampled_at": s.sampled_at,
                        "kind": s.dominant().map(|k| k.key()),
                        "samples": s.samples,
                        "mix": crate::groupstats::Kind::ALL.iter()
                            .map(|k| json!({
                                "kind": k.key(),
                                "n": s.kinds[
                                    crate::groupstats::Kind::ALL.iter()
                                        .position(|x| x == k).unwrap()],
                            })).collect::<Vec<_>>(),
                    }),
                    // Nothing cached: the sample is in flight,
                    // the UI polls.
                    None => json!({
                        "status": true, "sampling": true, "group": name,
                    }),
                }
            }
        }
    })
}

fn m_index_search(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let q = params.get("q").cloned().unwrap_or_default();
        // index_read_checked, not with_index_read: a saturated read
        // pool is not "no matches", and the wall already reports the
        // difference (Codex sweep 5 Aug M10). The UI keeps its list
        // on `status:false` and the next poll gets the real answer.
        let hits = match d.index_read_checked(|ix| ix.search(&q, 60).ok()) {
            Err(why) => {
                return Some(why.refusal());
            }
            Ok(hits) => hits.unwrap_or_default(),
        };
        // §131 D3: what was asked, and how much of it we had. Buffered
        // in memory and written by the flush task - never on this
        // handler's read-only connection. A busy index returns above
        // without recording, which is right: that is not a miss.
        d.note_search("wall", &q, "", hits.len());
        let hints = corr_hints(
            d,
            hits.iter().filter(|r| r.pre_title.is_empty()).map(|r| r.id),
        );
        {
            // Parsed name facts ride along so the UI can show
            // quality badges and offer one-click watchlisting.
            let cats = d.custom_categories.read_ok().clone();
            // Classified ONCE, up here, because the art lookup needs
            // every row's title key before the first row is rendered.
            // Doing it inside the map and again for the keys would
            // parse the whole page twice.
            let parsed: Vec<_> = hits
                .iter()
                .map(|r| nzbkit::categories::classify(r.display_name(), &cats))
                .collect();
            // The adult setting is read HERE even though `search()`
            // applies no adult filter of its own. That asymmetry is
            // the point: this list has always shown adult NAMES, and
            // showing an adult POSTER is a different act. See
            // `Index::title_art`.
            let art = row_art(
                d,
                parsed.iter().map(|p| p.key.clone()).collect(),
                d.wall_hide_adult.load(Ordering::Relaxed),
            );
            json!({"results": hits.iter().zip(&parsed).map(|(r, p)| {
                            let name = r.display_name();
                            json!({
                                "id": r.id, "name": name, "group": r.grp,
                                // Provenance, so a rescued name can be
                                // badged rather than shown as if it had
                                // been read off the wire.
                                "pre": r.pre_source,
                                // Phase 2: the best CORRELATED name for
                                // a still-unnamed obfuscated row - a
                                // suggestion, clearly labelled, never
                                // presented as the name.
                                "pre_hint": hints.get(&r.id).cloned()
                                    .unwrap_or(Value::Null),
                                "size": r.total_bytes, "files": r.files,
                                "complete": r.complete, "par2": r.has_par2,
                                "first_seen": r.first_seen,
                                "quality": crate::wall::quality_label(p),
                                "kind": nzbkit::index::kind_str(&p.kind).to_string(),
                                "title": p.title, "year": p.year,
                                // Wall-card dedupe key, the same field
                                // `index_browse` carries - what `art`
                                // below is keyed on.
                                "key": p.key,
                                // Poster thumbnail for this row's
                                // title, '' when the index has none
                                // (or the adult gate withheld it).
                                // Named `art` and not `poster`: on a
                                // RELEASE, "poster" is the person who
                                // posted it (`Release::poster`, the
                                // From: header), and one of those
                                // meanings is already in this file.
                                "art": art.get(&p.key).cloned()
                                    .unwrap_or_default(),
                            })
                        }).collect::<Vec<_>>()})
        }
    })
}

fn m_wall2(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");
        let show_all = get("all") == "1";
        let sort = nzbkit::index::CardSort::parse(get("sort"));
        let mut bq = nzbkit::index::BrowseQuery {
            q: get("q").to_string(),
            complete_only: matches!(get("complete"), "1" | "true"),
            // Title reads naturally ascending; everything else
            // defaults newest/biggest/best first.
            desc: match get("dir") {
                "asc" => false,
                "desc" => true,
                _ => sort != nzbkit::index::CardSort::Title,
            },
            // Curation: junk hidden unless the user flips the
            // "show hidden" toggle (all=1).
            max_junk: (!show_all).then_some(50),
            // M30: hides + learned rules always apply on the
            // wall (the Hidden panel is its own API).
            curated: true,
            // Same tier as the hides and rules: a browsing filter,
            // never applied to the uncurated facades.
            hide_adult: d.wall_hide_adult.load(Ordering::Relaxed),
            limit: 60,
            ..Default::default()
        };
        match get("cat") {
            "" | "all" => {}
            "4k" => {
                bq.kind = Some("movie".into());
                bq.res = Some("2160p".into());
            }
            // Built-in kinds plus user-defined category slugs
            // (lowercase alnum + '-'); the filter is a bound
            // SQL parameter, and an unknown slug just matches
            // nothing.
            k if is_kind_slug(k) => bq.kind = Some(k.to_string()),
            _ => {}
        }
        if let Some(r) = params.get("res").filter(|r| !r.is_empty()) {
            bq.res = Some(r.clone());
        }
        // 24C: card-scoped fetch (&key=<title_key>) - the
        // Releases surface's hover preview and group-by-title
        // rows ask for ONE title's card. Same vocabulary as
        // wall_art/wall_fix; deliberately does NOT mark the
        // title "recently opened" (hovering is not opening -
        // index_browse's title_key path is where that lives).
        if let Some(k) = params.get("key").filter(|k| !k.is_empty()) {
            bq.title_keys = vec![k.clone()];
        }
        // M30: genre chip + category grouping + decade range.
        if let Some(g) = params.get("genre").filter(|g| !g.is_empty()) {
            bq.genre = Some(g.clone());
        }
        if let Ok(n) = get("year_min").parse::<u32>() {
            bq.year_min = n;
        }
        if let Ok(n) = get("year_max").parse::<u32>() {
            bq.year_max = n;
        }
        let catgroup = get("catgroup") == "1";
        if let Ok(n) = get("limit").parse::<u32>() {
            bq.limit = n.clamp(1, 200);
        }
        if let Ok(n) = get("offset").parse::<u32>() {
            bq.offset = n;
        }
        let matched_only = get("matched") != "0";
        // M31b "your wall": the Affinity sort scores against
        // the user's taste profile. Build it (and the owned
        // set) OUTSIDE the index lock - taste_profile() takes
        // that lock itself, so nesting would deadlock. None on
        // cold start -> browse_cards degrades to "most posted".
        let aff_ctx = (sort == nzbkit::index::CardSort::Affinity)
            .then(|| d.affinity_ctx(&d.taste_profile()))
            .flatten();
        // §131 D3: this is a SEARCH only when the user typed
        // something and we are on the first page of it. A `key=`
        // fetch is one card's hover preview, and page 4 is the same
        // search as page 1.
        let note = (!bq.q.trim().is_empty() && bq.offset == 0 && bq.title_keys.is_empty())
            .then(|| (bq.q.clone(), bq.kind.clone().unwrap_or_default()));
        // index_read_checked, not with_index_read: a saturated read
        // pool is not an empty wall, and drawing one as the other is
        // how a busy index comes to be reported as a broken one.
        // An `error` field is the shape wallFetch already handles -
        // it toasts the text and returns WITHOUT re-rendering, so
        // the grid keeps the cards it has and the next poll picks
        // up the real answer. Blanking it is what "no cards" would
        // have done.
        match d.index_read_checked(|ix| {
            ix.browse_cards(&bq, sort, matched_only, catgroup, aff_ctx.as_ref())
                .ok()
        }) {
            Err(why) => why.refusal(),
            Ok(Some((cards, total))) => {
                // The honest count is `total`, not the page: a search
                // that matched 400 cards did not miss because the
                // first page holds 60.
                if let Some((q, kind)) = note {
                    d.note_search("wall", &q, &kind, total as usize);
                }
                // M30: "you have this" card badge - the
                // newest release's dupe key against the
                // library (movies mostly; a show card only
                // badges when its latest episode is owned).
                let owned = d.owned_dupe_keys();
                // M30: whatever the wall is showing without
                // metadata yet gets (a) a titles row - the
                // old mode=wall was the ONLY seeder, so
                // since M28 fresh titles never reached the
                // enricher at all - and (b) a slot in the
                // hot queue, so on-screen titles get art
                // first.
                // try_with_index_mut, not with_index_mut:
                // the seed is a shrug-off side-write, and
                // parking here would hand back the very
                // ingest-holds-the-lock wait the read-only
                // path just avoided. A busy connection skips
                // the seed; the next wall poll re-offers the
                // same cards.
                //
                // That last clause overstates this seed's role
                // and is kept only because it is true of the
                // view where the seed RUNS. The DEFAULT wall is
                // matched-only, which puts `t.checked > 0 AND
                // t.poster != ''` in `browse_cards`' WHERE
                // (`nzbkit::index::cards`), so every card it
                // returns is already enriched, `seeds` is empty
                // and the try_lock below is never attempted at
                // all - measured over 360 consecutive polls on
                // 22 Aug 2026, empty on every one. What seeds
                // fresh posts in that view is the tip watcher's
                // `seed_missing_titles(2, 200)`. This path is
                // reached by the show-unmatched view and by a
                // `key=`-scoped fetch.
                //
                // ONE transaction for the whole page, not one
                // autocommit INSERT per card. Winning that
                // try_lock does not win the SQLite WRITE lock,
                // and every autocommit had to take that for
                // itself: on a fresh index each one could sit
                // out the full 10 s busy_timeout behind a scan
                // chunk's IMMEDIATE transaction, so a page of
                // 60 unenriched cards was 60 chances to stall
                // an interactive poll. Now it is one lock
                // acquisition and one WAL commit.
                //
                // Built first, so a page with nothing to seed
                // - the steady state - never opens the index
                // at all.
                let seeds: Vec<nzbkit::index::TitleSeed> = cards
                    .iter()
                    .filter(|c| c.checked == 0)
                    .map(|c| {
                        let p = crate::wall::parse_release(&c.rep_stem);
                        nzbkit::index::TitleSeed {
                            key: c.title_key.clone(),
                            kind: c.kind.clone(),
                            title: if c.title.is_empty() {
                                p.title.clone()
                            } else {
                                c.title.clone()
                            },
                            year: if c.year > 0 {
                                c.year
                            } else {
                                p.year.unwrap_or(0)
                            },
                        }
                    })
                    .collect();
                if !seeds.is_empty() {
                    d.try_with_index_mut(|ix| ix.title_seed_many(&seeds).ok());
                    let mut hot = d.enrich_hot.lock_ok();
                    for s in &seeds {
                        if !hot.contains(&s.key) {
                            hot.push_back(s.key.clone());
                        }
                    }
                    while hot.len() > 120 {
                        hot.pop_front();
                    }
                }
                let art_dir = d.spool.join("art");
                // M29: availability verdict per card, from the
                // newest release's group family × post age.
                let ocx = d.oracle_ctx(ctx.cfg_path);
                // M29 3d: families in an active takedown wave
                // (fresh posts confidently gone) - the wall
                // flags their cards as "being reaped".
                let reaped: std::collections::HashSet<String> = ocx
                    .as_ref()
                    .map(|(s, b)| s.reaped_families(b).into_iter().map(|r| r.family).collect())
                    .unwrap_or_default();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|t| t.as_secs() as i64)
                    .unwrap_or(0);
                json!({
                    "total": total,
                    "offset": bq.offset,
                    // U4: the empty wall needs to say WHY it is empty.
                    // `groups` separates "no newsgroups chosen" from
                    // "chosen, index still filling"; `scanning` says a
                    // scan pass is mid-flight right now.
                    //
                    // `scanning` alone is the wrong question for the
                    // empty state: it is false for the whole post-pass
                    // SQLite section and the gap between passes, so a
                    // healthy install reads as idle half the time. What
                    // that state has to tell apart is scanning-in-
                    // progress from scanning-not-happening-at-all, and
                    // that is the stand-down reason (Codex sweep 7, L1).
                    "groups": d.index_groups.lock_ok().len(),
                    "scanning": d.scan_active.load(Ordering::Relaxed),
                    "idxpaused": d.indexing_pause_reason().is_some(),
                    // 24D: the dynamic category set - the UI
                    // renders one tab chip per entry.
                    "cats": d.custom_categories.read_ok().iter()
                        .map(|c| json!({"slug": c.slug, "name": c.name}))
                        .collect::<Vec<_>>(),
                    "cards": cards.iter().map(|c| {
                        // Enriched title wins; unmatched cards
                        // fall back to parsing the newest stem.
                        let (title, year) = if !c.title.is_empty() {
                            (c.title.clone(), c.year)
                        } else {
                            let p = crate::wall::parse_release(&c.rep_stem);
                            (p.title, p.year.unwrap_or(0))
                        };
                        let art = |f: &str, thumb: bool| {
                            if !f.is_empty() && art_dir.join(f).is_file() { if thumb {
                                    format!("/art/thumb_{f}?v={}", c.checked)
                                } else {
                                    format!("/art/{f}?v={}", c.checked)
                                } } else { Default::default() }
                        };
                        json!({
                            "key": c.title_key, "kind": c.kind,
                            "title": title, "year": year,
                            "n": c.n_releases, "latest": c.latest_posted,
                            "complete": c.any_complete,
                            "size": c.max_bytes, "res": c.best_res,
                            "rating": c.rating, "genres": c.genres,
                            "overview": c.overview, "actors": c.actors,
                            "aired": c.air_date,
                            "stem": c.rep_stem,
                            "poster": art(&c.poster_art, true),
                            "poster_full": art(&c.poster_art, false),
                            "backdrop": art(&c.backdrop_art, false),
                            "matched": c.checked > 0 && !c.poster_art.is_empty(),
                            "have": dupe_key(&c.rep_stem)
                                .is_some_and(|k| owned.contains(&k)),
                            "verdict": oracle_verdict_json(
                                &ocx, &c.rep_grp, c.latest_posted, now),
                            "reaped": reaped.contains(
                                &nzbkit::oracle::group_family(&c.rep_grp)),
                        })
                    }).collect::<Vec<_>>(),
                })
            }
            Ok(None) => json!({"status": false, "error": "index unavailable"}),
        }
    })
}

fn m_oracle_takedowns(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // M29 3d: content families in an active takedown wave -
        // fresh (≤7d) posts confidently gone on the user's
        // backbones (retention can't expire a week-old post, so
        // fresh+gone = a reap). Drives the wall's "being reaped"
        // flag and a diagnostics panel.
        let families = d
            .oracle_ctx(ctx.cfg_path)
            .map(|(s, b)| s.reaped_families(&b))
            .unwrap_or_default();
        json!({
            "status": true,
            "families": families.iter().map(|r| json!({
                "family": r.family,
                "bucket": r.bucket,
                "bucket_label": nzbkit::oracle::bucket_label(r.bucket),
                "hits": r.hits,
                "misses": r.misses,
            })).collect::<Vec<_>>(),
        })
    })
}

fn m_index_browse(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // M25 browse view: filtered/sorted/paginated release
        // list (the wall's list mode). All params optional.
        let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");
        let mut bq = nzbkit::index::BrowseQuery {
            q: get("q").to_string(),
            complete_only: matches!(get("complete"), "1" | "true"),
            sort: nzbkit::index::BrowseSort::parse(get("sort")),
            desc: get("dir") != "asc",
            ..Default::default()
        };
        // cat maps the UI tabs: built-in kinds and custom
        // category slugs pass through; "4k" is the
        // movie+2160p shorthand tab.
        match get("cat") {
            "" | "all" => {}
            "4k" => {
                bq.kind = Some("movie".into());
                bq.res = Some("2160p".into());
            }
            k if is_kind_slug(k) => bq.kind = Some(k.to_string()),
            _ => {}
        }
        if let Some(r) = params.get("res").filter(|r| !r.is_empty()) {
            bq.res = Some(r.clone());
        }
        // M28: card-scoped listing (a wall card's releases)
        // and the junk ceiling (all=1 shows everything).
        if let Some(tk) = params.get("title_key").filter(|t| !t.is_empty()) {
            bq.title_keys = vec![tk.clone()];
            // M34: a title_key-scoped browse IS the card's
            // detail sheet - the user opened this title. The
            // schema has no "last seen on the wall" column
            // (wall_hidden.at records the opposite act), so
            // this deliberate open is what "recently opened"
            // means, and the size cap protects it for
            // OPENED_PROTECT_DAYS days. Coalesced: reopening
            // the same card does not rewrite the log.
            d.touch_opened_title(tk);
        }
        if get("all") != "1" && bq.title_keys.is_empty() {
            bq.max_junk = Some(50);
        }
        // M30: curation applies to the list view but never to
        // a card's own sheet (title_key-scoped) - the sheet
        // shows everything a title has, rule-hit dubs
        // included, so the user can see what a rule does.
        bq.curated = bq.title_keys.is_empty();
        // Same tier, same scope: the adult filter is a browsing
        // filter over the list, and the wall's grouped endpoint
        // above has always set it. This one did not, so turning
        // group-by-title off was a way round the setting.
        bq.hide_adult = bq.curated && d.wall_hide_adult.load(Ordering::Relaxed);
        if let Ok(n) = get("limit").parse::<u32>() {
            // The grouped wall's nested expand asks for its cap PLUS
            // ONE (REL_PAGE/REL_MAX in wall.html) and reads an
            // over-full answer as "this list was cut" - clamping that
            // ask to 200 made the sentinel unreachable, so the G3
            // truncation row never rendered and the cut was silent
            // again. A title-scoped ask is bounded by one title's own
            // releases, so it may run to the Show-all cap's sentinel;
            // the curated feed keeps the tight page.
            let cap = if bq.title_keys.is_empty() { 200 } else { 2001 };
            bq.limit = n.clamp(1, cap);
        }
        if let Ok(n) = get("offset").parse::<u32>() {
            bq.offset = n;
        }
        // M29 3c: per-row availability verdict; verdict=ok now
        // pushes into the SQL WHERE (via bq.verdict_ok) so the
        // returned `total` and page agree - the old page-level
        // trim left total unfiltered, breaking paging.
        let want_ok = get("verdict") == "ok";
        // M30: badge rows the library already has (or that
        // are queued) - history dupe-key join.
        let owned = d.owned_dupe_keys();
        let ocx = d.oracle_ctx(ctx.cfg_path);
        // M29 3d: reaped families (fresh posts confidently
        // gone) - the list flags their rows as "being reaped".
        let reaped: std::collections::HashSet<String> = ocx
            .as_ref()
            .map(|(s, b)| s.reaped_families(b).into_iter().map(|r| r.family).collect())
            .unwrap_or_default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        if want_ok {
            // Reuse the loaded snapshot + backbones when present;
            // an absent/empty ledger yields a filter that matches
            // nothing (verdict null → not "ok"), i.e. total 0 -
            // the same "show only confirmed-ok" semantics.
            let (snap, bbs) = match &ocx {
                Some((s, b)) => (s.clone(), b.clone()),
                None => (nzbkit::oracle::Snapshot::default(), Vec::new()),
            };
            bq.verdict_ok = Some(nzbkit::index::VerdictFilter {
                snap,
                backbones: bbs,
                now,
            });
        }
        let ccats = d.custom_categories.read_ok().clone();
        // Ranked here, not in the browser: the weights are one
        // Rust function, and mirroring them in JS would let the
        // two drift apart.
        let qprefs = d.quality_prefs.lock_ok().clone();
        // §131 D3, same rule as wall2: a typed query, first page, not
        // a card's own sheet.
        let note = (!bq.q.trim().is_empty() && bq.offset == 0 && bq.title_keys.is_empty())
            .then(|| (bq.q.clone(), bq.kind.clone().unwrap_or_default()));
        match d.with_index_read(|ix| ix.browse(&bq).ok()) {
            Some((rows, total)) => {
                if let Some((q, kind)) = note {
                    d.note_search("wall", &q, &kind, total as usize);
                }
                let hints = corr_hints(
                    d,
                    rows.iter().filter(|r| r.pre_title.is_empty()).map(|r| r.id),
                );
                // TODO 131 rung 5: which rows are worth offering the
                // on-demand RAR namer on. Unnamed, still wearing a dark
                // stem, and not already known header-encrypted - that
                // last one is the point of the terminal classification,
                // so a row that has been asked once stops being asked.
                // The obfuscation verdict comes from `stem_is_a_name`,
                // the ONE definition the byte lanes and the claims gate
                // share; a second opinion here is how the .7z lane sat
                // inert at 14,349 rejections.
                let nameable: std::collections::HashSet<i64> = {
                    let cands: Vec<i64> = rows
                        .iter()
                        .filter(|r| {
                            r.pre_title.is_empty() && !nzbkit::release::stem_is_a_name(&r.stem)
                        })
                        .map(|r| r.id)
                        .collect();
                    let enc = d
                        .with_index_read(|ix| Some(ix.header_encrypted_ids(&cands)))
                        .unwrap_or_default();
                    cands.into_iter().filter(|id| !enc.contains(id)).collect()
                };
                // Classified ONCE, up here, because the art lookup
                // needs every row's title key before the first row is
                // rendered - and because `classify` is not free over a
                // 200-row page.
                let parsed: Vec<_> = rows
                    .iter()
                    .map(|r| nzbkit::categories::classify(r.display_name(), &ccats))
                    .collect();
                // `bq.hide_adult`, not the raw setting: on THIS path
                // the filter already dropped the row, so art on a
                // surviving row leaks nothing - passing the query's
                // own answer keeps the two from disagreeing.
                let art = row_art(
                    d,
                    parsed.iter().map(|p| p.key.clone()).collect(),
                    bq.hide_adult,
                );
                json!({
                    "total": total,
                    "offset": bq.offset,
                    // 24D: the dynamic category set - the UI
                    // renders one tab chip per entry.
                    "cats": ccats.iter()
                        .map(|c| json!({"slug": c.slug, "name": c.name}))
                        .collect::<Vec<_>>(),
                    "results": rows.iter().zip(&parsed).map(|(r, p)| {
                        let verdict = oracle_verdict_json(
                            &ocx, &r.grp, r.first_posted, now);
                        // Badge text still needs source/remux
                        // - a per-row parse of one page is
                        // cheap (pure text). Classified with
                        // the custom categories so "key"
                        // matches the stored title_key and
                        // the info sheet opens the right card.
                        // Parsed from the name the row is
                        // SHOWN under: for a release the pre
                        // feed rescued that is the real
                        // title, and parsing the obfuscated
                        // stem instead would throw the
                        // rescue away at the last step.
                        let name = r.display_name();
                        json!({
                            "verdict": verdict,
                            "reaped": reaped.contains(
                                &nzbkit::oracle::group_family(&r.grp)),
                            "have": dupe_key(name)
                                .is_some_and(|k| owned.contains(&k)),
                            // ROT13-rescued: the stem is
                            // rotated gibberish; title/year
                            // carry the decoded name.
                            "rescued": p.rescued,
                            // The name came from a pre feed,
                            // not off the wire. Carried so
                            // the row can say so rather than
                            // presenting somebody else's
                            // claim as something we read.
                            // '' on every ordinary release.
                            "pre": r.pre_source,
                            // Phase 2 suggestion for a row
                            // still wearing its obfuscated
                            // stem; null everywhere else.
                            "pre_hint": hints.get(&r.id).cloned()
                                .unwrap_or(Value::Null),
                            // Worth offering `mode=rar_name` on: dark,
                            // unnamed, not already known encrypted.
                            "nameable": nameable.contains(&r.id),
                            // The stem it was actually posted
                            // under, when that differs.
                            "posted": if r.pre_title.is_empty() {
                                String::new()
                            } else {
                                r.stem.clone()
                            },
                            "id": r.id, "name": name, "group": r.grp,
                            "size": r.total_bytes, "files": r.files,
                            "complete": r.complete, "par2": r.has_par2,
                            "first_posted": r.first_posted,
                            "first_seen": r.first_seen,
                            "kind": r.kind, "res": r.res,
                            "have_parts": r.have_parts,
                            "need_parts": r.need_parts,
                            "quality": crate::wall::quality_label(p),
                            // What separates two encodes of one
                            // film. Taken from the fresh parse
                            // rather than the stored columns so
                            // rows the quality_v10 pass has not
                            // reached yet still show their tags.
                            "vcodec": p.vcodec, "acodec": p.acodec,
                            "hdr": p.hdr,
                            // Higher = closer to what the user
                            // said they want; the sheet orders on
                            // this instead of raw size.
                            "pref": crate::watchlist::preference_score(p, &qprefs),
                            // Which preferences this one
                            // satisfies, so the row can say WHY
                            // it sorted where it did.
                            "prefhit": crate::watchlist::preference_hits(p, &qprefs),
                            // Wall-card dedupe key: lets the
                            // list's info action open the
                            // existing detail sheet, and is what
                            // `art` below is keyed on.
                            "key": p.key,
                            // Poster thumbnail for this row's
                            // title, '' when the index has none.
                            // Named `art` and not `poster`: on a
                            // RELEASE, "poster" is the person who
                            // posted it (`Release::poster`, the
                            // From: header).
                            "art": art.get(&p.key).cloned()
                                .unwrap_or_default(),
                            "title": p.title, "year": p.year,
                            // M28: the card sheet's episode
                            // grid needs these per release.
                            "season": p.season, "episode": p.episode,
                        })
                    }).collect::<Vec<_>>(),
                })
            }
            None => json!({"status": false, "error": "index unavailable"}),
        }
    })
}

fn m_index_dupe(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id: i64 = params.get("id").and_then(|v| v.parse().ok()).unwrap_or(-1);
        // stem_by_id is the indexed PK lookup with display_name()'s
        // exact COALESCE (the pre-fed title where one exists, else the
        // stem - so a pre-named release collides with the library copy
        // under the SAME real title). The old shape here materialized
        // the newest 100,000 releases and scanned for the id: a valid
        // release older than that window answered "release not found",
        // and every call held one of the four read connections for a
        // full-table sort.
        // index_read_checked, not with_index_read: a saturated read pool
        // must answer "busy", never "release not found" for a release
        // that exists.
        let stem = match d.index_read_checked(|ix| ix.stem_by_id(id).ok().flatten()) {
            Err(why) => {
                return Some(why.refusal());
            }
            Ok(stem) => stem,
        };
        match stem {
            Some(stem) => match d.dupe_collision(&stem) {
                Some(c) => json!({"status": true, "dupe": true,
                                "where": c.where_, "name": c.name, "nzo_id": c.nzo_id}),
                None => json!({"status": true, "dupe": false}),
            },
            None => json!({"status": false, "error": "release not found"}),
        }
    })
}

fn m_index_get(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Enqueue an indexed release for download by id.
        let id: i64 = params.get("id").and_then(|v| v.parse().ok()).unwrap_or(-1);
        // index_read_checked, not with_index_read: a wall Download/Play
        // click during a scan batch must hear "busy", not an error
        // claiming the release is gone.
        let r = match d.index_read_checked(|ix| {
            // Read the name by id. Scanning the newest rows
            // for it instead missed anything the index had
            // since buried, and the "release-<id>" fallback
            // is not just an ugly job name: it carries no
            // dupe key, so the duplicate hold, the
            // watchlist's history check and the wall's
            // "have" badge all go quiet for that grab.
            let name = ix
                .stem_by_id(id)
                .ok()
                .flatten()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("release-{id}"));
            Some((ix.make_nzb(id).ok()?, name))
        }) {
            Err(why) => {
                return Some(why.refusal());
            }
            Ok(r) => r,
        };
        // M30: optional SAB priority (2 Force / 1 High / …) -
        // the wall passes High for Download and Force for
        // Play so a hand-picked grab never waits behind
        // queued RSS/watchlist jobs.
        let prio: i32 = params
            .get("priority")
            .and_then(|v| v.parse().ok())
            .filter(|p| (-2..=2).contains(p))
            .unwrap_or(-100);
        // `dupe_ok=1`: the user was shown the collision by
        // `index_dupe` and chose to download it anyway, so the
        // hold does not apply. Only ever set by a click.
        let dupe_ok = params.get("dupe_ok").map(String::as_str) == Some("1");
        match r {
            Some((xml, name)) => {
                match d.enqueue(
                    xml.as_bytes(),
                    &name,
                    "",
                    prio,
                    None,
                    None,
                    "dashboard",
                    dupe_ok,
                ) {
                    Ok(Enqueued { nzo_id: nzo, .. }) => {
                        // M34: queued from the wall - protect the
                        // row from the size cap. The queue itself
                        // is protected by title_key too, but that
                        // stops the moment the job leaves the
                        // queue and this outlives it.
                        d.touch_opened_release(id);
                        json!({"status": true, "nzo_ids": [nzo]})
                    }
                    Err(e) => json!({"status": false, "error": e.to_string()}),
                }
            }
            None => json!({"status": false, "error": "release not found"}),
        }
    })
}

pub(crate) fn dispatch(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    mode: &str,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(match mode {
        // Browse-card status: is indexing on, and how big is it?
        "index_stats" => return m_index_stats(d, _req, params, ctx, _api_body),
        // The pre feed's own readout. Its own action rather than
        // three more columns on index_stats: that one is polled
        // every few seconds by every open dashboard, and this is
        // read when a settings card is looking at it.
        //
        // with_index_read, never a blocking lock on the shared
        // handle - a settings poll must not park an HTTP worker
        // behind a scan batch (the 28 Jul all-workers-wedged
        // hang), and "not right now" is a perfectly good answer
        // for a counter.
        "predb_stats" => return m_predb_stats(d, _req, params, ctx, _api_body),
        "probe7z_stats" => return m_probe7z_stats(d, _req, params, ctx, _api_body),
        // Read one obfuscated multi-volume RAR's own headers for the
        // inner filename. ON DEMAND by design - the pilot said NO-GO on
        // a scan-time RAR lane and the verdict stands; see m_rar_name.
        "rar_name" => return m_rar_name(d, _req, params, ctx, _api_body),
        "pesto_stats" => return m_pesto_stats(d, _req, params, ctx, _api_body),
        // §161: the fold census + the indexer-confirm day budget.
        "corr_confirm_stats" => return m_corr_confirm_stats(d, _req, params, ctx, _api_body),
        // What ingest threw away, and why - the four `ingest_drop_*`
        // running totals. Read on demand; see m_index_drops for why it
        // is neither an index_stats column nor a /metrics gauge.
        "index_drops" => return m_index_drops(d, _req, params, ctx, _api_body),
        // The parity scoreboard's readout: per-category coverage% /
        // named% / lag over a rolling window, plus the run state.
        // Same non-blocking with_index_read contract as predb_stats.
        "scoreboard" => return m_scoreboard(d, _req, params, ctx, _api_body),
        // §131 D3: the top queries this index was asked for and could
        // not answer. The scoreboard says what a reference indexer
        // has that we do not; this says what the PEOPLE HERE wanted
        // and did not get, which is the list a backfill should work
        // from. Nothing acts on it automatically - by design.
        "search_misses" => return m_search_misses(d, _req, params, ctx, _api_body),
        "search_log_clear" => return m_search_log_clear(d, _req, params, ctx, _api_body),
        // Phase 2: the ranked candidate list for one release (the
        // pick-a-name view). Read-only and on demand.
        "pre_candidates" => return m_pre_candidates(d, _req, params, ctx, _api_body),
        // Accept a correlated name by hand. The human is the gate;
        // provenance records that it was a human.
        "pre_assign" => return m_pre_assign(d, _req, params, ctx, _api_body),
        // Decline a suggestion. Declined is forever (it must not nag);
        // a correlation-applied name is revoked by the same action.
        "pre_reject" => return m_pre_reject(d, _req, params, ctx, _api_body),
        // Kick the historical seed import (manual, always - the
        // opt-in-indexing rule applies doubly to a feature that
        // fetches from a third party). days defaults to the design's
        // 180; one import at a time.
        "predb_seed_start" => return m_predb_seed_start(d, _req, params, ctx, _api_body),
        // Kick a scan pass immediately instead of waiting out the
        // interval (full key). value=<n> deep-backfills the last n
        // headers per group even where already scanned.
        "index_scan_now" => return m_index_scan_now(d, _req, params, ctx, _api_body),
        // Test hook, present only with NZBFAST_DEBUG_HOOKS=1 in
        // the environment: hold the shared index connection for
        // value seconds, standing in for a long catch-up ingest
        // batch. The hang-regression test wedges the lock with
        // this and asserts / and index_stats keep answering
        // (28 Jul: a 62s hold + the dashboard's 15s status poll
        // parked all 4 workers and the daemon served nothing).
        "debug_hold_index" if std::env::var_os("NZBFAST_DEBUG_HOOKS").is_some() => {
            return m_debug_hold_index(d, _req, params, ctx, _api_body);
        }
        // The same hook for the READ pool: hold one pooled read-only
        // connection for value seconds, standing in for the slow query
        // that caused the 2 Aug wedge (`wall2` at 85s, `wall_tip` at
        // 76s, both full scans of a 32M-release table). More of these
        // than there are connections must NOT queue - past
        // INDEX_READ_CONNS they answer `busy` immediately, which is what
        // keeps HTTP workers available for everything else.
        "debug_index_read_busy" if std::env::var_os("NZBFAST_DEBUG_HOOKS").is_some() => {
            return m_debug_index_read_busy(d, _req, params, ctx, _api_body);
        }
        "debug_slow_index_read" if std::env::var_os("NZBFAST_DEBUG_HOOKS").is_some() => {
            return m_debug_slow_index_read(d, _req, params, ctx, _api_body);
        }
        "debug_hold_index_read" if std::env::var_os("NZBFAST_DEBUG_HOOKS").is_some() => {
            return m_debug_hold_index_read(d, _req, params, ctx, _api_body);
        }
        // M16: corruption recovery - delete the whole index
        // database (+art cache) and rescan from scratch. The
        // shared connection is dropped under the lock so no query
        // touches a half-deleted file; the scan loop recreates the
        // db on its next cycle. value=wipe is the confirmation.
        "index_wipe" => return m_index_wipe(d, _req, params, ctx, _api_body),
        // M31a: reclaim disk after retention pruning (VACUUM). Only
        // safe when idle - it exclusive-locks and rewrites the
        // whole file - so refuse while a download or scan is in
        // flight and let the caller retry.
        "index_compact" => return m_index_compact(d, _req, params, ctx, _api_body),
        // M34 "shrink the database to X": prune until the index
        // is under a caller-supplied size, then leave the VACUUM
        // to the idle window (this returns as soon as the rows
        // are gone - it does not sit on the connection rewriting
        // a 40 GB file while the user waits on an HTTP request).
        //
        // Deliberately NOT gated on the index_evict toggle. That
        // switch exists to stop the daemon deleting on its OWN
        // initiative; this mode is the user pointing at a size
        // and asking for it, which is the same act as clicking
        // the button that sets the toggle. It cannot fire by
        // itself - there is no scheduler behind it.
        //
        // Full-key tier: it lives in this match, which the
        // add-only nzbkey never reaches (only addfile/addurl/
        // version do). That is load-bearing - this deletes rows.
        "index_shrink_to" => return m_index_shrink_to(d, _req, params, ctx, _api_body),
        // M34: run the automatic policy once, now, instead of
        // waiting for the next scan pass. "Against the current
        // settings" is literal - including the master switch, so
        // this cannot become a side door around an OFF toggle.
        // (The way to prune with eviction off is index_shrink_to,
        // where the user names the size themselves.)
        "index_evict_now" => return m_index_evict_now(d, _req, params, ctx, _api_body),
        "index_evict_preview" => return m_index_evict_preview(d, _req, params, ctx, _api_body),
        // Newsgroup discovery (the dashboard's "Find newsgroups"
        // browser): search/filter/sort/page the cached LIST
        // ACTIVE catalogue. First call with no catalogue and no
        // cache kicks a background fetch and reports fetching -
        // the UI polls until it lands.
        "groups" => return m_groups(d, _req, params, ctx, _api_body),
        // Bulk subscribe by pattern (slrn's `s` with a prefix,
        // tin's `S`): 400 alt.binaries.* groups in one call
        // instead of 400 clicks. Capped so a stray `*` cannot
        // enqueue the whole server into the scan loop.
        // What the indexer can be asked to look for, and what
        // each choice actually scans. The UI prints the group
        // names beside every option: an opt-in the user cannot
        // read is not much of an opt-in.
        "interests" => return m_interests(d, _req, params, ctx, _api_body),
        "groups_add_matching" => return m_groups_add_matching(d, _req, params, ctx, _api_body),
        // One group in detail: the sampled profile, and the newest
        // subjects so a user can SEE what is in there before
        // committing a scan to it. Competitor research put this at
        // the top of the list (NZBKing does it, nothing else does)
        // and it is the difference between picking a group by name
        // and picking it by contents.
        "group_sample" => return m_group_sample(d, _req, params, ctx, _api_body),
        "groups_refresh" => {
            *d.group_fetch_err.lock_ok() = None;
            let started = kick_group_fetch(d, ctx.cfg_path.to_path_buf());
            json!({"status": true, "started": started})
        }
        "index_search" => return m_index_search(d, _req, params, ctx, _api_body),
        // M28: the poster wall, paged in SQL - replaces mode=wall's
        // whole-index materialization (search('',5000) + client-side
        // filtering). Cards come from Index::browse_cards; poster
        // URLs point at the lazy /art/thumb_* thumbnails.
        "wall2" => return m_wall2(d, _req, params, ctx, _api_body),
        "oracle_takedowns" => return m_oracle_takedowns(d, _req, params, ctx, _api_body),
        "index_browse" => return m_index_browse(d, _req, params, ctx, _api_body),
        // Does grabbing this indexed release collide with something
        // the user already has? The wall asks BEFORE it adds, so a
        // second copy is a decision rather than a surprise: the
        // hold used to be applied silently, and a Play that became
        // a paused duplicate was indistinguishable from a download
        // that never started. Read-only; the answer carries the
        // colliding job so the UI can offer it directly.
        "index_dupe" => return m_index_dupe(d, _req, params, ctx, _api_body),
        "index_get" => return m_index_get(d, _req, params, ctx, _api_body),
        // M35 pull search: fan a query out to the enabled
        // third-party indexers, merge and dedupe, and hand the
        // UI opaque grab tokens - the NZB links carry the user's
        // per-site apikey and stay server-side.
        "indexer_search" => return m_indexer_search(d, _req, params, ctx, _api_body),
        // Spotnet: search what the spot scanner has stored. A
        // separate mode rather than a merge into the wall, because
        // a spot is a different kind of claim - somebody signed a
        // statement that they posted this - and folding the two
        // together would leave no way to say which is which.
        "spot_search" => return m_spot_search(d, _req, params, ctx, _api_body),
        // Grab a spot: fetch the NZB the spot points at and queue
        // it like any other add.
        //
        // The message-id must already be in our own spots table.
        // That is the whole authorization story: the daemon only
        // ever fetches articles its own scanner verified and
        // stored, so a browser cannot aim it at an arbitrary
        // message-id, and a spot whose signature failed was never
        // written in the first place.
        "spot_grab" => return m_spot_grab(d, _req, params, ctx, _api_body),
        // M35: grab one cached external result by token. The
        // token is the ONLY way in - the daemon fetches exactly
        // the URLs its own searches stored, so the browser can
        // never aim it at an arbitrary address.
        "indexer_grab" => return m_indexer_grab(d, _req, params, ctx, _api_body),
        _ => return None,
    })
}

// The pull surface (search / name / grab), moved out bodily (TODO 106).
// `dispatch` stays here and calls into it, so no route changed.
mod pull;
use pull::{m_indexer_grab, m_indexer_search, m_rar_name, m_spot_grab, m_spot_search};

#[cfg(all(test, unix))]
mod add_matching_tests {
    use super::*;
    use crate::testutil::test_daemon;
    use std::os::unix::fs::PermissionsExt;

    /// L1 (Codex sweep 5 Aug): the bulk subscribe discarded the whole
    /// `apply_and_save` result - groups joined the live scan list, the
    /// UI said "Added N groups", and an unwritable settings dir made
    /// the entire subscription vanish at the next restart. Live-plus-
    /// warning is the contract now.
    #[test]
    fn a_bulk_subscribe_that_cannot_persist_says_it_reverts() {
        let dir = std::env::temp_dir().join(format!("nzbfast-gbsave-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = test_daemon(&dir);
        *d.group_catalog.lock_ok() = Some(Arc::new(crate::groups::Catalog {
            fetched_at: 1,
            groups: vec![crate::groups::CatGroup {
                name: "alt.binaries.testers".into(),
                posts: 10,
                desc: String::new(),
                cat: crate::groups::Category::Other,
                status: 'y',
                first_seen: 0,
            }],
        }));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let mut req: tiny_http::Request = tiny_http::TestRequest::new().into();
        let cfg_path = dir.join("nzbfast.toml");
        let ctx = ApiCtx {
            cfg_path: &cfg_path,
            host_hdr: "",
            base: "",
            ua_hdr: "",
            bootstrap_apikey: false,
            via_add_only: false,
        };
        let mut params = std::collections::HashMap::new();
        params.insert("q".to_string(), "testers".to_string());
        let v = m_groups_add_matching(&d, &mut req, &params, &ctx, &mut None).unwrap();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(v["status"], true, "{v}");
        assert_eq!(v["added"], 1, "{v}");
        // The group IS live - and the response says it reverts.
        assert!(
            d.index_groups
                .lock_ok()
                .iter()
                .any(|g| g == "alt.binaries.testers"),
            "the live scan list was not updated"
        );
        let w = v["warning"].as_str().unwrap_or_default();
        assert!(w.contains("revert"), "no durability warning: {v}");
    }
}
