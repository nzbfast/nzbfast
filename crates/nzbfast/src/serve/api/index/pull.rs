//! The PULL surface: ask a configured indexer or Spotnet for results,
//! name an obfuscated RAR release from its own volume headers on demand,
//! and grab from either (TODO 106 code motion out of api/index.rs,
//! behaviour unchanged).

use super::*;

pub(super) fn m_indexer_search(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let q = params.get("q").cloned().unwrap_or_default();
        let kind = params.get("kind").cloned().unwrap_or_default();
        // M35 phase 2: precision ids. `title_key` is the
        // wall's own identity for a title, and the IMDb id
        // is looked up from it HERE rather than being sent
        // by the browser - the page never had the id (no
        // card JSON carries one), and a client-supplied id
        // would be a claim about someone else's data.
        //
        // TV rides a tvdbid where we have one. There deliberately was
        // none for a long time, and the reason is still worth keeping:
        // the only TV id this index held was a TVmaze SHOW id
        // (titles.tmdb_id, reused for TV), a different namespace to
        // TheTVDB's, and sending that as tvdbid asks confidently for
        // the wrong series. TODO 187 added titles.tvdb - a real
        // TheTVDB series id, written only by the lane that asked
        // TVmaze for it - so the id exists now and the comment that
        // said otherwise outlived it. Season/ep still ride alongside,
        // and plan_query decides between all three against the
        // indexer's caps.
        let season = params.get("season").and_then(|v| v.parse::<u32>().ok());
        let ep = params.get("ep").and_then(|v| v.parse::<u32>().ok());
        let (imdbid, tvdbid) = match params.get("title_key") {
            Some(k) if !k.is_empty() => d
                .with_index_read(|ix| {
                    let imdb = ix.title_get(k).ok().flatten()?.imdb;
                    // Its own lookup rather than a field on the row:
                    // the getter is what enforces `kind='tv'`, so a
                    // movie can never contribute a tvdbid.
                    let tvdb = ix.tvdb_id_for_title(k).ok().flatten().unwrap_or(0);
                    Some((
                        imdb,
                        if tvdb > 0 {
                            tvdb.to_string()
                        } else {
                            String::new()
                        },
                    ))
                })
                .unwrap_or_default(),
            _ => Default::default(),
        };
        let list: Vec<crate::newznab::IndexerConfig> = d
            .indexers
            .lock_ok()
            .iter()
            .filter(|i| i.enabled)
            .cloned()
            .collect();
        if q.trim().is_empty() {
            json!({"status": false, "error": "empty query"})
        } else if list.is_empty() {
            json!({"status": false, "error": "no indexers configured"})
        } else {
            // Budget/backoff gate, and the hit accounting,
            // in one pass under the lock. Skips are surfaced
            // per indexer - quota exhaustion must be
            // visible, never a silently thinner result list.
            let mut runnable = Vec::new();
            let mut notes = Vec::new();
            {
                let mut rt = d.indexer_rt.lock_ok();
                rt.usage.roll(unix_now());
                let now = Instant::now();
                for i in list {
                    if rt.penalty_until.get(&i.name).is_some_and(|t| *t > now) {
                        notes.push(json!({"indexer": i.name,
                                        "skipped": "backing off after a limit error"}));
                    } else if !rt.usage.hit_allowed(&i) {
                        notes.push(json!({"indexer": i.name,
                                        "skipped": "daily API budget reached"}));
                    } else {
                        rt.usage.count_hit(&i.name);
                        runnable.push(i);
                    }
                }
            }
            save_indexer_usage(d);
            let query = crate::newznab::SearchQuery {
                q: q.trim().to_string(),
                cats: cat_for_kind(&kind).map(|c| vec![c]).unwrap_or_default(),
                limit: 100,
                offset: 0,
                imdbid,
                tvdbid,
                season,
                ep,
            };
            // Only an id-carrying query needs caps; a plain
            // free-text one must never pay for a probe.
            let wants_caps =
                !query.imdbid.is_empty() || !query.tvdbid.is_empty() || query.season.is_some();
            // One xREL P2P search alongside the fan-out, and
            // only when the query carries no IMDb id of its
            // own: it is the id source for the true-P2P
            // "tagger" groups that scene predbs never list,
            // which is exactly the content a plain text
            // query turns up with no identity attached.
            //
            // Never a reason for the search to be slower: it
            // runs beside the indexers rather than after
            // them, and it declines its own slot rather than
            // queueing for one.
            let xrel_q = (query.imdbid.is_empty() && d.identity_lookup.load(Ordering::Relaxed))
                .then(|| q.trim().to_string());
            // Fan out on plain threads: user-clicked, each
            // call capped at the agent's 15 s, so the search
            // costs one slow indexer, not their sum.
            let d_ref = &d;
            let (outcomes, xrel_hits): (Vec<_>, Vec<crate::xrel::XrelRelease>) =
                std::thread::scope(|s| {
                    let xh = xrel_q
                        .as_deref()
                        .map(|q| s.spawn(move || crate::xrel::try_search_p2p(q, XREL_UI_WAIT)));
                    let handles: Vec<_> = runnable
                        .into_iter()
                        .map(|i| {
                            let query = query.clone();
                            s.spawn(move || {
                                let caps =
                                    wants_caps.then(|| indexer_caps_cached(d_ref, &i)).flatten();
                                let planned = crate::newznab::plan_query(caps.as_ref(), &query);
                                let r = indexer_search_one(&i, &planned);
                                (i, r)
                            })
                        })
                        .collect();
                    let outs = handles.into_iter().filter_map(|h| h.join().ok()).collect();
                    (outs, xh.and_then(|h| h.join().ok()).unwrap_or_default())
                });
            let xrel_ids = crate::xrel::by_dirname(&xrel_hits);
            // Merge (issue #44): the same release listed by several
            // indexers collapses to ONE row. Identity is the release
            // name reduced to the differences that mean something
            // (`release_ident`) plus a size the two indexers agree on
            // within their accounting slack (`size_clusters`).
            //
            // The highest-priority copy (lowest number) is the row's
            // headline, exactly as before - nothing about a default
            // grab changes. What is new is that the losing copies are
            // KEPT and ride along as the row's alternates, so the user
            // can take a different one when an indexer's NZB is dead.
            struct Copy {
                prio: i32,
                /// Arrival order across the fan-out. A priority tie
                /// keeps the first-seen copy, and this is what makes
                /// that deterministic: the grouping below walks a
                /// HashMap, whose order is randomised per process.
                seq: usize,
                indexer: String,
                /// That indexer's configured URL and the addresses it
                /// answered this search from - the origin its enclosure
                /// link is bound to when grabbed (M12/M9).
                origin: SourceOrigin,
                item: crate::newznab::SearchResult,
            }
            let mut groups: std::collections::HashMap<String, Vec<Copy>> =
                std::collections::HashMap::new();
            {
                let mut rt = d.indexer_rt.lock_ok();
                let now = Instant::now();
                let mut seq = 0usize;
                for (cfg, outcome) in outcomes {
                    match outcome {
                        Ok((items, origin)) => {
                            for item in items {
                                let key = crate::newznab::release_ident(&item.title);
                                groups.entry(key).or_default().push(Copy {
                                    prio: cfg.priority,
                                    seq,
                                    indexer: cfg.name.clone(),
                                    origin: origin.clone(),
                                    item,
                                });
                                seq += 1;
                            }
                        }
                        Err(e) => {
                            if matches!(e, crate::newznab::NewznabError::Limit(..)) {
                                rt.penalty_until
                                    .insert(cfg.name.clone(), now + INDEXER_LIMIT_BACKOFF);
                            }
                            notes.push(json!({"indexer": cfg.name,
                                            "error": e.to_string()}));
                        }
                    }
                }
            }
            // One name can still be two releases, so each name group is
            // cut into size clusters and every cluster is a row.
            let mut rows: Vec<Vec<Copy>> = Vec::with_capacity(groups.len());
            for (_, mut group) in groups {
                group.sort_by_key(|c| (c.item.size, c.prio, c.seq));
                let sizes: Vec<u64> = group.iter().map(|c| c.item.size).collect();
                // Drained back to front so each range still indexes the
                // vec it was measured against.
                for r in crate::newznab::size_clusters(&sizes).into_iter().rev() {
                    let mut cluster: Vec<Copy> = group.drain(r).collect();
                    // Headline first: highest priority, ties first seen.
                    cluster.sort_by_key(|c| (c.prio, c.seq));
                    rows.push(cluster);
                }
            }
            // Newest first; unknown ages sink to the bottom. The last
            // two keys are what make that a TOTAL order - without them
            // equal-aged rows come back in the randomised order the
            // HashMap walk above produced them in, and the same search
            // run twice lists them differently.
            rows.sort_by(|a, b| {
                b[0].item
                    .posted
                    .cmp(&a[0].item.posted)
                    .then(b[0].item.grabs.cmp(&a[0].item.grabs))
                    .then(a[0].item.title.cmp(&b[0].item.title))
                    .then(a[0].seq.cmp(&b[0].seq))
            });
            rows.truncate(500);
            let now_ts = unix_now();
            // TODO 282 item 5: one id for this whole search, stamped on
            // every token it mints, so a grab from it can find the other
            // candidates it was listed beside. A secret rather than a
            // counter for the same reason the tokens are: it is handed to
            // the browser inside them and must not be guessable.
            let cohort = fresh_secret();
            let mut out = Vec::with_capacity(rows.len());
            {
                let mut rt = d.indexer_rt.lock_ok();
                // Lazy TTL sweep keeps the cache honest even
                // if nobody ever grabs anything.
                let now = Instant::now();
                while let Some(front) = rt.order.front().cloned() {
                    let stale = rt
                        .results
                        .get(&front)
                        .is_none_or(|h| now.duration_since(h.at) > INDEXER_HIT_TTL);
                    if stale {
                        rt.order.pop_front();
                        rt.results.remove(&front);
                    } else {
                        break;
                    }
                }
                for (row_ix, row) in rows.into_iter().enumerate() {
                    // Every copy gets its own grab token: taking a
                    // different indexer's copy is the whole point of the
                    // group, so a source the UI shows but cannot grab
                    // would be worse than not showing it.
                    //
                    // Capped, and the cap is why the tokens minted by one
                    // search cannot push that search's own earliest rows
                    // out of the LRU: 500 rows x 8 stays clear of
                    // INDEXER_HIT_CAP. The copies are in priority order,
                    // so a cap past 8 configured indexers drops the ones
                    // ranked last.
                    const MAX_SOURCES: usize = 8;
                    let sources: Vec<Value> = row
                        .iter()
                        .take(MAX_SOURCES)
                        .enumerate()
                        .map(|(copy_ix, m)| {
                            let token = fresh_secret();
                            rt.results.insert(
                                token.clone(),
                                IndexerHit {
                                    url: m.item.link.clone(),
                                    title: m.item.title.clone(),
                                    indexer: m.indexer.clone(),
                                    origin: m.origin.clone(),
                                    at: now,
                                    cohort: cohort.clone(),
                                    row: row_ix as u32,
                                    headline: copy_ix == 0,
                                },
                            );
                            rt.order.push_back(token.clone());
                            json!({
                                "token": token,
                                "indexer": m.indexer,
                                // Its OWN title: the copies agree on the
                                // release, not on how to spell it, and
                                // the difference is worth seeing.
                                "title": m.item.title,
                                "size": m.item.size,
                                "age_days": (m.item.posted > 0)
                                    .then(|| (now_ts - m.item.posted).max(0) / 86_400),
                                "grabs": m.item.grabs,
                            })
                        })
                        .collect();
                    let m = &row[0];
                    out.push(json!({
                        // The headline copy's own fields stay at the top
                        // level exactly as they were, so every existing
                        // reader of this answer is untouched by grouping.
                        "token": sources[0]["token"],
                        "indexer": m.indexer,
                        "title": m.item.title,
                        // '' unless xREL named this exact
                        // release. Exact only - see
                        // `by_dirname`.
                        "imdb": xrel_ids
                            .get(&m.item.title.to_ascii_lowercase())
                            .cloned()
                            .unwrap_or_default(),
                        "size": m.item.size,
                        "kind": kind_for_cat(m.item.cat).unwrap_or("other"),
                        "age_days": (m.item.posted > 0)
                            .then(|| (now_ts - m.item.posted).max(0) / 86_400),
                        "grabs": m.item.grabs,
                        // The headline is sources[0]; a single-copy row
                        // carries a one-entry list rather than none, so
                        // the caller never has two shapes to handle.
                        "sources": sources,
                    }));
                }
                while rt.order.len() > INDEXER_HIT_CAP {
                    if let Some(old) = rt.order.pop_front() {
                        rt.results.remove(&old);
                    }
                }
            }
            json!({"status": true, "results": out, "notes": notes})
        }
    })
}

pub(super) fn m_spot_search(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");
        let q = nzbkit::index::SpotQuery {
            q: get("q").to_string(),
            category: get("cat").parse().ok(),
            include_adult: matches!(get("adult"), "1" | "true"),
            limit: get("limit").parse().unwrap_or(60),
            offset: get("offset").parse().unwrap_or(0),
        };
        let now = unix_now();
        // index_read_checked, not with_index_read: a busy read pool must
        // not answer "no spots match" as a plain success.
        match d.index_read_checked(|ix| ix.spot_browse(&q).ok()) {
            Err(why) => json!({
                "status": false, "busy": true,
                "error": why.message(),
            }),
            Ok(None) => json!({"status": true, "results": [], "total": 0,
                            "on": d.spot_enabled.load(Ordering::Relaxed)}),
            Ok(Some((hits, total))) => {
                let rows: Vec<Value> = hits
                    .iter()
                    .map(|s| {
                        json!({
                            "msgid": s.msgid,
                            "title": s.title,
                            "size": s.size,
                            "kind": nzbkit::index::spot_kind(s.category),
                            "cat": s.category,
                            "age_days": (s.date > 0)
                                // saturating: the spot date is an
                                // unbounded i64 out of an
                                // attacker-mintable self-signed
                                // From record, and a huge positive
                                // one underflows this subtraction
                                // (debug panic on the API thread,
                                // silent wrap in release).
                                .then(|| now.saturating_sub(s.date).max(0) / 86_400),
                            "spotter": s.spotter_id,
                            "adult": nzbkit::index::spot_is_adult(&s.subcats),
                            // A verified signature with a failed
                            // proof-of-work is worth showing: it
                            // is the one thing about a spot that
                            // is odd rather than wrong.
                            "hashcash_ok": s.hashcash_ok,
                        })
                    })
                    .collect();
                json!({"status": true, "results": rows, "total": total,
                                "on": d.spot_enabled.load(Ordering::Relaxed)})
            }
        }
    })
}

/// `Config::load` on the blocking pool, for the two API probes that run
/// under a `tokio::time::timeout`.
///
/// TODO 162 item 1, the request-path half of the Codex sweep H audit: a
/// synchronous `std::fs::read` inside a future cannot be cancelled, so
/// wrapping one in `timeout` bounds every step AFTER it and none of the
/// read itself. A config on a dropped SMB or NFS mount therefore held an
/// API worker indefinitely, past a ceiling written precisely so a mute
/// peer could not - and the daemon has eight of those workers. The
/// blocking pool absorbs the stuck read instead, and the caller gets its
/// deadline back.
async fn load_cfg_off_thread(path: std::path::PathBuf) -> Result<nzbkit::config::Config, String> {
    tokio::task::spawn_blocking(move || nzbkit::config::Config::load(&path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Name one obfuscated multi-volume RAR release from its own volume
/// headers, ON DEMAND (TODO 131 rung 5).
///
/// Deliberately not a background lane, and this is the whole reason it
/// is an API mode instead of a worker: the continuation-volume pilot
/// (research/RAR-continuation-pilot-2026-08-10) measured 24 of 26 RAR5
/// sets header-encrypted - 98% of the band by bytes - and a real-name
/// yield of ~1.2% by bytes on the readable remainder. That is not worth
/// a scan-time fetch budget. It IS worth one to three articles on a row
/// somebody is actually looking at.
///
/// Either way the row pays only once: a `-hp` verdict is written as the
/// terminal `header_encrypted` classification, so this mode and every
/// future byte lane skip it from then on. The answer comes back inline
/// (block_on + a hard ceiling, exactly like `spot_grab`) because the
/// caller asked a question and the work is three articles.
pub(super) fn m_rar_name(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let id = params
            .get("id")
            .or_else(|| params.get("value"))
            .and_then(|v| v.parse::<i64>().ok())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        // Already known locked: answer from the classification, spend
        // nothing. This is the line the whole rung exists to draw.
        // index_read_checked: a busy pool answered None here, which read
        // as "not encrypted" and re-spent a connection and up to three
        // articles on a row already terminally classified.
        let known_locked = match d.index_read_checked(|ix| Some(ix.header_encrypted(id))) {
            Err(why) => {
                return Some(json!({
                    "status": false, "busy": true,
                    "error": why.message(),
                }));
            }
            Ok(known) => known == Some(true),
        };
        if known_locked {
            return Some(json!({
                "status": false,
                "outcome": "encrypted",
                "error": "this archive's headers are encrypted - no probe can read a name \
                          out of it without the password",
            }));
        }
        // Read pool, never the shared write handle: this arm is about
        // to block_on a wire fetch, and parking an HTTP worker behind a
        // scan batch first is how the 28 Jul all-workers wedge started.
        // (The file rows are the 7z lane's accessor - the segment
        // decode and bracket normalisation are container-agnostic.)
        // index_read_checked, not with_index_read: the pool can be free
        // for the classification read above and saturated by the time
        // this one asks, and `with_index_read` maps that to None -
        // `unwrap_or_default` then answers "no such release" about a
        // release that exists. Same honesty as the first read, which
        // has reported busy since it was written.
        let files = match d.index_read_checked(|ix| ix.probe7z_files(id).ok()) {
            Err(why) => {
                return Some(json!({
                    "status": false, "busy": true,
                    "error": why.message(),
                }));
            }
            Ok(files) => files.unwrap_or_default(),
        };
        if files.is_empty() {
            return Some(json!({"status": false, "error": "no such release"}));
        }
        let cfg_path = ctx.cfg_path.to_path_buf();
        let probed = tokio::runtime::Handle::current().block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(60), async {
                // On the blocking pool, not inline: `Config::load` is a
                // `std::fs::read`, and a blocking read inside a future
                // is not cancellable - the ceiling above would elapse
                // with this API worker still parked in the read, which
                // is the one thing it exists to prevent (TODO 162 item
                // 1). Handing it to `spawn_blocking` makes the timeout
                // cover the config read as well as the network work.
                let cfg = load_cfg_off_thread(cfg_path.clone()).await?;
                let server = crate::scan_servers(&cfg)
                    .into_iter()
                    .next()
                    .ok_or_else(|| "no enabled server".to_string())?;
                let (mut conn, _) = nzbkit::nntp::Connection::connect(&server)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut spent = (0u64, 0u64);
                let r = super::super::tasks::run_rar_probe(&mut conn, &files, &mut spent)
                    .await
                    .map_err(|e| e.to_string());
                conn.quit().await;
                r
            })
            .await
        });
        match probed {
            Err(_) => json!({"status": false, "error": "timed out reading that archive"}),
            Ok(Err(e)) => json!({"status": false, "error": e}),
            Ok(Ok(run)) => {
                if let Some(kind) = run.enc_kind {
                    // The pilot's most reusable output: 98%-by-bytes of
                    // this band goes from "unknown, keep trying" to
                    // "known dead, never fetch again" - revisably, by a
                    // classifier generation nobody has to migrate.
                    //
                    // TODO 166: bounded, and a busy mutex ends the
                    // handler. This verdict is the product of a probe
                    // that just spent up to 60 s on the wire, and the
                    // answer that does not throw it away is the one
                    // that gets the click pressed again - reported
                    // WITHOUT an `outcome`, which is how the sheet
                    // tells "the probe never got to look" from "there
                    // was nothing in the post to read".
                    if let Err(why) =
                        d.index_write_checked(|ix| ix.probe7z_retire_encrypted(id, kind, now).ok())
                    {
                        return Some(json!({"status": false, "error": why.message()}));
                    }
                }
                let mut applied = Value::Null;
                if let Some(name) = &run.name {
                    let verdict = match d.index_write_checked(|ix| {
                        ix.apply_rar_named(id, name, run.key.as_deref(), now).ok()
                    }) {
                        Ok(v) => v.flatten(),
                        // Same rule, and the same 60 s: a name read out
                        // of the archive's own bytes must not be
                        // dropped because a scan batch held the mutex.
                        Err(why) => {
                            return Some(json!({"status": false, "error": why.message()}));
                        }
                    };
                    applied = json!(verdict.map(|v| format!("{v:?}")));
                }
                json!({
                    "status": run.outcome == "named",
                    "outcome": run.outcome,
                    "name": run.name,
                    "key": run.key,
                    "applied": applied,
                    "articles": run.articles,
                    "bytes": run.bytes,
                })
            }
        }
    })
}

pub(super) fn m_spot_grab(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let msgid = params
            .get("msgid")
            .or_else(|| params.get("value"))
            .cloned()
            .unwrap_or_default();
        let prio: i32 = params
            .get("priority")
            .and_then(|v| v.parse().ok())
            .filter(|p| (-2..=2).contains(p))
            .unwrap_or(-100);
        let cat = params.get("cat_name").cloned().unwrap_or_default();
        let dupe_ok = params.get("dupe_ok").map(String::as_str) == Some("1");
        let spot = d.with_index_read(|ix| ix.spot_by_msgid(&msgid).ok().flatten());
        match spot {
            None => json!({"status": false,
                            "error": "no such spot - rescan and try again"}),
            Some(spot) => {
                let cfg_path2 = ctx.cfg_path.to_path_buf();
                // block_on + a hard ceiling, like warm_bench:
                // a spot NZB is one HEAD plus a handful of
                // BODYs, but a black-holed server must not
                // wedge the API thread. Big spots are real -
                // one measured NZB was 929 KB over 2 payload
                // articles - so the ceiling is generous.
                let fetched = tokio::runtime::Handle::current().block_on(async {
                    tokio::time::timeout(std::time::Duration::from_secs(120), async {
                        // Off-thread for the reason `m_rar_name`'s
                        // twin documents: a blocking read inside the
                        // future outlives the ceiling around it.
                        let cfg = load_cfg_off_thread(cfg_path2.clone()).await?;
                        let server = crate::scan_servers(&cfg)
                            .into_iter()
                            .next()
                            .ok_or_else(|| "no enabled server".to_string())?;
                        let (mut conn, _) = nzbkit::nntp::Connection::connect(&server)
                            .await
                            .map_err(|e| e.to_string())?;
                        let r = nzbkit::spot::fetch_spot_nzb(&mut conn, &msgid)
                            .await
                            .map_err(|e| e.to_string());
                        conn.quit().await;
                        r
                    })
                    .await
                });
                match fetched {
                    Err(_) => json!({"status": false,
                                    "error": "timed out fetching that spot"}),
                    Ok(Err(e)) => json!({"status": false, "error": e}),
                    Ok(Ok((sx, nzb))) => {
                        // Remember the release payload ids (first
                        // segment per file, bracketed) - the join
                        // key against files.segments. The ftd
                        // chunk ids in sx.nzb_segments are useless
                        // downstream: they never appear in any
                        // content group.
                        //
                        // try_with_index, not with_index: this is a
                        // best-effort cache line - the scan loop sets
                        // the same column from its own spot fetch
                        // (scan.rs) and the result is discarded here -
                        // and it sits directly in front of `enqueue`
                        // on the user's Grab click. Parking for a tip
                        // ingest's whole transaction (~80 s measured
                        // 14 Aug 2026) would delay the grab itself to
                        // write a column nothing is waiting on.
                        d.try_with_index(|ix| {
                            ix.set_spot_nzb(&spot.msgid, &nzbkit::spot::payload_msgids(&nzb))
                                .ok()
                        });
                        // The spot's own title is the name:
                        // it is signed, and it is the reason
                        // this source exists at all.
                        let name = if sx.title.is_empty() {
                            spot.title.clone()
                        } else {
                            sx.title.clone()
                        };
                        match d.enqueue(&nzb, &name, &cat, prio, None, None, "spot", dupe_ok) {
                            Ok(Enqueued { nzo_id: id, .. }) => {
                                info!(target: "spots", "grabbed {name}");
                                json!({"status": true, "nzo_ids": [id]})
                            }
                            Err(e) => {
                                json!({"status": false, "error": e.to_string()})
                            }
                        }
                    }
                }
            }
        }
    })
}

pub(super) fn m_indexer_grab(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let token = params.get("token").cloned().unwrap_or_default();
        let prio: i32 = params
            .get("priority")
            .and_then(|v| v.parse().ok())
            .filter(|p| (-2..=2).contains(p))
            .unwrap_or(-100);
        let dupe_ok = params.get("dupe_ok").map(String::as_str) == Some("1");
        let hit = {
            let rt = d.indexer_rt.lock_ok();
            rt.results
                .get(&token)
                .filter(|h| h.at.elapsed() <= INDEXER_HIT_TTL)
                .cloned()
        };
        match hit {
            None => json!({"status": false,
                            "error": "result expired - search again"}),
            Some(h) => {
                let cfg = d
                    .indexers
                    .lock_ok()
                    .iter()
                    .find(|i| i.name == h.indexer)
                    .cloned();
                let allowed = {
                    let mut rt = d.indexer_rt.lock_ok();
                    rt.usage.roll(unix_now());
                    cfg.as_ref().is_none_or(|c| rt.usage.grab_allowed(c))
                };
                if !allowed {
                    json!({"status": false, "error":
                                    format!("{}: daily grab budget reached", h.indexer)})
                } else {
                    // fetch_url_from: h.url is the `<enclosure url>` the
                    // indexer's own search response supplied, so the
                    // fetch is bound to that indexer's origin - a
                    // private target it does not own is refused (M12).
                    match fetch_url_from(&h.url, &h.origin) {
                        Ok(f) => match d.enqueue_fetched(
                            &f, &h.title, "", prio, None, None, 0, "indexer", dupe_ok,
                        ) {
                            Ok(Enqueued { nzo_id: id, .. }) => {
                                d.indexer_rt.lock_ok().usage.count_grab(&h.indexer);
                                save_indexer_usage(d);
                                hold_search_spares(d, &id, &h);
                                json!({"status": true, "nzo_ids": [id]})
                            }
                            Err(e) => {
                                json!({"status": false, "error": e.to_string()})
                            }
                        },
                        // Same leak the nzblnk ladder had:
                        // fetch_url names the URL it failed
                        // on, and h.url is the enclosure link
                        // whose whole reason for living behind
                        // a token is that it carries the
                        // user's account credential.
                        Err(e) => json!({"status": false,
                                        "error": redact_url_creds(&e.to_string())}),
                    }
                }
            }
        }
    })
}

/// TODO 282 item 5: hold the next ranked candidates of the search this
/// grab came out of, as paused alternatives of the job just added.
///
/// **Off the request thread.** The click is answered the moment the
/// grabbed job is queued; the spares arrive a beat later. Each candidate
/// costs one HTTP fetch bounded by the shared agent's 15 s, so doing this
/// inline could put half a minute in front of a button press, for rows
/// the user is not waiting on.
///
/// The candidate list is captured HERE, under the cache lock, rather than
/// re-read on that thread: `INDEXER_HIT_TTL` and the LRU cap can both
/// drop a token while the thread runs, and a spare walk that quietly
/// shrinks is worse than one that fetches what it decided to fetch.
///
/// One candidate per OTHER row - see [`IndexerHit::row`] - so the walk
/// never spends the user's grab budget fetching a second indexer's copy
/// of the release it just grabbed.
#[cfg(feature = "indexer")]
fn hold_search_spares(d: &Arc<Daemon>, primary: &str, grabbed: &IndexerHit) {
    // §282 items 13/19: HOW MANY is the user's answer, not this file's.
    // Asked before the candidate walk because 0 genuinely means "hold
    // nothing" - it must not take the indexer lock, rank a search or
    // spawn an aux thread to arrive at that. The default behind it is
    // `spare::SPARE_HOLD_COUNT`, which `AltSettings::default` is
    // initialised from, so an install that has never touched the setting
    // behaves exactly as it did before there was one.
    let want = d.alt.hold_count.load(Ordering::Relaxed) as usize;
    if want == 0 {
        return;
    }
    let cands: Vec<spare::SpareCandidate> = {
        let rt = d.indexer_rt.lock_ok();
        let mut rows: Vec<(u32, &String, &IndexerHit)> = rt
            .results
            .iter()
            .filter(|(_, h)| {
                h.cohort == grabbed.cohort
                    && h.row != grabbed.row
                    && h.headline
                    && h.at.elapsed() <= INDEXER_HIT_TTL
            })
            .map(|(t, h)| (h.row, t, h))
            .collect();
        // The cache is a HashMap; row order is what the search sorted
        // them into (newest first), and it has to be restored here or
        // the same grab holds different spares on every run.
        rows.sort_by_key(|(r, _, _)| *r);
        rows.into_iter()
            .map(|(_, token, h)| spare::SpareCandidate {
                title: h.title.clone(),
                source: h.indexer.clone(),
                token: token.clone(),
            })
            .collect()
    };
    if cands.is_empty() {
        return;
    }
    // Weak, like every other aux lane: a shutdown must not wait out six
    // 15 s indexer fetches for rows nobody is looking at.
    let dw = Arc::downgrade(d);
    let primary = primary.to_string();
    crate::serve::spawn_aux("spare-hold", move || {
        let Some(d) = dw.upgrade() else { return };
        let held = d.hold_spares_with(&primary, &cands, want, |c| {
            let hit = {
                let rt = d.indexer_rt.lock_ok();
                rt.results
                    .get(&c.token)
                    .filter(|h| h.at.elapsed() <= INDEXER_HIT_TTL)
                    .cloned()
            };
            let hit = hit.ok_or_else(|| "that result has expired".to_string())?;
            // The user's metered budget decides, exactly as it does for
            // the grab itself: a spare IS an indexer grab, and one that
            // spent quota the account did not have would be a feature
            // charging for itself behind the user's back.
            let cfg = d
                .indexers
                .lock_ok()
                .iter()
                .find(|i| i.name == hit.indexer)
                .cloned();
            {
                let mut rt = d.indexer_rt.lock_ok();
                rt.usage.roll(unix_now());
                if !cfg.as_ref().is_none_or(|c| rt.usage.grab_allowed(c)) {
                    return Err(format!("{}: daily grab budget reached", hit.indexer));
                }
            }
            // fetch_url_from, never a bare fetch: the enclosure link is
            // bound to the origin the SEARCH answered from (M12/M9), and
            // a spare is fetched long after that search, on another
            // thread, which is exactly the window that binding closes.
            let f = fetch_url_from(&hit.url, &hit.origin)
                .map_err(|e| redact_url_creds(&e.to_string()))?;
            d.indexer_rt.lock_ok().usage.count_grab(&hit.indexer);
            save_indexer_usage(&d);
            Ok(f.bytes)
        });
        if held > 0 {
            info!(target: "queue", "{primary}: {held} spare(s) held against its failure");
        }
    });
}
