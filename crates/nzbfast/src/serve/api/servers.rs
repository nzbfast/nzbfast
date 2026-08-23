use super::super::*;
use super::ApiCtx;

fn m_server_stats(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Shape SAB apps expect: total/month/week/day bytes,
        // plus the same per server - fed from the usage ledger.
        let u = d.usage.lock_ok().clone();
        let days = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_secs() / 86_400) as i64)
            .unwrap_or(0);
        let (y, m, dd) = civil_from_days(days);
        let today = format!("{y:04}-{m:02}-{dd:02}");
        let month_prefix = format!("{y:04}-{m:02}");
        let week_cut = {
            let (wy, wm, wd) = civil_from_days(days - 6);
            format!("{wy:04}-{wm:02}-{wd:02}")
        };
        let mut tot = (0u64, 0u64, 0u64, 0u64); // total, month, week, day
        let mut servers = serde_json::Map::new();
        for (day, hosts) in &u {
            if day == "reliability" {
                continue; // article counters, not byte buckets
            }
            let Some(hosts) = hosts.as_object() else {
                continue;
            };
            let lifetime = day == "lifetime";
            for (host, b) in hosts {
                let b = b.as_u64().unwrap_or(0);
                let e = servers.entry(host.clone()).or_insert_with(|| {
                    json!({"total":0u64,"month":0u64,"week":0u64,"day":0u64,
                                    "daily":{}, "articles_tried":0,"articles_success":0})
                });
                let eo = e.as_object_mut().unwrap();
                let bump = |eo: &mut serde_json::Map<String, Value>, k: &str, v: u64| {
                    let cur = eo.get(k).and_then(Value::as_u64).unwrap_or(0);
                    eo.insert(k.into(), json!(cur + v));
                };
                if lifetime {
                    bump(eo, "total", b);
                    tot.0 += b;
                } else {
                    if day.starts_with(&month_prefix) {
                        bump(eo, "month", b);
                        tot.1 += b;
                    }
                    if day.as_str() >= week_cut.as_str() {
                        bump(eo, "week", b);
                        tot.2 += b;
                    }
                    if *day == today {
                        bump(eo, "day", b);
                        tot.3 += b;
                    }
                }
            }
        }
        // Reliability ledger → the SAB per-server article
        // counters apps already display.
        if let Some(rel) = u.get("reliability").and_then(Value::as_object) {
            for (host, counts) in rel {
                let g = |k| counts.get(k).and_then(Value::as_u64).unwrap_or(0);
                let (tried, missing) = (g("tried"), g("missing"));
                let e = servers.entry(host.clone()).or_insert_with(|| {
                    json!({"total":0u64,"month":0u64,"week":0u64,"day":0u64,
                                    "daily":{}, "articles_tried":0,"articles_success":0})
                });
                if let Some(eo) = e.as_object_mut() {
                    eo.insert("articles_tried".into(), json!(tried));
                    eo.insert(
                        "articles_success".into(),
                        json!(tried.saturating_sub(missing)),
                    );
                }
            }
        }
        json!({"total": tot.0, "month": tot.1, "week": tot.2, "day": tot.3,
                        "servers": Value::Object(servers)})
    })
}

fn m_server_save(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let raw = api_body.take().unwrap_or_default();
        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let idx = body.get("index").and_then(Value::as_i64).unwrap_or(-1);
        // Read and write under one lock: this whole block is a
        // read-modify-write of the entire server array.
        let _cfg = crate::setup::config_write_lock();
        let mut servers = current_servers(ctx.cfg_path);
        let existing = usize::try_from(idx)
            .ok()
            .and_then(|i| servers.get(i))
            .cloned();
        match normalized_server(
            existing.as_ref(),
            body.get("server").unwrap_or(&Value::Null),
        ) {
            Ok(merged) => {
                match usize::try_from(idx).ok().filter(|i| *i < servers.len()) {
                    Some(i) => servers[i] = merged,
                    None => servers.push(merged),
                }
                match crate::setup::write_servers(ctx.cfg_path, &servers) {
                    Ok(()) => {
                        info!(
                            target: "config",
                            "servers updated ({} total) - applies from the next download",
                            servers.len()
                        );
                        // Idle release is the exception to
                        // "applies from the next download":
                        // an operator turning it on does so
                        // precisely because connections are
                        // being held RIGHT NOW, and waiting
                        // for a download to free them would
                        // be backwards.
                        // Re-read rather than reuse the raw
                        // JSON above: `servers` here is the
                        // untyped form that was written, and
                        // the policy has to come from the
                        // parsed config the daemon will
                        // actually run with.
                        if let Ok(c) = nzbkit::config::Config::load(ctx.cfg_path) {
                            d.push_idle_release_policies(&c.servers);
                        }
                        // Raising a server's own connection count
                        // is the other half of the same control as
                        // the global setting, and has to retire a
                        // stored knee measured under the lower
                        // ceiling for the same reason. See
                        // conntune::reopen_low_knees.
                        crate::conntune::reopen_for_install(
                            ctx.cfg_path,
                            d.connections.load(Ordering::Relaxed),
                        );
                        json!({"status": true, "count": servers.len()})
                    }
                    Err(e) => json!({"status": false, "error": e.to_string()}),
                }
            }
            Err(e) => json!({"status": false, "error": e}),
        }
    })
}

fn m_server_secret(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let idx: usize = params
            .get("value")
            .and_then(|v| v.parse().ok())
            .unwrap_or(usize::MAX);
        match current_servers(ctx.cfg_path).get(idx) {
            // Decoded on the way out: this endpoint's whole
            // job is to hand back the CLEARTEXT so it can be
            // copied into another instance, and every other
            // writer stores obf1 - so a wizard-created or
            // imported server used to return `obf1:9c1a…`
            // labelled as the password. Pasted into
            // SABnzbd/NZBGet that silently fails AUTHINFO.
            // deobfuscate returns a non-obf1 string unchanged,
            // so this also repairs the cleartext entries the
            // dashboard already wrote to disk.
            Some(s) => json!({
                "status": true,
                "username": s.get("username").and_then(Value::as_str).unwrap_or(""),
                "password": nzbkit::config::deobfuscate(
                    s.get("password").and_then(Value::as_str).unwrap_or("")
                ),
            }),
            None => json!({"status": false, "error": "unknown server index"}),
        }
    })
}

fn m_server_enable(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let idx: usize = params
            .get("value")
            .and_then(|v| v.parse().ok())
            .unwrap_or(usize::MAX);
        let on = params.get("value2").map(String::as_str) != Some("0");
        let _cfg = crate::setup::config_write_lock();
        let mut servers = current_servers(ctx.cfg_path);
        if idx >= servers.len() {
            json!({"status": false, "error": "unknown server index"})
        } else {
            if let Some(o) = servers[idx].as_object_mut() {
                if on {
                    o.remove("enabled"); // default; keeps the file clean
                } else {
                    o.insert("enabled".into(), json!(false));
                }
            }
            match crate::setup::write_servers(ctx.cfg_path, &servers) {
                Ok(()) => {
                    info!(
                        target: "config",
                        "{} {}",
                        servers[idx]
                            .get("host")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("?"),
                        if on { "enabled" } else { "disabled" }
                    );
                    json!({"status": true})
                }
                Err(e) => json!({"status": false, "error": e.to_string()}),
            }
        }
    })
}

fn m_server_reorder(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let raw = api_body.take().unwrap_or_default();
        let order: Vec<usize> = serde_json::from_slice::<Value>(&raw)
            .ok()
            .and_then(|v| v.get("order").cloned())
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let _cfg = crate::setup::config_write_lock();
        let servers = current_servers(ctx.cfg_path);
        let mut sorted: Vec<usize> = order.clone();
        sorted.sort_unstable();
        if sorted != (0..servers.len()).collect::<Vec<_>>() {
            json!({"status": false,
                            "error": "order must be a permutation of all server indices"})
        } else {
            let reordered: Vec<Value> = order.iter().map(|&i| servers[i].clone()).collect();
            match crate::setup::write_servers(ctx.cfg_path, &reordered) {
                Ok(()) => {
                    info!(target: "config", "servers reordered");
                    json!({"status": true})
                }
                Err(e) => json!({"status": false, "error": e.to_string()}),
            }
        }
    })
}

fn m_server_delete(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let idx: usize = params
            .get("value")
            .and_then(|v| v.parse().ok())
            .unwrap_or(usize::MAX);
        let _cfg = crate::setup::config_write_lock();
        let mut servers = current_servers(ctx.cfg_path);
        if idx < servers.len() {
            let gone = servers.remove(idx);
            match crate::setup::write_servers(ctx.cfg_path, &servers) {
                Ok(()) => {
                    info!(
                        target: "config",
                        "removed server {} ({} left)",
                        gone.get("host").and_then(serde_json::Value::as_str).unwrap_or("?"),
                        servers.len()
                    );
                    json!({"status": true, "count": servers.len()})
                }
                Err(e) => json!({"status": false, "error": e.to_string()}),
            }
        } else {
            json!({"status": false, "error": "no such server"})
        }
    })
}

/// §96.5: restart a host's block-used counter after the user buys a
/// new block, by stamping the current lifetime figure as the block's
/// base - the lifetime ledger itself is never rewound (it also answers
/// the history totals). Keyed by HOST, not index: the counter belongs
/// to the account, and an index would re-point under a concurrent
/// reorder.
fn m_server_block_refilled(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(
        match params
            .get("value")
            .map(String::as_str)
            .filter(|h| !h.is_empty())
        {
            Some(host) => {
                d.block_refilled(host);
                info!(
                    target: "config",
                    "block refilled for {host} - used counter restarted at zero"
                );
                json!({"status": true, "block_used": 0})
            }
            None => json!({"status": false, "error": "value must name the server host"}),
        },
    )
}

/// What the editor should propose in the mirror-group box, or None
/// when the hostname says nothing useful.
pub(in crate::serve) struct GroupSuggestion {
    /// The backbone the hostname resolves to, as the oracle names it.
    backbone: String,
    /// The string to offer: a sibling's existing group name where there
    /// is one, otherwise the backbone name itself.
    suggest: String,
    /// The configured server whose name is being echoed, if any.
    same_as: Option<String>,
}

/// Derive the mirror-group suggestion for the server being edited.
///
/// Two rules, in this order:
///
/// 1. If another configured server resolves to the SAME backbone key
///    and already carries a group name, that string is the suggestion.
///    The field only does anything when both servers spell it
///    identically, so a second spelling beside a working one would fold
///    nothing while looking like it had. This rule holds even for a key
///    the alias table has never heard of - two hosts of one unlisted
///    brand are still one network, and the evidence for the name came
///    from the user's own config rather than from the table.
/// 2. Otherwise the backbone's own name, but ONLY when the table
///    actually LISTS it. An unlisted host keys under its own label
///    ("myisp"), which is a fine ledger key and a terrible thing to
///    propose to someone as the name of a provider network.
///
/// `editing` is the index being edited (-1 when adding), so a server
/// never has its own name suggested back to it.
///
/// This is a SUGGESTION and the caller must treat it as one: the alias
/// table is a hand-maintained snapshot of who resells whom, it goes
/// stale on its own schedule, and a wrong group name folds 430s across
/// servers that are not mirrors - which loses articles one of them
/// could have served.
pub(in crate::serve) fn group_suggestion(
    servers: &[nzbkit::config::ServerConfig],
    host: &str,
    editing: i64,
) -> Option<GroupSuggestion> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let key = nzbkit::oracle::backbone_of(host);
    let sibling = servers
        .iter()
        .enumerate()
        .filter(|(i, _)| i64::try_from(*i).unwrap_or(i64::MAX) != editing)
        .find_map(|(_, s)| {
            let group = s.group.as_deref().unwrap_or_default().trim();
            (!group.is_empty() && nzbkit::oracle::backbone_of(&s.host) == key)
                .then(|| (s.host.clone(), group.to_string()))
        });
    match sibling {
        Some((host, group)) => Some(GroupSuggestion {
            backbone: key,
            suggest: group,
            same_as: Some(host),
        }),
        None => nzbkit::oracle::known_backbone_of(host).map(|backbone| GroupSuggestion {
            suggest: backbone.clone(),
            backbone,
            same_as: None,
        }),
    }
}

/// Answer what the mirror-group box should GHOST for a hostname the
/// user is typing. `value` = the hostname in the form (which may not be
/// saved, or may not exist, yet), `value2` = the index being edited.
///
/// Nothing here writes anything. The editor shows the answer as a
/// placeholder plus a one-click accept, and the value only reaches the
/// config if the person accepts it - see `group_suggestion` for why the
/// heuristic must never set the field by itself.
fn m_server_backbone(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let host = params.get("value").map(String::as_str).unwrap_or_default();
    let editing = params
        .get("value2")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(-1);
    let servers = nzbkit::config::Config::load(ctx.cfg_path)
        .map(|c| c.servers)
        .unwrap_or_default();
    Some(match group_suggestion(&servers, host, editing) {
        Some(g) => json!({
            "status": true,
            "backbone": g.backbone,
            "suggest": g.suggest,
            "same_as": g.same_as,
        }),
        // A hostname the table does not know is not an error: the box
        // stays blank and quiet, which is what it did before.
        None => json!({"status": true, "backbone": null, "suggest": null, "same_as": null}),
    })
}

fn m_server_test(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Connect + TLS + AUTHINFO against the (merged) server
        // without saving it - a blank password borrows the
        // stored one, so "Test" works on saved servers too.
        let raw = api_body.take().unwrap_or_default();
        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let idx = body.get("index").and_then(Value::as_i64).unwrap_or(-1);
        let servers = current_servers(ctx.cfg_path);
        let existing = usize::try_from(idx)
            .ok()
            .and_then(|i| servers.get(i))
            .cloned();
        let sc = normalized_server(
            existing.as_ref(),
            body.get("server").unwrap_or(&Value::Null),
        )
        .and_then(|m| {
            serde_json::from_value::<nzbkit::config::ServerConfig>(m).map_err(|e| e.to_string())
        });
        match sc {
            Ok(sc) => {
                // Same block_on + hard-timeout pattern as
                // sysbench: a black-holed host must not wedge
                // the API thread.
                let t0 = std::time::Instant::now();
                let r = tokio::runtime::Handle::current().block_on(async {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(12),
                        nzbkit::nntp::Connection::connect(&sc),
                    )
                    .await
                });
                match r {
                    Ok(Ok((conn, greeting))) => {
                        let ms = t0.elapsed().as_millis() as u64;
                        tokio::runtime::Handle::current().block_on(conn.quit());
                        json!({"status": true, "greeting": greeting.line(), "latency_ms": ms})
                    }
                    Ok(Err(e)) => {
                        // §G: the pool already tells a capacity cap
                        // apart from a rejected credential, and the
                        // Providers card renders the distinction -
                        // but Test threw it away and printed one
                        // flat failure. Someone whose plan allows 10
                        // connections and who had asked for 20 was
                        // told to go and check a password that was
                        // never wrong. The classification costs
                        // nothing to carry; the remedy is what the
                        // user is here for.
                        json!({"status": false, "error": e.to_string(),
                                   "refusal": refusal_kind(&e)})
                    }
                    Err(_) => json!({"status": false,
                                    "error": "connect timed out (12 s)"}),
                }
            }
            Err(e) => json!({"status": false, "error": e}),
        }
    })
}

/// The url a `feed_test` / `feed_preview` body is actually asking about.
///
/// TODO §20c: the RSS editor's url box holds the MASKED url for a saved
/// feed, so a Test on a row the user did not retype would otherwise
/// fetch `https://indexer/rss?apikey=***` and report the feed as broken.
/// The body carries the feed's `id` alongside, and an unchanged url
/// against a known id resolves to the stored one - the same merge
/// `set_feeds` does, and for the same reason. A url the user DID type
/// is used verbatim, which is what makes Test useful before a save.
fn feed_body_url(d: &Arc<Daemon>, body: &Value) -> String {
    let url = body
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let id = body
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if !id.is_empty()
        && let Some(f) = d.feeds.lock_ok().iter().find(|f| f.id == id)
        && crate::rss::url_is_unchanged(url, &f.url)
    {
        return f.url.clone();
    }
    url.to_string()
}

fn m_feed_test(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        if req.method() != &tiny_http::Method::Post {
            json!({"status": false, "error": "POST required"})
        } else {
            // The body always arrives pre-read: serve() drains every
            // POST to /api before it authorizes, so a handler that
            // read the socket here would be reading it after the
            // authorization decision - the rotation window Codex
            // sweep 2's H1 closed. `unwrap_or_default()` and never a
            // fallback read: an empty body is a bad request, not a
            // reason to reach for the socket.
            let raw = api_body.take().unwrap_or_default();
            let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
            let url = feed_body_url(d, &body);
            if url.is_empty() {
                json!({"status": false, "error": "no url"})
            } else {
                // parse_feed_checked: a Test that got an HTTP 200
                // login page back must say so, not report a
                // healthy feed with zero items (Codex sweep 2,
                // 3 Aug ML1) - the whole point of the button is
                // telling a broken url from a quiet one.
                let r = fetch_url(&url).and_then(|f| {
                    crate::rss::parse_feed_checked(&String::from_utf8_lossy(&f.bytes))
                        .map_err(|e| anyhow::anyhow!("{e}"))
                });
                let health = match &r {
                    Ok(items) => crate::rss::FeedHealth::ok(unix_now(), items.len()),
                    Err(e) => {
                        crate::rss::FeedHealth::failed(unix_now(), &e.to_string(), redact_url_creds)
                    }
                };
                // A test of a CONFIGURED feed heals (or condemns) its
                // row straight away, instead of leaving a stale
                // failure sitting there until the next poll.
                if d.feeds.lock_ok().iter().any(|f| f.url == url) {
                    d.feed_health.lock_ok().insert(url.clone(), health.clone());
                }
                match r {
                    // Never the url, and never the feed's own text:
                    // the count is the answer, and the error has
                    // already been through redact_url_creds.
                    Ok(items) => json!({"status": true, "items": items.len()}),
                    Err(_) => json!({"status": false, "error": health.last_error}),
                }
            }
        }
    })
}

/// §129 2d: dry-run one feed's rules against its live items. Body:
/// `{"url": …, "rules": […], "category": …}` - the EDITOR's current
/// values, not the saved ones, so rules can be tuned before applying.
/// Reply items carry the verdict ("grab" / "skip" / "seen"), the rule
/// that decided (why), and the category/priority a grab would use.
/// Nothing is fetched beyond the feed body and nothing is enqueued;
/// "seen" comes from the poller's persisted rss-seen.json, so it means
/// exactly what the poller would mean by it.
fn m_feed_preview(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        if req.method() != &tiny_http::Method::Post {
            json!({"status": false, "error": "POST required"})
        } else {
            let raw = api_body.take().unwrap_or_default();
            let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
            let url = feed_body_url(d, &body);
            let rules: Vec<String> = body
                .get("rules")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let feed_cat = body
                .get("category")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if url.is_empty() {
                json!({"status": false, "error": "no url"})
            } else {
                let r = fetch_url(&url).and_then(|f| {
                    crate::rss::parse_feed_checked(&String::from_utf8_lossy(&f.bytes))
                        .map_err(|e| anyhow::anyhow!("{e}"))
                });
                match r {
                    Err(e) => {
                        let h = crate::rss::FeedHealth::failed(
                            unix_now(),
                            &e.to_string(),
                            redact_url_creds,
                        );
                        json!({"status": false, "error": h.last_error})
                    }
                    Ok(items) => {
                        let seen: std::collections::HashSet<String> =
                            std::fs::read(d.spool.join("rss-seen.json"))
                                .ok()
                                .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
                                .map(|v| v.into_iter().collect())
                                .unwrap_or_default();
                        // Bounded: a big indexer feed is a few hundred
                        // items; the preview is a reading aid, not an
                        // export.
                        let total = items.len();
                        let rows: Vec<Value> = items
                            .into_iter()
                            .take(200)
                            .map(|it| {
                                let j = crate::rss::rules_judge(&rules, &it);
                                let verdict = if seen.contains(&it.guid) {
                                    "seen"
                                } else if j.accept {
                                    "grab"
                                } else {
                                    "skip"
                                };
                                json!({
                                    "title": it.title,
                                    "size": it.size,
                                    "verdict": verdict,
                                    "why": j.why,
                                    "category": j.opts.category.clone()
                                        .unwrap_or_else(|| feed_cat.clone()),
                                    "priority": j.opts.priority.unwrap_or(-100),
                                })
                            })
                            .collect();
                        json!({"status": true, "total": total, "items": rows})
                    }
                }
            }
        }
    })
}

fn m_indexer_test(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // M35: t=caps against one indexer entry without
        // saving it. A blank apikey borrows the stored key
        // of the same-named saved entry, so "Test" works on
        // saved rows the UI round-trips with blank keys.
        let raw = api_body.take().unwrap_or_default();
        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let cfg = serde_json::from_value::<crate::newznab::IndexerConfig>(
            body.get("indexer").cloned().unwrap_or(Value::Null),
        );
        match cfg {
            Ok(mut cfg) if !cfg.url.trim().is_empty() => {
                if cfg.apikey.is_empty()
                    && let Some(saved) = d.indexers.lock_ok().iter().find(|i| i.name == cfg.name)
                {
                    cfg.apikey = saved.apikey.clone();
                }
                // Network on the API thread is acceptable
                // here (user-clicked; the shared agent
                // carries a 15 s ceiling - the wall_search
                // precedent).
                match indexer_caps_one(&cfg) {
                    Ok(caps) => {
                        let out = json!({
                            "status": true,
                            "server": caps.server,
                            "categories": caps.categories.len(),
                            "search": caps.search,
                            // Which precision searches this
                            // site accepts, so the UI can
                            // say so rather than the user
                            // discovering it by result
                            // quality.
                            "tvsearch": !caps.tvsearch.is_empty(),
                            "movie": !caps.movie.is_empty(),
                            "imdbid": caps.movie.iter().any(|p| p == "imdbid"),
                            "tvdbid": caps.tvsearch.iter().any(|p| p == "tvdbid"),
                            "limit_default": caps.limit_default,
                        });
                        // A Test click is the freshest caps
                        // answer there is - let searches use
                        // it instead of re-probing. Under the
                        // ENDPOINT's identity, never the
                        // name: this cfg may be an unsaved
                        // draft, and a draft that borrowed a
                        // saved entry's name used to publish
                        // its caps over the saved entry's -
                        // which then planned id searches
                        // against a site it never pointed at,
                        // for the full 24 h TTL, even if the
                        // user cancelled the edit.
                        d.indexer_rt
                            .lock_ok()
                            .caps
                            .insert(cfg.identity(), (Instant::now(), Some(caps)));
                        out
                    }
                    Err(e) => json!({"status": false, "error": e.to_string()}),
                }
            }
            Ok(_) => json!({"status": false, "error": "the entry needs a URL"}),
            Err(e) => json!({"status": false, "error": format!("indexer: {e}")}),
        }
    })
}

fn m_pooltest(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        match nzbkit::config::Config::load(ctx.cfg_path) {
            Err(e) => json!({"status": false, "error": e.to_string()}),
            Ok(c) if c.servers.is_empty() => {
                json!({"status": false, "error": "no servers configured"})
            }
            Ok(mut c) => {
                c.servers.retain(|s| s.enabled);
                if c.servers.is_empty() {
                    json!({"status": false, "error": "all servers disabled"})
                } else {
                    let grp = PROBE_GROUP;
                    let conns = d.connections.load(Ordering::Relaxed).max(1);
                    let pool: Vec<(nzbkit::config::ServerConfig, nzbkit::pool::PoolConfig)> = c
                        .servers
                        .iter()
                        .map(|s| {
                            let cfg = nzbkit::pool::PoolConfig {
                                connections: conns.min(s.connections.max(1) as usize),
                                window: 4,
                                ..nzbkit::pool::PoolConfig::default()
                            };
                            (s.clone(), cfg)
                        })
                        .collect();
                    let hosts: Vec<String> = c.servers.iter().map(|s| s.host.clone()).collect();
                    tokio::runtime::Handle::current().block_on(async {
                        // Enough ids to keep a multi-gig line busy
                        // for the whole 8 s window - a small fixed
                        // supply drains early and caps the reading
                        // at supply/window.
                        let ids = match tokio::time::timeout(
                            std::time::Duration::from_secs(30),
                            nzbkit::sysbench::discover_ids(&c.servers[0], grp, 10_000),
                        )
                        .await
                        {
                            Err(_) => {
                                return json!({"status": false,
                                        "error": "article discovery timed out"});
                            }
                            Ok(Err(e)) => {
                                return json!({"status": false,
                                        "error": format!("discovery: {e}")});
                            }
                            Ok(Ok(ids)) => ids,
                        };
                        let (gbps, per, granted, _) =
                            nzbkit::sysbench::timed_fetch_multi(pool, ids, usize::MAX, 8).await;
                        d.add_usage(
                            &hosts
                                .iter()
                                .cloned()
                                .zip(per.iter().copied())
                                .collect::<Vec<_>>(),
                        );
                        let total: u64 = per.iter().sum::<u64>().max(1);
                        let servers: Vec<Value> = hosts
                            .iter()
                            .zip(per.iter().zip(&granted))
                            .map(|(h, (&b, &g))| {
                                json!({"host": h, "bytes": b, "granted": g,
                                            "share_pct": (100.0 * b as f64 / total as f64).round()})
                            })
                            .collect();
                        json!({"status": true, "gbps": gbps,
                                    "connections_per_server": conns, "servers": servers,
                                    // Yardstick for the verdict, not a
                                    // bound on the measurement (0 = unset).
                                    "line_speed": d.line_speed.load(Ordering::Relaxed)})
                    })
                }
            }
        }
    })
}

fn m_connladder(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let idx: usize = params
            .get("value")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        match nzbkit::config::Config::load(ctx.cfg_path)
            .ok()
            .and_then(|c| c.servers.into_iter().nth(idx))
        {
            None => json!({"status": false, "error": "unknown server index"}),
            Some(srv) => {
                // Probe past the CONFIGURED limit on purpose:
                // some accounts allow 100 sockets, and the knee
                // may live above a conservative config value.
                // Over-asking is harmless (refused sockets bow
                // out; `granted` exposes the real ceiling).
                let cap = (srv.connections.max(1) as usize * 2).clamp(30, 100);
                // value2=N: test exactly N sockets (one step) -
                // "how many does the provider grant if I ask?"
                let fixed: Option<usize> = params.get("value2").and_then(|v| v.parse().ok());
                // One ladder at a time. Two of them are each other's
                // contention, so a second run does not just race to
                // write - it makes both readings wrong, on a probe
                // whose entire job is measuring contention.
                // A cancel left over from a previous run must not kill
                // this one before it has measured anything. Cleared only
                // AFTER the permit is ours: a losing request (retry
                // click, second tab) that cleared first would erase a
                // cancel meant for the run still climbing, and that run
                // would then pass the !cancelled gate and record a knee
                // from wherever the user lost patience.
                let Some(_permit) = crate::serve::daemon::LadderPermit::try_take(d) else {
                    return Some(json!({"status": false,
                            "error": "a connection test is already running -                                       wait for it to finish, then try again"}));
                };
                d.ladder_cancel.store(false, Ordering::Release);
                tokio::runtime::Handle::current().block_on(async {
                    // Real-content articles from the user's own
                    // downloads, STAT-verified on this provider (design
                    // doc 12.1): the synthetic probe group undermeasured
                    // a provider 17x, in the false-low direction no
                    // guard can catch. No usable supply = no test, said
                    // plainly - never a silent probe-group fallback.
                    let ids = match tokio::time::timeout(
                        std::time::Duration::from_secs(60),
                        crate::serve::probeids::real_ladder_ids(d, &srv),
                    )
                    .await
                    {
                        Err(_) | Ok(None) => {
                            return json!({"status": false, "no_real_articles": true,
                            "error": format!(
                                "{}: no articles from your own recent downloads could \
                                 be verified on this server, so there is nothing \
                                 representative to measure with. Complete a download \
                                 first, then test again",
                                srv.host
                            )});
                        }
                        Ok(Some(ids)) => ids,
                    };
                    // Raised with the reopen check: a ladder that
                    // stopped implausibly low now spends up to three
                    // more 5 s probes proving it, and a timeout here
                    // throws away a run the user is watching.
                    match tokio::time::timeout(std::time::Duration::from_secs(240), async {
                        match fixed {
                            Some(n) => {
                                let n = n.clamp(1, 150);
                                let ids = ids.clone();
                                let cfg = nzbkit::pool::PoolConfig {
                                    connections: n,
                                    window: 4,
                                    ..nzbkit::pool::PoolConfig::default()
                                };
                                let (gbps, per, granted, saturated) =
                                    nzbkit::sysbench::timed_fetch_multi(
                                        vec![(srv.clone(), cfg)],
                                        ids,
                                        usize::MAX,
                                        6,
                                    )
                                    .await;
                                Ok(vec![nzbkit::sysbench::LadderStep {
                                    connections: n,
                                    granted: granted.first().copied().unwrap_or(0),
                                    gbps,
                                    bytes: per.first().copied().unwrap_or(0),
                                    saturated,
                                }])
                            }
                            None => {
                                // Same ceiling the auto probe judges
                                // against: what a job would really
                                // be allowed to open here.
                                let ceiling = crate::conntune::effective_limit(
                                    d.connections.load(Ordering::Relaxed),
                                    srv.connections,
                                );
                                // Publish every phase change and
                                // every settled rung as it happens:
                                // this is the run a user is sitting
                                // and watching.
                                let host = srv.host.clone();
                                let started = epoch_secs();
                                let dd = d.clone();
                                nzbkit::sysbench::conn_ladder(
                                    &srv,
                                    ids.clone(),
                                    cap,
                                    ceiling,
                                    5,
                                    |phase, at, steps| {
                                        *dd.ladder_live.lock_ok() =
                                            Some(crate::serve::daemon::LadderLive {
                                                host: host.clone(),
                                                phase: phase.into(),
                                                at,
                                                steps: steps.to_vec(),
                                                started,
                                                done: false,
                                            });
                                        !dd.ladder_cancel.load(Ordering::Acquire)
                                    },
                                )
                                .await
                            }
                        }
                    })
                    .await
                    {
                        Err(_) => {
                            if let Some(l) = d.ladder_live.lock_ok().as_mut() {
                                l.done = true;
                            }
                            json!({"status": false,
                                        "error": "connection ladder timed out"})
                        }
                        Ok(Err(e)) => json!({"status": false,
                                        "error": format!("{}: {e}", srv.host)}),
                        Ok(Ok(steps)) => {
                            // The run is over however it ends, so the
                            // watcher stops watching. Set before the
                            // re-measure below, which publishes its
                            // own phases and would otherwise leave a
                            // finished run looking live.
                            if let Some(l) = d.ladder_live.lock_ok().as_mut() {
                                l.done = true;
                            }
                            // A ladder whose rungs contradict each
                            // other gets those rungs re-measured once
                            // and averaged in before anything is read
                            // off it (~5 s per disagreeing rung). A
                            // clean curve is its own corroboration -
                            // every rung agrees with its neighbours -
                            // so it pays nothing for this.
                            let contested = crate::conntune::knee_of(&steps)
                                .map(|k| (k.contested, k.gbps))
                                .filter(|(c, _)| !c.is_empty());
                            let steps = match contested {
                                None => steps,
                                Some((rungs, peak)) => {
                                    match tokio::time::timeout(
                                        std::time::Duration::from_secs(120),
                                        // The same verified supply the
                                        // climb rotated through - the
                                        // old path re-discovered these
                                        // very ids, so overlap behavior
                                        // is unchanged.
                                        nzbkit::sysbench::remeasure(
                                            &srv,
                                            ids.clone(),
                                            &rungs,
                                            peak,
                                            5,
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(Ok(extra)) => {
                                            crate::conntune::merge_samples(&steps, &extra)
                                        }
                                        // A failed re-measure leaves
                                        // the ladder as it was: still
                                        // jagged, so still suspect.
                                        _ => steps,
                                    }
                                }
                            };
                            // Probe traffic is real provider
                            // traffic - bill it. merge_samples sums
                            // both samples' bytes into the rung, so
                            // this covers the re-measure too.
                            d.add_usage(&[(srv.host.clone(), steps.iter().map(|s| s.bytes).sum())]);
                            //
                            // No knee at all when every rung moved
                            // essentially nothing: the provider
                            // answered GROUP/OVER and then served no
                            // bodies. That is a failed test, not a
                            // knee of 2, and recording it here is
                            // the sharper half of the bug - this
                            // path writes `suspect: false`, so one
                            // such ladder would cap the server's
                            // jobs at 2 connections from the very
                            // next job, with no second probe needed.
                            match crate::conntune::knee_of(&steps) {
                                None => json!({"status": false,
                                "error": format!(
                                    "{}: the test moved no data at any connection \
                                     count - the server accepted the connections but \
                                     served no articles, so there is no knee to apply",
                                    srv.host
                                )}),
                                Some(knee) => {
                                    let (best, peak) = (knee.connections, knee.gbps);
                                    // The SAME suspicion rule the auto
                                    // probe uses. A hand-triggered run
                                    // is the less controlled of the
                                    // two - it runs whenever the user
                                    // presses it, not when the queue
                                    // and the scan are both idle - so
                                    // it has no business being the one
                                    // that applies a low knee on
                                    // sight. See conntune::is_suspect.
                                    let ceiling = crate::conntune::effective_limit(
                                        d.connections.load(Ordering::Relaxed),
                                        srv.connections,
                                    );
                                    // A `value2=N` run measures ONE rung, so
                                    // `knee_of` cannot do anything but bless
                                    // it: with a single step the peak IS that
                                    // step, nothing can fall below the bar,
                                    // and out comes a trusted knee of N from
                                    // one 6 s sample. It then caps real jobs,
                                    // and - worse - a low N parks itself as
                                    // `pending`, so the next auto probe
                                    // corroborates against a number a
                                    // diagnostic invented.
                                    //
                                    // It also contradicts the screen it is on:
                                    // the dashboard offers an explicit "Apply
                                    // N to this server" button, which only
                                    // means anything if testing does not
                                    // itself apply. So this path measures and
                                    // reports, and touches nothing.
                                    // A cancelled ladder stopped
                                    // wherever the user pressed the
                                    // button, so its rungs are a
                                    // truncated climb rather than a
                                    // curve with a knee in it -
                                    // reading one off would record a
                                    // cap from wherever they happened
                                    // to lose patience.
                                    let cancelled = d.ladder_cancel.load(Ordering::Acquire);
                                    if fixed.is_none() && !cancelled {
                                        let suspect = crate::conntune::is_suspect(
                                            best,
                                            ceiling,
                                            knee.jagged,
                                            crate::conntune::load(ctx.cfg_path).get(&srv.host),
                                        );
                                        crate::conntune::record(
                                            ctx.cfg_path,
                                            &srv.host,
                                            crate::conntune::Tuned {
                                                connections: best,
                                                granted: steps
                                                    .iter()
                                                    .map(|s| s.granted)
                                                    .max()
                                                    .unwrap_or(0),
                                                asked: knee.asked,
                                                gbps: peak,
                                                checked: epoch_secs(),
                                                source: "manual".into(),
                                                suspect,
                                                pending: None,
                                                buckets: Vec::new(),
                                                shaped: None,
                                                capped: None,
                                                limit: ceiling,
                                                v: crate::conntune::SCHEMA,
                                            },
                                        );
                                        // A trusted ladder clears the shaped
                                        // flag in the store; the dashboard's
                                        // mirror only follows the store inside
                                        // the live tuner's clean-epoch branch,
                                        // which does not run with live tuning
                                        // off or between downloads.
                                        crate::serve::tasks::mirror_shaped(
                                            d,
                                            ctx.cfg_path,
                                            &srv.host,
                                        );
                                        // Manual runs re-judge line-speed
                                        // coverage too - same as the auto probe.
                                        if let Ok(c) = nzbkit::config::Config::load(ctx.cfg_path) {
                                            crate::serve::tasks::update_tune_hint(
                                                d,
                                                &c.servers,
                                                &crate::conntune::load(ctx.cfg_path),
                                            );
                                        }
                                    }
                                    json!({
                                        "status": true,
                                        "host": srv.host,
                                        "account_limit": srv.connections,
                                        // Read-only run: nothing was stored,
                                        // so the UI must not imply a knee was
                                        // applied.
                                        "applied": fixed.is_none() && !cancelled,
                                        "cancelled": cancelled,
                                        "steps": steps,
                                        "recommended": best,
                                        // The rung the knee was read
                                        // off: once clamped to the
                                        // granted count the
                                        // recommendation matches no
                                        // rung, and the ★ marking it
                                        // in the table would vanish.
                                        "asked": knee.asked,
                                        "jagged": knee.jagged,
                                        "peak_gbps": peak,
                                        // Yardstick for the verdict, not a
                                        // bound on the measurement (0 = unset).
                                        "line_speed": d.line_speed.load(Ordering::Relaxed),
                                    })
                                }
                            }
                        }
                    }
                })
            }
        }
    })
}

/// Which servers the diversity sweep may dial, and which it is skipping.
///
/// Split out of [`m_diversity`] so the policy in its doc comment is a
/// thing that can be tested, rather than three lines buried in a request
/// handler where nothing would ever exercise them. Returns the pool and
/// the switched-off hosts, in config order.
///
/// The skipped list comes back on an OPT-IN run too. It is not dead
/// there: the page labels those rows "switched off" instead of dropping
/// the note, so the report never shows a provider without saying whether
/// it is one the user is actually downloading from.
fn diversity_pool(
    servers: &[nzbkit::config::ServerConfig],
    include_off: bool,
) -> (Vec<nzbkit::config::ServerConfig>, Vec<String>) {
    let off = servers
        .iter()
        .filter(|s| !s.enabled)
        .map(|s| s.host.clone())
        .collect();
    let pool = if include_off {
        servers.to_vec()
    } else {
        servers.iter().filter(|s| s.enabled).cloned().collect()
    };
    (pool, off)
}

/// The Server diversity card's Analyze button: STAT one shared article
/// sample on each provider and report whose gaps line up.
///
/// ENABLED SERVERS ONLY unless `value=1` says otherwise, and that is a
/// decision rather than a detail. Everywhere else in the tree the switch
/// means "do not touch this account" - a discipline a whole incident was
/// spent establishing on 23 Aug 2026, when a machine was found holding
/// live sockets to a provider marked `"enabled": false` while another
/// machine was using that same shared account. A flag whose meaning
/// depends on which code path reads it is not a flag, so this path reads
/// it the same way every other one does.
///
/// The opt-in exists because "should I turn this account back on?" is a
/// real question and filtering alone kills it. It is the shape the
/// connection ladder already uses for the neighbouring card: the
/// automatic lane never spends on an account it should not, the manual
/// button stays open, and it says what it will do before it does it (see
/// `may_spend_on_measurement`, and `ladder.blockconfirm` in the
/// dashboard). The skipped hosts ride back on the report so the page can
/// name them and offer the opt-in instead of quietly showing fewer rows,
/// which would be the same defect one layer up.
fn m_diversity(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Infrastructure-overlap detector across the download pool.
        match nzbkit::config::Config::load(ctx.cfg_path) {
            Ok(c) => {
                let include_off = params.get("value").is_some_and(|v| v == "1");
                let (pool, off) = diversity_pool(&c.servers, include_off);
                if pool.is_empty() {
                    // Not an `error`: with every server switched off the
                    // page has something useful to offer (the opt-in), and
                    // red text with no next step is not it.
                    json!({"status": false, "servers_off": off,
                           "nothing_enabled": true})
                } else {
                    let grp = PROBE_GROUP;
                    // Sample ids spanning ages, discovered from the first
                    // ENABLED server that answers (see
                    // `sample_ids_for_diversity`). Both phases hard-capped
                    // so a dead server can't wedge the API thread (see
                    // sysbench).
                    let cap = std::time::Duration::from_secs(120);
                    let t_sample = Instant::now();
                    let sample = tokio::runtime::Handle::current().block_on(async {
                        tokio::time::timeout(cap, sample_ids_for_diversity(&pool, grp))
                            .await
                            .unwrap_or_else(|_| Err("diversity sample timed out".into()))
                    });
                    match sample {
                        Ok(ids) => {
                            info!(
                                target: "diversity",
                                "sampled {} ids in {:.1}s from {} server(s){}",
                                ids.len(),
                                t_sample.elapsed().as_secs_f64(),
                                pool.len(),
                                if include_off { ", switched-off included" } else { "" }
                            );
                            let rep = tokio::runtime::Handle::current().block_on(async {
                                tokio::time::timeout(
                                    cap,
                                    nzbkit::sysbench::diversity(&pool, &ids, grp),
                                )
                                .await
                            });
                            match rep {
                                Ok(rep) => {
                                    d.add_usage(
                                        &rep.servers
                                            .iter()
                                            .map(|p| (p.host.clone(), p.bytes))
                                            .collect::<Vec<_>>(),
                                    );
                                    let mut v = serde_json::to_value(&rep)
                                        .unwrap_or(json!({"status": false}));
                                    if let Some(o) = v.as_object_mut() {
                                        o.insert("servers_off".into(), json!(off));
                                        o.insert("included_off".into(), json!(include_off));
                                    }
                                    v
                                }
                                Err(_) => json!({"status": false,
                                                "error": "diversity sweep timed out"}),
                            }
                        }
                        Err(e) => json!({"status": false, "error": e}),
                    }
                }
            }
            Err(e) => json!({"status": false, "error": e.to_string()}),
        }
    })
}

pub(in crate::serve) fn dispatch(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    mode: &str,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(match mode {
        "server_stats" => return m_server_stats(d, req, params, ctx, api_body),
        "server_save" => return m_server_save(d, req, params, ctx, api_body),
        // Reveal one server's stored cleartext password - an explicit,
        // advanced action to ease copying credentials to another
        // instance. The general server list masks it; this is the
        // deliberate exception, behind the same apikey as the rest.
        "server_secret" => return m_server_secret(d, req, params, ctx, api_body),
        // Soft on/off (keeps the server configured): value=idx,
        // value2=0|1.
        "server_enable" => return m_server_enable(d, req, params, ctx, api_body),
        // Persist a new server ORDER (e.g. fastest-first after a
        // benchmark): POST {"order":[old indices]}.
        "server_reorder" => return m_server_reorder(d, req, params, ctx, api_body),
        "server_delete" => return m_server_delete(d, req, params, ctx, api_body),
        "server_test" => return m_server_test(d, req, params, ctx, api_body),
        // §96.5: the user bought a new prepaid block - restart the
        // host's used-counter at zero (value=host).
        "server_block_refilled" => {
            return m_server_block_refilled(d, req, params, ctx, api_body);
        }
        // Which provider network a hostname belongs to, so the editor
        // can GHOST a mirror-group name (value=host, value2=index being
        // edited). Read-only and advisory: see `group_suggestion`.
        "server_backbone" => return m_server_backbone(d, req, params, ctx, api_body),
        // §G: fetch and parse ONE feed right now and say what came
        // back. The poller runs on the feed's own interval - up to a
        // quarter of an hour - so without this the only way to find out
        // whether a url works was to add it and wait, and a feed that
        // never worked at all is indistinguishable from one with nothing
        // new until the next poll writes its health.
        //
        // POST like notify_test, and for the same reason: the url IS the
        // credential (`?apikey=…`), and a GET would put it in access
        // logs, browser history and any Referer that follows.
        "feed_test" => return m_feed_test(d, req, params, ctx, api_body),
        // §129 2d: the dry run behind the Preview button - fetch the
        // feed NOW and say what the rules WOULD do, item by item,
        // without grabbing anything. POST for the same credential
        // reason as feed_test.
        "feed_preview" => return m_feed_preview(d, req, params, ctx, api_body),
        "indexer_test" => return m_indexer_test(d, req, params, ctx, api_body),
        // M18c: whole-pool burst - every server together at the
        // CURRENT Connections setting, exactly like a real
        // download. The number that matters after per-server
        // tuning: does the union saturate the line?
        "pooltest" => return m_pooltest(d, req, params, ctx, api_body),
        // M18: per-server connection-count ladder. value = server
        // index; measures Gbps at rising socket counts so the user
        // can see what raising `connections` actually buys.
        // Live state of a ladder in flight, polled by the dashboard
        // while the (minutes-long) run happens. Cheap and read-only: a
        // clone of what the prober last published.
        // Stop a ladder in flight. Returns at once - the prober notices
        // at its next rung boundary, which is within a rung (5-10 s).
        "connladder_cancel" => {
            d.ladder_cancel.store(true, Ordering::Release);
            json!({"status": true, "running": d.ladder_busy.load(Ordering::Acquire)})
        }
        "connladder_live" => match d.ladder_live.lock_ok().clone() {
            None => json!({"status": true, "running": false}),
            Some(l) => json!({
                "status": true,
                "running": !l.done,
                "host": l.host,
                "phase": l.phase,
                "at": l.at,
                "steps": l.steps,
                "started": l.started,
            }),
        },
        "connladder" => return m_connladder(d, req, params, ctx, api_body),
        "diversity" => return m_diversity(d, req, params, ctx, api_body),
        _ => return None,
    })
}

/// The word `server_test` hands the UI for a refusal it can act on.
///
/// Only an AUTHINFO/greeting refusal classifies: a timeout, a TLS
/// failure or a closed socket is not a statement about the account, and
/// labelling it "permanent" would tell the user to change a password
/// over a flaky link. Those return None and keep the plain error.
fn refusal_kind(e: &nzbkit::nntp::NntpError) -> Option<&'static str> {
    match e {
        nzbkit::nntp::NntpError::AuthFailed { kind, .. } => Some(match kind {
            // Retrying at the same connection count re-provokes it: the
            // remedy is FEWER connections, not new credentials.
            nzbkit::nntp::AuthRefusal::Capacity => "capacity",
            nzbkit::nntp::AuthRefusal::Permanent => "permanent",
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nzbkit::nntp::{AuthRefusal, NntpError};

    fn cfg(host: &str, enabled: bool) -> nzbkit::config::ServerConfig {
        serde_json::from_value(serde_json::json!({ "host": host, "enabled": enabled })).unwrap()
    }

    /// The 23 Aug 2026 switch discipline, at the one path that was left
    /// out of the sweep that established it. Everywhere else `enabled`
    /// means "do not touch this account"; a card that read it as "do not
    /// download from it, but do dial it" would make the flag mean
    /// different things on different code paths, which is the same as it
    /// meaning nothing.
    #[test]
    fn analyze_dials_the_download_pool_and_names_what_it_skipped() {
        let all = [
            cfg("off.example.net", false),
            cfg("on.example.net", true),
            cfg("also-on.example.net", true),
        ];
        let (pool, off) = diversity_pool(&all, false);
        assert_eq!(
            pool.iter().map(|s| s.host.as_str()).collect::<Vec<_>>(),
            ["on.example.net", "also-on.example.net"],
            "a switched-off account must not be dialled by an Analyze click"
        );
        assert_eq!(
            off,
            ["off.example.net"],
            "and the page has to be able to say which ones it skipped, or \
             the report quietly shows fewer providers than the user has"
        );
    }

    /// The opt-in is the half that keeps "is this account worth turning
    /// back on?" answerable. It restores CONFIG ORDER rather than
    /// appending the switched-off ones, because the report is read as a
    /// list of the user's servers.
    #[test]
    fn the_opt_in_restores_every_configured_server_in_config_order() {
        let all = [cfg("off.example.net", false), cfg("on.example.net", true)];
        let (pool, off) = diversity_pool(&all, true);
        assert_eq!(
            pool.iter().map(|s| s.host.as_str()).collect::<Vec<_>>(),
            ["off.example.net", "on.example.net"]
        );
        assert_eq!(
            off,
            ["off.example.net"],
            "still reported on an opt-in run - the page marks those rows \
             switched off rather than dropping the note"
        );
    }

    /// An all-disabled config has an empty pool by default, and that is
    /// what puts the page on the opt-in branch instead of an error. The
    /// distinction matters: `m_diversity` answers `nothing_enabled` here
    /// rather than `error`, because there is a useful next step to offer
    /// and red text with no next step is not one.
    #[test]
    fn every_server_switched_off_leaves_an_empty_pool_not_a_partial_one() {
        let all = [cfg("a.example.net", false), cfg("b.example.net", false)];
        assert!(diversity_pool(&all, false).0.is_empty());
        assert_eq!(diversity_pool(&all, false).1.len(), 2);
        assert_eq!(diversity_pool(&all, true).0.len(), 2);
    }

    /// The mapping the dashboard's remedy text hangs off. Capacity and
    /// permanent are opposite advice - "lower your connections" versus
    /// "your password is wrong" - so getting this backwards sends the
    /// user to change a credential that works.
    #[test]
    fn a_refusal_reaches_the_ui_as_the_kind_the_pool_classified() {
        let cap = NntpError::AuthFailed {
            kind: AuthRefusal::Capacity,
            line: "481 max simultaneous IP addresses reached".into(),
        };
        assert_eq!(refusal_kind(&cap), Some("capacity"));
        let perm = NntpError::AuthFailed {
            kind: AuthRefusal::Permanent,
            line: "481 authentication failed".into(),
        };
        assert_eq!(refusal_kind(&perm), Some("permanent"));
        // Not a statement about the account: no remedy, plain error.
        assert_eq!(refusal_kind(&NntpError::Timeout), None);
        assert_eq!(refusal_kind(&NntpError::Closed), None);
        assert_eq!(
            refusal_kind(&NntpError::Unexpected {
                cmd: "<greeting>".into(),
                line: "502 permission denied".into(),
            }),
            None
        );
    }

    /// The classifier the arm above depends on, exercised through the
    /// same door `Connection::connect` uses. A provider at its cap and a
    /// wrong password share reply code 481, so the TEXT is the whole
    /// signal - and anything unrecognised must fall to Permanent, since
    /// retrying a bad credential forever is the worse failure.
    #[test]
    fn capacity_wording_is_told_apart_from_a_rejected_credential() {
        for line in [
            "481 max simultaneous IP addresses reached",
            "502 Too many connections",
            "481 Connection limit reached",
        ] {
            assert_eq!(
                nzbkit::nntp::classify_auth_refusal(line),
                AuthRefusal::Capacity,
                "{line}"
            );
        }
        for line in ["481 authentication failed", "481 account suspended"] {
            assert_eq!(
                nzbkit::nntp::classify_auth_refusal(line),
                AuthRefusal::Permanent,
                "{line}"
            );
        }
    }

    fn srv(host: &str, group: Option<&str>) -> nzbkit::config::ServerConfig {
        serde_json::from_value(json!({"host": host, "group": group})).unwrap()
    }

    /// The editor may only ghost a name it can defend. A hostname the
    /// alias table does not list resolves to its own label, and
    /// proposing "myisp" as a provider network teaches the user that
    /// the field means something it does not.
    #[test]
    fn an_unlisted_host_is_offered_no_group_at_all() {
        assert!(group_suggestion(&[], "news.myisp.example", -1).is_none());
        assert!(group_suggestion(&[], "localhost", -1).is_none());
        assert!(group_suggestion(&[], "   ", -1).is_none());
        // Nor does an unlisted twin invent one between them: two hosts
        // of one unknown brand with no name yet are still two servers
        // the page has nothing to call.
        let cfg = [srv("news1.myisp.example", None)];
        assert!(group_suggestion(&cfg, "news2.myisp.example", -1).is_none());
    }

    /// ...but once one of that pair HAS a name, the other is offered it.
    /// The evidence there is the user's own config, not the alias table,
    /// and two hosts of one brand really are one network.
    #[test]
    fn an_unlisted_twin_still_lends_the_name_its_owner_chose() {
        let cfg = [srv("news1.myisp.example", Some("my isp"))];
        let g = group_suggestion(&cfg, "news2.myisp.example", -1).expect("same key as the twin");
        assert_eq!(g.suggest, "my isp");
        assert_eq!(g.same_as.as_deref(), Some("news1.myisp.example"));
    }

    /// With nothing else configured on that backbone, the oracle's own
    /// name for it is the proposal.
    #[test]
    fn a_listed_host_alone_is_offered_the_backbone_name() {
        let g = group_suggestion(&[], "news.eweka.nl", -1).expect("eweka is listed");
        assert_eq!(g.backbone, "eweka");
        assert_eq!(g.suggest, "eweka");
        assert_eq!(g.same_as, None);
    }

    /// The point of the field is that both servers spell the group
    /// IDENTICALLY - a second spelling folds nothing. So an existing
    /// name on the same backbone wins over the backbone's own name,
    /// whatever the user called it.
    #[test]
    fn a_sibling_on_the_same_backbone_lends_its_own_spelling() {
        let cfg = [
            srv("news.myisp.example", Some("ignore me")),
            srv("news.newshosting.com", Some("Highwinds")),
        ];
        let g = group_suggestion(&cfg, "news.usenetserver.com", -1).expect("listed");
        assert_eq!(g.backbone, "highwinds");
        assert_eq!(g.suggest, "Highwinds");
        assert_eq!(g.same_as.as_deref(), Some("news.newshosting.com"));
        // A server on a DIFFERENT backbone lends nothing, even though
        // it has a perfectly good name. Eweka qualifies: same OWNER as
        // Newshosting, its own spool, so it is not a sibling here.
        for other in [
            [srv("news.giganews.com", Some("giga"))],
            [srv("news.eweka.nl", Some("eweka"))],
        ] {
            let g = group_suggestion(&other, "news.usenetserver.com", -1).expect("listed");
            assert_eq!(g.suggest, "highwinds");
            assert_eq!(g.same_as, None);
        }
    }

    /// The server being edited must not have its own name handed back
    /// to it: the box is blank because the user cleared or never set it,
    /// and echoing the stored value would look like the field had
    /// refilled itself.
    #[test]
    fn the_server_being_edited_is_not_its_own_sibling() {
        let cfg = [srv("news.newshosting.com", Some("mine"))];
        let g = group_suggestion(&cfg, "news.newshosting.com", 0).expect("listed");
        assert_eq!(g.suggest, "highwinds");
        assert_eq!(g.same_as, None);
        // ...but the SAME list, seen while adding a second server, does
        // lend that name.
        let g = group_suggestion(&cfg, "news.usenetserver.com", -1).expect("listed");
        assert_eq!(g.suggest, "mine");
        assert_eq!(g.same_as.as_deref(), Some("news.newshosting.com"));
    }

    /// A blank or whitespace group on a sibling is not a name.
    #[test]
    fn a_sibling_with_an_empty_group_lends_nothing() {
        let cfg = [
            srv("news.newshosting.com", Some("  ")),
            srv("news.easynews.com", None),
        ];
        let g = group_suggestion(&cfg, "news.usenetserver.com", -1).expect("listed");
        assert_eq!(g.suggest, "highwinds");
        assert_eq!(g.same_as, None);
    }
}
