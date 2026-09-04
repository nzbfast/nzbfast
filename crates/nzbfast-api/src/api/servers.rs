use super::super::*;
use super::ApiCtx;

/// Is `k` one of the usage ledger's DATE buckets?
///
/// The store is keyed `"YYYY-MM-DD" -> host -> bytes`, plus four
/// buckets that are not days and are never pruned as days:
/// `"lifetime"` (billed in parallel, answers the total),
/// `"reliability"` (lifetime article try counts, not bytes),
/// `"article_days"` (the same tally with a day dimension, pruned per
/// host rather than by this rule) and `"block_base"` (the §96.5
/// per-host lifetime offset stamped when the user pressed "Block
/// refilled").
///
/// Naming the non-date buckets and skipping those is what this used to
/// do, and it is the wrong way round: `"block_base"` was added after
/// the skip list was written, and `"block_base" >= "2026-08-22"` is
/// TRUE as a string comparison (`'b'` is 0x62, `'2'` is 0x32), so
/// every byte of that host's stamped lifetime figure was billed into
/// the WEEK column and stayed there forever. Asking what a key IS
/// costs the same and is proof against the fifth bucket somebody adds.
/// `crate::history::usage_sums` and the dashboard's own usage
/// table already classify this way.
fn is_date_bucket(k: &str) -> bool {
    let mut parts = k.split('-');
    let (Some(y), Some(m), Some(d), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    y.len() == 4
        && y.parse::<u32>().is_ok()
        && m.parse::<u32>().is_ok_and(|m| (1..=12).contains(&m))
        && d.parse::<u32>().is_ok_and(|d| (1..=31).contains(&d))
}

/// A per-server object with every field SAB publishes, at zero. The
/// three MAP fields are the shape half of GitHub #69 / TODO 320:
/// `_api_server_stats` hands the client `daily`, `articles_tried` and
/// `articles_success` as `{"YYYY-MM-DD": n}` objects
/// (`BPSMeter.amounts` returns `timeline_total`, `article_stats_tried`
/// and `article_stats_failed`, all declared `dict[str, dict[str, int]]`),
/// and we published `{}` for the first and a bare integer for the other
/// two. A statically-typed client deserializing `Map<String,Int>` from
/// `0` throws where it stands, which is what crashed nzb360's download
/// history view against us and not against SAB.
///
/// One function rather than a literal at each site because there were
/// two copies of that literal and both were wrong in the same way.
fn empty_server_stats() -> Value {
    json!({"total": 0u64, "month": 0u64, "week": 0u64, "day": 0u64,
           "daily": {}, "articles_tried": {}, "articles_success": {}})
}

/// The `mode=server_stats` payload, off the usage ledger. `days` is the
/// current UTC day number and `configured` is every server host in the
/// config, traffic or not. Split out from the handler so the bucket
/// classification above is testable without standing up a daemon.
fn server_stats_json(
    u: &serde_json::Map<String, Value>,
    days: i64,
    configured: &[String],
) -> Value {
    // Shape SAB apps expect: total/month/week/day bytes,
    // plus the same per server - fed from the usage ledger.
    let (y, m, dd) = civil_from_days(days);
    let today = format!("{y:04}-{m:02}-{dd:02}");
    let month_prefix = format!("{y:04}-{m:02}");
    let week_cut = {
        let (wy, wm, wd) = civil_from_days(days - 6);
        format!("{wy:04}-{wm:02}-{wd:02}")
    };
    let mut tot = (0u64, 0u64, 0u64, 0u64); // total, month, week, day
    let mut servers = serde_json::Map::new();
    // SAB iterates `config.get_servers()`, so a configured server that
    // has never been used still appears, with zeros. We built this map
    // from the LEDGER alone, so a second account showed up only once it
    // had spent something - and a client that walks its own server list
    // and indexes `servers[name]` got a null. That is an independent
    // crash path from the map-shaped fields above, and a compat bug on
    // its own (GitHub #69 finding 3). Seeded first, so the ledger fills
    // these in rather than the other way round.
    for host in configured {
        servers
            .entry(host.clone())
            .or_insert_with(empty_server_stats);
    }
    for (day, hosts) in u {
        let lifetime = day == "lifetime";
        if !lifetime && !is_date_bucket(day) {
            continue; // "reliability", "block_base", anything added next
        }
        let Some(hosts) = hosts.as_object() else {
            continue;
        };
        for (host, b) in hosts {
            let b = b.as_u64().unwrap_or(0);
            let e = servers
                .entry(host.clone())
                .or_insert_with(empty_server_stats);
            let eo = e.as_object_mut().unwrap();
            let bump = |eo: &mut serde_json::Map<String, Value>, k: &str, v: u64| {
                let cur = eo.get(k).and_then(Value::as_u64).unwrap_or(0);
                eo.insert(k.into(), json!(cur + v));
            };
            if lifetime {
                bump(eo, "total", b);
                tot.0 += b;
            } else {
                // `daily`: the per-day byte history, SAB's
                // `timeline_total`. This loop already had the value in
                // hand for the three windows below and threw it away,
                // so the map went out empty on every install - the
                // chart the client draws from it was blank even before
                // the shape above crashed the parse (GitHub #69
                // finding 1).
                if let Some(dm) = eo
                    .entry("daily")
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                {
                    let cur = dm.get(day.as_str()).and_then(Value::as_u64).unwrap_or(0);
                    dm.insert(day.clone(), json!(cur + b));
                }
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
    // The LIFETIME reliability bucket only puts the host on the list.
    // A provider that answered nothing but 430s has articles tried and
    // zero bytes billed, so it is in no date bucket and would otherwise
    // be missing from a payload that is partly about how badly it is
    // doing.
    if let Some(rel) = u.get("reliability").and_then(Value::as_object) {
        for host in rel.keys() {
            servers
                .entry(host.clone())
                .or_insert_with(empty_server_stats);
        }
    }
    // The counters themselves come from the DAY-dimensioned bucket,
    // which is what SAB publishes. A host with lifetime tries and no
    // day rows - every install that upgrades into this, until its next
    // download - gets `{}`, which is what SAB gives for a server it has
    // no article stats for. Deliberately not a synthetic key for today:
    // that would attribute the whole history to one day.
    if let Some(byday) = u.get("article_days").and_then(Value::as_object) {
        for (host, rows) in byday {
            let Some(rows) = rows.as_object() else {
                continue;
            };
            let e = servers
                .entry(host.clone())
                .or_insert_with(empty_server_stats);
            let Some(eo) = e.as_object_mut() else {
                continue;
            };
            let (mut tried_m, mut succ_m) = (serde_json::Map::new(), serde_json::Map::new());
            for (day, counts) in rows {
                if !is_date_bucket(day) {
                    continue;
                }
                let g = |k| counts.get(k).and_then(Value::as_u64).unwrap_or(0);
                let (tried, missing) = (g("tried"), g("missing"));
                tried_m.insert(day.clone(), json!(tried));
                // TODO 320 finding 4, NOT yet decided: SAB's own
                // `_api_server_stats` unpacks `article_stats_FAILED`
                // into the key `articles_success`, so a client
                // calibrated against SAB reads this number as failures.
                // We publish true successes. Whether to be bug-for-bug
                // compatible with an upstream misnomer is a maintainer's
                // call, so the meaning is left exactly as it was and
                // only the SHAPE moved here.
                succ_m.insert(day.clone(), json!(tried.saturating_sub(missing)));
            }
            eo.insert("articles_tried".into(), Value::Object(tried_m));
            eo.insert("articles_success".into(), Value::Object(succ_m));
        }
    }
    json!({"total": tot.0, "month": tot.1, "week": tot.2, "day": tot.3,
                    "servers": Value::Object(servers)})
}

fn m_server_stats(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    // Clone and drop the usage guard on this line: `current_servers`
    // below reads the config off disk, and the ledger mutex is taken by
    // every finishing download.
    let u = d.usage.lock_ok().clone();
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(0);
    // Keyed by `host`, which is what the ledger bills to, so a
    // configured server that HAS spent something lands on its own row
    // rather than beside a duplicate.
    let configured: Vec<String> = current_servers(ctx.cfg_path)
        .iter()
        .filter_map(|s| s.get("host").and_then(Value::as_str))
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .collect();
    Some(server_stats_json(&u, days, &configured))
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

/// Take a server out of the pool, or put it back, without removing it
/// from the list.
///
/// **This writes the config and nothing else - it never signals the
/// running warm pool.** The enabled set is read once per job, in
/// `get/plan.rs`'s `build_intake`, which is what builds the pool; so a
/// server switched off here keeps the sockets it already holds until
/// the next plan build, and the planner then logs
/// `<host> disabled - not in the pool`. Same timing as the scheduled
/// twin in `sched.rs` (`SchedAction::ServerEnable`), which says
/// so too and is keyed by host rather than by list index.
///
/// That gap is normally the tail of the running job. It is not bounded
/// by anything: measured on the live daemon 26 Aug 2026, five providers
/// disabled at 14:21:40Z still held 3 to 4 warm sockets each an hour
/// later and cleared only at the 15:29:51Z plan build - 68 minutes,
/// because the daemon was sitting on one long job at 0.0 MB/s with
/// nothing to trigger a re-plan. A lane read the config back, saw
/// `enabled: false`, and posted to three bench coordination files that
/// the accounts were free; they were not - the whole measurement is in
/// `research/COORD-PHANTOM-CLEARED-2026-08-26.md`, finding 2.
///
/// The dashboard toast (`toast.srvOff`) names that timing, and must
/// keep naming it. Whether the click should instead tear the pool down
/// immediately is an open PRODUCT question and not an oversight to fix
/// in passing: an immediate teardown fails the articles in flight on
/// those sockets, and any of them the surviving pool cannot serve
/// become misses on a post that is not missing. Do not change the
/// timing here without that decision.
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
pub(crate) struct GroupSuggestion {
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
pub(crate) fn group_suggestion(
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

/// One rung of the carry probe: what was asked for, what the provider
/// actually granted, and what came back.
///
/// `granted` and not `connections` is what the carry divides by, and
/// the distinction is the whole reason this struct carries both. A
/// provider that allows ten sockets and was asked for sixteen grants
/// ten; dividing the achieved rate by sixteen invents a carry 1.6x too
/// low and an implied fleet 1.6x too high, which is the direction §312
/// names as the hazard. `nzbkit::sysbench::timed_fetch_multi` reports
/// the PEAK held at once, so a provider that sheds a socket in the last
/// second of the window is still credited with having granted it.
struct CarryRung {
    connections: usize,
    granted: usize,
    bps: u64,
    bytes: u64,
    /// The rung drained its article supply before the window closed, so
    /// the connect ramp is inside the measured span and the rate reads
    /// slightly LOW. Reported rather than hidden: a low carry is the
    /// direction that over-states the implied fleet.
    drained: bool,
}

impl CarryRung {
    /// Bytes/s ONE socket carried, or `None` when the provider granted
    /// none - which is a fact about the account, not a failed probe.
    fn per_socket(&self) -> Option<u64> {
        (self.granted > 0).then(|| self.bps / self.granted as u64)
    }

    fn to_json(&self) -> Value {
        json!({
            "connections": self.connections,
            "granted": self.granted,
            "bps": self.bps,
            "bytes": self.bytes,
            "drained": self.drained,
            "per_socket_bps": self.per_socket(),
        })
    }
}

/// What a probe owes the account, kept OUTSIDE the future that measures.
///
/// Both probes in this module run their measurement inside a hard
/// `tokio::time::timeout`, and both keep the rungs they have completed
/// in a `Vec` INSIDE that future: the carry probe's `rungs`, the
/// ladder's `out`. A cancelled timeout drops the future and the Vec
/// with it, so on the timeout arm the bytes a completed rung really
/// moved were unrecoverable and nothing reached `add_usage` - while
/// every other arm of the same handler bills. This counter is created
/// before the timeout and only borrowed by it, so it survives the
/// cancellation and gives every exit ONE number to bill from.
///
/// It matters because the rule the billing sites state - a rung that
/// ran moved real bytes whatever the probe then concluded - has to hold
/// for a probe that never concluded too. A rung is up to
/// [`CARRY_MAX_ARTICLES`] articles (roughly 77 - 307 MB), and nothing
/// back-fills it later: `Daemon::flush_run_usage` folds the download
/// hub's pool, and these probes build their own. Unbilled, a prepaid
/// block's remaining figure and its exhaustion latch read high by that
/// amount and cut the account off later than the user was promised.
#[derive(Default)]
struct ProbeBill(AtomicU64);

impl ProbeBill {
    /// Bill one completed rung.
    ///
    /// Called the instant the rung returns and BEFORE the rotation and
    /// the push that follow it, so a rung that finished is counted even
    /// when the next await never resumes.
    fn rung(&self, bytes: u64) {
        self.0.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Bill from a RUNNING TOTAL of every rung settled so far.
    ///
    /// The ladder's progress callback is handed the whole `steps` slice
    /// each time rather than the newest rung, so its figure replaces
    /// this counter instead of adding to it. Never mixed with
    /// [`ProbeBill::rung`] on one counter.
    fn total(&self, bytes: u64) {
        self.0.store(bytes, Ordering::Relaxed);
    }

    /// What to hand `add_usage`, on whichever exit the probe takes.
    fn owed(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Measure one rung: `n` sockets against `srv` for `CARRY_RUNG_SECS`.
///
/// `ids` is rotated by the caller between rungs and never re-read
/// within a run, which is not tidiness - a provider (or anything on the
/// path) that cached the first rung's articles would serve the second
/// rung from memory, and the second rung is the one this probe compares
/// against the first. A warm re-read would show carry HOLDING at the
/// higher socket count on a link where it does not.
async fn carry_rung(srv: &nzbkit::config::ServerConfig, ids: Vec<String>, n: usize) -> CarryRung {
    let cfg = nzbkit::pool::PoolConfig {
        connections: n,
        window: 4,
        ..nzbkit::pool::PoolConfig::default()
    };
    let (gbps, per, granted, drained) = nzbkit::sysbench::timed_fetch_multi(
        vec![(srv.clone(), cfg)],
        ids,
        CARRY_MAX_ARTICLES,
        CARRY_RUNG_SECS,
    )
    .await;
    CarryRung {
        connections: n,
        granted: granted.first().copied().unwrap_or(0),
        // `timed_fetch_multi` answers in giga BITS; every rate this
        // daemon stores and every rate `linecap` divides is BYTES/s.
        bps: (gbps * 1e9 / 8.0).max(0.0) as u64,
        bytes: per.first().copied().unwrap_or(0),
        drained,
    }
}

/// How long each rung runs for.
///
/// The same 6 s the fixed-rung ladder uses, and the floor is set by
/// `timed_fetch_multi`'s own estimator rather than by patience: it
/// measures first-completion to last-completion - excluding the
/// connect, TLS and slow-start ramp, which is exactly the bias that
/// would make a carry probe lie - but only once at least 8 articles
/// have landed and the span is a second or more. Under that it falls
/// back to the whole window WITH the ramp in it, and reads low.
///
/// Both rungs are sized to clear that bar in the regime this probe
/// exists for: articles are 300 KB - 1.2 MB (`serve::probeids`), so a
/// socket carrying GH #62's ~7 Mbit completes about one a second, and
/// the smaller rung is at least two sockets.
const CARRY_RUNG_SECS: u64 = 6;

/// The most articles either rung will pull, whatever the link can do.
///
/// This is the probe's COST CONTROL and it is a count rather than a
/// window because a window is not one: six seconds is 26 MB on the
/// slow-per-socket link this probe exists for and 750 MB on a gigabit
/// one, so a time bound alone lets a diagnostic button spend a
/// gigabyte and a half to tell a user their sizing is fine. Measured
/// against a loopback provider on 28 Aug 2026: uncapped, one rung moved
/// 1.36 GB.
///
/// At `serve::probeids`' 300 KB - 1.2 MB band this is roughly 77 MB to
/// 307 MB a rung. The number is chosen so the CAP AND THE ANSWER NEVER
/// MEET, which is the property that makes capping safe here rather than
/// merely cheap:
///
/// * A rung that drains its supply early is timed to its real transfer
///   span, so it stays accurate - until that span falls under a second,
///   below which `timed_fetch_multi` reverts to a whole-window figure
///   with the connect ramp inside it and reads LOW. Draining this many
///   articles inside a second needs about 2.3 Gbit/s.
/// * Reading low over-states the implied fleet, which is the unsafe
///   direction. But an over-statement only MATTERS where the carry is
///   far under the plan, and that is a slow link by definition - one
///   that cannot come close to this cap in six seconds.
///
/// So the regime where a capped rung could lie and the regime where the
/// number is worth acting on do not overlap. `drained` is reported
/// either way rather than left to be inferred.
const CARRY_MAX_ARTICLES: usize = 256;

/// The smallest article `serve::probeids` will put in a probe supply.
///
/// Used only to turn a rung's byte count back into an article count for
/// the rotation, where over-stating is the safe direction.
const MIN_PROBE_ARTICLE_BYTES: u64 = 300_000;

/// The most sockets either rung will open, whatever the account allows.
///
/// A deliberate press is not a licence to put a provider's whole
/// account on the wire: the ladder next door climbs to 100 because it
/// is looking for a knee and has to find one, while this probe only has
/// to divide a rate by a socket count and gets nothing extra from a
/// bigger fleet.
const CARRY_MAX_CONNS: usize = 24;

/// Which regime the two rungs saw, as a TOKEN the dashboard
/// translates: the whole reason the probe runs two of them.
///
/// `base` and `more` are the per-socket carry at the fleet share and at
/// twice it. The ratio between them IS the answer, because the socket
/// count doubled: a carry that HOLDS means the total doubled, so the
/// route limits each CONNECTION and a bigger fleet buys proportionally
/// more - GH #62's regime, and the one where the implied fleet is a
/// real number. A carry that HALVES means the total did not move at
/// all, so the line or the path was already full and more sockets buy
/// nothing; the implied fleet is then arithmetic on a rate that cannot
/// be had, and the panel must not read as advice to go and get it.
///
/// `unknown` whenever there is no comparison to make - one rung only
/// because the account's ceiling was already reached, or no sockets
/// granted at all. Never a guess: a verdict this panel asserts is one a
/// user might act on.
fn carry_scaling(base: Option<u64>, more: Option<u64>) -> &'static str {
    match (base, more) {
        (Some(a), Some(b)) if a > 0 => match (b as f64) / (a as f64) {
            r if r >= 0.9 => "per_connection",
            r if r >= 0.6 => "mixed",
            _ => "line",
        },
        _ => "unknown",
    }
}

/// The two socket counts to measure at: what a download would really
/// dial on this server right now, and twice that.
///
/// `share` is this server's share of the fleet in force and `ceiling`
/// is what the account and the global dial allow, already held to
/// [`CARRY_MAX_CONNS`]. Two sockets is the floor because one is the
/// rung most likely to miss `timed_fetch_multi`'s 8-completion bar and
/// read ramp-biased low (see [`CARRY_RUNG_SECS`]), and low is the
/// direction that OVER-states the implied fleet.
///
/// When doubling the share would run past the ceiling - a single-server
/// install whose share IS the whole fleet, or any share over half the
/// ceiling (two servers at the auto curve's 25..=50 rungs give shares
/// of 13 to 23 against the 24 cap) - a true doubling cannot exist ABOVE
/// the share, so the BASE rung drops to half the ceiling instead and
/// the pair is still a genuine doubling (12 and 24 on the defaults).
/// It has to be genuine: [`carry_scaling`]'s 0.9/0.6 bars and its own
/// doc assume the socket count doubled, so a pair merely CLAMPED to the
/// ceiling (23 and 24) reads a fully line-bound link as
/// `per_connection` - the one verdict that tells the user more sockets
/// would go faster, about a link where they would not. The trade is
/// that the base rung stops being literally "what a download dials" in
/// these shapes, which the single-server case already accepted. The
/// probe never asks the account for a socket past the ceiling, which
/// would measure the provider's refusals rather than this link's
/// carry. Only a ceiling under 4 defeats the halving (half of it
/// collides with the two-socket floor), and there the rungs stay
/// equal, the caller runs one, and the panel says no comparison was
/// possible rather than staying silent about it.
fn carry_rungs_for(share: usize, ceiling: usize) -> (usize, usize) {
    let hi = ceiling.max(2);
    let mut now = share.clamp(2, hi);
    if now * 2 > hi && hi >= 4 {
        now = hi / 2;
    }
    (now, (now * 2).min(hi))
}

/// How many servers the next download will actually share the fleet
/// between: the ENABLED rows only.
///
/// The carry probe divides a fleet by this number, so counting the raw
/// editor list was wrong in the one direction that matters. An install
/// with five rows and two switched off measured a five-way share while
/// the next job opens a three-way one, so the panel reported a smaller
/// per-server share than the download will use - and reported the wrong
/// server count beside it. The job path drops disabled rows before it
/// builds a pool and the Providers card (`api/queue/caps.rs`
/// `planned_servers`) counts only enabled ones, so this is the third
/// spelling of one question and it now agrees with the other two.
///
/// Spelled over the RAW editor values rather than over
/// `nzbkit::config::Config::load`, because the caller resolves the row
/// it is probing out of this SAME list by index: two lists could differ
/// in length, and then the share would describe a set of rows that is
/// not the one the index was resolved against. An ABSENT `enabled` key
/// is enabled, matching `ServerConfig`'s own `default_true` - reading it
/// as false would have counted a hand-written config's rows as switched
/// off, since the key is only written when it is `false`.
///
/// COUNTS ONLY. Never filter the list itself: the row being probed is
/// resolved by raw index, so a filtered list mis-resolves every row
/// after a disabled one and would send the probe at the wrong host with
/// the wrong stored password.
fn enabled_server_count(servers: &[Value]) -> usize {
    servers
        .iter()
        .filter(|s| s.get("enabled").and_then(Value::as_bool).unwrap_or(true))
        .count()
}

/// Is a download in flight - the one signal both connection probes in
/// this file gate on?
///
/// `index_jobs_active`, and never `active_stream`: that slot outlives
/// its job on purpose so playback keeps working after a download
/// completes, so a probe gated on it would refuse for ever after the
/// first one. [`carry_refusal`] carries the whole argument. The counter
/// is raised by the post-processing ticket as well as by the runner, so
/// this is WIDER than "on the wire" - unpack and repair count - which is
/// why [`downloading_refusal`]'s sentence says so.
fn downloading_now(d: &Daemon) -> bool {
    d.index_jobs_active.load(Ordering::Acquire) > 0
}

/// The refusal both of those doors owe that download, written once
/// because a second spelling is the one nobody holds to the rule. The
/// `downloading` flag rides back on the answer so a panel can key on the
/// refusal rather than pattern-matching the prose.
fn downloading_refusal(downloading: bool) -> Option<Value> {
    if !downloading {
        return None;
    }
    let why = "a download is running - this test opens its own \
               connections, so running it now would take capacity from \
               the job and can make its own reconnects fail. Unpacking \
               and repair count as running too. Wait until nothing is \
               in the queue, then try again";
    Some(json!({"status": false, "downloading": true, "error": why}))
}

/// Why the carry probe may not run right now, or None when it may.
///
/// Split out of [`m_server_carry`] the way [`diversity_pool`] is split
/// out of [`m_diversity`], and for the same reason: a policy buried in a
/// request handler is one nothing ever exercises. Both answers are
/// reached BEFORE the shared ladder permit is taken, so the permit's
/// release assertion in `tests/daemon_carry` still means what it says -
/// a refusal never takes a permit it then has to remember to drop.
///
/// # A download is running
///
/// The probe opens a FRESH pool of up to [`CARRY_MAX_CONNS`] sockets for
/// two short rungs. Against an account already at its connection or IP
/// cap that draws refusals, and the live job's own reconnects then fail
/// - so the permit excluding another ladder or probe was never enough:
/// the thing most likely to be using this account is the download.
///
/// `downloading` must come from `index_jobs_active`, which is this
/// tree's "a download is running" signal in `index_maintenance_ok` and
/// `db_maintenance_ok`, and NOT from `active_stream`. That slot
/// deliberately outlives its job so playback keeps working after a
/// download completes (`whyslow.rs` says the same at its own site
/// and filters by job state before reading it), so a probe gated on it
/// would refuse for ever after the first download.
///
/// The counter is held by the post-processing ticket as well as by the
/// runner, so this refusal is WIDER than "on the wire" - it also covers
/// unpack and repair. That is deliberate, the point being not to
/// compete for the account, and the text says so: a user watching an
/// idle-looking network graph would otherwise read the refusal as a
/// bug.
///
/// # A switched-off server
///
/// Everywhere else in the tree the switch means "do not touch this
/// account" - the discipline a whole incident was spent establishing on
/// 23 Aug 2026, when a machine was found holding live sockets to a
/// provider marked `"enabled": false` while another machine was using
/// that same shared account. So this door reads it the way every other
/// one does, and offers [`m_diversity`]'s opt-in for the same reason it
/// does: "should I turn this account back on?" is a real question and
/// filtering alone kills it. `server_off` rides back on the refusal so
/// the panel can name the row and offer the opt-in rather than showing
/// red text with no next step.
fn carry_refusal(
    host: &str,
    downloading: bool,
    server_off: bool,
    include_off: bool,
) -> Option<Value> {
    // Not escapable, unlike the switch below: an opt-in here would be
    // an opt-in to making the running job slower.
    if let Some(no) = downloading_refusal(downloading) {
        return Some(no);
    }
    if server_off && !include_off {
        // Built above the macro rather than inside it, so the sentence
        // stays one readable block: rustfmt re-indents a multi-line
        // `format!` inside a `json!` body against the macro's own
        // bracket depth and the wrapped string ends up unreadable.
        let why = format!(
            "{host} is switched off, so it is not in the download pool and a \
             job would never dial it. Switch it on to measure it, or ask \
             again with \"include switched off\" to answer \"is this account \
             worth turning back on?\""
        );
        return Some(json!({"status": false, "server_off": true,
            "host": host, "error": why}));
    }
    None
}

/// TODO 312 item 2: what one socket to this provider actually carries,
/// and what fleet that carry implies for this line.
///
/// **This measures and reports. It persists nothing and changes no
/// arithmetic** - not the fleet, not the cap, not the knee, not the
/// per-server connection count. The representation a MEASURED carry
/// gets when it is eventually allowed to change what the pool spends is
/// TODO 275 item 1 parts 1+2, and the ceiling question is item 7 - a
/// judgement about what every install spends; a second spelling landed
/// here first would be the one nobody holds to the rule.
///
/// **Why two rungs.** One number cannot tell the two regimes apart, and
/// they want opposite advice. A route that limits each CONNECTION (GH
/// #62: ~6.4-7.6 Mbit a socket against AU-routed providers, on a line
/// that reads 1 Gbit) carries the same per socket however many are
/// open, so more sockets buy proportionally more and the implied fleet
/// is real. A line or path that is already full carries less per socket
/// as sockets are added, the total does not move, and the implied fleet
/// is a fiction. So the probe measures the fleet share this install
/// actually dials here, then twice that, and reports which happened.
///
/// **Why it starts at the fleet share and not at one socket.** The
/// number `linecap` divides is a whole pool's rate over its dialling
/// sockets, so a carry measured in a fleet is the like-for-like one. A
/// single socket alone is also the rung most likely to miss
/// `timed_fetch_multi`'s 8-completion bar and read ramp-biased low (see
/// `CARRY_RUNG_SECS`), and low is the unsafe direction here.
///
/// **When it refuses.** Two states are refused before anything is
/// dialled and before the shared permit is taken - a download in flight,
/// and a switched-off row. Both, and why the obvious spellings of each
/// are wrong, are in [`carry_refusal`]. The permit itself excludes only
/// another ladder or probe, which was never the thing most likely to be
/// using the account.
fn m_server_carry(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // The editor's current values merged over the saved row, the
        // same way `server_test` does it - so a blank password borrows
        // the stored one and the probe can be run before a save.
        let raw = api_body.take().unwrap_or_default();
        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let idx = body.get("index").and_then(Value::as_i64).unwrap_or(-1);
        // The opt-in for a switched-off row, and it rides in the BODY
        // rather than as `value=1` the way `m_diversity`'s does. Not a
        // second spelling by choice: the dashboard reaches this mode
        // through `apiPost`, which builds `/api?mode=<mode>` and has no
        // query string to add a flag to, so the body is the only
        // transport this door has. Same meaning, same default (off),
        // and `included_off` is echoed on the reading below exactly as
        // the diversity report echoes it.
        let include_off = body
            .get("include_off")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let servers = current_servers(ctx.cfg_path);
        // ENABLED rows only - see `enabled_server_count`, which is also
        // why the list itself is NOT filtered. `.max(1)` keeps the share
        // arithmetic below from dividing by zero on an all-off config,
        // which is only reachable at all on an opt-in run (the refusal
        // further down turns the ordinary one away).
        let n_servers = enabled_server_count(&servers).max(1);
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
        let srv = match sc {
            Err(e) => return Some(json!({"status": false, "error": e})),
            Ok(sc) => sc,
        };
        // The anchor the FLEET BUILD reads, spelled exactly as
        // `tasks/runner.rs` stamps it on the hub. Any other
        // reading here - the raw setting, whyslow's LAN-capped one -
        // would report an implied fleet against a line the arithmetic
        // does not use, which is the one way this panel could mislead
        // while every number in it was individually true.
        let (anchor_bps, anchor_src) = d.link_peak.effective(d.line_speed.load(Ordering::Relaxed));
        // The fleet the NEXT job will actually open, which since TODO
        // 275 item 1 part 2 means the curve AND the carry a previous job
        // banked (`linecarry.rs`, stamped on the hub by
        // `tasks/runner.rs` at job start). Passing 0 here would
        // report a smaller fleet than the job opens - the defect
        // `conntune::line_cap_fleet` closes by having no carry-free
        // spelling at all - and this panel's whole business is putting
        // that number beside the one it measured.
        //
        // READ, never written: this probe does NOT bank its own reading
        // into `d.line_carry`. That slot is a whole POOL's carry as a
        // job actually ran it, and this is one server measured on its
        // own for a few seconds; seeding one from the other is a
        // judgement about what every install SPENDS, which TODO 275
        // item 7 took on 2 Sep 2026 for the FLEET's own measured carry
        // and not for this probe's: what the second ceiling reads is
        // the anchor's provenance plus the account grant, and a
        // hand-triggered per-server reading is neither.
        //
        // Hoisted to a local because it is published as well as used:
        // `live_carry_bps` on the reading below is the same number, and
        // reading the slot twice in one handler would let the sentence
        // the panel prints and the fleet it prints it beside come from
        // two different observations of a moving value.
        let live_carry_bps = d.line_carry.carry_bps();
        let fleet_now = crate::conntune::line_cap_fleet(ctx.cfg_path, anchor_bps, live_carry_bps);
        // What a real download would open on THIS server right now:
        // its share of the fleet in force, never past what the account
        // and the global dial allow.
        let ceiling = crate::conntune::effective_limit(
            d.connections.load(Ordering::Relaxed),
            srv.connections,
        )
        .min(CARRY_MAX_CONNS);
        let share = match nzbkit::pool::linecap::fleet_cap(fleet_now) {
            // The rule is off, so there is no share to speak of and the
            // server's own number is what a job would dial.
            None => ceiling,
            Some(f) => nzbkit::pool::linecap::server_share(f, n_servers),
        };
        let (rung_now, rung_more) = carry_rungs_for(share, ceiling);
        // Both refusals stand BEFORE the permit is taken: a handler
        // that claims the shared permit and then turns the caller away
        // has to remember to drop it on every path, which is the leak
        // `tests/daemon_carry` exists to catch. Nothing here has
        // dialled anything yet either.
        //
        // `srv.enabled` is the SAVED state of the row - `normalized_server`
        // deliberately does not merge an `enabled` field, so the editor's
        // unsaved tick cannot talk this door into dialling an account the
        // config says to leave alone.
        if let Some(no) = carry_refusal(
            &srv.host,
            d.index_jobs_active.load(Ordering::Acquire) > 0,
            !srv.enabled,
            include_off,
        ) {
            return Some(no);
        }
        // One throughput probe at a time, and it shares the ladder's
        // permit rather than taking one of its own: two of them are
        // each other's contention, so a second run does not merely race
        // to report - it makes BOTH readings wrong, on probes whose
        // entire job is dividing a rate by a socket count.
        let Some(_permit) = crate::daemon::LadderPermit::try_take(d) else {
            return Some(json!({"status": false,
                "error": "a connection test is already running - wait for it \
                          to finish, then try again"}));
        };
        tokio::runtime::Handle::current().block_on(async {
            // Real articles from this install's own downloads,
            // STAT-verified on THIS provider (`serve::probeids`): the
            // synthetic probe group under-measured a provider 17x, in
            // the false-low direction no guard can catch - and a carry
            // probe that reads low is one that over-states the fleet
            // its own line wants. No usable supply is said plainly and
            // is never a silent fallback.
            let ids = match tokio::time::timeout(
                std::time::Duration::from_secs(60),
                crate::probeids::real_ladder_ids(d, &srv),
            )
            .await
            {
                Err(_) | Ok(None) => {
                    return json!({"status": false, "no_real_articles": true,
                    "error": format!(
                        "{}: no articles from your own recent downloads could be \
                         verified on this server, so there is nothing \
                         representative to measure with. Complete a download \
                         first, then test again",
                        srv.host
                    )});
                }
                Ok(Some(ids)) => ids,
            };
            // The same bounded `block_on` plus hard-timeout shape the
            // rest of this module uses: a black-holed host must not
            // wedge the API thread. Generous against two 6 s rungs on
            // purpose - a provider slow enough to overrun this is one
            // whose carry the user most wants to know - and
            // `timed_fetch_multi` stops its own pool politely at each
            // rung's deadline, so overrunning here cannot leak workers
            // that keep pulling articles against the account.
            //
            // The ledger lives out here rather than in the future
            // below, because the future is the thing this timeout
            // CANCELS: see [`ProbeBill`].
            let bill = ProbeBill::default();
            let measured = tokio::time::timeout(std::time::Duration::from_secs(90), async {
                let mut ids = ids;
                let mut rungs: Vec<CarryRung> = Vec::new();
                let mut interrupted = false;
                for n in [rung_now, rung_more] {
                    if rungs.iter().any(|r: &CarryRung| r.connections == n) {
                        // The account's ceiling is already reached,
                        // so there is no second rung to run and no
                        // scaling verdict to draw.
                        continue;
                    }
                    // The entry refusal is check-once and nothing on
                    // the download side waits on the permit (a download
                    // must never block on a diagnostic), so a job that
                    // started while the STAT gate held the wire - or
                    // during the first rung's 6 s - would share the
                    // line with this rung's fresh fleet: the exact
                    // interference the refusal names, and a reading
                    // that measures the job. Re-ask before each fleet
                    // goes on the wire; a break rather than a return so
                    // the rung that DID run is still billed below.
                    if d.index_jobs_active.load(Ordering::Acquire) > 0 {
                        interrupted = true;
                        break;
                    }
                    let r = carry_rung(&srv, ids.clone(), n).await;
                    // Billed here rather than from `rungs` below,
                    // because `rungs` is dropped with this future when
                    // the measure timeout fires and the bytes it holds
                    // are then unrecoverable. Before the rotation and
                    // the push on purpose: nothing between this rung
                    // returning and the next one is allowed to be the
                    // reason a rung that ran went unbilled.
                    bill.rung(r.bytes);
                    // Skip past everything that rung read, so the
                    // next one is COLD - see `carry_rung`. Derived
                    // from the bytes it actually moved rather than
                    // from a guess: dividing by the SMALLEST article
                    // the supply admits over-states the count, so
                    // the skip is never short.
                    let read = (r.bytes / MIN_PROBE_ARTICLE_BYTES) as usize;
                    let rot = read.min(ids.len().saturating_sub(1));
                    ids.rotate_left(rot);
                    rungs.push(r);
                }
                (rungs, interrupted)
            })
            .await;
            let (rungs, interrupted) = match measured {
                Err(_) => {
                    // Billed on the way out, from the same counter the
                    // answer below bills from: a rung that ran moved
                    // real bytes whatever the probe then concluded,
                    // INCLUDING when the probe never concluded. This
                    // arm is reachable with a completed rung - rung one
                    // returns in its 6 s and rung two's pool wedges on
                    // a black-holed host, which is the case this 90 s
                    // guard exists for - and its bytes went out on the
                    // wire against the account either way.
                    d.add_usage(&[(srv.host.clone(), bill.owed())]);
                    return json!({"status": false,
                        "error": format!("{}: the carry probe timed out", srv.host)});
                }
                Ok(r) => r,
            };
            // Probe traffic is real provider traffic - bill it, the
            // same as the ladder next door. It is what keeps a prepaid
            // block's remaining-bytes figure true, and this is the one
            // side effect the probe deliberately does have. Billed
            // BEFORE the interrupted refusal below: a rung that ran
            // moved real bytes whatever the probe then concluded.
            //
            // From the counter, not from `rungs`: one spelling for what
            // this handler owes, so the answer path and the refusal
            // above cannot come to disagree about it.
            d.add_usage(&[(srv.host.clone(), bill.owed())]);
            if interrupted {
                return json!({"status": false,
                    "error": "a download started while the test was running, and \
                              the reading would have measured it - try again \
                              when the queue is idle"});
            }
            let base = rungs.first();
            let carry_bps = base.and_then(CarryRung::per_socket).unwrap_or(0);
            // A provider that granted no sockets is a legitimate
            // outcome to REPORT - the 481 case, an account already full
            // from another machine - and not a failed probe. The pool
            // already tells a capacity refusal from a rejected
            // credential; what the user needs here is the number of
            // sockets they really have, which is the same evidence.
            let granted_none = base.is_some_and(|r| r.granted == 0);
            let scaling = carry_scaling(
                rungs.first().and_then(CarryRung::per_socket),
                rungs.get(1).and_then(CarryRung::per_socket),
            );
            json!({
                "status": true,
                "host": srv.host,
                "carry_bps": carry_bps,
                "rungs": rungs.iter().map(CarryRung::to_json).collect::<Vec<_>>(),
                "granted_none": granted_none,
                "scaling": scaling,
                "bytes": rungs.iter().map(|r| r.bytes).sum::<u64>(),
                // The line this carry is being divided into, and where
                // that reading came from ("measured" from a completed
                // download, "line" from the setting, "" from nothing at
                // all). A reader cannot judge the implied fleet without
                // it: over a typed line it is arithmetic on a claim.
                "anchor_bps": anchor_bps,
                "anchor_src": anchor_src,
                // REPORT ONLY. `implied_fleet` is unclamped on purpose -
                // seeing it stand above `fleet_max` is the point - and
                // `fleet_now` is what is actually in force, which is the
                // only one of the three that is spending anything.
                "fleet_now": fleet_now,
                "fleet_max": nzbkit::pool::linecap::LINE_CAP_MAX_FLEET,
                "implied_fleet":
                    nzbkit::pool::linecap::fleet_implied_by_carry(anchor_bps, carry_bps),
                // TODO 312 item 6(e): the OTHER reading of this same
                // quantity, so the panel can put the two side by side
                // instead of leaving the user to hold one of them in
                // their head across two screens. `carry_bps` above is
                // one server measured deliberately for a few seconds;
                // this is what a socket carried during the last real
                // download, `now_bps / dialling` maxed over that run
                // (`pool::linecap`'s `line_cap_tick`, banked by
                // `linecarry.rs`). Same arithmetic, same divisor,
                // so the two are directly comparable - and this is the
                // PERSISTED form of whyslow's own `fleet_carry_bps`,
                // which is that division at one tick.
                //
                // Persisted is what makes the pairing possible at all:
                // the probe REFUSES while a download runs, so whyslow's
                // live figure is never on screen at the moment this
                // reading exists, and the banked one is the only
                // spelling of "what your downloads actually get" that
                // outlives the job. 0 = an install that has never
                // finished a download, which the panel says nothing
                // about rather than printing a zero.
                //
                // It is a LINE-wide number over every dialling socket
                // and `carry_bps` is one host's, so the panel must name
                // the host it tested; on a multi-server install the two
                // are not the same quantity. No `live_implied` beside
                // it: that is whyslow's own sentence, it is what the
                // download panel already prints, and a second implied
                // fleet here would read as a rival recommendation.
                "live_carry_bps": live_carry_bps,
                // The number this carry was divided between, and what
                // it is a count OF. It is the SAVED ENABLED set, which
                // is the set the next download opens - not the editor's
                // raw list, and not the set minus whatever hosts a
                // running job has excluded, which changes between jobs
                // and would make the panel's arithmetic unreproducible.
                // The panel owes the reader that sentence; `servers_basis`
                // is what lets it say so rather than printing a bare
                // count the reader has to guess the provenance of.
                "servers": n_servers,
                "servers_basis": "saved_enabled",
                // Whether this reading was taken against a row that is
                // switched off, echoed the way `m_diversity` echoes it:
                // a carry measured on an account no job dials has to be
                // labelled, or it reads as a provider in use.
                "included_off": include_off,
                "metered": !srv.may_spend_on_measurement(),
            })
        })
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
                // The permit below excludes another LADDER and says
                // nothing about what is likeliest to be using this
                // account: the download. 100 sockets climbing for four
                // minutes, then two more re-measuring - refused BEFORE
                // the permit, so a refused caller has none to leak.
                if let Some(no) = downloading_refusal(downloading_now(d)) {
                    return Some(no);
                }
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
                let Some(_permit) = crate::daemon::LadderPermit::try_take(d) else {
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
                        crate::probeids::real_ladder_ids(d, &srv),
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
                    // The entry refusal is check-once, so a job picked
                    // up while the STAT gate held the wire - 60 s above -
                    // would share the line with every rung below. Still
                    // a plain refusal: nothing is measured yet. Also the
                    // `value2=N` branch's ONLY re-ask, it having no
                    // per-rung callback to carry one.
                    if let Some(no) = downloading_refusal(downloading_now(d)) {
                        return no;
                    }
                    // Set by the climb's callback, read once it returns:
                    // `conn_ladder` answers every stop with the rungs it
                    // had, so a cut-short climb reads like a cancelled
                    // one from the steps alone.
                    let hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let hit_cb = hit.clone();
                    // Same ledger the carry probe next door keeps, for
                    // the same reason: `conn_ladder`'s own `out` Vec is
                    // inside the future the timeout below cancels, so
                    // the timeout arm could only ever have billed
                    // nothing. Kept out here, it survives. See
                    // [`ProbeBill`]. Only the CLIMB feeds it - the
                    // `value2=N` branch is a single fetch with no
                    // progress callback, so a timeout there means no
                    // rung settled and there is nothing this daemon can
                    // honestly say was moved.
                    let bill = ProbeBill::default();
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
                                        // Every settled rung, handed to
                                        // this callback as a running
                                        // total before the next one
                                        // goes on the wire - so this is
                                        // the one place a cancelled
                                        // climb's bytes can be recorded
                                        // from.
                                        bill.total(steps.iter().map(|s| s.bytes).sum());
                                        *dd.ladder_live.lock_ok() =
                                            Some(crate::daemon::LadderLive {
                                                host: host.clone(),
                                                phase: phase.into(),
                                                at,
                                                steps: steps.to_vec(),
                                                started,
                                                done: false,
                                            });
                                        // Re-ask before each rung's
                                        // fleet goes on the wire, as
                                        // the carry probe does: a job
                                        // starting mid-climb both slows
                                        // under this ladder and reads
                                        // the rest of it flat.
                                        if downloading_now(&dd) {
                                            hit_cb.store(true, Ordering::Release);
                                            return false;
                                        }
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
                            // Billed before the refusal, as both arms
                            // below do: the rungs that settled before
                            // the climb wedged moved real bytes against
                            // the account, and a timeout is the one
                            // ending that used to drop them silently.
                            d.add_usage(&[(srv.host.clone(), bill.owed())]);
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
                            // Bail BEFORE the re-measure - two minutes
                            // of the user's account corroborating a
                            // reading known to be wrong - and before
                            // `record`, the half that caps the provider.
                            // Billed first: the rungs that ran moved
                            // real bytes.
                            if hit.load(Ordering::Acquire) {
                                let n = steps.iter().map(|s| s.bytes).sum();
                                d.add_usage(&[(srv.host.clone(), n)]);
                                return json!({"status": false, "downloading": true,
                                    "error": "a download started while the test was \
                                              running, so the rungs after it measured \
                                              the download rather than the server - try \
                                              again when the queue is idle"});
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
                            // The re-measure's OWN ledger, kept out
                            // here for the same reason the climb's is
                            // (see [`ProbeBill`]): the 120 s timeout
                            // below cancels the future, taking its
                            // `out` vec and the bytes of every rung
                            // that had already settled with it. Read
                            // only on the arms where `merge_samples`
                            // did NOT run, because a merged rung
                            // already carries both samples' bytes and
                            // billing both would charge the re-measure
                            // twice.
                            let rbill = ProbeBill::default();
                            let (steps, unmerged) = match contested {
                                None => (steps, 0),
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
                                            |st| rbill.rung(st.bytes),
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(Ok(extra)) => {
                                            (crate::conntune::merge_samples(&steps, &extra), 0)
                                        }
                                        // A failed or TIMED-OUT
                                        // re-measure leaves the ladder
                                        // as it was: still jagged, so
                                        // still suspect - but the rungs
                                        // it did complete went out on
                                        // the wire against the account
                                        // and are owed from the counter
                                        // above.
                                        _ => (steps, rbill.owed()),
                                    }
                                }
                            };
                            // Probe traffic is real provider
                            // traffic - bill it. merge_samples sums
                            // both samples' bytes into the rung, so
                            // `steps` covers a re-measure that merged;
                            // `unmerged` is what a re-measure that
                            // never came back still owes.
                            d.add_usage(&[(
                                srv.host.clone(),
                                steps.iter().map(|s| s.bytes).sum::<u64>() + unmerged,
                            )]);
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
                                        crate::tunestate::mirror_shaped(d, ctx.cfg_path, &srv.host);
                                        // Manual runs re-judge line-speed
                                        // coverage too - same as the auto probe.
                                        if let Ok(c) = nzbkit::config::Config::load(ctx.cfg_path) {
                                            crate::tunestate::update_tune_hint(
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

pub(crate) fn dispatch(
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
        // TODO 312 item 2: what one socket to this server actually
        // CARRIES, and what fleet that carry implies for this line.
        // Test connection's throughput sibling, and a separate mode
        // rather than a flag on it for two reasons: `testAllServers`
        // fires `server_test` at every server at once, and this one
        // spends real bandwidth and real provider connections, so it
        // must only ever run when a person pressed this button.
        //
        // POST like `server_test`, and for the same reason: the body
        // carries the editor's current server, password included, so
        // the probe works before a save.
        "server_carry" => return m_server_carry(d, req, params, ctx, api_body),
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
#[path = "servers_tests.rs"]
mod tests;
