use super::super::*;
use super::ApiCtx;

fn m_backup_export(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let read_json = |p: &std::path::Path| {
            std::fs::read(p)
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .unwrap_or_else(|| json!({}))
        };
        let apikey_file = std::fs::read_to_string(ctx.cfg_path.with_file_name("apikey"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        info!(target: "config", "settings backup exported to an authenticated caller");
        json!({
            "status": true,
            "backup": {
                "nzbfast_backup": 1,
                "version": env!("CARGO_PKG_VERSION"),
                "config": read_json(ctx.cfg_path),
                "settings": read_json(&ctx.cfg_path.with_file_name("settings.json")),
                "apikey_file": apikey_file,
            }
        })
    })
}

fn m_backup_import(
    _d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        if req.method() != &tiny_http::Method::Post {
            json!({"status": false, "error": "POST required"})
        } else {
            let raw = api_body.take().unwrap_or_default();
            let parsed = serde_json::from_slice::<Value>(&raw).ok();
            let bundle = parsed.as_ref().and_then(|v| {
                if v.get("nzbfast_backup").is_some() {
                    Some(v)
                } else {
                    v.get("backup")
                        .filter(|b| b.get("nzbfast_backup").is_some())
                }
            });
            match bundle {
                None => json!({
                    "status": false,
                    "error": "not an nzbfast backup file",
                }),
                Some(b) => {
                    let mut failed: Vec<String> = Vec::new();
                    let mut write_store = |path: &std::path::Path, v: &Value| {
                        let text = serde_json::to_string_pretty(v).unwrap_or_default();
                        if crate::persist::write_atomic(path, text.as_bytes()).is_err() {
                            failed.push(path.display().to_string());
                        }
                    };
                    if let Some(cfg) = b.get("config").filter(|v| v.is_object()) {
                        write_store(ctx.cfg_path, cfg);
                    }
                    if let Some(s) = b.get("settings").filter(|v| v.is_object()) {
                        write_store(&ctx.cfg_path.with_file_name("settings.json"), s);
                    }
                    // An explicit null is a fact, not a gap: the export
                    // writes `apikey_file: null` when the source install
                    // is keyless, so restoring it onto a KEYED
                    // destination has to remove that key. Leaving the
                    // sibling file behind meant the old key came back at
                    // the next restart (startup reads the keyfile), which
                    // is not "this install now matches the backup".
                    // A backup with no `apikey_file` member at all is
                    // from before the field existed and says nothing -
                    // that one is left alone.
                    match b.get("apikey_file") {
                        Some(Value::String(k)) if !k.trim().is_empty() => {
                            if crate::persist::write_atomic(
                                &ctx.cfg_path.with_file_name("apikey"),
                                k.trim().as_bytes(),
                            )
                            .is_err()
                            {
                                failed.push("apikey".into());
                            }
                        }
                        Some(_) => {
                            let keyfile = ctx.cfg_path.with_file_name("apikey");
                            if let Err(e) = std::fs::remove_file(&keyfile)
                                && e.kind() != std::io::ErrorKind::NotFound
                            {
                                failed.push("apikey".into());
                            }
                        }
                        None => {}
                    }
                    if failed.is_empty() {
                        info!(target: "config", "settings backup restored - restart to apply");
                        json!({"status": true, "restart_required": true})
                    } else {
                        json!({
                            "status": false,
                            "error": format!("could not write: {}", failed.join(", ")),
                        })
                    }
                }
            }
        }
    })
}

fn m_apikey_show(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let k = d.apikey.lock_ok().clone();
        info!(target: "config", "apikey revealed to an authenticated caller");
        json!({
            "status": true,
            // Null, not "", so the UI can tell "no key set on
            // this install" from "a key that is empty".
            "apikey": k,
            "nzbkey": d.nzbkey.lock_ok().clone(),
        })
    })
}

fn m_get_config(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // §129 2b: real values, not the static placeholders this used
        // to answer with. pp stays "" - repair+unpack are integral to
        // the one-pass download, so there is no per-category pp level
        // to report (decision 5's documented mapping).
        let cats: Vec<Value> = {
            let meta = d.cat_meta.lock_ok();
            d.cats
                .lock_ok()
                .iter()
                .map(|c| {
                    let m = meta.get(c).cloned().unwrap_or_default();
                    json!({
                        "name": c,
                        "dir": if !m.dir.is_empty() {
                            m.dir
                        } else if c == "*" {
                            String::new()
                        } else {
                            c.clone()
                        },
                        "priority": m.priority.unwrap_or(-100),
                        "pp": "",
                        "script": if m.script.is_empty() { "None".to_string() } else { m.script },
                    })
                })
                .collect()
        };
        // Usenet servers with SECRETS MASKED: the UI only ever
        // learns whether a password exists, never its value.
        let servers: Vec<Value> = nzbkit::config::Config::load(ctx.cfg_path)
            .map(|c| {
                c.servers
                    .iter()
                    .map(|s| {
                        // What the unset idle-release fields
                        // resolve to right now, so the UI can
                        // show the effective policy without
                        // duplicating the rule.
                        let rel = s.idle_release_policy();
                        json!({
                            "host": s.host,
                            "port": s.port,
                            "tls": s.tls,
                            "username": s.username.clone().unwrap_or_default(),
                            "has_password": s.password.is_some(),
                            "connections": s.connections,
                            // Echoed because the editor round-trips the
                            // whole form: unechoed, the box loaded
                            // unticked on a pinned server and the next
                            // Save silently dropped the pin. Found while
                            // adding block_account beside it, which
                            // would have inherited the same hole.
                            "pin_connections": s.pin_connections,
                            "level": s.level,
                            "group": s.group.clone().unwrap_or_default(),
                            "retention_days": s.retention_days,
                            "block_bytes": s.block_bytes.unwrap_or(0),
                            "block_account": s.block_account,
                            "block_used": d.block_spent(&s.host),
                            "enabled": s.enabled,
                            "warm_pool": s.warm_pool,
                            "idle_release_secs": s.idle_release_secs,
                            "idle_keep": s.idle_keep,
                            "max_source_ips": s.max_source_ips,
                            // M32 route controls. The SOCKS spec is one
                            // stored string that may end in a proxy
                            // password, so it is echoed in the three
                            // parts the editor shows, and the password is
                            // masked like every other secret here.
                            "bind_ip": s.bind_ip.clone().unwrap_or_default(),
                            "socks5": super::super::servers::socks5_addr(s.socks5.as_deref()),
                            "socks5_user": super::super::servers::socks5_creds(s.socks5.as_deref()).0,
                            "has_socks5_pass":
                                !super::super::servers::socks5_creds(s.socks5.as_deref()).1.is_empty(),
                            "idle_release_effective": {
                                "secs": rel.after.map(|d| d.as_secs()).unwrap_or(0),
                                "keep": rel.keep,
                                "tight_ips": s.source_ips_are_tight(),
                            },
                            // Lifetime article completion% from
                            // the reliability ledger (null until
                            // a job has finished on this host).
                            "completion_pct": d.reliability(&s.host).map(|(t, m)| {
                                100.0 * (t.saturating_sub(m)) as f64 / t as f64
                            }),
                            // Article tries behind completion_pct: the UI gates
                            // the "poor completion" verdict on sample size, and
                            // uses each server's share of tries to tell a primary
                            // (asked for ~everything) from a fill (only asked for
                            // the gaps others 430'd - low completion is by design).
                            "tried": d.reliability(&s.host).map(|(t, _)| t),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Restart-pending: for settings that only take effect on
        // restart, report the value SAVED to settings.json when it
        // differs from the value the daemon is running now. The UI
        // shows the live value in the field plus a "→ X after
        // restart" note, so a saved-but-not-yet-applied change is
        // never invisible. (Live settings can't diverge like this;
        // mem_limit already surfaces its saved value directly.)
        let staged = load_settings(&d.settings_path);
        let mut pending = serde_json::Map::new();
        let active_port = json!(d.port);
        if let Some(v) = staged.get("port")
            && v != &active_port
        {
            pending.insert("port".into(), v.clone());
        }
        // §129 2a: the TLS pair is bind-time too. A cleared value ("")
        // pending against a serving pair matters as much as a set one.
        for (k, active) in [
            ("tls_cert", crate::serve::settings::path_str(&d.tls_cert)),
            ("tls_key", crate::serve::settings::path_str(&d.tls_key)),
        ] {
            if let Some(v) = staged.get(k)
                && v != &json!(active)
            {
                pending.insert(k.into(), v.clone());
            }
        }
        #[cfg(feature = "indexer")]
        {
            let active_db = json!(d.index_db.to_string_lossy());
            if let Some(v) = staged.get("index_db")
                && v != &active_db
            {
                pending.insert("index_db".into(), v.clone());
            }
        }
        // The settings block itself: every row of the table
        // that exposes a value, plus the three the table
        // declares but leaves to us because they are built
        // from what we just computed above.
        let mut nzbfast = config_block(&ConfigCtx {
            d,
            cfg_path: ctx.cfg_path,
        });
        // First-run signal: the dashboard shows a welcome card
        // until a server exists.
        nzbfast.insert("servers_configured".into(), json!(!servers.is_empty()));
        // §129 4c: the SECOND first-run signal. A configured server is
        // not a working install - between the two comes a dashboard of
        // cards that can only read zero, and the question the user
        // actually has ("how do I start a download?") is answered
        // nowhere on it. See `jobs_ever` for why this cannot simply ask
        // whether the queue is empty.
        nzbfast.insert("jobs_ever".into(), json!(d.jobs_ever()));
        nzbfast.insert("servers".into(), json!(servers));
        nzbfast.insert("pending".into(), Value::Object(pending));
        json!({
            "config": {
                // The sorting/retention block is what Sonarr/Radarr
                // Test() probes: all sorting off (an EMPTY *_categories
                // list means "applies to every category", so the enable
                // flags must be 0) and history kept forever.
                "misc": {"complete_dir": d.out_dir().to_string_lossy(),
                         "enable_tv_sorting": 0, "tv_categories": [],
                         "enable_movie_sorting": 0, "movie_categories": [],
                         "enable_date_sorting": 0, "date_categories": [],
                         "pre_check": 0, "history_retention": "",
                         "history_retention_option": "all",
                         "history_retention_number": 0},
                "sorters": [],
                "categories": cats,
                "servers": [],
                // Everything the settings UI edits, in one
                // block. Values reflect the LIVE daemon state,
                // and every key in it comes from the settings
                // table - see `config_block`.
                "nzbfast": Value::Object(nzbfast),
            }
        })
    })
}

fn m_get_scripts(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // §129 2b follow-up: the honest list is everything the daemon
        // can run for a job - global AND per-category scripts (deduped
        // by basename, the name clients send back as `script=`).
        // "None" first: SAB's null choice, and what keeps a client's
        // dropdown rendering at all.
        let mut scripts = vec![json!("None")];
        for (name, _) in d.known_scripts() {
            scripts.push(json!(name));
        }
        json!({"scripts": scripts})
    })
}

fn m_config(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // A setting whose value is a JSON blob (watchlist,
        // feeds, notify targets, smart folders) outgrows the
        // 8 KB request line long before it outgrows anything
        // else, and the query-string form is then rejected
        // with a 414. Accept the same name/value pair in a
        // POST body; the GET form stays for the documented
        // SAB-compatible `mode=config` parity.
        let posted = if req.method() == &tiny_http::Method::Post {
            let raw = api_body.take().unwrap_or_default();
            serde_json::from_slice::<Value>(&raw).ok()
        } else {
            None
        };
        let from_body = |k: &str| {
            posted
                .as_ref()
                .and_then(|b| b.get(k))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        let name = from_body("name").or_else(|| params.get("name").cloned());
        let value = from_body("value").or_else(|| params.get("value").cloned());
        // The bootstrap hatch authorised exactly ONE setting, and
        // it decided that from the `name` in the QUERY string -
        // but the body wins two lines up. Without this check a
        // holder of the add-only NZB key could present
        // `?mode=config&name=apikey` to pass the gate and then
        // write `{"name":"script"}` in the body: an add-only
        // credential escalating to arbitrary config, and from
        // there to code execution, because `script` is run on the
        // job tail and `addfile` is itself add-only. Refuse with
        // the same phrase the gate uses, so nothing downstream
        // learns that the request got this far.
        if ctx.bootstrap_apikey && name.as_deref() != Some("apikey") {
            return Some(json!({
                "status": false,
                "error": "API Key Incorrect",
                "nzbfast": env!("CARGO_PKG_VERSION"),
            }));
        }
        match (name.as_deref(), value.as_deref()) {
            // The countdown banner's Cancel button. Answers whether
            // anything was actually pending, so a second click (or two
            // browser tabs racing) reports honestly rather than claiming
            // to have stopped a countdown that had already run.
            (Some("queue_finished_cancel"), _) => {
                let mut out = crate::serve::finish_action::cancel(d);
                if let Some(o) = out.as_object_mut() {
                    o.insert("status".into(), json!(true));
                }
                out
            }
            (Some("set_pause"), Some(v)) => {
                // SAB parity: config&name=set_pause&value=<minutes>.
                timed_pause(d, v.parse().unwrap_or(0), true);
                json!({"status": true})
            }
            // The two credentials get the same anti-drive-by gate as
            // `apikey_new`/`nzbkey_new`. Writing them THROUGH `config`
            // reaches the identical `set_apikey`/`nzbkey` code with none
            // of the protection, over a plain GET - so on a keyless
            // install (`NZBFAST_OPEN=1`, or one predating first-run
            // minting) an `<img src=".../api?mode=config&name=apikey
            // &value=…">` on any page the user happens to visit installs
            // an attacker-chosen key. That is precisely the outcome
            // `credential_mutation_allowed`'s own doc describes for the
            // mint routes: "the owner is locked out of their own daemon
            // by a key nobody has" - except here the attacker knows the
            // key, so `server_secret`, `script` and `backup_export`
            // follow. The gate is a no-op for legitimate callers (curl,
            // *arr, the dashboard's own POST); only a browser navigation
            // trips it.
            (Some(name @ ("apikey" | "nzbkey")), Some(v)) => match same_site_only(req) {
                Ok(()) => match apply_and_save(d, name, v) {
                    Ok((live, saved)) => {
                        info!(
                            target: "config",
                            "{name} → {}{}",
                            log_value(name, v),
                            if saved {
                                ""
                            } else {
                                " (NOT SAVED - reverts on restart)"
                            }
                        );
                        let _ = live;
                        json!({"status": true, "saved": saved})
                    }
                    Err(e) => json!({"status": false, "error": e}),
                },
                Err(e) => json!({"status": false, "error": e}),
            },
            (Some(name), Some(v)) => match apply_and_save(d, name, v) {
                Ok((live, saved)) => {
                    info!(
                        target: "config",
                        "{name} → {}{}{}",
                        log_value(name, v),
                        if live { "" } else { " (applies after restart)" },
                        if saved {
                            ""
                        } else {
                            " (NOT SAVED - reverts on restart)"
                        }
                    );
                    // The path, but only when the write FAILED: "it
                    // could not be written to disk" is not actionable
                    // without knowing which disk. On the success path
                    // it would just be the daemon volunteering its
                    // filesystem layout to every API caller.
                    //
                    // #18: the save is accepted, but if it carried a
                    // rules pattern that will not compile, say so NOW -
                    // by rule name, with the engine's compile error -
                    // rather than leaving it to the row annotation the
                    // user may never scroll back to. Null when there is
                    // nothing to say, so every other setting's answer is
                    // unchanged.
                    json!({"status": true, "live": live, "saved": saved,
                    "warning": rules_save_warning(name, v),
                    "path": if saved { Value::Null } else {
                        json!(d.settings_path.to_string_lossy())
                    }})
                }
                Err(e) => json!({"status": false, "error": e}),
            },
            _ => json!({"status": false, "error": "config needs name and value"}),
        }
    })
}

fn m_import_probe(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let mut cands: Vec<Value> = Vec::new();
        let mut paths: Vec<(String, PathBuf)> = Vec::new();
        if let Some(p) = params.get("value").filter(|p| !p.is_empty()) {
            let kind = if p.ends_with(".ini") {
                "sabnzbd"
            } else {
                "nzbget"
            };
            paths.push((kind.into(), PathBuf::from(p)));
        } else {
            let near: Vec<&std::path::Path> = ctx.cfg_path.parent().into_iter().collect();
            if let Some(p) = nzbkit::config::sabnzbd_ini_path(&near) {
                paths.push(("sabnzbd".into(), p));
            }
            for p in nzbget_conf_paths() {
                paths.push(("nzbget".into(), p));
            }
        }
        for (kind, path) in paths {
            let Ok(text) = read_import_config(&path) else {
                continue;
            };
            let servers = if kind == "sabnzbd" {
                nzbkit::config::parse_sabnzbd_ini(&text).unwrap_or_default()
            } else {
                nzbkit::config::parse_nzbget_conf(&text)
            };
            if servers.is_empty() {
                continue;
            }
            // #17: categories come over too, and the probe says so
            // before anything is written. SAB only - NZBGet has no
            // equivalent section.
            let cats = if kind == "sabnzbd" {
                nzbkit::config::parse_sabnzbd_categories(&text)
            } else {
                Default::default()
            };
            cands.push(json!({
                "kind": kind,
                "path": path.to_string_lossy(),
                "servers": servers.iter().map(|s| json!({
                    "host": s.host,
                    "username": s.username.clone().unwrap_or_default(),
                    "connections": s.connections,
                    "level": s.level,
                })).collect::<Vec<_>>(),
                "categories": cats.cats.iter().map(|c| json!({
                    "name": c.name,
                    "dir": c.dir.clone().unwrap_or_default(),
                })).collect::<Vec<_>>(),
                "categories_dropped": cats.dropped,
            }));
        }
        json!({"status": true, "candidates": cands})
    })
}

fn m_import_apply(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let path = params.get("value").cloned().unwrap_or_default();
        let kind = params.get("value2").cloned().unwrap_or_default();
        match read_import_config(std::path::Path::new(&path)) {
            Err(e) => json!({"status": false, "error": format!("{path}: {e}")}),
            Ok(text) => {
                let incoming = if kind == "sabnzbd" || path.ends_with(".ini") {
                    nzbkit::config::parse_sabnzbd_ini(&text).unwrap_or_default()
                } else {
                    nzbkit::config::parse_nzbget_conf(&text)
                };
                let _cfg = crate::setup::config_write_lock();
                let mut servers = current_servers(ctx.cfg_path);
                let have: std::collections::HashSet<(String, String)> = servers
                    .iter()
                    .map(|s| {
                        (
                            s.get("host")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_lowercase(),
                            s.get("username")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_lowercase(),
                        )
                    })
                    .collect();
                // Both competitors also name an archive-passwords
                // file (SAB `[misc] password_file`, NZBGet
                // `UnpackPassFile`). Importing their setup imports
                // that too - but only while OUR file is still
                // empty, so a list the user already curated here is
                // never abandoned by a re-import.
                // apply_and_save answers (live, saved), and `saved=false`
                // means the value works NOW and reverts at restart. The
                // import used to drop that bool at every site and report
                // plain success over an unwritable settings dir (Codex
                // sweep 5 Aug M7) - collect the non-durable adoptions
                // and say so in the response.
                let mut unsaved: Vec<&str> = Vec::new();
                let pw_adopted = {
                    let key_val = if kind == "sabnzbd" || path.ends_with(".ini") {
                        crate::import_sab::sab_ini_value(&text, "password_file")
                    } else {
                        crate::import_sab::nzbget_conf_value(&text, "UnpackPassFile")
                    };
                    key_val
                        .filter(|p| std::path::Path::new(p).is_file())
                        .filter(|_| d.read_unpack_passwords().is_empty())
                        .and_then(|p| match apply_and_save(d, "password_file", &p) {
                            Ok((_, saved)) => {
                                info!(target: "import", "adopted archive passwords file {p}");
                                // Still adopted - the live value is real
                                // and losing the path would be worse -
                                // but the revert-at-restart is reported.
                                if !saved {
                                    unsaved.push("password_file");
                                }
                                Some(p)
                            }
                            Err(e) => {
                                warn!(target: "import", "could not adopt passwords file {p}: {e}");
                                None
                            }
                        })
                };
                // #17. Categories are not cosmetic on this side:
                // `register_cat` exists because Sonarr and Radarr
                // validate their configured category against our list
                // and REFUSE TO CONNECT when it is missing, and it only
                // runs when a job carrying that category arrives. That
                // is the wrong order for a migration - without this the
                // *arrs fail their category test from the moment the
                // servers land until someone retypes every category by
                // hand or pushes a job through.
                //
                // Merged, never replaced, matching the contract this
                // endpoint already states for servers. `merge_cat_list`
                // is the same helper `register_cat` goes through.
                let cat_report = if kind == "sabnzbd" || path.ends_with(".ini") {
                    let found = nzbkit::config::parse_sabnzbd_categories(&text);
                    let names: Vec<&str> = found.cats.iter().map(|c| c.name.as_str()).collect();
                    let mut cats_added = 0;
                    if !names.is_empty() {
                        let before = d.cat_list();
                        let merged = crate::serve::merge_cat_list(&before, &names.join(", "));
                        if merged != before {
                            match apply_and_save(d, "categories", &merged) {
                                Err(e) => {
                                    warn!(target: "import", "could not merge categories: {e}");
                                }
                                Ok((_, saved)) => {
                                    if !saved {
                                        unsaved.push("categories");
                                    }
                                    cats_added =
                                        merged.split(',').count() - before.split(',').count();
                                }
                            }
                        }
                    }
                    // Only the categories whose folder differs from
                    // what we would do anyway, and only on top of any
                    // override the user already has.
                    //
                    // Applied ONE AT A TIME, and that is the point. The
                    // paths come from the machine SAB ran on, so on a
                    // migration they routinely do not exist here - a
                    // Docker or Synology move is exactly that - and the
                    // settings arm creates each destination, so one
                    // unreachable path used to abandon every override
                    // including the ones that would have worked. Now
                    // each is tried against the accumulated list, the
                    // survivors stick, and the rest are REPORTED with
                    // the reason rather than left to a log line.
                    let mut dirs_added = 0;
                    let mut dirs_failed: Vec<Value> = Vec::new();
                    let before = crate::serve::fmt_cat_dests(&d.move_completed_cats.read_ok());
                    let mut keep: Vec<String> = before
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect();
                    for c in &found.cats {
                        let Some(dir) = c.dir.as_ref() else { continue };
                        // Never overwrite an override the user already
                        // set for this category.
                        if keep.iter().any(|k| k.starts_with(&format!("{}=", c.name))) {
                            continue;
                        }
                        keep.push(format!("{}={dir}", c.name));
                        match apply_and_save(d, "move_completed_cats", &keep.join(", ")) {
                            Ok((_, saved)) => {
                                dirs_added += 1;
                                // The override IS live, so it stays in
                                // `keep` - popping it would desync the
                                // next apply from the daemon's state.
                                if !saved && !unsaved.contains(&"folders") {
                                    unsaved.push("folders");
                                }
                            }
                            Err(e) => {
                                keep.pop();
                                dirs_failed.push(json!({"name": c.name, "error": e}));
                            }
                        }
                    }
                    info!(
                        target: "import",
                        "{cats_added} categor(ies) and {dirs_added} folder(s) from {path}"
                    );
                    json!({"added": cats_added, "folders": dirs_added,
                               "folders_failed": dirs_failed,
                               "dropped": found.dropped})
                } else {
                    json!({"added": 0, "folders": 0, "folders_failed": Vec::<Value>::new(),
                               "dropped": Vec::<String>::new()})
                };
                let (mut added, mut skipped) = (0, 0);
                for s in incoming {
                    let key = (
                        s.host.to_lowercase(),
                        s.username.clone().unwrap_or_default().to_lowercase(),
                    );
                    if have.contains(&key) {
                        skipped += 1;
                        continue;
                    }
                    if let Ok(v) = serde_json::to_value(&s) {
                        servers.push(v);
                        added += 1;
                    }
                }
                // "It worked, but it is not durable": the live daemon
                // has everything, and the response says exactly what
                // reverts if the settings file stays unwritable.
                let warning = (!unsaved.is_empty()).then(|| {
                    format!(
                        "imported {} could not be written to {} - they work now \
                         but revert at the next restart",
                        unsaved.join(", "),
                        d.settings_path.display()
                    )
                });
                if added == 0 {
                    json!({"status": true, "added": 0, "skipped": skipped,
                               "password_file": pw_adopted,
                               "categories": cat_report,
                               "warning": warning})
                } else {
                    match crate::setup::write_servers(ctx.cfg_path, &servers) {
                        Ok(()) => {
                            info!(
                                target: "import",
                                "{added} server(s) from {path} ({skipped} already present)"
                            );
                            json!({"status": true, "added": added, "skipped": skipped,
                                       "password_file": pw_adopted,
                                       "categories": cat_report,
                                       "warning": warning})
                        }
                        Err(e) => json!({"status": false, "error": e.to_string()}),
                    }
                }
            }
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
        // The whole install in one downloadable file: everything a
        // moved or lost config directory takes with it (settings.json,
        // the config file with its servers, both keys). get_config
        // masks credentials by design; this deliberately does NOT -
        // its purpose is rebuilding the install, so it carries the
        // provider passwords exactly as stored (obfuscated, not
        // encrypted) and the API key. The UI labels the file
        // accordingly.
        //
        // AUTHORISATION: full key only, same reasoning as apikey_show
        // below - this must never join add_only, and must never accept
        // the bootstrap path.
        "backup_export" => return m_backup_export(d, req, params, ctx, api_body),
        // The other half: write a backup_export bundle back over this
        // install's stores. Accepts the export exactly as downloaded
        // (the whole response) or just its inner "backup" object.
        //
        // Files only, no live apply: the point of a restore is the
        // NEXT start, and pretending to apply a whole install's
        // settings to a running daemon piecemeal is how the files and
        // the live state end up disagreeing. The response says a
        // restart is required, and the dashboard offers it - anything
        // the running daemon saves in between would overwrite the
        // restored files, so restarting promptly is the whole advice.
        // Full-key gated (never add_only): this writes the
        // post-processing script path among everything else.
        "backup_import" => return m_backup_import(d, req, params, ctx, api_body),
        // Show the caller the key they already have, so setting up
        // Sonarr later does not mean digging through %LOCALAPPDATA%
        // or the browser's URL bar. get_config deliberately masks
        // every credential, and that masking must stay: this is a
        // separate, deliberate act with its own name in the log.
        //
        // AUTHORISATION: nothing extra is needed here, and that is
        // the point worth stating. `mode` is not in the `add_only`
        // list, so reaching this line already required `full` -
        // i.e. the API key ITSELF. The add-only NZB key cannot get
        // here, which matters: it exists to let a script submit
        // NZBs without gaining control, and handing it the API key
        // would silently promote it to exactly that. Do not add
        // "apikey_show" to add_only, and do not accept the
        // bootstrap path here (it proves possession of the NZB key,
        // not the API key).
        "apikey_show" => return m_apikey_show(d, req, params, ctx, api_body),
        // Mint a replacement. Routed through the same apply_setting
        // arm as a hand-typed key so persistence, replay and the
        // masked logging are identical - a second write path for a
        // credential is how the two drift.
        "apikey_new" => match credential_mutation_allowed(req) {
            Err(why) => json!({"status": false, "error": why}),
            Ok(()) => match random_apikey() {
                // Live state, key file and settings.json in one ordered
                // transaction (see `apply_and_save`) - persisting
                // separately let two rotations leave the three
                // disagreeing, and the loser's key came back on restart.
                // Still `status: true` with the key when the write
                // failed: the daemon IS on the new key now, so a page
                // that refused to adopt it would lock itself out.
                // `saved: false` is the durability signal.
                Some(k) => match apply_and_save(d, "apikey", &k) {
                    Ok((_, saved)) => {
                        info!(target: "config", "apikey regenerated");
                        json!({ "status": true, "apikey": k, "saved": saved })
                    }
                    Err(e) => json!({ "status": false, "error": e }),
                },
                None => json!({
                    "status": false,
                    "error": "could not read OS entropy for a new key",
                }),
            },
        },
        // Mint (or rotate) the add-only NZB key. Same shape and same
        // full-key gate as apikey_new: the NZB key must not be able to
        // rotate itself, or a leaked one could lock the owner's push
        // tools out. Revealing it rides apikey_show, which already
        // returns both keys.
        "nzbkey_new" => match credential_mutation_allowed(req) {
            Err(why) => json!({"status": false, "error": why}),
            Ok(()) => match random_apikey() {
                Some(k) => match apply_and_save(d, "nzbkey", &k) {
                    Ok((_, saved)) => {
                        info!(target: "config", "nzbkey regenerated");
                        json!({ "status": true, "nzbkey": k, "saved": saved })
                    }
                    Err(e) => json!({ "status": false, "error": e }),
                },
                None => json!({
                    "status": false,
                    "error": "could not read OS entropy for a new key",
                }),
            },
        },
        "get_config" => return m_get_config(d, req, params, ctx, api_body),
        "get_cats" => {
            json!({"categories": d.cats.lock_ok().iter().cloned().collect::<Vec<_>>()})
        }
        // The post-processing script list a remote app fills its
        // per-job dropdown from. We run one global script, so the
        // honest answer is None plus that script if it is set -
        // an empty list makes a client show no dropdown at all.
        "get_scripts" => return m_get_scripts(d, req, params, ctx, api_body),
        // Settings UI + SAB-compatible live config. Sizes are
        // absolute only ("4M", "500K", bare bytes/sec; 0 =
        // unlimited) - no SAB-style percentage values. Every
        // successful set persists to settings.json so it also
        // applies on the next launch.
        "config" => return m_config(d, req, params, ctx, api_body),
        // Server editor (settings UI). POST bodies so credentials
        // never ride in a query string. Writes go through the
        // setup-wizard helpers → same config.local.json shape;
        // downloads load the config per job, so changes apply
        // from the next download without a restart.
        // M19: import servers from other downloaders' configs.
        // Probe well-known SABnzbd + NZBGet locations (or an
        // explicit value=<path>) and report what's importable.
        "import_probe" => return m_import_probe(d, req, params, ctx, api_body),
        // Merge one probed config's servers into ours (dupes by
        // host+username skipped; nothing existing is touched).
        "import_apply" => return m_import_apply(d, req, params, ctx, api_body),
        _ => return None,
    })
}

/// May this request ROTATE a credential?
///
/// Minting a key is the one mutation that can lock the owner OUT, which
/// makes it reachable-by-accident in a way nothing else here is. On a
/// deliberately keyless install (`NZBFAST_OPEN=1`, or a legacy one that
/// predates first-run key minting) the gateway's `(None, None) => true`
/// arm authorises everything, so a hostile page the user happens to
/// visit could navigate to `/api?mode=nzbkey_new` on their LAN address:
/// the browser sends the request, the daemon mints a key, and the
/// same-origin policy stops the page ever reading it. The install is now
/// `(None, Some(unknown))`, which is exactly the state that turns full
/// access off - the owner is locked out of their own daemon by a key
/// nobody has.
///
/// Two gates, because neither is sufficient alone:
///
/// - **POST.** Kills the drive-by NAVIGATION - an `<img>`, an iframe, a
///   redirect, a typed link. A cross-site FORM can still POST, hence:
/// - **Same-site.** `Sec-Fetch-Site` (every browser since 2023 sends it
///   on every request) must say the request did not come from another
///   site, and an `Origin`, when present, must match the `Host` we were
///   asked on. Both are checked only WHEN PRESENT: curl, the *arr
///   clients and every script send neither, and those callers have to
///   keep working - the point is to stop a BROWSER being used as a
///   confused deputy, not to invent an authentication scheme.
fn credential_mutation_allowed(req: &tiny_http::Request) -> Result<(), String> {
    if req.method() != &tiny_http::Method::Post {
        return Err("POST required to create a key".into());
    }
    same_site_only(req)
}

/// The same-site half of [`credential_mutation_allowed`], on its own.
///
/// `mode=config&name=apikey|nzbkey` writes the same two credentials as
/// the mint routes, through the same `set_apikey`/`nzbkey` code, and had
/// none of this - so on a keyless install an `<img src=".../api?mode=
/// config&name=apikey&value=…">` on any page the user visited installed
/// an attacker-chosen key and locked the owner out, with the attacker
/// holding the only credential.
///
/// It gets the same-site check but NOT the POST requirement, because
/// unlike the mint routes this one has non-browser callers that have
/// always used GET (curl, scripts, the first-run flows the
/// `firstrun_key` suite pins). Dropping the POST half costs nothing
/// here: the attack is a browser being used as a confused deputy, and
/// every browser since 2023 labels such a request `Sec-Fetch-Site:
/// cross-site` whether it came from an `<img>`, an iframe, a redirect or
/// a cross-site form, GET or POST. A caller that sends no
/// `Sec-Fetch-*`/`Origin` at all is not a browser and keeps working,
/// exactly as the mint gate already allows.
fn same_site_only(req: &tiny_http::Request) -> Result<(), String> {
    let hv = |name: &'static str| {
        req.headers()
            .iter()
            .find(|h| h.field.equiv(name))
            .map(|h| h.value.as_str().trim().to_string())
            .filter(|v| !v.is_empty())
    };
    // "none" is a user-typed URL or a bookmark; "same-origin" is our own
    // dashboard. "cross-site" and "same-site" are both somebody else's
    // page - a sibling subdomain is not this daemon.
    if let Some(site) = hv("Sec-Fetch-Site")
        && !matches!(site.to_ascii_lowercase().as_str(), "same-origin" | "none")
    {
        return Err("a key can only be created from nzbfast's own pages".into());
    }
    // Compare HOSTS, not whole URLs: the dashboard may be reached over
    // http or https through a reverse proxy, and the scheme the browser
    // reports is not the scheme we were spoken to on.
    if let Some(origin) = hv("Origin") {
        let host_of = |s: &str| {
            s.rsplit_once("//")
                .map_or(s, |(_, rest)| rest)
                .split('/')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase()
        };
        let asked = hv("Host").unwrap_or_default().to_ascii_lowercase();
        if host_of(&origin) != asked {
            return Err("a key can only be created from nzbfast's own pages".into());
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::serve::testutil::test_daemon;
    use std::os::unix::fs::PermissionsExt;

    /// M7 (Codex sweep 5 Aug): `apply_and_save` answers (live, saved),
    /// and the SAB import dropped `saved` at every site - an unwritable
    /// settings dir imported "successfully" and then silently reverted
    /// at restart. The response must say what is live-only.
    #[test]
    fn an_import_over_an_unwritable_settings_dir_says_it_reverts() {
        let scratch = std::env::temp_dir().join(format!("nzbfast-impsave-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        let cfgdir = scratch.join("cfg");
        std::fs::create_dir_all(&cfgdir).unwrap();
        let pw = scratch.join("pw.txt");
        std::fs::write(&pw, "hunter2\n").unwrap();
        let dest = scratch.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        let ini = scratch.join("sabnzbd.ini");
        std::fs::write(
            &ini,
            format!(
                "[misc]\npassword_file = {}\n[categories]\n[[sabimports]]\n\
                 name = sabimports\ndir = {}\n",
                pw.display(),
                dest.display()
            ),
        )
        .unwrap();

        let d = test_daemon(&cfgdir);
        // The daemon's settings.json lives in cfgdir; a read-only dir
        // fails the atomic temp-file write exactly like a full disk.
        std::fs::set_permissions(&cfgdir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let mut req: tiny_http::Request = tiny_http::TestRequest::new().into();
        let cfg_path = cfgdir.join("nzbfast.toml");
        let ctx = ApiCtx {
            cfg_path: &cfg_path,
            host_hdr: "",
            base: "",
            ua_hdr: "",
            key_q: "",
            #[cfg(feature = "indexer")]
            tmdb_key: &None,
            bootstrap_apikey: false,
            via_add_only: false,
        };
        let mut params = std::collections::HashMap::new();
        params.insert("value".to_string(), ini.display().to_string());
        params.insert("value2".to_string(), "sabnzbd".to_string());
        let v = m_import_apply(&d, &mut req, &params, &ctx, &mut None).unwrap();

        std::fs::set_permissions(&cfgdir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&scratch);

        // Live import still worked - that nuance is deliberate...
        assert_eq!(v["status"], true, "{v}");
        assert_eq!(v["password_file"], pw.display().to_string(), "{v}");
        // ...but the response must carry the revert-at-restart warning,
        // naming what is live-only.
        let w = v["warning"].as_str().unwrap_or_default();
        assert!(w.contains("revert"), "no durability warning: {v}");
        assert!(w.contains("password_file"), "{v}");
        assert!(w.contains("categories"), "{v}");
    }
}
