//! Every `apply_setting` validator that is not the indexer family's
//! (TODO 106).
//!
//! settings.rs was 2,922 lines against the size gate's 3,000-line file
//! ceiling - 78 lines of headroom, which is the shape that reddens main
//! for whoever adds the next setting rather than for whoever wrote this
//! one. The write half comes out whole: one `set_*` per setting, each
//! validating a value from the settings UI, applying what it can to the
//! live daemon, and returning what to persist. What stays behind is the
//! other two halves - the settings TABLE and the read path built from
//! it, and `apply_setting`'s dispatch, which both source-scanning
//! guards read where they always did.
//!
//! Third file in the family and the same shape as the other two: a
//! child module of `settings`, so `use super::*` names `Daemon`,
//! `ConfigCtx` and the shared helpers exactly as the inline definitions
//! did, and the parent globs these back in for the dispatch. The
//! `#[path]` hook keeps it a flat sibling beside settings_apply.rs and
//! settings_index.rs; without it a plain `mod` would resolve to
//! `serve/settings/`, since settings.rs is not itself reached by
//! `#[path]`.
//!
//! `key_charset_ok` and `KEY_CHARSET_ERR` stayed in settings.rs on
//! purpose, though `set_apikey` is their first caller: they are the
//! charset RULE rather than a setter, and `serve::tests_api` names them
//! by path (`settings::key_charset_ok`), which a private glob re-import
//! in the parent would not answer.

use super::*;

pub(super) fn set_speedlimit(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let size = || parse_size(v).ok_or_else(|| format!("{name}: bad size (e.g. 4M, 10G, 0 = off)"));
    Ok({
        // SAB-compatible semantics (remote apps send percentages):
        // bare number ≤ 100 = PERCENT of the configured line speed
        // (100 = unlimited); anything else = absolute bytes/sec
        // (with or without K/M/G suffix), our native convention.
        let t = v.trim();
        let bps = match t.parse::<u64>() {
            Ok(0) => 0, // 0 = unlimited, both conventions
            Ok(pct) if pct <= 100 => {
                if pct >= 100 {
                    0
                } else {
                    // Percentage of the configured line speed - or,
                    // when none is set, of the measured link peak.
                    // Phone remotes (LunaSea, nzb360) send bare
                    // percentages on installs that have never opened
                    // Settings, and a refusal here surfaces in the app
                    // as "failed to set the speed limit" (§18); the
                    // learned peak is the same 100% anchor the
                    // dashboard's graph already uses. Only when
                    // NEITHER number exists is the honest answer
                    // still an error - a percentage of nothing.
                    let line = d.line_speed.load(Ordering::Relaxed);
                    let (peak, _src, _hint) = d.link_peak.chart(line);
                    let anchor = if line > 0 { line } else { peak };
                    if anchor == 0 {
                        return Err(
                            "percentage limits need a Line speed (Settings → Speed & scheduling)"
                                .into(),
                        );
                    }
                    anchor * pct / 100
                }
            }
            _ => size()?,
        };
        d.set_speed_ceiling(bps);
        (true, json!(bps))
    })
}

pub(super) fn set_auto_speed(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        let on = flag();
        d.auto_speed.store(on, Ordering::Relaxed);
        if !on {
            // Hand the wheel back: rate returns to the ceiling.
            d.hub.rate.set(d.speed_ceiling.load(Ordering::Relaxed));
        }
        (true, json!(on))
    })
}

pub(super) fn set_update_url(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let t = v.trim();
        if !t.is_empty() && !(t.starts_with("http://") || t.starts_with("https://")) {
            return Err("update_url: must be http(s), or empty to disable checks".into());
        }
        *d.update_url.lock_ok() = t.to_string();
        (true, json!(t))
    })
}

pub(super) fn set_ui_locale(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // §5 i18n daemon default. Empty = auto (each browser follows
        // its own language). The value is injected into served HTML,
        // so only known tags pass.
        let t = v.trim().to_ascii_lowercase();
        if !t.is_empty() && !UI_LOCALES.contains(&t.as_str()) {
            // List derived from UI_LOCALES so it can't drift as locales are added.
            return Err(format!(
                "ui_locale: one of {} - or empty for auto",
                UI_LOCALES.join(", ")
            ));
        }
        *d.ui_locale.lock_ok() = t.clone();
        (true, json!(t))
    })
}

/// §141 (issue #33): which origins the SAB-compatible API answers
/// `Access-Control-Allow-Origin` for.
///
/// `*` is the default because that is what real SABnzbd sends, and it is
/// the only value at which a browser extension works with no
/// configuration - which is the whole bug. It weakens nothing: the API
/// key rides every request explicitly, and CORS decides what a page may
/// READ, not who may call. A comma-separated list of origins narrows it
/// for anyone who wants it tighter; empty sends no header at all.
///
/// The charset is gated HERE rather than at the emit site, because the
/// value goes into a response header verbatim. tiny_http header values
/// are `AsciiString`, and CR and LF are ASCII: an ungated setting is
/// response splitting on the daemon's own origin, which is the same
/// shape the `/watch` redirect learned the hard way.
pub(super) fn set_cors_origin(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let mut cleaned: Vec<String> = Vec::new();
    for part in v.split(',') {
        let e = part.trim();
        if e.is_empty() {
            continue;
        }
        // An origin is scheme + host + optional port and NOTHING else -
        // no path, no space, no quote, nothing outside ASCII. Splitting
        // at the `://` is what makes "no path" checkable: the authority
        // that follows may not carry a slash, so `https://x.example/`
        // and `https://x.example/../evil` are refused rather than
        // silently compared against an Origin that can never contain
        // one. `[`/`]` admit an IPv6 literal; `moz-extension://` and
        // `chrome-extension://` fall out of the scheme rule.
        let shaped = e == "*"
            || e.split_once("://").is_some_and(|(scheme, authority)| {
                !scheme.is_empty()
                    && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                    && scheme
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
                    && !authority.is_empty()
                    && authority.chars().all(|c| {
                        c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':' | '[' | ']')
                    })
            });
        if !shaped {
            return Err("cors_origin: `*`, or origins like https://example.com or \
                 moz-extension://<id>, comma-separated - or empty to send no header"
                .into());
        }
        cleaned.push(e.to_string());
    }
    // A browser accepts exactly ONE value, so `*` alongside named
    // origins is a contradiction: whichever we answered, the other half
    // of the setting would be silently doing nothing.
    if cleaned.len() > 1 && cleaned.iter().any(|e| e == "*") {
        return Err("cors_origin: `*` cannot be combined with named origins".into());
    }
    let joined = cleaned.join(", ");
    *d.cors_origin.lock_ok() = joined.clone();
    Ok((true, json!(joined)))
}

pub(super) fn set_index_gapfill(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // A8: incomplete releases re-hunted per pass; 0 = off.
        let n = uint()?;
        if n > 100 {
            return Err("index_gapfill: 0-100 releases per pass".into());
        }
        d.index_gapfill.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

pub(super) fn set_index_probe7z_budget(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // B3: probe articles per hour across all releases; 0 = off.
        // 2000/h is ~13x the default and already past the point where
        // the lane outruns the band's daily inflow.
        let n = uint()?;
        if n > 2000 {
            return Err("index_probe7z_budget: 0-2000 articles per hour".into());
        }
        d.index_probe7z_budget.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

pub(super) fn set_index_pesto_budget(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // Pesto rung articles per hour; 0 = off. A named set costs ~2
        // articles, so even the default 120 outruns the band's inflow.
        let n = uint()?;
        if n > 2000 {
            return Err("index_pesto_budget: 0-2000 articles per hour".into());
        }
        d.index_pesto_budget.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

pub(super) fn set_index_nzbimport_budget(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // Posted-NZB fetch articles per hour; 0 = off. Most candidates
        // are one article; the 32 MiB decode cap bounds the largest at
        // ~48, and 2000/h is far past the walk's own 3-a-minute pace.
        let n = uint()?;
        if n > 2000 {
            return Err("index_nzbimport_budget: 0-2000 articles per hour".into());
        }
        d.index_nzbimport_budget.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

pub(super) fn set_bench_interval(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // Hours between scheduled system benchmarks; 0 = off.
        let h = uint()?;
        if h > 720 {
            return Err("bench_interval: 0-720 hours".into());
        }
        d.bench_interval.store(h, Ordering::Relaxed);
        (true, json!(h))
    })
}

pub(super) fn set_auto_prefetch(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        let on = flag();
        d.auto_prefetch.store(on, Ordering::Relaxed);
        if !on {
            // Turning it off also stops a running sidecar.
            d.poke_sidecar(|_| true);
        }
        (true, json!(on))
    })
}

pub(super) fn set_race_stragglers(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // The pool reads the persisted value per job, so this
        // applies from the NEXT download; the atomic is the
        // settings API's live mirror.
        let on = flag();
        d.race_stragglers.store(on, Ordering::Relaxed);
        (true, json!(on))
    })
}

pub(super) fn set_history_rows(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // 0 would render an empty card that looks broken; the upper
        // bound is what one page can show before it is a scroll job.
        let n = uint()?;
        if !(1..=200).contains(&n) {
            return Err("history_rows: 1-200".into());
        }
        d.history_rows.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

pub(super) fn set_connections(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        let n = uint()?.clamp(1, 999) as usize;
        d.connections.store(n, Ordering::Relaxed);
        // Raising this number has to be able to beat a stored
        // auto-tune knee, or it is a control that does nothing: a
        // v1.0.14 tester set 22, then 24, restarted, tried a fresh
        // NZB, and every job still ran at the knee of 6 the tuner
        // had measured once. A knee is a measurement taken UNDER a
        // ceiling, so a higher ceiling retires it pending a
        // re-probe. Lowering the number changes nothing here -
        // min(configured, knee) already handles that direction.
        crate::conntune::reopen_for_install(&d.cfg_path, n);
        (true, json!(n))
    })
}

pub(super) fn set_fast_verify(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        let on = flag();
        d.fast_verify.store(on, Ordering::Relaxed);
        if !on {
            // Full verify supersedes lean - no article-CRC skipping.
            d.verify_lean.store(false, Ordering::Relaxed);
        }
        // This arm moves BOTH fields, so it has to persist both. The
        // caller saves only the key it was handed, and at launch
        // apply_saved_settings applies fast_verify FIRST and then
        // verify_mode, which sets the pair again - so a stale
        // verify_mode left in settings.json reverts this write on
        // every restart, and an install that once chose lean comes
        // back lean after the user asked for full. Read verify_lean
        // after the stores above, never before.
        let mode = match (on, d.verify_lean.load(Ordering::Relaxed)) {
            (false, _) => "full",
            (true, false) => "fast",
            (true, true) => "lean",
        };
        save_setting(&d.settings_path, "verify_mode", json!(mode));
        (true, json!(on))
    })
}

pub(super) fn set_verify_mode(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let (fast, lean) = match v.trim() {
            "full" => (false, false),
            "fast" => (true, false),
            "lean" => (true, true),
            _ => return Err("verify_mode must be full, fast, or lean".into()),
        };
        d.fast_verify.store(fast, Ordering::Relaxed);
        d.verify_lean.store(lean, Ordering::Relaxed);
        (true, json!(v.trim()))
    })
}

pub(super) fn set_out_umask(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Empty clears it, which is the documented way back to
        // "whatever the process umask gives" - the state every
        // install starts in.
        let v = v.trim();
        if v.is_empty() {
            d.out_umask.store(u32::MAX, Ordering::Relaxed);
            return Ok((true, json!("")));
        }
        // Octal, and range-checked. A umask outside 0-0777 is not a
        // stricter setting, it is a typo: `0o1000` would wrap into
        // mode bits that mean setuid rather than permission.
        let m = u32::from_str_radix(v, 8)
            .ok()
            .filter(|m| *m <= 0o777)
            .ok_or("out_umask must be an octal umask like 002 or 022")?;
        d.out_umask.store(m, Ordering::Relaxed);
        (true, json!(format!("{m:03o}")))
    })
}

pub(super) fn set_auto_retry_mins(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let m = v
            .trim()
            .parse::<u64>()
            .map_err(|_| "auto_retry_mins must be a number")?;
        d.auto_retry_secs.store(m * 60, Ordering::Relaxed);
        (true, json!(m))
    })
}

pub(super) fn set_quota_period(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let p = match v.trim() {
            "d" | "D" => b'd',
            "w" | "W" => b'w',
            "m" | "M" => b'm',
            _ => return Err("quota_period must be d, w or m".into()),
        };
        d.quota_period.store(p, Ordering::Relaxed);
        (true, json!((p as char).to_string()))
    })
}

pub(super) fn set_watch(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let p = v.trim();
        if !p.is_empty() {
            let _ = std::fs::create_dir_all(p);
        }
        *d.watch_dir.lock_ok() = (!p.is_empty()).then(|| PathBuf::from(p));
        (true, json!(p))
    })
}

pub(super) fn set_schedule(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let text = v.trim().to_string();
        if text.is_empty() {
            d.schedule.lock_ok().clear();
            d.schedule_text.lock_ok().clear();
        } else {
            let entries = parse_schedule(&text).map_err(|e| e.to_string())?;
            // Re-evaluate the week immediately, exactly like startup:
            // if the new schedule implies paused/limited NOW, apply it.
            let (paused, limit) = effective_state(&entries, local_minute_of_week());
            // Through the one mutator, so this route cancels a pending
            // timed pause too. Otherwise identical: the pause leg
            // already wound the transfer down here.
            if let Some(p) = paused {
                apply_action(
                    d,
                    if p {
                        SchedAction::Pause
                    } else {
                        SchedAction::Resume
                    },
                );
            }
            if let Some(l) = limit {
                d.set_speed_ceiling_from(l, "schedule");
            }
            *d.schedule.lock_ok() = entries;
            *d.schedule_text.lock_ok() = text.clone();
        }
        (true, json!(text))
    })
}

pub(super) fn set_library_cats(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let cats: Vec<String> = v
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect();
        *d.library_cats.lock_ok() = cats.clone();
        (true, json!(cats))
    })
}

pub(super) fn set_index_groups(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let groups: Vec<String> = v
            .split(',')
            .map(str::trim)
            .filter(|g| !g.is_empty())
            .map(str::to_string)
            .collect();
        *d.index_groups.lock_ok() = groups.clone();
        (true, json!(groups))
    })
}

#[cfg(feature = "indexer")]
pub(super) fn set_index_interests(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Comma list of interest keys (crate::interests). Unknown
        // keys are dropped, not rejected: the stored value must
        // survive a downgrade, and the failure direction that
        // matters is "indexed something nobody asked for".
        let keys = crate::interests::parse(v);
        let norm = keys.join(",");
        *d.index_interests.lock_ok() = norm.clone();
        // Resolve now if the catalogue is already here; otherwise
        // apply_interests asks for one and the fetch applies it.
        apply_interests(d);
        (true, json!(norm))
    })
}

pub(super) fn set_delete_to_trash(
    _d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // Deletes of the downloads themselves go to the Trash so a
        // wrong click is recoverable. On by default on macOS and
        // Windows, where the Trash is a place the user can see and
        // empty; off by default on Linux and FreeBSD, where it is not -
        // see `trash_suits_this_platform`. Off means a permanent delete.
        // Garbage cleanup follows this too unless `cleanup_delete_mode`
        // says otherwise.
        let on = flag();
        crate::smart::set_delete_to_trash(on);
        (true, json!(on))
    })
}

pub(super) fn set_cleanup_delete_mode(
    _d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    // Garbage-class deletes only (spent volumes, repair files, junk
    // sweeps): "follow" rides delete_to_trash, "trash" is always
    // recoverable, "delete" is always permanent. An unknown value is
    // refused rather than defaulted - a typo silently becoming
    // permanent deletes is the one wrong answer here.
    let Some(mode) = crate::smart::CleanupMode::parse(&v.to_ascii_lowercase()) else {
        return Err(format!(
            "unknown cleanup_delete_mode {v:?} - use follow, trash or delete"
        ));
    };
    crate::smart::set_cleanup_mode(mode);
    Ok((true, json!(mode.as_str())))
}

pub(super) fn set_watch_interval_secs(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // The filesystem watcher already makes a local drop instant,
        // so this is the fallback rate for shares it cannot see.
        // Floored at 1 s: below that it is a directory listing per
        // frame for no gain, since the watcher covers the fast case.
        let n = uint()?.clamp(1, 3600);
        d.watch_interval_secs.store(n, Ordering::Relaxed);
        d.watch_scan_now.notify_one();
        (true, json!(n))
    })
}

pub(super) fn set_index_tip_secs(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // 0 = off. Otherwise floor at 5 s: the tick costs one GROUP
        // command per group when nothing has arrived, but there is
        // no reason to spin faster than posts appear.
        let n = uint()?;
        let n = if n == 0 { 0 } else { n.max(5) };
        d.index_tip_secs.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

pub(super) fn set_nested_max_depth(
    _d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // Depth cap for nested (RAR/7z-in-archive) extraction, shared
        // by the in-stream child chain and the disk post-pass. At the
        // cap the deepest layer materializes - never a failed job.
        // Applies to downloads started after the change.
        let n = uint()?.clamp(1, 64);
        nzbkit::extract::set_nested_depth_cap(n as usize);
        (true, json!(n))
    })
}

pub(super) fn set_apikey(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    if !key_charset_ok(v.trim()) {
        return Err(format!("apikey: {KEY_CHARSET_ERR}"));
    }
    Ok({
        let k = v.trim().to_string();
        *d.apikey.lock_ok() = (!k.is_empty()).then(|| k.clone());
        // settings.json and the key file are both siblings of the
        // config (see settings_file / first_run_apikey).
        let keyfile = d.settings_path.with_file_name("apikey");
        if k.is_empty() {
            match std::fs::remove_file(&keyfile) {
                Ok(()) => {
                    info!(target: "config", "apikey cleared - removed {}", keyfile.display())
                }
                // Nothing to remove: the key came from --apikey, a
                // hand-written settings.json, or a container env.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                // Best-effort, as everywhere else in here: never fail
                // a live setting on an IO error. But say so - the key
                // WILL come back on the next start, and a silent
                // failure here is the exact bug being fixed.
                Err(e) => warn!(
                    target: "settings",
                    "⚠ cleared the API key but could not remove {} ({e}) - it will be read \
                     back on the next start. Delete that file to stay keyless.",
                    keyfile.display()
                ),
            }
        } else {
            // Setting a key puts the file BACK. Clearing removes it,
            // so clear-then-rekey used to leave settings.json keyed
            // and no key file at all - which the daemon itself does
            // not mind (settings.json wins at load, and
            // first_run_apikey only reads the file when no key is
            // set, so the duplicate is harmless), but the container
            // entrypoint reads the file to decide whether an
            // established install is about to publish the control
            // API keyless. With the file gone it refused to start,
            // and the container could not be restarted at all.
            //
            // Best-effort like the removal above: never fail a live
            // setting on an IO error, but do say so.
            if let Err(e) = crate::persist::write_atomic(&keyfile, k.as_bytes()) {
                warn!(
                    target: "settings",
                    "⚠ set the API key but could not write {} ({e}) - the key itself is \
                     live and saved in Settings; a container may refuse to restart until \
                     that file can be written.",
                    keyfile.display()
                );
            }
        }
        (true, if k.is_empty() { Value::Null } else { json!(k) })
    })
}

pub(super) fn set_feeds(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // JSON array of {id, url, interval_secs, category, rules}; the
        // poller picks the new list up on its next 30 s pass.
        let text = v.trim();
        let mut list: Vec<crate::rss::FeedConfig> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("feeds: {e}"))?
        };
        // TODO §20c: get_config ships each feed's url MASKED, so what
        // comes back for an untouched row is the mask, not the url -
        // and the mask must never be stored, or one save of an
        // unrelated setting on that row would erase the indexer
        // credential. The id is what makes that recoverable: it is the
        // merge key (the url cannot be, precisely because it is the
        // secret), and `url_is_unchanged` is the same "blank keeps the
        // stored one" contract the indexer apikey and the list-source
        // token already use, widened by one spelling.
        {
            let cur = d.feeds.lock_ok();
            for f in list.iter_mut() {
                f.id = f.id.trim().to_string();
                f.url = f.url.trim().to_string();
                if let Some(old) = cur.iter().find(|o| !o.id.is_empty() && o.id == f.id)
                    && crate::rss::url_is_unchanged(&f.url, &old.url)
                {
                    f.url = old.url.clone();
                }
            }
        }
        // The masked-field trap, refused rather than obeyed: a user who
        // edits ONE parameter of a masked url leaves the `***` sitting
        // in the middle of it, and that url no longer equals the mask,
        // so every rule above reads it as a NEW address and the
        // credential is gone. Anything still carrying the mask marker
        // after the merge is that edit. English, like every other
        // daemon string - the display edge translates what it knows and
        // shows the rest verbatim (§5).
        //
        // Which is why the dashboard makes this same judgement one step
        // EARLIER, in feedMaskEdited() in web/dashboard.html: a toast
        // written on the page gets an ordinary t() key the extractor
        // scrapes into all 27 catalogues, where translating THIS
        // sentence would mean a key that is the whole sentence, a hand
        // entry in extract.js's dynamic err.* family, and a reword here
        // silently un-translating every locale with each CI gate still
        // green. So a dashboard user never reaches this string. It is
        // not redundant: it is the guard for every other API client,
        // and it is still what answers the row whose feed was deleted
        // elsewhere between load and save, which the page cannot see.
        // Reword it freely - nothing keys on the text.
        if list.iter().any(|f| f.url.contains("***")) {
            return Err("feeds: a feed URL still has *** in it, which is where the \
                        hidden API key goes. Paste the whole address again, or put \
                        the row back exactly as it was to keep the stored key."
                .into());
        }
        // A row left with no url after that merge is a row whose id
        // matched nothing - a client sending "keep the stored url" for
        // a feed that no longer exists. There is no url to poll and
        // nothing to keep, so it is dropped rather than stored as a
        // feed that fails forever.
        list.retain(|f| !f.url.is_empty());
        // F8: two rows carrying the SAME address are refused, because the
        // poller cannot tell them apart and says nothing when it fails to.
        // `assign_feed_ids` below hands every row a distinct id, so the
        // list looked fine from here - but the poller keys its next-poll
        // deadline by url, its health by url, and the on-disk seen scope
        // by url (`FeedConfig::scope_key` hashes the url). So the first
        // row polls and arms the deadline; every later row with that url
        // reads the same future deadline and is skipped, on that pass and
        // on every pass after it, forever, with no error anywhere - and
        // its settings row displays the FIRST row's health, so the UI
        // positively asserts that a feed which has never polled is fine.
        // Two rows with disjoint Accept rules could not both work.
        //
        // Refused rather than fixed by keying those maps per id: the
        // third key is the seen scope, which is baked into the on-disk
        // rss-seen.json, so moving it orphans every existing entry and
        // the whole rolling window would be re-grabbed on the next poll.
        // Per-id seen scopes also raise a product question nobody has
        // answered - an item matching both rows would be enqueued twice.
        // A refusal costs no migration, touches no durable format, and
        // turns a silent permanent starvation into a legible error at the
        // moment of the mistake.
        //
        // AFTER the id-keyed merge above and after the empty-url retain,
        // never before either: a row that sent the mask back still holds
        // the mask at that point, so it would be compared as `***` rather
        // than as the url it stands for - two untouched rows of two
        // DIFFERENT feeds can mask to the same string, and a check placed
        // earlier would refuse an ordinary save of a correct list.
        //
        // Accepted limit: the comparison is of raw url strings, so two
        // spellings of one address - the same query parameters in a
        // different order, a trailing slash - are not caught. A
        // canonicaliser here would be a second guess at every indexer's
        // url grammar, and guessing wrong would MERGE two feeds that are
        // genuinely different.
        {
            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for f in &list {
                if !seen.insert(f.url.as_str()) {
                    // The MASKED url, never the raw one: this string
                    // reaches the settings UI and the log ring, and a feed
                    // url essentially always carries the indexer's
                    // `apikey=`. Same rule as `FeedHealth::failed`.
                    //
                    // English, like every other daemon string (§5), and
                    // nothing keys on the text - reword it freely.
                    return Err(format!(
                        "feeds: {} is listed twice. One address is one feed: the poller \
                         keys a feed's next poll, its health and what it has already seen \
                         by its address, so the second row would never poll and would show \
                         the first row's health. Delete it and put its rules on the first \
                         row - Accept(category=..., priority=...) files what each rule \
                         matches.",
                        crate::rss::mask_feed_url(&f.url)
                    ));
                }
            }
        }
        crate::rss::assign_feed_ids(&mut list);
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.feeds.lock_ok() = list;
        (true, persist)
    })
}

pub(super) fn set_indexers(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // M35: JSON array of newznab::IndexerConfig. A blank apikey
        // in an entry keeps the stored key of the same-named entry
        // (get_config never echoes keys, so the UI round-trips
        // blanks); renaming an entry and blanking its key in the
        // same edit drops the key, which is the honest reading.
        let text = v.trim();
        let mut list: Vec<crate::newznab::IndexerConfig> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("indexers: {e}"))?
        };
        {
            let cur = d.indexers.lock_ok();
            for i in list.iter_mut() {
                i.name = i.name.trim().to_string();
                i.url = i.url.trim().to_string();
                // TODO 297: a group list is typed by hand, so it
                // arrives with the blanks and stray whitespace a
                // textarea leaves behind. Cleaned here so `search_url`
                // never has to decide what an empty group means.
                i.nzbindex.groups = i
                    .nzbindex
                    .groups
                    .iter()
                    .map(|g| g.trim().to_string())
                    .filter(|g| !g.is_empty())
                    .collect();
                if i.apikey.is_empty()
                    && let Some(old) = cur.iter().find(|o| o.name == i.name)
                {
                    i.apikey = old.apikey.clone();
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        for i in &list {
            if i.name.is_empty() || i.url.is_empty() {
                return Err("indexers: every entry needs a name and a URL".into());
            }
            if !(i.url.starts_with("http://") || i.url.starts_with("https://")) {
                return Err(format!("indexers: {}: the URL must be http(s)", i.name));
            }
            if !seen.insert(i.name.clone()) {
                return Err(format!("indexers: duplicate name {}", i.name));
            }
            // TODO 297: an nzbindex entry's own ranges, refused HERE
            // rather than at search time. An inverted range is not an
            // error at the far end - it is a filter that matches
            // nothing - so a search would come back empty and read as
            // "nzbindex has none of that", which is the failure this
            // whole source is built to avoid reporting falsely.
            if i.kind == crate::newznab::SourceKind::Nzbindex {
                let o = &i.nzbindex;
                if o.max_size_mb > 0 && o.min_size_mb > o.max_size_mb {
                    return Err(format!(
                        "indexers: {}: smallest size is above the largest",
                        i.name
                    ));
                }
                if o.max_age_days > 0 && o.min_age_days > o.max_age_days {
                    return Err(format!(
                        "indexers: {}: oldest age is below the newest",
                        i.name
                    ));
                }
            }
        }
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.indexers.lock_ok() = list;
        (true, persist)
    })
}

pub(super) fn set_watchlist_external(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // M35 phase 2: let the watcher ask the user's indexer
        // accounts for wanted items. Each item then spends at most
        // one search per WATCH_EXT_INTERVAL_SECS, and per-indexer
        // daily budgets still apply on top.
        //
        // M35b: writing here is the user ANSWERING, which pins the
        // value against the indexers-configured default - including
        // an explicit off, which must survive adding an indexer.
        d.watchlist_external.store(flag(), Ordering::Relaxed);
        d.watchlist_external_set.store(true, Ordering::Relaxed);
        (true, json!(d.watchlist_external.load(Ordering::Relaxed)))
    })
}

pub(super) fn set_watchlist_instant(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // §74: grab a watched release as it ARRIVES rather than at
        // the next periodic pass. Nothing to arm or disarm here - the
        // arrival hooks read the flag each time - and with the
        // built-in indexer off there are no arrivals to react to, so
        // this is inert rather than wrong on an index-less install.
        d.watchlist_instant.store(flag(), Ordering::Relaxed);
        (true, json!(d.watchlist_instant.load(Ordering::Relaxed)))
    })
}

pub(super) fn set_watchlist_instant_max(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // §74: instant passes per hour, 0 = no limit. Capped well
        // above any sane value rather than validated tightly: over
        // the ceiling the periodic pass still grabs everything a
        // minute later, so a silly number costs churn, not downloads.
        let n = uint()?.min(3600) as u32;
        d.watchlist_instant_max.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

pub(super) fn set_watchlist(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // JSON array of watchlist::WatchItem; an edit wakes the
        // watcher so adds are checked against the index at once.
        let text = v.trim();
        let list: Vec<crate::watchlist::WatchItem> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("watchlist: {e}"))?
        };
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.watchlist.lock_ok() = list;
        d.watch_now.notify_one();
        (true, persist)
    })
}

pub(super) fn set_smart_folders(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // M23: JSON array of rules; every enqueue from now on runs
        // through the new list (first match wins).
        let text = v.trim();
        let list: Vec<crate::smart::Rule> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("smart_folders: {e}"))?
        };
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.smart_folders.lock_ok() = list;
        (true, persist)
    })
}

pub(super) fn set_password_file(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Path to the SAB/NZBGet-compatible passwords file (one per
        // line). Empty resets to the default next to the config.
        // Created immediately if missing so the path the UI shows
        // is never a dangling promise; contents are read fresh per
        // unlock, so this is live.
        let p = v.trim();
        let path = if p.is_empty() {
            d.cfg_path.with_file_name("passwords.txt")
        } else {
            std::path::PathBuf::from(p)
        };
        if !path.exists() {
            crate::persist::write_atomic(&path, b"")
                .map_err(|e| format!("password_file: cannot create {}: {e}", path.display()))?;
        }
        *d.password_file.lock_ok() = path.clone();
        *d.hub.unpack_password_file.lock_ok() = Some(path.clone());
        crate::smart::set_operator_password_file(Some(path.clone()));
        (true, json!(path.to_string_lossy()))
    })
}

/// §129 3e. Switching it OFF while a storage pause is holding must
/// RELEASE that pause, or the user is left with a paused queue and the
/// mechanism that would resume it disarmed. The watcher does that on its
/// next tick (it owns the judge state), so this only flips the flag.
pub(super) fn set_slow_storage_pause(d: &Arc<Daemon>, on: bool) -> (bool, Value) {
    d.slow_storage.set_enabled(on);
    (true, json!(on))
}

pub(super) fn set_password_prompt(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // now | done | never - what the dashboard does when an
        // archive turns out passworded ("never" also changes the
        // completion shape: left packed, no failure text).
        let m = v.trim().to_ascii_lowercase();
        if !matches!(m.as_str(), "now" | "done" | "never") {
            return Err("password_prompt must be now, done or never".into());
        }
        *d.password_prompt.lock_ok() = m.clone();
        (true, json!(m))
    })
}

pub(super) fn set_preview(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // off | metadata-only | full. Live: the endpoint reads it per
        // request and the dashboard reads it off the queue poll, so a
        // change reaches an open page within the second.
        let m = v.trim().to_ascii_lowercase();
        if !PREVIEW_MODES.contains(&m.as_str()) {
            return Err("preview must be off, metadata-only or full".into());
        }
        *d.preview.lock_ok() = m.clone();
        (true, json!(m))
    })
}

pub(super) fn set_unpack_eat_volumes(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // TODO 101. off | low_disk | always. Live: the decision is
        // taken per job, at the moment its disk unpack is about to
        // start, so a change here applies to the very next unpack -
        // including one already downloading.
        let m = v.trim().to_ascii_lowercase();
        let Some(mode) = crate::eatvol::EatMode::parse(&m) else {
            return Err("unpack_eat_volumes must be off, low_disk or always".into());
        };
        *d.unpack_eat_volumes.lock_ok() = mode.as_str().to_string();
        crate::eatvol::set_mode(mode);
        (true, json!(mode.as_str()))
    })
}

pub(super) fn set_fast_par(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // "Fast PAR mode": heavy repairs take the NTT syndrome path.
        // Live - the flag is read per repair. NZBFAST_NTT in the
        // daemon's environment overrides it inside nzbkit.
        let on = flag();
        d.fast_par.store(on, Ordering::Relaxed);
        nzbkit::par2repair::set_fast_par_enabled(on);
        (true, json!(on))
    })
}

pub(super) fn set_prefer_external_unrar(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // Live for any unpack that has not started: the disk-path
        // engine choice reads it per unpack, the top-level RAR
        // chase latches it per job. No daemon restart needed.
        let on = flag();
        d.prefer_external_unrar.store(on, Ordering::Relaxed);
        nzbkit::extract::set_prefer_external_unrar(on);
        (true, json!(on))
    })
}

/// TODO 60a, the save-time half of `prefer_external_unrar`: a warning
/// for the answer to `mode=config` when the setting is turned ON and
/// there is no `unrar` to turn it on for.
///
/// A warning, never an Err. Gating the save on this probe would turn a
/// working config into an unsettable one twice over: a container that
/// mounts unrar after the daemon started, and a PATH that differs
/// between this request thread and the unpack, both save a setting they
/// would then refuse. The value stores either way and the dashboard
/// shows this at the control, which is the whole point - until now the
/// only signal was the "volumes left on disk" line in the log, one
/// failed job later.
///
/// Only on the way ON, and only when the probe finds nothing: turning
/// the setting off cannot want unrar, and a note on every re-save by
/// someone who has it is a note everyone learns to scroll past.
///
/// No subprocess - a settings write has never shelled out, and this is
/// on the request thread. `tools::resolve` plus the PATH walk `Command`
/// would do is a handful of stats. What it proves is "there is a file
/// to run", not "it runs": a binary that is present and broken still
/// reports at unpack time, where the "unrar not runnable" line lives.
pub(super) fn prefer_external_unrar_warning(name: &str, v: &str) -> Option<String> {
    prefer_external_unrar_warning_with(name, v, unrar_resolves)
}

/// The half a test can pin. The probe's own answer is whatever the box
/// running the suite happens to have installed, so a test that called
/// the real one could only assert the tautology - and the case that
/// matters is the one CI will no longer be in once TODO 60b lands unrar
/// on the runner.
pub(super) fn prefer_external_unrar_warning_with(
    name: &str,
    v: &str,
    resolves: impl Fn() -> bool,
) -> Option<String> {
    if name != "prefer_external_unrar" || !(v == "1" || v.eq_ignore_ascii_case("true")) {
        return None;
    }
    (!resolves()).then(|| {
        "unrar is not installed, so unpacking keeps using the built-in extractor. \
         Install unrar, or put it beside the nzbfast program, and the setting \
         takes effect on the very next unpack."
            .to_string()
    })
}

/// The probe itself. `tools::resolve` answers either a sibling binary it
/// has already stat'd or the BARE name, which is a lookup this has to
/// finish: `Command` searches PATH for a bare name and never the current
/// directory, so a bare answer must be walked rather than stat'd where
/// it stands.
fn unrar_resolves() -> bool {
    let bin = crate::tools::resolve("unrar");
    if bin.components().count() > 1 {
        return bin.is_file();
    }
    // Windows resolves `unrar` to `unrar.exe` through PATHEXT, so both
    // spellings count - the sibling half of `resolve` uses EXE_SUFFIX
    // for exactly this reason.
    let exe = format!("unrar{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| d.join("unrar").is_file() || d.join(&exe).is_file())
    })
}

pub(super) fn set_custom_categories(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // TODO 24D: JSON array of user categories (slug, name, match
        // rules, base behavior). Validated as a whole - a reserved or
        // duplicate slug rejects the save. On change the scan loop
        // runs a chunked re-classification pass over stored rows.
        let text = v.trim();
        let list: Vec<nzbkit::categories::CustomCategory> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("custom_categories: {e}"))?
        };
        nzbkit::categories::validate(&list).map_err(|e| format!("custom_categories: {e}"))?;
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.custom_categories.write_ok() = list;
        d.reclassify_pending.store(true, Ordering::Relaxed);
        (true, persist)
    })
}

pub(super) fn set_failure_link(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // off | report | regrab. See Daemon::report_failure.
        let m = v.trim().to_ascii_lowercase();
        if !matches!(m.as_str(), "off" | "report" | "regrab") {
            return Err("failure_link must be off, report or regrab".into());
        }
        *d.failure_link.lock_ok() = m.clone();
        (true, json!(m))
    })
}

pub(super) fn set_prefer_quality(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // {"res":"2160p","vcodec":"x265","acodec":"Atmos","hdr":"DV"},
        // any field omitted or "" meaning no opinion. Validated here
        // so a typo is a visible error rather than a preference that
        // silently never matches anything.
        let p = crate::watchlist::QualityPrefs::from_json(v)
            .map_err(|e| format!("prefer_quality: {e}"))?;
        let stored = p.to_json();
        *d.quality_prefs.lock_ok() = p;
        (true, stored)
    })
}

pub(super) fn set_notify_targets(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // JSON array of media servers / webhooks told about every
        // finished job. Applies to the next completion.
        let text = v.trim();
        let mut list: Vec<crate::notify::Target> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("notify_targets: {e}"))?
        };
        // get_config never hands the token back (it is a credential),
        // so the dashboard - which rebuilds this whole list from the
        // DOM and replaces it wholesale - submits a blank one for
        // every unchanged row. Blank means KEEP: carry the stored
        // token forward. Matched on (kind, url, name), not on
        // position: rows get reordered and deleted between the load
        // and the save, and an index match would hand one target's
        // credential to another.
        {
            let old = d.notify_targets.lock_ok().clone();
            merge_notify_tokens(&mut list, &old);
        }
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.notify_targets.lock_ok() = list;
        (true, persist)
    })
}

pub(super) fn set_arr_giveup_threshold(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // §96.3: distinct failed releases per target before the
        // give-up fires. 0 = off.
        //
        // Capped at the evidence store's own cap, not at a round 1000:
        // a target remembers at most `MAX_STEMS` distinct failed stems,
        // so a threshold above that is a condition that can never become
        // true - "off", but spelt as a number the user believes will
        // fire (M13, 10 Aug sweep). Clamping says what actually happens.
        let n = uint()?.min(super::giveup::MAX_STEMS as u64);
        d.arr_giveup_threshold.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

pub(super) fn set_arr_instances(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // §96.3: JSON array of {name, kind, url, apikey, enabled}.
        // Validated as a whole - a typo'd kind would otherwise be an
        // instance the breaker silently never acts on.
        let text = v.trim();
        let mut list: Vec<super::giveup::ArrInstance> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("arr_instances: {e}"))?
        };
        for i in &list {
            if !matches!(i.kind.as_str(), "sonarr" | "radarr") {
                return Err(format!(
                    "arr_instances: kind must be sonarr or radarr, not {:?}",
                    i.kind
                ));
            }
            let u = i.url.trim();
            if !(u.starts_with("http://") || u.starts_with("https://")) {
                return Err("arr_instances: url must start with http:// or https://".into());
            }
        }
        // get_config never hands the apikey back, so a UI that
        // round-trips the list submits a blank one for every
        // unchanged row. Blank means KEEP: carried forward from the
        // stored instance at the same (kind, url), or failing that
        // the same (kind, name) - correcting a typo'd host must not
        // throw the key away.
        {
            let old = d.arr_instances.lock_ok().clone();
            for i in list.iter_mut().filter(|i| i.apikey.is_empty()) {
                if let Some(o) = old
                    .iter()
                    .find(|o| o.kind == i.kind && o.url == i.url)
                    .or_else(|| old.iter().find(|o| o.kind == i.kind && o.name == i.name))
                {
                    i.apikey = o.apikey.clone();
                }
            }
        }
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.arr_instances.lock_ok() = list;
        (true, persist)
    })
}

pub(super) fn set_port(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        let p = uint()?;
        if !(1..=65535).contains(&p) {
            return Err("port must be 1-65535".into());
        }
        // Refused, not silently ignored: saving a port this
        // installation will never bind is how a container ends up
        // unreachable through its published mapping with the UI still
        // claiming the change took.
        if d.port_locked {
            return Err(
                "this installation's port is set by how it was started (a container's \
                     published port, or the Synology package's own setting), so it can't be \
                     changed here. Change it where the port is published instead."
                    .into(),
            );
        }
        (false, json!(p))
    })
}

/// §193 c: the dashboard/API listen address, applied at the next
/// restart like the port beside it.
///
/// An IP literal only, and empty means the default 0.0.0.0 (every
/// interface). A NAME is refused rather than resolved: the resolution
/// would have to happen on an API worker, and a bind address that
/// depends on what DNS said at save time is a daemon that starts
/// somewhere different the next time the answer changes. Nothing else
/// narrows here - `apply_saved_settings` still honours whatever the
/// file holds, so a hand-written value keeps working; this is the check
/// on what the UI is allowed to write.
///
/// No reachability check. Whether this machine actually HAS the address
/// is a question only the bind can answer, and the answer changes with
/// the network - so the row carries the warning and the restart carries
/// the verdict.
pub(super) fn set_bind(
    _d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let a = v.trim();
    if a.is_empty() {
        return Ok((false, json!("0.0.0.0")));
    }
    if a.parse::<std::net::IpAddr>().is_err() {
        return Err(format!(
            "{a:?} is not an IP address. Use 0.0.0.0 for every interface, 127.0.0.1 \
             for this machine only, :: for every interface including IPv6, or the \
             address of one interface."
        ));
    }
    Ok((false, json!(a)))
}

/// §129 2a: the TLS pair is validated at SAVE time - a path typo or a
/// non-PEM file fails the Apply with the reason, instead of surfacing as
/// a refused restart later with nobody watching the log. Empty clears
/// the half (both empty = plain HTTP). Applies at the next restart, like
/// the port; take_listener re-validates at bind with the same wording.
pub(super) fn set_tls_cert(
    _d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let p = v.trim();
    if !p.is_empty() {
        use rustls::pki_types::pem::PemObject;
        let certs: Vec<rustls::pki_types::CertificateDer<'_>> =
            rustls::pki_types::CertificateDer::pem_file_iter(std::path::Path::new(p))
                .map_err(|e| format!("{p}: {e}"))?
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| format!("{p}: {e}"))?;
        if certs.is_empty() {
            return Err(format!(
                "{p}: no certificates in the file (is it a PEM certificate?)"
            ));
        }
        let (_, leaf) = x509_parser::parse_x509_certificate(certs[0].as_ref())
            .map_err(|e| format!("{p}: not a valid X.509 certificate ({e})"))?;
        let val = leaf.validity();
        if !val.is_valid_at(x509_parser::time::ASN1Time::now()) {
            return Err(format!(
                "{p}: the certificate is expired or not valid yet (valid {} to {})",
                val.not_before, val.not_after
            ));
        }
    }
    Ok((false, json!(p)))
}

pub(super) fn set_tls_key(
    _d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let p = v.trim();
    if !p.is_empty() {
        use rustls::pki_types::pem::PemObject;
        rustls::pki_types::PrivateKeyDer::from_pem_file(std::path::Path::new(p))
            .map_err(|e| format!("{p}: {e}"))?;
    }
    Ok((false, json!(p)))
}

pub(super) fn set_out_dir(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let p = v.trim();
        if p.is_empty() {
            return Err("out_dir can't be empty".into());
        }
        let path = PathBuf::from(p);
        // Create it if missing so a hand-typed path isn't a dead setting,
        // and fail loudly if we can't - better than silently pointing the
        // downloads at a folder that won't accept them.
        std::fs::create_dir_all(&path).map_err(|e| format!("can't use {p}: {e}"))?;
        // Same real-write rule as the move destinations: access(2)
        // consults permission bits, and permission bits are not the
        // only gatekeeper.
        if let Err(e) = write_probe(&path) {
            return Err(format!("{p} did not accept a test write: {e}"));
        }
        // LIVE: the next enqueue builds its job directory from here. The
        // spool (queue journal / usage / art) was fixed at startup and
        // deliberately does NOT move, so in-flight state is never stranded.
        *d.out_root.write_ok() = path;
        (true, json!(p))
    })
}

pub(super) fn set_move_completed(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // M33: post-completion destination (NAS share etc.). Empty
        // clears it - downloads then stay under out_dir.
        let p = v.trim();
        if p.is_empty() {
            *d.move_completed.write_ok() = None;
            (true, json!(""))
        } else {
            let path = PathBuf::from(p);
            require_absolute_dest(&path)?;
            std::fs::create_dir_all(&path).map_err(|e| format!("can't use {p}: {e}"))?;
            // A REAL write, not access(2): permission bits are not the
            // only gatekeeper (macOS network-volume consent said no
            // while access said yes, 7 Aug), and catching that here
            // costs one empty directory instead of a stranded payload
            // per finished job.
            if let Err(e) = write_probe(&path) {
                return Err(format!("{p} did not accept a test write: {e}"));
            }
            if same_dir(&path, &d.out_root.read_ok()) {
                return Err(
                    "move_completed is the download folder itself - nothing to move".into(),
                );
            }
            *d.move_completed.write_ok() = Some(path);
            (true, json!(p))
        }
    })
}

pub(super) fn set_move_completed_cats(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // M33 v2: "tv=/NAS/TV, movies=/NAS/Movies". Empty clears.
        let list = parse_cat_dests(v)?;
        for (_, path) in &list {
            let p = path.display();
            require_absolute_dest(path)?;
            std::fs::create_dir_all(path).map_err(|e| format!("can't use {p}: {e}"))?;
            // Same real-write rule as the global destination above.
            if let Err(e) = write_probe(path) {
                return Err(format!("{p} did not accept a test write: {e}"));
            }
            // The global destination has always been refused when it
            // is the download folder; the per-category ones were not
            // checked at all, and they reach the same move_tree.
            if same_dir(path, &d.out_root.read_ok()) {
                return Err(format!(
                    "{p} is the download folder itself - nothing to move"
                ));
            }
        }
        let echo = fmt_cat_dests(&list);
        *d.move_completed_cats.write_ok() = list;
        (true, json!(echo))
    })
}

pub(super) fn set_categories(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // "tv, movies, sonarr". The built-ins are a floor, not a
        // starting point: a client already configured against one
        // must not stop resolving because the list was edited.
        // Each name is sanitised to the single path component it
        // becomes under the download root.
        let mut set: std::collections::BTreeSet<String> =
            DEFAULT_CATS.iter().map(|s| s.to_string()).collect();
        for raw in v.split(',') {
            let name = raw.trim();
            if name.is_empty() || name == "*" {
                continue;
            }
            let clean = nzbkit::disk::sanitize_filename(name);
            if clean.is_empty() {
                return Err(format!("{name:?} is not a usable category name"));
            }
            set.insert(clean);
        }
        *d.cats.lock_ok() = set;
        (true, json!(d.cat_list()))
    })
}
