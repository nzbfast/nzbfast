//! The tail of `apply_setting`'s dispatch table (TODO 106).
//!
//! One `match name` arm per setting is the right shape - it is the thing the
//! settings table is checked against - but the match reached 507 lines and
//! settings.rs 3,065, over both size-gate ceilings. The table splits in two
//! at the indexer block: names the first half does not know fall through to
//! `apply_setting_tail`, whose own `_` arm is the original one, so an
//! unknown name still gets the same three-way diagnosis it always did.
//!
//! A child module of `settings`, so `super::*` names the private `set_*`
//! validators exactly as the inline arms did.

use super::*;

/// Second half of [`super::apply_setting`]'s table. Same contract:
/// `(applied_live, persist_value)`, `Err` for a name this daemon will not
/// take. Only reached from that function's `_` arm.
pub(super) fn apply_setting_tail(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    let size = || parse_size(v).ok_or_else(|| format!("{name}: bad size (e.g. 4M, 10G, 0 = off)"));
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok(match name {
        "index_groups" => set_index_groups(d, name, v)?,
        #[cfg(feature = "indexer")]
        "index_interests" => set_index_interests(d, name, v)?,
        "index_interests_applied" => {
            // Internal bookkeeping, persisted so a restart does not
            // re-apply interests over groups the user has since pruned.
            *d.index_interests_applied.lock_ok() = v.trim().to_string();
            (true, json!(v.trim()))
        }
        "index_interval_secs" => {
            let n = uint()?.max(30);
            d.index_interval_secs.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "index_scan_par" => {
            let n = uint()?.clamp(1, 8);
            d.index_scan_par.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        // What happens when the queue runs dry. Refused rather than
        // read as "off" on an unknown word: this is the control that
        // turns the machine off, and a typo that silently disarmed it
        // would be indistinguishable from one that silently armed it.
        "queue_finished_action" => {
            let a = crate::serve::finish_action::FinishAction::parse(v).ok_or_else(|| {
                format!(
                    "{name}: one of none, script, sleep, shutdown (got {:?})",
                    v.trim()
                )
            })?;
            d.finish.set_action(a);
            (true, json!(a.as_str()))
        }
        "queue_finished_script" => {
            let p = v.trim();
            d.finish
                .set_script((!p.is_empty()).then(|| PathBuf::from(p)));
            (true, json!(p))
        }
        // How long the countdown runs before a sleep or shutdown. Zero
        // is allowed and means "no warning" - the banner still appears
        // for the poll it takes to fire, and someone running headless
        // has no use for a wait nobody is there to see.
        "queue_finished_delay_secs" => {
            let n = d.finish.set_delay_secs(uint()?);
            (true, json!(n))
        }
        // §129 4a: the pre-queue hook and its own deadline (an add
        // blocks on this one, so it is NOT the post-processing hour).
        "pre_queue_script" => {
            let p = v.trim();
            *d.pre_queue_script.lock_ok() = (!p.is_empty()).then(|| PathBuf::from(p));
            (true, json!(p))
        }
        "pre_queue_timeout_secs" => {
            let n: u64 = v.trim().parse().map_err(|_| {
                "pre_queue_timeout_secs: a number of seconds, 0 = no limit".to_string()
            })?;
            d.pre_queue_timeout.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "delete_to_trash" => set_delete_to_trash(d, name, v)?,
        "cleanup_delete_mode" => set_cleanup_delete_mode(d, name, v)?,
        "watch_interval_secs" => set_watch_interval_secs(d, name, v)?,
        "index_tip_secs" => set_index_tip_secs(d, name, v)?,
        "nested_max_depth" => set_nested_max_depth(d, name, v)?,
        "oracle_sample" => {
            // M29: idle STAT budget, STATs/hour/server (0 = off).
            let n = uint()?.min(3600);
            d.oracle_sample.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "index_backfill" => {
            let n = uint()?;
            d.index_backfill.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "index_max_age_secs" => {
            let n = uint()?;
            d.index_max_age_secs.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "group_desc_isc" => {
            let on = v == "1" || v.eq_ignore_ascii_case("true");
            d.group_desc_isc.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "index_retention" => {
            let on = v == "1" || v.eq_ignore_ascii_case("true");
            d.index_retention.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "index_pause_on_download" => {
            let on = v == "1" || v.eq_ignore_ascii_case("true");
            d.index_pause_on_download.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "predb_enabled" => set_predb_enabled(d, name, v)?,
        "predb_corr_enabled" => set_predb_corr_enabled(d, name, v)?,
        "predb_corr_auto" => set_predb_corr_auto(d, name, v)?,
        #[cfg(feature = "indexer")]
        "predb_max_rows" => set_predb_max_rows(d, name, v)?,
        #[cfg(feature = "indexer")]
        "predb_seed_days" => {
            // The source's own paging depth is the real ceiling; 366 is
            // just the point past which asking is pointless.
            let n = uint()?.clamp(1, 366);
            d.predb_seed_days.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "scoreboard_enabled" => set_scoreboard_enabled(d, name, v)?,
        "scoreboard_url" => set_scoreboard_url(d, name, v)?,
        "scoreboard_source" => set_scoreboard_source(d, name, v)?,
        "corr_confirm_enabled" => set_corr_confirm_enabled(d, name, v)?,
        "corr_confirm_source" => set_corr_confirm_source(d, name, v)?,
        "scoreboard_cats" => set_scoreboard_cats(d, name, v)?,
        "scoreboard_calibrate" => {
            let on = v == "1" || v.eq_ignore_ascii_case("true");
            d.scoreboard_calibrate.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        // Same shape as omdb_key below: clearing persists NULL, so
        // save_setting REMOVES the key rather than storing "" forever.
        "scoreboard_key" => {
            let k = v.trim().to_string();
            *d.scoreboard_key.lock_ok() = (!k.is_empty()).then(|| k.clone());
            (true, if k.is_empty() { Value::Null } else { json!(k) })
        }
        "predb_server" => set_predb_server(d, name, v)?,
        "predb_channels" => set_predb_channels(d, name, v)?,
        "predb_nick" => set_predb_nick(d, name, v)?,
        "index_paused" => set_index_paused(d, name, v)?,
        #[cfg(feature = "indexer")]
        "index_enabled" => set_index_enabled(d, name, v)?,
        #[cfg(feature = "indexer")]
        "spot_enabled" => set_spot_enabled(d, name, v)?,
        "spot_groups" => set_spot_groups(d, name, v)?,
        "spot_backfill" => set_spot_backfill(d, name, v)?,
        "spot_deepen" => set_spot_deepen(d, name, v)?,
        "spot_resolve" => set_spot_resolve(d, name, v)?,
        // M34 size cap. Four settings, and only the last of them can
        // delete anything - see index_evict.
        //
        // The two that ARM the cap - the switch, and a cap set while the
        // switch is already on - wake the scan loop, because that loop
        // is what enforces it (`evict_between_passes`, once per
        // pass) and its idle sleep is 15 s only when there is nothing
        // whatsoever to scan. Spotnet went default-on in 129f293e, so a
        // groupless install now has a spot pass to do and sleeps the
        // full `index_interval_secs` - 900 s by default - which turned
        // "switch the cap on" into a quarter of an hour of apparently
        // nothing. One extra pass per user action, not the
        // four-a-minute free.pt walk the 15 s re-check was narrowed to
        // avoid. Switching OFF is not urgent: nothing awaits deletion.
        "index_max_bytes" => {
            // SAB-style sizes, same as min_free/quota: "20G", "500M",
            // bare bytes. 0 = unlimited, the default.
            let n = size()?;
            d.index_max_bytes.store(n, Ordering::Relaxed);
            if n > 0 && d.index_evict.load(Ordering::Relaxed) {
                d.scan_now.notify_one();
            }
            (true, json!(n))
        }
        #[cfg(feature = "indexer")]
        "index_evict_order" => set_index_evict_order(d, name, v)?,
        #[cfg(feature = "indexer")]
        "index_evict_kinds" => set_index_evict_kinds(d, name, v)?,
        "index_evict" => {
            let applied = set_index_evict(d, name, v)?;
            if d.index_evict.load(Ordering::Relaxed) {
                d.scan_now.notify_one();
            }
            applied
        }
        #[cfg(feature = "indexer")]
        "index_gates" => set_index_gates(d, name, v)?,
        // Clearing a key persists NULL, not "". save_setting REMOVES a
        // null key, so "cleared" means "stop overriding" - the --apikey
        // flag or the default applies again on the next launch. Storing
        // "" instead made the empty string win over an explicit --apikey
        // forever, with no way back through the API: every restart read
        // the blank back and unauthenticated the daemon.
        //
        // The deliberate consequence: while --apikey is passed you cannot
        // turn auth OFF from the dashboard - you drop the flag. That is
        // the right precedence for a credential.
        //
        // Removing the key from settings.json is only half of "keyless"
        // though: first_run_apikey ALSO reads the minted key file beside
        // the config, and reading it back is what makes a key stable
        // across restarts. So clearing here without touching that file
        // left the daemon keyless until the next restart and then keyed
        // again, with nothing on screen to explain it. Delete the file
        // too, so the user's choice actually survives.
        //
        // Deleted, not blanked: the empty-file branch in first_run_apikey
        // deliberately refuses to mint a replacement and warns loudly
        // every boot, which is the right answer to a file someone
        // truncated by hand but pure noise for a choice made in the
        // dashboard. With the file gone, the same function falls through
        // to its first-run test, sees the settings file we are about to
        // write (and the running install's spool), and leaves the daemon
        // keyless - silently, which is what was asked for.
        "apikey" => set_apikey(d, name, v)?,
        "nzbkey" => {
            let k = v.trim().to_string();
            if !super::settings::key_charset_ok(&k) {
                return Err(format!("nzbkey: {}", super::settings::KEY_CHARSET_ERR));
            }
            *d.nzbkey.lock_ok() = (!k.is_empty()).then(|| k.clone());
            (true, if k.is_empty() { Value::Null } else { json!(k) })
        }
        // Same shape as apikey/nzbkey above: clearing it persists NULL, so
        // save_setting REMOVES the key and the launch-time default applies
        // again. Storing "" made the empty string a saved OVERRIDE that won
        // on every later start, with no way back through the API.
        "omdb_key" => {
            let k = v.trim().to_string();
            *d.omdb_key.lock_ok() = (!k.is_empty()).then(|| k.clone());
            (true, if k.is_empty() { Value::Null } else { json!(k) })
        }
        "feeds" => set_feeds(d, name, v)?,
        "indexers" => set_indexers(d, name, v)?,
        "list_sources" => set_list_sources(d, name, v)?,
        "watchlist_external" => set_watchlist_external(d, name, v)?,
        "watchlist_instant" => set_watchlist_instant(d, name, v)?,
        "watchlist_instant_max" => set_watchlist_instant_max(d, name, v)?,
        "watchlist" => set_watchlist(d, name, v)?,
        "smart_folders" => set_smart_folders(d, name, v)?,
        "cleanup_exts" => {
            // M23: comma list of extensions ("par2, sfv, srr, url").
            let list = crate::smart::parse_ext_list(v);
            *d.cleanup_exts.lock_ok() = list.clone();
            (true, json!(list))
        }
        "password_file" => set_password_file(d, name, v)?,
        "password_prompt" => set_password_prompt(d, name, v)?,
        "unpack_eat_volumes" => set_unpack_eat_volumes(d, name, v)?,
        "preview" => set_preview(d, name, v)?,
        "par_cleanup" => {
            let on = flag();
            d.par_cleanup.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "watch_keep_nzb" => {
            // Live: the watch loop reads it per pickup.
            let on = flag();
            d.watch_keep_nzb.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "slow_storage_pause" => set_slow_storage_pause(d, flag()),
        "watch_recursive" => {
            // Live: read per pass; the fs watcher re-arms itself when
            // the mode it is armed with stops matching.
            let on = flag();
            d.watch_recursive.store(on, Ordering::Relaxed);
            d.watch_scan_now.notify_one();
            (true, json!(on))
        }
        "cat_meta" => {
            // §129 2b: {"tv": {"dir": "series", "priority": 1,
            // "script": "/path/x.py"}, ...}. Empty value clears.
            let map: std::collections::HashMap<String, super::daemon::CatMeta> =
                if v.trim().is_empty() {
                    Default::default()
                } else {
                    serde_json::from_str(v).map_err(|e| format!("cat_meta must be JSON: {e}"))?
                };
            for m in map.values() {
                if let Some(p) = m.priority
                    && !(-2..=2).contains(&p)
                {
                    return Err("cat_meta priority must be -2 to 2".into());
                }
            }
            *d.cat_meta.lock_ok() = map.clone();
            (true, json!(map))
        }
        "dupe_action" => {
            let m = v.trim().to_ascii_lowercase();
            if !matches!(m.as_str(), "pause" | "discard" | "fail") {
                return Err("dupe_action must be pause, discard or fail".into());
            }
            *d.dupe_action.lock_ok() = m.clone();
            (true, json!(m))
        }
        "dupe_scope" => {
            let m = v.trim().to_ascii_lowercase();
            if !matches!(m.as_str(), "smart" | "exact") {
                return Err("dupe_scope must be smart or exact".into());
            }
            *d.dupe_scope.lock_ok() = m.clone();
            (true, json!(m))
        }
        "watch_move_rejected" => {
            // Live: read at the moment a file is rejected.
            let on = flag();
            d.watch_move_rejected.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "fast_par" => set_fast_par(d, name, v)?,
        "prefer_external_unrar" => set_prefer_external_unrar(d, name, v)?,
        "custom_categories" => set_custom_categories(d, name, v)?,
        "failure_link" => set_failure_link(d, name, v)?,
        "prefer_quality" => set_prefer_quality(d, name, v)?,
        "notify_targets" => set_notify_targets(d, name, v)?,
        "arr_giveup_threshold" => set_arr_giveup_threshold(d, name, v)?,
        "arr_instances" => set_arr_instances(d, name, v)?,
        // Restart-only: bound/opened at startup. Persisted now, applied
        // on the next launch.
        "mem_limit" => {
            let b = size()?; // 0 = automatic sizing
            (false, json!(b))
        }
        "port" => set_port(d, name, v)?,
        "tls_cert" => set_tls_cert(d, name, v)?,
        "tls_key" => set_tls_key(d, name, v)?,
        "out_dir" => set_out_dir(d, name, v)?,
        "move_completed" => set_move_completed(d, name, v)?,
        // C: how file moves share the machine with downloads. One
        // setting, three modes: "yield" (pace to measured headroom,
        // full speed on an idle queue), "full" (never pace), or an
        // integer cap in MB/s.
        "move_pace" => {
            let m = v.trim().to_ascii_lowercase();
            let ok = m == "yield"
                || m == "full"
                || m.parse::<u64>().is_ok_and(|n| (1..=100_000).contains(&n));
            if !ok {
                return Err("move_pace must be yield, full, or a speed in MB/s".into());
            }
            *d.move_pace.lock_ok() = m.clone();
            (true, json!(m))
        }
        "move_completed_cats" => set_move_completed_cats(d, name, v)?,
        "categories" => set_categories(d, name, v)?,
        "index_db" => {
            let p = v.trim();
            if p.is_empty() {
                return Err("index_db can't be empty".into());
            }
            (false, json!(p))
        }
        // Three different failures used to arrive here looking identical.
        // The table tells them apart: a row that says it is read-only, a
        // row someone declared and then forgot to write an arm for (our
        // bug, and the one that used to fail silently), and a name that
        // was simply never a setting.
        _ => {
            return Err(match setting(name) {
                Some(s) if s.write != Write::Setting => format!("{name} is read-only"),
                Some(_) => format!(
                    "{name} is declared in the settings table but apply_setting has no arm \
                     for it - that is a bug, please report it"
                ),
                None => format!("unsupported config item {name}"),
            });
        }
    })
}
