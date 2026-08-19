use super::*;

#[path = "settings_apply.rs"]
mod settings_apply;
use settings_apply::apply_setting_tail;

#[path = "settings_index.rs"]
mod settings_index;
// Globbed rather than listed: six of these validators are
// `#[cfg(feature = "indexer")]`, and an explicit list would need the same
// cfg maze a second time.
use settings_index::*;

/// Everything `get_config` needs to read the live daemon, so a table row
/// can be a plain `fn` pointer instead of a closure over locals.
pub(super) struct ConfigCtx<'a> {
    pub(super) d: &'a Arc<Daemon>,
    pub(super) cfg_path: &'a std::path::Path,
}

/// How a setting's value reaches the settings UI.
pub(super) enum Expose {
    /// Read straight off the live daemon by this function, under the
    /// row's own name. This is what builds `get_config`'s block.
    Config(fn(&ConfigCtx) -> Value),
    /// In the block, but assembled by `get_config` itself out of values
    /// it has already computed (the masked server list, the
    /// restart-pending diff). Declared here only so the drift check
    /// still sees it.
    Assembled,
    /// Writable but never echoed back: credentials (the UI learns only
    /// that one is stored, via a `has_*` row) and the SAB-compatible
    /// one-shot actions, which have no stored value to show.
    Hidden,
}

/// What the `[config]` line may print as this setting's new value.
pub(super) enum Log {
    /// A switch, a number, a path, a plain word or a list of them:
    /// nothing that can carry a credential, so print it verbatim.
    Plain,
    /// A credential. Never printed.
    Masked,
    /// Structured and credential-bearing: a notify target's `url` IS its
    /// bearer token for Discord/ntfy/Gotify, so kinds and counts only.
    Targets,
    /// A feed url essentially always embeds the indexer's `apikey=`, so
    /// the log gets the count and nothing else.
    Feeds,
    /// M35 indexer entries carry a per-site `apikey` field: count only.
    Indexers,
    /// §151 list sources carry a watchlist RSS url (itself a bearer
    /// capability) and a Plex account token: count only. `Feeds` would
    /// print the wrong noun and `Plain` would print the credential.
    Lists,
    /// Everything else: how big it was, and nothing about what was in
    /// it. The default, so the next credential-bearing setting someone
    /// adds cannot silently reopen the log.
    Shape,
}

/// One row per setting the config API knows about.
///
/// THIS IS THE LIST. It used to be three of them kept in step by hand -
/// a logging allowlist, the `apply_setting` match, and one enormous
/// `json!` literal in `get_config` - and a setting left out of any one
/// failed silently: no error, the setting simply did nothing.
/// `get_config`'s settings block is now BUILT from this table so a row
/// cannot go missing from it, `log_value` takes its rule from here, and
/// `apply_setting`'s fallthrough can tell a declared row with no writer
/// apart from a name nobody ever declared. The one edge left - the match
/// itself, which cannot be generated without rewriting a hundred
/// hand-written validators - is held to the table by
/// `apply_arms_match_the_table`.
///
/// One surface stays outside the table on purpose: `apply_saved_settings`
/// maps saved JSON onto launch options BEFORE a Daemon exists, so it can
/// share no shape with rows that read live daemon state. That leg is
/// pinned behaviourally instead, by `settings_survive_a_restart` in
/// tests/settings_catalogue.rs.
///
/// The rows carry the API's persisted key names verbatim. Renaming one
/// is a settings.json migration, not an edit here.
pub(super) struct Setting {
    pub(super) name: &'static str,
    pub(super) expose: Expose,
    pub(super) write: Write,
    pub(super) log: Log,
}

/// What `mode=config&name=<row>` does with this row.
#[derive(PartialEq)]
pub(super) enum Write {
    /// `apply_setting` has an arm for it, which validates the value,
    /// applies it live where it can, and returns what to persist.
    /// `apply_arms_match_the_table` holds this to the source.
    Setting,
    /// Accepted by `mode=config`, but intercepted before `apply_setting`
    /// ever sees it: an action, not a stored value.
    Action,
    /// Reported to the UI; there is nothing to set.
    No,
}

/// Shorthand for the common shape: live-readable, writable, safe to log.
pub(super) const fn rw(name: &'static str, read: fn(&ConfigCtx) -> Value) -> Setting {
    Setting {
        name,
        expose: Expose::Config(read),
        write: Write::Setting,
        log: Log::Plain,
    }
}

/// Readable and writable, but the value is a blob we only log the size of.
/// Tell the editor what each rule's pattern will actually do (#18).
///
/// Both `match` and `but not` ride `nzbkit::categories::pat_match`, which
/// never fails - a pattern that will not compile silently becomes a
/// literal keyword search, and one that compiles to "match anything"
/// silently claims the whole queue. Neither is visible in the rules
/// editor, so a broken rule looks exactly like one that has not fired.
///
/// Computed on the READ path and attached here rather than stored on
/// `Rule` / `CustomCategory`: those two structs are the persisted shape in
/// settings.json, and a field that only ever describes the value would be
/// written back into the file. The editors rebuild their payload from the
/// row inputs and send only the keys they own (saveSmart / saveCats in
/// dashboard.html), so these never echo back - the same read-only-sibling
/// contract `feed_health` uses.
///
/// `PatternVerdict::Ok` is left off entirely: an absent key is the normal
/// case, and shipping `"ok"` on every rule of every install would be pure
/// payload for the reading that means "nothing to say".
fn annotate_patterns(v: Value) -> Value {
    use nzbkit::categories::{PatternVerdict, pat_verdict};
    let Value::Array(rules) = v else { return v };
    Value::Array(
        rules
            .into_iter()
            .map(|mut rule| {
                for (field, out) in [("match", "match_verdict"), ("not_match", "not_verdict")] {
                    let pat = rule.get(field).and_then(Value::as_str).unwrap_or("");
                    let verdict = pat_verdict(pat);
                    if verdict != PatternVerdict::Ok
                        && let Some(obj) = rule.as_object_mut()
                    {
                        obj.insert(out.into(), json!(verdict));
                    }
                }
                rule
            })
            .collect(),
    )
}

/// The save-time half of the #18 diagnostic: a warning for the answer to
/// `mode=config`, when the rules just saved contain a pattern that will
/// not compile.
///
/// `annotate_patterns` above marks the row - but only on the next READ of
/// the settings, and only for eyes that are on that card. The moment the
/// user actually acts is Apply, and the answer to Apply said only
/// "status: true", which is true (the save is accepted, the fallback to a
/// keyword search is documented behaviour) and still the wrong moment to
/// stay quiet: a rule that quietly does nothing looks exactly like a rule
/// that has not fired yet. So the answer carries the rule's name and the
/// engine's own compile error, and the dashboard toasts it.
///
/// Only the did-not-compile shape warns here, deliberately. A pattern
/// that compiles to "matches everything" is marked in the row too, but a
/// catch-all as the LAST rule ("everything else goes to misc") is a
/// legitimate configuration, and a toast that nagged on every re-save of
/// a deliberate setup would teach people to ignore it. A compile failure
/// is never deliberate.
///
/// A warning, not an Err: refusing the save would change semantics the
/// issue explicitly asks to keep (plain keywords are documented to work,
/// and they arrive down this same code path as uncompilable patterns).
pub(super) fn rules_save_warning(name: &str, v: &str) -> Option<String> {
    use nzbkit::categories::pat_compile_error;
    if !matches!(name, "smart_folders" | "custom_categories") {
        return None;
    }
    let rules: Vec<Value> = serde_json::from_str(v.trim()).ok()?;
    let mut parts: Vec<String> = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let label = rule
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| format!("\"{s}\""))
            .unwrap_or_else(|| format!("rule {}", i + 1));
        for (field, what) in [("match", "pattern"), ("not_match", "\"but not\" pattern")] {
            let pat = rule.get(field).and_then(Value::as_str).unwrap_or("");
            if let Some(err) = pat_compile_error(pat) {
                parts.push(format!(
                    "{label}: {what} \"{pat}\" does not compile ({err}), so it is \
                     searched for as plain text and will almost never match"
                ));
            }
        }
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

pub(super) const fn rw_opaque(name: &'static str, read: fn(&ConfigCtx) -> Value) -> Setting {
    Setting {
        name,
        expose: Expose::Config(read),
        write: Write::Setting,
        log: Log::Shape,
    }
}

/// Reported to the UI, but there is nothing to set.
/// A row `get_config` builds itself and nothing may write: the server
/// list, the two first-run signals, the pending-restart diff.
pub(super) const fn assembled(name: &'static str) -> Setting {
    Setting {
        name,
        expose: Expose::Assembled,
        write: Write::No,
        log: Log::Plain,
    }
}

pub(super) const fn ro(name: &'static str, read: fn(&ConfigCtx) -> Value) -> Setting {
    Setting {
        name,
        expose: Expose::Config(read),
        write: Write::No,
        log: Log::Plain,
    }
}

/// Paths and the control port.
pub(super) const PATHS: &[Setting] = &[
    rw("port", |c| json!(c.d.port)),
    // §129 2a: opt-in native HTTPS. Bind-time values like the port -
    // the write arms validate the files NOW (so a typo fails the save,
    // not the next restart), persist, and `pending` carries the diff.
    rw("tls_cert", |c| json!(path_str(&c.d.tls_cert))),
    rw("tls_key", |c| json!(path_str(&c.d.tls_key))),
    // §141 (issue #33): which browser origins may read the SAB API.
    // Lives beside the port and the TLS pair because it is a property of
    // the listening surface, not of a download.
    rw("cors_origin", |c| json!(c.d.cors_origin.lock_ok().clone())),
    rw("out_dir", |c| json!(c.d.out_dir().to_string_lossy())),
    rw("move_pace", |c| json!(c.d.move_pace.lock_ok().clone())),
    rw("move_completed", |c| {
        json!(
            c.d.move_completed
                .read()
                .unwrap()
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default()
        )
    }),
    rw("move_completed_cats", |c| {
        json!(fmt_cat_dests(&c.d.move_completed_cats.read_ok()))
    }),
    rw("categories", |c| json!(c.d.cat_list())),
    rw("watch", |c| json!(path_str(&c.d.watch_dir.lock_ok()))),
    rw("watch_interval_secs", |c| {
        json!(c.d.watch_interval_secs.load(Ordering::Relaxed))
    }),
    rw("dupe_action", |c| json!(c.d.dupe_action.lock_ok().clone())),
    rw("dupe_scope", |c| json!(c.d.dupe_scope.lock_ok().clone())),
    rw("cat_meta", |c| json!(c.d.cat_meta.lock_ok().clone())),
    rw("watch_recursive", |c| {
        json!(c.d.watch_recursive.load(Ordering::Relaxed))
    }),
    rw("watch_move_rejected", |c| {
        json!(c.d.watch_move_rejected.load(Ordering::Relaxed))
    }),
    rw(
        "delete_to_trash",
        |_| json!(crate::smart::delete_to_trash()),
    ),
    rw("cleanup_delete_mode", |_| {
        json!(crate::smart::cleanup_mode().as_str())
    }),
    rw("script", |c| {
        json!(nzbget_script::chain_str(&c.d.scripts.lock_ok()))
    }),
    rw("script_timeout_secs", |c| {
        json!(c.d.script_timeout.load(Ordering::Relaxed))
    }),
    rw("pre_queue_script", |c| {
        json!(path_str(&c.d.pre_queue_script.lock_ok()))
    }),
    rw("pre_queue_timeout_secs", |c| {
        json!(c.d.pre_queue_timeout.load(Ordering::Relaxed))
    }),
    #[cfg(feature = "indexer")]
    rw("index_db", |c| json!(c.d.index_db.to_string_lossy())),
    ro("config_path", |c| json!(c.cfg_path.to_string_lossy())),
    ro("settings_path", |c| {
        json!(c.d.settings_path.to_string_lossy())
    }),
];

/// The download engine.
pub(super) const DOWNLOAD: &[Setting] = &[
    rw("connections", |c| {
        json!(c.d.connections.load(Ordering::Relaxed))
    }),
    rw("window", |c| json!(c.d.window.load(Ordering::Relaxed))),
    rw("decoders", |c| json!(c.d.decoders.load(Ordering::Relaxed))),
    rw("fast_verify", |c| {
        json!(c.d.fast_verify.load(Ordering::Relaxed))
    }),
    rw("verify_mode", |c| {
        json!(match (
            c.d.fast_verify.load(Ordering::Relaxed),
            c.d.verify_lean.load(Ordering::Relaxed),
        ) {
            (false, _) => "full",
            (true, false) => "fast",
            (true, true) => "lean",
        })
    }),
    rw("min_free", |c| json!(c.d.min_free.load(Ordering::Relaxed))),
    // #20. Echoed as the octal STRING it was typed as, empty when off,
    // so the field shows back what the guides print rather than a
    // decimal nobody recognises.
    rw("out_umask", |c| {
        let m = c.d.out_umask.load(Ordering::Relaxed);
        json!(if m <= 0o777 {
            format!("{m:03o}")
        } else {
            String::new()
        })
    }),
    rw("auto_retry_mins", |c| {
        json!(c.d.auto_retry_secs.load(Ordering::Relaxed) / 60)
    }),
    rw("server_outage_mins", |c| {
        json!(c.d.server_outage_mins.load(Ordering::Relaxed))
    }),
    rw("quota", |c| json!(c.d.quota.load(Ordering::Relaxed))),
    rw("quota_period", |c| {
        json!((c.d.quota_period.load(Ordering::Relaxed) as char).to_string())
    }),
    rw("nested_max_depth", |_| {
        json!(nzbkit::extract::nested_depth_cap())
    }),
    // The saved override (0/absent = auto); the resolved budget is
    // mem_budget_total.
    rw("mem_limit", |c| {
        json!(
            load_settings(&c.d.settings_path)
                .get("mem_limit")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        )
    }),
    ro("mem_budget_total", |c| json!(c.d.mem_budget_total)),
];

/// Speed, scheduling and the auto-tuners.
pub(super) const SPEED: &[Setting] = &[
    rw("speedlimit", |c| {
        json!(c.d.speed_ceiling.load(Ordering::Relaxed))
    }),
    rw("line_speed", |c| {
        json!(c.d.line_speed.load(Ordering::Relaxed))
    }),
    rw("auto_speed", |c| {
        json!(c.d.auto_speed.load(Ordering::Relaxed))
    }),
    rw("auto_defer", |c| {
        json!(c.d.auto_defer.load(Ordering::Relaxed))
    }),
    rw("post_health", |c| {
        json!(c.d.post_health.load(Ordering::Relaxed))
    }),
    rw("post_health_defer", |c| {
        json!(c.d.post_health_defer.load(Ordering::Relaxed))
    }),
    rw("post_health_fail", |c| {
        json!(c.d.post_health_fail.load(Ordering::Relaxed))
    }),
    rw("wall_hide_adult", |c| {
        json!(c.d.wall_hide_adult.load(Ordering::Relaxed))
    }),
    rw("auto_connections", |c| {
        json!(c.d.auto_connections.load(Ordering::Relaxed))
    }),
    rw("live_tune", |c| {
        json!(c.d.live_tune.load(Ordering::Relaxed))
    }),
    ro("conntune", |c| {
        serde_json::to_value(crate::conntune::load(c.cfg_path)).unwrap_or_else(|_| json!({}))
    }),
    // The tuner's line-speed verdict (empty = fine or unjudged) -
    // written by the probe loop, shown near the line-speed setting.
    ro("tune_hint", |c| json!(c.d.tune_hint.lock_ok().clone())),
    rw("auto_prefetch", |c| {
        json!(c.d.auto_prefetch.load(Ordering::Relaxed))
    }),
    rw("race_stragglers", |c| {
        json!(c.d.race_stragglers.load(Ordering::Relaxed))
    }),
    rw("adaptive_timeouts", |c| {
        json!(c.d.adaptive_timeouts.load(Ordering::Relaxed))
    }),
    rw("oracle_route", |c| {
        json!(c.d.oracle_route.load(Ordering::Relaxed))
    }),
    rw("oracle_sample", |c| {
        json!(c.d.oracle_sample.load(Ordering::Relaxed))
    }),
    rw("bench_interval", |c| {
        json!(c.d.bench_interval.load(Ordering::Relaxed))
    }),
    // Free-form text; only its size reaches the log.
    rw_opaque("schedule", |c| json!(c.d.schedule_text.lock_ok().clone())),
];

/// Auto-rename, and how a finished download is labelled.
pub(super) const RENAME: &[Setting] = &[
    rw("auto_rename", |c| {
        json!(c.d.auto_rename.load(Ordering::Relaxed))
    }),
    rw("identity_lookup", |c| {
        json!(c.d.identity_lookup.load(Ordering::Relaxed))
    }),
    rw("rename_resolution", |c| {
        json!(c.d.rename_resolution.load(Ordering::Relaxed))
    }),
    rw("rename_vcodec", |c| {
        json!(c.d.rename_vcodec.load(Ordering::Relaxed))
    }),
    rw("rename_acodec", |c| {
        json!(c.d.rename_acodec.load(Ordering::Relaxed))
    }),
    rw("rename_source", |c| {
        json!(c.d.rename_source.load(Ordering::Relaxed))
    }),
    rw("rename_group", |c| {
        json!(c.d.rename_group.load(Ordering::Relaxed))
    }),
    rw("rename_year_parens", |c| {
        json!(c.d.rename_year_parens.load(Ordering::Relaxed))
    }),
    rw("rename_quality_brackets", |c| {
        json!(c.d.rename_quality_brackets.load(Ordering::Relaxed))
    }),
    rw("rename_extra_words", |c| {
        json!(c.d.rename_extra_words.load(Ordering::Relaxed))
    }),
    rw("rename_identify", |c| {
        json!(c.d.rename_identify.load(Ordering::Relaxed))
    }),
    rw("rename_episode_titles", |c| {
        json!(c.d.rename_episode_titles.load(Ordering::Relaxed))
    }),
    rw("rename_junk", |c| {
        json!(c.d.rename_junk.load(Ordering::Relaxed))
    }),
    rw("rename_media_only", |c| {
        json!(c.d.rename_media_only.load(Ordering::Relaxed))
    }),
    rw("skip_samples", |c| {
        json!(c.d.skip_samples.load(Ordering::Relaxed))
    }),
    rw("rename_from_nzb", |c| {
        json!(c.d.rename_from_nzb.load(Ordering::Relaxed))
    }),
    rw("history_rows", |c| {
        json!(c.d.history_rows.load(Ordering::Relaxed))
    }),
    // §129 D5: optional retention, BOTH default 0 = keep everything
    // (history is unlimited by ruling; the knobs exist for whoever
    // disagrees, and they ship OFF).
    rw("history_keep_count", |c| {
        json!(c.d.history_keep_count.load(Ordering::Relaxed))
    }),
    rw("history_keep_days", |c| {
        json!(c.d.history_keep_days.load(Ordering::Relaxed))
    }),
    rw("history_color_names", |c| {
        json!(c.d.history_color_names.load(Ordering::Relaxed))
    }),
    rw("media_chip_color", |c| {
        json!(c.d.media_chip_color.load(Ordering::Relaxed))
    }),
    rw("shape_chip_color", |c| {
        json!(c.d.shape_chip_color.load(Ordering::Relaxed))
    }),
];

/// The indexer and the library scanner.
pub(super) const INDEXING: &[Setting] = &[
    // The master switch. Everything else in this table is inert while it
    // is off, and the UI hides the lot - so it is read first by both.
    #[cfg(feature = "indexer")]
    rw("index_enabled", |c| {
        json!(c.d.index_enabled.load(Ordering::Relaxed))
    }),
    // Spotnet: its own switch, not a sub-option of the one above.
    #[cfg(feature = "indexer")]
    rw("spot_enabled", |c| {
        json!(c.d.spot_enabled.load(Ordering::Relaxed))
    }),
    rw("spot_groups", |c| json!(c.d.spot_groups.lock_ok().clone())),
    rw("spot_backfill", |c| {
        json!(c.d.spot_backfill.load(Ordering::Relaxed))
    }),
    // TODO 131 item 7 (Spotnet as catalogue breadth): how much of the
    // feed's HISTORY each pass reads below the low-water mark, and how
    // many of those spots the resolver turns into wall cards.
    rw("spot_deepen", |c| {
        json!(c.d.spot_deepen.load(Ordering::Relaxed))
    }),
    rw("spot_resolve", |c| {
        json!(c.d.spot_resolve.load(Ordering::Relaxed))
    }),
    rw("library_cats", |c| {
        json!(c.d.library_cats.lock_ok().clone())
    }),
    rw("library_recheck_secs", |c| {
        json!(c.d.library_recheck_secs.load(Ordering::Relaxed))
    }),
    rw("index_groups", |c| {
        json!(c.d.index_groups.lock_ok().clone())
    }),
    #[cfg(feature = "indexer")]
    rw("index_interests", |c| {
        json!(c.d.index_interests.lock_ok().clone())
    }),
    // Written by the setup wizard to record that the interests it
    // collected have been turned into groups. No UI field reads it back.
    Setting {
        name: "index_interests_applied",
        expose: Expose::Hidden,
        write: Write::Setting,
        log: Log::Plain,
    },
    rw("index_interval_secs", |c| {
        json!(c.d.index_interval_secs.load(Ordering::Relaxed))
    }),
    rw("index_scan_par", |c| {
        json!(c.d.index_scan_par.load(Ordering::Relaxed))
    }),
    rw("index_tip_secs", |c| {
        json!(c.d.index_tip_secs.load(Ordering::Relaxed))
    }),
    rw("index_backfill", |c| {
        json!(c.d.index_backfill.load(Ordering::Relaxed))
    }),
    rw("index_deepen", |c| {
        json!(c.d.index_deepen.load(Ordering::Relaxed))
    }),
    rw("index_coverage", |c| {
        json!(c.d.index_coverage.load(Ordering::Relaxed))
    }),
    rw("index_gapfill", |c| {
        json!(c.d.index_gapfill.load(Ordering::Relaxed))
    }),
    // TODO 131 B3: the byte-probe naming lane's kill switch and its
    // article budget (per hour, 0 = off).
    rw("index_probe7z", |c| {
        json!(c.d.index_probe7z.load(Ordering::Relaxed))
    }),
    rw("index_probe7z_budget", |c| {
        json!(c.d.index_probe7z_budget.load(Ordering::Relaxed))
    }),
    // TODO 131 red-team 5a: the pesto tiny-PAR2 naming rung's kill
    // switch and its article budget (per hour, 0 = off).
    rw("index_pesto", |c| {
        json!(c.d.index_pesto.load(Ordering::Relaxed))
    }),
    rw("index_pesto_budget", |c| {
        json!(c.d.index_pesto_budget.load(Ordering::Relaxed))
    }),
    // §131 #6: the posted-NZB ingestion rung's kill switch and its
    // article budget (per hour, 0 = off).
    rw("index_nzbimport", |c| {
        json!(c.d.index_nzbimport.load(Ordering::Relaxed))
    }),
    rw("index_nzbimport_budget", |c| {
        json!(c.d.index_nzbimport_budget.load(Ordering::Relaxed))
    }),
    // §131 D3: record what this index was asked for and how much of
    // it we answered, so the misses can say what to backfill. Local
    // data that never leaves the box; switching it off also clears
    // what was recorded.
    rw("index_search_log", |c| {
        json!(c.d.index_search_log.load(Ordering::Relaxed))
    }),
    rw("group_desc_isc", |c| {
        json!(c.d.group_desc_isc.load(Ordering::Relaxed))
    }),
    rw("index_max_age_secs", |c| {
        json!(c.d.index_max_age_secs.load(Ordering::Relaxed))
    }),
    rw("index_retention", |c| {
        json!(c.d.index_retention.load(Ordering::Relaxed))
    }),
    rw("index_pause_on_download", |c| {
        json!(c.d.index_pause_on_download.load(Ordering::Relaxed))
    }),
    rw("index_paused", |c| {
        json!(c.d.index_paused.load(Ordering::Relaxed))
    }),
    // M34 size cap. Bytes, not a SAB-style string: the UI formats, the
    // API parses.
    rw("index_max_bytes", |c| {
        json!(c.d.index_max_bytes.load(Ordering::Relaxed))
    }),
    rw("index_evict", |c| {
        json!(c.d.index_evict.load(Ordering::Relaxed))
    }),
    #[cfg(feature = "indexer")]
    rw("index_evict_order", |c| {
        json!(c.d.index_evict_order.lock_ok().clone())
    }),
    #[cfg(feature = "indexer")]
    rw("index_evict_kinds", |c| {
        json!(c.d.index_evict_kinds.lock_ok().clone())
    }),
    #[cfg(feature = "indexer")]
    rw("index_gates", |c| {
        json!(c.d.index_gates.lock_ok().0.clone())
    }),
    // Pre feed. Off by default; the other three are inert while it is.
    rw("predb_enabled", |c| {
        json!(c.d.predb_enabled.load(Ordering::Relaxed))
    }),
    rw("predb_server", |c| {
        json!(c.d.predb_server.lock_ok().clone())
    }),
    rw("predb_channels", |c| {
        json!(c.d.predb_channels.lock_ok().clone())
    }),
    rw("predb_nick", |c| json!(c.d.predb_nick.lock_ok().clone())),
    // Phase 2 correlation - two separate switches on purpose. Hearing
    // pre lines (above) is harmless; INFERRING names from timing+size
    // is a policy, and applying one without a click is a second policy.
    rw("predb_corr_enabled", |c| {
        json!(c.d.predb_corr_enabled.load(Ordering::Relaxed))
    }),
    rw("predb_corr_auto", |c| {
        json!(c.d.predb_corr_auto.load(Ordering::Relaxed))
    }),
    // Capacity, not policy: how many pre rows to keep, and how far back
    // a seed import reaches when it is not told.
    #[cfg(feature = "indexer")]
    rw("predb_max_rows", |c| {
        json!(c.d.predb_max_rows.load(Ordering::Relaxed))
    }),
    #[cfg(feature = "indexer")]
    rw("predb_seed_days", |c| {
        json!(c.d.predb_seed_days.load(Ordering::Relaxed))
    }),
    // Parity scoreboard. Off by default and inert without a reference
    // URL; the API key is a credential and lives in KEYS below.
    rw("scoreboard_enabled", |c| {
        json!(c.d.scoreboard_enabled.load(Ordering::Relaxed))
    }),
    rw("scoreboard_url", |c| {
        json!(c.d.scoreboard_url.lock_ok().clone())
    }),
    // Which of the user's indexer accounts is the reference; empty =
    // the manual URL+key pair. A NAME, never a credential - the url
    // and key are resolved from the `indexers` entry at run time.
    rw("scoreboard_source", |c| {
        json!(c.d.scoreboard_source.lock_ok().clone())
    }),
    // Which categories the daily sample asks for - one request each, so
    // this is what the card's requests-per-day figure is counting.
    // Empty = all four, the most it ever asks for; the list can only
    // take categories away.
    rw("scoreboard_cats", |c| {
        json!(c.d.scoreboard_cats.lock_ok().clone())
    }),
    // Indexer-confirm lane. Off by default; spends a small daily
    // budget of the named indexer account's quota turning STRONG
    // correlation suggestions into proven msgid-set names.
    rw("corr_confirm_enabled", |c| {
        json!(c.d.corr_confirm_enabled.load(Ordering::Relaxed))
    }),
    // A NAME from the user's indexer accounts, resolved at run time
    // like scoreboard_source; empty = the lane is inert.
    rw("corr_confirm_source", |c| {
        json!(c.d.corr_confirm_source.lock_ok().clone())
    }),
    rw("scoreboard_calibrate", |c| {
        json!(c.d.scoreboard_calibrate.load(Ordering::Relaxed))
    }),
];

/// Automation: what gets grabbed, sorted and announced.
pub(super) const AUTOMATION: &[Setting] = &[
    rw("prefer_quality", |c| c.d.quality_prefs.lock_ok().to_json()),
    // Every feed url essentially always embeds the indexer's `apikey=`.
    //
    // §G: each entry also carries what its last poll did (last_poll,
    // last_error, items_seen). Merged in here rather than shipped as a
    // second keyed list on purpose - a separate block would have to
    // repeat the feed url to say which feed it described, and that url
    // is the credential. These are read-only additions: `saveFeeds`
    // rebuilds the list from the row inputs, so nothing echoes back, and
    // the persisted settings.json shape is unchanged (the writer
    // serialises FeedConfig, which has no idea these exist).
    Setting {
        name: "feeds",
        expose: Expose::Config(|c| {
            let feeds = c.d.feeds.lock_ok().clone();
            let health = c.d.feed_health.lock_ok();
            Value::Array(
                feeds
                    .iter()
                    .map(|f| {
                        let mut v = serde_json::to_value(f).unwrap_or_else(|_| json!({}));
                        if let (Some(m), Some(h)) = (v.as_object_mut(), health.get(&f.url)) {
                            m.insert("last_poll".into(), json!(h.last_poll));
                            m.insert("last_error".into(), json!(h.last_error));
                            m.insert("items_seen".into(), json!(h.items_seen));
                        }
                        v
                    })
                    .collect(),
            )
        }),
        write: Write::Setting,
        log: Log::Feeds,
    },
    // M35 pull-search indexers. The apikey never round-trips: the UI
    // learns `has_key`, and the writer merges a blank key back onto the
    // stored one (the server-password convention), so an edit in the
    // dashboard cannot leak or erase a key.
    Setting {
        name: "indexers",
        expose: Expose::Config(|c| {
            Value::Array(
                c.d.indexers
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|i| {
                        json!({
                            "name": i.name,
                            "url": i.url,
                            "enabled": i.enabled,
                            "priority": i.priority,
                            "hits_per_day": i.hits_per_day,
                            "grabs_per_day": i.grabs_per_day,
                            "has_key": !i.apikey.is_empty(),
                        })
                    })
                    .collect(),
            )
        }),
        write: Write::Setting,
        log: Log::Indexers,
    },
    // §151 external list sources. The user's OWN watchlist rows only -
    // `watchlist` is what the dashboard editor round-trips, and the
    // synced rows must not enter that array (see Daemon::watch_items).
    rw_opaque("watchlist", |c| {
        serde_json::to_value(&*c.d.watchlist.lock_ok()).unwrap_or(json!([]))
    }),
    // §151. Neither credential is ever echoed: the UI learns `has_url` /
    // `has_token`, and the writer merges a blank one back onto the
    // stored one (the server-password convention), so an edit in the
    // dashboard cannot leak or erase either. What each source's last
    // sync did is merged in here rather than shipped as a second keyed
    // list, exactly as `feeds` does and for the same reason - the key
    // that would say which source a health block described is the
    // source's own address.
    Setting {
        name: "list_sources",
        expose: Expose::Config(|c| list_sources_config(c.d)),
        write: Write::Setting,
        log: Log::Lists,
    },
    // The EFFECTIVE answer, not the raw bool: the dashboard checkbox has
    // to show what the watcher will actually do, and while the user has
    // not answered that is derived from whether any indexer exists.
    rw("watchlist_external", |c| json!(c.d.watchlist_external_on())),
    rw("watchlist_instant", |c| {
        json!(c.d.watchlist_instant.load(Ordering::Relaxed))
    }),
    rw("watchlist_instant_max", |c| {
        json!(c.d.watchlist_instant_max.load(Ordering::Relaxed))
    }),
    rw_opaque("smart_folders", |c| {
        annotate_patterns(serde_json::to_value(&*c.d.smart_folders.lock_ok()).unwrap_or(json!([])))
    }),
    rw("custom_categories", |c| {
        annotate_patterns(
            serde_json::to_value(&*c.d.custom_categories.read_ok()).unwrap_or(json!([])),
        )
    }),
    rw("cleanup_exts", |c| {
        json!(c.d.cleanup_exts.lock_ok().clone())
    }),
    // SAB/NZBGet-parity passwords file. Only the PATH and a count reach
    // the UI - the contents are credentials, edited in the file itself
    // (the has_password/notify-token contract).
    rw("password_file", |c| {
        json!(c.d.password_file.lock_ok().to_string_lossy())
    }),
    ro("password_file_count", |c| {
        json!(c.d.read_unpack_passwords().len())
    }),
    rw("password_prompt", |c| {
        json!(c.d.password_prompt.lock_ok().clone())
    }),
    rw("unpack_eat_volumes", |c| {
        json!(c.d.unpack_eat_volumes.lock_ok().clone())
    }),
    // §73 phase 2: off | metadata-only | full.
    rw("preview", |c| json!(preview_mode(c.d))),
    rw("par_cleanup", |c| {
        json!(c.d.par_cleanup.load(Ordering::Relaxed))
    }),
    rw("watch_keep_nzb", |c| {
        json!(c.d.watch_keep_nzb.load(Ordering::Relaxed))
    }),
    // §129 3e. Only the switch: the judge's thresholds live in
    // settings.json under `slow_storage`.
    rw("slow_storage_pause", |c| json!(c.d.slow_storage.enabled())),
    rw("fast_par", |c| json!(c.d.fast_par.load(Ordering::Relaxed))),
    rw("prefer_external_unrar", |c| {
        json!(c.d.prefer_external_unrar.load(Ordering::Relaxed))
    }),
    // Never the token itself: it is the Plex token / Jellyfin API key /
    // Kodi `user:password`, and get_config is a read anyone with the key
    // can make from a browser. Same contract as has_password/has_apikey -
    // the UI learns only that one is stored. The config writer merges a
    // blank token back onto the saved one, so a round-trip through the
    // dashboard cannot erase it. A target's `url` IS its bearer token for
    // Discord/ntfy/Gotify, so the log gets kinds and counts only.
    //
    // §G: `last_send` is what this target's last delivery did. The
    // OUTCOME travels; the key it is stored under (which embeds the url)
    // never does - the row is matched by position in this list, which is
    // the same list the UI renders from.
    Setting {
        name: "notify_targets",
        expose: Expose::Config(|c| {
            let targets = c.d.notify_targets.lock_ok().clone();
            let health = c.d.notify_health.lock_ok();
            Value::Array(
                targets
                    .iter()
                    .map(|t| {
                        json!({
                            "name": t.name,
                            "kind": t.kind,
                            "url": t.url,
                            "body": t.body,
                            "enabled": t.enabled,
                            "on_failure": t.on_failure,
                            "category": t.category,
                            "events": t.events,
                            "email_to": t.email_to,
                            "email_from": t.email_from,
                            "has_token": !t.token.is_empty(),
                            "has_secret": !t.secret.is_empty(),
                            "last_send": health.get(&crate::notify::target_key(t)),
                        })
                    })
                    .collect(),
            )
        }),
        write: Write::Setting,
        log: Log::Targets,
    },
    rw("failure_link", |c| {
        json!(c.d.failure_link.lock_ok().clone())
    }),
    // §96.3 give-up breaker: distinct failed releases per target before
    // it is unmonitored. 0 = off, the default.
    rw("arr_giveup_threshold", |c| {
        json!(c.d.arr_giveup_threshold.load(Ordering::Relaxed))
    }),
    // The *arr instances the breaker may act on. The apikey is a
    // credential: only `has_key` crosses back to the UI, and the writer
    // merges a blank key onto the stored one - the notify_targets
    // contract.
    Setting {
        name: "arr_instances",
        expose: Expose::Config(|c| {
            Value::Array(
                c.d.arr_instances
                    .lock_ok()
                    .iter()
                    .map(|i| {
                        json!({
                            "name": i.name,
                            "kind": i.kind,
                            "url": i.url,
                            "enabled": i.enabled,
                            "has_key": !i.apikey.is_empty(),
                        })
                    })
                    .collect(),
            )
        }),
        write: Write::Setting,
        log: Log::Targets,
    },
    // What happens when the queue runs dry: none | script | sleep |
    // shutdown. The three rows are one control: the action, the script
    // it names, and how long the countdown runs before the two that end
    // the session. See serve/finish_action.rs for why sleep and shutdown
    // disarm themselves after firing and `script` does not.
    rw("queue_finished_action", |c| {
        json!(c.d.finish.action().as_str())
    }),
    rw("queue_finished_script", |c| {
        json!(path_str(&c.d.finish.script()))
    }),
    rw("queue_finished_delay_secs", |c| {
        json!(c.d.finish.delay_secs())
    }),
];

/// The dashboard itself, and update checking.
pub(super) const INTERFACE: &[Setting] = &[
    rw("update_checks", |c| {
        json!(c.d.update_checks.load(Ordering::Relaxed))
    }),
    rw("unit_bits", |c| {
        json!(c.d.unit_bits.load(Ordering::Relaxed))
    }),
    rw("update_url", |c| json!(c.d.update_url.lock_ok().clone())),
    rw("ui_locale", |c| json!(c.d.ui_locale.lock_ok().clone())),
];

/// Credentials. Set-only: the UI is told a key EXISTS, never what it is.
pub(super) const KEYS: &[Setting] = &[
    Setting {
        name: "apikey",
        expose: Expose::Hidden,
        write: Write::Setting,
        log: Log::Masked,
    },
    Setting {
        name: "nzbkey",
        expose: Expose::Hidden,
        write: Write::Setting,
        log: Log::Masked,
    },
    Setting {
        name: "omdb_key",
        expose: Expose::Hidden,
        write: Write::Setting,
        log: Log::Masked,
    },
    Setting {
        name: "scoreboard_key",
        expose: Expose::Hidden,
        write: Write::Setting,
        log: Log::Masked,
    },
    ro("has_apikey", |c| json!(c.d.apikey.lock_ok().is_some())),
    ro("has_nzbkey", |c| json!(c.d.nzbkey.lock_ok().is_some())),
    ro("has_omdb", |c| json!(c.d.omdb_key.lock_ok().is_some())),
    ro("has_scoreboard_key", |c| {
        json!(c.d.scoreboard_key.lock_ok().is_some())
    }),
];

/// Rows `get_config` fills in itself, plus the SAB-compatible actions
/// that go through `mode=config` without being settings at all.
pub(super) const RUNTIME: &[Setting] = &[
    // The usenet servers, secrets masked - built alongside the two
    // first-run signals: whether any server exists yet, and (§129 4c)
    // whether anything has ever been downloaded. The second is derived
    // from the queue, the history AND the usage store, which is why it
    // is assembled here rather than read off any one of them.
    assembled("servers"),
    assembled("servers_configured"),
    assembled("jobs_ever"),
    // Saved-but-not-yet-applied values for the restart-only settings.
    assembled("pending"),
    // SAB parity: `config&name=set_pause&value=<minutes>`. Handled
    // before apply_setting ever sees it, and stores nothing.
    Setting {
        name: "set_pause",
        expose: Expose::Hidden,
        write: Write::Action,
        log: Log::Plain,
    },
    // The countdown banner's Cancel button. An action, not a value: it
    // stops a sleep or shutdown that has been announced and switches the
    // arm off (see `finish_action::cancel` for why it does both).
    Setting {
        name: "queue_finished_cancel",
        expose: Expose::Hidden,
        write: Write::Action,
        log: Log::Plain,
    },
];

/// The table, in the order the settings UI lays the cards out.
pub(super) const SETTING_GROUPS: &[&[Setting]] = &[
    PATHS, DOWNLOAD, SPEED, RENAME, INDEXING, AUTOMATION, INTERFACE, KEYS, RUNTIME,
];

pub(super) fn settings() -> impl Iterator<Item = &'static Setting> {
    SETTING_GROUPS.iter().copied().flatten()
}

pub(super) fn setting(name: &str) -> Option<&'static Setting> {
    settings().find(|s| s.name == name)
}

/// What the `[config]` line may print as a setting's new value.
///
/// stdout is not private here: logtee mirrors it into the dashboard log
/// ring (`mode=log`, and the JSON-RPC `log`/`loadlog` methods) - the pane
/// users screenshot into support threads - as well as journald and
/// `docker logs`. Several settings carry credentials inside an otherwise
/// innocuous-looking value: a notify target's `url` IS its bearer token
/// for Discord/ntfy/Gotify, its `token` is a Plex token or a Kodi
/// `user:password`, and a feed url essentially always embeds the
/// indexer's `apikey=`. `notify.rs` already holds the line that a webhook
/// url must never reach the log; this keeps the config write to the same
/// rule.
///
/// Default-deny by design: the rule comes from the setting's row in
/// [`SETTING_GROUPS`], and a name with no row at all gets a shape
/// summary, not its value - so the next credential-bearing setting
/// someone adds cannot silently reopen this.
pub(super) fn log_value(name: &str, v: &str) -> String {
    match setting(name).map(|s| &s.log) {
        Some(Log::Plain) => v.to_string(),
        // Straight credentials.
        Some(Log::Masked) => "•••".to_string(),
        // Structured, credential-bearing: kinds and counts only, no urls.
        Some(Log::Targets) => match serde_json::from_str::<Vec<Value>>(v) {
            Ok(ts) => {
                let mut kinds: Vec<&str> = ts
                    .iter()
                    .map(|t| t.get("kind").and_then(Value::as_str).unwrap_or("?"))
                    .collect();
                kinds.sort_unstable();
                kinds.dedup();
                if kinds.is_empty() {
                    format!("{} targets", ts.len())
                } else {
                    format!("{} targets ({})", ts.len(), kinds.join(", "))
                }
            }
            Err(_) => shape_only(v),
        },
        Some(Log::Feeds) => match serde_json::from_str::<Vec<Value>>(v) {
            Ok(f) => format!("{} feeds", f.len()),
            Err(_) => shape_only(v),
        },
        Some(Log::Indexers) => match serde_json::from_str::<Vec<Value>>(v) {
            Ok(f) => format!("{} indexers", f.len()),
            Err(_) => shape_only(v),
        },
        Some(Log::Lists) => match serde_json::from_str::<Vec<Value>>(v) {
            Ok(f) => format!("{} list sources", f.len()),
            Err(_) => shape_only(v),
        },
        Some(Log::Shape) | None => shape_only(v),
    }
}

/// An optional path setting as the UI wants it: the path, or "" for unset.
pub(super) fn path_str(p: &Option<PathBuf>) -> String {
    p.as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The settings block `get_config` hands the UI, built by walking the
/// table rather than by one enormous `json!` literal. Every
/// [`Expose::Config`] row contributes its live value under its own name;
/// the [`Expose::Assembled`] rows are filled in by the caller, which has
/// already computed them.
pub(super) fn config_block(ctx: &ConfigCtx) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    for s in settings() {
        if let Expose::Config(read) = s.expose {
            map.insert(s.name.to_string(), read(ctx));
        }
    }
    map
}

/// How big it was, and nothing about what was in it.
pub(super) fn shape_only(v: &str) -> String {
    if v.is_empty() {
        "(empty)".to_string()
    } else {
        format!("({} chars, not logged)", v.chars().count())
    }
}

fn set_speedlimit(
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

fn set_auto_speed(
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

fn set_update_url(
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

fn set_ui_locale(
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
fn set_cors_origin(
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

fn set_index_gapfill(
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

fn set_index_probe7z_budget(
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

fn set_index_pesto_budget(
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

fn set_index_nzbimport_budget(
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

fn set_bench_interval(
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

fn set_auto_prefetch(
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

fn set_race_stragglers(
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

fn set_history_rows(
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

fn set_connections(
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

fn set_fast_verify(
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

fn set_verify_mode(
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

fn set_out_umask(
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

fn set_auto_retry_mins(
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

fn set_quota_period(
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

fn set_watch(d: &Arc<Daemon>, _name: &str, v: &str) -> std::result::Result<(bool, Value), String> {
    Ok({
        let p = v.trim();
        if !p.is_empty() {
            let _ = std::fs::create_dir_all(p);
        }
        *d.watch_dir.lock_ok() = (!p.is_empty()).then(|| PathBuf::from(p));
        (true, json!(p))
    })
}

fn set_schedule(
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

fn set_library_cats(
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

fn set_index_groups(
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
fn set_index_interests(
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

fn set_delete_to_trash(
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

fn set_cleanup_delete_mode(
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

fn set_watch_interval_secs(
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

fn set_index_tip_secs(
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

fn set_nested_max_depth(
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

/// The charset a stored key may use: letters, digits, `-` and `_`.
/// The `/watch` handler already drops anything outside this set before
/// echoing a key into a header, and characters like `&`, `+`, `%` or
/// `#` sent raw change the parsed query of every generated link - so a
/// key holding them authenticates direct calls but breaks the URLs the
/// daemon writes. Refuse at creation instead of failing later.
pub(super) fn key_charset_ok(k: &str) -> bool {
    k.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

pub(super) const KEY_CHARSET_ERR: &str =
    "keys may use letters, digits, '-' and '_' only - other characters break generated links";

fn set_apikey(d: &Arc<Daemon>, _name: &str, v: &str) -> std::result::Result<(bool, Value), String> {
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

fn set_feeds(d: &Arc<Daemon>, _name: &str, v: &str) -> std::result::Result<(bool, Value), String> {
    Ok({
        // JSON array of {url, interval_secs, category, rules}; the
        // poller picks the new list up on its next 30 s pass.
        let text = v.trim();
        let list: Vec<crate::rss::FeedConfig> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("feeds: {e}"))?
        };
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.feeds.lock_ok() = list;
        (true, persist)
    })
}

fn set_indexers(
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
        }
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.indexers.lock_ok() = list;
        (true, persist)
    })
}

fn set_watchlist_external(
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

fn set_watchlist_instant(
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

fn set_watchlist_instant_max(
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

fn set_watchlist(
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

fn set_smart_folders(
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

fn set_password_file(
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
fn set_slow_storage_pause(d: &Arc<Daemon>, on: bool) -> (bool, Value) {
    d.slow_storage.set_enabled(on);
    (true, json!(on))
}

fn set_password_prompt(
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

fn set_preview(
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

fn set_unpack_eat_volumes(
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

fn set_fast_par(
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

fn set_prefer_external_unrar(
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

fn set_custom_categories(
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

fn set_failure_link(
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

fn set_prefer_quality(
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

fn set_notify_targets(
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

fn set_arr_giveup_threshold(
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

fn set_arr_instances(
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

fn set_port(d: &Arc<Daemon>, name: &str, v: &str) -> std::result::Result<(bool, Value), String> {
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

/// §129 2a: the TLS pair is validated at SAVE time - a path typo or a
/// non-PEM file fails the Apply with the reason, instead of surfacing as
/// a refused restart later with nobody watching the log. Empty clears
/// the half (both empty = plain HTTP). Applies at the next restart, like
/// the port; take_listener re-validates at bind with the same wording.
fn set_tls_cert(
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

fn set_tls_key(
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

fn set_out_dir(
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

fn set_move_completed(
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

fn set_move_completed_cats(
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

fn set_categories(
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

/// Apply one settings-UI change to the running daemon. Returns
/// `(applied_live, persist_value)` - `persist_value` is what lands in
/// settings.json under `name`. `applied_live = false` marks the few
/// settings that only take effect on the next launch.
pub(super) fn apply_setting(
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
        "speedlimit" => set_speedlimit(d, name, v)?,
        "line_speed" => {
            let b = size()?;
            d.line_speed.store(b, Ordering::Relaxed);
            // A different declaration gets its own chance: evidence the
            // learner gathered against the OLD line speed must not
            // instantly invalidate the new one (linkpeak.rs).
            d.link_peak.line_changed();
            (true, json!(b))
        }
        "auto_speed" => set_auto_speed(d, name, v)?,
        "auto_defer" => {
            let on = flag();
            d.auto_defer.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "post_health" => {
            let on = flag();
            d.post_health.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "post_health_defer" => {
            let on = flag();
            d.post_health_defer.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "post_health_fail" => {
            let on = flag();
            d.post_health_fail.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "wall_hide_adult" => {
            let on = flag();
            d.wall_hide_adult.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "auto_connections" => {
            let on = flag();
            d.auto_connections.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "live_tune" => {
            let on = flag();
            d.live_tune.store(on, Ordering::Relaxed);
            // The pool build reads the hub's mirror; keep them one value.
            d.hub.live_tune.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "update_checks" => {
            let on = flag();
            d.update_checks.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "unit_bits" => {
            let on = flag();
            d.unit_bits.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "update_url" => set_update_url(d, name, v)?,
        "ui_locale" => set_ui_locale(d, name, v)?,
        "cors_origin" => set_cors_origin(d, name, v)?,
        "index_deepen" => {
            // Articles of history added per scan pass; 0 = off.
            let n = uint()?;
            d.index_deepen.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "index_coverage" => {
            // A8: scan the other backbones' tips too (their own marks).
            d.index_coverage.store(flag(), Ordering::Relaxed);
            (true, json!(d.index_coverage.load(Ordering::Relaxed)))
        }
        "index_gapfill" => set_index_gapfill(d, name, v)?,
        "index_probe7z" => {
            // TODO 131 B3: the byte-probe naming lane's kill switch.
            d.index_probe7z.store(flag(), Ordering::Relaxed);
            (true, json!(d.index_probe7z.load(Ordering::Relaxed)))
        }
        "index_probe7z_budget" => set_index_probe7z_budget(d, name, v)?,
        "index_pesto" => {
            // TODO 131 red-team 5a: the pesto rung's kill switch.
            d.index_pesto.store(flag(), Ordering::Relaxed);
            (true, json!(d.index_pesto.load(Ordering::Relaxed)))
        }
        "index_pesto_budget" => set_index_pesto_budget(d, name, v)?,
        "index_nzbimport" => {
            // §131 #6: the posted-NZB ingestion rung's kill switch.
            d.index_nzbimport.store(flag(), Ordering::Relaxed);
            (true, json!(d.index_nzbimport.load(Ordering::Relaxed)))
        }
        "index_nzbimport_budget" => set_index_nzbimport_budget(d, name, v)?,
        "index_search_log" => {
            // §131 D3 search-miss logging. Turning it OFF also clears
            // the table: a privacy switch that leaves the history
            // behind is not one, and this is the user's own search
            // history on the user's own box.
            let on = flag();
            d.index_search_log.store(on, Ordering::Relaxed);
            #[cfg(feature = "indexer")]
            if !on {
                d.clear_search_log();
            }
            (true, json!(d.index_search_log.load(Ordering::Relaxed)))
        }
        "bench_interval" => set_bench_interval(d, name, v)?,
        "auto_prefetch" => set_auto_prefetch(d, name, v)?,
        "race_stragglers" => set_race_stragglers(d, name, v)?,
        "adaptive_timeouts" => {
            // Same per-job read as race_stragglers: applies from the
            // NEXT download; the atomic is the live mirror.
            let on = flag();
            d.adaptive_timeouts.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "oracle_route" => {
            // Applies from the NEXT download (the snapshot is installed at
            // job launch).
            d.oracle_route.store(flag(), Ordering::Relaxed);
            (true, json!(d.oracle_route.load(Ordering::Relaxed)))
        }
        "auto_rename" => {
            let on = flag();
            d.auto_rename.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "identity_lookup" => {
            let on = flag();
            d.identity_lookup.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_resolution" => {
            let on = flag();
            d.rename_resolution.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_vcodec" => {
            let on = flag();
            d.rename_vcodec.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_acodec" => {
            let on = flag();
            d.rename_acodec.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_source" => {
            let on = flag();
            d.rename_source.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_group" => {
            let on = flag();
            d.rename_group.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_year_parens" => {
            let on = flag();
            d.rename_year_parens.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_quality_brackets" => {
            let on = flag();
            d.rename_quality_brackets.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_extra_words" => {
            let on = flag();
            d.rename_extra_words.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_identify" => {
            let on = flag();
            d.rename_identify.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_episode_titles" => {
            let on = flag();
            d.rename_episode_titles.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "script_timeout_secs" => {
            let n: u64 = v.trim().parse().map_err(|_| {
                "script_timeout_secs: a number of seconds, 0 = no limit".to_string()
            })?;
            d.script_timeout.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "history_rows" => set_history_rows(d, name, v)?,
        "history_keep_count" | "history_keep_days" => {
            let n = v
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("{name}: a number, 0 = keep everything"))?;
            if name == "history_keep_count" {
                d.history_keep_count.store(n, Ordering::Relaxed);
            } else {
                d.history_keep_days.store(n, Ordering::Relaxed);
            }
            // Applies now, not at the next park - setting a cap on a
            // grown history is exactly when the user wants it enforced.
            d.history_enforce_retention();
            (true, json!(n))
        }
        "history_color_names" => {
            let on = flag();
            d.history_color_names.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "media_chip_color" => {
            let on = flag();
            d.media_chip_color.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "shape_chip_color" => {
            let on = flag();
            d.shape_chip_color.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_junk" => {
            let on = flag();
            d.rename_junk.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_media_only" => {
            let on = flag();
            d.rename_media_only.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "skip_samples" => {
            let on = flag();
            d.skip_samples.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_from_nzb" => {
            let on = flag();
            d.rename_from_nzb.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "connections" => set_connections(d, name, v)?,
        "window" => {
            let n = uint()?.clamp(1, 64) as usize;
            d.window.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "decoders" => {
            let n = uint()?.clamp(1, 128) as usize;
            d.decoders.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "fast_verify" => set_fast_verify(d, name, v)?,
        // M32 verify_mode = full | fast | lean. Lean is the slow-CPU
        // boost: like fast, but per-article yEnc CRCs are also skipped
        // once PAR2 covers a file, so in-stream corruption detection
        // rests on the PAR2 block CRC32 alone (one CRC32 layer instead
        // of two - a corrupt article is caught slightly later, at its
        // block, and with single-CRC32 confidence). End-of-job
        // verification and repair are unchanged; PAR2-less downloads
        // keep article CRCs automatically. Applies from the NEXT job.
        "verify_mode" => set_verify_mode(d, name, v)?,
        "out_umask" => set_out_umask(d, name, v)?,
        "min_free" => {
            let b = size()?;
            d.min_free.store(b, Ordering::Relaxed);
            (true, json!(b))
        }
        "auto_retry_mins" => set_auto_retry_mins(d, name, v)?,
        "server_outage_mins" => {
            let m = v
                .trim()
                .parse::<u64>()
                .map_err(|_| "server_outage_mins must be a number")?;
            d.server_outage_mins.store(m, Ordering::Relaxed);
            (true, json!(m))
        }
        "quota" => {
            let b = size()?;
            d.quota.store(b, Ordering::Relaxed);
            (true, json!(b))
        }
        "quota_period" => set_quota_period(d, name, v)?,
        "watch" => set_watch(d, name, v)?,
        "script" => {
            // §192: a comma- (or semicolon-) separated ORDERED chain,
            // not one path. Stored parsed, read back joined by commas,
            // so what the settings row shows is what the daemon will
            // run and in what order.
            let chain = nzbget_script::script_chain(v);
            let out = nzbget_script::chain_str(&chain);
            *d.scripts.lock_ok() = chain;
            (true, json!(out))
        }
        "schedule" => set_schedule(d, name, v)?,
        "library_cats" => set_library_cats(d, name, v)?,
        "library_recheck_secs" => {
            let n = uint()?.max(60);
            d.library_recheck_secs.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        // The rest of the table is in settings_apply.rs - this match was
        // 507 lines, past the size gate's function ceiling.
        _ => apply_setting_tail(d, name, v)?,
    })
}

/// [`apply_setting`] and its persistence as ONE transaction.
///
/// An API key lives in three places - the live mutex, the sibling `apikey`
/// file, and `settings.json` - and `apply_setting` writes the first two while
/// the CALLER writes the third. Two authenticated clients rotating the key at
/// once could therefore interleave as
///
/// ```text
/// A: live/keyfile = A ; B: live/keyfile = B ; B: settings = B ; A: settings = A
/// ```
///
/// with both answering success. The live key is B, `settings.json` says A, and
/// settings wins at load - so the key the user just pasted into Sonarr stops
/// working at the next restart, with nothing in the logs. Credential changes
/// take the transaction lock so the three stores can never disagree; every
/// other setting is a single value and needs no ordering.
pub(super) fn apply_and_save(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, bool), String> {
    static CREDENTIAL_TX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _tx = matches!(name, "apikey" | "nzbkey")
        // A poisoned lock here would mean a panic mid-rotation; the data it
        // guards is the ordering, not an invariant a panic can corrupt.
        .then(|| CREDENTIAL_TX.lock_ok());
    let (live, persist) = apply_setting(d, name, v)?;
    // Same rule as `save_queue` and `persist_pause`: the dashboard's
    // revisioned poll only resends the queue payload when this handle
    // moves, and several settings ARE that payload - speedlimit_abs,
    // auto_speed, limit_source, quota, password_prompt,
    // unpack_eat_volumes. Without a bump the page keeps the object it
    // last applied, so on an idle daemon the header limit dropdown
    // snapped back to its old value a second after it was changed, the
    // way the Offline button did.
    //
    // Deliberately blunt - every setting, not the payload-borne few. A
    // list here would be a second copy of `queue_json`'s field set, and
    // the two would drift the moment either is edited; the cost of being
    // wrong in this direction is one extra queue payload on a poll that
    // was going to answer anyway.
    d.queue_rev.fetch_add(1, Ordering::Relaxed);
    // The write result is the only signal that the change is DURABLE, and
    // it used to be dropped: on a full disk or a read-only settings dir
    // the live key became B and B was returned as a success while
    // settings.json and the key file still held A, so the next restart
    // silently reverted and the client's stored key stopped working.
    //
    // Reported, deliberately NOT raised as an Err. `apply_setting` has
    // already moved the live value (and, for apikey, the key file), so a
    // caller that reads this as outright failure would keep using the OLD
    // key against a daemon that no longer accepts it - worse than the bug.
    // The honest answer is "it worked, but it is not durable".
    let saved = save_settings(&d.settings_path, &[(name, persist)]);
    if !saved {
        warn!(
            target: "settings",
            "⚠ {name} is live now but could not be written to {} - it reverts to \
             the stored value on the next start",
            d.settings_path.display()
        );
    }
    Ok((live, saved))
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod settings_tests;
