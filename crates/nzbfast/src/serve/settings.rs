use super::*;

#[path = "settings_apply.rs"]
mod settings_apply;
use settings_apply::apply_setting_tail;

#[path = "settings_setters.rs"]
mod settings_setters;
// Globbed for the same reason as settings_index below: one of the
// validators in there is `#[cfg(feature = "indexer")]`.
use settings_setters::*;

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
/// tests/integration/settings_catalogue.rs.
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

/// Tell the editor what each rule's pattern will actually do (#18).
///
/// Both `match` and `but not` ride `nzbkit::categories::pat_match`, which
/// never fails - a pattern that will not compile and carries no wildcard
/// silently becomes a literal keyword search, and one that compiles to
/// "match anything" silently claims the whole queue. Neither is visible
/// in the rules editor, so a broken rule looks exactly like one that has
/// not fired. (A pattern that will not compile but does carry a `*` or a
/// `?` is a glob and works, so it is not marked - see `glob_match`.)
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
/// Only the did-not-compile-and-does-not-glob shape warns here,
/// deliberately. A wildcard pattern reaches `pat_compile_error` with a
/// regex complaint about it and gets None back, because failing to be a
/// regex is not a mistake when it is a working glob (TODO 104 item 2). A
/// pattern that compiles to "matches everything" is marked in the row too, but a
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

/// Everything the answer to `mode=config` has to say about a save it
/// ACCEPTED: #18's uncompilable-rule diagnostic, or TODO 60a's "you
/// turned on external unrar and there is no unrar" probe.
///
/// One hook rather than a chain at the response site, because the two
/// share a shape that will keep recurring: the save is right, the daemon
/// knows something about it the caller cannot, and the moment to say so
/// is the moment the user acted. First one to speak wins - a given name
/// is judged by exactly one of them, so the order is not a precedence
/// rule.
pub(super) fn save_warning(name: &str, v: &str) -> Option<String> {
    rules_save_warning(name, v).or_else(|| prefer_external_unrar_warning(name, v))
}

/// Readable and writable, but the value is a blob we only log the size of.
pub(super) const fn rw_opaque(name: &'static str, read: fn(&ConfigCtx) -> Value) -> Setting {
    Setting {
        name,
        expose: Expose::Config(read),
        write: Write::Setting,
        log: Log::Shape,
    }
}

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

/// Reported to the UI, but there is nothing to set.
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
    // §193 c: the listener's own address. Honoured from settings.json
    // since the `--bind` flag existed, but absent from this table - so
    // `get_config` never echoed it and no UI row could exist. Bind-time
    // like the port and the TLS pair; `pending` carries the diff.
    rw("bind", |c| json!(c.d.bind.clone())),
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
                .read_ok()
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
    // §210: the local link the hint may be naming, for the dashboard.
    ro("local_link", |c| {
        serde_json::to_value(c.d.local_link.lock_ok().clone()).unwrap_or(serde_json::Value::Null)
    }),
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
    //
    // Issue #45 gave the age knob a dashboard control and moved
    // it from days to SECONDS, so "delete 20 minutes after it finished"
    // is expressible. The old `history_keep_days` is NOT in this table:
    // echoing it would mean answering "0 days" to someone who set 20
    // minutes. It is still read out of settings.json at startup when
    // this key is absent, which is what a config written before the
    // change looks like.
    rw("history_keep_count", |c| {
        json!(c.d.history_keep_count.load(Ordering::Relaxed))
    }),
    rw("history_keep_secs", |c| {
        json!(c.d.history_keep_secs.load(Ordering::Relaxed))
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
    // Every feed url essentially always embeds the indexer's `apikey=`,
    // so what ships here is `mask_feed_url`'s version of it and never
    // the url itself (TODO §20c). The row stays editable because each
    // feed carries an `id`: a save sends the mask back, `set_feeds`
    // recognises it against that id and keeps the stored url, and a url
    // the user actually retyped cannot equal the mask, so it replaces
    // it. The url the poller fetches with never leaves the daemon.
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
                        if let Some(m) = v.as_object_mut() {
                            // The serialised FeedConfig carries the real
                            // url; it is overwritten here rather than
                            // built field by field so a field added to
                            // the struct later still reaches the UI, and
                            // a `url` that somehow did not serialise
                            // still ends up masked rather than absent.
                            m.insert("url".into(), json!(f.masked_url()));
                            if let Some(h) = health.get(&f.url) {
                                m.insert("last_poll".into(), json!(h.last_poll));
                                m.insert("last_error".into(), json!(h.last_error));
                                m.insert("items_seen".into(), json!(h.items_seen));
                            }
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
                    .lock_ok()
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
    // TODO 280: the container post.
    rw("refeed_nzb", |c| {
        json!(c.d.refeed_nzb.load(Ordering::Relaxed))
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
    // §193 d: same write-only shape as omdb_key. The value never comes
    // back out - `has_tmdb` below is all the UI learns.
    Setting {
        name: "tmdb_key",
        expose: Expose::Hidden,
        write: Write::Setting,
        log: Log::Masked,
    },
    ro("has_apikey", |c| json!(c.d.apikey.lock_ok().is_some())),
    ro("has_nzbkey", |c| json!(c.d.nzbkey.lock_ok().is_some())),
    ro("has_omdb", |c| json!(c.d.omdb_key.lock_ok().is_some())),
    ro("has_tmdb", |c| json!(c.d.tmdb_key.lock_ok().is_some())),
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
            // §210: the link verdict is scored against this number, so
            // a new line speed gets judged now rather than after the
            // next ladder (which may be a week away). The provider half
            // re-reads the last ladder results from disk, as the
            // prober does.
            if let Ok(cfg) = nzbkit::config::Config::load(&d.cfg_path) {
                super::tasks::update_tune_hint(
                    d,
                    &cfg.servers,
                    &crate::conntune::load(&d.cfg_path),
                );
            }
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
            // TODO 166: _deferred, because this caller has no way to
            // report a busy index - the switch itself has already
            // landed - and an "off" that leaves the history behind is
            // not off. A busy index latches and the searchlog tick
            // retries it on the writer.
            #[cfg(feature = "indexer")]
            if !on {
                d.clear_search_log_deferred();
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
        "history_keep_count" | "history_keep_secs" => {
            let n = v
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("{name}: a number, 0 = keep everything"))?;
            // Clamped so the age cutoff arithmetic stays in i64 and a
            // fat-fingered paste cannot become a negative cutoff that
            // matches every row. A century is past any real intent.
            let n = n.min(if name == "history_keep_count" {
                1_000_000
            } else {
                100 * 365 * 86_400
            });
            if name == "history_keep_count" {
                d.history_keep_count.store(n, Ordering::Relaxed);
            } else {
                d.history_keep_secs.store(n, Ordering::Relaxed);
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
