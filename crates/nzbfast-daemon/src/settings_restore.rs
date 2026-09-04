//! Reading the saved settings back onto a Daemon: the two restore
//! halves and the per-setting seeders they and `build_daemon` share.
//!
//! Split out of `startup` under the size gate (TODO 106). One currency:
//! a settings.json blob on disk and the Daemon fields it has to become.
//! `restore_job_settings` covers how a job is fetched, unpacked and
//! reported; `restore_ui_and_index_settings` covers the UI and indexer
//! side; the ~45 `seed_*` readers below them are the per-field halves
//! that `build_daemon` also calls, because a field the constructor
//! needs cannot wait for a restore pass that runs after it.
//!
//! What stays in `startup` is everything AROUND this: the orchestrating
//! `restore_runtime_state`, the listener and its bind grace, TLS, the
//! single-instance lock, the task spawns, the ready banner and
//! `build_daemon` itself. The startup CALL ORDER is load-bearing and
//! nothing here reorders it - this is the same code, only moved.
//!
//! A SIBLING of `startup` rather than a child, which is what keeps the
//! move honest: `pub(super)` on ~45 seeders means "visible in `serve`",
//! which is what `serve/mod.rs`'s `use startup::*` and `testutil`'s
//! `seed_tmdb_key` call have always relied on. As a child it would mean
//! "visible in `startup`" and every one of them would have had to be
//! respelled `pub(crate)`. Two items changed visibility here
//! instead of forty-eight.

use super::*;

/// The saved settings that govern how a job is fetched, unpacked and
/// reported: post-processing and unpack, the passwords file, the watch
/// folder, categories, the indexer's interests, notifications and the
/// *arr give-up breaker.
///
/// Split out of `restore_runtime_state` (TODO 106) with
/// [`restore_ui_and_index_settings`], at the one boundary the block
/// offered - the on-disk notices, which are files rather than settings.
/// The reads are in their original order and stayed together: two of
/// them WRITE a migrated value back through `settings_path`, so this
/// half owns it.
pub fn restore_job_settings(
    daemon: &Arc<Daemon>,
    saved: &serde_json::Map<String, Value>,
    settings_path: &Path,
) {
    if let Some(v) = saved.get("smart_folders") {
        match serde_json::from_value::<Vec<crate::smart::Rule>>(v.clone()) {
            Ok(list) => *daemon.smart_folders.lock_ok() = list,
            Err(e) => warn!(target: "smart", "ignoring saved smart_folders: {e}"),
        }
    }
    // Queue-finished action. Restored, unlike most one-shot state,
    // because "shut down when this batch finishes" is routinely armed
    // for an overnight run that a daemon restart (an update, a reboot of
    // the NAS) sits in the middle of - and the two that end the session
    // disarm THEMSELVES on firing, so what is on disk is only ever an
    // arm nobody has spent yet. An unrecognised word is dropped rather
    // than guessed at: this is the control that turns the machine off.
    if let Some(v) = saved.get("queue_finished_action").and_then(Value::as_str) {
        match finish_action::FinishAction::parse(v) {
            Some(a) => daemon.finish.set_action(a),
            None => warn!(target: "finish", "ignoring saved queue_finished_action {v:?}"),
        }
    }
    if let Some(v) = saved.get("queue_finished_script").and_then(Value::as_str) {
        daemon
            .finish
            .set_script((!v.trim().is_empty()).then(|| PathBuf::from(v.trim())));
    }
    if let Some(v) = saved
        .get("queue_finished_delay_secs")
        .and_then(Value::as_u64)
    {
        daemon.finish.set_delay_secs(v);
    }
    if let Some(v) = saved.get("cleanup_exts") {
        match serde_json::from_value::<Vec<String>>(v.clone()) {
            Ok(list) => *daemon.cleanup_exts.lock_ok() = list,
            Err(e) => warn!(target: "cleanup", "ignoring saved cleanup_exts: {e}"),
        }
    }
    // SAB/NZBGet-parity passwords file. A saved path (adopted from a
    // competitor import, or user-set) wins; empty/absent = the
    // default next to the config.
    if let Some(p) = saved
        .get("password_file")
        .and_then(Value::as_str)
        .filter(|p| !p.trim().is_empty())
    {
        *daemon.password_file.lock_ok() = PathBuf::from(p.trim());
    }
    // One-shot migration: the short-lived `unpack_passwords` LIST
    // setting (shipped and replaced the same day) seeds the file,
    // but never overwrites one that already has content - the file
    // is the operator's now.
    if let Some(list) = saved
        .get("unpack_passwords")
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .filter(|l| !l.is_empty())
    {
        let path = daemon.password_file.lock_ok().clone();
        if !path.exists() {
            let body = list.join("\n") + "\n";
            if let Err(e) = crate::persist::write_atomic(&path, body.as_bytes()) {
                warn!(target: "unlock", "could not migrate unpack_passwords to {}: {e}", path.display());
            } else {
                info!(target: "unlock", "moved {} saved password(s) into {}", list.len(), path.display());
            }
        }
    }
    // Make sure the file exists so "where do passwords go" has one
    // answer: the path the settings page shows. 0600 like every
    // credential-bearing file (write_atomic's mode).
    {
        let path = daemon.password_file.lock_ok().clone();
        if !path.exists()
            && let Err(e) = crate::persist::write_atomic(&path, b"")
        {
            warn!(target: "unlock", "could not create {}: {e}", path.display());
        }
        // Mirror for the in-stream probe (it holds a hub, not the
        // daemon), and for the on-disk extraction ladder (which holds
        // neither - see `smart::set_operator_password_file`).
        *daemon.hub.unpack_password_file.lock_ok() = Some(path.clone());
        crate::pwfile::set_operator_password_file(Some(path));
    }
    if let Some(m) = saved.get("password_prompt").and_then(Value::as_str)
        && matches!(m, "now" | "done" | "never")
    {
        *daemon.password_prompt.lock_ok() = m.to_string();
    }
    // §73 phase 2. An unrecognised value is ignored rather than
    // rejected: the field is read through `preview_mode`, which falls
    // back to the default, and a settings.json a human edited badly
    // should not turn a feature off silently.
    if let Some(m) = saved.get("preview").and_then(Value::as_str)
        && PREVIEW_MODES.contains(&m)
    {
        *daemon.preview.lock_ok() = m.to_string();
    }
    // TODO 101: the mode is read by the unpack ladder through
    // `eatvol`, so mirror it whether it was saved or defaulted -
    // same shape as fast_par below. Nothing is ever eaten under the
    // "off" default, so a mirror of the default is a no-op that
    // keeps the two stores from drifting.
    if let Some(m) = saved
        .get("unpack_eat_volumes")
        .and_then(Value::as_str)
        .and_then(crate::eatvol::EatMode::parse)
    {
        *daemon.unpack_eat_volumes.lock_ok() = m.as_str().to_string();
    }
    crate::eatvol::set_mode(
        crate::eatvol::EatMode::parse(&daemon.unpack_eat_volumes.lock_ok().clone())
            .unwrap_or_default(),
    );
    if let Some(on) = saved.get("par_cleanup").and_then(Value::as_bool) {
        daemon.par_cleanup.store(on, Ordering::Relaxed);
    }
    // §129 lane width. settings.json only for now (no UI row until
    // testers ask - a setting is three places). Clamped again at the
    // read, so a hand-edited 0 or 99 cannot widen the lane.
    if let Some(n) = saved.get("postproc_jobs").and_then(Value::as_u64) {
        daemon.postproc_jobs.store(n.clamp(1, 4), Ordering::Relaxed);
    }
    // TODO 313: the queue spill, same settings.json-only shape and for
    // the same reason - a setting is three places, and this one is off
    // until it has been measured on a real link. There is no second
    // knob for how many phases may run at once: `spill::MAX_DOWNLOAD_
    // PHASES` is a structural bound of this daemon's two wire slots,
    // not a preference, and a number a user could type past it would be
    // a lie.
    if let Some(on) = saved.get("queue_spill").and_then(Value::as_bool) {
        daemon.queue_spill.store(on, Ordering::Relaxed);
    }
    // §129 3e. The switch is a real setting (UI + get_config); the
    // detector's thresholds are settings.json only, under
    // `slow_storage`, and every one of them is clamped on read - a
    // hand-edited file must not be able to make this a hair trigger.
    if let Some(on) = saved.get("slow_storage_pause").and_then(Value::as_bool) {
        daemon.slow_storage.set_enabled(on);
    }
    if let Some(v) = saved.get("slow_storage") {
        daemon
            .slow_storage
            .set_tune(crate::slowstore::Tune::from_settings(v));
    }
    if let Some(on) = saved.get("watch_keep_nzb").and_then(Value::as_bool) {
        daemon.watch_keep_nzb.store(on, Ordering::Relaxed);
    }
    if let Some(on) = saved.get("refeed_nzb").and_then(Value::as_bool) {
        daemon.refeed_nzb.store(on, Ordering::Relaxed);
    }
    if let Some(on) = saved.get("watch_recursive").and_then(Value::as_bool) {
        daemon.watch_recursive.store(on, Ordering::Relaxed);
    }
    if let Some(on) = saved.get("watch_move_rejected").and_then(Value::as_bool) {
        daemon.watch_move_rejected.store(on, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("cat_meta") {
        match serde_json::from_value::<std::collections::HashMap<String, crate::daemon::CatMeta>>(
            v.clone(),
        ) {
            Ok(m) => *daemon.cat_meta.lock_ok() = m,
            Err(e) => warn!(target: "config", "ignoring saved cat_meta: {e}"),
        }
    }
    if let Some(m) = saved.get("dupe_action").and_then(Value::as_str)
        && matches!(m, "pause" | "discard" | "fail")
    {
        *daemon.dupe_action.lock_ok() = m.to_string();
    }
    if let Some(m) = saved.get("dupe_scope").and_then(Value::as_str)
        && matches!(m, "smart" | "exact")
    {
        *daemon.dupe_scope.lock_ok() = m.to_string();
    }
    if let Some(on) = saved.get("fast_par").and_then(Value::as_bool) {
        daemon.fast_par.store(on, Ordering::Relaxed);
    }
    // Mirror into the repair library whether saved or defaulted
    // (NZBFAST_NTT in the environment still overrides it there).
    nzbkit::par2repair::set_fast_par_enabled(daemon.fast_par.load(Ordering::Relaxed));
    if let Some(on) = saved.get("prefer_external_unrar").and_then(Value::as_bool) {
        daemon.prefer_external_unrar.store(on, Ordering::Relaxed);
    }
    // Same shape as fast_par: mirrored whether saved or defaulted
    // (NZBFAST_NO_NATIVE_UNRAR in the environment still forces it on
    // inside nzbkit).
    nzbkit::extract::set_prefer_external_unrar(
        daemon.prefer_external_unrar.load(Ordering::Relaxed),
    );
    // TODO 24D user categories: validated on save, but re-validated
    // here so a hand-edited settings.json can't smuggle a reserved
    // or duplicate slug into the classifier.
    if let Some(v) = saved.get("custom_categories") {
        match serde_json::from_value::<Vec<nzbkit::categories::CustomCategory>>(v.clone()) {
            Ok(mut list) => {
                // A slug that only became reserved in a LATER release
                // must not cost the user every OTHER category they set
                // up: validation rejects the list as a whole, and the
                // Err arm below discards all of it.
                let renamed = nzbkit::categories::migrate_reserved_slugs(&mut list);
                for (from, to) in &renamed {
                    info!(
                        target: "cats",
                        "category slug {from:?} is now a built-in kind - renamed \
                         to {to:?} so your other categories still load"
                    );
                }
                if !renamed.is_empty() {
                    save_settings(settings_path, &[("custom_categories", json!(&list))]);
                }
                match nzbkit::categories::validate(&list) {
                    Ok(()) => *daemon.custom_categories.write_ok() = list,
                    Err(e) => warn!(target: "cats", "ignoring saved custom_categories: {e}"),
                }
            }
            Err(e) => warn!(target: "cats", "ignoring saved custom_categories: {e}"),
        }
    }
    // What the user asked the indexer to look for, and how much of
    // that has already been turned into scanned groups. Both are
    // read here rather than applied: applying needs the provider's
    // group list, which the startup path below fetches.
    if let Some(v) = saved.get("index_interests").and_then(Value::as_str) {
        *daemon.index_interests.lock_ok() = crate::interests::parse(v).join(",");
    }
    if let Some(v) = saved.get("index_interests_applied").and_then(Value::as_str) {
        *daemon.index_interests_applied.lock_ok() = v.to_string();
    }
    match saved.get("index_interest_groups") {
        Some(v) => {
            if let Ok(groups) = serde_json::from_value::<Vec<String>>(v.clone()) {
                *daemon.index_interest_groups.lock_ok() = groups;
            }
        }
        // No provenance recorded: this install predates the key. Without
        // a backfill, `owned` stays empty forever, `reconcile` finds
        // nothing removable, and unticking a preset silently removes
        // NOTHING. It does not self-heal either - re-ticking skips a
        // group that is already present, so it never enters next_owned
        // and the next untick fails the same way. The only escape was
        // hand-editing index_groups.
        //
        // Reconstruct it the only honest way available: the groups the
        // applied presets resolve to, intersected with what is actually
        // being indexed. A group the user added by hand is therefore
        // never claimed as preset-owned, which is the direction that
        // errs toward keeping their groups rather than deleting them.
        None => {
            let applied = daemon.index_interests_applied.lock_ok().clone();
            let keys = crate::interests::parse(&applied);
            if !keys.is_empty() {
                let have = daemon.index_groups.lock_ok().clone();
                let owned = crate::interests::backfill_owned(&keys, &have);
                if !owned.is_empty() {
                    info!(
                        target: "interests",
                        "recorded {} preset-owned group(s) for an install \
                         that predates provenance tracking",
                        owned.len()
                    );
                    save_settings(settings_path, &[("index_interest_groups", json!(&owned))]);
                    *daemon.index_interest_groups.lock_ok() = owned;
                }
            }
        }
    }
    if let Some(v) = saved.get("failure_link").and_then(Value::as_str)
        && matches!(v, "off" | "report" | "regrab")
    {
        *daemon.failure_link.lock_ok() = v.to_string();
    }
    if let Some(v) = saved.get("notify_targets") {
        match serde_json::from_value::<Vec<crate::notify::Target>>(v.clone()) {
            Ok(list) => *daemon.notify_targets.lock_ok() = list,
            Err(e) => warn!(target: "notify", "ignoring saved notify_targets: {e}"),
        }
    }
    // §96.3 give-up breaker: the threshold, the *arr instances it may
    // act on, and the counters a previous run accumulated.
    if let Some(n) = saved.get("arr_giveup_threshold").and_then(Value::as_u64) {
        daemon.arr_giveup_threshold.store(n, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("arr_instances") {
        match serde_json::from_value::<Vec<giveup::ArrInstance>>(v.clone()) {
            Ok(list) => *daemon.arr_instances.lock_ok() = list,
            Err(e) => warn!(target: "giveup", "ignoring saved arr_instances: {e}"),
        }
    }
    let giveup_path = daemon.spool.join("giveup-state.json");
    if let Some(v) = crate::persist::load_json_with_backup(&giveup_path) {
        match serde_json::from_value(v) {
            Ok(s) => *daemon.giveup.lock_ok() = s,
            Err(e) => warn!(target: "giveup", "ignoring {}: {e}", giveup_path.display()),
        }
    }
    // The kept-files notices outlive the process on purpose: each one
    // names a folder whose history row is gone, so losing them at a
    // restart leaves the payload on disk with nothing anywhere
    // pointing at it. See `Daemon::save_delete_kept`.
    let kept_path = daemon.spool.join("delete-kept.json");
    if let Some(v) = crate::persist::load_json_with_backup(&kept_path) {
        // Either shape: the file written before the notice grew its
        // retry offer is an array of 4-arrays, and it names folders
        // still sitting on the user's disk. See `kept_notes_from_json`.
        match kept_notes_from_json(&v) {
            Some(k) => *daemon.delete_kept.lock_ok() = k,
            None => warn!(target: "queue", "ignoring {}", kept_path.display()),
        }
    }
    // And the deletes themselves, for the same reason one step earlier:
    // the advice for a refused delete is to try again in a few minutes,
    // and a restart is what people do in between. See
    // `Daemon::note_releases_deleted`.
    let marks_path = daemon.spool.join("deleted-recent.json");
    if let Some(v) = crate::persist::load_json_with_backup(&marks_path) {
        match serde_json::from_value(v) {
            Ok(m) => *daemon.deleted_recent.lock_ok() = m,
            Err(e) => warn!(target: "queue", "ignoring {}: {e}", marks_path.display()),
        }
    }
}

/// The rest of the saved settings: presentation, the auto-tuning and
/// health switches, the update ratchet, the move/completed paths, the
/// indexer's budgets and history retention.
///
/// The other half of [`restore_job_settings`] - same order, same
/// shape, and the same rule that a setting absent from settings.json
/// leaves the daemon's own default alone.
pub fn restore_ui_and_index_settings(daemon: &Arc<Daemon>, saved: &serde_json::Map<String, Value>) {
    if let Some(v) = saved.get("ui_locale").and_then(Value::as_str) {
        *daemon.ui_locale.lock_ok() = v.to_string();
    }
    // §141: absent leaves the `*` default in place; an explicitly saved
    // empty string is a deliberate "send no Access-Control header" and
    // has to survive the restart as one.
    if let Some(v) = saved.get("cors_origin").and_then(Value::as_str) {
        *daemon.cors_origin.lock_ok() = v.to_string();
    }
    if let Some(v) = saved.get("wall_hide_adult").and_then(Value::as_bool) {
        daemon.wall_hide_adult.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("auto_connections").and_then(Value::as_bool) {
        daemon.auto_connections.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("live_tune").and_then(Value::as_bool) {
        daemon.live_tune.store(v, Ordering::Relaxed);
        daemon.hub.live_tune.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("auto_defer").and_then(Value::as_bool) {
        daemon.auto_defer.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("post_health").and_then(Value::as_bool) {
        daemon.post_health.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("post_health_defer").and_then(Value::as_bool) {
        daemon.post_health_defer.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("post_health_fail").and_then(Value::as_bool) {
        daemon.post_health_fail.store(v, Ordering::Relaxed);
    }
    // §282 item 13. The third list settings_catalogue.rs pins: a key
    // missing here works until the daemon restarts and then quietly
    // reverts, with nothing logged either way.
    if let Some(v) = saved.get("alt_hold_count").and_then(Value::as_u64) {
        daemon.alt.hold_count.store(v as u32, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("alt_auto_switch").and_then(Value::as_bool) {
        daemon.alt.auto_switch.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("alt_auto_search").and_then(Value::as_bool) {
        daemon.alt.auto_search.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("alt_max_copies").and_then(Value::as_u64) {
        daemon.alt.max_copies.store(v as u32, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("alt_max_extra_bytes").and_then(Value::as_u64) {
        daemon.alt.max_extra_bytes.store(v, Ordering::Relaxed);
    }
    // §310's scheduled heal, and the same third list. A saved
    // `heal_auto` that did not survive a restart would be the WORST
    // shape of the three failures named above: the user turned an
    // automatic downloader off, and the next restart turns it back on.
    if let Some(v) = saved.get("heal_auto").and_then(Value::as_bool) {
        daemon.heal_auto.enabled.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("heal_auto_interval_h").and_then(Value::as_u64) {
        daemon.heal_auto.interval_h.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("heal_auto_max_jobs").and_then(Value::as_u64) {
        daemon.heal_auto.max_jobs.store(v as u32, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("heal_auto_max_bytes").and_then(Value::as_u64) {
        daemon.heal_auto.max_bytes.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("auto_prefetch").and_then(Value::as_bool) {
        daemon.auto_prefetch.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("oracle_route").and_then(Value::as_bool) {
        daemon.oracle_route.store(v, Ordering::Relaxed);
    }
    for (key, field) in [
        ("race_stragglers", &daemon.race_stragglers),
        ("adaptive_timeouts", &daemon.adaptive_timeouts),
        ("auto_rename", &daemon.auto_rename),
        ("identity_lookup", &daemon.identity_lookup),
        ("rename_resolution", &daemon.rename.resolution),
        ("rename_vcodec", &daemon.rename.vcodec),
        ("rename_acodec", &daemon.rename.acodec),
        ("rename_source", &daemon.rename.source),
        ("rename_group", &daemon.rename.group),
        ("rename_year_parens", &daemon.rename.year_parens),
        ("rename_quality_brackets", &daemon.rename.quality_brackets),
        ("rename_extra_words", &daemon.rename.extra_words),
        ("rename_identify", &daemon.rename.identify),
        ("rename_episode_titles", &daemon.rename.episode_titles),
        ("history_color_names", &daemon.history_color_names),
        ("media_chip_color", &daemon.media_chip_color),
        ("shape_chip_color", &daemon.shape_chip_color),
        ("rename_junk", &daemon.rename.junk),
        ("early_file_publish", &daemon.early_file_publish),
        ("write_through", &daemon.write_through),
        ("write_manifest", &daemon.write_manifest),
        ("metrics_open", &daemon.metrics_open),
        ("rename_media_only", &daemon.rename.media_only),
        ("rename_from_nzb", &daemon.rename.from_nzb),
        ("skip_samples", &daemon.skip_samples),
    ] {
        if let Some(v) = saved.get(key).and_then(Value::as_bool) {
            field.store(v, Ordering::Relaxed);
        }
    }
    // NOTE: a saved `auto_update` from pre-1.0.5 is deliberately
    // IGNORED - self-update was removed in 1.0.5 (notify-only).
    if let Some(v) = saved.get("update_checks").and_then(Value::as_bool) {
        daemon.update_checks.store(v, Ordering::Relaxed);
    }
    // The anti-rollback ratchet, now ENFORCED. Restored as-is, and the
    // permissive direction of a hand edit is a feature rather than an
    // oversight: LOWERING or removing this line is the documented local
    // reset, and the only way out of an install wedged by a bad serial,
    // because the ratchet has no server-side reset. It needs a shell on
    // the box and a stopped daemon, which is what keeps it out of reach
    // of the network - see the field docs on `update_serial_seen`.
    // Raising it by hand only makes this install fussier. Nothing to
    // validate or clamp either way.
    if let Some(v) = saved.get("update_serial_seen").and_then(Value::as_u64) {
        daemon.update_serial_seen.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("unit_bits").and_then(Value::as_bool) {
        daemon.unit_bits.store(v, Ordering::Relaxed);
    }
    // Saved empty string is meaningful: the user disabled update checks.
    if let Some(v) = saved.get("update_url").and_then(Value::as_str) {
        *daemon.update_url.lock_ok() = v.to_string();
    }
    if let Some(v) = saved.get("index_scan_par").and_then(Value::as_u64) {
        daemon
            .index_scan_par
            .store(v.clamp(1, 8), Ordering::Relaxed);
    }
    if let Some(v) = saved.get("index_tip_secs").and_then(Value::as_u64) {
        daemon.index_tip_secs.store(
            if v == 0 {
                0
            } else {
                v.max(super::settings::index_tip_floor_secs())
            },
            Ordering::Relaxed,
        );
    }
    if let Some(v) = saved.get("watch_interval_secs").and_then(Value::as_u64) {
        daemon
            .watch_interval_secs
            .store(v.clamp(1, 3600), Ordering::Relaxed);
    }
    if let Some(v) = saved.get("delete_to_trash").and_then(Value::as_bool) {
        crate::smart::set_delete_to_trash(v);
    }
    if let Some(s) = saved.get("cleanup_delete_mode").and_then(Value::as_str) {
        // Mirror the live setter (set_cleanup_delete_mode): lowercase
        // first, and never let an unparseable value fall through in
        // silence - the process default is Follow, which can resolve
        // to permanent deletion, and a typo in a hand-edited
        // settings.json must not silently select that. Trash is the
        // recoverable stand-in until the value is fixed.
        match crate::smart::CleanupMode::parse(&s.to_ascii_lowercase()) {
            Some(m) => crate::smart::set_cleanup_mode(m),
            None => {
                eprintln!(
                    "⚠ settings.json: unknown cleanup_delete_mode {s:?} - \
                     use follow, trash or delete; treating it as \"trash\" \
                     (recoverable) until it is corrected"
                );
                crate::smart::set_cleanup_mode(crate::smart::CleanupMode::Trash);
            }
        }
    }
    // Nested-extraction depth cap shared by the in-stream child chain
    // and the disk post-pass (a process-global in nzbkit). Clamp 1..=64:
    // real nesting is 2-3 levels, the ceiling is a DoS backstop.
    if let Some(v) = saved.get("nested_max_depth").and_then(Value::as_u64) {
        nzbkit::extract::set_nested_depth_cap(v.clamp(1, 64) as usize);
    }
    // No create/writable check at startup: a NAS that is down at
    // boot must not wipe the setting - the move path degrades to
    // leave-in-place on its own.
    if let Some(v) = saved.get("move_pace").and_then(Value::as_str)
        && !v.is_empty()
    {
        *daemon.move_pace.lock_ok() = v.to_string();
    }
    // ABSOLUTE, the same rule `set_move_completed` applies - and the
    // paragraph above is why it has to be spelled out again here rather
    // than assumed from the setter. A relative destination is not a NAS
    // that is down: it is a path that will resolve against the daemon's
    // working directory whatever the NAS does, so completed payloads move
    // somewhere nobody can predict, which is the exact behaviour the API
    // validator exists to refuse. Legacy, imported and hand-edited
    // settings files reach here without ever passing that validator.
    // IGNORED and warned, never cleared: dropping the stored value would
    // lose a setting the user can still fix by hand, and the move path
    // degrades to leave-in-place on its own.
    if let Some(v) = saved.get("move_completed").and_then(Value::as_str)
        && !v.is_empty()
    {
        let path = PathBuf::from(v);
        match require_absolute_dest(&path) {
            Ok(()) => *daemon.move_completed.write_ok() = Some(path),
            Err(e) => warn!(target: "settings", "⚠ stored move_completed ignored: {e}"),
        }
    }
    if let Some(v) = saved.get("move_completed_cats").and_then(Value::as_str)
        && let Ok(list) = parse_cat_dests(v)
    {
        // Per entry, not all-or-nothing: one bad rule must not take the
        // categories that ARE absolute down with it.
        let (good, bad): (Vec<_>, Vec<_>) = list
            .into_iter()
            .partition(|(_, p)| require_absolute_dest(p).is_ok());
        for (cat, p) in bad {
            warn!(
                target: "settings",
                "⚠ stored destination for category {cat} ignored: {}",
                require_absolute_dest(&p).unwrap_err()
            );
        }
        *daemon.move_completed_cats.write_ok() = good;
    }
    // TODO 317: names only, and NOT held to the category list - a
    // category is registered the first time a job uses it, so a
    // write-through rule saved for one not yet seen must survive the
    // restart that would otherwise drop it.
    if let Some(v) = saved.get("write_through_cats").and_then(Value::as_str) {
        *daemon.write_through_cats.lock_ok() = parse_cat_names(v);
    }
    if let Some(v) = saved.get("categories").and_then(Value::as_str) {
        let mut set = daemon.cats.lock_ok();
        for name in v.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            let clean = nzbkit::disk::sanitize_filename(name);
            if !clean.is_empty() {
                set.insert(clean);
            }
        }
    }
    if let Some(v) = saved.get("oracle_sample").and_then(Value::as_u64) {
        daemon.oracle_sample.store(v.min(3600), Ordering::Relaxed);
    }
    if let Some(v) = saved.get("index_deepen").and_then(Value::as_u64) {
        daemon.index_deepen.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("index_coverage").and_then(Value::as_bool) {
        daemon.index_coverage.store(v, Ordering::Relaxed);
    }
    // Present in settings.json == the user answered the question, so
    // the stored value wins over the indexers-configured default.
    if let Some(v) = saved.get("watchlist_external").and_then(Value::as_bool) {
        daemon.watchlist_external.store(v, Ordering::Relaxed);
        daemon.watchlist_external_set.store(true, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("watchlist_instant").and_then(Value::as_bool) {
        daemon.watchlist_instant.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("watchlist_instant_max").and_then(Value::as_u64) {
        daemon
            .watchlist_instant_max
            .store(v.min(3600) as u32, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("insurance_cap_gb").and_then(Value::as_u64) {
        daemon.insurance_cap_gb.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("watchlist_deferred").and_then(Value::as_bool) {
        daemon.watchlist_deferred.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("index_gapfill").and_then(Value::as_u64) {
        daemon.index_gapfill.store(v.min(100), Ordering::Relaxed);
    }
    if let Some(v) = saved.get("index_fold_secs").and_then(Value::as_u64) {
        daemon.index_fold_secs.store(
            v.clamp(Daemon::FOLD_SECS_MIN, Daemon::FOLD_SECS_MAX),
            Ordering::Relaxed,
        );
    }
    if let Some(v) = saved.get("index_probe7z").and_then(Value::as_bool) {
        daemon.index_probe7z.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("index_probe7z_budget").and_then(Value::as_u64) {
        daemon
            .index_probe7z_budget
            .store(v.min(2000), Ordering::Relaxed);
    }
    if let Some(v) = saved.get("index_pesto").and_then(Value::as_bool) {
        daemon.index_pesto.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("index_pesto_budget").and_then(Value::as_u64) {
        daemon
            .index_pesto_budget
            .store(v.min(2000), Ordering::Relaxed);
    }
    if let Some(v) = saved.get("index_nzbimport").and_then(Value::as_bool) {
        daemon.index_nzbimport.store(v, Ordering::Relaxed);
    }
    if let Some(v) = saved.get("index_nzbimport_budget").and_then(Value::as_u64) {
        daemon
            .index_nzbimport_budget
            .store(v.min(2000), Ordering::Relaxed);
    }
    // §131 D3. A privacy switch that silently comes back ON after a
    // restart is worse than not having one, so this restore is the
    // load-bearing third of the three lists.
    if let Some(v) = saved.get("index_search_log").and_then(Value::as_bool) {
        daemon.index_search_log.store(v, Ordering::Relaxed);
        // TODO 166: the switch's clear is DEFERRED when the index is
        // busy, so a daemon stopped inside that window would come back
        // with the rows still there and nothing left to retry - the one
        // hole an in-process latch cannot cover on its own. "Off" means
        // the table is empty, so re-assert it at every start: the
        // searchlog tick picks this up, runs one DELETE on the writer,
        // and it is a no-op whenever the table already is empty.
        #[cfg(feature = "indexer")]
        if !v {
            daemon
                .search_log_clear_pending
                .store(true, Ordering::Relaxed);
        }
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = saved.get("predb_max_rows").and_then(Value::as_u64) {
        daemon.predb.max_rows.store(
            v.clamp(
                predb_seed::PREDB_MAX_ROWS_MIN,
                predb_seed::PREDB_MAX_ROWS_MAX,
            ),
            Ordering::Relaxed,
        );
    }
    if let Some(v) = saved.get("predb_seed_days").and_then(Value::as_u64) {
        daemon
            .predb
            .seed_days
            .store(v.clamp(1, 366), Ordering::Relaxed);
    }
    // Script knobs: script_timeout_secs, script_confined (TODO 314
    // stage 1) + the §129 4a pre-queue pair.
    daemon.restore_script_knobs(saved);
    if let Some(v) = saved.get("history_rows").and_then(Value::as_u64)
        && (1..=200).contains(&v)
    {
        daemon.history_rows.store(v, Ordering::Relaxed);
    }
    // §129 D5: the optional retention knobs (0 = unlimited, the
    // default). Seeded AFTER load_queue has restored the records,
    // so enforce once here - the load-time pass ran with the knobs
    // still at their unlimited defaults.
    {
        let mut retention_set = false;
        if let Some(v) = saved.get("history_keep_count").and_then(Value::as_u64) {
            daemon.history_keep_count.store(v, Ordering::Relaxed);
            retention_set = v > 0;
        }
        // Issue #45: the age knob is SECONDS now. `history_keep_days`
        // is what a config written before that change holds, and it is read
        // only when the new key is absent - the two are the same setting, so
        // the one the dashboard writes has to win, or a value saved today
        // would be overruled by a value saved last month.
        //
        // Deliberately NOT migrated in place. Rewriting the file would take
        // the setting away from a user who downgrades, and deleting the old
        // key would throw away the only record of what they had chosen.
        // Left alone, it keeps working untouched for anyone who never opens
        // the new control, and goes quietly inert for anyone who does.
        let secs = saved
            .get("history_keep_secs")
            .and_then(Value::as_u64)
            .or_else(|| {
                saved
                    .get("history_keep_days")
                    .and_then(Value::as_u64)
                    .map(|d| {
                        let secs = d.saturating_mul(86_400);
                        if d > 0 {
                            info!(
                                target: "queue",
                                "history retention: history_keep_days={d} \
                                 read as {secs}s (the setting is seconds now)"
                            );
                        }
                        secs
                    })
            });
        if let Some(v) = secs {
            daemon
                .history_keep_secs
                .store(v.min(100 * 365 * 86_400), Ordering::Relaxed);
            retention_set |= v > 0;
        }
        if retention_set {
            daemon.history_enforce_retention();
        }
    }
    if let Some(v) = saved.get("bench_interval").and_then(Value::as_u64) {
        daemon.bench_interval.store(v, Ordering::Relaxed);
    }
}

pub fn seed_index_retention(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_retention")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    )
}

pub fn seed_index_pause_on_download(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_pause_on_download")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    )
}

pub fn seed_index_paused(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_paused")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

/// Metadata lanes: paused only if the user saved it so. Same seed shape
/// as `index_paused`, and deliberately a separate key - see
/// `Daemon::enrich_paused`.
pub fn seed_enrich_paused(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("enrich_paused")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub fn seed_predb_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("predb_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub fn seed_predb_server(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("predb_server")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(nzbkit::predb::DEFAULT_HOST)
            .to_string(),
    )
}

pub fn seed_predb_channels(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("predb_channels")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| nzbkit::predb::DEFAULT_CHANNELS.join(",")),
    )
}

pub fn seed_predb_nick(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("predb_nick")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(nzbkit::predb::DEFAULT_NICK)
            .to_string(),
    )
}

pub fn seed_predb_corr_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("predb_corr_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub fn seed_predb_corr_auto(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("predb_corr_auto")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub fn seed_scoreboard_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("scoreboard_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub fn seed_scoreboard_url(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("scoreboard_url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string(),
    )
}

pub fn seed_scoreboard_source(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("scoreboard_source")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string(),
    )
}

pub fn seed_corr_confirm_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("corr_confirm_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub fn seed_corr_confirm_source(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("corr_confirm_source")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string(),
    )
}

/// Which categories the daily sample asks for. Empty (the default, and
/// what an unreadable or nonsense value falls back to) = all four: a
/// setting that can only ever REDUCE the day's requests has to fail
/// towards the full sample, never towards a silently narrowed one.
pub fn seed_scoreboard_cats(settings_path: &Path) -> Mutex<Vec<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("scoreboard_cats")
            .and_then(|v| match v {
                // save_setting persists the parsed Vec<String>; the
                // comma string is accepted too so a hand-written
                // settings.json works.
                Value::Array(a) => Some(
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .and_then(|s| parse_scoreboard_cats(&s).ok())
            .unwrap_or_default(),
    )
}

pub fn seed_scoreboard_key(settings_path: &Path) -> Mutex<Option<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("scoreboard_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    )
}

pub fn seed_scoreboard_calibrate(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("scoreboard_calibrate")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub fn seed_spot_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    // Default ON (TODO 131, measured in E3): ~182 verified named
    // releases a day with fetchable NZBs, promoted to first-class wall
    // cards. A saved setting always wins - anyone who switched spots
    // off stays off.
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("spot_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    )
}

pub fn seed_spot_groups(settings_path: &Path) -> Mutex<Vec<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("spot_groups")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_else(|| vec!["free.pt".to_string()]),
    )
}

pub fn seed_spot_backfill(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("spot_backfill")
            .and_then(Value::as_u64)
            .unwrap_or(50_000)
            .clamp(1_000, 1_000_000),
    )
}

pub fn seed_spot_deepen(settings_path: &Path) -> AtomicU64 {
    // Default on. The deepening leg is OVER-only and it TERMINATES:
    // free.pt's 4.43 M articles are ~2.3 days of passes at this rate,
    // after which the mark sits on the group's first article and the
    // leg costs one GROUP command a pass forever. The catalogue it
    // reaches is 15 years of verified names with fetchable NZBs, in
    // groups the header scanner never reads.
    AtomicU64::new(
        load_settings(settings_path)
            .get("spot_deepen")
            .and_then(Value::as_u64)
            .unwrap_or(20_000)
            .min(1_000_000),
    )
}

pub fn seed_spot_resolve(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("spot_resolve")
            .and_then(Value::as_u64)
            .unwrap_or(40)
            .min(1_000),
    )
}

pub fn seed_index_max_bytes(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("index_max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    )
}

pub fn seed_index_evict(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_evict")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

#[cfg(feature = "indexer")]
pub fn seed_index_evict_order(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("index_evict_order")
            .and_then(Value::as_str)
            // A hand-edited settings.json can hold anything; keep
            // the invariant that this field is always valid.
            .filter(|s| parse_evict_order(s).is_some())
            .unwrap_or("ladder")
            .to_string(),
    )
}

/// Per-entry parse for the two saved kind lists. Both are PROTECTIVE
/// (keep = exempt from eviction; evict = restrict eviction to these),
/// and for both the empty list widens what may be deleted - so the old
/// whole-string `.ok()` fallback, which discarded the ENTIRE list over
/// one bad hand-edited token, silently widened eviction. Keep every
/// valid entry and warn about each dropped one instead; the setter path
/// (settings_index.rs) still refuses the same values loudly.
#[cfg(feature = "indexer")]
fn seed_evict_kinds_lenient(name: &str, s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in s.split(',') {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        match parse_evict_kinds(t) {
            Ok(ks) => {
                for k in ks {
                    if !out.contains(&k) {
                        out.push(k);
                    }
                }
            }
            Err(e) => warn!(target: "evict", "ignoring saved {name} entry {t:?}: {e}"),
        }
    }
    out
}

#[cfg(feature = "indexer")]
pub fn seed_index_evict_kinds(settings_path: &Path) -> Mutex<Vec<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("index_evict_kinds")
            .and_then(|v| match v {
                // save_setting persists the parsed Vec<String>; the
                // comma string is accepted too so a hand-written
                // settings.json works.
                Value::Array(a) => Some(
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .map(|s| seed_evict_kinds_lenient("index_evict_kinds", &s))
            .unwrap_or_default(),
    )
}

#[cfg(feature = "indexer")]
pub fn seed_index_keep_kinds(settings_path: &Path) -> Mutex<Vec<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("index_keep_kinds")
            .and_then(|v| match v {
                // Same two accepted shapes as index_evict_kinds above.
                Value::Array(a) => Some(
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .map(|s| seed_evict_kinds_lenient("index_keep_kinds", &s))
            .unwrap_or_default(),
    )
}

#[cfg(feature = "indexer")]
pub fn seed_index_evict_scope(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("index_evict_scope")
            .and_then(Value::as_str)
            // A hand-edited settings.json can hold anything; keep the
            // invariant that this field is always valid. The fallback is
            // "all", which WIDENS what eviction may touch, so a dropped
            // value is warned about rather than swallowed.
            .filter(|s| {
                let ok = parse_evict_scope(s).is_some();
                if !ok {
                    warn!(target: "evict",
                        "ignoring saved index_evict_scope {s:?}: falling back to \"all\", \
                         which widens what eviction may delete");
                }
                ok
            })
            .unwrap_or("all")
            .to_string(),
    )
}

#[cfg(feature = "indexer")]
pub fn seed_index_evict_headroom(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("index_evict_headroom")
            .and_then(Value::as_u64)
            .map(|n| n.min(50))
            .unwrap_or(10),
    )
}

#[cfg(feature = "indexer")]
pub fn seed_index_gates(
    settings_path: &Path,
    index_gates: Option<crate::gates::Gates>,
) -> Mutex<(String, Option<crate::gates::Gates>)> {
    Mutex::new((
        load_settings(settings_path)
            .get("index_gates")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        index_gates,
    ))
}

/// The user's own watchlist, read at CONSTRUCTION rather than when its
/// watcher task is spawned.
///
/// It is seeded here because the watchlist has readers that start
/// EARLIER than `spawn_watchlist_watcher` does. §74's instant path is
/// one: `Daemon::instant_matcher` compiles this list into the name test
/// the ingest legs install as an arrival watch, and both of those legs -
/// `spawn_index_scan` and `spawn_tip_watcher` - are spawned before the
/// watchlist watcher in `spawn_core_tasks`. A `tokio::spawn`ed task can
/// begin running on another worker the instant it is spawned, so loading
/// the list inside the watcher spawn left the two racing: a tip tick
/// that read the list first got `None`, installed NO watch, and every
/// release it then ingested arrived unseen - a complete, matching
/// release sitting in the index with nothing to say it had landed, until
/// the 60 s periodic pass picked it up.
///
/// That is not a hypothetical ordering worry. It is the nightly
/// armv7-cross red of 28 Aug 2026, where the emulator stretched the
/// first tick's connect + GROUP far enough that the arriving release
/// landed inside the window, and
/// `watchlist_instant::an_arriving_release_is_grabbed_without_waiting_for_the_pass`
/// failed both attempts at its 45 s budget having ingested the post
/// perfectly. Reproduced on the host by sleeping 3 s between the matcher
/// read and the walk: `matcher_is_some=false` on the first tick, the
/// same "2 new headers" line, the same silence after it.
///
/// Seeding in `build_daemon` rather than moving the call a few lines up
/// in `spawn_core_tasks` is deliberate: the field is then populated
/// before ANY task exists, so no future spawn order can reopen this.
///
/// READ THAT AS BEING ABOUT THIS FIELD AND NOT ABOUT THE INSTANT PATH.
/// `Daemon::watch_items` is the UNION of this list and the §151 synced
/// rows in `lists.items`, so the same window existed for a watchlist
/// item that arrived through a synced LIST. That half is closed too, by
/// `listsrc::seed_lists`, which this literal calls three lines below -
/// `spawn_list_sync` now only polls. Those two are the whole class -
/// the other two synchronous loads before a `tokio::spawn` here are
/// safe by construction, and the survey is in the handoff above.
pub fn seed_watchlist(settings_path: &Path) -> Mutex<Vec<nzbfast_meta::watchlist::WatchItem>> {
    let mut items = Vec::new();
    if let Some(v) = load_settings(settings_path).get("watchlist") {
        match serde_json::from_value(v.clone()) {
            Ok(l) => items = l,
            Err(e) => warn!(target: "watch", "ignoring saved watchlist setting: {e}"),
        }
    }
    Mutex::new(items)
}

/// The watchlist's own state file - which slot holds which release, and
/// what the instant path has already recorded. Seeded beside
/// [`seed_watchlist`] and for the same reason: the pass an arrival kick
/// wakes reads both, and that kick can come from a leg spawned before
/// the watcher.
pub fn seed_watch_state(spool: &Path) -> Mutex<nzbfast_meta::watchlist::WatchState> {
    let state_path = spool.join("watchlist-state.json");
    let mut state = nzbfast_meta::watchlist::WatchState::default();
    if let Some(v) = crate::persist::load_json_with_backup(&state_path) {
        match serde_json::from_value(v) {
            Ok(s) => state = s,
            Err(e) => warn!(target: "watch", "ignoring {}: {e}", state_path.display()),
        }
    }
    Mutex::new(state)
}

pub fn seed_line_speed(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("line_speed")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    )
}

pub fn seed_auto_retry_secs(_settings_path: &Path, auto_retry_mins: u64) -> AtomicU64 {
    AtomicU64::new(
        std::env::var("NZBFAST_AUTO_RETRY_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(auto_retry_mins * 60),
    )
}

/// Minutes of accumulated no-connection time before a server is retired
/// for the rest of a job (0 = never). Defaults to the pool's own shipped
/// budget, so the two cannot drift apart by editing only one of them.
pub fn seed_server_outage_mins(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("server_outage_mins")
            .and_then(|v| v.as_u64())
            .unwrap_or(nzbkit::pool::default_outage_mins()),
    )
}

pub fn seed_quality_prefs(settings_path: &Path) -> Mutex<nzbfast_meta::watchlist::QualityPrefs> {
    Mutex::new(
        load_settings(settings_path)
            .get("prefer_quality")
            .and_then(|v| nzbfast_meta::watchlist::QualityPrefs::from_value(v).ok())
            .unwrap_or_default(),
    )
}

pub fn seed_stream_secret(settings_path: &Path) -> String {
    {
        let saved = load_settings(settings_path)
            .get("stream_secret")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        match saved {
            Some(s) => s,
            None => {
                let s = fresh_secret();
                // Playback URLs minted from this secret are advertised
                // as permanent (expires: null, library .strm files), a
                // promise only a PERSISTED secret can keep - a restart
                // regenerates it and 401s every URL handed out under
                // the lost one. Say so loudly when the write fails;
                // the daemon still runs (best-effort settings policy).
                if !save_settings(settings_path, &[("stream_secret", json!(&s))]) {
                    eprintln!(
                        "⚠ could not persist the stream secret to {} - playback and \
                         .strm links minted this run will stop working after a \
                         restart (fix the settings directory to make them durable)",
                        settings_path.display()
                    );
                }
                s
            }
        }
    }
}

pub fn seed_omdb_key(settings_path: &Path) -> Mutex<Option<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("omdb_key")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|k| !k.is_empty()),
    )
}

/// §193 d: the TMDB key, from the settings row FIRST and the two older
/// homes after it.
///
/// M13: this is the metadata enrichment worker's key, and the
/// identifier's second source. WITH one they use TMDB; WITHOUT one they
/// still run, keyless, via TVmaze (tv) + Wikidata/Wikipedia (movies) -
/// TMDB declines API applications for NZB tooling, so keyless is the
/// normal path. iTunes used to serve movies; Apple removed that
/// endpoint. Either way the lookups stay on the worker's thread, never
/// on the API's.
///
/// Unlike its siblings this key predates its own settings row by a long
/// way: `tmdb_key` in the config file and `TMDB_API_KEY` in the
/// environment are what the hint on the rename card told people to use,
/// and both are still honoured. Order is settings.json, then the config
/// file, then the env - the row the user typed into last wins, and an
/// install that never opens that row behaves exactly as it did before.
///
/// The migration is a READ, not a move: nothing rewrites the config
/// file, so a key that lives there keeps working even for a daemon
/// started against a different settings directory. Saving the row writes
/// settings.json, and settings.json is read first, so the UI value wins
/// from then on.
///
/// One inherited limit, unchanged and worth knowing: `Config::load`
/// refuses a file with no servers in it, so a `tmdb_key` sitting beside
/// an empty server list has never been readable from there. The settings
/// row has no such condition, which is one more reason it is the home
/// the UI writes to.
pub fn seed_tmdb_key(settings_path: &Path, config: &Path) -> Mutex<Option<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("tmdb_key")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                nzbkit::config::Config::load(config)
                    .ok()
                    .and_then(|c| c.tmdb_key)
            })
            .or_else(|| std::env::var("TMDB_API_KEY").ok())
            .filter(|k| !k.is_empty()),
    )
}

#[cfg(feature = "indexer")]
pub fn resolve_index_enabled(settings_path: &Path, index_groups: &[String]) -> bool {
    let saved = load_settings(settings_path);
    match saved.get("index_enabled").and_then(Value::as_bool) {
        Some(v) => v,
        None => {
            let configured = !index_groups.is_empty()
                || saved
                    .get("index_interests")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.trim().is_empty());
            //
            // Deliberately NOT written back to settings.json. The
            // derivation is stable (it re-runs identically every
            // start), the first touch of the switch in the UI saves
            // a real answer that wins from then on, and startup
            // writes to that file are their own hazard - the
            // first-run API key mint keys off which keys are in it
            // (see SETUP_ANSWER_KEYS).
            if configured {
                info!(
                    target: "index",
                    "indexing is on for the groups this install already had; \
                     it is a switch now (Settings → Indexing) and new installs start off"
                );
            }
            configured
        }
    }
}

/// The seed halves of F3/F4 (27 Aug 2026 sweep): a bad hand-edited token
/// in a PROTECTIVE list must not empty the whole list, because for both
/// kind lists empty means "eviction may touch more".
#[cfg(all(test, feature = "indexer"))]
mod evict_seed_tests {
    use super::*;

    #[test]
    fn one_bad_token_drops_only_itself_from_a_seeded_kind_list() {
        assert_eq!(
            seed_evict_kinds_lenient("index_evict_kinds", "tv,bo ok,other"),
            vec!["tv".to_string(), "other".to_string()],
            "the valid entries survive a malformed neighbour"
        );
        // The widened vocabulary loads too: music/book and custom slugs.
        assert_eq!(
            seed_evict_kinds_lenient("index_keep_kinds", "music,book,formula-1"),
            vec![
                "music".to_string(),
                "book".to_string(),
                "formula-1".to_string()
            ]
        );
        assert_eq!(
            seed_evict_kinds_lenient("index_evict_kinds", ""),
            Vec::<String>::new()
        );
    }
}

/// §74's startup-ordering guard: the watchlist and its state are read
/// when the daemon is CONSTRUCTED, not when their watcher is spawned.
/// Not indexer-gated - the watchlist has an external-indexer leg too, so
/// both seeds run in the slim build and are tested there.
#[cfg(test)]
mod watchlist_seed_tests {
    use super::*;

    /// The §74 ordering guard, from the other end: a settings file with
    /// a watchlist in it produces a POPULATED list at construction, so
    /// `Daemon::instant_matcher` is armed before the first task exists.
    /// This used to be loaded inside `spawn_watchlist_watcher`, which is
    /// spawned after both ingest legs - see `seed_watchlist` for the
    /// nightly armv7-cross red that cost.
    #[test]
    fn the_watchlist_is_seeded_from_settings_at_construction() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-seedwl-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("settings.json");
        std::fs::write(
            &p,
            r#"{"watchlist":[{"id":7,"kind":"tv","title":"Wanted Show","seasons":"",
                 "episodes":"","min_quality":"any","target_quality":"1080p","enabled":true}]}"#,
        )
        .unwrap();
        let got = seed_watchlist(&p);
        let items = got.lock_ok();
        assert_eq!(items.len(), 1, "the saved watchlist was not seeded");
        assert_eq!(items[0].id, 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A settings file with no watchlist key, and one whose value will
    /// not parse, both seed an EMPTY list rather than refusing to build
    /// the daemon. The unparseable case is warned about, not fatal.
    #[test]
    fn a_missing_or_broken_watchlist_seeds_empty() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-seedwl-bad-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let none = dir.join("none.json");
        std::fs::write(&none, "{}").unwrap();
        assert!(seed_watchlist(&none).lock_ok().is_empty());
        let bad = dir.join("bad.json");
        std::fs::write(&bad, r#"{"watchlist":"not a list"}"#).unwrap();
        assert!(seed_watchlist(&bad).lock_ok().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The state half: an absent spool file is the default state, and a
    /// written one comes back. Seeded beside the list for the same
    /// reason - the pass an arrival kick wakes reads both.
    #[test]
    fn the_watch_state_is_seeded_from_the_spool_at_construction() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-seedws-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(seed_watch_state(&dir).lock_ok().slots.is_empty());
        std::fs::write(
            dir.join("watchlist-state.json"),
            r#"{"slots":{"7:S01E01":{"rank":40,"quality":"1080p",
                 "stem":"Wanted.Show.S01E01","nzo_id":"","grabbed_at":0}},"pending":[]}"#,
        )
        .unwrap();
        let got = seed_watch_state(&dir);
        assert_eq!(
            got.lock_ok().slots.len(),
            1,
            "the saved state was not seeded"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// M6 (29 Aug 2026 sweep): the absolute-path rule the API setters
/// enforce, applied to what startup reads back off disk.
#[cfg(test)]
mod move_dest_restore_tests {
    use super::*;

    fn restored(saved: serde_json::Value) -> Arc<Daemon> {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-restore-dest-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = crate::testutil::test_daemon(&dir);
        let map = saved.as_object().unwrap().clone();
        restore_ui_and_index_settings(&d, &map);
        let _ = std::fs::remove_dir_all(&dir);
        d
    }

    /// An absolute destination spelled the way THIS platform spells
    /// one.
    ///
    /// `/NAS/Movies` is absolute on unix and is NOT on Windows, where
    /// `Path::is_absolute` wants a drive prefix or a UNC root - so a
    /// POSIX literal makes these tests assert the exact opposite of
    /// what they mean on the one platform nobody on this fleet runs.
    /// The rule under test is right either way; the literals were not.
    /// That is how they reddened windows-unit shards 1/6 and 6/6 with
    /// every host gate green (run 33284073343, 30 Aug 2026) - the
    /// SIXTEENTH gate's class, arriving through a test rather than
    /// through a unix-only symbol, so `win-portability-gate` had
    /// nothing to see.
    fn abs(tail: &str) -> String {
        match cfg!(windows) {
            true => format!(r"C:\{}", tail.replace('/', r"\")),
            false => format!("/{tail}"),
        }
    }

    #[test]
    fn a_relative_stored_destination_is_ignored_not_adopted() {
        // Legacy, imported or hand-edited settings never passed
        // `set_move_completed`. Adopted, a relative destination resolves
        // against the daemon's working directory and completed payloads
        // move somewhere nobody can predict.
        let good = abs("NAS/Movies");
        let d = restored(serde_json::json!({
            "move_completed": "nas/movies",
            "move_completed_cats": format!("tv=nas/TV, movies={good}"),
        }));
        assert!(
            d.move_completed.read_ok().is_none(),
            "a relative global destination must not be adopted at startup"
        );
        let cats = d.move_completed_cats.read_ok().clone();
        assert_eq!(
            cats,
            vec![("movies".to_string(), PathBuf::from(&good))],
            "one bad rule must not take the absolute ones down with it"
        );
    }

    #[test]
    fn an_absolute_stored_destination_still_loads_when_it_is_unreachable() {
        // The point of restoring without a create/writable probe: a NAS
        // that is down at boot must not lose the setting.
        let nas = abs("nowhere/that/exists/NAS");
        let d = restored(serde_json::json!({ "move_completed": nas.clone() }));
        assert_eq!(
            d.move_completed.read_ok().clone(),
            Some(PathBuf::from(&nas))
        );
    }
}

// `seeded_predb` and `seeded_scoreboard` moved DOWN here from
// `serve/startup.rs` when the daemon layer became its own crate.
// Both build a DAEMON-layer type out of the `seed_predb_*` /
// `seed_scoreboard_*` readers already in this file, so the only
// wiring thing about them was the file they sat in - and
// `testutil::test_daemon` builds a Daemon without a boot sequence,
// so it cannot reach up into wiring for them. `build_daemon` still
// calls both under their old bare names through serve's root glob.
/// The pre-database feed and correlation settings, seeded from the
/// saved file.
///
/// A constructor rather than an inline sub-struct literal, for the
/// reason `seeded_scoreboard` states: an inline literal costs
/// `build_daemon` the same lines plus two braces, which is the whole
/// reason the group moved.
///
/// Explicit opt-in throughout: a missing key, a null, or a non-bool
/// all land on OFF - there is no path that opens an outbound IRC
/// connection, or turns an inference engine on, by accident.
pub fn seeded_predb(settings_path: &std::path::Path) -> crate::daemon::PredbSettings {
    crate::daemon::PredbSettings {
        enabled: seed_predb_enabled(settings_path),
        server: seed_predb_server(settings_path),
        channels: seed_predb_channels(settings_path),
        nick: seed_predb_nick(settings_path),
        #[cfg(feature = "indexer")]
        pending: Mutex::new(Vec::new()),
        status: Mutex::new(String::new()),
        corr_enabled: seed_predb_corr_enabled(settings_path),
        corr_auto: seed_predb_corr_auto(settings_path),
        #[cfg(feature = "indexer")]
        max_rows: std::sync::atomic::AtomicU64::new(crate::predb_seed::PREDB_MAX_ROWS_DEFAULT),
        #[cfg(feature = "indexer")]
        seed_days: std::sync::atomic::AtomicU64::new(crate::predb_seed::PREDB_SEED_DAYS_DEFAULT),
        #[cfg(not(feature = "indexer"))]
        seed_days: std::sync::atomic::AtomicU64::new(180),
        #[cfg(feature = "indexer")]
        seed_running: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        seed_status: Mutex::new(String::new()),
    }
}

/// The parity scoreboard's settings, seeded from the saved file.
///
/// A constructor rather than a struct literal inside `build_daemon`,
/// because that function is one `field: value` line per `Daemon` field
/// and an inline sub-struct costs it the same lines plus two braces -
/// which is the whole reason the group moved. It lives here rather than
/// beside the type because every value comes from a `seed_scoreboard_*`
/// reader in this file.
///
/// OFF and sourceless unless the user saved their own reference
/// indexer. No path samples anybody's API by accident, and no key or
/// URL ever ships as a constant.
pub fn seeded_scoreboard(settings_path: &std::path::Path) -> crate::daemon::ScoreboardSettings {
    crate::daemon::ScoreboardSettings {
        enabled: seed_scoreboard_enabled(settings_path),
        url: seed_scoreboard_url(settings_path),
        source: seed_scoreboard_source(settings_path),
        cats: seed_scoreboard_cats(settings_path),
        key: seed_scoreboard_key(settings_path),
        calibrate: seed_scoreboard_calibrate(settings_path),
        #[cfg(feature = "indexer")]
        running: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        status: Mutex::new(String::new()),
    }
}
