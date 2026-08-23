//! Sweep 8, L12: maintenance of a Spot-only index database - the
//! deferred picker-index build, and (TODO 199 item 5's policy half,
//! decided 22 Aug 2026) the retention reap, the planner-statistics
//! refresh and the shatter fold beside it.
//!
//! `Index::open` builds the partial picker indexes inline only under
//! `PICKER_INDEX_INLINE_MAX` rows, so a database that has grown past it
//! reaches the daemon without them and the maintenance pass is the only
//! thing that can ever create them. That pass ran exclusively inside
//! `if !groups.is_empty()`, and Spot ingestion runs with a deliberately
//! EMPTY group vector - so on a Spot-only install the deferred list
//! could never drain, and the complete-browse page kept its whole-table
//! plan indefinitely rather than merely across a migration.
//!
//! The correction TODO 199 records is pinned first, because the obvious
//! gate is the wrong one: `index_maintenance_ok()` goes through
//! `indexing_pause_reason()`, which answers `Some("off")` in exactly
//! this configuration. Gating the backfill on it would have left the
//! build unreachable and looked like a fix.
//!
//! The same trap has a second face on the retention leg, and that one
//! is nastier: put the wrong predicate on the reap's PER-SLICE stand-
//! down and the pass is admitted at the door, breaks out before its
//! first slice, prunes nothing, never stamps its hourly clock - and
//! logs that maintenance ran.

use super::*;

/// A throwaway daemon on its own temp directory - `daemon_tests`'
/// helper of the same name, which is not reachable from a sibling
/// `#[cfg(test)]` module.
fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
    let dir = std::env::temp_dir().join(format!("nzbfast-dmn-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);
    f(&d);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spot on, groups off - what a Spot-only install IS.
fn spot_only(d: &Arc<Daemon>) {
    d.index_enabled.store(false, Ordering::Relaxed);
    d.spot_enabled.store(true, Ordering::Relaxed);
    assert!(d.index_groups.lock_ok().is_empty());
}

#[test]
fn a_spot_only_index_can_still_reach_its_deferred_picker_indexes() {
    with_daemon("l12picker", |d| {
        spot_only(d);
        assert_eq!(
            d.indexing_pause_reason(),
            Some("off"),
            "the premise: group indexing is off, which is what the handoff's \
             suggested gate reads"
        );
        assert!(
            !d.index_maintenance_ok(),
            "so `index_maintenance_ok` is permanently false here - gating the \
             deferred build on it would have changed nothing"
        );
        assert!(
            d.db_maintenance_ok(),
            "the shared-database gate asks whether ANY scan source is live, \
             because both write into the same tables"
        );

        // A database past the inline threshold: `Index::open` declines
        // to build the picker indexes and the deferred list is the only
        // route to them.
        let era = d.index_era();
        {
            let ix = nzbkit::index::Index::open(&d.index_db).expect("open the index");
            ix.debug_defer_picker_indexes();
        }
        let fresh = nzbkit::index::Index::open(&d.index_db).expect("reopen the index");
        assert!(
            fresh.missing_picker_index().is_some(),
            "a database past the inline bound reaches the daemon without them"
        );
        d.publish_index(era, fresh);

        // Drain the deferred list the way the scan loop does: one per
        // pass, until there is nothing left to build.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut built = Vec::new();
        for _ in 0..16 {
            let Some(name) = d.with_index(|ix| ix.missing_picker_index()) else {
                break;
            };
            built.push(name);
            rt.block_on(picker_index_backfill(d));
            assert!(
                d.with_index(|ix| ix.missing_picker_index()) != Some(name),
                "a pass that ran must have built {name} - otherwise the loop \
                 below spins and the finding is still open"
            );
        }
        assert_eq!(
            d.with_index(|ix| ix.missing_picker_index()),
            None,
            "every deferred index must exist after the passes (built: {built:?})"
        );
        // And the pair still deploys posted-leading, which is the M11
        // ordering this fix must not disturb.
        assert_eq!(
            built
                .iter()
                .position(|n| *n == "idx_rel_complete_posted")
                .zip(built.iter().position(|n| *n == "idx_rel_complete_kind"))
                .map(|(p, k)| p < k),
            Some(true),
            "posted must still be built before kind: {built:?}"
        );
    });
}

/// The gate is not simply "always true": with the database unwanted, or
/// a job running, or the whole indexer paused, the build stands down
/// exactly as the group-only one did.
#[test]
fn the_picker_gate_still_stands_down_for_the_things_that_matter() {
    with_daemon("l12gate", |d| {
        spot_only(d);
        assert!(d.db_maintenance_ok());

        // Nothing wants the database at all.
        d.spot_enabled.store(false, Ordering::Relaxed);
        assert!(
            !d.db_maintenance_ok(),
            "no source, no database, nothing to index for"
        );
        d.spot_enabled.store(true, Ordering::Relaxed);

        // A download owns the machine.
        d.index_jobs_active.fetch_add(1, Ordering::AcqRel);
        assert!(!d.db_maintenance_ok(), "a running job stands it down");
        d.index_jobs_active.fetch_sub(1, Ordering::AcqRel);

        // Offline and paused reach it through BOTH pause predicates, so
        // neither can be cleared by the other source being on.
        d.offline.store(true, Ordering::Relaxed);
        assert!(!d.db_maintenance_ok(), "offline means no maintenance");
        d.offline.store(false, Ordering::Relaxed);
        d.index_paused.store(true, Ordering::Relaxed);
        assert!(!d.db_maintenance_ok(), "paused means paused");
        d.index_paused.store(false, Ordering::Relaxed);

        // And a group-only install is unchanged.
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(d.db_maintenance_ok());
        assert!(d.index_maintenance_ok());
    });
}

/// Ingest one release, `age_secs` old.
///
/// Two are wanted, and the fresh one is not decoration: the fold laps
/// the id space against `MAX(id)`, so a database the prune has just
/// emptied gives it nothing to lap and no lap marker to assert. A real
/// install always has rows the window spares.
fn seed_release(d: &Arc<Daemon>, tag: &str, age_secs: i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    let entries = vec![nzbkit::nntp::OverEntry {
        number: 1,
        subject: format!("\"Policy.{tag}.S01E01.1080p-GRP.rar\" yEnc (1/1)"),
        from: "p@x".into(),
        date: now - age_secs,
        message_id: format!("<policy{tag}@x>"),
        bytes: 4096,
    }];
    d.with_index_mut(|ix| ix.ingest("a.b.policy", &entries, now).ok())
        .expect("ingest");
}

/// One release far outside any window this test sets, one comfortably
/// inside it.
fn seed_one_stale_and_one_fresh(d: &Arc<Daemon>) {
    seed_release(d, "Stale", 400 * 86_400);
    seed_release(d, "Fresh", 60);
}

/// The exact release count, past the TTL cache - `at = None` is what
/// the pass's own `refresh_index_stats` installs.
fn releases(d: &Arc<Daemon>) -> i64 {
    d.index_stats_cache.lock_ok().at = None;
    d.index_stats_snapshot().expect("exact figures").0 as i64
}

/// Has a leg stamped its clock? Each of the three writes a kv key when
/// it runs, and nothing else in the daemon writes these.
fn stamped(d: &Arc<Daemon>, key: &str) -> bool {
    d.with_index(|ix| Some(ix.kv_get(key).is_some()))
        .expect("the index is open")
}

/// TODO 199 item 5's policy half, decided 22 Aug 2026: retention, the
/// planner-statistics refresh and the shatter fold are upkeep of the
/// SHARED database, not of the group scanner, so they run on a
/// Spot-only install exactly as they do on a group-indexed one.
///
/// The oracle is deliberately three-part, because the two ways to get
/// this wrong fail differently. Leaving the entry gate group-only skips
/// all three. Fixing only the entry gate and leaving the reap's own
/// per-slice stand-down on `index_maintenance_ok` is worse: the pass is
/// admitted, breaks out before its first slice, prunes nothing and
/// never stamps its hourly clock - and the log says maintenance ran.
/// So the row going away and `retention_at` being stamped are asserted
/// separately from `analyze_at`, which the entry gate alone would
/// satisfy.
#[test]
fn a_spot_only_database_is_pruned_analysed_and_folded_like_any_other() {
    with_daemon("l12policy", |d| {
        spot_only(d);
        // A one-day retention window and one release posted years
        // before it. `promote_spot` clamps a spot's own posted date
        // specifically so a promoted card cannot "dodge the retention
        // prunes" - a clamp that means nothing unless the prune runs
        // on this install at all.
        d.index_retention.store(true, Ordering::Relaxed);
        d.index_max_age_secs.store(86_400, Ordering::Relaxed);
        seed_one_stale_and_one_fresh(d);
        assert_eq!(
            releases(d),
            2,
            "the fixture is one prunable release and one the window spares"
        );
        assert!(
            !stamped(d, "retention_at"),
            "a fresh database has never reaped - the hourly throttle is open"
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Exactly the call the scan loop makes on a Spot-only pass: no
        // groups, spots live, and a `waiting` closure that is always
        // false there (it is `scan_groups && ...`), so the gate inside
        // is the only stand-down in play.
        assert!(rt.block_on(maintenance_slice(d, false, true, &|| false)));

        assert_eq!(
            releases(d),
            1,
            "the age prune must take the release older than the window and \
             spare the other - a Spot-only install that sets a retention \
             window and gets nothing is the finding"
        );
        assert!(
            stamped(d, "retention_at"),
            "a reap that ran out of rows stamps its hourly clock; an \
             admitted-then-refused reap never does"
        );
        assert!(
            stamped(d, "analyze_at"),
            "the planner statistics are the same statistics whichever \
             source filled the table - without them `wall2` plans as a \
             full scan of every release"
        );
        assert!(
            stamped(d, "shatter_fold_lap_v1"),
            "the fold laps the id space and marks the lap; it finds \
             nothing on a pure Spot database, and is here for the \
             install this configuration actually describes - one that \
             scanned groups and then switched the indexer off"
        );
    });
}

/// And the same three legs still stand down on a Spot-only install when
/// a download owns the machine. The gate is the ONLY thing that can
/// stop them there, so this is not the group case restated: `waiting()`
/// is permanently false with no groups, and a leg that reads it instead
/// of the gate would run straight through somebody's download.
#[test]
fn spot_only_maintenance_still_stands_down_for_a_download() {
    with_daemon("l12policygate", |d| {
        spot_only(d);
        d.index_retention.store(true, Ordering::Relaxed);
        d.index_max_age_secs.store(86_400, Ordering::Relaxed);
        seed_one_stale_and_one_fresh(d);
        d.index_jobs_active.fetch_add(1, Ordering::AcqRel);
        assert!(!d.db_maintenance_ok());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(rt.block_on(maintenance_slice(d, false, true, &|| false)));

        d.index_jobs_active.fetch_sub(1, Ordering::AcqRel);
        assert_eq!(releases(d), 2, "nothing may be pruned while a job runs");
        assert!(
            !stamped(d, "analyze_at"),
            "and no ANALYZE may be started behind it either"
        );
    });
}
