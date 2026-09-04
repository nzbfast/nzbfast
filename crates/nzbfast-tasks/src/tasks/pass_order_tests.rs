//! Sweep 8, L7: the pass's one exact stats recompute must be its LAST
//! act.
//!
//! It used to run immediately after group ingest - before gap-fill adds
//! rows, before retention prunes them, before the shatter fold rewrites
//! shards, and before the size cap evicts whole releases. A pass that
//! removed a known set therefore left `/status` and the dashboard
//! reporting counts the just-finished pass had already contradicted,
//! with nothing to invalidate them until the 45 s TTL expired. The
//! manual shrink and evict endpoints have always invalidated
//! explicitly; the pass's own recompute simply ran too early.
//!
//! An ordering inside one long async block has no seam to drive, so
//! this reads the source - the same shape `settings_catalogue.rs` uses
//! for reflection gates. It is checking a fact about the code, and the
//! code is what it reads.

/// `refresh_index_stats` runs after every writer the pass owns.
#[test]
fn the_exact_stats_recompute_is_the_last_thing_the_pass_does() {
    let src = include_str!("../tasks.rs");
    let scan = src
        .split_once("pub fn spawn_index_scan")
        .expect("spawn_index_scan moved - re-point this gate")
        .1;
    let refresh = scan
        .find("refresh_index_stats()")
        .expect("the pass must still take one exact stats recompute");
    for writer in ["gapfill", "maintenance_slice(", "evict_between_passes("] {
        let at = scan
            .find(writer)
            .unwrap_or_else(|| panic!("{writer} is gone from the pass - re-point this gate"));
        assert!(
            at < refresh,
            "{writer} writes to the index and runs AFTER the exact stats \
             recompute: the pass would publish counts it then contradicts"
        );
    }
}

/// A pass that stands down mid-way expires the cache rather than
/// leaving half-applied figures warm. The machine is standing down for
/// a download and owes it no table scan; the next reader pays.
#[test]
fn a_stand_down_expires_the_stats_cache() {
    let src = include_str!("../tasks.rs");
    let waiting = src
        .split_once("let waiting = ||")
        .expect("the stand-down closure moved - re-point this gate")
        .1;
    let body = &waiting[..waiting.find("};").unwrap_or(waiting.len())];
    assert!(
        // F-18 (bug sweep 22 Aug 2026): the expiry goes through the
        // helper that also bumps the generation fence, so an in-flight
        // snapshot cannot stamp pre-stand-down figures fresh.
        body.contains("expire_index_stats()"),
        "a stand-down must expire the stats cache: {body}"
    );
}

/// TODO 198 tail: the deep-statistics leg must run AFTER the picker
/// backfill, and it must retire the read pool when it lands.
///
/// Both are facts the compiler cannot hold and neither fails loudly.
/// Order first: a picker index that has just been built carries no
/// `sqlite_stat1` row, and one missing row makes the next `PRAGMA
/// optimize` re-sample that index's whole table and delete every stat4
/// sample on it. Measure before building and the pass throws its own
/// work away - up to 74 s of it on the index this was measured against.
///
/// The pool retirement is the one that would make the whole leg a
/// no-op. New statistics are NOT picked up by a connection that is
/// already open: a reader held across the ANALYZE keeps planning the
/// old way while a freshly opened one takes the new index (measured on
/// a 2M-row fixture, 22 Aug 2026). Browse, the wall and the newznab
/// facade all read through the pooled read-only connections, so a leg
/// that measures and does not retire them changes nothing a user can
/// see - and every test of the statistics themselves still passes.
#[test]
fn the_deep_statistics_leg_runs_last_and_retires_the_readers() {
    // Re-pointed 2 Sep 2026: the nine between-pass functions moved to
    // `indexer/passes.rs` for the 4,000-line file ceiling. The gate
    // reads the file `maintenance_slice` lives in, wherever that is.
    let src = include_str!("indexer/passes.rs");
    let slice = src
        .split_once("pub(crate) async fn maintenance_slice")
        .expect("maintenance_slice moved - re-point this gate")
        .1;
    let build = slice
        .find("picker_index_backfill(")
        .expect("the picker backfill is gone from the maintenance slice");
    let deep = slice
        .find("deep_stats_pass(")
        .expect("the deep-statistics leg is gone from the maintenance slice");
    assert!(
        build < deep,
        "deep_stats_pass runs BEFORE picker_index_backfill: the next \
         PRAGMA optimize will re-sample the table the new index is on and \
         delete everything this pass just measured"
    );
    let leg = include_str!("indexer/deep_stats.rs");
    assert!(
        leg.contains("drop_index_read()"),
        "the deep-statistics leg no longer retires the read pool, so the \
         statistics it measures reach nothing the user reads"
    );
}

/// 2 Sep 2026: the durable seed replay must run in the lap, and after
/// the folds.
///
/// In the lap at all because until that day it ran ONLY in
/// `seed_harvest.rs`, which reaches it through
/// `index_pass_gate.try_lock()` - a gate this very loop holds for the
/// whole of its work. When lap work grew from ~9 minutes to 42-46 on
/// the live index, the inter-lap sleep the lane used to run in stopped
/// happening and the lane reconciled nothing for 91 minutes across
/// three restarts, silently (research/SEED-REPLAY-STARVATION-2026-09-02.md).
/// Delete the slice below and that returns, with no test failing and
/// no line in the log.
///
/// After the folds because an exact seed hit needs COMPLETE local file
/// rows whose full manifest matches, and that is exactly what a fold
/// has just finished making. Replaying first would score sets against
/// rows this same lap is about to complete, and the cursor only comes
/// back round a whole cycle later.
#[test]
fn the_seed_replay_slice_runs_in_the_lap_and_after_the_folds() {
    let src = include_str!("indexer/passes.rs");
    let slice = src
        .split_once("pub(crate) async fn maintenance_slice")
        .expect("maintenance_slice moved - re-point this gate")
        .1;
    let replay = slice.find("seed_replay_pass(").expect(
        "the durable seed replay is gone from the maintenance slice: it is \
         back to running only when it wins a gate the scan lap holds",
    );
    let album = slice
        .find("album_fold_pass(")
        .expect("the album fold is gone from the maintenance slice");
    assert!(
        album < replay,
        "seed_replay_pass runs BEFORE album_fold_pass: it will score seed \
         sets against file rows this lap has not folded whole yet, and the \
         cursor does not come back to them for a whole cycle"
    );
}
