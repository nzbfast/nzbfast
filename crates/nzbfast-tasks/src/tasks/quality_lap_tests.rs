//! The `quality_v10` bump's LAP LEG: `passes::quality_backfill_pass`,
//! which finishes inside the indexer lap what the two seconds inside
//! `Index::open` could not.
//!
//! It shipped on 2 Sep 2026 (`83f96e811`) with one caller and no test
//! of its own, and the daemon suite could not have reached it if it had
//! tried: a fresh test index is EMPTY, so the very first `Index::open`
//! walks nothing, stamps the version key and every later slice returns
//! at its first kv read. The leg was therefore green in every suite by
//! never running - the shape memory calls "a gate that never runs",
//! reached here through the fixture rather than the trigger.
//!
//! `debug_stale_classification` is what breaks that: it puts the table
//! into the state a real index upgraded ACROSS the bump is in - stored
//! rows carrying an older classifier's answer, and the version key
//! un-stamped - which is the only state in which the pass has work.
//!
//! What this file pins is the LEG, not the slice. `schema.rs` already
//! proves the slice heals a row and parks on a spent budget; what had
//! no coverage is that the lap REACHES it, that it runs to completion
//! there, and that it stands down for a download like every leg beside
//! it. So the daemon's own index handle is the only thing in play: the
//! writer is opened once and kept, so after the poison nothing but the
//! lap can re-stamp that key.
//!
//! Observed against a real daemon before this file was written
//! (research/QUALITY-V10-LAP-LEG-OBSERVED-2026-09-02.md): on a 400k-row
//! index seeded by the pre-bump binary, 200,000 rows changed lane and
//! 100,000 crossed from junk>=50 (which the wall hides by default) to
//! visible, with no row moving the wrong way.

use super::*;

/// A throwaway daemon on its own temp directory. A third copy of
/// `daemon_tests`' helper of the same name, for the reason
/// `picker_index_tests` records beside its own: a sibling `#[cfg(test)]`
/// module cannot reach either of the others.
fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
    let dir = std::env::temp_dir().join(format!("nzbfast-dmn-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::testutil::test_daemon(&dir);
    f(&d);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spots on, groups off - the same configuration
/// `picker_index_tests` uses, so `maintenance_slice`'s entry gate is
/// open with an empty group vector and the call below is the one the
/// scan loop makes.
fn spot_only(d: &Arc<Daemon>) {
    d.index_enabled.store(false, Ordering::Relaxed);
    d.spot_enabled.store(true, Ordering::Relaxed);
}

/// The four shapes the 2 Sep classifier fixes move, and three controls
/// that must not move, as
/// research/INTEREST-PRESETS-BOOKS-MUSIC-ANIME-2026-09-02.md sections
/// 2-4 found them on the wire. The group is load-bearing on two of
/// them - `recover_kind_from_group` and `recover_episode_from_group`
/// are exactly what v10 costs over a free re-run of v9.
const SHAPES: [(&str, &str); 7] = [
    // Moved by the fixes:
    (
        "Perry Rhodan 3390 - Die Stunde der Deponentin (Ungekuerzt)",
        "alt.binaries.mp3.audiobooks",
    ),
    (
        "Bleach - 187 - Ichigo Rages! The Assassin's Secret",
        "alt.binaries.multimedia.anime.highspeed",
    ),
    ("04-kmfdm-anarchy-web-2026", "alt.binaries.sounds.mp3"),
    (
        "The New York Times - 15 August 2026",
        "alt.binaries.e-book.magazines",
    ),
    // Controls:
    (
        "Dune.Part.Two.2024.2160p.UHD.BluRay.REMUX.DV.HDR.HEVC.TrueHD.Atmos-GRP",
        "alt.binaries.boneless",
    ),
    ("Max Brooks - World War Z (epub)", "alt.binaries.e-book"),
    (
        "[SubsPlease] Frieren - 18 (1080p) [ABCD1234]",
        "alt.binaries.multimedia.anime.highspeed",
    ),
];

/// Ingest one release per shape, into its own group.
fn seed_shapes(d: &Arc<Daemon>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    for (i, (stem, grp)) in SHAPES.iter().enumerate() {
        let entries = vec![nzbkit::nntp::OverEntry {
            number: 1 + i as u64,
            subject: format!("\"{stem}.part1.rar\" yEnc (1/1)"),
            from: format!("poster{i}@x"),
            date: now - 3600,
            message_id: format!("<qual{i}@x>"),
            bytes: 2_000_000_000,
        }];
        d.with_index_mut(|ix| ix.ingest(grp, &entries, now).ok())
            .expect("ingest");
    }
}

/// Every seeded row's `(stem, kind, junk, title_key)`, read through a
/// connection of the test's own - the same thing `seed_harvest`'s tests
/// do, because no public reader on `Index` returns these three columns
/// together.
fn rows(d: &Arc<Daemon>) -> Vec<(String, String, i64, String)> {
    let db = rusqlite::Connection::open(&d.index_db).expect("open the index file");
    let mut st = db
        .prepare("SELECT stem, kind, junk, title_key FROM releases ORDER BY id")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

/// The lane a given seeded stem is in.
fn lane<'a>(rows: &'a [(String, String, i64, String)], stem: &str) -> (&'a str, i64) {
    let r = rows
        .iter()
        .find(|r| r.0 == stem)
        .unwrap_or_else(|| panic!("no row for {stem} - the fixture stopped ingesting it"));
    (r.1.as_str(), r.2)
}

/// One lap heals every stored row the classifier now reads differently,
/// and stamps the version key so it never walks the table again.
///
/// The oracle is the classification the rows carried BEFORE the poison,
/// not a hardcoded table: what the leg owes is that a row disagreeing
/// with the current classifier is brought back to the current
/// classifier's answer, which stays true when the next fix lands. The
/// two named lanes underneath it are the memo's actual finding and are
/// meant to red if a future change moves them - an audiobook filed as a
/// junk movie is the bug the bump exists for.
#[test]
fn one_lap_heals_every_stored_row_the_classifier_now_reads_differently() {
    with_daemon("qualityheal", |d| {
        spot_only(d);
        seed_shapes(d);
        let truth = rows(d);
        assert_eq!(truth.len(), SHAPES.len(), "one row per shape");
        assert_eq!(
            lane(
                &truth,
                "Perry Rhodan 3390 - Die Stunde der Deponentin (Ungekuerzt)"
            )
            .0,
            "book",
            "the premise: the CURRENT classifier reads the audiobook group"
        );
        assert_eq!(
            lane(&truth, "Bleach - 187 - Ichigo Rages! The Assassin's Secret").0,
            "tv",
            "...and the dashed `Show - NNN - Title` episode"
        );

        // The state a real index upgraded across the bump is in: the
        // pre-2-Sep answer stored (an audiobook folder carried exactly
        // `kind=movie, junk=60`, which the wall hides at 50) and the
        // version key un-stamped.
        let poisoned = d
            .with_index_mut(|ix| Some(ix.debug_stale_classification("movie", 60)))
            .expect("the index is open");
        assert_eq!(poisoned, SHAPES.len(), "every row carries the old answer");
        assert!(
            d.with_index(|ix| Some(ix.kv_get("quality_v10").is_none()))
                .expect("the index is open"),
            "and the pass has the whole table to walk"
        );
        assert!(
            rows(d).iter().all(|r| r.1 == "movie" && r.2 == 60),
            "the fixture must actually be wrong before the lap - a poison \
             that did not stick makes every assertion below vacuous"
        );

        // Exactly the call the scan loop makes on a Spot-only pass. The
        // daemon's write handle is already open and nothing reopens it,
        // so the lap leg is the only thing that can heal these rows -
        // `Index::open`'s own two-second slice ran long ago, on an
        // empty table.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(rt.block_on(maintenance_slice(d, false, true, &|| false)));

        let healed = rows(d);
        assert!(
            healed.iter().all(|r| r.3 != "stale-answer"),
            "every row must have been RE-PARSED, not merely left alone: {:?}",
            healed
                .iter()
                .filter(|r| r.3 == "stale-answer")
                .map(|r| &r.0)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            healed, truth,
            "and re-parsed back to the classifier's own current answer"
        );
        assert_eq!(
            lane(
                &healed,
                "Perry Rhodan 3390 - Die Stunde der Deponentin (Ungekuerzt)"
            ),
            ("book", 0),
            "the audiobook leaves the junk-movie lane the bump exists to empty"
        );
        assert_eq!(
            lane(
                &healed,
                "Bleach - 187 - Ichigo Rages! The Assassin's Secret"
            ),
            ("tv", 0),
            "and the dashed anime episode stops being a hidden movie"
        );
        assert!(
            d.with_index(|ix| Some(ix.kv_get("quality_v10").as_deref() == Some("1")))
                .expect("the index is open"),
            "a pass that ran out of rows STAMPS - an unstamped key means the \
             lap walks the whole table again on every lap forever"
        );
        assert_eq!(
            d.with_index(|ix| Some(ix.quality_backfill_cursor()))
                .expect("the index is open"),
            None,
            "and the cursor reads complete, which is what makes the leg's \
             log line say so rather than `cursor at release 0`"
        );
    });
}

/// And it stands down for a download, like every leg beside it.
///
/// The gate is the only stand-down in play here: `waiting()` is
/// permanently false on a Spot-only install (it is `scan_groups &&
/// ...`), so a leg reading that instead of `db_maintenance_ok` would
/// re-parse the whole table straight through somebody's download - the
/// one thing this pass must never do, since it holds the index WRITE
/// mutex for a second at a time.
#[test]
fn the_quality_leg_stands_down_for_a_download() {
    with_daemon("qualitygate", |d| {
        spot_only(d);
        seed_shapes(d);
        d.with_index_mut(|ix| Some(ix.debug_stale_classification("movie", 60)))
            .expect("the index is open");
        d.index_jobs_active.fetch_add(1, Ordering::AcqRel);
        assert!(
            !d.db_maintenance_ok(),
            "the premise: a job owns the machine"
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(rt.block_on(maintenance_slice(d, false, true, &|| false)));
        d.index_jobs_active.fetch_sub(1, Ordering::AcqRel);

        assert!(
            rows(d).iter().all(|r| r.3 == "stale-answer"),
            "not one row may be re-parsed while a job runs"
        );
        assert!(
            d.with_index(|ix| Some(ix.kv_get("quality_v10").is_none()))
                .expect("the index is open"),
            "and nothing may stamp the key it never earned - a stamp here \
             would abandon every un-healed row for good"
        );
    });
}
