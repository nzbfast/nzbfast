use super::*;
use crate::index::testutil::{entry, teardown};

const REAL_NAME: &str = "Real.Show.S01E01.1080p.WEB-DL.x264-GRP";

fn open(name: &str) -> (std::path::PathBuf, Index) {
    let dir =
        std::env::temp_dir().join(format!("nzbfast-seed-replay-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    (dir, ix)
}

fn spec<'a>(source: &'a str, guid: &'a str, name: &'a str) -> NzbSeedSpec<'a> {
    NzbSeedSpec {
        source,
        source_guid: guid,
        name,
        category: "tv",
        posted: 1_700_000_000,
        bytes: 9_000,
    }
}

fn seed_usage(ix: &Index) -> (i64, i64, i64, i64) {
    ix.db
        .query_row(
            "SELECT sets,assertions,posted_assertions,charged_bytes
               FROM nzb_seed_usage WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

fn nzb_xml(files: &[(&str, &[&str])]) -> Vec<u8> {
    let mut xml = String::from(r#"<?xml version="1.0"?><nzb>"#);
    for (subject, ids) in files {
        xml.push_str(&format!(
            r#"<file subject="{subject}" poster="p@x" date="1700000000"><groups><group>alt.binaries.test</group></groups><segments>"#
        ));
        for (i, id) in ids.iter().enumerate() {
            xml.push_str(&format!(
                r#"<segment bytes="100" number="{}">{id}</segment>"#,
                i + 1
            ));
        }
        xml.push_str("</segments></file>");
    }
    xml.push_str("</nzb>");
    xml.into_bytes()
}

fn settle_release(ix: &Index, release_id: i64, now: i64) {
    let settled_at = now - SEED_RELEASE_SETTLE_SECS - 1;
    ix.db
        .execute(
            "UPDATE releases SET first_seen=?2,seed_manifest_at=?2 WHERE id=?1",
            rusqlite::params![release_id, settled_at],
        )
        .unwrap();
}

fn ingest_file(ix: &mut Index, group: &str, stem: &str, ids: &[&str], now: i64) -> i64 {
    let entries: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            entry(
                &format!(r#""{stem}.rar" yEnc ({}/{})"#, i + 1, ids.len()),
                "poster@x",
                id,
                900,
            )
        })
        .collect();
    ix.ingest(group, &entries, now).unwrap();
    let release_id = ix
        .db
        .query_row(
            "SELECT id FROM releases WHERE stem=?1 AND grp=?2",
            rusqlite::params![stem, group],
            |r| r.get(0),
        )
        .unwrap();
    settle_release(ix, release_id, now);
    release_id
}

fn ingest_named_file(ix: &mut Index, group: &str, filename: &str, ids: &[&str], now: i64) -> i64 {
    let entries: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            entry(
                &format!(r#""{filename}" yEnc ({}/{})"#, i + 1, ids.len()),
                "poster@x",
                id,
                900,
            )
        })
        .collect();
    ix.ingest(group, &entries, now).unwrap();
    let release_id = ix
        .db
        .query_row(
            "SELECT release_id FROM msgid_map WHERE h=?1 ORDER BY release_id LIMIT 1",
            [claims::msgid_hash(ids[0])],
            |row| row.get(0),
        )
        .unwrap();
    settle_release(ix, release_id, now);
    release_id
}

fn ingest_two_files(
    ix: &mut Index,
    group: &str,
    stem: &str,
    first: &[&str],
    second: &[&str],
    now: i64,
) -> i64 {
    let mut entries = Vec::new();
    for (file_no, ids) in [first, second].into_iter().enumerate() {
        for (part, id) in ids.iter().enumerate() {
            entries.push(entry(
                &format!(
                    r#""{stem}.part{:02}.rar" yEnc ({}/{})"#,
                    file_no + 1,
                    part + 1,
                    ids.len()
                ),
                "poster@x",
                id,
                900,
            ));
        }
    }
    ix.ingest(group, &entries, now).unwrap();
    let release_id = ix
        .db
        .query_row(
            "SELECT id FROM releases WHERE stem=?1 AND grp=?2",
            rusqlite::params![stem, group],
            |r| r.get(0),
        )
        .unwrap();
    settle_release(ix, release_id, now);
    release_id
}

fn ingest_three_files(
    ix: &mut Index,
    group: &str,
    stem: &str,
    first: &[&str],
    second: &[&str],
    third: &[&str],
    now: i64,
) -> i64 {
    let mut entries = Vec::new();
    for (file_no, ids) in [first, second, third].into_iter().enumerate() {
        for (part, id) in ids.iter().enumerate() {
            entries.push(entry(
                &format!(
                    r#""{stem}.part{:02}.rar" yEnc ({}/{})"#,
                    file_no + 1,
                    part + 1,
                    ids.len()
                ),
                "poster@x",
                id,
                900,
            ));
        }
    }
    ix.ingest(group, &entries, now).unwrap();
    let release_id = ix
        .db
        .query_row(
            "SELECT id FROM releases WHERE stem=?1 AND grp=?2",
            rusqlite::params![stem, group],
            |r| r.get(0),
        )
        .unwrap();
    settle_release(ix, release_id, now);
    release_id
}

fn applied_name(ix: &Index, rid: i64) -> String {
    ix.db
        .query_row("SELECT pre_title FROM releases WHERE id=?1", [rid], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn assertion_lookup_is_read_only_and_uses_store_normalization() {
    let (dir, mut ix) = open("assertion-lookup");
    assert!(!ix.nzb_seed_schema_present().unwrap());
    assert!(
        !ix.nzb_seed_assertion_exists(" user-upload ", " sha256:one ", REAL_NAME)
            .unwrap()
    );
    assert!(
        !ix.nzb_seed_strong_assertion_exists(" user-upload ", " sha256:one ", REAL_NAME)
            .unwrap()
    );
    assert!(
        !ix.nzb_seed_schema_present().unwrap(),
        "a lookup must not install the optional seed schema"
    );

    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["lookup1@x", "lookup2@x", "lookup3@x"],
    )]);
    ix.nzb_seed_store_xml(
        spec(
            " user-upload ",
            " sha256:one ",
            &format!(" {REAL_NAME}.NZb "),
        ),
        &xml,
        10,
    )
    .unwrap();

    assert!(
        ix.nzb_seed_assertion_exists("user-upload", "sha256:one", REAL_NAME)
            .unwrap()
    );
    assert!(
        ix.nzb_seed_strong_assertion_exists("user-upload", "sha256:one", REAL_NAME)
            .unwrap()
    );
    assert!(
        ix.nzb_seed_assertion_exists(
            " user-upload ",
            " sha256:one ",
            &format!(" {REAL_NAME}.nzb ")
        )
        .unwrap()
    );
    assert!(
        !ix.nzb_seed_assertion_exists("user-upload", "sha256:other", REAL_NAME)
            .unwrap()
    );
    assert!(
        !ix.nzb_seed_assertion_exists("user-upload", "sha256:one", "Other.Release")
            .unwrap()
    );
    teardown(&dir, ix);
}

#[test]
fn strong_assertion_lookup_rejects_a_keyless_legacy_set_until_same_source_reacquisition() {
    let (dir, mut ix) = open("strong-assertion-lookup-legacy");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["strong1@x", "strong2@x", "strong3@x"],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("nzb-add", "same-guid", REAL_NAME), &xml, 10)
        .unwrap();
    assert!(
        ix.nzb_seed_strong_assertion_exists("nzb-add", "same-guid", REAL_NAME)
            .unwrap()
    );

    let parsed = crate::nzb::Nzb::parse(&xml).unwrap();
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2 WHERE id=?1",
            rusqlite::params![stored.set_id, membership_key(&parsed)],
        )
        .unwrap();
    assert!(
        !ix.nzb_seed_strong_assertion_exists("nzb-add", "same-guid", REAL_NAME)
            .unwrap(),
        "complete file keys under a legacy MD5 identity are still reacquired"
    );
    ix.db
        .execute_batch("DROP TABLE nzb_seed_file_keys")
        .unwrap();
    assert!(!ix.nzb_seed_file_key_schema_present().unwrap());
    assert!(
        ix.nzb_seed_assertion_exists("nzb-add", "same-guid", REAL_NAME)
            .unwrap(),
        "the legacy sampled assertion itself still exists"
    );
    assert!(
        !ix.nzb_seed_strong_assertion_exists("nzb-add", "same-guid", REAL_NAME)
            .unwrap(),
        "a keyless legacy assertion must not suppress reacquisition"
    );
    assert!(
        !ix.nzb_seed_file_key_schema_present().unwrap(),
        "the strong lookup must not recreate the optional file-key schema"
    );

    let reacquired = ix
        .nzb_seed_store_xml(spec("nzb-add", "same-guid", REAL_NAME), &xml, 20)
        .unwrap();
    assert_ne!(reacquired.set_id, stored.set_id);
    assert!(reacquired.new_set && reacquired.new_assertion);
    assert!(
        ix.nzb_seed_strong_assertion_exists("nzb-add", "same-guid", REAL_NAME)
            .unwrap(),
        "the same source assertion is complete after strong reacquisition"
    );
    teardown(&dir, ix);
}

#[test]
fn strong_assertion_lookup_recomputes_equal_count_file_keys_before_suppressing_reacquisition() {
    let (dir, mut ix) = open("strong-assertion-lookup-corrupt-key");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &[
            "lookup-corrupt1@x",
            "lookup-corrupt2@x",
            "lookup-corrupt3@x",
        ],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("nzb-add", "corrupt-guid", REAL_NAME), &xml, 10)
        .unwrap();
    assert!(
        ix.nzb_seed_strong_assertion_exists("nzb-add", "corrupt-guid", REAL_NAME)
            .unwrap()
    );

    ix.db
        .execute(
            "UPDATE nzb_seed_file_keys SET manifest_key=?2
              WHERE set_id=?1 AND file_ord=0",
            rusqlite::params![stored.set_id, "0".repeat(64)],
        )
        .unwrap();
    assert!(
        !ix.nzb_seed_strong_assertion_exists("nzb-add", "corrupt-guid", REAL_NAME)
            .unwrap(),
        "a SHA-looking but inconsistent manifest must not suppress reacquisition"
    );
    teardown(&dir, ix);
}

#[test]
fn strong_assertion_lookup_rejects_an_orphan_file_key_row() {
    let (dir, mut ix) = open("strong-assertion-lookup-orphan-key");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["orphan-key1@x", "orphan-key2@x", "orphan-key3@x"],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("nzb-add", "orphan-guid", REAL_NAME), &xml, 10)
        .unwrap();
    assert!(
        ix.nzb_seed_strong_assertion_exists("nzb-add", "orphan-guid", REAL_NAME)
            .unwrap()
    );

    ix.db
        .execute(
            "INSERT INTO nzb_seed_file_keys(set_id,file_ord,kind,manifest_key)
             VALUES(?1,999,0,?2)",
            rusqlite::params![stored.set_id, format!("sha256:{}", "0".repeat(64))],
        )
        .unwrap();
    assert!(
        !ix.nzb_seed_strong_assertion_exists("nzb-add", "orphan-guid", REAL_NAME)
            .unwrap(),
        "an orphan key row must not make a corrupt set look complete"
    );
    teardown(&dir, ix);
}

#[test]
fn assertion_lookup_rejects_metadata_exactly_like_store() {
    let (dir, mut ix) = open("assertion-lookup-invalid");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["invalid1@x", "invalid2@x", "invalid3@x"],
    )]);
    let parsed = crate::nzb::Nzb::parse(&xml).unwrap();

    for (source, guid, name) in [
        ("", "guid", REAL_NAME),
        ("source", "", REAL_NAME),
        ("source", "guid", " .nzb "),
        ("sou\nrce", "guid", REAL_NAME),
    ] {
        let lookup_error = ix
            .nzb_seed_assertion_exists(source, guid, name)
            .unwrap_err()
            .to_string();
        let strong_lookup_error = ix
            .nzb_seed_strong_assertion_exists(source, guid, name)
            .unwrap_err()
            .to_string();
        let store_error = ix
            .nzb_seed_store(spec(source, guid, name), &parsed, 10)
            .unwrap_err()
            .to_string();
        assert_eq!(lookup_error, store_error);
        assert_eq!(strong_lookup_error, store_error);
    }

    let long_source = "x".repeat(129);
    let lookup_error = ix
        .nzb_seed_assertion_exists(&long_source, "guid", REAL_NAME)
        .unwrap_err()
        .to_string();
    let store_error = ix
        .nzb_seed_store(spec(&long_source, "guid", REAL_NAME), &parsed, 10)
        .unwrap_err()
        .to_string();
    assert_eq!(lookup_error, store_error);
    assert!(!ix.nzb_seed_schema_present().unwrap());
    teardown(&dir, ix);
}

#[test]
fn a_seed_missed_today_replays_after_the_articles_arrive_and_after_reopen() {
    let (dir, mut ix) = open("delayed");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["late1@x", "late2@x", "late3@x"],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-1", REAL_NAME), &xml, 10)
        .unwrap();
    assert!(stored.new_set && stored.probe_complete);
    let first = ix.nzb_seed_reconcile(20, 10).unwrap();
    assert_eq!(first.sets_unmatched, 1, "{first:?}");

    drop(ix);
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    let rid = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "aB7kQ2mZ9xP4vN6tR",
        &["late1@x", "late2@x", "late3@x"],
        30,
    );
    let second = ix.nzb_seed_reconcile(40, 10).unwrap();
    assert_eq!(second.claims_applied, 1, "{second:?}");
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    assert_eq!(ix.nzb_seed_inventory().unwrap().named_release_edges, 1);
    teardown(&dir, ix);
}

#[test]
fn guarded_reconcile_rolls_back_when_foreground_work_arrives_mid_scan() {
    let (dir, mut ix) = open("guarded-reconcile");
    let ids = ["yield1@x", "yield2@x", "yield3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "yield", REAL_NAME), &xml, 10)
        .unwrap();
    let a = ingest_file(&mut ix, "alt.binaries.one", "aB7kQ2mZ9xP4vN6tR", &ids, 20);
    let b = ingest_file(&mut ix, "alt.binaries.two", "bC8mR3nA1yQ5wP7uS", &ids, 20);
    let calls = std::cell::Cell::new(0usize);
    let deferred = ix
        .nzb_seed_reconcile_set_guarded(stored.set_id, 30, || {
            calls.set(calls.get() + 1);
            calls.get() <= 6
        })
        .unwrap();
    assert!(deferred.is_none());
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    assert!(ix.name_claims(a).unwrap().is_empty());
    assert!(ix.name_claims(b).unwrap().is_empty());

    let retried = ix.nzb_seed_reconcile_set(stored.set_id, 40).unwrap();
    assert_eq!(retried.claims_applied, 2, "{retried:?}");
    assert_eq!(applied_name(&ix, a), REAL_NAME);
    assert_eq!(applied_name(&ix, b), REAL_NAME);
    teardown(&dir, ix);
}

#[test]
fn guarded_reconcile_can_yield_after_decoding_one_large_file() {
    let (dir, mut ix) = open("guarded-large-file");
    let ids = ["large1@x", "large2@x", "large3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "large-file", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "cD9nS4pB2zR6xQ8vT", &ids, 20);
    let mut segments: Vec<crate::index::segcodec::Seg> = ids
        .iter()
        .enumerate()
        .map(|(index, id)| ((index + 1) as u32, format!("<{id}>"), 900))
        .collect();
    segments.extend(
        (4..=1_024).map(|number| (number, format!("<unrelated-large-{number:04}@x>"), 900)),
    );
    ix.db
        .execute(
            "UPDATE files SET total_parts=?2,segments=?3 WHERE release_id=?1",
            rusqlite::params![
                rid,
                segments.len() as i64,
                crate::index::segcodec::encode(&segments)
            ],
        )
        .unwrap();

    let calls = std::cell::Cell::new(0usize);
    let deferred = ix
        .nzb_seed_reconcile_set_guarded(stored.set_id, 30, || {
            calls.set(calls.get() + 1);
            // Candidate discovery and chunked decode complete first. The
            // refusal lands in the guarded post-decode Message-ID walk.
            calls.get() <= 29
        })
        .unwrap();
    assert!(deferred.is_none());
    assert_eq!(calls.get(), 30);
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    assert!(ix.name_claims(rid).unwrap().is_empty());

    let retried = ix.nzb_seed_reconcile_set(stored.set_id, 40).unwrap();
    assert_eq!(retried.sets_partial, 1, "{retried:?}");
    assert_eq!(retried.claims_applied, 0, "{retried:?}");
    assert_eq!(applied_name(&ix, rid), "");
    teardown(&dir, ix);
}

#[test]
fn hash_candidate_prefilter_checks_the_guard_between_indexed_rows() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (dir, mut ix) = open("guarded-hash-prefilter");
    let ids = ["prefilter1@x", "prefilter2@x", "prefilter3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "prefilter", REAL_NAME), &xml, 10)
        .unwrap();
    let hash: i64 = ix
        .db
        .query_row(
            "SELECT h FROM nzb_seed_msgids WHERE set_id=?1 ORDER BY part_ord LIMIT 1",
            [stored.set_id],
            |row| row.get(0),
        )
        .unwrap();
    ix.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    for release_id in 1..=(SEED_CANDIDATE_CAP + 1) as i64 {
        ix.db
            .execute(
                "INSERT INTO msgid_map(h,release_id) VALUES(?1,?2)",
                rusqlite::params![hash, release_id],
            )
            .unwrap();
    }
    ix.db.execute_batch("COMMIT").unwrap();

    let opcodes = Arc::new(AtomicUsize::new(0));
    let progress = Arc::clone(&opcodes);
    ix.db
        .progress_handler(
            100,
            Some(move || {
                progress.fetch_add(100, Ordering::Relaxed);
                false
            }),
        )
        .unwrap();
    let previous = std::cell::Cell::new(0usize);
    let largest_gap = std::cell::Cell::new(0usize);
    let result = ix
        .nzb_seed_reconcile_set_guarded(stored.set_id, 30, || {
            let now = opcodes.load(Ordering::Relaxed);
            largest_gap.set(largest_gap.get().max(now.saturating_sub(previous.get())));
            previous.set(now);
            largest_gap.get() < 5_000
        })
        .unwrap();
    ix.db.progress_handler(100, None::<fn() -> bool>).unwrap();
    let stats = result.expect("indexed row probes must not outrun the guard");
    assert_eq!(stats.sets_saturated, 1, "{stats:?}");
    assert!(
        largest_gap.get() < 5_000,
        "gap was {} opcodes",
        largest_gap.get()
    );
    teardown(&dir, ix);
}

#[test]
fn exact_match_edges_stop_at_the_derived_fanout_boundary() {
    for (case, releases, saturated) in [
        ("match-edge-at-cap", SEED_MATCH_EDGE_CAP, false),
        ("match-edge-over-cap", SEED_MATCH_EDGE_CAP + 1, true),
    ] {
        let (dir, mut ix) = open(case);
        let ids = ["edge1@x", "edge2@x", "edge3@x"];
        let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
        let stored = ix
            .nzb_seed_store_xml(spec("licensed", case, REAL_NAME), &xml, 10)
            .unwrap();
        let mut release_ids = Vec::new();
        for group in 0..releases {
            release_ids.push(ingest_file(
                &mut ix,
                &format!("alt.binaries.edge.{group:03}"),
                "eF1pU6qC4aS8zR3vN",
                &ids,
                20,
            ));
        }
        let stats = ix.nzb_seed_reconcile_set(stored.set_id, 30).unwrap();
        assert_eq!(stats.sets_saturated, usize::from(saturated), "{stats:?}");
        if saturated {
            assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
            for &release_id in &release_ids {
                assert_eq!(applied_name(&ix, release_id), "");
                assert!(ix.name_claims(release_id).unwrap().is_empty());
            }
        } else {
            assert_eq!(
                ix.nzb_seed_matches(stored.set_id).unwrap().len(),
                SEED_MATCH_EDGE_CAP
            );
            for &release_id in &release_ids {
                assert_eq!(applied_name(&ix, release_id), REAL_NAME);
            }
            let extra = ingest_file(
                &mut ix,
                "alt.binaries.edge.overflow",
                "eF1pU6qC4aS8zR3vN",
                &ids,
                40,
            );
            release_ids.push(extra);
            let overflow = ix.nzb_seed_reconcile_set(stored.set_id, 50).unwrap();
            assert_eq!(overflow.sets_saturated, 1, "{overflow:?}");
            assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
            for release_id in release_ids {
                assert_eq!(applied_name(&ix, release_id), "");
                assert!(ix.name_claims(release_id).unwrap().is_empty());
            }
        }
        teardown(&dir, ix);
    }
}

#[test]
fn duplicate_acquisition_and_replay_are_idempotent() {
    let (dir, mut ix) = open("idempotent");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["idem1@x", "idem2@x", "idem3@x"],
    )]);
    let a = ix
        .nzb_seed_store_xml(spec("licensed", "same", REAL_NAME), &xml, 10)
        .unwrap();
    let b = ix
        .nzb_seed_store_xml(spec("licensed", "same", REAL_NAME), &xml, 11)
        .unwrap();
    assert_eq!(a.set_id, b.set_id);
    assert!(!b.new_set && !b.new_assertion);
    let c = ix
        .nzb_seed_store_xml(spec("user-upload", "other", REAL_NAME), &xml, 12)
        .unwrap();
    assert_eq!(a.set_id, c.set_id, "same membership is one origin");
    assert!(c.new_assertion);
    assert_eq!(ix.nzb_seed_inventory().unwrap().assertions, 2);

    let rid = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "jK8mQ3vT7xN2pR5zB",
        &["idem1@x", "idem2@x", "idem3@x"],
        20,
    );
    let first = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(first.claims_applied, 1, "{first:?}");
    assert!(!first.cycle_wrapped, "first cursor pass wrapped: {first:?}");
    let second = ix.nzb_seed_reconcile(40, 10).unwrap();
    assert_eq!(second.claims_confirmed, 1, "{second:?}");
    assert!(
        second.cycle_wrapped,
        "second cursor pass did not wrap: {second:?}"
    );
    assert_eq!(ix.name_claims(rid).unwrap().len(), 1);
    teardown(&dir, ix);
}

#[test]
fn an_exact_duplicate_succeeds_when_every_seed_capacity_counter_is_full() {
    let (dir, mut ix) = open("capacity-idempotent");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["full1@x", "full2@x", "full3@x"],
    )]);
    ix.nzb_seed_store_xml(spec("licensed", "full", REAL_NAME), &xml, 10)
        .unwrap();
    ix.db
        .execute(
            "UPDATE nzb_seed_usage
                SET sets=?1,assertions=?2,posted_assertions=?3,charged_bytes=?4
              WHERE id=1",
            rusqlite::params![
                SEED_SET_CAP,
                SEED_ASSERTIONS_CAP,
                SEED_ASSERTION_CLASS_CAP,
                SEED_CHARGED_BYTES_CAP
            ],
        )
        .unwrap();

    let duplicate = ix
        .nzb_seed_store_xml(spec("licensed", "full", REAL_NAME), &xml, 20)
        .unwrap();
    assert!(!duplicate.new_set && !duplicate.new_assertion);
    assert_eq!(
        seed_usage(&ix),
        (
            SEED_SET_CAP,
            SEED_ASSERTIONS_CAP,
            SEED_ASSERTION_CLASS_CAP,
            SEED_CHARGED_BYTES_CAP
        )
    );
    teardown(&dir, ix);
}

#[test]
fn set_and_total_assertion_capacity_accept_the_boundary_then_rollback_the_next() {
    {
        let (dir, mut ix) = open("capacity-set-boundary");
        let a = nzb_xml(&[(
            r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
            &["seta1@x", "seta2@x", "seta3@x"],
        )]);
        let b = nzb_xml(&[(
            r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
            &["setb1@x", "setb2@x", "setb3@x"],
        )]);
        let c = nzb_xml(&[(
            r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
            &["setc1@x", "setc2@x", "setc3@x"],
        )]);
        ix.nzb_seed_store_xml(spec("licensed", "set-a", REAL_NAME), &a, 10)
            .unwrap();
        ix.db
            .execute(
                "UPDATE nzb_seed_usage SET sets=?1 WHERE id=1",
                [SEED_SET_CAP - 1],
            )
            .unwrap();
        ix.nzb_seed_store_xml(spec("licensed", "set-b", REAL_NAME), &b, 20)
            .unwrap();
        assert_eq!(seed_usage(&ix).0, SEED_SET_CAP);
        let at_cap = seed_usage(&ix);
        assert!(matches!(
            ix.nzb_seed_store_xml(spec("licensed", "set-c", REAL_NAME), &c, 30),
            Err(NzbSeedError::Capacity("set limit"))
        ));
        assert_eq!(seed_usage(&ix), at_cap);
        assert_eq!(ix.nzb_seed_inventory().unwrap().sets, 2);
        teardown(&dir, ix);
    }

    {
        let (dir, mut ix) = open("capacity-assertion-boundary");
        let xml = nzb_xml(&[(
            r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
            &["asta1@x", "asta2@x", "asta3@x"],
        )]);
        ix.nzb_seed_store_xml(spec("licensed", "assert-a", REAL_NAME), &xml, 10)
            .unwrap();
        ix.db
            .execute(
                "UPDATE nzb_seed_usage
                    SET assertions=?1,posted_assertions=?2 WHERE id=1",
                rusqlite::params![SEED_ASSERTIONS_CAP - 1, SEED_ASSERTION_CLASS_CAP],
            )
            .unwrap();
        ix.nzb_seed_store_xml(spec("licensed", "assert-b", REAL_NAME), &xml, 20)
            .unwrap();
        assert_eq!(seed_usage(&ix).1, SEED_ASSERTIONS_CAP);
        let at_cap = seed_usage(&ix);
        assert!(matches!(
            ix.nzb_seed_store_xml(spec("licensed", "assert-c", REAL_NAME), &xml, 30),
            Err(NzbSeedError::Capacity("assertion limit"))
        ));
        assert_eq!(seed_usage(&ix), at_cap);
        assert_eq!(ix.nzb_seed_inventory().unwrap().assertions, 2);
        teardown(&dir, ix);
    }
}

#[test]
fn posted_and_trusted_assertion_classes_have_independent_boundaries() {
    {
        let (dir, mut ix) = open("capacity-trusted-boundary");
        let xml = nzb_xml(&[(
            r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
            &["trst1@x", "trst2@x", "trst3@x"],
        )]);
        ix.nzb_seed_store_xml(spec("licensed", "trusted-a", REAL_NAME), &xml, 10)
            .unwrap();
        ix.db
            .execute(
                "UPDATE nzb_seed_usage
                    SET assertions=?1,posted_assertions=0 WHERE id=1",
                [SEED_ASSERTION_CLASS_CAP - 1],
            )
            .unwrap();
        ix.nzb_seed_store_xml(spec("licensed", "trusted-b", REAL_NAME), &xml, 20)
            .unwrap();
        assert_eq!(
            seed_usage(&ix).1 - seed_usage(&ix).2,
            SEED_ASSERTION_CLASS_CAP
        );
        let at_cap = seed_usage(&ix);
        assert!(matches!(
            ix.nzb_seed_store_xml(spec("licensed", "trusted-c", REAL_NAME), &xml, 30),
            Err(NzbSeedError::Capacity("trusted assertion limit"))
        ));
        assert_eq!(seed_usage(&ix), at_cap);
        teardown(&dir, ix);
    }

    {
        let (dir, mut ix) = open("capacity-posted-boundary");
        let xml = nzb_xml(&[(
            r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
            &["post1@x", "post2@x", "post3@x"],
        )]);
        ix.nzb_seed_store_xml(
            spec(NZB_SEED_POSTED_SOURCE, "posted-a", REAL_NAME),
            &xml,
            10,
        )
        .unwrap();
        ix.db
            .execute(
                "UPDATE nzb_seed_usage
                    SET assertions=?1,posted_assertions=?1 WHERE id=1",
                [SEED_ASSERTION_CLASS_CAP - 1],
            )
            .unwrap();
        ix.nzb_seed_store_xml(
            spec(NZB_SEED_POSTED_SOURCE, "posted-b", REAL_NAME),
            &xml,
            20,
        )
        .unwrap();
        assert_eq!(seed_usage(&ix).2, SEED_ASSERTION_CLASS_CAP);
        let at_cap = seed_usage(&ix);
        assert!(matches!(
            ix.nzb_seed_store_xml(
                spec(NZB_SEED_POSTED_SOURCE, "posted-c", REAL_NAME),
                &xml,
                30
            ),
            Err(NzbSeedError::Capacity("posted assertion limit"))
        ));
        assert_eq!(seed_usage(&ix), at_cap);
        teardown(&dir, ix);
    }
}

#[test]
fn posted_sets_cannot_consume_the_trusted_set_reserve() {
    let (dir, mut ix) = open("capacity-posted-set-reserve");
    let a = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["pseta1@x", "pseta2@x", "pseta3@x"],
    )]);
    let b = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["psetb1@x", "psetb2@x", "psetb3@x"],
    )]);
    let c = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["psetc1@x", "psetc2@x", "psetc3@x"],
    )]);
    ix.nzb_seed_store_xml(spec(NZB_SEED_POSTED_SOURCE, "pset-a", REAL_NAME), &a, 10)
        .unwrap();
    ix.db
        .execute(
            "UPDATE nzb_seed_usage SET sets=?1 WHERE id=1",
            [SEED_POSTED_SET_CAP - 1],
        )
        .unwrap();
    ix.nzb_seed_store_xml(spec(NZB_SEED_POSTED_SOURCE, "pset-b", REAL_NAME), &b, 20)
        .unwrap();
    assert_eq!(seed_usage(&ix).0, SEED_POSTED_SET_CAP);
    let at_public_cap = seed_usage(&ix);
    assert!(matches!(
        ix.nzb_seed_store_xml(spec(NZB_SEED_POSTED_SOURCE, "pset-c", REAL_NAME), &c, 30),
        Err(NzbSeedError::Capacity("posted set reserve"))
    ));
    assert_eq!(seed_usage(&ix), at_public_cap);

    ix.nzb_seed_store_xml(spec("licensed", "pset-c", REAL_NAME), &c, 40)
        .unwrap();
    assert_eq!(seed_usage(&ix).0, SEED_POSTED_SET_CAP + 1);
    teardown(&dir, ix);
}

#[test]
fn posted_bytes_cannot_consume_the_trusted_byte_reserve() {
    let (dir, mut ix) = open("capacity-posted-byte-reserve");
    let a = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["pbytea1@x", "pbytea2@x", "pbytea3@x"],
    )]);
    let b = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["pbyteb1@x", "pbyteb2@x", "pbyteb3@x"],
    )]);
    let c = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["pbytec1@x", "pbytec2@x", "pbytec3@x"],
    )]);
    ix.nzb_seed_store_xml(spec(NZB_SEED_POSTED_SOURCE, "pbyte-a", REAL_NAME), &a, 10)
        .unwrap();
    let equal_shape_charge = seed_usage(&ix).3;
    ix.db
        .execute(
            "UPDATE nzb_seed_usage SET charged_bytes=?1 WHERE id=1",
            [SEED_POSTED_CHARGED_BYTES_CAP - equal_shape_charge],
        )
        .unwrap();
    ix.nzb_seed_store_xml(spec(NZB_SEED_POSTED_SOURCE, "pbyte-b", REAL_NAME), &b, 20)
        .unwrap();
    assert_eq!(seed_usage(&ix).3, SEED_POSTED_CHARGED_BYTES_CAP);
    let at_public_cap = seed_usage(&ix);
    assert!(matches!(
        ix.nzb_seed_store_xml(spec(NZB_SEED_POSTED_SOURCE, "pbyte-c", REAL_NAME), &c, 30),
        Err(NzbSeedError::Capacity("posted charged-byte reserve"))
    ));
    assert_eq!(seed_usage(&ix), at_public_cap);

    ix.nzb_seed_store_xml(spec("licensed", "pbyte-c", REAL_NAME), &c, 40)
        .unwrap();
    assert!(seed_usage(&ix).3 > SEED_POSTED_CHARGED_BYTES_CAP);
    assert!(seed_usage(&ix).3 < SEED_CHARGED_BYTES_CAP);
    teardown(&dir, ix);
}

#[test]
fn charged_byte_capacity_accepts_the_exact_boundary_then_rejects_one_more_row() {
    let (dir, mut ix) = open("capacity-bytes-boundary");
    let a = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["chargea1@x", "chargea2@x", "chargea3@x"],
    )]);
    let b = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["chargeb1@x", "chargeb2@x", "chargeb3@x"],
    )]);
    let c = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["chargec1@x", "chargec2@x", "chargec3@x"],
    )]);
    ix.nzb_seed_store_xml(spec("licensed", "charge-a", REAL_NAME), &a, 10)
        .unwrap();
    let one_seed_charge = seed_usage(&ix).3;
    assert!(one_seed_charge > 0 && one_seed_charge < SEED_CHARGED_BYTES_CAP);
    ix.db
        .execute(
            "UPDATE nzb_seed_usage SET charged_bytes=?1 WHERE id=1",
            [SEED_CHARGED_BYTES_CAP - one_seed_charge],
        )
        .unwrap();
    ix.nzb_seed_store_xml(spec("licensed", "charge-b", REAL_NAME), &b, 20)
        .unwrap();
    assert_eq!(seed_usage(&ix).3, SEED_CHARGED_BYTES_CAP);
    let at_cap = seed_usage(&ix);
    assert!(matches!(
        ix.nzb_seed_store_xml(spec("licensed", "charge-c", REAL_NAME), &c, 30),
        Err(NzbSeedError::Capacity("charged-byte limit"))
    ));
    assert_eq!(seed_usage(&ix), at_cap);
    assert_eq!(ix.nzb_seed_inventory().unwrap().sets, 2);
    teardown(&dir, ix);
}

#[test]
fn an_existing_capacity_schema_repair_survives_a_rejected_admission() {
    let (dir, mut ix) = open("capacity-repair-before-rejection");
    let first = nzb_xml(&[(
        r#"&quot;first.mkv&quot; yEnc (1/3)"#,
        &["repair-a1@x", "repair-a2@x", "repair-a3@x"],
    )]);
    let second = nzb_xml(&[(
        r#"&quot;second.mkv&quot; yEnc (1/3)"#,
        &["repair-b1@x", "repair-b2@x", "repair-b3@x"],
    )]);
    ix.nzb_seed_store_xml(spec("licensed", "repair-a", REAL_NAME), &first, 10)
        .unwrap();
    ix.db
        .execute_batch("DROP INDEX idx_nzb_seed_assertions_trusted")
        .unwrap();
    ix.db
        .execute(
            "UPDATE nzb_seed_usage SET charged_bytes=?1 WHERE id=1",
            [SEED_CHARGED_BYTES_CAP],
        )
        .unwrap();
    assert!(!ix.nzb_seed_capacity_schema_present().unwrap());

    assert!(matches!(
        ix.nzb_seed_store_xml(spec("licensed", "repair-b", REAL_NAME), &second, 20),
        Err(NzbSeedError::Capacity("charged-byte limit"))
    ));
    assert!(
        ix.nzb_seed_capacity_schema_present().unwrap(),
        "capacity rejection rolled the existing-catalog repair back"
    );
    assert_eq!(ix.nzb_seed_inventory().unwrap().sets, 1);
    teardown(&dir, ix);
}

#[test]
fn a_split_pack_becomes_a_fragment_edge_not_two_wrong_names() {
    let (dir, mut ix) = open("fragmented");
    let xml = nzb_xml(&[
        (
            r#"&quot;episode01.mkv&quot; yEnc (1/3)"#,
            &["ep1a@x", "ep1b@x", "ep1c@x"],
        ),
        (
            r#"&quot;episode02.mkv&quot; yEnc (1/3)"#,
            &["ep2a@x", "ep2b@x", "ep2c@x"],
        ),
    ]);
    let stored = ix
        .nzb_seed_store_xml(
            spec("licensed", "pack", "Real.Show.S01.1080p.WEB-GRP"),
            &xml,
            10,
        )
        .unwrap();
    let a = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "rT6pL2mQ9xV4nK7zA",
        &["ep1a@x", "ep1b@x", "ep1c@x"],
        20,
    );
    let b = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "sU7qM3nR8yW5pL2xB",
        &["ep2a@x", "ep2b@x", "ep2c@x"],
        20,
    );
    let stats = ix.nzb_seed_reconcile_set(stored.set_id, 30).unwrap();
    assert_eq!(stats.sets_fragmented, 1, "{stats:?}");
    assert_eq!(stats.claims_applied, 0);
    assert_eq!(applied_name(&ix, a), "");
    assert_eq!(applied_name(&ix, b), "");
    let matches = ix.nzb_seed_matches(stored.set_id).unwrap();
    assert_eq!(matches.len(), 2);
    assert!(matches.iter().all(|m| m.state == "partial"));
    assert_eq!(ix.nzb_seed_inventory().unwrap().fragmented_sets, 1);
    teardown(&dir, ix);
}

#[test]
fn a_fragmented_seed_exports_one_named_collection_without_naming_its_shards() {
    let (dir, mut ix) = open("fragmented-collection");
    let first = ["collect-a1@x", "collect-a2@x", "collect-a3@x"];
    let second = ["collect-b1@x", "collect-b2@x", "collect-b3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;episode01.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;episode02.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(
            spec("licensed", "collection", "Real.Show.S01.1080p.WEB-GRP"),
            &xml,
            10,
        )
        .unwrap();
    let a = ingest_file(&mut ix, "alt.binaries.one", "nK4sY8vC2mQ6pR9tA", &first, 20);
    let b = ingest_file(
        &mut ix,
        "alt.binaries.two",
        "oL5tZ9wD3nR7qS2uB",
        &second,
        20,
    );
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_fragmented, 1, "{stats:?}");

    let collection = ix
        .make_nzb_seed_collection(stored.set_id)
        .unwrap()
        .expect("exact shard union should export");
    assert_eq!(collection.name, "Real.Show.S01.1080p.WEB-GRP");
    assert_eq!(collection.data_files, 2);
    assert_eq!(collection.optional_files, 0);
    assert_eq!(collection.release_ids, vec![a, b]);
    assert_eq!(applied_name(&ix, a), "");
    assert_eq!(applied_name(&ix, b), "");
    let parsed = crate::nzb::Nzb::parse(collection.xml.as_bytes()).unwrap();
    assert_eq!(
        collection.bytes, 5_400,
        "local encoded bytes are authoritative"
    );
    assert_eq!(collection.bytes, parsed.total_bytes());
    assert_eq!(parsed.files.len(), 2);
    assert!(parsed.meta.contains(&(
        "title".to_string(),
        "Real.Show.S01.1080p.WEB-GRP".to_string()
    )));
    let ids: std::collections::HashSet<_> = parsed
        .files
        .iter()
        .flat_map(|file| {
            file.segments
                .iter()
                .map(|segment| segment.message_id.as_str())
        })
        .collect();
    assert_eq!(ids.len(), 6);
    assert!(first.into_iter().chain(second).all(|id| ids.contains(id)));
    let round_trip = ix
        .nzb_seed_store_xml(
            spec("round-trip", "collection-copy", &collection.name),
            collection.xml.as_bytes(),
            31,
        )
        .unwrap();
    assert_eq!(round_trip.set_id, stored.set_id);
    assert_eq!(round_trip.membership_key, stored.membership_key);
    teardown(&dir, ix);
}

#[test]
fn a_complete_collection_can_export_before_cursor_reconciliation() {
    let (dir, mut ix) = open("collection-before-replay");
    let first = ["early-a1@x", "early-a2@x", "early-a3@x"];
    let second = ["early-b1@x", "early-b2@x", "early-b3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "early", REAL_NAME), &xml, 10)
        .unwrap();
    let a = ingest_file(&mut ix, "alt.binaries.one", "fD6kS2pW4eJ8hL3nU", &first, 20);
    let b = ingest_file(
        &mut ix,
        "alt.binaries.two",
        "gE7mT3qX5fK9iM4oV",
        &second,
        20,
    );

    let state: String = ix
        .db
        .query_row(
            "SELECT state FROM nzb_seed_sets WHERE id=?1",
            [stored.set_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "pending");
    let collection = ix
        .make_nzb_seed_collection(stored.set_id)
        .unwrap()
        .expect("the on-demand proof does not depend on cached replay state");
    assert_eq!(collection.release_ids, vec![a, b]);
    assert_eq!(applied_name(&ix, a), "");
    assert_eq!(applied_name(&ix, b), "");
    teardown(&dir, ix);
}

#[test]
fn one_local_superset_exports_only_the_exact_seed_files() {
    let (dir, mut ix) = open("collection-one-superset");
    let first = ["super-a1@x", "super-a2@x", "super-a3@x"];
    let second = ["super-b1@x", "super-b2@x", "super-b3@x"];
    let extra = ["super-x1@x", "super-x2@x", "super-x3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "one-superset", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_three_files(
        &mut ix,
        "alt.binaries.test",
        "hF8nU4rY6gL2jN5pW",
        &first,
        &second,
        &extra,
        20,
    );
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_partial, 1, "{stats:?}");
    assert_eq!(applied_name(&ix, rid), "");

    let collection = ix
        .make_nzb_seed_collection(stored.set_id)
        .unwrap()
        .expect("file-level proof can safely select a subset of one local row");
    assert_eq!(collection.release_ids, vec![rid]);
    assert_eq!(collection.data_files, 2);
    assert!(extra.iter().all(|id| !collection.xml.contains(id)));
    teardown(&dir, ix);
}

#[test]
fn collection_export_rejects_a_hash_only_stale_candidate() {
    let (dir, mut ix) = open("collection-hash-only");
    let first = ["true-a1@x", "true-a2@x", "true-a3@x"];
    let second = ["true-b1@x", "true-b2@x", "true-b3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "stale", REAL_NAME), &xml, 10)
        .unwrap();
    let bogus_ids = ["bogus-1@x", "bogus-2@x", "bogus-3@x"];
    let bogus = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "iG9pV5sZ7hM3kP6qX",
        &bogus_ids,
        20,
    );
    for id in first.into_iter().chain(second) {
        ix.db
            .execute(
                "INSERT OR IGNORE INTO msgid_map(h,release_id) VALUES(?1,?2)",
                rusqlite::params![claims::msgid_hash(id), bogus],
            )
            .unwrap();
    }

    assert!(
        ix.make_nzb_seed_collection(stored.set_id)
            .unwrap()
            .is_none(),
        "64-bit hash rows alone are never collection proof"
    );
    teardown(&dir, ix);
}

#[test]
fn collection_local_ids_allow_one_exact_wrapper_but_not_permissive_trimming() {
    let (dir, mut ix) = open("collection-local-id-canonicalization");
    let ids = ["wrap1@x", "wrap2@x", "wrap3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "wrappers", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "jH2qW6tA8iN4mR7sY", &ids, 20);
    assert!(
        ix.make_nzb_seed_collection(stored.set_id)
            .unwrap()
            .is_some(),
        "XOVER's exact <id> wrapper is accepted"
    );

    for malformed in [" <wrap1@x>", "<wrap1@x"] {
        ix.db
            .execute(
                "UPDATE files SET segments=?2 WHERE release_id=?1",
                rusqlite::params![
                    rid,
                    crate::index::segcodec::encode(&[
                        (1, malformed.to_string(), 900),
                        (2, "<wrap2@x>".to_string(), 900),
                        (3, "<wrap3@x>".to_string(), 900),
                    ])
                ],
            )
            .unwrap();
        assert!(
            ix.make_nzb_seed_collection(stored.set_id)
                .unwrap()
                .is_none(),
            "boundary whitespace and one-sided wrappers cannot fabricate an ID"
        );
    }
    teardown(&dir, ix);
}

#[test]
fn collection_export_selects_exact_files_and_omits_an_unrelated_local_sibling() {
    let (dir, mut ix) = open("collection-omit-extra");
    let first = ["keep-a1@x", "keep-a2@x", "keep-a3@x"];
    let second = ["keep-b1@x", "keep-b2@x", "keep-b3@x"];
    let unrelated = ["omit-1@x", "omit-2@x", "omit-3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;wanted-a.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;wanted-b.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "omit", REAL_NAME), &xml, 10)
        .unwrap();
    let _superset = ingest_two_files(
        &mut ix,
        "alt.binaries.one",
        "pM6uA2xE4oS8rT3vC",
        &first,
        &unrelated,
        20,
    );
    let _other = ingest_file(
        &mut ix,
        "alt.binaries.two",
        "qN7vB3yF5pT9sU4wD",
        &second,
        20,
    );
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_fragmented, 1, "{stats:?}");
    let collection = ix
        .make_nzb_seed_collection(stored.set_id)
        .unwrap()
        .expect("the exact files still form a collection");
    assert_eq!(collection.data_files, 2);
    assert!(
        unrelated.iter().all(|id| !collection.xml.contains(id)),
        "{collection:?}"
    );
    teardown(&dir, ix);
}

#[test]
fn collection_export_finds_a_separately_posted_optional_par2_file() {
    let (dir, mut ix) = open("collection-optional-par2");
    let first = ["par-data-a1@x", "par-data-a2@x", "par-data-a3@x"];
    let second = ["par-data-b1@x", "par-data-b2@x", "par-data-b3@x"];
    let parity = ["par-index-1@x", "par-index-2@x", "par-index-3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;wanted-a.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;wanted-b.mkv&quot; yEnc (1/3)"#, &second),
        (r#"&quot;wanted.par2&quot; yEnc (1/3)"#, &parity),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "optional", REAL_NAME), &xml, 10)
        .unwrap();
    let _a = ingest_file(&mut ix, "alt.binaries.one", "rP8wC4zG6qU2tV5xE", &first, 20);
    let _b = ingest_file(
        &mut ix,
        "alt.binaries.two",
        "sQ9xD5aH7rV3uW6yF",
        &second,
        20,
    );
    let par_release = ingest_named_file(
        &mut ix,
        "alt.binaries.parity",
        "tR2yE6bJ8sW4vX7zG.par2",
        &parity,
        20,
    );
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_fragmented, 1, "{stats:?}");
    let collection = ix
        .make_nzb_seed_collection(stored.set_id)
        .unwrap()
        .expect("optional PAR2 is independently discoverable");
    assert_eq!(collection.data_files, 2);
    assert_eq!(collection.optional_files, 1);
    assert!(collection.release_ids.contains(&par_release));
    assert!(parity.iter().all(|id| collection.xml.contains(id)));
    teardown(&dir, ix);
}

#[test]
fn collection_export_revalidates_deletion_and_local_manifest_changes() {
    let (dir, mut ix) = open("collection-revalidate");
    let first = ["fresh-a1@x", "fresh-a2@x", "fresh-a3@x"];
    let second = ["fresh-b1@x", "fresh-b2@x", "fresh-b3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "fresh", REAL_NAME), &xml, 10)
        .unwrap();
    let a = ingest_file(&mut ix, "alt.binaries.one", "uS3zF7cK9tX5wY8aH", &first, 20);
    let b = ingest_file(
        &mut ix,
        "alt.binaries.two",
        "vT4aG8dL2uY6xZ9bJ",
        &second,
        20,
    );
    ix.nzb_seed_reconcile(30, 10).unwrap();
    assert!(
        ix.make_nzb_seed_collection(stored.set_id)
            .unwrap()
            .is_some()
    );

    ix.db
        .execute(
            "UPDATE files SET segments=?2 WHERE release_id=?1",
            rusqlite::params![
                a,
                crate::index::segcodec::encode(&[
                    (1, "changed-a1@x".into(), 900),
                    (2, "changed-a2@x".into(), 900),
                    (3, "changed-a3@x".into(), 900),
                ])
            ],
        )
        .unwrap();
    assert!(
        ix.make_nzb_seed_collection(stored.set_id)
            .unwrap()
            .is_none()
    );

    ix.db
        .execute("DELETE FROM releases WHERE id=?1", [b])
        .unwrap();
    assert!(
        ix.make_nzb_seed_collection(stored.set_id)
            .unwrap()
            .is_none()
    );
    teardown(&dir, ix);
}

#[test]
fn a_legacy_keyless_seed_forks_on_reacquisition_without_inheriting_assertions() {
    let (dir, mut ix) = open("collection-key-upgrade");
    let first = ["legacy-a1@x", "legacy-a2@x", "legacy-a3@x"];
    let second = ["legacy-b1@x", "legacy-b2@x", "legacy-b3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "legacy-a", REAL_NAME), &xml, 10)
        .unwrap();
    let _a = ingest_file(&mut ix, "alt.binaries.one", "wU5bH9eM3vZ7yA2cK", &first, 20);
    let _b = ingest_file(
        &mut ix,
        "alt.binaries.two",
        "xV6cJ2fN4wA8zB3dL",
        &second,
        20,
    );
    ix.nzb_seed_reconcile(30, 10).unwrap();
    let parsed = crate::nzb::Nzb::parse(&xml).unwrap();
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2 WHERE id=?1",
            rusqlite::params![stored.set_id, membership_key(&parsed)],
        )
        .unwrap();
    ix.db
        .execute(
            "DELETE FROM nzb_seed_file_keys WHERE set_id=?1",
            [stored.set_id],
        )
        .unwrap();
    assert!(
        ix.make_nzb_seed_collection(stored.set_id)
            .unwrap()
            .is_none()
    );

    let reacquired = ix
        .nzb_seed_store_xml(spec("licensed", "legacy-b", REAL_NAME), &xml, 40)
        .unwrap();
    assert_ne!(reacquired.set_id, stored.set_id);
    assert!(reacquired.new_set);
    assert!(reacquired.membership_key.starts_with("sha256:"));
    let assertion_sets: Vec<(i64, i64)> = {
        let mut stmt = ix
            .db
            .prepare(
                "SELECT set_id,count(*) FROM nzb_seed_assertions GROUP BY set_id ORDER BY set_id",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    assert_eq!(
        assertion_sets,
        vec![(stored.set_id, 1), (reacquired.set_id, 1)]
    );
    let stats = ix.nzb_seed_reconcile(50, 10).unwrap();
    assert_eq!(stats.sets_fragmented, 1, "{stats:?}");
    assert!(
        ix.make_nzb_seed_collection(stored.set_id)
            .unwrap()
            .is_none()
    );
    assert!(
        ix.make_nzb_seed_collection(reacquired.set_id)
            .unwrap()
            .is_some()
    );
    teardown(&dir, ix);
}

#[test]
fn a_keyless_membership_collision_cannot_inherit_the_old_title() {
    let (dir, mut ix) = open("collection-keyless-collision");
    let old_ids = ["old-a1@x", "old-a2@x", "old-a3@x"];
    let new_ids = ["new-b1@x", "new-b2@x", "new-b3@x"];
    let old_xml = nzb_xml(&[(r#"&quot;old.mkv&quot; yEnc (1/3)"#, &old_ids)]);
    let new_xml = nzb_xml(&[(r#"&quot;new.mkv&quot; yEnc (1/3)"#, &new_ids)]);
    let old = ix
        .nzb_seed_store_xml(spec("old-source", "old-guid", REAL_NAME), &old_xml, 10)
        .unwrap();
    ix.db
        .execute(
            "DELETE FROM nzb_seed_file_keys WHERE set_id=?1",
            [old.set_id],
        )
        .unwrap();
    let parsed_new = crate::nzb::Nzb::parse(&new_xml).unwrap();
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2 WHERE id=?1",
            rusqlite::params![old.set_id, membership_key(&parsed_new)],
        )
        .unwrap();

    let replacement_name = "Other.Show.S02E03.1080p.WEB-GRP";
    let new = ix
        .nzb_seed_store_xml(
            spec("new-source", "new-guid", replacement_name),
            &new_xml,
            20,
        )
        .unwrap();
    assert_ne!(new.set_id, old.set_id);
    assert!(new.membership_key.starts_with("sha256:"));
    let old_names: Vec<String> = {
        let mut stmt = ix
            .db
            .prepare("SELECT name FROM nzb_seed_assertions WHERE set_id=?1")
            .unwrap();
        stmt.query_map([old.set_id], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    let new_names: Vec<String> = {
        let mut stmt = ix
            .db
            .prepare("SELECT name FROM nzb_seed_assertions WHERE set_id=?1")
            .unwrap();
        stmt.query_map([new.set_id], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    assert_eq!(old_names, vec![REAL_NAME]);
    assert_eq!(new_names, vec![replacement_name]);
    teardown(&dir, ix);
}

#[test]
fn reacquisition_refuses_an_equal_count_strong_manifest_disagreement() {
    let (dir, mut ix) = open("collection-key-disagreement");
    let first = ["strong-a1@x", "strong-a2@x", "strong-a3@x"];
    let second = ["strong-b1@x", "strong-b2@x", "strong-b3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "strong-a", REAL_NAME), &xml, 10)
        .unwrap();
    ix.db
        .execute(
            "UPDATE nzb_seed_file_keys SET manifest_key=?2
              WHERE set_id=?1 AND file_ord=0",
            rusqlite::params![stored.set_id, "0".repeat(64)],
        )
        .unwrap();

    let error = ix
        .nzb_seed_store_xml(spec("licensed", "strong-b", REAL_NAME), &xml, 20)
        .unwrap_err();
    assert!(matches!(
        error,
        NzbSeedError::Corrupt("strong file manifests disagree for one membership key")
    ));
    assert_eq!(ix.nzb_seed_inventory().unwrap().assertions, 1);
    teardown(&dir, ix);
}

#[test]
fn reordered_files_reuse_the_same_strong_manifest_set() {
    let (dir, mut ix) = open("collection-key-reorder");
    let first = ["order-a1@x", "order-a2@x", "order-a3@x"];
    let second = ["order-b1@x", "order-b2@x", "order-b3@x"];
    let forward = nzb_xml(&[
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let reverse = nzb_xml(&[
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
    ]);
    let a = ix
        .nzb_seed_store_xml(spec("licensed", "order-a", REAL_NAME), &forward, 10)
        .unwrap();
    let b = ix
        .nzb_seed_store_xml(spec("licensed", "order-b", REAL_NAME), &reverse, 20)
        .unwrap();
    assert_eq!(a.set_id, b.set_id);
    assert!(!b.new_set);
    assert!(b.new_assertion);
    teardown(&dir, ix);
}

#[test]
fn a_fragmented_title_conflict_blocks_collection_export() {
    let (dir, mut ix) = open("collection-title-conflict");
    let first = ["fight-a1@x", "fight-a2@x", "fight-a3@x"];
    let second = ["fight-b1@x", "fight-b2@x", "fight-b3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("one", "fight-a", REAL_NAME), &xml, 10)
        .unwrap();
    ix.nzb_seed_store_xml(
        spec("two", "fight-b", "Other.Show.S02E03.1080p.WEB-GRP"),
        &xml,
        11,
    )
    .unwrap();
    let _a = ingest_file(&mut ix, "alt.binaries.one", "yW7dK3gP5xB9aC4eM", &first, 20);
    let _b = ingest_file(
        &mut ix,
        "alt.binaries.two",
        "zX8eL4hQ6yC2bD5fN",
        &second,
        20,
    );
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_fragmented, 1, "{stats:?}");
    assert!(
        ix.make_nzb_seed_collection(stored.set_id)
            .unwrap()
            .is_none()
    );
    teardown(&dir, ix);
}

#[test]
fn exact_crosspost_alternatives_collapse_to_one_deterministic_collection_file() {
    let (dir, mut ix) = open("collection-crosspost");
    let first = ["copy-a1@x", "copy-a2@x", "copy-a3@x"];
    let second = ["copy-b1@x", "copy-b2@x", "copy-b3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "copies", REAL_NAME), &xml, 10)
        .unwrap();
    let a = ingest_file(&mut ix, "alt.binaries.one", "aY9fM5iR7zD3cE6gP", &first, 20);
    let duplicate = ingest_file(
        &mut ix,
        "alt.binaries.mirror",
        "bZ2gN6jS8aE4dF7hQ",
        &first,
        20,
    );
    let b = ingest_file(
        &mut ix,
        "alt.binaries.two",
        "cA3hP7kT9bF5eG8iR",
        &second,
        20,
    );
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_fragmented, 1, "{stats:?}");
    let collection = ix
        .make_nzb_seed_collection(stored.set_id)
        .unwrap()
        .expect("identical crossposts are safe alternatives");
    assert_eq!(collection.data_files, 2);
    assert_eq!(collection.release_ids, vec![a.min(duplicate), b]);
    let parsed = crate::nzb::Nzb::parse(collection.xml.as_bytes()).unwrap();
    assert_eq!(parsed.files.len(), 2);
    teardown(&dir, ix);
}

#[test]
fn an_unavailable_optional_par2_does_not_hide_a_complete_data_collection() {
    let (dir, mut ix) = open("collection-missing-optional");
    let first = ["need-a1@x", "need-a2@x", "need-a3@x"];
    let second = ["need-b1@x", "need-b2@x", "need-b3@x"];
    let parity = ["missing-p1@x", "missing-p2@x", "missing-p3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;first.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;second.mkv&quot; yEnc (1/3)"#, &second),
        (r#"&quot;missing.par2&quot; yEnc (1/3)"#, &parity),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "no-par", REAL_NAME), &xml, 10)
        .unwrap();
    let _a = ingest_file(&mut ix, "alt.binaries.one", "dB4iQ8mU2cG6fH9jS", &first, 20);
    let _b = ingest_file(
        &mut ix,
        "alt.binaries.two",
        "eC5jR9nV3dH7gJ2kT",
        &second,
        20,
    );
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_fragmented, 1, "{stats:?}");
    let collection = ix
        .make_nzb_seed_collection(stored.set_id)
        .unwrap()
        .expect("all required payload files are exact");
    assert_eq!(collection.data_files, 2);
    assert_eq!(collection.optional_files, 0);
    assert!(parity.iter().all(|id| !collection.xml.contains(id)));
    teardown(&dir, ix);
}

#[test]
fn an_episode_seed_cannot_rename_a_broader_local_pack() {
    let (dir, mut ix) = open("local-superset");
    let episode = ["one1@x", "one2@x", "one3@x"];
    let other = ["two1@x", "two2@x", "two3@x"];
    let xml = nzb_xml(&[(r#"&quot;episode01.mkv&quot; yEnc (1/3)"#, &episode)]);
    ix.nzb_seed_store_xml(spec("licensed", "episode", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_two_files(
        &mut ix,
        "alt.binaries.test",
        "tV7nM3qR9xP5kL2zJ",
        &episode,
        &other,
        20,
    );
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_partial, 1, "{stats:?}");
    assert_eq!(stats.claims_applied, 0);
    assert_eq!(applied_name(&ix, rid), "");
    teardown(&dir, ix);
}

#[test]
fn a_true_multi_file_release_covers_every_file_and_applies() {
    let (dir, mut ix) = open("multifile");
    let first = ["mf1a@x", "mf1b@x", "mf1c@x"];
    let second = ["mf2a@x", "mf2b@x", "mf2c@x"];
    let xml = nzb_xml(&[
        (r#"&quot;payload.part01.rar&quot; yEnc (1/3)"#, &first),
        (r#"&quot;payload.part02.rar&quot; yEnc (1/3)"#, &second),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "multi", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_two_files(
        &mut ix,
        "alt.binaries.test",
        "uV8rN4pS2zX6mQ9tC",
        &first,
        &second,
        20,
    );
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.claims_applied, 1, "{stats:?}");
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    let matches = ix.nzb_seed_matches(stored.set_id).unwrap();
    assert_eq!(matches[0].covered_data_files, 2);
    teardown(&dir, ix);
}

#[test]
fn a_shared_probe_prefix_cannot_name_a_different_full_manifest() {
    let (dir, mut ix) = open("shared-prefix-different-tail");
    let seed_ids = ["same-a@x", "same-b@x", "same-c@x", "seed-tail@x"];
    let local_ids = ["same-a@x", "same-b@x", "same-c@x", "local-tail@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/4)"#, &seed_ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "different-tail", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "vM6qR2xT8cF4nK9zP",
        &local_ids,
        20,
    );

    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.claims_applied, 0, "{stats:?}");
    assert_eq!(applied_name(&ix, rid), "");
    let matches = ix.nzb_seed_matches(stored.set_id).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].state, "partial");
    teardown(&dir, ix);
}

#[test]
fn an_exact_growing_prefix_waits_for_settle_and_withdraws_on_change() {
    let (dir, mut ix) = open("exact-manifest-settle");
    let ids = ["settle-a@x", "settle-b@x", "settle-c@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "settle", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "vM6qR2xT8cF4nK9zQ", &ids, 20);
    ix.db
        .execute(
            "UPDATE releases SET first_seen=?2,seed_manifest_at=?2 WHERE id=?1",
            rusqlite::params![rid, 20],
        )
        .unwrap();

    let fresh = ix.nzb_seed_reconcile_set(stored.set_id, 30).unwrap();
    assert_eq!(fresh.sets_unsettled, 1, "{fresh:?}");
    assert_eq!(fresh.claims_applied, 0, "{fresh:?}");
    assert_eq!(applied_name(&ix, rid), "");
    assert_eq!(
        ix.nzb_seed_matches(stored.set_id).unwrap()[0].state,
        "unsettled"
    );

    let settled = ix
        .nzb_seed_reconcile_set(stored.set_id, 20 + SEED_RELEASE_SETTLE_SECS + 1)
        .unwrap();
    assert_eq!(settled.claims_applied, 1, "{settled:?}");
    assert_eq!(applied_name(&ix, rid), REAL_NAME);

    ix.db
        .execute(
            "UPDATE files SET total_parts=4,segments=?2 WHERE release_id=?1",
            rusqlite::params![
                rid,
                crate::index::segcodec::encode(&[
                    (1, "<settle-a@x>".into(), 900),
                    (2, "<settle-b@x>".into(), 900),
                    (3, "<settle-c@x>".into(), 900),
                    (4, "<settle-extra@x>".into(), 900),
                ])
            ],
        )
        .unwrap();
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    let state: String = ix
        .db
        .query_row(
            "SELECT state FROM nzb_seed_sets WHERE id=?1",
            [stored.set_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "pending");
    teardown(&dir, ix);
}

#[test]
fn an_old_release_waits_again_after_its_manifest_changes_to_an_exact_match() {
    let (dir, mut ix) = open("old-release-resettle");
    let first = ["resettle-a@x", "resettle-b@x", "resettle-c@x"];
    let second = ["resettle-d@x", "resettle-e@x", "resettle-f@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.part01.rar&quot; yEnc (1/3)"#, &first)]);
    let stored = ix
        .nzb_seed_store_xml(
            spec("licensed", "old-release-resettle", REAL_NAME),
            &xml,
            10,
        )
        .unwrap();
    let rid = ingest_two_files(
        &mut ix,
        "alt.binaries.test",
        "bC8dE4fG2hJ6kL3mP",
        &first,
        &second,
        20,
    );
    let before = ix.nzb_seed_reconcile_set(stored.set_id, 30).unwrap();
    assert_eq!(before.claims_applied, 0, "{before:?}");

    ix.db
        .execute(
            "DELETE FROM files WHERE release_id=?1 AND filename LIKE '%.part02.rar'",
            [rid],
        )
        .unwrap();
    ix.db
        .execute(
            "UPDATE releases SET seed_manifest_at=100 WHERE id=?1",
            [rid],
        )
        .unwrap();
    let fresh = ix.nzb_seed_reconcile_set(stored.set_id, 101).unwrap();
    assert_eq!(fresh.sets_unsettled, 1, "{fresh:?}");
    assert_eq!(fresh.claims_applied, 0, "{fresh:?}");
    assert_eq!(applied_name(&ix, rid), "");

    let settled = ix
        .nzb_seed_reconcile_set(stored.set_id, 100 + SEED_RELEASE_SETTLE_SECS + 1)
        .unwrap();
    assert_eq!(settled.claims_applied, 1, "{settled:?}");
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    teardown(&dir, ix);
}

#[test]
fn a_release_that_grows_past_the_exact_manifest_loses_seed_name_support() {
    let (dir, mut ix) = open("exact-manifest-grew");
    let ids = ["grew-a@x", "grew-b@x", "grew-c@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "grew", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "wN7rS3yU9dG5pL2aQ", &ids, 20);
    let first = ix.nzb_seed_reconcile_set(stored.set_id, 30).unwrap();
    assert_eq!(first.claims_applied, 1, "{first:?}");
    assert_eq!(applied_name(&ix, rid), REAL_NAME);

    ix.db
        .execute(
            "UPDATE files SET total_parts=4,segments=?2 WHERE release_id=?1",
            rusqlite::params![
                rid,
                crate::index::segcodec::encode(&[
                    (1, "<grew-a@x>".into(), 900),
                    (2, "<grew-b@x>".into(), 900),
                    (3, "<grew-c@x>".into(), 900),
                    (4, "<grew-extra@x>".into(), 900),
                ])
            ],
        )
        .unwrap();
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    let changed = ix.nzb_seed_reconcile_set(stored.set_id, 40).unwrap();
    assert_eq!(changed.claims_applied, 0, "{changed:?}");
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    teardown(&dir, ix);
}

#[test]
fn segment_table_swap_keeps_seed_revocation_on_the_promoted_files_table() {
    let (dir, mut ix) = open("seed-segmig-trigger-reinstall");
    assert!(!ix.nzb_seed_schema_present().unwrap());
    ix.segmig_debug_install_legacy_layout().unwrap();

    let ids = ["segmig-a@x", "segmig-b@x", "segmig-c@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "segmig", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "sE8gM4iG2tR6pL3aQ", &ids, 20);
    assert_eq!(
        ix.nzb_seed_reconcile_set(stored.set_id, 30)
            .unwrap()
            .claims_applied,
        1
    );
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    assert_eq!(ix.name_claims(rid).unwrap().len(), 1);
    assert_eq!(ix.nzb_seed_matches(stored.set_id).unwrap().len(), 1);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !ix.segmig_copy_slice(deadline).unwrap().finished {}
    assert_eq!(ix.segmig_state(), SegMigState::Swappable);
    assert_eq!(ix.segmig_swap().unwrap(), Some(1));

    let active_seed_triggers: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE type='trigger' AND tbl_name='files'
                AND name IN ('nzb_seed_file_ai_v2',
                             'nzb_seed_file_au_v2',
                             'nzb_seed_file_ad_v2')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active_seed_triggers, 3);
    let stranded_seed_triggers: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE type='trigger' AND tbl_name='files_old'
                AND name LIKE 'nzb_seed_file_%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stranded_seed_triggers, 0);
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    assert_eq!(ix.name_claims(rid).unwrap().len(), 1);
    assert_eq!(ix.nzb_seed_matches(stored.set_id).unwrap().len(), 1);

    assert_eq!(ix.segmig_reclaim_slice(deadline).unwrap(), (1, true));
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    assert_eq!(ix.name_claims(rid).unwrap().len(), 1);
    assert_eq!(ix.nzb_seed_matches(stored.set_id).unwrap().len(), 1);

    ix.db
        .execute(
            "UPDATE files SET total_parts=4,segments=?2 WHERE release_id=?1",
            rusqlite::params![
                rid,
                crate::index::segcodec::encode(&[
                    (1, "<segmig-a@x>".into(), 900),
                    (2, "<segmig-b@x>".into(), 900),
                    (3, "<segmig-c@x>".into(), 900),
                    (4, "<segmig-extra@x>".into(), 900),
                ])
            ],
        )
        .unwrap();
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    teardown(&dir, ix);
}

#[test]
fn moving_a_file_between_releases_withdraws_both_seed_edges_immediately() {
    let (dir, mut ix) = open("release-file-move");
    let destination_ids = ["move-dst-a@x", "move-dst-b@x", "move-dst-c@x"];
    let source_ids = ["move-src-a@x", "move-src-b@x", "move-src-c@x"];
    let xml = nzb_xml(&[(
        r#"&quot;destination.mkv&quot; yEnc (1/3)"#,
        &destination_ids,
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "release-file-move", REAL_NAME), &xml, 10)
        .unwrap();
    let destination = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "aB7cD3eF9gH5jK2mN",
        &destination_ids,
        20,
    );
    let source = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "pQ8rS4tU2vW6xY3zA",
        &source_ids,
        20,
    );
    let named = ix.nzb_seed_reconcile_set(stored.set_id, 30).unwrap();
    assert_eq!(named.claims_applied, 1, "{named:?}");
    assert_eq!(applied_name(&ix, destination), REAL_NAME);

    ix.db
        .execute(
            "UPDATE files SET release_id=?1 WHERE release_id=?2",
            rusqlite::params![destination, source],
        )
        .unwrap();

    assert_eq!(applied_name(&ix, destination), "");
    assert!(ix.name_claims(destination).unwrap().is_empty());
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    let changed: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM releases
              WHERE id IN (?1,?2) AND seed_manifest_at>0",
            rusqlite::params![destination, source],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(changed, 2);
    teardown(&dir, ix);
}

#[test]
fn production_ingest_cannot_restore_a_seed_title_after_same_release_manifest_growth() {
    let (dir, mut ix) = open("ingest-title-carry");
    let ids = ["carry-a@x", "carry-b@x", "carry-c@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "ingest-title-carry", REAL_NAME), &xml, 10)
        .unwrap();
    let group = "alt.binaries.test";
    let stem = "cD9eF5gH3jK7mN4pQ";
    let rid = ingest_file(&mut ix, group, stem, &ids, 20);
    assert_eq!(
        ix.nzb_seed_reconcile_set(stored.set_id, 30)
            .unwrap()
            .claims_applied,
        1
    );
    assert_eq!(applied_name(&ix, rid), REAL_NAME);

    ix.ingest(
        group,
        &[entry(
            // `release_stem` folds this PAR2 into the existing release, so
            // production ingest genuinely grows the named row's manifest.
            &format!(r#""{stem}.par2" yEnc (1/1)"#),
            "poster@x",
            "carry-extra@x",
            200,
        )],
        40,
    )
    .unwrap();
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    teardown(&dir, ix);
}

#[test]
fn corrupting_a_stored_file_key_retracts_its_previous_seed_name() {
    let (dir, mut ix) = open("stored-file-key-corrupt-retract");
    let ids = ["key-corrupt-a@x", "key-corrupt-b@x", "key-corrupt-c@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "key-corrupt", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "xP8tU4zW2fH6qM3bR", &ids, 20);
    assert_eq!(
        ix.nzb_seed_reconcile_set(stored.set_id, 30)
            .unwrap()
            .claims_applied,
        1
    );
    assert_eq!(applied_name(&ix, rid), REAL_NAME);

    ix.db
        .execute(
            "UPDATE nzb_seed_file_keys SET manifest_key=?2
              WHERE set_id=?1 AND file_ord=0",
            rusqlite::params![stored.set_id, "0".repeat(64)],
        )
        .unwrap();
    let unsafe_replay = ix.nzb_seed_reconcile_set(stored.set_id, 40).unwrap();
    assert_eq!(unsafe_replay.sets_unsafe, 1, "{unsafe_replay:?}");
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    teardown(&dir, ix);
}

#[test]
fn withdrawing_stale_seed_support_preserves_a_stronger_body_name() {
    let (dir, mut ix) = open("seed-withdraw-preserves-stronger");
    let ids = ["stronger-a@x", "stronger-b@x", "stronger-c@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "stronger", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "yQ9uV5aX3gJ7rN4cS", &ids, 20);
    ix.nzb_seed_reconcile_set(stored.set_id, 30).unwrap();
    let body_name = "Body.Proven.Show.S02E03.1080p.WEB-GRP";
    let body = NameClaim {
        name: body_name.to_string(),
        evidence: NameEvidence::BodyProbe,
        key: "body-manifest-1".to_string(),
        source: "body/7z".to_string(),
    };
    assert_eq!(
        ix.apply_proven_name(rid, &body, 35).unwrap(),
        ProvenOutcome::Replaced
    );
    assert_eq!(applied_name(&ix, rid), body_name);

    ix.db
        .execute(
            "UPDATE nzb_seed_file_keys SET manifest_key=?2
              WHERE set_id=?1 AND file_ord=0",
            rusqlite::params![stored.set_id, "0".repeat(64)],
        )
        .unwrap();
    ix.nzb_seed_reconcile_set(stored.set_id, 40).unwrap();
    assert_eq!(applied_name(&ix, rid), body_name);
    let claims = ix.name_claims(rid).unwrap();
    assert_eq!(claims.len(), 1, "{claims:?}");
    assert_eq!(claims[0].0, body_name);
    assert_eq!(claims[0].1, NameEvidence::BodyProbe.tag());
    teardown(&dir, ix);
}

#[test]
fn separately_clustered_par2_keeps_crossposts_collection_only() {
    let (dir, mut ix) = open("par2-crosspost");
    let data = ["data1@x", "data2@x", "data3@x"];
    let parity = ["par1@x", "par2@x", "par3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &data),
        (r#"&quot;payload.vol000+01.par2&quot; yEnc (1/3)"#, &parity),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "cross", REAL_NAME), &xml, 10)
        .unwrap();
    assert_eq!(stored.data_files, 1, "PAR2 is not a required data file");
    let a = ingest_file(&mut ix, "alt.binaries.one", "vW9sP5qT3aY7nR2uD", &data, 20);
    let b = ingest_file(&mut ix, "alt.binaries.two", "wX2tQ6rU4bZ8pS3vE", &data, 20);
    let _par = ingest_named_file(
        &mut ix,
        "alt.binaries.test",
        "payload.vol000+01.par2",
        &parity,
        20,
    );
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_fragmented, 1, "{stats:?}");
    assert_eq!(stats.claims_applied, 0, "{stats:?}");
    assert_eq!(applied_name(&ix, a), "");
    assert_eq!(applied_name(&ix, b), "");
    let collection = ix
        .make_nzb_seed_collection(stored.set_id)
        .unwrap()
        .expect("full per-file proofs can assemble the named collection");
    assert_eq!(collection.data_files, 1);
    assert_eq!(collection.optional_files, 1);
    teardown(&dir, ix);
}

#[test]
fn a_par2_only_nzb_is_not_an_actionable_identity_seed() {
    let (dir, mut ix) = open("par2-only");
    let ids = ["onlypar1@x", "onlypar2@x", "onlypar3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.vol000+01.par2&quot; yEnc (1/3)"#, &ids)]);
    let error = ix
        .nzb_seed_store_xml(spec("licensed", "par-only", REAL_NAME), &xml, 10)
        .unwrap_err();
    assert!(matches!(
        error,
        NzbSeedError::Invalid("NZB has no data files")
    ));
    assert_eq!(ix.nzb_seed_inventory().unwrap().sets, 0);
    teardown(&dir, ix);
}

#[test]
fn programmatic_noncanonical_ids_cannot_bypass_the_xml_seed_boundary() {
    let (dir, mut ix) = open("programmatic-noncanonical-id");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["safe1@x", "safe2@x", "safe3@x"],
    )]);
    let mut programmatic = crate::nzb::Nzb::parse(&xml).unwrap();
    programmatic.files[0].segments[0].message_id = "\u{a0}safe1@x".to_string();
    let error = ix
        .nzb_seed_store(spec("programmatic", "unsafe", REAL_NAME), &programmatic, 10)
        .unwrap_err();
    assert!(matches!(
        error,
        NzbSeedError::Invalid("NZB contains a non-canonical segment")
    ));

    let hostile_xml = br#"<?xml version="1.0"?><nzb><file subject="payload.mkv" poster="p@x" date="1"><groups><group>alt.binaries.test</group></groups><segments><segment bytes="100" number="1">&#xa0;safe1@x</segment></segments></file></nzb>"#;
    let parsed_hostile = crate::nzb::Nzb::parse(hostile_xml).unwrap();
    assert!(parsed_hostile.files[0].segments.is_empty());
    assert_eq!(parsed_hostile.files[0].dropped_segments, 1);
    let xml_error = ix
        .nzb_seed_store(spec("xml", "unsafe", REAL_NAME), &parsed_hostile, 20)
        .unwrap_err();
    assert!(matches!(
        xml_error,
        NzbSeedError::Invalid("NZB has no usable Message-IDs")
    ));
    teardown(&dir, ix);
}

#[test]
fn ambiguous_programmatic_parts_and_ids_are_rejected() {
    let (dir, mut ix) = open("programmatic-ambiguous-id");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["unique1@x", "unique2@x", "unique3@x"],
    )]);
    let parsed = crate::nzb::Nzb::parse(&xml).unwrap();

    let mut duplicate_part = parsed.clone();
    let mut extra = duplicate_part.files[0].segments[1].clone();
    extra.number = 1;
    duplicate_part.files[0].segments.push(extra);
    assert!(matches!(
        ix.nzb_seed_store(
            spec("programmatic", "duplicate-part", REAL_NAME),
            &duplicate_part,
            10,
        )
        .unwrap_err(),
        NzbSeedError::Invalid("NZB contains ambiguous segment identity")
    ));

    let mut duplicate_id = parsed;
    duplicate_id.files[0].segments[1].message_id = "unique1@x".to_string();
    assert!(matches!(
        ix.nzb_seed_store(
            spec("programmatic", "duplicate-id", REAL_NAME),
            &duplicate_id,
            20,
        )
        .unwrap_err(),
        NzbSeedError::Invalid("NZB contains ambiguous segment identity")
    ));
    teardown(&dir, ix);
}

#[test]
fn empty_or_oversized_programmatic_files_cannot_enter_the_seed_store() {
    let (dir, mut ix) = open("programmatic-file-shape");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["shape1@x", "shape2@x", "shape3@x"],
    )]);
    let parsed = crate::nzb::Nzb::parse(&xml).unwrap();

    let mut with_empty = parsed.clone();
    with_empty.files.push(crate::nzb::NzbFile {
        subject: "missing.bin".to_string(),
        ..Default::default()
    });
    assert!(matches!(
        ix.nzb_seed_store(
            spec("programmatic", "empty-file", REAL_NAME),
            &with_empty,
            10,
        )
        .unwrap_err(),
        NzbSeedError::Invalid("NZB contains an empty file")
    ));

    let mut oversized = parsed;
    oversized.files[0].subject = "x".repeat(crate::nzb::limits::MAX_FIELD + 1);
    assert!(matches!(
        ix.nzb_seed_store(
            spec("programmatic", "long-subject", REAL_NAME),
            &oversized,
            20,
        )
        .unwrap_err(),
        NzbSeedError::Invalid("file subject is too long")
    ));
    assert_eq!(ix.nzb_seed_inventory().unwrap().sets, 0);
    teardown(&dir, ix);
}

#[test]
fn conflicting_readable_titles_for_one_membership_block_application() {
    let (dir, mut ix) = open("title-conflict");
    let ids = ["tc1@x", "tc2@x", "tc3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    ix.nzb_seed_store_xml(spec("one", "a", REAL_NAME), &xml, 10)
        .unwrap();
    ix.nzb_seed_store_xml(
        spec("two", "b", "Other.Show.S02E03.1080p.WEB-GRP"),
        &xml,
        11,
    )
    .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "yZ4vS8tW6dB2rU5xG", &ids, 20);
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_title_conflict, 1, "{stats:?}");
    assert_eq!(stats.claims_applied, 0);
    assert_eq!(applied_name(&ix, rid), "");
    assert_eq!(ix.nzb_seed_inventory().unwrap().title_conflict_sets, 1);
    teardown(&dir, ix);
}

#[test]
fn an_overlong_assertion_stays_auditable_but_cannot_fan_out_into_names() {
    let (dir, mut ix) = open("overlong-derived-title");
    let ids = ["long-a@x", "long-b@x", "long-c@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let name = format!(
        "{}.S01E01.1080p-GRP",
        "A".repeat(SEED_APPLIED_TITLE_BYTES_CAP)
    );
    assert!(name.len() > SEED_APPLIED_TITLE_BYTES_CAP);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "overlong", &name), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "rS9tU5vW3xY7zA4bC", &ids, 20);

    let stats = ix.nzb_seed_reconcile_set(stored.set_id, 30).unwrap();
    assert_eq!(stats.sets_invalid_title, 1, "{stats:?}");
    assert_eq!(stats.claims_applied, 0, "{stats:?}");
    assert_eq!(applied_name(&ix, rid), "");
    assert_eq!(ix.nzb_seed_inventory().unwrap().assertions, 1);
    teardown(&dir, ix);
}

#[test]
fn a_late_title_conflict_retracts_the_once_applied_exact_name() {
    let (dir, mut ix) = open("late-title-conflict");
    let ids = ["late-tc1@x", "late-tc2@x", "late-tc3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("one", "late-a", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "zA5wT9uX7eC3sV6yH", &ids, 20);
    let first = ix.nzb_seed_reconcile_set(stored.set_id, 30).unwrap();
    assert_eq!(first.claims_applied, 1, "{first:?}");
    assert_eq!(applied_name(&ix, rid), REAL_NAME);

    ix.nzb_seed_store_xml(
        spec("two", "late-b", "Other.Show.S02E03.1080p.WEB-GRP"),
        &xml,
        40,
    )
    .unwrap();
    let conflict = ix.nzb_seed_reconcile_set(stored.set_id, 50).unwrap();
    assert_eq!(conflict.sets_title_conflict, 1, "{conflict:?}");
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    teardown(&dir, ix);
}

#[test]
fn posted_nzb_titles_stay_shadow_until_a_trusted_assertion_arrives() {
    let (dir, mut ix) = open("posted-title-shadow");
    let ids = ["posted-shadow1@x", "posted-shadow2@x", "posted-shadow3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(
            spec(
                NZB_SEED_POSTED_SOURCE,
                "public-object",
                "Attacker.Chosen.Show.S99E99-GRP",
            ),
            &xml,
            10,
        )
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "uV6xA4sD8fG2hJ9kL", &ids, 20);

    let shadow = ix.nzb_seed_reconcile_set(stored.set_id, 30).unwrap();
    assert_eq!(shadow.sets_invalid_title, 1, "{shadow:?}");
    assert_eq!(shadow.claims_applied, 0, "{shadow:?}");
    assert_eq!(applied_name(&ix, rid), "");
    let edges = ix.nzb_seed_matches(stored.set_id).unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].state, "invalid-title");

    ix.nzb_seed_store_xml(spec("nzb-add", "trusted-object", REAL_NAME), &xml, 40)
        .unwrap();
    let trusted = ix.nzb_seed_reconcile_set(stored.set_id, 50).unwrap();
    assert_eq!(trusted.sets_title_conflict, 0, "{trusted:?}");
    assert_eq!(trusted.claims_applied, 1, "{trusted:?}");
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    let inventory = ix.nzb_seed_inventory().unwrap();
    assert_eq!(inventory.assertions, 2);
    assert_eq!(inventory.title_conflict_sets, 0);
    teardown(&dir, ix);
}

#[test]
fn the_hash_prefilter_is_verified_against_raw_message_ids() {
    let (dir, mut ix) = open("hash-verify");
    let seed_ids = ["seed1@x", "seed2@x", "seed3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &seed_ids)]);
    ix.nzb_seed_store_xml(spec("licensed", "hash", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "zA5wT9uX7eC3sV6yH",
        &["other1@x", "other2@x", "other3@x"],
        20,
    );
    for id in seed_ids {
        ix.db
            .execute(
                "INSERT OR IGNORE INTO msgid_map(h,release_id) VALUES(?1,?2)",
                rusqlite::params![claims::msgid_hash(id), rid],
            )
            .unwrap();
    }
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.hash_candidates, 1, "{stats:?}");
    assert_eq!(stats.hash_candidates_rejected, 1, "{stats:?}");
    assert_eq!(stats.sets_unmatched, 1, "{stats:?}");
    assert_eq!(applied_name(&ix, rid), "");
    teardown(&dir, ix);
}

#[test]
fn replay_accepts_only_exact_local_wrappers_and_positive_declared_parts() {
    for (case, first_id, declared_parts, should_apply) in [
        ("exact-wrapper", "<strict1@x>", 3, true),
        ("leading-space", " <strict1@x>", 3, false),
        ("one-sided", "<strict1@x", 3, false),
        ("zero-parts", "<strict1@x>", 0, false),
    ] {
        let (dir, mut ix) = open(case);
        let ids = ["strict1@x", "strict2@x", "strict3@x"];
        let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
        ix.nzb_seed_store_xml(spec("licensed", case, REAL_NAME), &xml, 10)
            .unwrap();
        let rid = ingest_file(&mut ix, "alt.binaries.test", "kP4sV8xB2mQ6tY9cF", &ids, 20);
        ix.db
            .execute(
                "UPDATE files SET total_parts=?2,segments=?3 WHERE release_id=?1",
                rusqlite::params![
                    rid,
                    declared_parts,
                    crate::index::segcodec::encode(&[
                        (1, first_id.to_string(), 900),
                        (2, "<strict2@x>".to_string(), 900),
                        (3, "<strict3@x>".to_string(), 900),
                    ])
                ],
            )
            .unwrap();
        settle_release(&ix, rid, 30);

        let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
        assert_eq!(stats.claims_applied, usize::from(should_apply), "{stats:?}");
        assert_eq!(
            applied_name(&ix, rid) == REAL_NAME,
            should_apply,
            "{stats:?}"
        );
        teardown(&dir, ix);
    }
}

#[test]
fn a_corrupt_hash_candidate_quarantines_the_set_before_later_hits() {
    let (dir, mut ix) = open("corrupt-candidate-stop");
    let ids = ["stop1@x", "stop2@x", "stop3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "stop", REAL_NAME), &xml, 10)
        .unwrap();
    let corrupt_rid = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "aA4sV8xB2mQ6tY9cF",
        &["unrelated1@x", "unrelated2@x", "unrelated3@x"],
        20,
    );
    for id in ids {
        ix.db
            .execute(
                "INSERT OR IGNORE INTO msgid_map(h,release_id) VALUES(?1,?2)",
                rusqlite::params![claims::msgid_hash(id), corrupt_rid],
            )
            .unwrap();
    }
    ix.db
        .execute(
            "UPDATE files SET segments=42 WHERE release_id=?1",
            [corrupt_rid],
        )
        .unwrap();
    let good_rid = ingest_file(&mut ix, "alt.binaries.test", "zZ4sV8xB2mQ6tY9cF", &ids, 21);

    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.hash_candidates, 2, "{stats:?}");
    assert_eq!(stats.hash_candidates_rejected, 1, "{stats:?}");
    assert_eq!(stats.sets_errored, 1, "{stats:?}");
    assert_eq!(stats.claims_applied, 0, "{stats:?}");
    assert_eq!(applied_name(&ix, good_rid), "");
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    teardown(&dir, ix);
}

#[test]
fn xml_disallowed_seed_metadata_is_rejected_before_storage() {
    let (dir, mut ix) = open("metadata-noncharacter");
    let ids = ["meta1@x", "meta2@x", "meta3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let parsed = crate::nzb::Nzb::parse(&xml).unwrap();
    let mut invalid = spec("licensed", "metadata", REAL_NAME);
    invalid.category = "tv\u{FFFE}";
    assert!(matches!(
        ix.nzb_seed_store(invalid, &parsed, 10),
        Err(NzbSeedError::Invalid(
            "metadata field contains an XML-disallowed character"
        ))
    ));
    assert_eq!(ix.nzb_seed_inventory().unwrap().sets, 0);
    teardown(&dir, ix);
}

#[test]
fn collection_export_rejects_invalid_local_text_cells() {
    let (dir, mut ix) = open("collection-invalid-local-text");
    let ids = ["cell1@x", "cell2@x", "cell3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "cells", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "mR5uW9zC3nS7vA2dG", &ids, 20);

    ix.db
        .execute(
            "UPDATE files SET filename=zeroblob(4) WHERE release_id=?1",
            [rid],
        )
        .unwrap();
    assert!(
        ix.make_nzb_seed_collection(stored.set_id)
            .unwrap()
            .is_none()
    );

    ix.db
        .execute(
            "UPDATE files SET filename='payload.rar' WHERE release_id=?1",
            [rid],
        )
        .unwrap();
    ix.db
        .execute("UPDATE releases SET grp=zeroblob(4) WHERE id=?1", [rid])
        .unwrap();
    assert!(
        ix.make_nzb_seed_collection(stored.set_id)
            .unwrap()
            .is_none()
    );
    teardown(&dir, ix);
}

#[test]
fn claim_key_commits_to_the_complete_seed_manifest() {
    let (dir, mut ix) = open("claim-key");
    let ids = [
        "key1@x", "key2@x", "key3@x", "key4@x", "key5@x", "key6@x", "key7@x", "key8@x",
    ];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/8)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "key", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "bC6xU2vY8fD4tW7zK", &ids, 20);
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.claims_applied, 1, "{stats:?}");
    let claims = ix.name_claims(rid).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        claims[0].2, stored.membership_key,
        "the bounded reverse map is only a candidate index"
    );
    teardown(&dir, ix);
}

#[test]
fn grouped_par2_manifest_is_part_of_the_direct_claim_key() {
    let (dir, mut ix) = open("claim-key-par2");
    let data = ["gdata1@x", "gdata2@x", "gdata3@x"];
    let parity = ["gpar1@x", "gpar2@x", "gpar3@x"];
    let xml = nzb_xml(&[
        (r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &data),
        (r#"&quot;payload.vol000+01.par2&quot; yEnc (1/3)"#, &parity),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "key-par2", REAL_NAME), &xml, 10)
        .unwrap();
    let stem = "cD7yV3wZ9gE5uX8aL";
    let rid = ingest_two_files(&mut ix, "alt.binaries.test", stem, &data, &parity, 20);
    let changed = ix
        .db
        .execute(
            "UPDATE files SET filename=?2
              WHERE release_id=?1 AND filename LIKE '%.part02.rar'",
            rusqlite::params![rid, format!("{stem}.vol000+01.par2")],
        )
        .unwrap();
    assert_eq!(changed, 1);
    settle_release(&ix, rid, 30);
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.claims_applied, 1, "{stats:?}");
    let claims = ix.name_claims(rid).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        claims[0].2, stored.membership_key,
        "every exact local file belongs to the direct proof key"
    );
    teardown(&dir, ix);
}

#[test]
fn a_growing_local_manifest_waits_until_every_part_is_present() {
    let (dir, mut ix) = open("claim-key-growth");
    let ids = [
        "grow1@x", "grow2@x", "grow3@x", "grow4@x", "grow5@x", "grow6@x", "grow7@x", "grow8@x",
    ];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/8)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "growth", REAL_NAME), &xml, 10)
        .unwrap();
    let stem = "dE8zW4xA2hF6vY9bM";
    let late: Vec<_> = (4..=6)
        .map(|part| {
            entry(
                &format!(r#""{stem}.rar" yEnc ({part}/8)"#),
                "poster@x",
                ids[part - 1],
                900,
            )
        })
        .collect();
    ix.ingest("alt.binaries.test", &late, 20).unwrap();
    let rid: i64 = ix
        .db
        .query_row("SELECT id FROM releases WHERE stem=?1", [stem], |r| {
            r.get(0)
        })
        .unwrap();
    let first = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(first.claims_applied, 0, "{first:?}");
    assert!(ix.name_claims(rid).unwrap().is_empty());

    let early: Vec<_> = (1..=3)
        .map(|part| {
            entry(
                &format!(r#""{stem}.rar" yEnc ({part}/8)"#),
                "poster@x",
                ids[part - 1],
                900,
            )
        })
        .collect();
    ix.ingest("alt.binaries.test", &early, 40).unwrap();
    let second = ix.nzb_seed_reconcile(50, 10).unwrap();
    assert_eq!(second.claims_applied, 0, "{second:?}");
    assert!(ix.name_claims(rid).unwrap().is_empty());

    let final_parts: Vec<_> = (7..=8)
        .map(|part| {
            entry(
                &format!(r#""{stem}.rar" yEnc ({part}/8)"#),
                "poster@x",
                ids[part - 1],
                900,
            )
        })
        .collect();
    ix.ingest("alt.binaries.test", &final_parts, 60).unwrap();
    settle_release(&ix, rid, 70);
    let third = ix.nzb_seed_reconcile(70, 10).unwrap();
    assert_eq!(third.claims_applied, 1, "{third:?}");
    let claims = ix.name_claims(rid).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].2, stored.membership_key);
    teardown(&dir, ix);
}

#[test]
fn file_role_is_part_of_the_canonical_membership_identity() {
    let (dir, mut ix) = open("membership-role");
    let first = ["role1@x", "role2@x", "role3@x"];
    let second = ["role4@x", "role5@x", "role6@x"];
    let two_data = nzb_xml(&[
        (r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;extra.mkv&quot; yEnc (1/3)"#, &second),
    ]);
    let data_and_par = nzb_xml(&[
        (r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &first),
        (r#"&quot;extra.par2&quot; yEnc (1/3)"#, &second),
    ]);
    let a = ix
        .nzb_seed_store_xml(spec("licensed", "role-a", REAL_NAME), &two_data, 10)
        .unwrap();
    let b = ix
        .nzb_seed_store_xml(spec("licensed", "role-b", REAL_NAME), &data_and_par, 11)
        .unwrap();
    assert_ne!(a.set_id, b.set_id);
    assert_ne!(a.membership_key, b.membership_key);
    assert_eq!(a.data_files, 2);
    assert_eq!(b.data_files, 1);
    teardown(&dir, ix);
}

#[test]
fn corrupt_candidate_does_not_starve_the_next_seed() {
    let (dir, mut ix) = open("corrupt-cursor");
    let bad_ids = ["badrow1@x", "badrow2@x", "badrow3@x"];
    let good_ids = ["goodrow1@x", "goodrow2@x", "goodrow3@x"];
    let bad_xml = nzb_xml(&[(r#"&quot;bad.mkv&quot; yEnc (1/3)"#, &bad_ids)]);
    let good_xml = nzb_xml(&[(r#"&quot;good.mkv&quot; yEnc (1/3)"#, &good_ids)]);
    let bad = ix
        .nzb_seed_store_xml(spec("licensed", "bad-row", REAL_NAME), &bad_xml, 10)
        .unwrap();
    ix.nzb_seed_store_xml(
        spec("licensed", "good-row", "Other.Show.S02E03.1080p.WEB-GRP"),
        &good_xml,
        11,
    )
    .unwrap();
    let bad_rid = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "eF9aX5yB3iG7wZ2cN",
        &bad_ids,
        20,
    );
    let good_rid = ingest_file(
        &mut ix,
        "alt.binaries.test",
        "fG2bY6zC4jH8xA3dP",
        &good_ids,
        20,
    );
    ix.db
        .execute(
            "UPDATE files SET segments=42 WHERE release_id=?1",
            [bad_rid],
        )
        .unwrap();
    let stats = ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(stats.sets_errored, 1, "{stats:?}");
    assert_eq!(stats.claims_applied, 1, "{stats:?}");
    let state: String = ix
        .db
        .query_row(
            "SELECT state FROM nzb_seed_sets WHERE id=?1",
            [bad.set_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "error");
    assert_eq!(applied_name(&ix, bad_rid), "");
    assert_eq!(
        applied_name(&ix, good_rid),
        "Other.Show.S02E03.1080p.WEB-GRP"
    );
    teardown(&dir, ix);
}

#[test]
fn deleting_a_release_removes_its_seed_match_edge() {
    let (dir, mut ix) = open("release-delete");
    let ids = ["delete1@x", "delete2@x", "delete3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "delete", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "gH3cZ7aD5kI9yB4eQ", &ids, 20);
    ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(ix.nzb_seed_matches(stored.set_id).unwrap().len(), 1);
    ix.db
        .execute("DELETE FROM releases WHERE id=?1", [rid])
        .unwrap();
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    teardown(&dir, ix);
}

#[test]
fn lazy_schema_stamps_runtime_ddl_once() {
    let (dir, mut ix) = open("ddl");
    assert!(!ix.take_schema_ddl(), "a fresh open stamps nothing");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["ddl1@x", "ddl2@x", "ddl3@x"],
    )]);
    ix.nzb_seed_store_xml(spec("licensed", "ddl", REAL_NAME), &xml, 10)
        .unwrap();
    assert!(ix.take_schema_ddl(), "first store installs the schema");
    ix.nzb_seed_store_xml(spec("licensed", "ddl", REAL_NAME), &xml, 11)
        .unwrap();
    assert!(!ix.take_schema_ddl(), "existing schema causes no new DDL");
    teardown(&dir, ix);
}

#[test]
fn a_prepared_seed_can_be_stored_after_the_full_nzb_is_dropped() {
    let (dir, mut ix) = open("prepared-store");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["prepared1@x", "prepared2@x", "prepared3@x"],
    )]);
    let nzb = crate::nzb::Nzb::parse(&xml).unwrap();
    let prepared = NzbSeedPrepared::from_nzb(&nzb).unwrap();
    drop(nzb);

    let stored = ix
        .nzb_seed_store_prepared(spec("nzb-add", "prepared", REAL_NAME), &prepared, 10)
        .unwrap();
    assert!(stored.new_set);
    assert!(stored.new_assertion);
    assert!(
        ix.nzb_seed_assertion_exists("nzb-add", "prepared", REAL_NAME)
            .unwrap()
    );
    teardown(&dir, ix);
}

#[test]
fn paid_seed_store_uses_full_durability_and_restores_the_writer_setting() {
    let (dir, mut ix) = open("durable-store");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["durable1@x", "durable2@x", "durable3@x"],
    )]);
    let nzb = crate::nzb::Nzb::parse(&xml).unwrap();
    let prepared = NzbSeedPrepared::from_nzb(&nzb).unwrap();
    let synchronous = |index: &Index| {
        index
            .db
            .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
            .unwrap()
    };
    assert_eq!(synchronous(&ix), 1);

    let stored = ix
        .nzb_seed_store_prepared_durable(spec("nzb-indexer", "durable", REAL_NAME), &prepared, 10)
        .unwrap();
    assert!(stored.new_assertion);
    assert_eq!(synchronous(&ix), 1);

    let invalid = ix
        .nzb_seed_store_prepared_durable(spec("nzb-indexer", "invalid", "Bad\nName"), &prepared, 11)
        .unwrap_err();
    assert!(matches!(invalid, NzbSeedError::Invalid(_)));
    assert_eq!(synchronous(&ix), 1);
    teardown(&dir, ix);
}

#[test]
fn retry_kv_handoff_is_atomic_and_restores_normal_synchronous_mode() {
    let (dir, ix) = open("durable-retry-kv");
    let synchronous = |index: &Index| {
        index
            .db
            .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
            .unwrap()
    };
    assert_eq!(synchronous(&ix), 1);
    ix.kv_set("retry-first", "old").unwrap();
    ix.retry_kv_set_durable(&[("retry-first", "new"), ("retry-second", "owned")])
        .unwrap();
    assert_eq!(ix.kv_get("retry-first").as_deref(), Some("new"));
    assert_eq!(ix.kv_get("retry-second").as_deref(), Some("owned"));
    assert_eq!(synchronous(&ix), 1);

    ix.db
        .execute_batch(
            "CREATE TEMP TRIGGER fail_retry_second
             BEFORE INSERT ON kv
             WHEN NEW.k='retry-fail'
             BEGIN
               SELECT RAISE(ABORT, 'injected retry kv failure');
             END;",
        )
        .unwrap();
    let error = ix
        .retry_kv_set_durable(&[("retry-first", "rolled-back"), ("retry-fail", "x")])
        .unwrap_err();
    assert!(error.to_string().contains("injected retry kv failure"));
    assert_eq!(ix.kv_get("retry-first").as_deref(), Some("new"));
    assert_eq!(ix.kv_get("retry-fail"), None);
    assert_eq!(synchronous(&ix), 1);
    teardown(&dir, ix);
}

#[test]
fn a_refused_commit_guard_rolls_back_every_seed_row() {
    let (dir, mut ix) = open("guarded-store");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["guard1@x", "guard2@x", "guard3@x"],
    )]);
    let nzb = crate::nzb::Nzb::parse(&xml).unwrap();
    let prepared = NzbSeedPrepared::from_nzb(&nzb).unwrap();

    let refused = ix
        .nzb_seed_store_prepared_guarded(
            spec("nzb-add", "guarded", REAL_NAME),
            &prepared,
            10,
            || None::<()>,
        )
        .unwrap();
    assert_eq!(refused, None);
    assert_eq!(
        ix.nzb_seed_inventory().unwrap(),
        NzbSeedInventory::default()
    );
    assert!(
        !ix.nzb_seed_schema_present().unwrap(),
        "refused first commit left optional seed DDL behind"
    );

    let stored = ix
        .nzb_seed_store_prepared(spec("nzb-add", "guarded", REAL_NAME), &prepared, 11)
        .unwrap();
    assert!(stored.new_set);
    assert!(stored.new_assertion);
    teardown(&dir, ix);
}

#[test]
fn a_refused_commit_guard_rolls_back_an_existing_capacity_ledger_delta() {
    let (dir, mut ix) = open("guarded-store-capacity");
    let first = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["guard-a1@x", "guard-a2@x", "guard-a3@x"],
    )]);
    let second = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["guard-b1@x", "guard-b2@x", "guard-b3@x"],
    )]);
    ix.nzb_seed_store_xml(spec("nzb-add", "guard-a", REAL_NAME), &first, 10)
        .unwrap();
    let usage_before = seed_usage(&ix);
    let parsed = crate::nzb::Nzb::parse(&second).unwrap();
    let prepared = NzbSeedPrepared::from_nzb(&parsed).unwrap();
    let refused = ix
        .nzb_seed_store_prepared_guarded(
            spec("nzb-add", "guard-b", REAL_NAME),
            &prepared,
            20,
            || None::<()>,
        )
        .unwrap();
    assert_eq!(refused, None);
    assert_eq!(seed_usage(&ix), usage_before);
    assert_eq!(ix.nzb_seed_inventory().unwrap().sets, 1);
    teardown(&dir, ix);
}

#[test]
fn an_outer_release_failure_restores_autocommit_and_allows_a_clean_retry() {
    let (dir, mut ix) = open("store-release-failure");
    let first = nzb_xml(&[(
        r#"&quot;first.mkv&quot; yEnc (1/3)"#,
        &["release-a1@x", "release-a2@x", "release-a3@x"],
    )]);
    let second = nzb_xml(&[(
        r#"&quot;second.mkv&quot; yEnc (1/3)"#,
        &["release-b1@x", "release-b2@x", "release-b3@x"],
    )]);
    ix.nzb_seed_store_xml(spec("licensed", "release-a", REAL_NAME), &first, 10)
        .unwrap();
    let usage_before = seed_usage(&ix);
    let parsed = crate::nzb::Nzb::parse(&second).unwrap();
    let prepared = NzbSeedPrepared::from_nzb(&parsed).unwrap();

    ix.db.commit_hook(Some(|| true)).unwrap();
    let error = ix
        .nzb_seed_store_prepared(spec("licensed", "release-b", REAL_NAME), &prepared, 20)
        .unwrap_err();
    ix.db.commit_hook(None::<fn() -> bool>).unwrap();
    assert!(matches!(error, NzbSeedError::Sqlite(_)), "{error:?}");
    assert!(
        ix.db.is_autocommit(),
        "failed RELEASE left a live transaction"
    );
    assert_eq!(seed_usage(&ix), usage_before);
    assert_eq!(ix.nzb_seed_inventory().unwrap().sets, 1);

    let retried = ix
        .nzb_seed_store_prepared(spec("licensed", "release-b", REAL_NAME), &prepared, 30)
        .unwrap();
    assert!(retried.new_set && retried.new_assertion);
    assert!(ix.db.is_autocommit());
    teardown(&dir, ix);
}

#[test]
fn legacy_seed_rows_backfill_the_exact_usage_ledger_after_reopen() {
    let (dir, mut ix) = open("capacity-backfill");
    let xml = nzb_xml(&[(
        r#"&quot;påyløad.mkv&quot; yEnc (1/3)"#,
        &["backfill1@x", "backfill2@x", "backfill3@x"],
    )]);
    ix.nzb_seed_store_xml(spec("licenséd", "bäckfill-a", REAL_NAME), &xml, 10)
        .unwrap();
    ix.nzb_seed_store_xml(
        spec(NZB_SEED_POSTED_SOURCE, "bäckfill-b", REAL_NAME),
        &xml,
        20,
    )
    .unwrap();
    let expected = seed_usage(&ix);
    ix.db
        .execute_batch(
            "DROP TABLE nzb_seed_usage;
             DROP INDEX idx_nzb_seed_assertions_trusted;",
        )
        .unwrap();
    drop(ix);

    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    assert!(!ix.take_schema_ddl());
    let duplicate = ix
        .nzb_seed_store_xml(spec("licenséd", "bäckfill-a", REAL_NAME), &xml, 30)
        .unwrap();
    assert!(!duplicate.new_set && !duplicate.new_assertion);
    assert_eq!(seed_usage(&ix), expected);
    assert!(ix.take_schema_ddl(), "ledger/index repair is runtime DDL");
    teardown(&dir, ix);
}

#[test]
fn cleanup_upgrade_purges_edges_before_publishing_its_marker() {
    let (dir, mut ix) = open("cleanup-upgrade");
    let ids = ["upgrade1@x", "upgrade2@x", "upgrade3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "upgrade", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "hI4dA8bE6lJ2zC5fR", &ids, 20);
    ix.nzb_seed_reconcile(30, 10).unwrap();
    assert_eq!(ix.nzb_seed_matches(stored.set_id).unwrap().len(), 1);
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    assert_eq!(ix.name_claims(rid).unwrap().len(), 1);
    assert!(ix.take_schema_ddl());

    ix.db
        .execute_batch(
            "DROP TRIGGER nzb_seed_release_ad_v2;
             DROP INDEX idx_nzb_seed_matches_release;",
        )
        .unwrap();
    let parsed = crate::nzb::Nzb::parse(&xml).unwrap();
    let prepared = NzbSeedPrepared::from_nzb(&parsed).unwrap();
    let refused = ix
        .nzb_seed_store_prepared_guarded(
            spec("licensed", "upgrade", REAL_NAME),
            &prepared,
            39,
            || None::<()>,
        )
        .unwrap();
    assert_eq!(refused, None);
    assert_eq!(
        ix.nzb_seed_matches(stored.set_id).unwrap().len(),
        1,
        "refused upgrade cleanup escaped its outer savepoint"
    );
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    assert_eq!(ix.name_claims(rid).unwrap().len(), 1);
    let state_before_commit: String = ix
        .db
        .query_row(
            "SELECT state FROM nzb_seed_sets WHERE id=?1",
            [stored.set_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state_before_commit, "matched");

    ix.nzb_seed_store_xml(spec("licensed", "upgrade", REAL_NAME), &xml, 40)
        .unwrap();
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    let state: String = ix
        .db
        .query_row(
            "SELECT state FROM nzb_seed_sets WHERE id=?1",
            [stored.set_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "pending");
    let cleanup_objects: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE name IN ('nzb_seed_release_ad_v2','idx_nzb_seed_matches_release')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(cleanup_objects, 2);
    assert!(ix.take_schema_ddl());
    teardown(&dir, ix);
}

#[test]
fn reopening_an_existing_seed_catalog_with_old_cleanup_revokes_weak_claims_immediately() {
    let (dir, mut ix) = open("cleanup-open-upgrade");
    let ids = ["open-upgrade1@x", "open-upgrade2@x", "open-upgrade3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "open-upgrade", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "jK5eB9cF7mL3aD6gS", &ids, 20);
    assert_eq!(
        ix.nzb_seed_reconcile_set(stored.set_id, 30)
            .unwrap()
            .claims_applied,
        1
    );
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    ix.db
        .execute_batch(
            "DROP TRIGGER nzb_seed_release_ad_v2;
             DROP INDEX idx_nzb_seed_matches_release;",
        )
        .unwrap();
    drop(ix);

    let ix = Index::open(&dir.join("index.db")).unwrap();
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    let state: String = ix
        .db
        .query_row(
            "SELECT state FROM nzb_seed_sets WHERE id=?1",
            [stored.set_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "pending");
    teardown(&dir, ix);
}

#[test]
fn reopening_rejects_a_seed_cleanup_trigger_attached_to_the_wrong_table() {
    let (dir, mut ix) = open("cleanup-open-wrong-table");
    let ids = ["wrong-table1@x", "wrong-table2@x", "wrong-table3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "wrong-table", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "kL6fC2dG8nM4bE7hT", &ids, 20);
    assert_eq!(
        ix.nzb_seed_reconcile_set(stored.set_id, 30)
            .unwrap()
            .claims_applied,
        1
    );
    assert_eq!(applied_name(&ix, rid), REAL_NAME);

    // Reproduce the old false-positive shape: every cleanup object name is
    // present, but one file trigger is attached to a different table.
    ix.db
        .execute_batch(
            "DROP TRIGGER nzb_seed_file_au_v2;
             CREATE TRIGGER nzb_seed_file_au_v2
                AFTER UPDATE ON nzb_seed_meta BEGIN SELECT 1; END;",
        )
        .unwrap();
    drop(ix);

    let ix = Index::open(&dir.join("index.db")).unwrap();
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    let active_seed_triggers: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE type='trigger' AND tbl_name='files'
                AND name IN ('nzb_seed_file_ai_v2',
                             'nzb_seed_file_au_v2',
                             'nzb_seed_file_ad_v2')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active_seed_triggers, 3);
    teardown(&dir, ix);
}

#[test]
fn reopening_replaces_seed_cleanup_objects_attached_to_the_wrong_tables() {
    let (dir, mut ix) = open("cleanup-open-wrong-owners");
    let ids = ["wrong-owner1@x", "wrong-owner2@x", "wrong-owner3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "wrong-owners", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "pM7gD3kL9sQ5vB2xR", &ids, 20);
    assert_eq!(
        ix.nzb_seed_reconcile_set(stored.set_id, 30)
            .unwrap()
            .claims_applied,
        1
    );
    assert_eq!(applied_name(&ix, rid), REAL_NAME);

    ix.db
        .execute_batch(
            "DROP TRIGGER nzb_seed_release_ad_v2;
             CREATE TRIGGER nzb_seed_release_ad_v2
                AFTER DELETE ON nzb_seed_meta BEGIN SELECT 1; END;
             DROP INDEX idx_nzb_seed_matches_release;
             CREATE INDEX idx_nzb_seed_matches_release
                ON nzb_seed_assertions(set_id);",
        )
        .unwrap();
    drop(ix);

    let ix = Index::open(&dir.join("index.db")).unwrap();
    assert_eq!(applied_name(&ix, rid), "");
    assert!(ix.name_claims(rid).unwrap().is_empty());
    assert!(ix.nzb_seed_matches(stored.set_id).unwrap().is_empty());
    let owners: Vec<(String, String, String)> = {
        let mut stmt = ix
            .db
            .prepare(
                "SELECT type,name,tbl_name FROM sqlite_master
                  WHERE name IN ('nzb_seed_release_ad_v2',
                                 'idx_nzb_seed_matches_release')
                  ORDER BY name",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    assert_eq!(
        owners,
        vec![
            (
                "index".to_string(),
                "idx_nzb_seed_matches_release".to_string(),
                "nzb_seed_matches".to_string(),
            ),
            (
                "trigger".to_string(),
                "nzb_seed_release_ad_v2".to_string(),
                "releases".to_string(),
            ),
        ]
    );
    teardown(&dir, ix);
}

#[test]
fn a_probe_cap_that_cuts_one_data_file_can_never_auto_apply() {
    let (dir, mut ix) = open("probe-cap");
    // 171 data files x 3 desired ids = 513. The bounded seed retains 512,
    // so one file is short and the whole membership set stays shadow-only.
    let mut xml = String::from(r#"<?xml version="1.0"?><nzb>"#);
    for file in 0..171 {
        xml.push_str(&format!(
            r#"<file subject="&quot;payload{file:03}.mkv&quot; yEnc (1/3)" poster="p@x" date="1"><groups><group>alt.binaries.test</group></groups><segments>"#
        ));
        for part in 1..=3 {
            xml.push_str(&format!(
                r#"<segment bytes="100" number="{part}">cap{file:03}-{part}@x</segment>"#
            ));
        }
        xml.push_str("</segments></file>");
    }
    xml.push_str("</nzb>");
    let stored = ix
        .nzb_seed_store_xml(
            spec("licensed", "wide", "Real.Show.S01.Pack.1080p.WEB-GRP"),
            xml.as_bytes(),
            10,
        )
        .unwrap();
    assert_eq!(stored.probe_ids, crate::nzbimport::PROBE_CAP);
    assert!(!stored.probe_complete);
    let stats = ix.nzb_seed_reconcile(20, 10).unwrap();
    assert_eq!(stats.sets_unsafe, 1, "{stats:?}");
    assert_eq!(stats.claims_applied, 0);
    teardown(&dir, ix);
}

/// Clear the one-shot repair marker `Index::open` already stamped on this
/// fresh database, so a test can drive the repair over a set it has just
/// downgraded to the legacy shape.
fn rearm_rekey(ix: &Index) {
    ix.db
        .execute(
            "DELETE FROM kv WHERE k IN ('nzb_seed_rekey_v1','nzb_seed_rekey_at')",
            [],
        )
        .unwrap();
}

fn set_key_and_state(ix: &Index) -> Vec<(i64, String, String)> {
    let mut stmt = ix
        .db
        .prepare("SELECT id,membership_key,state FROM nzb_seed_sets ORDER BY id")
        .unwrap();
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap();
    rows.collect::<rusqlite::Result<_>>().unwrap()
}

#[test]
fn a_legacy_md5_seed_is_rekeyed_in_place_and_stops_replaying_as_unsafe() {
    let (dir, mut ix) = open("legacy-rekey-in-place");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["rk1@x", "rk2@x", "rk3@x"],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-rk", REAL_NAME), &xml, 10)
        .unwrap();
    let parsed = crate::nzb::Nzb::parse(&xml).unwrap();
    let strong = strong_membership_key(&parsed);
    let legacy = membership_key(&parsed);
    let victim = ingest_file(&mut ix, "alt.binaries.test", "unrelated", &["other@x"], 10);

    // Exactly the shape the live index carries: a complete strong file-key
    // manifest under a membership key the verifier can never match, plus a
    // match edge written against that dead identity.
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2,state='unsafe' WHERE id=?1",
            rusqlite::params![stored.set_id, &legacy],
        )
        .unwrap();
    ix.db
        .execute(
            "INSERT OR REPLACE INTO nzb_seed_matches(
                set_id,release_id,exact_ids,covered_data_files,state,claim_key,at)
             VALUES(?1,?2,1,1,'partial','',10)",
            rusqlite::params![stored.set_id, victim],
        )
        .unwrap();
    rearm_rekey(&ix);
    assert!(
        !ix.nzb_seed_strong_assertion_exists("licensed", "guid-rk", REAL_NAME)
            .unwrap(),
        "precondition: the legacy identity is unverifiable"
    );
    let charged_before = seed_usage(&ix).3;

    let stats = ix.nzb_seed_legacy_rekey_slice().unwrap();
    assert_eq!(
        (
            stats.examined,
            stats.rekeyed,
            stats.collided,
            stats.unrepairable,
            stats.done
        ),
        (1, 1, 0, 0, true),
        "{stats:?}"
    );
    assert_eq!(
        set_key_and_state(&ix),
        vec![(stored.set_id, strong.clone(), "pending".to_string())],
        "the set carries the recomputed strong key and is queued to replay"
    );
    let edges: i64 = ix
        .db
        .query_row(
            "SELECT COUNT(*) FROM nzb_seed_matches WHERE set_id=?1",
            [stored.set_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        edges, 0,
        "edges written under the dead identity are dropped"
    );
    assert!(
        ix.nzb_seed_strong_assertion_exists("licensed", "guid-rk", REAL_NAME)
            .unwrap(),
        "the identity verifies again, so replay can leave 'unsafe'"
    );
    assert_eq!(
        seed_usage(&ix).3 - charged_before,
        2 * (strong.len() as i64 - legacy.len() as i64),
        "the unique membership index keeps a second copy of the longer key"
    );

    // One-shot: the marker is stamped, so the next open reads nothing.
    let again = ix.nzb_seed_legacy_rekey_slice().unwrap();
    assert_eq!((again.examined, again.done), (0, true), "{again:?}");
    teardown(&dir, ix);
}

#[test]
fn a_legacy_seed_whose_strong_key_is_already_held_is_left_exactly_as_it_is() {
    let (dir, mut ix) = open("legacy-rekey-collision");
    let healthy_xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["cl1@x", "cl2@x", "cl3@x"],
    )]);
    let healthy = ix
        .nzb_seed_store_xml(spec("licensed", "guid-new", REAL_NAME), &healthy_xml, 10)
        .unwrap();
    let stale_xml = nzb_xml(&[(
        r#"&quot;other.mkv&quot; yEnc (1/3)"#,
        &["cl4@x", "cl5@x", "cl6@x"],
    )]);
    let stale = ix
        .nzb_seed_store_xml(spec("licensed", "guid-old", REAL_NAME), &stale_xml, 10)
        .unwrap();
    let legacy = membership_key(&crate::nzb::Nzb::parse(&stale_xml).unwrap());

    // Make the older row a second copy of the same NZB under the old
    // identity: same per-file manifest, legacy membership key.
    ix.db
        .execute(
            "DELETE FROM nzb_seed_file_keys WHERE set_id=?1",
            [stale.set_id],
        )
        .unwrap();
    ix.db
        .execute(
            "INSERT INTO nzb_seed_file_keys(set_id,file_ord,kind,manifest_key)
             SELECT ?1,file_ord,kind,manifest_key FROM nzb_seed_file_keys WHERE set_id=?2",
            rusqlite::params![stale.set_id, healthy.set_id],
        )
        .unwrap();
    ix.db
        .execute(
            "UPDATE nzb_seed_sets
                SET membership_key=?2,state='unsafe',
                    file_count=(SELECT file_count FROM nzb_seed_sets WHERE id=?3)
              WHERE id=?1",
            rusqlite::params![stale.set_id, &legacy, healthy.set_id],
        )
        .unwrap();
    rearm_rekey(&ix);
    let before = set_key_and_state(&ix);

    let stats = ix.nzb_seed_legacy_rekey_slice().unwrap();
    assert_eq!(
        (stats.examined, stats.rekeyed, stats.collided, stats.done),
        (1, 0, 1, true),
        "{stats:?}"
    );
    assert_eq!(
        set_key_and_state(&ix),
        before,
        "the healthy twin already holds the evidence, so nothing is merged or moved"
    );
    teardown(&dir, ix);
}

#[test]
fn a_legacy_seed_without_strong_file_keys_waits_for_a_later_grab() {
    let (dir, mut ix) = open("legacy-rekey-unrepairable");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["nr1@x", "nr2@x", "nr3@x"],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-nr", REAL_NAME), &xml, 10)
        .unwrap();
    let legacy = membership_key(&crate::nzb::Nzb::parse(&xml).unwrap());
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2,state='unsafe' WHERE id=?1",
            rusqlite::params![stored.set_id, &legacy],
        )
        .unwrap();
    ix.db
        .execute(
            "DELETE FROM nzb_seed_file_keys WHERE set_id=?1",
            [stored.set_id],
        )
        .unwrap();
    rearm_rekey(&ix);

    let stats = ix.nzb_seed_legacy_rekey_slice().unwrap();
    assert_eq!(
        (
            stats.examined,
            stats.rekeyed,
            stats.unrepairable,
            stats.done
        ),
        (1, 0, 1, true),
        "{stats:?}"
    );
    assert_eq!(
        set_key_and_state(&ix),
        vec![(stored.set_id, legacy, "unsafe".to_string())],
        "an identity that is not on disk is never invented"
    );
    teardown(&dir, ix);
}

#[test]
fn a_short_file_key_manifest_is_not_rekeyed_from_the_rows_that_survive() {
    let (dir, mut ix) = open("legacy-rekey-short-manifest");
    let xml = nzb_xml(&[
        (
            r#"&quot;payload.part1.rar&quot; yEnc (1/2)"#,
            &["sh1@x", "sh2@x"],
        ),
        (
            r#"&quot;payload.part2.rar&quot; yEnc (1/2)"#,
            &["sh3@x", "sh4@x"],
        ),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-sh", REAL_NAME), &xml, 10)
        .unwrap();
    let legacy = membership_key(&crate::nzb::Nzb::parse(&xml).unwrap());
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2,state='unsafe' WHERE id=?1",
            rusqlite::params![stored.set_id, &legacy],
        )
        .unwrap();
    // Drop one file's key. The survivors would hash to a perfectly
    // well-formed digest of a DIFFERENT manifest, which is exactly the
    // silent-wrong-identity this guard exists to refuse.
    ix.db
        .execute(
            "DELETE FROM nzb_seed_file_keys WHERE set_id=?1 AND file_ord=(
                SELECT MAX(file_ord) FROM nzb_seed_file_keys WHERE set_id=?1)",
            [stored.set_id],
        )
        .unwrap();
    rearm_rekey(&ix);

    let stats = ix.nzb_seed_legacy_rekey_slice().unwrap();
    assert_eq!(
        (stats.examined, stats.rekeyed, stats.unrepairable),
        (1, 0, 1),
        "{stats:?}"
    );
    assert_eq!(
        set_key_and_state(&ix),
        vec![(stored.set_id, legacy, "unsafe".to_string())],
    );
    teardown(&dir, ix);
}

#[test]
fn a_legacy_seed_that_could_never_name_a_row_names_it_after_the_open_path_repair() {
    let (dir, mut ix) = open("legacy-rekey-end-to-end");
    let ids = ["e2e1@x", "e2e2@x", "e2e3@x"];
    let xml = nzb_xml(&[(r#"&quot;payload.mkv&quot; yEnc (1/3)"#, &ids)]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-e2e", REAL_NAME), &xml, 10)
        .unwrap();
    let rid = ingest_file(&mut ix, "alt.binaries.test", "aB7kQ2mZ9xP4vN6tR", &ids, 20);
    settle_release(&ix, rid, 40);

    // The live shape: a complete, settled, exactly matching local release and
    // a seed that cannot verify its own identity.
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2,state='pending',last_reconciled=0
              WHERE id=?1",
            rusqlite::params![
                stored.set_id,
                membership_key(&crate::nzb::Nzb::parse(&xml).unwrap())
            ],
        )
        .unwrap();
    rearm_rekey(&ix);
    let blind = ix.nzb_seed_reconcile(40, 10).unwrap();
    assert_eq!(
        (blind.sets_unsafe, blind.claims_applied),
        (1, 0),
        "the legacy identity replays to 'unsafe' forever: {blind:?}"
    );
    assert_eq!(applied_name(&ix, rid), "");

    // Reopening runs the one-shot repair, and the same row is now nameable
    // by the same unchanged proof rule.
    drop(ix);
    let mut ix = Index::open(&dir.join("index.db")).unwrap();
    assert!(
        ix.nzb_seed_legacy_rekey_slice().unwrap().done,
        "open leaves the repair complete"
    );
    let repaired = ix.nzb_seed_reconcile(60, 10).unwrap();
    assert_eq!(
        (repaired.sets_unsafe, repaired.claims_applied),
        (0, 1),
        "{repaired:?}"
    );
    assert_eq!(applied_name(&ix, rid), REAL_NAME);
    teardown(&dir, ix);
}

#[test]
fn the_rekey_repair_survives_a_catalogue_that_has_no_capacity_ledger() {
    let (dir, mut ix) = open("legacy-rekey-no-ledger");
    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["nl1@x", "nl2@x", "nl3@x"],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-nl", REAL_NAME), &xml, 10)
        .unwrap();
    let strong = strong_membership_key(&crate::nzb::Nzb::parse(&xml).unwrap());
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2,state='unsafe' WHERE id=?1",
            rusqlite::params![
                stored.set_id,
                membership_key(&crate::nzb::Nzb::parse(&xml).unwrap())
            ],
        )
        .unwrap();
    // The shape a prototype catalogue can be in: seed tables, no ledger.
    // This runs on the open path, so a "no such table" here would refuse
    // the whole index rather than skip an accounting line.
    ix.db.execute_batch("DROP TABLE nzb_seed_usage").unwrap();
    assert!(!ix.nzb_seed_capacity_schema_present().unwrap());
    rearm_rekey(&ix);

    let stats = ix.nzb_seed_legacy_rekey_slice().unwrap();
    assert_eq!((stats.rekeyed, stats.done), (1, true), "{stats:?}");
    assert_eq!(
        set_key_and_state(&ix),
        vec![(stored.set_id, strong, "pending".to_string())],
    );
    teardown(&dir, ix);
}

/// Clear the one-shot purge marker `Index::open` already stamped on this
/// fresh database, so a test can drive the purge over a set it has just
/// downgraded to the unrepairable legacy shape.
fn rearm_purge(ix: &Index) {
    ix.db
        .execute(
            "DELETE FROM kv WHERE k IN ('nzb_seed_purge_v1','nzb_seed_purge_at')",
            [],
        )
        .unwrap();
}

/// Rows still hanging off `set_id` in each of the five child tables.
fn seed_child_rows(ix: &Index, set_id: i64) -> Vec<i64> {
    [
        "nzb_seed_assertions",
        "nzb_seed_files",
        "nzb_seed_file_keys",
        "nzb_seed_msgids",
        "nzb_seed_matches",
    ]
    .into_iter()
    .map(|table| {
        ix.db
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE set_id=?1"),
                [set_id],
                |row| row.get(0),
            )
            .unwrap()
    })
    .collect()
}

/// Downgrade a stored set to the exact live residue shape: a legacy MD5
/// membership key with no strong file-key rows at all.
fn make_unrepairable(ix: &Index, set_id: i64, xml: &[u8]) -> String {
    let legacy = membership_key(&crate::nzb::Nzb::parse(xml).unwrap());
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2,state='unsafe' WHERE id=?1",
            rusqlite::params![set_id, &legacy],
        )
        .unwrap();
    ix.db
        .execute("DELETE FROM nzb_seed_file_keys WHERE set_id=?1", [set_id])
        .unwrap();
    legacy
}

#[test]
fn admitting_a_seed_and_deleting_it_returns_every_ledger_counter() {
    let (dir, mut ix) = open("seed-delete-ledger-roundtrip");
    // Prime the optional catalogue with an unrelated set, so this measures
    // against a non-zero ledger rather than the empty case.
    let other = nzb_xml(&[(r#"&quot;other.mkv&quot; yEnc (1/2)"#, &["ot1@x", "ot2@x"])]);
    ix.nzb_seed_store_xml(spec("licensed", "guid-other", REAL_NAME), &other, 10)
        .unwrap();
    let before = seed_usage(&ix);

    let xml = nzb_xml(&[
        (
            r#"&quot;payload.part1.rar&quot; yEnc (1/2)"#,
            &["rt1@x", "rt2@x"],
        ),
        (
            r#"&quot;payload.part2.rar&quot; yEnc (1/2)"#,
            &["rt3@x", "rt4@x"],
        ),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-rt", REAL_NAME), &xml, 10)
        .unwrap();
    let admitted = seed_usage(&ix);
    assert_ne!(
        admitted, before,
        "the admission has to have charged something"
    );

    // The pristine round trip, and the reason the backfill and the refund
    // share one expression: whatever `seed_set_charge` and
    // `seed_assertion_charge` took, the delete gives back.
    ix.delete_nzb_seed_set(stored.set_id).unwrap();
    assert_eq!(
        seed_usage(&ix),
        before,
        "a deleted set gives the ledger back exactly what admission took"
    );
    assert_eq!(seed_child_rows(&ix, stored.set_id), vec![0; 5]);
    assert!(
        !set_key_and_state(&ix)
            .iter()
            .any(|(id, _, _)| *id == stored.set_id),
        "the set row itself is gone"
    );
    teardown(&dir, ix);
}

#[test]
fn deleting_a_posted_only_seed_returns_the_posted_assertion_counter_too() {
    let (dir, mut ix) = open("seed-delete-posted-counter");
    let other = nzb_xml(&[(r#"&quot;other.mkv&quot; yEnc (1/2)"#, &["op1@x", "op2@x"])]);
    ix.nzb_seed_store_xml(spec("licensed", "guid-op", REAL_NAME), &other, 10)
        .unwrap();
    let before = seed_usage(&ix);

    let xml = nzb_xml(&[(
        r#"&quot;posted.mkv&quot; yEnc (1/3)"#,
        &["po1@x", "po2@x", "po3@x"],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec(NZB_SEED_POSTED_SOURCE, "guid-po", REAL_NAME), &xml, 10)
        .unwrap();
    assert_eq!(
        seed_usage(&ix).2,
        before.2 + 1,
        "a posted assertion was charged"
    );

    ix.delete_nzb_seed_set(stored.set_id).unwrap();
    assert_eq!(seed_usage(&ix), before);
    teardown(&dir, ix);
}

#[test]
fn the_purge_gives_the_ledger_back_the_set_it_removes() {
    let (dir, mut ix) = open("seed-purge-ledger-give-back");
    let other = nzb_xml(&[(r#"&quot;other.mkv&quot; yEnc (1/2)"#, &["og1@x", "og2@x"])]);
    ix.nzb_seed_store_xml(spec("licensed", "guid-og", REAL_NAME), &other, 10)
        .unwrap();
    let before = seed_usage(&ix);

    let xml = nzb_xml(&[(
        r#"&quot;payload.mkv&quot; yEnc (1/3)"#,
        &["pg1@x", "pg2@x", "pg3@x"],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-pg", REAL_NAME), &xml, 10)
        .unwrap();
    make_unrepairable(&ix, stored.set_id, &xml);
    // Downgrading in a test drops charged rows behind the ledger's back, so
    // the honest claim here is against the set AS IT NOW STANDS - which is
    // also the shape the live residue is actually in. The exact-to-the-byte
    // admission round trip is
    // `admitting_a_seed_and_deleting_it_returns_every_ledger_counter`.
    let charge = ix.nzb_seed_set_logical_charge(stored.set_id).unwrap();
    assert!(charge > 0);
    let downgraded = seed_usage(&ix);

    rearm_purge(&ix);
    let stats = ix.nzb_seed_unrepairable_purge_slice().unwrap();
    assert_eq!(
        (
            stats.examined,
            stats.purged,
            stats.kept,
            stats.claimed,
            stats.done
        ),
        (1, 1, 0, 0, true),
        "{stats:?}"
    );

    let after = seed_usage(&ix);
    assert_eq!(
        (after.0, after.1, after.2),
        (before.0, before.1, before.2),
        "set and assertion counters return to their pre-admission values"
    );
    assert_eq!(
        after.3,
        downgraded.3 - charge,
        "charged_bytes falls by exactly the purged set's own logical charge"
    );
    assert_eq!(seed_child_rows(&ix, stored.set_id), vec![0; 5]);
    assert!(
        !set_key_and_state(&ix)
            .iter()
            .any(|(id, _, _)| *id == stored.set_id),
        "the set row itself is gone"
    );
    teardown(&dir, ix);
}

#[test]
fn the_purge_takes_only_the_legacy_set_that_cannot_express_its_identity() {
    let (dir, mut ix) = open("seed-purge-only-unrepairable");
    let healthy_xml = nzb_xml(&[(r#"&quot;healthy.mkv&quot; yEnc (1/2)"#, &["he1@x", "he2@x"])]);
    let healthy = ix
        .nzb_seed_store_xml(spec("licensed", "guid-he", REAL_NAME), &healthy_xml, 10)
        .unwrap();

    // Legacy key, but the strong manifests ARE on disk: the re-key owns it.
    let repairable_xml = nzb_xml(&[(
        r#"&quot;repairable.mkv&quot; yEnc (1/2)"#,
        &["re1@x", "re2@x"],
    )]);
    let repairable = ix
        .nzb_seed_store_xml(spec("licensed", "guid-re", REAL_NAME), &repairable_xml, 10)
        .unwrap();
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2,state='unsafe' WHERE id=?1",
            rusqlite::params![
                repairable.set_id,
                membership_key(&crate::nzb::Nzb::parse(&repairable_xml).unwrap())
            ],
        )
        .unwrap();

    // Legacy key AND no manifests at all: the residue this pass exists for.
    let doomed_xml = nzb_xml(&[(r#"&quot;doomed.mkv&quot; yEnc (1/2)"#, &["do1@x", "do2@x"])]);
    let doomed = ix
        .nzb_seed_store_xml(spec("licensed", "guid-do", REAL_NAME), &doomed_xml, 10)
        .unwrap();
    make_unrepairable(&ix, doomed.set_id, &doomed_xml);

    rearm_purge(&ix);
    let stats = ix.nzb_seed_unrepairable_purge_slice().unwrap();
    assert_eq!(
        (stats.examined, stats.purged, stats.kept, stats.claimed),
        (2, 1, 1, 0),
        "the sha256 set is never even selected: {stats:?}"
    );
    let surviving: Vec<i64> = set_key_and_state(&ix)
        .into_iter()
        .map(|(id, ..)| id)
        .collect();
    assert_eq!(surviving, vec![healthy.set_id, repairable.set_id]);
    teardown(&dir, ix);
}

#[test]
fn a_short_file_key_manifest_is_purged_rather_than_hashed_from_the_survivors() {
    let (dir, mut ix) = open("seed-purge-short-manifest");
    let xml = nzb_xml(&[
        (
            r#"&quot;payload.part1.rar&quot; yEnc (1/2)"#,
            &["ps1@x", "ps2@x"],
        ),
        (
            r#"&quot;payload.part2.rar&quot; yEnc (1/2)"#,
            &["ps3@x", "ps4@x"],
        ),
    ]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-ps", REAL_NAME), &xml, 10)
        .unwrap();
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET membership_key=?2,state='unsafe' WHERE id=?1",
            rusqlite::params![
                stored.set_id,
                membership_key(&crate::nzb::Nzb::parse(&xml).unwrap())
            ],
        )
        .unwrap();
    // A partial manifest is not an identity either: the survivors would hash
    // to a well-formed digest of a DIFFERENT set. The re-key refuses it, and
    // this pass takes it for the same reason rather than inventing a key.
    ix.db
        .execute(
            "DELETE FROM nzb_seed_file_keys WHERE set_id=?1 AND file_ord=(
                SELECT MAX(file_ord) FROM nzb_seed_file_keys WHERE set_id=?1)",
            [stored.set_id],
        )
        .unwrap();

    rearm_purge(&ix);
    assert_eq!(ix.nzb_seed_unrepairable_purge_slice().unwrap().purged, 1);
    assert_eq!(seed_child_rows(&ix, stored.set_id), vec![0; 5]);
    teardown(&dir, ix);
}

#[test]
fn the_purge_keeps_a_legacy_set_that_still_supports_a_name_claim() {
    let (dir, mut ix) = open("seed-purge-live-claim");
    let xml = nzb_xml(&[(r#"&quot;claimed.mkv&quot; yEnc (1/2)"#, &["cl1@x", "cl2@x"])]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-cl", REAL_NAME), &xml, 10)
        .unwrap();
    make_unrepairable(&ix, stored.set_id, &xml);
    // The 17 live sets have no match edge at all, which is why they carry no
    // claim. Force the shape anyway: the guard is a check, not an assumption.
    ix.db
        .execute(
            "INSERT INTO nzb_seed_matches(
                set_id,release_id,exact_ids,covered_data_files,state,claim_key,at)
             VALUES(?1,1,2,1,'exact','forced-claim-key',10)",
            [stored.set_id],
        )
        .unwrap();

    rearm_purge(&ix);
    let stats = ix.nzb_seed_unrepairable_purge_slice().unwrap();
    assert_eq!(
        (stats.examined, stats.purged, stats.claimed),
        (1, 0, 1),
        "{stats:?}"
    );
    assert!(
        set_key_and_state(&ix)
            .iter()
            .any(|(id, _, _)| *id == stored.set_id),
        "a set something still names is never deleted"
    );
    teardown(&dir, ix);
}

#[test]
fn the_purge_leaves_a_catalogue_with_no_file_key_table_entirely_alone() {
    let (dir, mut ix) = open("seed-purge-no-file-key-table");
    let xml = nzb_xml(&[(r#"&quot;nokeys.mkv&quot; yEnc (1/2)"#, &["nk1@x", "nk2@x"])]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-nk", REAL_NAME), &xml, 10)
        .unwrap();
    let legacy = make_unrepairable(&ix, stored.set_id, &xml);
    // Without the table EVERY set reads as "no strong keys on disk". Purging
    // here would empty the catalogue on the strength of a missing table.
    ix.db
        .execute_batch("DROP TABLE nzb_seed_file_keys")
        .unwrap();
    rearm_purge(&ix);

    let stats = ix.nzb_seed_unrepairable_purge_slice().unwrap();
    assert_eq!(
        (stats.examined, stats.purged, stats.done),
        (0, 0, false),
        "nothing runs, and the marker stays unset so a later open retries: {stats:?}"
    );
    assert_eq!(
        set_key_and_state(&ix),
        vec![(stored.set_id, legacy, "unsafe".to_string())],
    );
    teardown(&dir, ix);
}

#[test]
fn the_purge_survives_a_catalogue_that_has_no_capacity_ledger() {
    let (dir, mut ix) = open("seed-purge-no-ledger");
    let xml = nzb_xml(&[(
        r#"&quot;noledger.mkv&quot; yEnc (1/2)"#,
        &["nq1@x", "nq2@x"],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-nq", REAL_NAME), &xml, 10)
        .unwrap();
    make_unrepairable(&ix, stored.set_id, &xml);
    // Seed tables, no ledger. This runs on the open path, so a "no such
    // table" here would refuse the whole index rather than skip accounting.
    ix.db.execute_batch("DROP TABLE nzb_seed_usage").unwrap();
    assert!(!ix.nzb_seed_capacity_schema_present().unwrap());
    rearm_purge(&ix);

    let stats = ix.nzb_seed_unrepairable_purge_slice().unwrap();
    assert_eq!((stats.purged, stats.done), (1, true), "{stats:?}");
    assert_eq!(set_key_and_state(&ix), vec![]);
    teardown(&dir, ix);
}

#[test]
fn a_drifted_ledger_is_clamped_rather_than_refusing_the_index() {
    let (dir, mut ix) = open("seed-purge-drifted-ledger");
    let xml = nzb_xml(&[(r#"&quot;drift.mkv&quot; yEnc (1/2)"#, &["dr1@x", "dr2@x"])]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-dr", REAL_NAME), &xml, 10)
        .unwrap();
    make_unrepairable(&ix, stored.set_id, &xml);
    // A ledger that already reads lower than the rows it accounts for. A
    // bare subtraction would trip one of the table's CHECK constraints, and
    // on the open path that refuses the whole index instead of repairing it.
    ix.db
        .execute_batch(
            "UPDATE nzb_seed_usage
                SET sets=0,assertions=0,posted_assertions=0,charged_bytes=1
              WHERE id=1",
        )
        .unwrap();
    rearm_purge(&ix);

    assert_eq!(ix.nzb_seed_unrepairable_purge_slice().unwrap().purged, 1);
    assert_eq!(seed_usage(&ix), (0, 0, 0, 0));
    teardown(&dir, ix);
}

#[test]
fn the_open_path_purge_is_one_shot_and_clears_the_replay_residue() {
    let (dir, mut ix) = open("seed-purge-open-path");
    let xml = nzb_xml(&[(
        r#"&quot;residue.mkv&quot; yEnc (1/3)"#,
        &["rs1@x", "rs2@x", "rs3@x"],
    )]);
    let stored = ix
        .nzb_seed_store_xml(spec("licensed", "guid-rs", REAL_NAME), &xml, 10)
        .unwrap();
    make_unrepairable(&ix, stored.set_id, &xml);
    ix.db
        .execute(
            "UPDATE nzb_seed_sets SET state='pending',last_reconciled=0 WHERE id=?1",
            [stored.set_id],
        )
        .unwrap();
    rearm_rekey(&ix);
    rearm_purge(&ix);
    // Before the repair the set replays to `unsafe` and can never name a row.
    let blind = ix.nzb_seed_reconcile(40, 10).unwrap();
    assert_eq!(
        (blind.sets_unsafe, blind.claims_applied),
        (1, 0),
        "{blind:?}"
    );

    drop(ix);
    let ix = Index::open(&dir.join("index.db")).unwrap();
    assert_eq!(set_key_and_state(&ix), vec![], "open clears the residue");
    assert!(
        ix.nzb_seed_unrepairable_purge_slice().unwrap().done,
        "the marker makes it one-shot"
    );
    teardown(&dir, ix);
}
