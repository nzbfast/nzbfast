use super::*;

fn with_daemon(name: &str, test: impl FnOnce(&Arc<Daemon>)) {
    let dir =
        std::env::temp_dir().join(format!("nzbfast-posted-seed-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let daemon = crate::testutil::test_daemon(&dir);
    test(&daemon);
    drop(daemon);
    let _ = std::fs::remove_dir_all(&dir);
}

fn xml(subject: &str) -> Vec<u8> {
    format!(
            r#"<?xml version="1.0"?><nzb><head><meta type="title">Meta.Show.S02E03.1080p-GRP</meta></head><file subject="&quot;{subject}&quot; yEnc (1/3)" poster="p@x" date="1700000000"><groups><group>a.b.dark</group></groups><segments><segment bytes="100" number="1">posted1@x</segment><segment bytes="100" number="2">posted2@x</segment><segment bytes="100" number="3">posted3@x</segment></segments></file></nzb>"#
        )
        .into_bytes()
}

fn candidate(stem: &str) -> nzbkit::index::PostedNzbCandidate {
    nzbkit::index::PostedNzbCandidate {
        release_id: 42,
        arrival_seq: 7,
        stem: stem.into(),
        grp: "private.secret.group".into(),
        junk: 0,
        segs: Vec::new(),
        bytes: 999,
    }
}

fn settle_for_test(
    d: &Arc<Daemon>,
    candidate: &nzbkit::index::PostedNzbCandidate,
    xml: Option<Vec<u8>>,
) -> bool {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(settle_posted_candidate(
            d,
            d.index_era(),
            candidate.arrival_seq,
            candidate.stem.clone(),
            xml,
        ))
}

fn write_legacy_retry(d: &Daemon, encoded: &[u8]) {
    crate::persist::write_atomic(&confirm_retry_path(d), encoded).unwrap();
    crate::smart::sync_dir(&d.spool).unwrap();
}

#[test]
fn posted_settlement_is_durable_before_cursor_and_has_fixed_private_provenance() {
    with_daemon("durable", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let xml = xml("payload.mkv");
        let candidate = candidate("Outer.Show.S01E01.1080p-GRP.nzb");
        let guid = nzb_sha(&xml);

        assert!(settle_for_test(d, &candidate, Some(xml.clone())));
        assert_eq!(
            d.with_index(|index| Some(index.nzbimport_cursor()))
                .unwrap(),
            candidate.arrival_seq
        );
        d.with_index(|index| {
            assert!(
                index
                    .nzb_seed_assertion_exists("posted-nzb", &guid, "Outer.Show.S01E01.1080p-GRP",)
                    .unwrap()
            );
            assert!(
                    !index
                        .nzb_seed_assertion_exists(
                            &candidate.grp,
                            &guid,
                            "Outer.Show.S01E01.1080p-GRP",
                        )
                        .unwrap()
                );
            let inventory = index.nzb_seed_inventory().unwrap();
            assert_eq!((inventory.sets, inventory.assertions), (1, 1));
            Some(())
        })
        .unwrap();

        assert!(settle_for_test(d, &candidate, Some(xml)));
        d.with_index(|index| {
            assert_eq!(index.nzb_seed_inventory().unwrap().assertions, 1);
            Some(())
        })
        .unwrap();
    });
}

#[test]
fn posted_seed_retries_without_creating_a_switched_off_index() {
    with_daemon("off", |d| {
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.close_index();
        let xml = xml("payload.mkv");
        let candidate = candidate("Outer.Show.S01E01.1080p-GRP.nzb");
        assert!(!settle_for_test(d, &candidate, Some(xml)));
        assert_eq!(
            d.with_index(|index| Some(index.nzbimport_cursor())),
            None,
            "retryable storage created or advanced a switched-off index"
        );
        assert!(!d.index_db.exists());
    });
}

#[test]
fn posted_seed_capacity_is_terminal_and_advances_the_cursor() {
    with_daemon("capacity-terminal", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let data = xml("payload.mkv");
        let first = candidate("First.Show.S01E01.1080p-GRP.nzb");
        assert!(settle_for_test(d, &first, Some(data.clone())));

        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.close_index();
        let db = rusqlite::Connection::open(&d.index_db).unwrap();
        db.execute(
            "UPDATE nzb_seed_usage SET charged_bytes=?1 WHERE id=1",
            [1_i64 << 30],
        )
        .unwrap();
        drop(db);
        d.index_enabled.store(true, Ordering::Relaxed);

        let mut second = candidate("Second.Show.S01E02.1080p-GRP.nzb");
        second.arrival_seq = first.arrival_seq + 1;
        assert!(
            settle_for_test(d, &second, Some(data)),
            "a permanent public-proof limit must not park the source cursor"
        );
        d.with_index(|index| {
            assert_eq!(index.nzbimport_cursor(), second.arrival_seq);
            assert_eq!(index.nzb_seed_inventory().unwrap().assertions, 1);
            Some(())
        })
        .unwrap();
    });
}

#[test]
fn posted_seed_catalog_corruption_retries_without_advancing_the_cursor() {
    with_daemon("catalog-corrupt-retry", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let data = xml("payload.mkv");
        let first = candidate("Catalog.Show.S01E01.1080p-GRP.nzb");
        assert!(settle_for_test(d, &first, Some(data.clone())));

        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.close_index();
        let db = rusqlite::Connection::open(&d.index_db).unwrap();
        assert_eq!(
            db.execute(
                "DELETE FROM nzb_seed_file_keys
                      WHERE set_id=(SELECT MIN(id) FROM nzb_seed_sets)",
                [],
            )
            .unwrap(),
            1
        );
        drop(db);
        d.index_enabled.store(true, Ordering::Relaxed);

        let mut second = candidate("Catalog.Show.S01E01.1080p-GRP.nzb");
        second.arrival_seq = first.arrival_seq + 1;
        let settled = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(settle_posted_candidate(
                d,
                d.index_era(),
                second.arrival_seq,
                second.stem,
                Some(data),
            ));
        assert!(
            !settled,
            "catalog corruption was treated as terminal content"
        );
        assert_eq!(
            d.with_index(|index| Some(index.nzbimport_cursor())),
            Some(first.arrival_seq)
        );
    });
}

#[test]
fn a_republished_seed_retry_remains_popppable_if_recent_cleanup_did_not_commit() {
    with_daemon("seed-retry-boundary", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let title = "Retry.Boundary.S01E01.1080p-GRP";
        let key = nzbkit::predb::match_key(title);
        d.with_index(|index| {
            index
                .kv_set(
                    SEED_QUEUE_KEY,
                    &serde_json::to_string(&vec![title]).unwrap(),
                )
                .ok()?;
            index
                .kv_set(SEED_RECENT_KEY, &serde_json::to_string(&vec![key]).unwrap())
                .ok()
        })
        .unwrap();

        assert_eq!(seed_pop(d).as_deref(), Some(title));
    });
}

#[test]
fn a_seed_retry_survives_temporary_index_disablement_in_the_retry_journal() {
    with_daemon("seed-retry-journal", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let (era, catalog_id) = confirm_catalog_fence(d).unwrap();
        let title = "Retry.Journal.S01E01.1080p-GRP";
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.close_index();

        retry_confirm_pick(d, era, &catalog_id, true, None, title);
        assert!(confirm_retry_path(d).is_file());
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(flush_confirm_retry(d));
        assert!(!confirm_retry_path(d).exists());
        assert_eq!(seed_pop(d).as_deref(), Some(title));
    });
}

#[test]
fn an_expected_retry_survives_temporary_index_disablement_in_the_retry_journal() {
    with_daemon("expected-retry-journal", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let (era, catalog_id) = confirm_catalog_fence(d).unwrap();
        let pick = super::super::expected::ExpectedPick::Tv {
            show: "Retry Journal Show".into(),
            season: 1,
            episode: 2,
        };
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.close_index();

        retry_confirm_pick(d, era, &catalog_id, false, Some(&pick), &pick.query());
        assert!(confirm_retry_path(d).is_file());
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(flush_confirm_retry(d));
        assert!(!confirm_retry_path(d).exists());
        let restored = super::super::expected::expected_next(d, 1).unwrap();
        assert_eq!(restored.query(), pick.query());
    });
}

#[test]
fn a_legacy_seed_retry_uses_the_same_catalog_recent_witness_after_restart() {
    with_daemon("legacy-seed-retry", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let title = "Legacy.Seed.Retry.S01E01.1080p-GRP";
        d.with_index(|index| {
            index
                .kv_set(
                    SEED_QUEUE_KEY,
                    &serde_json::to_string(&vec![title]).unwrap(),
                )
                .ok()
        })
        .unwrap();
        assert_eq!(seed_pop(d).as_deref(), Some(title));
        write_legacy_retry(
            d,
            format!(r#"{{"Seed":{{"era":0,"title":"{title}"}}}}"#).as_bytes(),
        );

        d.close_index();
        assert!(flush_confirm_retry(d));
        assert!(!confirm_retry_path(d).exists());
        assert_eq!(seed_pop(d).as_deref(), Some(title));
    });
}

#[test]
fn a_legacy_expected_retry_uses_the_same_catalog_done_witness_after_restart() {
    with_daemon("legacy-expected-retry", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let pick = super::super::expected::ExpectedPick::Movie {
            title: "Legacy Expected Retry".into(),
            year: 2026,
        };
        let era = d.index_era();
        assert_eq!(
            super::super::expected::expected_retry_at(d, era, &pick),
            Some(true)
        );
        let popped = super::super::expected::expected_next(d, 1).unwrap();
        assert_eq!(popped.query(), pick.query());
        write_legacy_retry(
            d,
            serde_json::json!({"Expected": {"era": 0, "pick": pick}})
                .to_string()
                .as_bytes(),
        );

        d.close_index();
        assert!(flush_confirm_retry(d));
        assert!(!confirm_retry_path(d).exists());
        let restored = super::super::expected::expected_next(d, 1).unwrap();
        assert_eq!(restored.query(), popped.query());
    });
}

#[test]
fn a_legacy_retry_without_a_catalog_witness_is_not_injected_after_wipe() {
    with_daemon("legacy-retry-wipe", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let title = "Legacy.Wiped.Retry.S01E01.1080p-GRP";
        d.with_index(|index| {
            index
                .kv_set(
                    SEED_QUEUE_KEY,
                    &serde_json::to_string(&vec![title]).unwrap(),
                )
                .ok()
        })
        .unwrap();
        assert_eq!(seed_pop(d).as_deref(), Some(title));
        write_legacy_retry(
            d,
            format!(r#"{{"Seed":{{"era":0,"title":"{title}"}}}}"#).as_bytes(),
        );

        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.close_index();
        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{suffix}", d.index_db.display()));
            let _ = std::fs::remove_file(path);
        }
        d.index_migrated.store(false, Ordering::Release);
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(flush_confirm_retry(d));
        assert!(!confirm_retry_path(d).exists());
        assert_eq!(seed_pop(d), None);
    });
}

#[test]
fn a_retry_journal_from_a_wiped_catalog_is_not_injected_into_the_new_index() {
    with_daemon("retry-catalog-fence", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let (era, catalog_id) = confirm_catalog_fence(d).unwrap();
        let title = "Wiped.Catalog.S01E01.1080p-GRP";
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.close_index();
        retry_confirm_pick(d, era, &catalog_id, true, None, title);
        assert!(confirm_retry_path(d).is_file());

        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{suffix}", d.index_db.display()));
            let _ = std::fs::remove_file(path);
        }
        d.index_migrated.store(false, Ordering::Release);
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(flush_confirm_retry(d));
        assert!(!confirm_retry_path(d).exists());
        assert_eq!(seed_pop(d), None);
    });
}

#[test]
fn a_retry_journal_restores_after_restart_against_the_same_catalog() {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-posted-seed-retry-restart-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let title = "Restarted.Retry.S01E01.1080p-GRP";
    {
        let d = crate::testutil::test_daemon(&dir);
        d.index_enabled.store(true, Ordering::Relaxed);
        let (era, catalog_id) = confirm_catalog_fence(&d).unwrap();
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.close_index();
        retry_confirm_pick(&d, era, &catalog_id, true, None, title);
        assert!(confirm_retry_path(&d).is_file());
    }

    let d = crate::testutil::test_daemon(&dir);
    d.index_enabled.store(true, Ordering::Relaxed);
    assert!(flush_confirm_retry(&d));
    assert_eq!(seed_pop(&d).as_deref(), Some(title));
    drop(d);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_committed_requeue_with_an_uncleared_journal_replays_idempotently() {
    with_daemon("retry-commit-before-unlink", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let (era, catalog_id) = confirm_catalog_fence(d).unwrap();
        let title = "Committed.Retry.S01E01.1080p-GRP";
        let retry = ConfirmRetry::Seed {
            catalog_id,
            title: title.into(),
        };
        save_confirm_retry(d, &retry).unwrap();
        assert_eq!(seed_retry_at(d, era, title), Some(true));
        assert!(confirm_retry_path(d).is_file());

        d.close_index();
        assert!(flush_confirm_retry(d));
        assert!(!confirm_retry_path(d).exists());
        assert_eq!(seed_pop(d).as_deref(), Some(title));
        assert_eq!(seed_pop(d), None);
    });
}

#[test]
fn an_old_fence_cannot_pop_a_candidate_from_a_recreated_catalog() {
    with_daemon("retry-pop-fence", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let (old_era, _) = confirm_catalog_fence(d).unwrap();
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.close_index();
        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{suffix}", d.index_db.display()));
            let _ = std::fs::remove_file(path);
        }
        d.index_migrated.store(false, Ordering::Release);
        d.index_enabled.store(true, Ordering::Relaxed);
        let title = "New.Catalog.S01E01.1080p-GRP";
        d.with_index(|index| {
            index
                .kv_set(
                    SEED_QUEUE_KEY,
                    &serde_json::to_string(&vec![title]).unwrap(),
                )
                .ok()
        })
        .unwrap();

        assert_eq!(seed_pop_at(d, old_era), None);
        assert_eq!(seed_pop(d).as_deref(), Some(title));
    });
}

#[test]
fn an_old_era_retry_is_not_injected_into_the_new_index_queue() {
    with_daemon("retry-era-fence", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let old_era = d.index_era();
        d.index_generation.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            seed_retry_at(d, old_era, "Old.Era.S01E01.1080p-GRP"),
            Some(false)
        );
        assert_eq!(seed_pop(d), None);

        let pick = super::super::expected::ExpectedPick::Movie {
            title: "Old Era Movie".into(),
            year: 2026,
        };
        assert_eq!(
            super::super::expected::expected_retry_at(d, old_era, &pick),
            Some(false)
        );
        assert!(super::super::expected::expected_next(d, 1).is_none());
    });
}

#[test]
fn posted_seed_uses_the_name_ladder_and_terminally_rejects_parity_only_xml() {
    with_daemon("name-and-invalid", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let candidate = candidate("3f9a7c1e5b8d4a2f6c0e9b7d1a3f5c8e.nzb");
        let data = xml("payload.mkv");
        let nzb = nzbkit::nzb::Nzb::parse(&data).unwrap();
        assert_eq!(
            posted_seed_name(&candidate.stem, &nzb).as_deref(),
            Some("Meta.Show.S02E03.1080p-GRP")
        );

        let parity = xml("payload.par2");
        assert!(settle_for_test(d, &candidate, Some(parity)));
        assert_eq!(
            d.with_index(|index| Some(index.nzbimport_cursor()))
                .unwrap(),
            candidate.arrival_seq,
            "terminal content did not advance the cursor"
        );
        d.with_index(|index| {
            assert_eq!(index.nzb_seed_inventory().unwrap().sets, 0);
            Some(())
        })
        .unwrap();
    });
}

#[test]
fn posted_seed_normalization_strips_exactly_one_nzb_suffix() {
    with_daemon("one-suffix", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let data = xml("payload.mkv");
        let guid = nzb_sha(&data);
        let candidate = candidate("Double.Show.S01E01.1080p-GRP.nzb.nzb");
        assert_eq!(
            persist_posted_seed(d, d.index_era(), &candidate.stem, data),
            PostedSeedDisposition::Durable
        );
        d.with_index(|index| {
            assert!(
                index
                    .nzb_seed_assertion_exists(
                        nzbkit::index::NZB_SEED_POSTED_SOURCE,
                        &guid,
                        &candidate.stem,
                    )
                    .unwrap()
            );
            Some(())
        })
        .unwrap();
    });
}

#[test]
fn posted_seed_defers_while_a_foreground_index_job_is_active() {
    with_daemon("foreground-job", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let candidate = candidate("Outer.Show.S01E01.1080p-GRP.nzb");
        let data = xml("payload.mkv");
        let guard = d.begin_index_job();
        assert_eq!(
            persist_posted_seed(d, d.index_era(), &candidate.stem, data.clone()),
            PostedSeedDisposition::Retry
        );
        d.with_index(|index| {
            assert_eq!(index.nzb_seed_inventory().unwrap().sets, 0);
            Some(())
        })
        .unwrap();
        drop(guard);
        assert_eq!(
            persist_posted_seed(d, d.index_era(), &candidate.stem, data),
            PostedSeedDisposition::Durable
        );
    });
}

#[test]
fn posted_settlement_never_advances_a_fresh_index_with_an_old_era() {
    with_daemon("era-fence", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let stale_era = d.index_era();
        d.with_index(|index| {
            assert_eq!(index.nzbimport_cursor(), 0);
            Some(())
        })
        .unwrap();

        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.close_index();
        d.index_enabled.store(true, Ordering::Relaxed);
        assert_ne!(d.index_era(), stale_era);

        assert!(!advance_posted_cursor(d, stale_era, 77));
        assert_eq!(
            persist_posted_seed(
                d,
                stale_era,
                "Outer.Show.S01E01.1080p-GRP.nzb",
                xml("payload.mkv"),
            ),
            PostedSeedDisposition::Retry
        );
        assert_eq!(
            d.with_index(|index| Some(index.nzbimport_cursor())),
            Some(0),
            "an old-era settlement moved the fresh database cursor"
        );
    });
}

#[test]
fn posted_candidate_article_cost_is_a_hard_admission_cap() {
    assert_eq!(posted_candidate_cost(0), None);
    assert_eq!(posted_candidate_cost(1), Some(1.0));
    assert_eq!(
        posted_candidate_cost(NZBIMPORT_ARTICLES_MAX),
        Some(NZBIMPORT_ARTICLES_MAX as f64)
    );
    assert_eq!(posted_candidate_cost(NZBIMPORT_ARTICLES_MAX + 1), None);
    assert_eq!(posted_candidate_cost(10_000), None);
}

#[test]
fn a_successful_fetch_resets_transient_history_even_if_storage_retries() {
    let mut transient = (0, 0, 0);
    for count in 1..NZBIMPORT_TRANSIENT_TRIES {
        assert!(matches!(
            classify_import_fetch(ImportFetch::Transient, 11, 7, &mut transient),
            ImportDecision::Retry
        ));
        assert_eq!(transient, (11, 7, count));
    }
    assert!(matches!(
        classify_import_fetch(ImportFetch::Ok(vec![1]), 11, 7, &mut transient),
        ImportDecision::Store(_)
    ));
    assert_eq!(transient, (0, 0, 0));

    // A local SQLite retry happens after classification and must not
    // resurrect the four older network failures. The next transient is
    // the first one in a new run, not the give-up threshold.
    assert!(matches!(
        classify_import_fetch(ImportFetch::Transient, 11, 7, &mut transient),
        ImportDecision::Retry
    ));
    assert_eq!(transient, (11, 7, 1));
}

#[test]
fn a_reused_arrival_sequence_in_a_new_era_gets_a_fresh_transient_budget() {
    let mut transient = (3, 7, NZBIMPORT_TRANSIENT_TRIES - 1);
    assert!(matches!(
        classify_import_fetch(ImportFetch::Transient, 4, 7, &mut transient),
        ImportDecision::Retry
    ));
    assert_eq!(transient, (4, 7, 1));
}
