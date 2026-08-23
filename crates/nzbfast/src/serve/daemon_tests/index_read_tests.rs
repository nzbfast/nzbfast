//! The read seam's stale-statement handling, moved out of daemon_tests.rs
//! under the size gate (TODO 106). `use super::*` carries `with_daemon`
//! and everything daemon.rs's test module already has in scope.

use super::*;

/// A pooled read whose statements go STALE must reach the caller as an
/// error, not as an empty answer.
///
/// `index_read_checked` takes an `FnOnce(&Index) -> Option<T>`, so every
/// caller's `.ok()` has already discarded the `rusqlite::Error` by the
/// time the seam sees a result: a query that failed and a query that
/// legitimately matched nothing are the same `None`. That is what turned
/// `SqliteFailure(SchemaChanged/17, "vtable constructor failed: rel_fts")`
/// into `<newznab:response total="0"/>` and delivered it to Sonarr as
/// "this indexer has nothing" (see the memory note on 16 Aug's newznab
/// flake, and `nzbkit`'s `index::retry`).
///
/// Retrying on `None` cannot be the fix - it would be wrong AND would
/// double the work of every miss - so nzbkit stamps the fault on the
/// CONNECTION, where it survives the flattening, and this seam reads the
/// stamp either side of the closure.
#[cfg(feature = "indexer")]
#[test]
fn a_stale_statement_on_a_pooled_read_is_not_an_empty_answer() {
    with_daemon("schemafault", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        // A read-write open runs the migrations and publishing it sets
        // `index_migrated`, which is what routes queries to the read POOL
        // instead of the startup fallback to the write mutex.
        let era = d.index_era();
        let fresh = nzbkit::index::Index::open(&d.index_db).expect("open the index");
        d.publish_index(era, fresh);
        let q = nzbkit::index::BrowseQuery {
            limit: 10,
            ..Default::default()
        };

        // Control: a free pool answers, and an index with no rows in it
        // is a perfectly good `Ok(Some(empty))`. Nothing below is allowed
        // to turn that into an error.
        assert!(
            matches!(d.index_read_checked(|ix| ix.browse(&q).ok()), Ok(Some(_))),
            "a free pool answers an empty index with an empty result"
        );

        // One stale statement: nzbkit prepares again and the caller never
        // learns it happened.
        assert!(
            matches!(
                d.index_read_checked(|ix| {
                    ix.debug_fail_next_queries(1);
                    ix.browse(&q).ok()
                }),
                Ok(Some(_))
            ),
            "a single SQLITE_SCHEMA is retried away, not surfaced"
        );

        // A fault that outlives the retry. The closure's `.ok()` throws
        // the error away exactly as every real caller does, so before the
        // stamp this was `Ok(None)` - drawn as "nothing found".
        assert_eq!(
            d.index_read_checked(|ix| {
                ix.debug_fail_next_queries(2);
                ix.browse(&q).ok()
            })
            .err(),
            Some(super::super::daemon_index::IndexBusy::SchemaChanged),
            "a read that FAILED must not be reported as a read that found nothing"
        );
    });
}

/// TODO 200: a tail parked on the index write mutex says so on its row,
/// and only then. Gary's two 20 Aug jobs read "unpacking" for 14 and 27
/// minutes of index wait; the wait is bounded now, but a bounded wait
/// under the pipeline's last word still reads as a broken unpacker.
#[cfg(feature = "indexer")]
#[test]
fn a_tail_waiting_on_the_index_says_so_and_only_while_it_waits() {
    with_daemon("indexwait", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let tok = |d: &Daemon| d.hub.activity.lock_ok().get("nzo-iw").copied();

        // An uncontended index never touches the row: the caller's own
        // stage stands before, during and after.
        d.note_tail_stage("nzo-iw", "identifying");
        let seen = std::cell::Cell::new(None);
        d.with_index_for_tail("nzo-iw", |_| {
            seen.set(tok(d));
            Some(())
        });
        assert_eq!(seen.get(), Some("identifying"), "no contention, no relabel");
        assert_eq!(tok(d), Some("identifying"));

        // Held by someone else for longer than the tail's budget: the
        // row flips to indexwait while the wait runs, the wait gives
        // up on schedule, and the caller's stage comes back.
        let guard = d.index.lock_ok();
        let d2 = d.clone();
        let probe = std::thread::spawn(move || {
            let mut flipped = false;
            for _ in 0..100 {
                std::thread::sleep(std::time::Duration::from_millis(20));
                if d2.hub.activity.lock_ok().get("nzo-iw").copied() == Some("indexwait") {
                    flipped = true;
                    break;
                }
            }
            flipped
        });
        let short = std::time::Duration::from_millis(400);
        let ran = d.with_index_for_tail_within("nzo-iw", short, |_| Some(()));
        assert!(ran.is_none(), "the budget elapsed under a held mutex");
        assert!(
            probe.join().unwrap(),
            "the row said indexwait during the wait"
        );
        assert_eq!(tok(d), Some("identifying"), "the prior stage is restored");
        drop(guard);

        // The wire word for the *arrs is the same `Moving` every other
        // tail stage reports - nothing new reaches Sonarr.
        d.note_tail_stage("nzo-iw", "indexwait");
        assert_eq!(d.tail_phase("nzo-iw"), Some("Moving"));
    });
}

/// TODO 143, second half: the pre-migration fallback is BOUNDED.
///
/// `index_read_checked` routes to the read-only pool once
/// `index_migrated` says a read-write open has run the migrations, and
/// falls back to the write mutex until then. That fallback used to be
/// `with_index` - an unbounded park on exactly the mutex this path
/// exists to stay off. It was reachable for the life of the process
/// while `publish_index` forgot to set the flag (the first half of
/// §143, pinned by `a_published_scan_connection_marks_the_index_migrated`),
/// and every query endpoint queued on the write mutex through it: the
/// 28 Jul and 2 Aug wedges, shipped in v1.0.22.
///
/// The flag is honest now, so the branch is only reachable before the
/// first open - but "only reachable at startup" is what was believed
/// about it the first time. A held mutex here answers `Saturated`
/// within `PREMIGRATION_INDEX_WAIT` instead of waiting for whatever is
/// holding it.
#[cfg(feature = "indexer")]
#[test]
fn a_read_before_the_first_migration_is_bounded_not_parked() {
    with_daemon("premigration", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        // The precondition IS the branch: nothing has opened the
        // read-write connection, so there is no pool to read from yet.
        assert!(
            !d.index_migrated.load(Ordering::Acquire),
            "precondition: no read-write open has run the migrations"
        );

        // Somebody else is holding the write mutex - the open itself,
        // in the shape this branch assumes, or anything at all in the
        // shape it must survive.
        let guard = d.index.lock_ok();
        let t = std::time::Instant::now();
        let out = d.index_read_checked(|_| Some(1i64));
        let waited = t.elapsed();
        assert_eq!(
            out.err(),
            Some(super::super::daemon_index::IndexBusy::Saturated),
            "a query that could not be answered must say so, not park"
        );
        assert!(
            waited < std::time::Duration::from_secs(10),
            "the pre-migration fallback waited {}ms - it is unbounded again",
            waited.as_millis()
        );
        drop(guard);

        // Control: with the mutex free the same call opens the index,
        // answers, and leaves the flag set - so the NEXT read is a
        // pooled one and this branch is behind us.
        assert_eq!(d.index_read_checked(|_| Some(1i64)), Ok(Some(1)));
        assert!(d.index_migrated.load(Ordering::Acquire));
    });
}
