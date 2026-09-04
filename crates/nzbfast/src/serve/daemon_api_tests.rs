//! Daemon-layer tests that reach UP into the api and tasks layers.
//!
//! Ten tests, lifted out of `crates/nzbfast-daemon/src` by lane 2 of the
//! serve split. Each composes a daemon-layer item with an `api::` or
//! `tasks::` one that stayed in the bin, so this is the only crate that
//! can see both halves - the answer steps 2, 3 and 4 of
//! `research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md` each reached for
//! the handful of tests they could not take down with their module.
//!
//! They are LIFTED, not rewritten: every assertion, doc comment and
//! attribute is verbatim, and each carries a line naming the daemon file
//! it came from. What changed is `super::`, which means `serve` here
//! rather than the daemon crate root.
//!
//! Nothing about the SUBJECT moved: the daemon behaviour these pin is
//! still in `nzbfast-daemon`, and lane 3 (api and tasks as sibling
//! crates) will have to decide where they land next - most of them
//! belong with the api crate, since it is the api half that is the
//! expensive import here.

use super::*;

// The daemon crate's own root vocabulary, which `use super::*` reached
// while these tests lived there: `super::` means `serve` here, and
// serve's globs carry the units but not the crate root's own imports.
use nzbfast_daemon::daemon::Daemon;
// Only the two seed-harvest tests read it, and both are indexer-only.
#[cfg(feature = "indexer")]
use nzbfast_daemon::epoch_secs;
use nzbfast_daemon::job::{Job, JobState};
use nzbfast_daemon::testutil::{MINIMAL_NZB as NZB, rec, scratch_dir};
use nzbfast_daemon::testutil::{jv, test_daemon, with_daemon};
use nzbfast_daemon::{MutexExt, RwLockExt};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

// Lifted from `crates/nzbfast-daemon/src/daemon_park.rs`.
/// A delete verb that owes a HISTORY row keeps the spooled NZB - the
/// row is retryable and the retry reads that copy - so the
/// kept-files notice raised by the same refusal must NOT also claim
/// it.
///
/// Both records named one file and neither knew about the other, so
/// whichever was spent first silently broke the other. Dismissing
/// the strip (or letting it age off the 12-entry ring, or pressing
/// "download it again") ran `drop_kept_nzb` and removed the spool
/// copy while the history row still pointed at it, and the
/// advertised retry then failed with a raw ENOENT out of the NZB
/// read (Codex sweep 3, M11).
#[test]
fn a_history_owed_delete_keeps_its_nzb_out_of_the_kept_notice() {
    let dir = std::env::temp_dir().join(format!("nzbfast-parkcust-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let d = test_daemon(&dir);

    let spool_nzb = d.spool.join("Kept.Release.nzb");
    std::fs::write(&spool_nzb, NZB).expect("spool copy");
    // The removal has to be REFUSED, and the cheapest honest refusal
    // is a path that is not a directory: `remove_user_dir` passes
    // the error straight through as `FilesGone::Kept`, exactly as a
    // Trash that will not take the folder does.
    let out = dir.join("Kept.Release");
    std::fs::write(&out, b"not a directory").expect("blocker");

    let job = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-parkcust-1",
            "name": "Kept.Release",
            "nzb_path": spool_nzb.to_string_lossy(),
            "out_dir": out.to_string_lossy(),
            "state": "Failed",
        }))
        .expect("job"),
    ));
    // Exactly what JSON-RPC `GroupDelete` leaves behind for a job it
    // caught DOWNLOADING: tombstoned, stamped for a history row, its
    // file removal deferred to park.
    {
        let mut g = job.lock_ok();
        g.fail_message = "deleted from the queue".into();
        g.finished_unix = Some(1);
        g.tombstone = true;
        g.delete_status = "MANUAL".into();
        g.del_on_drop = true;
    }
    d.queue.lock_ok().push_back(job.clone());
    d.park_gen(job.clone(), None);

    let note = d
        .delete_kept
        .lock_ok()
        .front()
        .cloned()
        .expect("the refused removal must raise a kept-files notice");
    assert!(
        note.nzb.is_empty(),
        "the notice claimed the spool copy the history row still owns"
    );
    assert!(
        d.history
            .lock_ok()
            .iter()
            .any(|j| j.lock_ok().nzo_id == "nzo-parkcust-1"),
        "M5: a delete verb with a status files a retryable row"
    );

    // The user dismisses the strip. That spends the notice - and
    // with it, before the fix, the NZB the row's retry needs.
    assert!(
        crate::serve::api::queue::spend_kept_notice(&d, &note.path),
        "the notice is the one being dismissed"
    );
    assert!(
        spool_nzb.exists(),
        "dismissing the notice deleted the spooled NZB the history retry reads"
    );
    assert!(
        d.retry("nzo-parkcust-1"),
        "the filed delete row is retryable"
    );
    let named = job.lock_ok().nzb_path.clone();
    assert_eq!(
        named, spool_nzb,
        "the re-queued row still names its spool copy"
    );
    let bytes = std::fs::read(&named).expect("the retry's NZB read");
    d.enqueue(&bytes, "Kept.Release", "", -100, None, None, "test", true)
        .expect("the kept spool copy must still parse and enqueue");

    let _ = std::fs::remove_dir_all(&dir);
}

// Lifted from `crates/nzbfast-daemon/src/daemon_tests.rs`.
#[test]
fn priority_write_moves_the_row_to_its_run_position() {
    with_daemon("priomove", |d| {
        {
            let mut q = d.queue.lock_ok();
            let active = jv("dl", "active", serde_json::json!({"priority": 0}));
            active.lock_ok().state = JobState::Downloading;
            q.push_back(active);
            q.push_back(jv(
                "b",
                "forced-earlier",
                serde_json::json!({"priority": 2}),
            ));
            q.push_back(jv("a", "plain", serde_json::json!({"priority": 0})));
            q.push_back(jv("c", "forced-now", serde_json::json!({"priority": 0})));
        }
        let order = |q: &std::collections::VecDeque<Arc<Mutex<Job>>>| -> Vec<String> {
            q.iter().map(|j| j.lock_ok().nzo_id.clone()).collect()
        };
        // ⏫ on the last row: both priority arms write through
        // apply_priority and then reposition. The row lands after the
        // active download and the earlier Force job - exactly where
        // pick_job will run it - instead of staying at the tail while
        // the toast said "Downloads next".
        {
            let mut q = d.queue.lock_ok();
            {
                let job = q
                    .iter()
                    .find(|j| j.lock_ok().nzo_id == "c")
                    .unwrap()
                    .clone();
                let mut g = job.lock_ok();
                assert!(crate::serve::api::queue::apply_priority(d, &mut g, 2));
            }
            crate::serve::api::queue::reposition_for_priority(&mut q, "c");
            assert_eq!(order(&q), ["dl", "b", "c", "a"]);
            // The active row never moves, whatever is written.
            crate::serve::api::queue::reposition_for_priority(&mut q, "dl");
            assert_eq!(order(&q), ["dl", "b", "c", "a"]);
            // Dropping a Force back to Normal sends it behind its new
            // group's earlier arrivals, same rule downward.
            {
                let job = q
                    .iter()
                    .find(|j| j.lock_ok().nzo_id == "b")
                    .unwrap()
                    .clone();
                let mut g = job.lock_ok();
                assert!(crate::serve::api::queue::apply_priority(d, &mut g, 0));
            }
            crate::serve::api::queue::reposition_for_priority(&mut q, "b");
            assert_eq!(order(&q), ["dl", "c", "a", "b"]);
        }
    });
}

// Lifted from `crates/nzbfast-daemon/src/daemon_tests.rs`.
/// TODO 46: a user category is a category an *arr may be configured
/// against, so its slug joins the list clients are offered - while the
/// `categories` setting's own round-trip value stays untouched, or the
/// slug would be written back to settings.json as a filing category and
/// outlive the user category it came from.
#[test]
fn client_cats_offers_user_category_slugs_without_touching_cat_list() {
    with_daemon("clientcats", |d| {
        {
            let mut cats = d.cats.lock_ok();
            cats.clear();
            for c in ["tv", "*", "movies"] {
                cats.insert(c.to_string());
            }
        }
        assert_eq!(d.cat_list(), "movies, tv");
        assert_eq!(
            crate::serve::api::config::client_cats(d)
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["*", "movies", "tv"]
        );

        *d.custom_categories.write_ok() = vec![
            nzbkit::categories::CustomCategory {
                slug: "formula-1".into(),
                name: "Formula 1".into(),
                pattern: "formula.?1".into(),
                not_match: String::new(),
                base: nzbkit::categories::BaseBehavior::None,
            },
            // A slug already present as a filing category must not
            // double up - the union is a set, not a concatenation.
            nzbkit::categories::CustomCategory {
                slug: "movies".into(),
                name: "Movies".into(),
                pattern: "x".into(),
                not_match: String::new(),
                base: nzbkit::categories::BaseBehavior::Movie,
            },
        ];
        assert_eq!(
            crate::serve::api::config::client_cats(d)
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["*", "formula-1", "movies", "tv"]
        );
        // The setting is unchanged, so nothing new can be written back.
        assert_eq!(d.cat_list(), "movies, tv");
    });
}

// Lifted from `crates/nzbfast-daemon/src/daemon_tests.rs`.
/// The indexer-confirm lane end to end against a mock newznab, with
/// the suggestion created by the REAL correlation machinery (seeded
/// pre + dark scanned row + catchup walk - the design's own worked
/// example numbers). Round one: the listing matches, its NZB
/// msgid-joins at quorum, then gains the pre title as a proven msgid-set name
/// after the manifest quiet window and the suggestion settles 'confirmed'. Round two:
/// a second suggestion's NZB joins nothing - stamped out, nothing
/// named, and the suggestion left standing rather than falsely
/// settled.
#[cfg(feature = "indexer")]
#[test]
fn an_indexer_confirmed_suggestion_becomes_a_proven_name() {
    use nzbkit::predb::{PreKind, PreLine};
    with_daemon("corrconfirm", |d| {
        d.index_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let seed = |ix: &mut nzbkit::index::Index, stem: &str, tag: &str, title: &str| {
            let entries: Vec<nzbkit::nntp::OverEntry> = (1..=3u64)
                .map(|n| nzbkit::nntp::OverEntry {
                    number: n,
                    subject: format!(r#""{stem}" yEnc ({n}/3)"#),
                    from: "p@x".into(),
                    message_id: format!("<{tag}{n}@test>"),
                    bytes: 1_666_666_666,
                    date: 4_600,
                })
                .collect();
            ix.ingest("alt.binaries.x264", &entries, 5_000).unwrap();
            ix.predb_store(
                &[PreLine {
                    kind: PreKind::New,
                    title: title.into(),
                    category: "X264-HD".into(),
                    size: 4_900_000_000,
                    date: 1_000,
                    source: "PRE".into(),
                    ..Default::default()
                }],
                5_000,
            )
            .unwrap();
        };
        const TITLE: &str = "Test.Release.2026.1080p.WEB.H264-GRP";
        d.with_index_mut(|ix| {
            seed(ix, "x7Pq9RtK2mVb8NcJ4wZs", "cc", TITLE);
            let (_, suggested, _) = ix.predb_corr_backlog(400, 0, false, 6_200).unwrap();
            assert_eq!(suggested, 1, "the real scorer suggested the pairing");
            let picks = ix.corr_confirm_pick(5).unwrap();
            assert_eq!(picks.len(), 1);
            assert_eq!(picks[0].1, TITLE);
            Some(())
        })
        .unwrap();

        // Mock newznab: request 1 = the search, request 2 = the NZB.
        // Connection: close forces a fresh connection per request so
        // the accept loop sees each one.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let nzb_ids: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>> =
            std::sync::Arc::new(std::sync::Mutex::new(vec!["cc1", "cc2", "cc3"]));
        let ids2 = nzb_ids.clone();
        let listed_title: std::sync::Arc<std::sync::Mutex<&'static str>> =
            std::sync::Arc::new(std::sync::Mutex::new(TITLE));
        let listed_title2 = listed_title.clone();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            for stream in listener.incoming().take(6) {
                let mut s = stream.unwrap();
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if req.contains("t=search") {
                    let title = *listed_title2.lock().unwrap();
                    format!(
                        r#"<?xml version="1.0"?><rss><channel>
<item><title>{title}</title><guid>g1</guid>
<enclosure url="http://127.0.0.1:{port}/nzb" length="4900000000" type="application/x-nzb"/>
</item></channel></rss>"#
                    )
                } else {
                    let ids = ids2.lock().unwrap().clone();
                    let segs: String = ids
                        .iter()
                        .enumerate()
                        .map(|(i, id)| {
                            format!(
                                r#"<segment bytes="1666666666" number="{}">{id}@test</segment>"#,
                                i + 1
                            )
                        })
                        .collect();
                    format!(
                        r#"<?xml version="1.0"?><nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="p@x" date="4600" subject="&quot;x&quot; yEnc (1/3)">
<groups><group>alt.binaries.x264</group></groups>
<segments>{segs}</segments></file></nzb>"#
                    )
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });

        d.indexers.lock_ok().push(crate::newznab::IndexerConfig {
            kind: Default::default(),
            nzbindex: Default::default(),
            name: "mock".into(),
            url: format!("http://127.0.0.1:{port}"),
            apikey: "k".into(),
            enabled: true,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        });
        *d.corr_confirm_source.lock_ok() = "mock".into();
        // Both switches: the confirm lane is a child of correlation
        // and stands down whenever the parent is off.
        d.predb
            .corr_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        d.corr_confirm_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let mut seed_harvest = super::seed_harvest::HarvestState::new(d.index_era());
        assert!(super::tasks::corr_confirm_once(d), "budget was spent");
        let replay = super::seed_harvest::tick(d, &mut seed_harvest);
        assert_eq!(
            replay.stored, 1,
            "commercial proof was not drained: {replay:?}"
        );
        assert_eq!(
            replay.named, 0,
            "a fresh commercial manifest bypassed the quiet window: {replay:?}"
        );
        let settled = d
            .with_index_mut_retiring_ddl(|index| {
                index
                    .nzb_seed_reconcile(epoch_secs() as i64 + 3_600, 64)
                    .ok()
            })
            .expect("settle commercial proof after the quiet window");
        assert_eq!(settled.claims_applied, 1, "{settled:?}");
        d.with_index(|ix| {
            let r = &ix.search("x7Pq9RtK2mVb8NcJ4wZs", 5).unwrap()[0];
            assert_eq!(r.pre_title, TITLE, "the join named the row");
            let stats = ix.predb_corr_stats().unwrap();
            let confirmed = stats
                .iter()
                .find(|(k, _)| k == "confirmed")
                .map(|(_, v)| *v)
                .unwrap_or(0);
            assert_eq!(confirmed, 1, "the suggestion settled confirmed");
            assert!(
                ix.corr_confirm_pick(5).unwrap().is_empty(),
                "checked once, never again"
            );
            Some(())
        })
        .unwrap();

        // Round two: a fresh suggestion whose fetched NZB shares no
        // message-ids with the row - the join must find nothing.
        const TITLE2: &str = "Other.Show.S01E05.1080p.WEB.H264-GRP";
        d.with_index_mut(|ix| {
            seed(ix, "q2Wm8VbN5xKj3RtY7pLc", "dd", TITLE2);
            // The backlog cursor parked below round one's rows; a seed
            // generation bump is production's own re-open mechanism.
            ix.kv_set("predb_seed_gen", "test2").unwrap();
            let (_, suggested, _) = ix.predb_corr_backlog(400, 0, false, 6_300).unwrap();
            assert_eq!(suggested, 1);
            Some(())
        })
        .unwrap();
        *nzb_ids.lock().unwrap() = vec!["ee1", "ee2", "ee3"];
        *listed_title.lock().unwrap() = TITLE2;
        assert!(
            super::tasks::corr_confirm_once(d),
            "budget spent on the miss too"
        );
        let miss = super::seed_harvest::tick(d, &mut seed_harvest);
        assert_eq!(
            miss.stored, 1,
            "commercial miss proof was not drained: {miss:?}"
        );
        assert_eq!(
            miss.named, 0,
            "a non-joining commercial proof named a row: {miss:?}"
        );
        let settled_miss = d
            .with_index_mut_retiring_ddl(|index| {
                index
                    .nzb_seed_reconcile(epoch_secs() as i64 + 3_600, 64)
                    .ok()
            })
            .expect("reconcile the non-joining proof after the quiet window");
        assert_eq!(settled_miss.claims_applied, 0, "{settled_miss:?}");
        d.with_index(|ix| {
            let r = &ix.search("q2Wm8VbN5xKj3RtY7pLc", 5).unwrap()[0];
            assert_eq!(r.pre_title, "", "no join, no name");
            assert!(
                ix.corr_confirm_pick(5).unwrap().is_empty(),
                "stamped regardless"
            );
            Some(())
        })
        .unwrap();
        drop(server);
    });
}

// Lifted from `crates/nzbfast-daemon/src/daemon_tests.rs`.
/// F5 item 2 end to end: the confirm lane's LEFTOVER-AS-TITLE hunt.
///
/// A dark scanned row whose cluster stem already reads as a release
/// title is worth sending to the user's indexers as `q=` - measured 1
/// Sep 2026 to hit real listings on all five configured Newznab
/// accounts. Here the daemon is put one attempt into the hunts' share
/// of the daily budget and the whole wire runs: pick the row off the
/// index, search the account, grab the enclosure, message-id-join the
/// NZB back.
///
/// WHAT GETS NAMED IS THE OTHER ROW. `leftover_is_a_title` (which
/// picks a row for this hunt) and `release::stem_is_a_name` (which
/// `apply_proven_name` asks before writing a name) are the same
/// predicate, so the readable row is by construction one the claims
/// layer will not rename - its stem is the poster's own name and
/// stands. The commercial NZB that the readable row FINDS also covers
/// the hash-stemmed post beside it, and that one is genuinely dark.
/// That is the lane's product effect, and this test pins both halves
/// so neither can be quietly reversed:
///
/// * the hash-stemmed row gains the LISTING's title, never the
///   leftover token that found it, tagged `proven:msgid-set:nzb-hunt`
///   so this lane's yield stays separable when it is scored;
/// * the readable row keeps its own stem and is NOT renamed.
#[cfg(feature = "indexer")]
#[test]
fn a_leftover_as_title_hunt_names_the_dark_row_beside_it() {
    with_daemon("hunt-leftover", |d| {
        use std::sync::atomic::Ordering;
        d.index_enabled.store(true, Ordering::Relaxed);
        // The finder: scene-shaped stem, no proven name.
        const STEM: &str = "Hunt.Target.2026.1080p.WEB.H264-GRP";
        // The dark row in the same posting - a hash, which is what
        // "dark" actually looks like.
        const DARK: &str = "b41f9c7ad2e83f60c19a7d4e5b28fa91c07d6e3b";
        // What the indexer calls the release. Different from STEM on
        // purpose: this is the string that must reach the dark row.
        const LISTED: &str = "Hunt.Target.2026.1080p.AMZN.WEB-DL.DDP5.1.H.264-REALGRP";
        d.with_index_mut(|ix| {
            let mut ingest = |stem: &str, tag: &str| {
                let entries: Vec<nzbkit::nntp::OverEntry> = (1..=3u64)
                    .map(|n| nzbkit::nntp::OverEntry {
                        number: n,
                        subject: format!(r#""{stem}" yEnc ({n}/3)"#),
                        from: "p@x".into(),
                        message_id: format!("<{tag}{n}@test>"),
                        bytes: 1_666_666_666,
                        date: 4_600,
                    })
                    .collect();
                ix.ingest("alt.binaries.x264", &entries, 5_000).unwrap();
            };
            ingest(STEM, "hu");
            ingest(DARK, "dk");
            // The pick source must SEE the finder, and must NOT offer
            // the hash row - otherwise the rest of this would pass by
            // doing nothing.
            let (rows, examined) = ix.dark_title_leftovers(i64::MAX, 200).unwrap();
            assert!(examined.is_some(), "the SQL window found candidate rows");
            assert!(
                rows.iter().any(|(_, stem)| stem == STEM),
                "a scene-shaped dark row is a leftover-as-title candidate, got {rows:?}"
            );
            assert!(
                !rows.iter().any(|(_, stem)| stem == DARK),
                "a hash stem is not a title and must not be sent as one"
            );
            Some(())
        })
        .unwrap();

        // Mock newznab: the search, then one NZB covering BOTH posts -
        // which is the ordinary shape, a release being several files.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            for stream in listener.incoming().take(6) {
                let mut s = stream.unwrap();
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                seen2
                    .lock()
                    .unwrap()
                    .push(req.lines().next().unwrap_or("").to_string());
                let body = if req.contains("t=search") {
                    format!(
                        r#"<?xml version="1.0"?><rss><channel>
<item><title>{LISTED}</title><guid>hg1</guid>
<enclosure url="http://127.0.0.1:{port}/nzb" length="4900000000" type="application/x-nzb"/>
</item></channel></rss>"#
                    )
                } else {
                    let file = |tag: &str| {
                        let segs: String = (1..=3)
                            .map(|i| {
                                format!(
                                    r#"<segment bytes="1666666666" number="{i}">{tag}{i}@test</segment>"#
                                )
                            })
                            .collect();
                        format!(
                            r#"<file poster="p@x" date="4600" subject="&quot;x&quot; yEnc (1/3)">
<groups><group>alt.binaries.x264</group></groups>
<segments>{segs}</segments></file>"#
                        )
                    };
                    format!(
                        r#"<?xml version="1.0"?><nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
{}{}</nzb>"#,
                        file("hu"),
                        file("dk")
                    )
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });

        // TWO enabled Newznab accounts. A leftover hunt must ask BOTH:
        // the smaller accounts recover 7 of 64 leftovers the two big
        // ones miss, which is the whole reason this pick fans out.
        let mk = |name: &str| crate::newznab::IndexerConfig {
            kind: Default::default(),
            nzbindex: Default::default(),
            name: name.into(),
            url: format!("http://127.0.0.1:{port}"),
            apikey: "k".into(),
            enabled: true,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        };
        d.indexers.lock_ok().push(mk("mock"));
        d.indexers.lock_ok().push(mk("other"));
        *d.corr_confirm_source.lock_ok() = "mock".into();
        d.predb.corr_enabled.store(true, Ordering::Relaxed);
        d.corr_confirm_enabled.store(true, Ordering::Relaxed);

        // Put the day one attempt INTO the hunts' share. Unmetered
        // quotas make the budget CONFIRM_UNLIMITED_PER_DAY, so the
        // floor is three quarters of it; below that the measured lanes
        // get the tick and this test would prove nothing.
        let cfg = d.indexers.lock_ok()[0].clone();
        let budget = super::indexers::confirm_budget(&cfg);
        let floor = budget - budget / 4;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        d.with_index(|ix| {
            ix.kv_set("corr_confirm_day", &now.div_euclid(86_400).to_string())
                .ok();
            ix.kv_set("corr_confirm_spent", &floor.to_string()).ok()
        });

        assert!(super::tasks::corr_confirm_once(d), "the hunt spent budget");

        d.with_index(|ix| {
            let dark = &ix.search(DARK, 5).unwrap()[0];
            assert_eq!(
                dark.pre_title, LISTED,
                "the LISTING's title names the dark row, not the leftover that found it"
            );
            assert_eq!(
                dark.pre_source, "proven:msgid-set:nzb-hunt",
                "hunt provenance stays separable from the confirm lane's"
            );
            let finder = &ix.search(STEM, 5).unwrap()[0];
            assert_eq!(
                finder.pre_title, "",
                "the readable stem is the poster's own name and stands - \
                 a leftover hunt finds the NZB, it does not rename its own row"
            );
            Some(())
        })
        .unwrap();
        // The stem really was sent as `q=`, so this was the leftover
        // hunt and not some other lane arriving at the same answer.
        let reqs = seen.lock().unwrap().clone();
        assert!(
            reqs.iter()
                .any(|r| r.contains("t=search") && r.contains("Hunt.Target")),
            "the finder row's own stem was the query, got {reqs:?}"
        );
        assert_eq!(
            reqs.iter().filter(|r| r.contains("t=search")).count(),
            2,
            "leftover-as-title asks EVERY enabled Newznab account, got {reqs:?}"
        );
        drop(server);
    });
}

// Lifted from `crates/nzbfast-daemon/src/daemon_tests.rs`.
/// The other hunt: NEXT EPISODE after a proven name, and the account
/// rule that separates the two.
///
/// Both rules here are measured, not chosen (1 Sep 2026 listing
/// probes), and both spend somebody else's rate limit, so they are
/// pinned rather than left to a comment. Leftover-as-title asks EVERY
/// enabled Newznab account, because the three smaller ones recover 7
/// of 64 leftovers that NZBGeek and DrunkenSlug both miss (61% union
/// to 72%). Next-episode asks only the reference account, because
/// Geek+Slug already reach 30 of 32 and the other three recover
/// exactly ZERO on top - four extra searches an episode, for nothing.
///
/// The naming itself is the same msgid-set join as every other proof:
/// the next episode's `q=` only chooses what to search for, and what
/// lands a name is the NZB that comes back containing a dark row's own
/// message-ids. Nothing copies the previous episode's title anywhere.
#[cfg(feature = "indexer")]
#[test]
fn a_next_episode_hunt_asks_one_account_and_names_by_join() {
    with_daemon("hunt-next", |d| {
        use std::sync::atomic::Ordering;
        d.index_enabled.store(true, Ordering::Relaxed);
        const NAMED: &str = "Some.Show.S01E01.1080p.WEB.H264-GRP";
        const DARK: &str = "77c3ba90d1e45f28ab6c04d9e731f5028cb4a6d1";
        const LISTED: &str = "Some.Show.S01E02.1080p.WEB.H264-GRP";
        d.with_index_mut(|ix| {
            let mut ingest = |stem: &str, tag: &str| {
                let entries: Vec<nzbkit::nntp::OverEntry> = (1..=3u64)
                    .map(|n| nzbkit::nntp::OverEntry {
                        number: n,
                        subject: format!(r#""{stem}" yEnc ({n}/3)"#),
                        from: "p@x".into(),
                        message_id: format!("<{tag}{n}@test>"),
                        bytes: 1_666_666_666,
                        date: 4_600,
                    })
                    .collect();
                ix.ingest("alt.binaries.x264", &entries, 5_000).unwrap();
            };
            // Episode 1: obfuscated on the wire, then PROVEN by a join
            // - which is what puts it in `name_claims` and so in the
            // next-episode pick's walk.
            ingest("2f8ad61c904be735182acd7f0e69b4315cd820af", "e1");
            ingest(DARK, "dk");
            let rid = ix
                .search("2f8ad61c904be735182acd7f0e69b4315cd820af", 5)
                .unwrap()[0]
                .id;
            let claim = nzbkit::index::NameClaim {
                name: NAMED.into(),
                evidence: nzbkit::index::NameEvidence::MsgidSet,
                key: "seedkey".into(),
                source: "posted-nzb".into(),
            };
            assert_eq!(
                ix.apply_proven_name(rid, &claim, 5_000).unwrap(),
                nzbkit::index::ProvenOutcome::Applied,
                "precondition: episode 1 carries a proven name"
            );
            let picks = ix.named_for_next_episode(i64::MAX, 200).unwrap();
            assert!(
                picks.iter().any(|(_, t, _)| t == NAMED),
                "the proven name is a next-episode candidate, got {picks:?}"
            );
            Some(())
        })
        .unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            for stream in listener.incoming().take(6) {
                let mut s = stream.unwrap();
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                seen2
                    .lock()
                    .unwrap()
                    .push(req.lines().next().unwrap_or("").to_string());
                let body = if req.contains("t=search") {
                    format!(
                        r#"<?xml version="1.0"?><rss><channel>
<item><title>{LISTED}</title><guid>ng1</guid>
<enclosure url="http://127.0.0.1:{port}/nzb" length="4900000000" type="application/x-nzb"/>
</item></channel></rss>"#
                    )
                } else {
                    let segs: String = (1..=3)
                        .map(|i| {
                            format!(
                                r#"<segment bytes="1666666666" number="{i}">dk{i}@test</segment>"#
                            )
                        })
                        .collect();
                    format!(
                        r#"<?xml version="1.0"?><nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="p@x" date="4600" subject="&quot;x&quot; yEnc (1/3)">
<groups><group>alt.binaries.x264</group></groups>
<segments>{segs}</segments></file></nzb>"#
                    )
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });

        // TWO enabled Newznab accounts, both answering. Only the
        // reference may be asked.
        let mk = |name: &str| crate::newznab::IndexerConfig {
            kind: Default::default(),
            nzbindex: Default::default(),
            name: name.into(),
            url: format!("http://127.0.0.1:{port}"),
            apikey: "k".into(),
            enabled: true,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        };
        d.indexers.lock_ok().push(mk("mock"));
        d.indexers.lock_ok().push(mk("other"));
        *d.corr_confirm_source.lock_ok() = "mock".into();
        d.predb.corr_enabled.store(true, Ordering::Relaxed);
        d.corr_confirm_enabled.store(true, Ordering::Relaxed);

        let cfg = d.indexers.lock_ok()[0].clone();
        let budget = super::indexers::confirm_budget(&cfg);
        let floor = budget - budget / 4;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        d.with_index(|ix| {
            ix.kv_set("corr_confirm_day", &now.div_euclid(86_400).to_string())
                .ok();
            ix.kv_set("corr_confirm_spent", &floor.to_string()).ok();
            // Take the next-episode turn: the sources alternate, and
            // this test is about that one.
            ix.kv_set("namehunt_turn", "leftover").ok()
        });

        assert!(super::tasks::corr_confirm_once(d), "the hunt spent budget");

        d.with_index(|ix| {
            let dark = &ix.search(DARK, 5).unwrap()[0];
            assert_eq!(
                dark.pre_title, LISTED,
                "the next episode's own listing title names the dark row"
            );
            assert_eq!(dark.pre_source, "proven:msgid-set:nzb-hunt");
            Some(())
        })
        .unwrap();

        let reqs = seen.lock().unwrap().clone();
        let searches = reqs.iter().filter(|r| r.contains("t=search")).count();
        assert_eq!(
            searches, 1,
            "next-episode asks the REFERENCE account only - the other four \
             accounts recover zero and are somebody else's rate limit, got {reqs:?}"
        );
        assert!(
            reqs.iter()
                .any(|r| r.contains("t=search") && r.contains("s01e02")),
            "the query is the episode AFTER the proven one, got {reqs:?}"
        );
        drop(server);
    });
}

// Lifted from `crates/nzbfast-daemon/src/histstore.rs`.
/// ...and RESUMING a job is one of the things that re-arms it.
///
/// Only the add and the runner's pick used to clear the latch, and
/// neither can happen while a global pause (or an offline/disk/quota
/// hold) keeps `pick_job` away. So pause -> resume -> pause on the
/// last job announced the first idle edge and swallowed the second,
/// even though the queue had genuinely gone runnable and quiet again
/// in between (Codex sweep 14 Aug L2).
#[test]
fn resuming_a_job_re_arms_the_idle_latch() {
    let dir = scratch_dir("lifted", "idle-resume");
    let d = test_daemon(&dir);
    let v = json!({
        "nzo_id": "nzo-idle-1", "name": "Runnable.Release",
        "out_dir": "/tmp/o", "nzb_path": "/tmp/n.nzb", "state": "Queued",
    });
    let job = Arc::new(Mutex::new(job_from_json(&v).expect("job")));
    d.queue.lock_ok().push_back(job.clone());

    let idles = |d: &Arc<Daemon>| {
        d.life_since(0)
            .0
            .iter()
            .filter(|e| e["kind"] == "queue.idle")
            .count()
    };
    // A runnable job means the queue is not idle, whatever the latch
    // says - so this emits nothing and leaves the latch as it found it.
    d.queue_idle_latch
        .store(false, std::sync::atomic::Ordering::Relaxed);
    d.note_queue_idle();
    assert_eq!(idles(&d), 0, "a runnable queue is not idle");

    let pause = |d: &Arc<Daemon>, job: &Arc<Mutex<Job>>, on: bool| {
        let _q = d.queue.lock_ok();
        let mut g = job.lock_ok();
        assert!(crate::serve::api::queue::apply_pause(d, &mut g, on));
    };
    pause(&d, &job, true);
    d.note_queue_idle();
    assert_eq!(
        idles(&d),
        1,
        "pausing the last runnable job idles the queue"
    );

    // The queue is runnable again, and nothing can pick it up.
    pause(&d, &job, false);
    d.note_queue_idle();
    assert_eq!(idles(&d), 1, "a runnable queue is still not idle");

    pause(&d, &job, true);
    d.note_queue_idle();
    assert_eq!(
        idles(&d),
        2,
        "the second idle transition was swallowed - the resume never re-armed the latch"
    );

    // And the latch still keeps repeats silent, which is what stops
    // an over-broad re-arm from turning every poll into an event.
    d.note_queue_idle();
    assert_eq!(idles(&d), 2, "the latch must keep repeats silent");
    std::fs::remove_dir_all(&dir).unwrap();
}

// Lifted from `crates/nzbfast-daemon/src/sidecar.rs`.
/// ...and the fetch that was filling the old directory is stopped.
///
/// Without it the prefetch goes on spending provider quota writing
/// into a folder the record has left, for as long as the release
/// takes - and its result is void the moment the re-point lands.
#[test]
fn a_recategorize_stops_the_prefetch_it_re_pointed() {
    let dir = scratch_dir("lifted", "recatpoke");
    let d = test_daemon(&dir);
    // Held for the whole test: a Sidecar needs a JoinHandle, and a
    // handle whose runtime has already been dropped is not one.
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let job = Arc::new(Mutex::new(
            job_from_json(&serde_json::json!({
                "nzo_id": "nzo-recatpoke-1", "name": "Some.Release",
                "out_dir": crate::serve::naming::out_dir(&d).join("movies/Some.Release").to_string_lossy(),
                "nzb_path": "/tmp/n.nzb", "state": "Queued",
            }))
            .expect("job"),
        ));
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let other = Arc::new(std::sync::atomic::AtomicBool::new(false));
    d.queue.lock_ok().push_back(job.clone());

    // A prefetch serving some OTHER job must be left alone: the
    // signal is aimed by id, and this is the whole reason it is.
    *d.sidecar.lock_ok() = Some(Sidecar {
        nzo_id: "nzo-somebody-else".into(),
        hub: Arc::new(crate::StreamHub::default()),
        progress: Arc::new(AtomicU64::new(0)),
        rate_win: Mutex::new(VecDeque::new()),
        cancelled: other.clone(),
        task: rt.spawn(async {}),
        borrowed: false,
    });
    super::api::queue::requeue_category(&d, &job, "Some.Release", "tv").expect("recategorize");
    assert!(
        !other.load(std::sync::atomic::Ordering::Relaxed),
        "the re-point stopped a prefetch that was serving a different job"
    );

    // The prefetch serving THIS job is stopped.
    d.sidecar.lock_ok().as_mut().unwrap().nzo_id = "nzo-recatpoke-1".into();
    d.sidecar.lock_ok().as_mut().unwrap().cancelled = cancelled.clone();
    super::api::queue::requeue_category(&d, &job, "Some.Release", "films").expect("recategorize");
    assert!(
        cancelled.load(std::sync::atomic::Ordering::Relaxed),
        "the prefetch went on filling a directory the record had left"
    );

    *d.sidecar.lock_ok() = None;
    let _ = std::fs::remove_dir_all(&dir);
}

// Lifted from `crates/nzbfast-daemon/src/stream.rs`.
/// Pass 2 of the media chip over that same window: a miss taken
/// mid-move is not the settled "no media file" it looks like.
///
/// The claim is that the PROBER cannot tell the two apart -
/// `probe_disk_facts_checked` answers `Ok(None)` to both, and by
/// its own contract that is "a settled answer: no media file of
/// ours in the output directory". Under the fence it is nothing of
/// the kind: the disk read fine and the payload is whole, it is
/// simply not under the name the record still carries. So the
/// distinction has to be the caller's, which is what
/// `miss_is_in_flight` is.
///
/// Worth a test because the arm it guards has no second chance.
/// Pass 2 is the ONLY source of a chip for a shape that unpacks
/// after the download - pass 1 sees no media file at all for one -
/// and those are exactly the jobs that then take a move. Nothing
/// re-derives what it drops: the mover owes no final pass when it
/// lands, and §188's re-derivation skips a row with no label
/// outright, so this arm getting it wrong is a chipless row for the
/// life of the record.
///
/// Here rather than beside the prober for the reason the sibling
/// tests above are: the window wants the real markers and a real
/// emptied source folder, and a seeded spool cannot rig it.
#[test]
fn a_disk_pass_miss_mid_move_is_not_a_row_with_no_chip() {
    let dir = std::env::temp_dir().join(format!("nzbfast-move-media-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let d = nzbfast_daemon::testutil::test_daemon(&dir);
    let id = "SABnzbd_nzo_mediamove";
    let job_dir = crate::serve::naming::out_dir(&d).join("Some.Show.S01E02");
    std::fs::create_dir_all(&job_dir).unwrap();
    let job = rec(
        id,
        serde_json::json!({ "out_dir": job_dir.to_string_lossy() }),
    );

    // In flight: the mover holds the fence over a source folder its
    // copy has emptied, and `out_dir` still names it.
    d.moving.lock_ok().insert(id.to_string());
    assert!(
        matches!(
            crate::serve::mediadisk::probe_disk_facts_checked(&d, &job),
            Ok(None)
        ),
        "the prober reads the emptied folder as a settled miss"
    );
    assert!(
        crate::serve::tasks::miss_is_in_flight(&d, &job, id),
        "a miss under the fence is owed another look, not a chipless row"
    );

    // Settled: the same empty folder and the same `Ok(None)`, with
    // no marker over it. This one really is the end of it.
    d.moving.lock_ok().remove(id);
    assert!(matches!(
        crate::serve::mediadisk::probe_disk_facts_checked(&d, &job),
        Ok(None)
    ));
    assert!(!crate::serve::tasks::miss_is_in_flight(&d, &job, id));

    // And the owed marker answers it on its own, with no fence: a
    // job still sitting in the mover queue has not been read yet.
    job.lock_ok().move_pending = true;
    assert!(crate::serve::tasks::miss_is_in_flight(&d, &job, id));
    let _ = std::fs::remove_dir_all(&dir);
}
