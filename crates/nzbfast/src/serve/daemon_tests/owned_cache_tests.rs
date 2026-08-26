//! N12's two per-poll caches: the owned-title-key set and the
//! enabled-backbone list.
//!
//! Both replaced work that ran on every wall poll - ~14,500
//! `parse_release` calls in one case, a config disk read and JSON parse
//! in the other - so what these tests pin is not the speed but the two
//! ways a cache can be wrong: answering something the uncached path
//! would not, and answering the OLD thing after its input moved.
//!
//! A child of daemon_tests, out here for the size gate (TODO 106) and
//! carrying the same `#[path]` requirement; `use super::*` brings the
//! harness (`with_daemon`, `jv`).

use super::*;

/// The cached answer is the walk's answer. Not "close enough": the
/// Affinity sort sinks exactly the keys in this set and the eviction
/// pass protects exactly the keys in this set, so any divergence is a
/// wrongly ordered wall or a wrongly deleted index row.
#[cfg(feature = "indexer")]
#[test]
fn the_cached_set_is_the_walks_set() {
    with_daemon("ownedcache", |d| {
        let queued = "The.Show.S01E01.720p.WEB.x264-ABC";
        let done = "Some.Movie.2021.1080p.BluRay.x264-XYZ";
        let failed = "Other.Film.2019.720p.WEB.x264-QQQ";
        d.queue
            .lock_ok()
            .push_back(jv("q1", queued, serde_json::json!({})));
        d.history
            .lock_ok()
            .push(jv("h1", done, serde_json::json!({"state": "Completed"})));
        d.history
            .lock_ok()
            .push(jv("h2", failed, serde_json::json!({"state": "Failed"})));

        let walk = d.owned_title_keys_uncached();
        // Miss, then hit: both must equal the walk, and the second must
        // not be some emptier thing the cache invented.
        assert_eq!(d.owned_title_keys(), walk, "first call (cache miss)");
        assert_eq!(d.owned_title_keys(), walk, "second call (cache hit)");
        assert!(walk.contains(&crate::wall::parse_release(queued).key));
        assert!(walk.contains(&crate::wall::parse_release(done).key));
    });
}

/// A revision bump is what the cache watches, so a mutation that moves
/// it is visible on the very next call.
///
/// This is the invariant the eviction pass leans on: a completed job
/// reaches history through `histstore`, which bumps `history_rev` with
/// the write, and `protected_set` must see that title before the next
/// eviction decides the index no longer needs it.
#[cfg(feature = "indexer")]
#[test]
fn a_revision_bump_is_seen_on_the_next_call() {
    with_daemon("ownedbump", |d| {
        let first = "Some.Movie.2021.1080p.BluRay.x264-XYZ";
        let later = "Another.Show.S02E03.1080p.WEB.x264-DEF";
        d.history
            .lock_ok()
            .push(jv("h1", first, serde_json::json!({"state": "Completed"})));
        d.history_rev.fetch_add(1, Ordering::Relaxed);

        let before = d.owned_title_keys();
        assert!(before.contains(&crate::wall::parse_release(first).key));
        assert!(!before.contains(&crate::wall::parse_release(later).key));

        // Exactly the shape of the production seam: mutate, THEN bump.
        d.queue
            .lock_ok()
            .push_back(jv("q1", later, serde_json::json!({})));
        d.queue_rev.fetch_add(1, Ordering::Relaxed);

        let after = d.owned_title_keys();
        assert!(after.contains(&crate::wall::parse_release(later).key));
        assert_eq!(after, d.owned_title_keys_uncached());
    });
}

/// The other half of the contract, stated as a test because it is the
/// thing that would bite: a mutation that does NOT move either revision
/// is not seen. Every production seam bumps (see `histstore`'s module
/// doc and `save_queue`), and `rename_queued` was given its own bump for
/// exactly this reason - a new one that forgets is a wall that sorts a
/// title the user owns as if they did not, and an eviction pass that
/// does not protect it.
#[cfg(feature = "indexer")]
#[test]
fn a_mutation_without_a_bump_is_not_seen() {
    with_daemon("ownednobump", |d| {
        let first = "Some.Movie.2021.1080p.BluRay.x264-XYZ";
        let sneaky = "Unbumped.Release.2022.1080p.WEB.x264-GHI";
        d.history
            .lock_ok()
            .push(jv("h1", first, serde_json::json!({"state": "Completed"})));
        let before = d.owned_title_keys();
        assert!(before.contains(&crate::wall::parse_release(first).key));

        d.queue
            .lock_ok()
            .push_back(jv("q1", sneaky, serde_json::json!({})));
        assert_eq!(
            d.owned_title_keys(),
            before,
            "no bump, so the cached answer stands - the walk disagrees"
        );
        assert!(
            d.owned_title_keys_uncached()
                .contains(&crate::wall::parse_release(sneaky).key),
            "...and the walk is what the bump would have published"
        );
    });
}

/// The backbone list is read from the config file, and a rewrite of that
/// file is seen on the next call - which is the case that matters,
/// because the dashboard edits servers through the API and the wall must
/// not keep ranking against a server the user just turned off.
#[cfg(feature = "indexer")]
#[test]
fn the_backbone_cache_follows_the_config_file() {
    with_daemon("oraclebb", |d| {
        let write = |servers: &str| {
            let body = format!(r#"{{"servers": [{servers}]}}"#);
            crate::persist::write_atomic(&d.cfg_path, body.as_bytes()).expect("write config");
        };
        let srv = |host: &str, enabled: bool| {
            format!(
                r#"{{"host": "{host}", "port": 119, "username": "u", "password": "p",
                     "connections": 1, "enabled": {enabled}}}"#
            )
        };

        write(&format!(
            "{}, {}",
            srv("news.a.example", true),
            srv("news.b.example", false)
        ));
        let first = d.enabled_backbones(&d.cfg_path);
        assert_eq!(
            first,
            vec![nzbkit::oracle::backbone_of("news.a.example")],
            "disabled servers contribute nothing"
        );
        assert_eq!(d.enabled_backbones(&d.cfg_path), first, "cache hit");

        // Same length, same second: only the enabled flag moves. The
        // stamp still has to catch it - `write_atomic` publishes by
        // rename, so the inode does.
        write(&format!(
            "{}, {}",
            srv("news.a.example", false),
            srv("news.b.example", true)
        ));
        assert_eq!(
            d.enabled_backbones(&d.cfg_path),
            vec![nzbkit::oracle::backbone_of("news.b.example")],
            "the rewrite is seen"
        );
    });
}

/// A config file that is not there is not cacheable: `Config::load`
/// answers a missing path by searching for a SABnzbd ini, and the list
/// it returns then came from a file the stamp does not describe. The
/// uncached path must simply run.
#[cfg(feature = "indexer")]
#[test]
fn a_missing_config_is_not_cached() {
    with_daemon("oraclemissing", |d| {
        let absent = d.spool.join("no-such-config.json");
        // host-config-gate: the missing-file fallback IS this test's
        // subject - the path must not exist, which is what makes
        // `enabled_backbones` uncacheable here.
        let _ = d.enabled_backbones(&absent);
        assert!(
            d.oracle_bb_cache.lock_ok().is_none(),
            "nothing to stamp, so nothing is filed"
        );
    });
}
