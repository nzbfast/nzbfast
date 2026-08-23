//! The dashboard's "app, without the indexer" log view means it.
//!
//! `web/dashboard.html` splits the log ring into two views by the
//! `[tag]` prefix, which is the tracing target of the line, and it does
//! it from one hand-maintained list: `LOG_INDEX_TAGS`. A target that is
//! not in the list falls through to the "app" view. That fall-through is
//! the right default for HIDING (residual noise beats losing a download
//! line) and the wrong one for the EXPORT: `exportLog()` blobs exactly
//! what the pane shows into a file the user is about to hand to someone
//! else, and the option is labelled "app, without the indexer" in every
//! locale. A lane missing from the list turns that label into a false
//! promise.
//!
//! That is not hypothetical. `scan` and `probe7z` were both missing, so
//! an exported "app" log carried provider hostnames, group names,
//! internal release ids and archive-derived release names from the
//! indexer's own scan and 7z-probe lanes.
//!
//! Nothing about the list is checked by the browser, so it is checked
//! here: walk the indexer-only sources for their `target: "..."`
//! literals and require each one to be either in the set or in the
//! SHARED allowlist below, on purpose.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Targets emitted from the indexer sources that BOTH sides emit, and
/// which therefore must stay in the "app" view.
///
/// Pulling one of these into the indexer set would hide genuine
/// download-side lines from the app view - the exact failure the
/// fall-through default exists to avoid.
///
///  * `oracle`   - the completeness oracle also runs for queued jobs;
///  * `watch`    - the watch folder is an app-side feature;
///  * `nzbimport`- posted-NZB import is how a job gets queued;
///  * `cats`     - custom-category migration also runs at startup
///                 (serve/startup.rs), on the app side.
const SHARED: &[&str] = &["oracle", "watch", "nzbimport", "cats"];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a source file with CRLF folded away.
///
/// A CRLF checkout has reddened a source-scanning test in public CI
/// before now (no `.gitattributes` on the public repo), and a `\r`
/// riding on the end of a line is not worth a red build.
fn read_normalised(p: &Path) -> String {
    let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    String::from_utf8(bytes)
        .unwrap_or_else(|e| panic!("{} is not utf-8: {e}", p.display()))
        .replace("\r\n", "\n")
}

/// The sources whose log lines belong to the indexer and nothing else.
///
/// `scan.rs` is the index scanner (its `scan` target is emitted only
/// from `index_scan_into` / `scan_connect` / `collect_scan_pass`, none
/// of which the download path reaches), and everything under
/// `serve/tasks/indexer/` is the indexer task tree.
fn indexer_sources() -> Vec<PathBuf> {
    let root = crate_root().join("src");
    let mut out = vec![root.join("scan.rs"), root.join("serve/tasks/indexer.rs")];
    let dir = root.join("serve/tasks/indexer");
    let mut extra: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    extra.sort();
    out.extend(extra);
    for p in &out {
        assert!(p.is_file(), "{} moved - update this test", p.display());
    }
    out
}

/// Every `target: "name"` literal in the given source.
fn targets_in(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = src;
    while let Some(at) = rest.find("target: \"") {
        let after = &rest[at + "target: \"".len()..];
        match after.find('"') {
            Some(end) => {
                out.insert(after[..end].to_string());
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    out
}

/// The `LOG_INDEX_TAGS` set as the dashboard actually spells it.
fn dashboard_index_tags() -> BTreeSet<String> {
    let page = read_normalised(&crate_root().join("../../web/dashboard.html"));
    // Anchored on the declaration, so a rename BREAKS this test rather
    // than quietly passing over a set that no longer exists.
    let at = page
        .find("const LOG_INDEX_TAGS=new Set([")
        .expect("web/dashboard.html no longer declares LOG_INDEX_TAGS - the log view split moved");
    let body = &page[at..];
    let open = body.find('[').unwrap();
    let close = body[open..]
        .find(']')
        .expect("LOG_INDEX_TAGS literal is not closed");
    let list = &body[open + 1..open + close];
    let mut out = BTreeSet::new();
    let mut rest = list;
    while let Some(a) = rest.find('\'') {
        let after = &rest[a + 1..];
        let b = after.find('\'').expect("unterminated tag literal");
        out.insert(after[..b].to_string());
        rest = &after[b + 1..];
    }
    assert!(!out.is_empty(), "parsed an empty LOG_INDEX_TAGS");
    out
}

/// Every indexer-only lane is either in the set or shared on purpose.
#[test]
fn the_log_view_split_covers_every_indexer_lane() {
    let tags = dashboard_index_tags();
    let mut missing: Vec<String> = Vec::new();
    for path in indexer_sources() {
        for t in targets_in(&read_normalised(&path)) {
            if tags.contains(&t) || SHARED.contains(&t.as_str()) {
                continue;
            }
            missing.push(format!("{t} (from {})", path.display()));
        }
    }
    assert!(
        missing.is_empty(),
        "indexer log lanes that the dashboard's \"app, without the indexer\" view \
         still shows, and exportLog() therefore writes into the exported file: {missing:?}\n\
         Add each to LOG_INDEX_TAGS in web/dashboard.html, or - if the app side \
         emits it too - to SHARED in this file with the reason."
    );
}

/// The two lanes that earned this file.
#[test]
fn scan_and_probe7z_are_indexer_lanes() {
    let tags = dashboard_index_tags();
    for t in ["scan", "probe7z"] {
        assert!(
            tags.contains(t),
            "[{t}] lines are indexer-only and carry provider hostnames, group \
             names and release names - they must not survive the \"app, without \
             the indexer\" filter that exportLog() writes out"
        );
    }
}

/// A stale SHARED entry must not be able to mask a real omission.
#[test]
fn every_shared_exception_is_still_emitted() {
    let mut all = BTreeSet::new();
    for path in indexer_sources() {
        all.extend(targets_in(&read_normalised(&path)));
    }
    for t in SHARED {
        assert!(
            all.contains(*t),
            "SHARED lists {t:?} but no indexer source emits it any more - drop it, \
             or the next lane that takes that name is exempted by accident"
        );
    }
}

/// The dashboard matches a tag with `/\[([a-z0-9_]+)\]/`, so a target
/// with anything else in it (a dash, a capital) is invisible to BOTH
/// views' predicate and silently lands in "app".
#[test]
fn every_indexer_lane_is_spelled_the_way_the_filter_matches() {
    for path in indexer_sources() {
        for t in targets_in(&read_normalised(&path)) {
            assert!(
                !t.is_empty()
                    && t.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "target {t:?} in {} cannot be matched by the dashboard's \
                 [a-z0-9_]+ tag regex, so it can never reach the indexer view",
                path.display()
            );
        }
    }
}
