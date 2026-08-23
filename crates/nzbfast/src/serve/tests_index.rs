//! serve tests: spool migration, the watchlist keys, index
//! maintenance, disk measurement and multipart parsing.//!
//! Split out of serve/mod.rs's inline `mod tests` by TODO 106 phase 4;
//! attached to serve as a sibling child module, so `super` still means
//! `serve` exactly as it did inline.

use super::*;

/// A scratch data dir + download dir, returned as (dir, config, out).
/// `new` is the spool beside the config, `old` the one in the download
/// folder. An empty `new` is created as an empty DIRECTORY (that is the
/// placeholder case); an empty `old` is not created at all (there is no
/// leftover to find).
fn spool_case(name: &str, new: &[&str], old: &[&str]) -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("nzbfast-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config = dir.join("config.local.json");
    let out = dir.join("downloads");
    std::fs::create_dir_all(dir.join(".spool")).unwrap();
    for f in new {
        std::fs::write(dir.join(".spool").join(f), f.as_bytes()).unwrap();
    }
    if !old.is_empty() {
        std::fs::create_dir_all(out.join(".spool")).unwrap();
        for f in old {
            std::fs::write(out.join(".spool").join(f), f.as_bytes()).unwrap();
        }
    }
    (dir, config, out)
}

/// The report this fixes: Gary's `Downloads\nzbfast\.spool` was still
/// there on 1.0.10, months after the state moved to the data dir. The
/// old migration returned the instant the new spool existed and never
/// looked at what it had left in the download folder.
///
/// The live spool must be untouched (it is the state the daemon runs
/// on), the download folder must come out clean, and the residue must
/// still be findable rather than deleted.
#[test]
fn a_leftover_download_spool_is_retired_out_of_the_download_folder() {
    let (dir, config, out) = spool_case("retire-leftover", &["queue.json"], &["queue.json"]);
    let spool = super::spool_dir(&config, &out);

    assert_eq!(
        spool,
        dir.join(".spool"),
        "the live spool is the migrated one"
    );
    assert!(!out.join(".spool").exists(), "the download folder is clean");
    assert_eq!(
        std::fs::read_to_string(spool.join("queue.json")).unwrap(),
        "queue.json",
        "the live queue is the one the daemon has been running on"
    );
    assert!(
        spool.join("legacy-spool/queue.json").exists(),
        "the residue is retired, not deleted"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two leftovers are two installs' residue, so the second gets its own
/// name instead of merging into a directory that never existed.
#[test]
fn a_second_leftover_spool_lands_beside_the_first() {
    let (dir, config, out) = spool_case("retire-twice", &["queue.json"], &["a.nzb"]);
    super::spool_dir(&config, &out);
    std::fs::create_dir_all(out.join(".spool")).unwrap();
    std::fs::write(out.join(".spool/b.nzb"), "b").unwrap();
    let spool = super::spool_dir(&config, &out);

    assert!(spool.join("legacy-spool/a.nzb").exists());
    assert!(spool.join("legacy-spool-1/b.nzb").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty spool at the new location is a placeholder, not a completed
/// migration. Taking it as one would start the daemon on an empty queue
/// while the real state sat in the download folder - and then save that
/// empty queue over it.
#[test]
fn an_empty_new_spool_does_not_pass_for_a_migration() {
    let (dir, config, out) = spool_case("empty-placeholder", &[], &["queue.json"]);
    let spool = super::spool_dir(&config, &out);

    assert_eq!(
        std::fs::read_to_string(spool.join("queue.json")).unwrap(),
        "queue.json",
        "the real state migrates instead of being shadowed by the placeholder"
    );
    assert!(
        !spool.join("legacy-spool").exists(),
        "a migration is not a retirement"
    );
    assert!(!out.join(".spool").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The ordinary path: nothing in the download folder, nothing to do.
/// In particular `spool_dir` must not CREATE the spool - the caller
/// does that, after it has decided which path it is.
#[test]
fn a_clean_install_has_nothing_to_migrate_or_retire() {
    let (dir, config, out) = spool_case("no-leftover", &["queue.json"], &[]);
    let spool = super::spool_dir(&config, &out);

    assert_eq!(spool, dir.join(".spool"));
    assert!(!out.join(".spool").exists());
    assert!(!spool.join("legacy-spool").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A watchlist entry protects the index rows the watcher would match.
/// TV keys carry no year, so they are exact; a film pinned to a year
/// ALSO protects the year-less form, because a stem with no year in
/// it parses to `m:<title>` and is the same film.
#[cfg(feature = "indexer")]
#[test]
fn watchlist_entry_yields_the_keys_its_releases_carry() {
    let item = |kind: &str, title: &str, year: Option<u32>| crate::watchlist::WatchItem {
        id: 1,
        kind: kind.into(),
        title: title.into(),
        year,
        seasons: String::new(),
        episodes: String::new(),
        min_quality: String::new(),
        target_quality: "1080p".into(),
        upgrade: true,
        delete_old: false,
        category: String::new(),
        min_age: String::new(),
        max_age: String::new(),
        enabled: true,
    };
    assert_eq!(
        super::watch_item_keys(&item("tv", "The Wire", None)),
        ["t:the wire"]
    );
    assert_eq!(
        super::watch_item_keys(&item("movie", "The Matrix", Some(1999))),
        ["m:the matrix:1999", "m:the matrix"]
    );
    assert_eq!(
        super::watch_item_keys(&item("movie", "Dune", None)),
        ["m:dune"]
    );
    // 24D: a custom entry protects its category's own key space. The
    // bare form is what the episodic and daily shapes key on; the
    // tailed keys one-per-event live in the index, and protected_set
    // resolves those by prefix.
    assert_eq!(
        super::watch_item_keys(&item("formula-1", "Formula1", None)),
        ["c:formula-1:formula1"]
    );
    // Nothing to protect from a blank entry - and crucially, NOT the
    // key "t:" or "m:", which would match every unparsed row.
    assert!(super::watch_item_keys(&item("tv", "   ", None)).is_empty());
}

/// The protected set is the whole point of the feature: everything in
/// it is data the user explicitly asked to keep. All four categories
/// must survive the assembly, and the assembly must not lose one to
/// deduplication against another.
#[cfg(feature = "indexer")]
#[test]
fn protected_set_carries_all_four_categories() {
    let p = super::assemble_protected(
        // 1. watchlisted
        vec!["t:the wire".into(), "m:dune".into()],
        // 2 + 3. queued/downloading, and completed history - the
        // daemon's single "owned" key set covers both.
        vec!["t:severance".into(), "m:heat:1995".into()],
        // 4. recently opened (detail sheet)
        vec!["m:arrival:2016".into(), "t:the wire".into()],
        // 4. recently opened (getnzb / queued by id)
        vec![42, 7, 42],
    );
    for want in [
        "t:the wire",     // watchlisted
        "m:dune",         // watchlisted, no year pinned
        "t:severance",    // queued
        "m:heat:1995",    // downloaded
        "m:arrival:2016", // opened
    ] {
        assert!(
            p.title_keys.iter().any(|k| k == want),
            "{want} dropped out of the protected set: {:?}",
            p.title_keys
        );
    }
    // A key in two categories appears once, not twice - the engine
    // binds these as SQL parameters and duplicates are pure waste.
    assert_eq!(
        p.title_keys.iter().filter(|k| *k == "t:the wire").count(),
        1
    );
    assert_eq!(p.title_keys.len(), 5);
    assert_eq!(p.release_ids, vec![7, 42]);
}

/// An empty protected set is an empty protected set - it must not
/// pick up a stray "" key, which would match every unparsed row and
/// quietly protect the junk the cap exists to shed.
#[cfg(feature = "indexer")]
#[test]
fn protected_set_never_contains_the_empty_key() {
    let p = super::assemble_protected(
        vec![String::new()],
        vec![String::new(), "t:x".into()],
        vec![String::new()],
        vec![-1, 3],
    );
    assert_eq!(p.title_keys, ["t:x"]);
}

/// The touch log is the "recently opened" protection. It coalesces
/// (browsing a card twice is one signal), it expires, and it is
/// bounded - a scripted crawl of the wall cannot grow the file
/// without limit or pin the whole database forever.
#[cfg(feature = "indexer")]
#[test]
fn opened_log_coalesces_expires_and_stays_bounded() {
    let mut log = super::OpenedLog::default();
    let t0 = 1_700_000_000i64;
    // First touch is news (persist); the same key a minute later is not.
    assert!(log.touch_title("t:the wire", t0));
    assert!(!log.touch_title("t:the wire", t0 + 60));
    // ...but after the coalesce window it is worth persisting again.
    assert!(log.touch_title("t:the wire", t0 + 2 * super::OPENED_COALESCE_SECS));
    // A blank key is not a signal.
    assert!(!log.touch_title("", t0));
    assert!(log.titles.len() == 1);

    assert!(log.touch_release(5, t0));
    assert!(!log.touch_release(5, t0 + 1));
    // A parse failure gives id -1; that is not a release.
    assert!(!log.touch_release(-1, t0));
    assert_eq!(log.releases.len(), 1);

    // Expiry drops what has aged past the protection window and keeps
    // what has not.
    let window = super::OPENED_PROTECT_DAYS * 86_400;
    log.touch_title("t:old", t0 - window - 1);
    log.expire(t0 + 2 * super::OPENED_COALESCE_SECS, window);
    assert!(!log.titles.contains_key("t:old"));
    assert!(log.titles.contains_key("t:the wire"));

    // Bounded: oldest touches drop first.
    let mut big = super::OpenedLog::default();
    for i in 0..(super::OPENED_MAX_ENTRIES + 50) {
        big.touch_title(&format!("t:{i}"), t0 + i as i64);
    }
    assert_eq!(big.titles.len(), super::OPENED_MAX_ENTRIES);
    assert!(
        !big.titles.contains_key("t:0"),
        "oldest should have been trimmed"
    );
    assert!(
        big.titles
            .contains_key(&format!("t:{}", super::OPENED_MAX_ENTRIES + 49))
    );
}

/// A failed index read and an empty index must not look alike to the
/// wall. The wall latches the first `latest` it receives as its
/// cursor, so answering a failure with 0 - which is what
/// `.unwrap_or_default()` did - made the NEXT successful poll report
/// every non-junk title posted in the last week as an arrival: the
/// pill claiming 890,000 arrivals, arrived at from the other side.
#[cfg(feature = "indexer")]
#[test]
fn a_failed_tip_read_is_not_a_cursor_of_zero() {
    use nzbkit::index::TipInfo;

    // The index could not be read at all.
    let failed = super::wall_tip_body(None, true);
    assert!(
        failed["latest"].is_null(),
        "a failed read must not answer with a number the wall can latch: {failed}"
    );
    assert_eq!(failed["new"], 0);
    // The browser drops it on exactly this test, so it has to hold.
    assert!(!failed["latest"].is_i64() && !failed["latest"].is_f64());

    // An EMPTY index is a different thing and still reports a real,
    // usable cursor of 0 - the fix must not have made zero unusable.
    let empty = super::wall_tip_body(
        Some(TipInfo {
            latest: 0,
            new_keys: 0,
            keys: Vec::new(),
        }),
        true,
    );
    assert_eq!(
        empty["latest"], 0,
        "an empty index has a genuine zero cursor"
    );

    // And a first poll (`since=-1`) still reports the mark while
    // announcing nothing, which is the case that comment exists for.
    let first = super::wall_tip_body(
        Some(TipInfo {
            latest: 890_000,
            new_keys: 890_000,
            keys: vec!["t:x".into()],
        }),
        false,
    );
    assert_eq!(first["latest"], 890_000);
    assert_eq!(first["new"], 0, "'I just got here' announces nothing");
    assert_eq!(first["keys"].as_array().map(Vec::len), Some(0));
}

/// The daemon half above is only half the fix: the poll must actually
/// refuse to latch a non-number. This greps the shipped wall for that
/// guard because the HTML is embedded in the binary, so a regression
/// here ships silently.
#[cfg(feature = "indexer")]
#[test]
fn the_wall_poll_refuses_to_latch_a_failed_tip() {
    let poll = WALL_HTML
        .split("async function tipPoll")
        .nth(1)
        .and_then(|s| s.split("function renderPill").next())
        .expect("wall.html no longer has a tipPoll to guard");
    assert!(
        poll.contains("typeof j.latest!=='number'"),
        "the arrivals poll must drop a tip it cannot read as a number"
    );
    // The guard has to come BEFORE the latch, or it guards nothing.
    let guard = poll.find("typeof j.latest!=='number'").unwrap();
    let latch = poll.find("tipMark=j.latest").expect("the latch moved");
    assert!(guard < latch, "the guard must precede the latch");
}

/// An empty wall may not claim a scan that is not happening, and it has
/// to notice when the answer changes underneath it.
///
/// The empty state read only the group COUNT, so an install that was
/// offline or paused said "Scanning your newsgroups" indefinitely; and
/// the unchanged-page signature left out both the count and the scan
/// state, so choosing the first newsgroup in another tab left "Choose
/// newsgroups" up on an empty page forever, because the page itself
/// never changed (Codex sweep 7, L1). Source-scanned for the same
/// reason as the tip guard above: the HTML ships inside the binary.
#[cfg(feature = "indexer")]
#[test]
fn the_empty_wall_reads_the_stand_down_answer_and_repaints_on_it() {
    // The mid-pass bit is deliberately NOT what the copy turns on: it
    // is false for the whole post-pass database section and the gap
    // between passes, so a healthy install would flip copy every poll.
    assert!(
        WALL_HTML.contains("idxPaused=!!j.idxpaused"),
        "the wall must read the daemon's stand-down answer, not infer one"
    );
    let ladder = WALL_HTML
        .split("wall.empty.scanning")
        .next()
        .expect("the empty-state ladder moved");
    assert!(
        ladder.contains("idxGroups>0 && idxPaused"),
        "a stood-down index must be told apart from one that is scanning"
    );
    let sig = WALL_HTML
        .split("const sig=`")
        .nth(1)
        .and_then(|s| s.split('`').next())
        .expect("the unchanged-page signature moved");
    for input in ["idxGroups", "idxPaused"] {
        assert!(
            sig.contains(input),
            "{input} decides what an empty wall says, so it belongs in the \
             signature that decides whether to repaint one: {sig}"
        );
    }
}

/// The wall's nav pill keeps a translation marker while it is renamed.
///
/// `navPillName` runs before the catalogue arrives, so the loader calls
/// it again afterwards - but it used to strip the element's only
/// `data-i18n` selector on the first call, so the retry found nothing
/// and every non-English locale kept the English word (Codex sweep 7,
/// L4).
#[cfg(feature = "indexer")]
#[test]
fn the_wall_nav_pill_keeps_a_selector_across_the_catalogue() {
    let f = WALL_HTML
        .split("function navPillName()")
        .nth(1)
        .and_then(|s| s.split("\nfunction ").next())
        .expect("wall.html no longer has navPillName");
    assert!(
        !f.contains("removeAttribute('data-i18n')"),
        "the label must keep a marker the retry (and applyI18n) can find"
    );
    assert!(
        f.contains("dataset.i18n='hdr.find'"),
        "the renamed label must be re-keyed to the string it now shows"
    );
}

/// Every copy in a cross-indexer group shows its own name.
///
/// Grouping (issue #44) folds the same release from several indexers
/// into one row whose children are the losing copies. Those children
/// printed a name only where it DIFFERED from the headline's, to avoid
/// repeating one identical string down the group - but indexers
/// scraping the same scene pre usually spell it identically, so the
/// common child was a name cell holding nothing but an indexer badge,
/// and `esc()` maps a missing name to '' without complaint. KarkaLT
/// reported the blank rows on #44 the day v1.2.0 shipped. Source-scanned
/// for the same reason as the guards above: the HTML lives in the
/// binary, so nothing else here would notice it regress.
#[cfg(feature = "indexer")]
#[test]
fn every_grouped_indexer_copy_renders_its_own_name() {
    let f = WALL_HTML
        .split("function extSrcRow(")
        .nth(1)
        .and_then(|s| s.split("\nfunction ").next())
        .expect("wall.html no longer has extSrcRow");
    // The name a child renders may not be conditional on differing.
    assert!(
        !f.contains("s.title!==headTitle\n") && !f.contains("s.title!==headTitle?"),
        "a copy's name must not be rendered only when it differs from \
         the headline's - that is what left the cell empty: {f}"
    );
    // It falls back to the headline rather than to nothing, so a copy
    // that somehow arrives without a title still names its release.
    assert!(
        f.contains("s.title||headTitle"),
        "a titleless copy must fall back to the headline's name: {f}"
    );
    // And the name reaches the cell.
    assert!(
        f.contains("esc(nm)"),
        "the copy's name must be written into the row: {f}"
    );
    // Truncation at 520px is why the cell is titled: the tooltip is the
    // only way to read a long name in full.
    let cell = f
        .split("<td class=\"name\"")
        .nth(1)
        .expect("the name cell moved");
    assert!(
        cell.starts_with(" title="),
        "the name cell must carry a tooltip, or a clipped name is \
         unreadable and a blank one is unexplained: {cell}"
    );
}

/// `compact_verdict` only answers "is a download running?" once, a
/// moment before the rewrite starts - and the rewrite then holds the
/// very gate a starting download waits on. A job arriving one moment
/// later used to sit in `Downloading` with no progress and nothing
/// logged for the whole VACUUM: measured on a 175 MB database that is
/// ~0.5 s, so on the multi-GB indexes this feature exists for it is
/// minutes. The watcher keeps asking, and can still act on the answer.
#[cfg(feature = "indexer")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_download_that_starts_mid_vacuum_aborts_it() {
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    // The rewrite is under way and a job turns up.
    let jobs = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let aborts = Arc::new(AtomicUsize::new(0));
    let watch = {
        let (j, d, a) = (jobs.clone(), done.clone(), aborts.clone());
        tokio::spawn(super::abort_compact_when_job_starts(j, d, move || {
            a.fetch_add(1, Ordering::Release);
        }))
    };
    // Two poll intervals of quiet: nothing is downloading, so the
    // rewrite must be left alone.
    tokio::time::sleep(std::time::Duration::from_millis(
        super::COMPACT_ABORT_POLL_MS * 2 + 50,
    ))
    .await;
    assert_eq!(
        aborts.load(Ordering::Acquire),
        0,
        "an idle box must not lose its compact"
    );

    jobs.fetch_add(1, Ordering::Release);
    // Bounded, because the failure this guards against is a download
    // that waits forever: without the timeout a watcher that never
    // notices hangs the whole suite instead of naming the bug.
    let saw = tokio::time::timeout(std::time::Duration::from_secs(5), watch)
        .await
        .expect("the watcher never noticed the download - this is the stall itself")
        .unwrap();
    assert!(saw, "a starting download must abort the rewrite");
    assert_eq!(
        aborts.load(Ordering::Acquire),
        1,
        "and abort it exactly once"
    );

    // The other order: the rewrite finished first, so there is no
    // statement left to interrupt. Interrupting is per-CONNECTION, so
    // a late abort would hit whatever the index does next instead.
    let jobs = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let aborts = Arc::new(AtomicUsize::new(0));
    let watch = {
        let (j, d, a) = (jobs.clone(), done.clone(), aborts.clone());
        tokio::spawn(super::abort_compact_when_job_starts(j, d, move || {
            a.fetch_add(1, Ordering::Release);
        }))
    };
    done.store(true, Ordering::Release);
    jobs.fetch_add(1, Ordering::Release);
    assert!(!watch.await.unwrap(), "a finished rewrite is not aborted");
    assert_eq!(
        aborts.load(Ordering::Acquire),
        0,
        "and nothing else gets interrupted"
    );
}

/// The compaction rule the user chose: never interrupt anything.
/// VACUUM waits for a moment with no scan pass and no download, and
/// it also waits for room - it rewrites the whole file beside the
/// original, and these run on NAS boxes.
#[cfg(feature = "indexer")]
#[test]
fn compaction_defers_while_busy_and_fires_when_idle() {
    use super::CompactVerdict as V;
    let gb: u64 = 1 << 30;
    let plenty = Some(64 * gb);

    // Nothing has asked for it.
    assert_eq!(
        super::compact_verdict(false, false, false, gb, plenty, true),
        V::NotNeeded
    );
    // A scan pass is running - defer.
    assert!(matches!(
        super::compact_verdict(true, true, false, gb, plenty, true),
        V::Busy(_)
    ));
    // A download is in flight - defer. (Checked first: it is the one
    // the user is watching.)
    assert!(matches!(
        super::compact_verdict(true, false, true, gb, plenty, true),
        V::Busy(_)
    ));
    assert!(matches!(
        super::compact_verdict(true, true, true, gb, plenty, true),
        V::Busy(_)
    ));
    // Idle and roomy - go.
    assert_eq!(
        super::compact_verdict(true, false, false, gb, plenty, true),
        V::Go
    );

    // Idle but the volume cannot hold the rebuild: stay deferred
    // rather than fail halfway through rewriting the database.
    match super::compact_verdict(true, false, false, 4 * gb, Some(5 * gb), true) {
        V::NoRoom { need, free } => {
            assert!(need > 8 * gb, "VACUUM needs ~2x the file, got {need}");
            assert_eq!(free, 5 * gb);
        }
        other => panic!("expected NoRoom, got {other:?}"),
    }
    // Unmeasurable volume (an unmounted NAS share) is NOT treated as
    // "plenty of room" - that is how the min-free guard once filled
    // the disk it was protecting.
    assert!(matches!(
        super::compact_verdict(true, false, false, gb, None, true),
        V::NoRoom { .. }
    ));

    // §95: the chunked path needs no scratch space at all - it moves
    // pages down inside the file it already has and truncates. Both
    // of the room checks above must stop applying to it, or the
    // small NAS volumes this matters most on would defer forever
    // (silently and permanently - compact_pending is sticky).
    assert_eq!(
        super::compact_verdict(true, false, false, 4 * gb, Some(5 * gb), false),
        V::Go
    );
    assert_eq!(
        super::compact_verdict(true, false, false, gb, None, false),
        V::Go
    );
    // Busy still outranks it: standing off a download is the rule
    // the whole feature exists to keep.
    assert!(matches!(
        super::compact_verdict(true, false, true, gb, plenty, false),
        V::Busy(_)
    ));
}

/// There is no ceiling on the protected set any more - the engine
/// re-checks every candidate in Rust against the full uncapped set, so
/// a large set costs scan work and nothing else. What is still bounded
/// is how many passes an on-demand eviction will make before giving
/// up, which is the only loop that could otherwise spin.
#[cfg(feature = "indexer")]
#[test]
fn evict_pass_count_is_bounded_and_useful() {
    assert!(
        super::EVICT_MAX_PASSES >= 2,
        "one pass is what undershoot needs a retry for"
    );
    assert!(
        super::EVICT_MAX_PASSES <= 32,
        "a bound this loose is not a bound"
    );
    // The touch log is bounded on both halves so a scripted crawl of
    // the wall cannot grow the protected set without limit.
    assert!(super::OPENED_MAX_ENTRIES > 0);
}

/// Two very different reasons a prune stops short, and telling the
/// user the wrong one sends them hunting for protected releases that
/// do not exist.
#[cfg(feature = "indexer")]
#[test]
fn shrink_shortfall_distinguishes_protection_from_the_db_floor() {
    let floor = super::shrink_shortfall_reason(0);
    assert!(floor.contains("nothing is protected"), "{floor}");
    let prot = super::shrink_shortfall_reason(12);
    assert!(prot.contains("12 keys"), "{prot}");
    assert!(prot.contains("watchlisted"), "{prot}");
}

#[test]
fn civil_dates() {
    assert_eq!(super::civil_from_days(0), (1970, 1, 1));
    assert_eq!(super::civil_from_days(10957), (2000, 1, 1));
    assert_eq!(super::civil_from_days(20653), (2026, 7, 19));
}

#[test]
fn days_from_civil_inverts_civil_from_days() {
    for z in [-719_468i64, -1, 0, 59, 10_957, 20_653, 1_000_000] {
        let (y, m, d) = super::civil_from_days(z);
        assert_eq!(super::days_from_civil(y, m, d), z, "roundtrip of day {z}");
    }
    // Leap-year boundary both ways.
    assert_eq!(
        super::civil_from_days(super::days_from_civil(2024, 2, 29)),
        (2024, 2, 29)
    );
}

#[test]
fn quota_period_rolls_on_the_local_calendar() {
    use super::QuotaLedger as L;
    // Issue #25: at 2026-07-31T23:30Z a UTC clock is still on Jul 31,
    // but a UTC+2 clock (Berlin) already reads Aug 1. The period
    // identity must follow the LOCAL civil date, so the same instant
    // lands in different periods depending on the timezone.
    let utc_view = (2026i64, 7u32, 31u32);
    let berlin_view = (2026i64, 8u32, 1u32);
    assert_ne!(
        L::period_start_on('d', utc_view),
        L::period_start_on('d', berlin_view),
        "local midnight must open a new daily period"
    );
    assert_ne!(
        L::period_start_on('m', utc_view),
        L::period_start_on('m', berlin_view),
        "the local 1st must open a new monthly period"
    );
    // Within one local day the token never moves, and a monthly period
    // is pinned to the 1st of that local month.
    assert_eq!(
        L::period_start_on('d', berlin_view),
        L::period_start_on('d', (2026, 8, 1))
    );
    assert_eq!(
        L::period_start_on('m', (2026, 8, 17)),
        L::period_start_on('m', (2026, 8, 1))
    );
    assert_eq!(
        L::period_start_on('m', (2026, 8, 17)),
        super::days_from_civil(2026, 8, 1) as u64 * 86_400
    );
    // On a UTC machine the encoding matches the pre-#25 scheme
    // (days-since-epoch * 86_400), so upgrading does not reset a
    // half-spent ledger.
    assert_eq!(L::period_start_on('d', (2026, 7, 19)), 20_653 * 86_400);
}

/// §129 2g: the weekly period pins to the most recent local Monday.
#[test]
fn weekly_quota_period_pins_to_the_local_monday() {
    use super::QuotaLedger as L;
    // 2026-07-19 encodes as day 20_653 (asserted above) and is a
    // Sunday, so 2026-08-03 (+15 days) is a Monday.
    let monday = super::days_from_civil(2026, 8, 3) as u64 * 86_400;
    for d in 3..=9 {
        assert_eq!(
            L::period_start_on('w', (2026, 8, d)),
            monday,
            "2026-08-{d:02} belongs to the week of Monday the 3rd"
        );
    }
    assert_eq!(
        L::period_start_on('w', (2026, 8, 10)),
        super::days_from_civil(2026, 8, 10) as u64 * 86_400,
        "the next Monday opens a new weekly period"
    );
}

/// Codex 7 Aug M2: the UTC-to-local token migration must not discard a
/// non-UTC user's persisted spend. A LEGACY ledger (no "local" marker)
/// whose token matches what the old UTC scheme computes right now is
/// the current window's spend and carries; new-format ledgers demand
/// exact equality so a stale one cannot ride a coincidental UTC match.
#[test]
fn legacy_utc_quota_ledger_carries_across_the_upgrade() {
    use super::QuotaLedger as L;
    // UTC+10 at 2026-08-06 23:00Z: local token = Aug 7, legacy = Aug 6.
    let local = L::period_start_on('d', (2026, 8, 7));
    let legacy_now = L::period_start_on('d', (2026, 8, 6));
    // The upgrade moment: a legacy ledger written seconds ago under the
    // UTC scheme must carry into the local window...
    assert!(L::carry_persisted(legacy_now, false, local, legacy_now));
    // ...while a legacy ledger from an EARLIER window still drops...
    let stale = L::period_start_on('d', (2026, 8, 5));
    assert!(!L::carry_persisted(stale, false, local, legacy_now));
    // ...and a NEW-format ledger matching only the legacy token is
    // yesterday's spend, not today's - strict equality applies.
    assert!(!L::carry_persisted(legacy_now, true, local, legacy_now));
    assert!(L::carry_persisted(local, true, local, legacy_now));
}

#[test]
fn quota_ledger_persists_and_rolls() {
    let dir = std::env::temp_dir().join(format!("nzbfast-quota-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut led = super::QuotaLedger::open(&dir, 'd');
    led.add(1_000_000);
    led.add(2_000_000);
    // Survives a restart within the same period.
    let mut led2 = super::QuotaLedger::open(&dir, 'd');
    assert_eq!(led2.spent(), 3_000_000);
    // A stale period on disk is discarded on open.
    std::fs::write(dir.join("quota.json"), r#"{"start": 0, "bytes": 999}"#).unwrap();
    let mut led3 = super::QuotaLedger::open(&dir, 'd');
    assert_eq!(led3.spent(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn auto_speed_controller() {
    use super::{AUTO_SPEED_FLOOR, AUTO_SPEED_MAX, AUTO_SPEED_START, auto_speed_step};
    // Quiet network, no ceiling: climbs from the start value.
    let c1 = auto_speed_step(5, 60, 0, 0);
    assert!(c1 > AUTO_SPEED_START, "should climb: {c1}");
    // Congested: multiplicative backoff.
    let c2 = auto_speed_step(200, 60, 10_000_000, 0);
    assert_eq!(c2, 8_000_000);
    // Repeated congestion floors out, never starves.
    let mut cap = 2_000_000;
    for _ in 0..50 {
        cap = auto_speed_step(500, 60, cap, 0);
    }
    assert_eq!(cap, AUTO_SPEED_FLOOR);
    // Probe timeout (delay = MAX) is congestion at its loudest.
    assert!(auto_speed_step(u64::MAX, 60, 10_000_000, 0) < 10_000_000);
    // Ceiling respected on the climb.
    let c3 = auto_speed_step(5, 60, 3_900_000, 4_000_000);
    assert_eq!(c3, 4_000_000);
    // In the dead band (target/2 ..= target): hold.
    assert_eq!(auto_speed_step(45, 60, 5_000_000, 0), 5_000_000);
    // Unlimited climb is bounded by the sanity max.
    let mut cap = AUTO_SPEED_MAX - 1;
    cap = auto_speed_step(0, 60, cap, 0);
    assert_eq!(cap, AUTO_SPEED_MAX);
}

#[test]
fn dupe_keys() {
    assert_eq!(
        super::dupe_key("Show.Name.S01E02.1080p.WEB-DL"),
        Some("show name/s1e2".into())
    );
    assert_eq!(
        super::dupe_key("show name s01e02 720p"),
        Some("show name/s1e2".into())
    );
    // Same episode, different quality → same key.
    assert_eq!(
        super::dupe_key("Show.Name.S01E02.2160p.REMUX"),
        super::dupe_key("Show.Name.S01E02.480p")
    );
    assert_eq!(
        super::dupe_key("Movie.Title.2026.2160p"),
        Some("movie title/2026".into())
    );
    // Daily-date episodes: each date is its own identity (the movie-
    // year arm used to collapse a whole year of a daily show), and
    // dotted vs compact posts of the SAME date share a key.
    assert_eq!(
        super::dupe_key("The.Daily.Show.2026.07.21.Guest.1080p.WEB"),
        Some("the daily show/20260721 guest".into())
    );
    // What that tail is really for: a matchday is not one release.
    // Held on the bare date, the second fixture was admitted paused
    // at priority -3 and only ever promoted if the FIRST failed.
    assert_ne!(
        super::dupe_key("EPL.2026.08.22.Arsenal.vs.Spurs.1080p.WEB.h264-VERUM"),
        super::dupe_key("EPL.2026.08.22.Liverpool.vs.Everton.1080p.WEB.h264-VERUM")
    );
    assert_eq!(
        super::dupe_key("EPL.2026.08.22.Arsenal.vs.Spurs.1080p.WEB.h264-VERUM"),
        Some("epl/20260822 arsenal vs spurs".into())
    );
    // Two encodes of ONE fixture are still one release: resolution,
    // source, codec and group never reach the tail.
    assert_eq!(
        super::dupe_key("EPL.2026.08.22.Arsenal.vs.Spurs.720p.HDTV.x264-OTHER"),
        super::dupe_key("EPL.2026.08.22.Arsenal.vs.Spurs.2160p.WEB.h265-VERUM")
    );
    // Same shape for a fight card and for date-style motorsport,
    // which the year arm's F1 fix could never reach.
    assert_ne!(
        super::dupe_key("UFC.Fight.Night.2026.05.03.Early.Prelims.1080p.WEB-GRP"),
        super::dupe_key("UFC.Fight.Night.2026.05.03.Main.Card.1080p.WEB-GRP")
    );
    assert_ne!(
        super::dupe_key("Formula1.2026.07.19.Hungary.Qualifying.1080p.WEB-DL-MWR"),
        super::dupe_key("Formula1.2026.07.19.Hungary.Race.1080p.WEB-DL-MWR")
    );
    assert_ne!(
        super::dupe_key("The.Daily.Show.2026.07.21.1080p"),
        super::dupe_key("The.Daily.Show.2026.07.28.1080p")
    );
    assert_eq!(
        super::dupe_key("At.Midnight.150615.720p"),
        Some("at midnight/20150615".into())
    );
    assert_eq!(
        super::dupe_key("At.Midnight.20150615.720p"),
        super::dupe_key("At.Midnight.150615.480p")
    );
    // Year in the title, episode marker present → episode wins.
    assert_eq!(
        super::dupe_key("Show.2026.S03E07.WEB"),
        Some("show 2026/s3e7".into())
    );
    // Leading year is a title, trailing year is the marker.
    assert_eq!(
        super::dupe_key("2001.A.Space.Odyssey.1968.1080p"),
        Some("2001 a space odyssey/1968".into())
    );
    // NxNN alternate form ≡ SxxEyy (a 3x07 alt of an owned S03E07
    // used to skip the dupe check entirely and fully download).
    assert_eq!(
        super::dupe_key("Show.Name.3x07.1080p.WEB"),
        super::dupe_key("Show.Name.S03E07.720p.HDTV")
    );
    assert_eq!(
        super::dupe_key("show name 1x02 720p"),
        Some("show name/s1e2".into())
    );
    // "4x4" (single-digit "episode") is a title token, not a marker.
    assert_eq!(
        super::dupe_key("Extreme.4x4.Trucks.2026.1080p"),
        Some("extreme 4x4 trucks/2026".into())
    );
    assert_eq!(super::dupe_key("obfuscated8f3a2bc"), None);
    assert!(super::is_proper("Show.S01E02.PROPER.1080p"));
    assert!(super::is_proper("Movie.2026.REPACK.2160p"));
    assert!(!super::is_proper("The.Real.World.S01E01"));
}

/// Event releases put the SEASON in the year slot and their identity
/// after it. Keyed on title+year alone, every session of every round
/// of a year collapsed onto one key ("formula1/2026"), so the user's
/// first F1 grab downloaded and every later one was held as a paused
/// duplicate at priority -3 - the daily-date bug, one shape over.
#[test]
fn event_releases_key_on_what_follows_the_year() {
    let k = |s: &str| super::dupe_key(s).expect(s);
    // The user's two real NZBs: one round, two sessions, and the
    // second in a completely different quality dress. Both keyed to
    // "formula1/2026", so the second arrived paused.
    let show =
        k("Formula1.2026.Round11.Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p.H264.English-MWR");
    let quali =
        k("Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR");
    assert_ne!(
        show, quali,
        "the user's two real NZBs must not share a dupe key"
    );
    assert_eq!(
        show,
        "formula1/2026 round11 hungary post qualifying show f1tv"
    );
    assert_eq!(quali, "formula1/2026 round11 hungary qualifying f1tv");
    // Widened: another round in another country, and a third session.
    let belgium = k("Formula1.2026.Round12.Belgium.Race.F1TV.WEB-DL.1080p.H264.English-MWR");
    let race_uhd = k("Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.H265.English-MWR");
    let all = [&show, &quali, &belgium, &race_uhd];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b, "F1 sessions must not share a dupe key");
        }
    }
    // …but the SAME session re-posted in another resolution, codec,
    // source and by another group is still one release. Quality never
    // reaches the tail: the scan stops at the first furniture token.
    assert_eq!(
        race_uhd,
        k("Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.1080p.H264.English-MWR")
    );
    assert_eq!(
        race_uhd,
        k("Formula1.2026.Round11.Hungary.Race.F1TV.HDTV.x264.AAC5.1-OTHER")
    );
    // Generalizes past motorsport: rounds, weeks and stages all sit
    // in the same slot, and a bare number is identity, not furniture.
    assert_ne!(
        k("MotoGP.2026.Round05.France.Race.1080p.WEB-DL.H264-GRP"),
        k("MotoGP.2026.Round06.Italy.Race.1080p.WEB-DL.H264-GRP")
    );
    assert_ne!(
        k("NFL.2026.Week.05.Bears.at.Packers.1080p.WEB-DL-GRP"),
        k("NFL.2026.Week.06.Bears.at.Packers.1080p.WEB-DL-GRP")
    );
    assert_ne!(
        k("Cycling.Tour.de.France.2026.Stage.11.1080p.HDTV-GRP"),
        k("Cycling.Tour.de.France.2026.Stage.12.1080p.HDTV-GRP")
    );
    // A group tag is noise even when nothing else separates it from
    // the event name.
    assert_eq!(
        k("Formula1.2026.Round11.Hungary.Race-MWR"),
        k("Formula1.2026.Round11.Hungary.Race-OTHER")
    );
    // Events named by nationality: "Hungarian"/"Belgian" are language
    // tags, so treating a language as a hard stop would have thrown
    // the whole event name away with it and collapsed the season
    // again. A language run is only furniture when it is ALL the tail
    // has (see the dub cases in `ordinary_movies_…`); alongside real
    // identity tokens it is carried.
    assert_eq!(
        k("Formula1.2026.Hungarian.Grand.Prix.Race.1080p.WEB-DL-GRP"),
        "formula1/2026 hungarian grand prix race"
    );
    assert_ne!(
        k("Formula1.2026.Hungarian.Grand.Prix.Race.1080p.WEB-DL-GRP"),
        k("Formula1.2026.Belgian.Grand.Prix.Race.1080p.WEB-DL-GRP")
    );
}

/// The other half of the same coin: an ordinary film's year IS its
/// release date, everything after it is furniture, and the key must
/// come out byte-identical to what it was before the event fix.
#[test]
fn ordinary_movies_keep_their_bare_title_year_key() {
    let k = |s: &str| super::dupe_key(s).expect(s);
    // Two very different encodes of one film - one key.
    assert_eq!(
        k("The.Matrix.1999.1080p.BluRay.x264-GROUP"),
        "the matrix/1999"
    );
    assert_eq!(
        k("The.Matrix.1999.2160p.UHD.BluRay.REMUX.HDR.HEVC.TrueHD.Atmos-FraMeSToR"),
        "the matrix/1999"
    );
    assert_eq!(
        k("The.Matrix.1999.1080p.BluRay.x264-GROUP"),
        k("The.Matrix.1999.2160p.UHD.BluRay.REMUX.HDR.HEVC.TrueHD.Atmos-FraMeSToR")
    );
    // Furniture shapes that must all reduce to nothing: split audio
    // channel tokens, glued channel counts, editions, dubs, friendly
    // renames, and a title that is itself a year.
    for s in [
        "Dune.Part.Two.2024.2160p.WEB-DL.DDP5.1.Atmos.DV.HDR.H.265-FLUX",
        "Dune.Part.Two.2024.1080p.AMZN.WEB-DL.DD.5.1.H.264-NTb",
        "Dune.Part.Two.2024.720p.BluRay.x264.AAC5.1-YTSMX",
        "Dune Part Two (2024) [1080p] [WEBRip] [YTS.MX]",
        "Dune.Part.Two.2024.EXTENDED.1080p.BluRay.x264-GRP",
        "Dune.Part.Two.2024.Directors.Cut.1080p.BluRay.x264-GRP",
        "Dune.Part.Two.2024.German.DL.1080p.BluRay.x264-DEU",
        "Dune.Part.Two.2024.MULTi.TRUEFRENCH.1080p.WEB-GRP",
        "Dune.Part.Two.2024.iNTERNAL.HDR.2160p.WEB.h265-GRP",
    ] {
        assert_eq!(k(s), "dune part two/2024", "{s}");
    }
    // A second year after the marker is furniture, not identity.
    assert_eq!(
        k("Blade.Runner.2049.2017.2160p.WEB-DL"),
        "blade runner/2049"
    );
}

/// A double-episode grab is recorded in BOTH episode slots, so an
/// upgrade of one of them must not delete the download that is still
/// the only copy of the other - including once the sibling slot has
/// already been rewritten by the same pass, which is what a scan of
/// the live slot map misses.
#[test]
fn an_upgrade_only_deletes_what_it_fully_replaces() {
    use crate::watchlist as wl;
    let tv = wl::WatchItem {
        id: 7,
        kind: "tv".into(),
        title: "Show Name".into(),
        year: None,
        seasons: String::new(),
        episodes: String::new(),
        min_quality: "any".into(),
        target_quality: "2160p".into(),
        upgrade: true,
        delete_old: true,
        category: String::new(),
        min_age: String::new(),
        max_age: String::new(),
        enabled: true,
    };
    let slot = |stem: &str, nzo: &str| wl::Slot {
        rank: 3,
        stem: stem.into(),
        quality: "720p WEB".into(),
        nzo_id: nzo.into(),
        grabbed_at: 0,
        failed: Vec::new(),
    };
    let double = slot("Show.Name.S01E01E02.720p.WEB.h264-GRP", "nzo-double");
    let single = slot("Show.Name.S01E03.720p.WEB.h264-GRP", "nzo-single");
    let mut state = wl::WatchState::default();
    state.slots.insert("7:s01e01".into(), double.clone());
    state.slots.insert("7:s01e02".into(), double.clone());
    state.slots.insert("7:s01e03".into(), single.clone());
    let p = |s: &str| crate::wall::parse_release(s);

    // Upgrading E02 with a single-episode 1080p leaves E01 with only
    // the double for company - the delete has to wait.
    let e02 = p("Show.Name.S01E02.1080p.WEB.h264-GRP");
    assert!(!super::upgrade_supersedes_all(
        &tv,
        &state,
        &double,
        &e02,
        &[]
    ));
    // ...and still has to wait once E01's own upgrade has rewritten
    // that slot in this very pass. Nothing points at the double any
    // more, but it is still the only copy of E01 until nzo-e01 lands.
    let e01_up = slot("Show.Name.S01E01.1080p.WEB.h264-GRP", "nzo-e01");
    state.slots.insert("7:s01e01".into(), e01_up);
    assert!(!super::upgrade_supersedes_all(
        &tv,
        &state,
        &double,
        &e02,
        &[]
    ));

    // A like-for-like double upgrade reaches both slots, so the
    // superseded copy is deleted as the user asked - leaving it would
    // orphan a full copy on every multi-episode upgrade.
    let both = p("Show.Name.S01E01E02.1080p.WEB.h264-GRP");
    assert!(super::upgrade_supersedes_all(
        &tv,
        &state,
        &double,
        &both,
        &[]
    ));
    // A single-episode grab owns only its own slot.
    let e03 = p("Show.Name.S01E03.1080p.WEB.h264-GRP");
    assert!(super::upgrade_supersedes_all(
        &tv,
        &state,
        &single,
        &e03,
        &[]
    ));
}

/// The watch folder's settle gate must fail CLOSED: a signature it
/// cannot take is not a signature that matches. It also has to
/// measure what `read` will read, which for a symlinked .nzb is the
/// target, not the link (whose own size and mtime never move).
#[test]
fn watch_signature_follows_links_and_fails_closed() {
    let dir = std::env::temp_dir().join(format!("nzbfast-watchsig-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("post.nzb");
    std::fs::write(&f, b"<nzb></nzb>").unwrap();
    let sig = super::watch_sig(&f).expect("a real file has a signature");
    assert_eq!(sig.1, 11);
    assert_eq!(super::watch_sig(&dir.join("nothing.nzb")), None);
    #[cfg(unix)]
    {
        let link = dir.join("link.nzb");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert_eq!(super::watch_sig(&link), Some(sig));
        std::fs::write(&f, b"<nzb>grown</nzb>").unwrap();
        assert_ne!(
            super::watch_sig(&link),
            Some(sig),
            "the target's size counts"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every platform we ship must actually measure the volume. Windows
/// had no implementation at all for a while: disk_stat returned None
/// unconditionally, which silently disabled the min-free guard and
/// printed "0.00 GB free" on the dashboard.
#[cfg(any(unix, windows))]
#[test]
fn disk_stat_measures_the_volume_holding_a_path() {
    let (free, total) =
        super::disk_stat(&std::env::temp_dir()).expect("the temp dir is on a real filesystem");
    assert!(total > 0, "a mounted volume has a size");
    assert!(free <= total, "free {free} exceeds total {total}");
}

/// The min-free guard only acts when free_bytes answers, so a
/// not-yet-created output directory used to disable it outright: the
/// job ran and filled the disk the guard was meant to protect. An
/// unmounted NAS mount point is the same shape.
#[cfg(any(unix, windows))]
#[test]
fn free_bytes_answers_for_a_directory_that_does_not_exist_yet() {
    let base = std::env::temp_dir();
    let here = super::free_bytes(&base).expect("temp dir is on a real filesystem");
    let missing = base.join(format!("nzbfast-absent-{}/deep/deeper", std::process::id()));
    assert!(!missing.exists());
    let got = super::free_bytes(&missing).expect("resolves via the nearest existing ancestor");
    // Same filesystem as the nearest existing ancestor, so the same
    // ballpark - not an exact match, free space moves under us.
    let (lo, hi) = (here.min(got), here.max(got));
    assert!(
        hi - lo < hi / 10,
        "expected the ancestor's filesystem: {here} vs {got}"
    );
}

/// The dashboard and the NZBGet-compat status report need (free,
/// total), and both used bare disk_stat: a completed-downloads dir
/// that hadn't been created yet (it's made lazily at job completion)
/// reported "0 MB free on disk", and the *arrs read a full disk.
#[cfg(any(unix, windows))]
#[test]
fn disk_stat_walk_answers_for_a_directory_that_does_not_exist_yet() {
    let base = std::env::temp_dir();
    let missing = base.join(format!(
        "nzbfast-walkabsent-{}/deep/deeper",
        std::process::id()
    ));
    assert!(!missing.exists());
    let (free, total) =
        super::disk_stat_walk(&missing).expect("resolves via the nearest existing ancestor");
    assert!(total > 0, "the ancestor's volume has a size");
    assert!(free <= total);
}

/// The key comparison was already constant-time, but a wrong key was
/// recorded nowhere and slowed nothing down, so an unauthenticated peer
/// could grind it at full request rate leaving no trace in any log.
#[test]
fn repeated_bad_keys_from_one_address_get_refused() {
    let table = super::Mutex::new(std::collections::HashMap::new());
    let note = |ip| super::note_auth_failure_in(&table, ip, "test");
    let attacker = Some(std::net::IpAddr::from([10, 0, 0, 9]));

    for attempt in 1..super::AUTH_FAIL_THRESHOLD {
        assert!(
            !note(attacker),
            "attempt {attempt} should still be allowed through"
        );
    }
    assert!(note(attacker), "the threshold attempt must be refused");
    assert!(note(attacker), "and stay refused");

    // A different address is unaffected - one hostile peer must not lock
    // out the household's *arr apps.
    assert!(!note(Some(std::net::IpAddr::from([10, 0, 0, 10]))));

    // No address at all (a transport that does not report one) is never
    // blocked: accounting fails open, the key check does not.
    assert!(!note(None));
}

/// The tracking table must not become the attack: a spray from many
/// source addresses cannot grow it without bound.
#[test]
fn the_auth_failure_table_is_bounded() {
    let table = super::Mutex::new(std::collections::HashMap::new());
    for i in 0..(super::AUTH_FAIL_MAX_TRACKED + 500) {
        let ip = std::net::IpAddr::from(((i as u32) + 0x0100_0000).to_be_bytes());
        super::note_auth_failure_in(&table, Some(ip), "spray");
    }
    assert!(
        table.lock().unwrap().len() <= super::AUTH_FAIL_MAX_TRACKED,
        "the table grew past its ceiling"
    );
}

#[cfg(feature = "indexer")]
#[test]
fn image_sniff_accepts_real_formats_only() {
    assert!(super::looks_image(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]));
    assert!(super::looks_image(b"\x89PNG\r\n\x1a\n...."));
    assert!(super::looks_image(b"GIF89a...."));
    assert!(super::looks_image(b"RIFF\x00\x00\x00\x00WEBPVP8 "));
    assert!(!super::looks_image(b"<html><body>404</body></html>"));
    assert!(!super::looks_image(b"RIFF\x00\x00\x00\x00WAVEfmt "));
    assert!(!super::looks_image(b""));
}

/// /art/ is unauthenticated, so its name check is the only thing
/// between a stranger and `art_root.join(...)`. The device names are
/// the ones that bite: they pass the alphanumeric class, and on
/// Windows the open resolves to the console and the read never
/// returns, wedging an HTTP worker for good.
#[cfg(feature = "indexer")]
#[test]
fn art_names_reject_traversal_and_dos_devices() {
    assert!(super::art_name_ok("m_the_matrix_1999.jpg"));
    assert!(super::art_name_ok("t_severance.bd.jpg"));
    assert!(super::art_name_ok("thumb_m_the_matrix_1999.jpg"));
    assert!(!super::art_name_ok(""));
    assert!(!super::art_name_ok("../../etc/passwd"));
    assert!(!super::art_name_ok("a/b.jpg"));
    assert!(!super::art_name_ok("CON"));
    assert!(!super::art_name_ok("con.jpg"));
    assert!(!super::art_name_ok("COM1"));
    assert!(!super::art_name_ok("LPT9.jpg"));
    // The thumb source is joined too, so it gets its own pass.
    assert!(!super::art_name_ok(
        "thumb_CON.jpg".strip_prefix("thumb_").unwrap()
    ));
}

/// The pre-auth amplifier. `Content-Type: multipart/form-data;
/// boundary=` is accepted by tiny_http and makes the delimiter
/// `--`, so a body of hyphens split once every two bytes - and the
/// splitter held a fat pointer per segment, turning a 256 MiB body
/// (which an UNAUTHENTICATED caller gets to send, because the key
/// may be a form field) into roughly 2 GiB of vector on top of it,
/// outside the body budget. Both halves are pinned: the boundary is
/// refused outright, and the parse no longer materializes segments.
#[test]
fn an_empty_boundary_parses_nothing() {
    assert!(!super::valid_boundary(""));
    assert!(!super::valid_boundary(&"x".repeat(71)));
    assert!(super::valid_boundary("----nzbfastboundary"));
    let body = b"--".repeat(1 << 20);
    assert!(super::multipart_fields(&body, "").is_empty());
    assert!(super::multipart_file(&body, "").is_none());
}

/// One boundary parse for the gateway and both file-part handlers.
///
/// There were three copies and they disagreed after Codex sweep 2's
/// H1 taught the gateway that a media type's parameter names are
/// case-insensitive: `Boundary=` then parsed as multipart at the
/// gateway - fields merged, the key found, auth decided - and as
/// nothing in `addfile`, so the upload arrived with no file part at
/// all. The parameter NAME is matched case-insensitively; the VALUE
/// is a literal delimiter and keeps its case exactly.
#[test]
fn one_boundary_parse_serves_the_gateway_and_the_handlers() {
    let b = |c: &str| super::multipart_boundary(c);
    assert_eq!(
        b("multipart/form-data; boundary=AbCd1234"),
        Some("AbCd1234".into())
    );
    // The spellings a standards-compliant client may legally send.
    assert_eq!(
        b("Multipart/Form-Data; Boundary=AbCd1234"),
        Some("AbCd1234".into())
    );
    assert_eq!(
        b("multipart/form-data; BOUNDARY=\"AbCd1234\""),
        Some("AbCd1234".into())
    );
    // The refusals `valid_boundary` exists for, now unforgettable
    // because they live at the single source rather than in each
    // caller.
    assert_eq!(b("multipart/form-data; boundary="), None);
    assert_eq!(b("multipart/form-data"), None);
    assert_eq!(b("application/json"), None);
    assert_eq!(
        b(&format!("multipart/form-data; boundary={}", "x".repeat(71))),
        None
    );
}

/// A form with thousands of fields is not a form. The parser's own
/// working set must be bounded by something other than how many
/// delimiters the caller sent.
#[test]
fn multipart_fields_are_capped() {
    let b = "----nzbfastboundary";
    let mut body = Vec::new();
    for i in 0..1000 {
        body.extend_from_slice(
            format!("--{b}\r\nContent-Disposition: form-data; name=\"f{i}\"\r\n\r\nv\r\n")
                .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{b}--\r\n").as_bytes());
    assert_eq!(super::multipart_fields(&body, b).len(), 256);
}

/// Codex H8: a part whose "header block" is attacker-sized invalid
/// UTF-8 must never reach the lossy decode - `from_utf8_lossy`
/// expands each invalid byte to a 3-byte replacement character, and
/// this parser runs pre-authentication on a body of up to 256 MiB.
/// The giant part is skipped; legitimate parts beside it still work.
#[test]
fn a_giant_part_header_is_never_decoded() {
    let b = "----nzbfastboundary";
    let mut body = Vec::new();
    // One part: 4 MiB of 0xFF posing as the header, then CRLFCRLF.
    body.extend_from_slice(format!("--{b}\r\n").as_bytes());
    body.extend_from_slice(&vec![0xFFu8; 4 << 20]);
    body.extend_from_slice(b"\r\n\r\nv\r\n");
    // A normal field and a normal file part after it.
    body.extend_from_slice(
        format!("--{b}\r\nContent-Disposition: form-data; name=\"mode\"\r\n\r\naddfile\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"e.nzb\"\r\n\r\n<nzb/>\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("--{b}--\r\n").as_bytes());
    assert_eq!(
        super::multipart_fields(&body, b),
        vec![("mode".to_string(), "addfile".to_string())]
    );
    assert_eq!(super::multipart_file(&body, b).unwrap().1, b"<nzb/>");
    // And a header just under the bound still parses - the cap must
    // not eat legitimate long filenames.
    let long_name = "x".repeat(300);
    let mut small = Vec::new();
    small.extend_from_slice(
        format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"n\"; filename=\"{long_name}\"\r\n\r\nd\r\n--{b}--\r\n"
        )
        .as_bytes(),
    );
    assert_eq!(super::multipart_file(&small, b).unwrap().0, long_name);
}

#[test]
fn multipart_parses() {
    let boundary = "----nzbfastboundary";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"e.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n").as_bytes());
    body.extend_from_slice(b"<nzb>hi</nzb>");
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let got = super::multipart_file(&body, boundary).expect("parse");
    assert_eq!(got.0, "e.nzb");
    assert_eq!(got.1, b"<nzb>hi</nzb>");
}

/// The SAB-compat field extractor: form fields come out, the file
/// part stays out (it belongs to multipart_file), and a field-shaped
/// part carrying megabytes is refused as a parameter.
#[test]
fn multipart_fields_parses_and_skips_files() {
    let b = "----nzbfastboundary";
    let mut body = Vec::new();
    for (n, v) in [("mode", "addfile"), ("apikey", "sekrit"), ("cat", "tv")] {
        body.extend_from_slice(
            format!("--{b}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n")
                .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"e.nzb\"\r\n\r\n<nzb/>\r\n"
        )
        .as_bytes(),
    );
    let huge = "x".repeat(5000);
    body.extend_from_slice(
        format!("--{b}\r\nContent-Disposition: form-data; name=\"blob\"\r\n\r\n{huge}\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("--{b}--\r\n").as_bytes());
    let fields = super::multipart_fields(&body, b);
    assert_eq!(
        fields,
        vec![
            ("mode".to_string(), "addfile".to_string()),
            ("apikey".to_string(), "sekrit".to_string()),
            ("cat".to_string(), "tv".to_string()),
        ]
    );
    // The file part is still the file parser's to find.
    assert_eq!(super::multipart_file(&body, b).unwrap().1, b"<nzb/>");
}
