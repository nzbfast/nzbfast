//! Unit tests for the pure helpers in job.rs (TODO 106 phase 3).
//! Covers the gaps the serve/mod.rs test mod does not touch.

use super::*;
use std::path::{Path, PathBuf};

fn tdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-job-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---- choose_out_dir ----

#[test]
fn choose_out_dir_free_base_is_taken_as_is() {
    let base = PathBuf::from("/x/Show");
    let (dir, replaces) = choose_out_dir(&base, "Show", &|_| DirClaim::Free);
    assert_eq!(dir, base);
    assert_eq!(replaces, None);
}

#[test]
fn choose_out_dir_payload_at_base_records_replace_and_climbs() {
    let base = PathBuf::from("/x/Show");
    let claim = |p: &Path| {
        if p == Path::new("/x/Show") {
            DirClaim::Payload
        } else {
            DirClaim::Free
        }
    };
    let (dir, replaces) = choose_out_dir(&base, "Show", &claim);
    assert_eq!(dir, PathBuf::from("/x/Show.2"));
    assert_eq!(replaces, Some(base));
}

#[test]
fn choose_out_dir_payload_on_numbered_sibling_is_not_replaced() {
    // Base is Active (another job), .2 holds a completed payload: the
    // numbered sibling is left alone and no replace is recorded.
    let base = PathBuf::from("/x/Show");
    let claim = |p: &Path| {
        if p == Path::new("/x/Show") {
            DirClaim::Active
        } else if p == Path::new("/x/Show.2") {
            DirClaim::Payload
        } else {
            DirClaim::Free
        }
    };
    let (dir, replaces) = choose_out_dir(&base, "Show", &claim);
    assert_eq!(dir, PathBuf::from("/x/Show.3"));
    assert_eq!(replaces, None);
}

#[test]
fn choose_out_dir_active_climbs_without_replace() {
    let base = PathBuf::from("/x/Show");
    let claim = |p: &Path| {
        if p == Path::new("/x/Show") {
            DirClaim::Active
        } else {
            DirClaim::Free
        }
    };
    let (dir, replaces) = choose_out_dir(&base, "Show", &claim);
    assert_eq!(dir, PathBuf::from("/x/Show.2"));
    assert_eq!(replaces, None);
}

/// The climb's rungs have to be writable, and the base being writable
/// does not make them so.
///
/// `dir_stem` arrives capped at 255 bytes - `Daemon::enqueue` and
/// `refile_out_dir` both spell it through `sanitize_filename_capped`, and
/// `an_overlong_job_name_still_gets_a_writable_directory` in
/// `tests_jobs.rs` pins that end. `.2` on top of a name AT the cap is 257
/// bytes and every `mkdir` under it is `ENAMETOOLONG` (measured on APFS
/// 31 Aug 2026: 255 creates, 256 does not), so the FIRST collision handed
/// a job a directory it could not have - and a collision is the ordinary
/// case this ladder exists for, not a corner.
///
/// That pin could not see it because its claim never collides, which is
/// the general shape: a cap tested at the base says nothing about a name
/// composed onto the base.
#[test]
fn choose_out_dir_climbs_to_a_directory_the_disk_will_create() {
    let root = std::env::temp_dir().join(format!(
        "nzbfast-climbcap-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let stem = nzbkit::disk::sanitize_filename_capped(&"L".repeat(400));
    assert_eq!(stem.len(), 255, "the premise moved");
    let base = root.join(&stem);

    // The canonical directory is taken, so the job climbs.
    let (dir, replaces) = choose_out_dir(&base, &stem, &|p| {
        if p == base {
            DirClaim::Active
        } else {
            DirClaim::Free
        }
    });
    assert_ne!(dir, base, "it must climb");
    assert_eq!(replaces, None, "an ACTIVE claimant is not replaced");
    // The assertion the byte count is standing in for everywhere else.
    std::fs::create_dir_all(&dir).expect("the climbed directory must be creatable");
    assert_eq!(dir.parent(), Some(root.as_path()), "still a sibling");

    // Nothing that works today moves: inside the cap the rung is still
    // the plain `format!`, byte for byte.
    let short = root.join("Show");
    let (plain, _) = choose_out_dir(&short, "Show", &|p| {
        if p == short {
            DirClaim::Active
        } else {
            DirClaim::Free
        }
    });
    assert_eq!(plain, root.join("Show.2"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn choose_out_dir_multi_step_climb_keeps_base_replace() {
    // Payload at base, Active at .2: climbs to .3, still replacing base.
    let base = PathBuf::from("/x/Show");
    let claim = |p: &Path| {
        if p == Path::new("/x/Show") {
            DirClaim::Payload
        } else if p == Path::new("/x/Show.2") {
            DirClaim::Active
        } else {
            DirClaim::Free
        }
    };
    let (dir, replaces) = choose_out_dir(&base, "Show", &claim);
    assert_eq!(dir, PathBuf::from("/x/Show.3"));
    assert_eq!(replaces, Some(base));
}

// ---- is_season_dir ----

#[test]
fn season_dir_shapes() {
    assert!(is_season_dir(Path::new("/lib/Show/Season 01")));
    assert!(is_season_dir(Path::new("/lib/Show/Season 1")));
    assert!(is_season_dir(Path::new("/lib/Show/Season 007")));
    assert!(!is_season_dir(Path::new("/lib/Show/Season ")));
    assert!(!is_season_dir(Path::new("/lib/Show/Season 1a")));
    // Case-sensitive by design.
    assert!(!is_season_dir(Path::new("/lib/Show/season 01")));
    assert!(!is_season_dir(Path::new("/lib/Show")));
}

// ---- disk_full_failure ----

#[test]
fn disk_full_phrasings_match() {
    assert!(disk_full_failure("No space left on device"));
    assert!(disk_full_failure("There is not enough space on the disk."));
    assert!(disk_full_failure("unpack failed: disk full"));
}

#[test]
fn disk_full_is_case_insensitive() {
    assert!(disk_full_failure("NO SPACE LEFT ON DEVICE"));
    assert!(disk_full_failure("Not Enough Space on the disk"));
    assert!(disk_full_failure("DISK FULL"));
}

#[test]
fn disk_full_rejects_unrelated_messages() {
    assert!(!disk_full_failure("connection reset by peer"));
    assert!(!disk_full_failure(""));
}

// ---- the mid-download out-of-disk-space verdict ----

#[test]
fn mid_download_disk_full_verdict_classifies_end_to_end() {
    // The verdict drain_network bails with, kind-classified at the
    // write - the quoted OS text may be localized or carry an odd code,
    // so the OPENING must be enough on its own.
    let msg = "out of disk space - the output volume filled during the download, \
               so fetching was stopped early; what landed is journaled and kept \
               (write vol.r01: Speicherplatz reicht nicht aus (os error 999))";
    assert!(disk_full_mid_download(msg));
    assert!(disk_full_failure(msg));
    // Local + disk-full = the SPACE action and the SPACE *arr verdict.
    assert!(matches!(fail_kind(msg), FailKind::Local));
    assert_eq!(fail_action(FailKind::Local, "", msg, false), "space");
    // Appended clauses never move the opening: classification holds.
    let appended = format!("{msg}; free about 4.2 GB on that disk");
    assert!(disk_full_mid_download(&appended));
    assert!(disk_full_failure(&appended));
}

/// Gary, 16 Aug: both surfaces that talk about a missing-articles
/// failure promise "posts often finish propagating within the hour".
/// `incomplete_reason` now says when the post is older than that can
/// explain, and this is the token the drawer picks the copy by. It is
/// the LAST arm, so a post that is both old and hopeless still reports
/// the hopeless part - that is the one with a different answer.
#[test]
fn an_old_post_is_hinted_stale_but_never_over_a_sharper_hint() {
    let base = "download incomplete: 1 file(s) with missing segments, 0 decode/write \
                errors; 1965 of 4506 segment(s) never arrived (1879 MB did)";
    let old = format!(
        "{base}; the post is 4 day(s) old, well past the minutes-to-hours that \
         propagation takes"
    );
    assert_eq!(fail_hint(&old), "stale");
    // The button does not change: a retry still fetches only the gaps,
    // and a late backfill can still fill one. Only the sentence does.
    assert_eq!(
        fail_action(fail_kind(&old), fail_hint(&old), &old, false),
        "retry"
    );
    assert!(matches!(fail_kind(&old), FailKind::MissingArticles));

    // A post with no parity at all is answered by another release
    // whatever its age, and that hint must survive the age clause.
    let nopar2 = format!(
        "{old}; 1965 segment(s) were confirmed missing by every server AND this \
         post carries no PAR2 recovery data"
    );
    assert_eq!(fail_hint(&nopar2), "nopar2");
    assert_eq!(
        fail_action(fail_kind(&nopar2), fail_hint(&nopar2), &nopar2, false),
        "search"
    );

    // A fresh post carries no clause, so nothing is hinted and the
    // kind's own "ask again" stands.
    assert_eq!(fail_hint(base), "");
    assert_eq!(fail_action(fail_kind(base), "", base, false), "retry");
}

/// Damaged copies on the server are not a fault of this machine, and the
/// drawer must not answer them with "show the folder". Both clauses land
/// in `Local` (they are neither missing articles nor a repair verdict),
/// so the HINT is what carries the remedy. Wire-corruption leg, 11 Aug.
#[test]
fn corrupt_articles_offer_retry_and_a_short_post_offers_search() {
    let corrupt = "the articles did not decode: 1 damaged article(s) and no missing \
                   segments - every article arrived, but their contents failed the yEnc \
                   checks, so the copies on the server are corrupt. Retrying re-fetches \
                   them, and a second provider usually carries a clean copy \
                   (first error: decode error: =yend size 700000 does not match \
                   decoded length 700024)";
    assert_eq!(fail_hint(corrupt), "corrupt");
    assert_eq!(
        fail_action(fail_kind(corrupt), fail_hint(corrupt), corrupt, false),
        "retry",
        "a re-fetch is the remedy for bytes the server damaged"
    );

    let short = "post size header disagrees with its parts: every payload article \
                 arrived and decoded, but 2 file(s) declare more bytes than the post \
                 actually carries, 0 decode/write errors. Re-downloading cannot change \
                 this - the missing bytes were never posted";
    assert_eq!(fail_hint(short), "shortpost");
    assert_eq!(
        fail_action(fail_kind(short), fail_hint(short), short, false),
        "search",
        "asking again returns the same short post - another release is the answer"
    );

    // A genuine write failure keeps the folder, and a locked archive
    // still outranks every hint.
    let wrote = "could not write the download: 3 decode/write error(s) and no missing \
                 segments - every article arrived, so check free space, permissions and \
                 the log above";
    assert_eq!(fail_hint(wrote), "");
    assert_eq!(fail_action(fail_kind(wrote), "", wrote, false), "path");
    assert_eq!(
        fail_action(fail_kind(corrupt), "corrupt", corrupt, true),
        "password"
    );
}

#[test]
fn mid_download_verdict_keys_on_the_opening_only() {
    // An unpack-stage disk-full mentions space but did NOT halt the
    // fetch - the two want different guidance.
    assert!(!disk_full_mid_download(
        "extraction failed: No space left on device (os error 28)"
    ));
    // Moved off the opening, it is not the mid-download verdict.
    assert!(!disk_full_mid_download(
        "download incomplete; out of disk space"
    ));
}

#[cfg(unix)]
#[test]
fn disk_full_unix_numeric_form() {
    assert!(disk_full_failure("write failed (os error 28)"));
    // The closing paren keeps 28 from matching inside 280.
    assert!(!disk_full_failure("write failed (os error 280)"));
    // 112 is EHOSTDOWN on unix, not disk full.
    assert!(!disk_full_failure("write failed (os error 112)"));
}

// ---- dated_key ----

#[test]
fn dated_key_trims_trailing_group_tag() {
    let tokens = ["epl", "2026", "08", "22", "arsenal", "everton", "grp"];
    let key = dated_key(
        &tokens,
        1,
        4,
        "20260822",
        "EPL.2026.08.22.Arsenal.Everton-GRP",
    );
    assert_eq!(key, "epl/20260822 arsenal everton");
}

#[test]
fn dated_key_without_group_keeps_tail_intact() {
    let tokens = ["epl", "2026", "08", "22", "arsenal", "everton"];
    let key = dated_key(&tokens, 1, 4, "20260822", "EPL.2026.08.22.Arsenal.Everton");
    assert_eq!(key, "epl/20260822 arsenal everton");
}

#[test]
fn dated_key_group_not_last_token_is_kept() {
    // Tail ends in the group's word, but the token list's LAST token is
    // furniture, so the positional guard refuses the pop.
    let tokens = ["epl", "2026", "08", "22", "arsenal", "grp", "1080p"];
    let key = dated_key(&tokens, 1, 4, "20260822", "Whatever-GRP");
    assert_eq!(key, "epl/20260822 arsenal grp");
}

#[test]
fn dated_key_empty_tail_is_head_slash_date() {
    let tokens = ["nfl", "2026", "08", "22"];
    assert_eq!(
        dated_key(&tokens, 1, 4, "20260822", "NFL.2026.08.22"),
        "nfl/20260822"
    );
}

#[test]
fn dated_key_furniture_only_tail_is_empty() {
    let tokens = ["nfl", "2026", "08", "22", "1080p", "web"];
    assert_eq!(
        dated_key(&tokens, 1, 4, "20260822", "NFL.2026.08.22.1080p.WEB"),
        "nfl/20260822"
    );
}

#[test]
fn dated_key_date_first_gives_leading_slash() {
    let tokens = ["2026", "08", "22", "arsenal"];
    assert_eq!(
        dated_key(&tokens, 0, 3, "20260822", "2026.08.22.Arsenal"),
        "/20260822 arsenal"
    );
}

// ---- claim_extra_slot ----

fn slot(rank: u32, stem: &str, nzo: &str) -> nzbfast_meta::watchlist::Slot {
    nzbfast_meta::watchlist::Slot {
        rank,
        stem: stem.to_string(),
        quality: String::new(),
        nzo_id: nzo.to_string(),
        grabbed_at: 0,
        failed: Vec::new(),
    }
}

#[test]
fn claim_extra_slot_vacant_inserts() {
    let mut slots = std::collections::HashMap::new();
    claim_extra_slot(&mut slots, "k".into(), &slot(3, "a", "n1"));
    assert_eq!(slots["k"].nzo_id, "n1");
}

#[test]
fn claim_extra_slot_better_occupant_refuses() {
    let mut slots = std::collections::HashMap::new();
    slots.insert("k".to_string(), slot(5, "a", "n1"));
    claim_extra_slot(&mut slots, "k".into(), &slot(3, "b", "n2"));
    assert_eq!(slots["k"].nzo_id, "n1");
}

#[test]
fn claim_extra_slot_same_stem_always_overwrites() {
    let mut slots = std::collections::HashMap::new();
    slots.insert("k".to_string(), slot(5, "a", "n1"));
    claim_extra_slot(&mut slots, "k".into(), &slot(3, "a", "n2"));
    assert_eq!(slots["k"].nzo_id, "n2");
    assert_eq!(slots["k"].rank, 3);
}

#[test]
fn claim_extra_slot_equal_rank_takes() {
    let mut slots = std::collections::HashMap::new();
    slots.insert("k".to_string(), slot(3, "a", "n1"));
    claim_extra_slot(&mut slots, "k".into(), &slot(3, "b", "n2"));
    assert_eq!(slots["k"].nzo_id, "n2");
}

#[test]
fn claim_extra_slot_higher_rank_takes() {
    let mut slots = std::collections::HashMap::new();
    slots.insert("k".to_string(), slot(3, "a", "n1"));
    claim_extra_slot(&mut slots, "k".into(), &slot(5, "b", "n2"));
    assert_eq!(slots["k"].nzo_id, "n2");
}

// ---- nzb_sha ----

#[test]
fn nzb_sha_known_digests() {
    assert_eq!(
        nzb_sha(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        nzb_sha(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn nzb_sha_is_64_lowercase_hex() {
    let s = nzb_sha(b"anything at all");
    assert_eq!(s.len(), 64);
    assert!(
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}

// ---- priority_name ----

#[test]
fn priority_names() {
    assert_eq!(priority_name(-3), "Duplicate");
    assert_eq!(priority_name(2), "Force");
    assert_eq!(priority_name(1), "High");
    assert_eq!(priority_name(-1), "Low");
    assert_eq!(priority_name(0), "Normal");
    assert_eq!(priority_name(7), "Normal");
    assert_eq!(priority_name(-100), "Normal");
    assert_eq!(priority_name(i32::MIN), "Normal");
}

// ---- job_json / job_from_json ----

fn minimal_job_value() -> Value {
    json!({
        "nzo_id": "n1",
        "name": "A.Release",
        "nzb_path": "/tmp/a.nzb",
        "out_dir": "/out/A.Release",
        "state": "Queued",
    })
}

#[test]
fn job_round_trip_preserves_fields() {
    let v = json!({
        "nzo_id": "n42",
        "name": "Show.S01E02.1080p",
        "nzb_path": "/tmp/show.nzb",
        "origin": "rss",
        "category": "tv",
        "state": "Completed",
        "total_bytes": 123_456u64,
        "out_dir": "/out/Show",
        "fail_message": "boom",
        "fail_detail": "stack",
        "priority": 1,
        "paused": true,
        "retries": 2,
        "dupe_key": "show/s1e2",
        "library": true,
        "fetched": true,
        "downloaded_bytes": 999u64,
        "elapsed_secs": 12.5,
        "finished_unix": 1_700_000_000i64,
        "nzb_sha": "abcd",
        "finalizing": true,
        "deferred": true,
        "defer_reason": "disk",
        "defer_at": 1_700_000_123u64,
        "defer_count": 3,
        "password": "pw",
        "bad_blocks": 4u64,
        "verify_blocks": 10u64,
        "tv_sort": true,
        "smart_rule": "rule",
        "filed": false,
        "filed_suffix": " 1080p",
        "filed_title": " - Pilot",
        "filed_base": "Show - S01E02",
        "password_required": true,
        "eat_volumes_ok": true,
        "zip_packed": true,
        "unpack_blocked_by": "rar5",
        "move_split": "/src/part",
        "archive_shape": "rar",
        "inner_crc": 77u64,
        "identity_name": "Show",
        "identity_imdb": "tt0000001",
        "identity_src": "tmdb",
        "auto_retry_at": 5u64,
        "auto_retry_why": "transport",
        "pp_params": [["k", "v"], ["k2", "v2"]],
        "replaces": "/out/Show.prev",
        "failure_link": "https://x/fail",
        "failure_host": "x",
        "failure_https": true,
        "failure_depth": 2,
        "identify": "Show (2026)",
        "cleaned_files": 5u64,
        "cleaned_par2": 6u64,
        "cleaned_trash": true,
        "whyslow": {"layer": "provider", "detail": "news.example.invalid",
                    "held_secs": 640u64, "total_secs": 900u64},
        "resume_route": {"mapped": false, "restored_bytes": 2_236_500_000u64,
                         "budget_bytes": 970_000_000u64,
                         "widest_slot_bytes": 256_000_000u64,
                         "seatable_bytes": 270_000_000u64},
    });
    let j = job_from_json(&v).expect("parses");
    assert_eq!(j.nzo_id, "n42");
    assert_eq!(j.name, "Show.S01E02.1080p");
    assert_eq!(j.nzb_path, PathBuf::from("/tmp/show.nzb"));
    assert_eq!(j.origin, "rss");
    assert_eq!(j.category, "tv");
    assert_eq!(j.state, JobState::Completed);
    assert_eq!(j.total_bytes, 123_456);
    assert_eq!(j.out_dir, PathBuf::from("/out/Show"));
    assert_eq!(j.fail_message, "boom");
    assert_eq!(j.fail_detail, "stack");
    assert_eq!(j.priority, 1);
    assert!(j.paused);
    assert_eq!(j.retries, 2);
    assert_eq!(j.dupe_key.as_deref(), Some("show/s1e2"));
    assert!(j.library);
    assert!(j.fetched);
    assert_eq!(j.downloaded_bytes, 999);
    assert_eq!(j.elapsed_secs, 12.5);
    assert_eq!(j.finished_unix, Some(1_700_000_000));
    assert_eq!(j.nzb_sha, "abcd");
    assert!(j.finalizing);
    assert!(j.deferred);
    assert_eq!(j.defer_reason, "disk");
    assert_eq!(j.defer_at, 1_700_000_123);
    assert_eq!(j.defer_count, 3);
    assert_eq!(j.password.as_deref(), Some("pw"));
    assert_eq!(j.bad_blocks, Some(4));
    assert_eq!(j.verify_blocks, 10);
    assert!(j.tv_sort);
    assert_eq!(j.smart_rule, "rule");
    assert!(!j.filed);
    assert_eq!(j.filed_suffix.as_deref(), Some(" 1080p"));
    assert_eq!(j.filed_title.as_deref(), Some(" - Pilot"));
    assert_eq!(j.filed_base.as_deref(), Some("Show - S01E02"));
    assert!(j.password_required);
    assert!(j.eat_volumes_ok);
    assert!(j.zip_packed);
    assert_eq!(j.unpack_blocked_by, "rar5");
    assert_eq!(j.move_split, "/src/part");
    assert_eq!(j.archive_shape, "rar");
    assert_eq!(j.inner_crc, 77);
    assert_eq!(j.identity_name, "Show");
    assert_eq!(j.identity_imdb, "tt0000001");
    assert_eq!(j.identity_src, "tmdb");
    assert_eq!(j.auto_retry_at, Some(5));
    assert_eq!(j.auto_retry_why.as_deref(), Some("transport"));
    assert_eq!(
        j.pp_params,
        vec![
            ("k".to_string(), "v".to_string()),
            ("k2".to_string(), "v2".to_string())
        ]
    );
    assert_eq!(j.replaces, Some(PathBuf::from("/out/Show.prev")));
    assert_eq!(j.failure_link, "https://x/fail");
    assert_eq!(j.failure_host, "x");
    assert!(j.failure_https);
    assert_eq!(j.failure_depth, 2);
    assert_eq!(j.identify, "Show (2026)");
    assert_eq!(j.cleaned_files, 5);
    assert_eq!(j.cleaned_par2, 6);
    assert!(j.cleaned_trash);
    let why = j.whyslow.clone().expect("the verdict survives the wire");
    assert_eq!(why.layer, "provider");
    assert_eq!(why.detail, "news.example.invalid");
    assert_eq!((why.held_secs, why.total_secs), (640, 900));
    // TODO 309: and so does the resume route, which is persisted for
    // the same reason - the report is asked for after the fact, often
    // for a history row and often after a restart, by which time the
    // engine's log line about the decision is long gone.
    let route = j.resume_route.expect("the route survives the wire");
    assert!(!route.mapped);
    assert_eq!(route.restored_bytes, 2_236_500_000);
    assert_eq!(route.budget_bytes, 970_000_000);
    assert_eq!(route.widest_slot_bytes, 256_000_000);
    assert_eq!(route.seatable_bytes, 270_000_000);

    // Serialize and parse again: the persisted form is a fixed point.
    let v1 = job_json(&j);
    let j2 = job_from_json(&v1).expect("round-trips");
    assert_eq!(v1, job_json(&j2));
}

/// TODO 207: every record written before the verdict field existed has
/// to read as ABSENT. Not as `unknown` (which is a verdict this surface
/// emits, meaning "the evidence disagreed with itself") and not as
/// `line` (which would tell the reader the download was fine). Same
/// trap as `bad_blocks`, where a stored 0 meant both "verified, nothing
/// bad" and "nothing ever verified this".
#[test]
fn a_record_from_before_the_verdict_field_reads_as_absent() {
    let pre = minimal_job_value();
    assert!(
        pre.get("resume_route").is_none(),
        "the fixture is pre-field"
    );
    let pre_j = job_from_json(&pre).expect("parses");
    assert!(
        pre_j.resume_route.is_none(),
        "TODO 309: no field means no route, and no route means the \
         report says nothing - never that the run took the cheap path"
    );
    assert_eq!(job_json(&pre_j)["resume_route"], Value::Null);
    // `mapped` is the discriminator and has no default: a record
    // carrying figures but no verdict is not a mapped run, it is a
    // record that never had one.
    let mut half = minimal_job_value();
    half["resume_route"] = json!({"restored_bytes": 8_000_000u64});
    assert!(job_from_json(&half).expect("parses").resume_route.is_none());

    assert!(pre.get("whyslow").is_none(), "the fixture is pre-field");
    let j = job_from_json(&pre).expect("parses");
    assert!(j.whyslow.is_none(), "no field means no verdict");
    // ...and it stays absent through a rewrite, so a compaction cannot
    // invent one for it.
    assert_eq!(job_json(&j)["whyslow"], Value::Null);
    assert!(job_from_json(&job_json(&j)).unwrap().whyslow.is_none());

    // The shapes that must ALSO read as absent rather than as a
    // verdict: the honest `unknown` the live core publishes, a layer
    // token from some future build, and a torn record.
    for bad in [
        json!({"layer": "unknown"}),
        json!({"layer": "quantum"}),
        json!({"layer": 7}),
        json!("provider"),
        Value::Null,
    ] {
        let mut v = minimal_job_value();
        v["whyslow"] = bad.clone();
        assert!(
            job_from_json(&v).unwrap().whyslow.is_none(),
            "{bad} must not become a verdict"
        );
    }
}

#[test]
fn job_from_json_missing_required_keys() {
    for key in ["nzo_id", "name", "nzb_path", "out_dir", "state"] {
        let mut v = minimal_job_value();
        v.as_object_mut().unwrap().remove(key);
        assert!(job_from_json(&v).is_none(), "missing {key} must be None");
    }
    assert!(job_from_json(&minimal_job_value()).is_some());
}

#[test]
fn job_from_json_unknown_state_reads_queued() {
    let mut v = minimal_job_value();
    v["state"] = json!("Bananas");
    assert_eq!(job_from_json(&v).unwrap().state, JobState::Queued);
    // A job caught mid-Downloading resumes as Queued too.
    v["state"] = json!("Downloading");
    assert_eq!(job_from_json(&v).unwrap().state, JobState::Queued);
    v["state"] = json!("Failed");
    assert_eq!(job_from_json(&v).unwrap().state, JobState::Failed);
}

#[test]
fn job_from_json_legacy_filed_migration() {
    // No `filed` key: tv_sort plus a season-shaped out_dir means filed.
    let mut v = minimal_job_value();
    v["tv_sort"] = json!(true);
    v["out_dir"] = json!("/lib/Show/Season 01");
    assert!(job_from_json(&v).unwrap().filed);

    // Season dir without tv_sort: not filed.
    let mut v = minimal_job_value();
    v["out_dir"] = json!("/lib/Show/Season 01");
    assert!(!job_from_json(&v).unwrap().filed);

    // tv_sort with a private dir: not filed.
    let mut v = minimal_job_value();
    v["tv_sort"] = json!(true);
    assert!(!job_from_json(&v).unwrap().filed);

    // An explicit `filed` wins over the shape test.
    let mut v = minimal_job_value();
    v["tv_sort"] = json!(true);
    v["out_dir"] = json!("/lib/Show/Season 01");
    v["filed"] = json!(false);
    assert!(!job_from_json(&v).unwrap().filed);
}

#[test]
fn job_from_json_bad_blocks_tri_state() {
    // Non-zero count is a verdict on its own.
    let mut v = minimal_job_value();
    v["bad_blocks"] = json!(3u64);
    assert_eq!(job_from_json(&v).unwrap().bad_blocks, Some(3));

    // Zero with a companion block count: verified clean.
    let mut v = minimal_job_value();
    v["bad_blocks"] = json!(0u64);
    v["verify_blocks"] = json!(10u64);
    assert_eq!(job_from_json(&v).unwrap().bad_blocks, Some(0));

    // Bare zero from a legacy record: unknowable, so not verified.
    let mut v = minimal_job_value();
    v["bad_blocks"] = json!(0u64);
    assert_eq!(job_from_json(&v).unwrap().bad_blocks, None);

    // Zero with a zero block count: same unknowable.
    let mut v = minimal_job_value();
    v["bad_blocks"] = json!(0u64);
    v["verify_blocks"] = json!(0u64);
    assert_eq!(job_from_json(&v).unwrap().bad_blocks, None);

    // Absent entirely.
    assert_eq!(
        job_from_json(&minimal_job_value()).unwrap().bad_blocks,
        None
    );
}

// ---- post_year_of ----

fn nzb_xml(dates: &[i64]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, d) in dates.iter().enumerate() {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"{d}\" subject=\"&quot;f{i}.rar&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"1000\" number=\"1\">id{i}@x</segment>\n    </segments>\n  </file>\n"
        ));
    }
    xml.push_str("</nzb>\n");
    xml
}

#[test]
fn post_year_of_unreadable_path_is_zero() {
    let d = tdir("post-year-missing");
    assert_eq!(post_year_of(&d.join("nope.nzb")), 0);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn post_year_of_uses_newest_file_date() {
    let d = tdir("post-year-newest");
    let p = d.join("a.nzb");
    // 1_000 is 1970; 1_700_000_000 is November 2023. Newest wins.
    std::fs::write(&p, nzb_xml(&[1_000, 1_700_000_000])).unwrap();
    assert_eq!(
        post_year_of(&p),
        crate::identify::year_of_unix(1_700_000_000)
    );
    assert_eq!(post_year_of(&p), 2023);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn post_year_of_non_positive_dates_are_zero() {
    let d = tdir("post-year-zero");
    let p = d.join("a.nzb");
    std::fs::write(&p, nzb_xml(&[0, 0])).unwrap();
    assert_eq!(post_year_of(&p), 0);
    let _ = std::fs::remove_dir_all(&d);
}

// ---- file_count ----

#[test]
fn file_count_missing_dir_is_zero() {
    let d = tdir("file-count-missing");
    assert_eq!(file_count(&d.join("gone")), 0);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn file_count_walks_nested_dirs() {
    let d = tdir("file-count-nested");
    std::fs::write(d.join("a.bin"), b"x").unwrap();
    std::fs::write(d.join("b.bin"), b"x").unwrap();
    let sub = d.join("sub");
    std::fs::create_dir_all(sub.join("deeper")).unwrap();
    std::fs::write(sub.join("c.bin"), b"x").unwrap();
    std::fs::write(sub.join("deeper").join("d.bin"), b"x").unwrap();
    assert_eq!(file_count(&d), 4);
    // An empty subdir adds nothing.
    std::fs::create_dir_all(d.join("empty")).unwrap();
    assert_eq!(file_count(&d), 4);
    let _ = std::fs::remove_dir_all(&d);
}

// ---- same_dir ----

#[test]
fn same_dir_equal_paths_true_even_when_missing() {
    let p = Path::new("/definitely/not/on/disk");
    assert!(same_dir(p, p));
}

#[test]
fn same_dir_distinct_dirs_false() {
    let a = tdir("same-dir-a");
    let b = tdir("same-dir-b");
    assert!(!same_dir(&a, &b));
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
}

#[test]
fn same_dir_missing_path_falls_back_to_false() {
    let a = tdir("same-dir-missing");
    assert!(!same_dir(&a, &a.join("gone")));
    let _ = std::fs::remove_dir_all(&a);
}

#[test]
fn same_dir_dot_component_resolves_equal() {
    let a = tdir("same-dir-dot");
    assert!(same_dir(&a, &a.join(".")));
    let _ = std::fs::remove_dir_all(&a);
}

// ---- settle_locked_failure ----

/// The password ladder awaits two unbounded blocking calls (the
/// encrypted-archive probe, then a KDF per candidate password), and it
/// used to write its verdict back with no recheck at all. A delete verb
/// files the Failed row into history and a Retry of that row re-queues
/// the SAME Arc one generation on, so the ladder's late `Completed`
/// landed on a QUEUED record - a state `pick_job` never picks, so the
/// retry the user pressed never ran and only a second retry cleared it
/// (Codex sweep 3, H2).
///
/// Staged rather than raced: the generation is bumped BEFORE the call,
/// which is the same record the awaits would have handed back.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_unlock_never_settles_a_record_that_was_retried_out_from_under_it() {
    use nzbkit::zip::fixtures::{Encrypt, Spec, zip_of};
    let dir = tdir("settle-locked-gen");
    let d = crate::testutil::test_daemon(&dir);
    let payload: Vec<u8> = (0..2_000u32).map(|i| (i * 7 + 3) as u8).collect();

    // Two identical locked jobs: one the tail still owns, one retried
    // out from under it. A fence that declined everything would pass the
    // stale half alone and stop unlocking every real locked release.
    for (id, retried) in [("nzo-lock-stale", true), ("nzo-lock-live", false)] {
        let out = dir.join(id);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            out.join("payload.zip"),
            zip_of(&[Spec {
                encrypt: Some(Encrypt::ZipCrypto { password: "pw123" }),
                ..Spec::deflated("movie.mkv", &payload)
            }]),
        )
        .unwrap();
        let job = Arc::new(Mutex::new(
            job_from_json(&json!({
                "nzo_id": id,
                "name": id,
                "nzb_path": dir.join("locked.nzb").to_string_lossy(),
                "out_dir": out.to_string_lossy(),
                "state": "Failed",
                "fail_message": "an archive in the output directory could not be unpacked",
            }))
            .unwrap(),
        ));
        d.queue.lock_ok().push_back(job.clone());
        let gen0 = Daemon::record_generation(&job.lock_ok());
        if retried {
            // What a delete-then-Retry leaves behind: the same Arc,
            // queued to run again, one generation on.
            let mut j = job.lock_ok();
            j.retries += 1;
            j.state = JobState::Queued;
            j.fail_message.clear();
        }
        let settled = settle_locked_failure(
            &d,
            &job,
            &out,
            id,
            &dir.join("locked.nzb"),
            "",
            Some("pw123"),
            true,
            Some(gen0),
        )
        .await;
        let g = job.lock_ok();
        if retried {
            assert!(!settled, "a stale ladder must not report a completion");
            assert_eq!(
                g.state,
                JobState::Queued,
                "the stale ladder stamped Completed onto the record the retry queued"
            );
            assert!(
                !g.password_required,
                "and flagged the fresh download as needing a password"
            );
            assert_eq!(g.password, None, "and wrote its password onto it");
        } else {
            assert!(settled, "the round that owns the record still settles it");
            assert_eq!(g.state, JobState::Completed);
            assert_eq!(g.password.as_deref(), Some("pw123"));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- the automatic retry's age gate ----

/// The age gate suppresses the one automatic retry, and a suppressed
/// retry ALSO makes the failure final - the indexer is told the release
/// is dead, the FailureLink re-grab runs, a held duplicate is promoted.
/// It read the age clause alone, and that clause stands down only when
/// EVERY loss was transport. One confirmed 430 among a thousand timeouts
/// therefore looked exactly like an aged dead post, and the run that a
/// journal-resume retry would have finished was written off instead
/// (Codex sweep 3, M8).
#[test]
fn an_aged_post_still_retries_while_the_loss_is_ambiguous() {
    let cooldown = 900;
    let failed = |msg: &str| {
        let mut j = job_from_json(&json!({
            "nzo_id": "nzo-m8",
            "name": "Some.Release",
            "nzb_path": "/spool/x.nzb",
            "out_dir": "/downloads/x",
            "state": "Failed",
        }))
        .unwrap();
        j.fail_message = msg.to_string();
        j
    };
    let census = "download incomplete: 1 file(s) with missing segments, 0 decode/write \
                  errors; 1965 of 4506 segment(s) never arrived (1879 MB did); the post \
                  is 9 day(s) old, well past the minutes-to-hours that propagation takes";

    // Every loss a takedown, every server answering: nothing is coming,
    // and this is the case the suppression exists for.
    let proven = failed(census);
    assert!(!auto_retry_eligible(&proven, cooldown));
    assert_eq!(post_job_plan(&proven, "regrab", cooldown), Some(true));

    // Same age, same census, but the message says where some of the
    // bytes actually went. That is ours to fix, and a retry resumes from
    // the journal and refetches only the gaps.
    let mixed = failed(&format!(
        "{census}; 1900 segment(s) lost to transport/connection errors, not takedowns"
    ));
    assert!(matches!(
        fail_kind(&mixed.fail_message),
        FailKind::MissingArticles
    ));
    assert!(
        auto_retry_eligible(&mixed, cooldown),
        "a transport-dominant loss is not an aged dead post"
    );
    assert_eq!(
        post_job_plan(&mixed, "regrab", cooldown),
        Some(false),
        "and the failure is not final, so nothing is reported or re-grabbed yet"
    );

    // A server that never connected leaves its segments counted as
    // missing without anyone having looked at them.
    let starved = failed(&format!(
        "{census}; no usable connection to news.example.net for the entire run"
    ));
    assert!(auto_retry_eligible(&starved, cooldown));
}

// ---- clear_attempt_verdicts (bug sweep 22 Aug 2026, F-16/F-17) ----

#[test]
fn clear_attempt_verdicts_drops_whyslow_and_postproc_secs() {
    let mut j = job_from_json(&serde_json::json!({
        "nzo_id": "cav1",
        "name": "x",
        "nzb_path": "/spool/cav1.nzb",
        "out_dir": "/dl/cav1",
        "state": "Queued",
    }))
    .expect("job_from_json");
    j.whyslow = Some(WhyVerdict {
        layer: "line".into(),
        detail: String::new(),
        held_secs: 3,
        total_secs: 4,
    });
    j.postproc_secs = 12.5;
    j.fail_detail = "detail".into();
    j.fail_message = "msg".into();
    j.finished_unix = Some(1);
    j.finished_at = Some(std::time::Instant::now());
    j.clear_attempt_verdicts();
    assert!(j.whyslow.is_none());
    assert_eq!(j.postproc_secs, 0.0);
    assert!(j.fail_detail.is_empty());
    assert!(j.finished_unix.is_none() && j.finished_at.is_none());
    // Not the helper's to clear: retry and demote own this one.
    assert_eq!(j.fail_message, "msg");
}
