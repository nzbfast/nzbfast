//! Tests for the spool-stem sanitiser and the origin attribution.
//!
//! Split out of serve/mod.rs's inline `mod spool_naming_tests` by
//! TODO 106 phase 4.

use super::*;
use std::collections::HashMap;

/// The whole point: a spool file you can match to something you saw.
#[test]
fn the_release_name_survives_into_the_filename() {
    assert_eq!(
        safe_spool_stem("Some.Show.S01E02.1080p"),
        "Some.Show.S01E02.1080p"
    );
}

/// This string becomes a filename, so it must not be able to escape
/// the spool directory or hide itself.
#[test]
fn a_hostile_name_cannot_escape_the_spool() {
    for bad in ["../../etc/passwd", "..\\..\\windows", "/abs/path", "a/b/c"] {
        let out = safe_spool_stem(bad);
        assert!(!out.contains('/'), "{bad} -> {out}");
        assert!(!out.contains('\\'), "{bad} -> {out}");
        assert!(!out.contains(".."), "{bad} -> {out}");
        assert!(
            !out.starts_with('.'),
            "{bad} -> {out} would be a hidden file"
        );
    }
    // A name of nothing usable still yields a filename.
    assert_eq!(safe_spool_stem("///"), "job");
    assert_eq!(safe_spool_stem(""), "job");
}

/// A very long release name plus the job id must not approach a path
/// limit.
#[test]
fn long_names_are_capped() {
    let out = safe_spool_stem(&"A".repeat(500));
    assert!(out.chars().count() <= 60, "{} chars", out.chars().count());
}

/// Non-ASCII names are common and must not produce an empty stem.
#[test]
fn non_ascii_names_still_produce_something() {
    let out = safe_spool_stem("Кино.2024.Фильм");
    assert!(!out.is_empty());
    assert!(!out.contains('/'));
}

#[test]
fn arr_adds_are_told_apart_from_dashboard_adds() {
    let mut arr = HashMap::new();
    arr.insert("nzbname".to_string(), "Show.S01E01".to_string());
    assert_eq!(origin_of(&arr), "arr");
    assert_eq!(origin_of(&HashMap::new()), "dashboard");
}

/// The two Sonarr and Radarr strings are the ones a real Sonarr and
/// Radarr actually sent during download-client certification,
/// captured off a live test, not ones we assumed.
#[test]
fn real_clients_name_themselves() {
    for (ua, want) in [
        ("Sonarr/4.0.19.2979 (macos 10.0)", "sonarr"),
        ("Radarr/6.3.0.10514 (macos 10.0)", "radarr"),
        ("Lidarr/2.4.3.4248 (ubuntu 22.04)", "lidarr"),
        ("Readarr/0.4.7.2718 (debian 12)", "readarr"),
        ("Prowlarr/1.21.2.4649 (docker)", "prowlarr"),
        ("nzb360/17.4 (Android 14)", "nzb360"),
        ("LunaSea/10.3.0", "lunasea"),
        ("SABnzbd/4.3.2", "sabnzbd"),
        ("NZBGet/21.1", "nzbget"),
        ("curl/8.7.1", "curl"),
    ] {
        assert_eq!(api_client(ua).as_deref(), Some(want), "{ua}");
    }
}

/// A browser is not an automation - including our own dashboard,
/// whose upload posts to the very same addfile endpoint.
#[test]
fn browsers_and_silence_fall_back() {
    for ua in [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15",
        "",
        "   ",
        "/4.0",
        "Кино/1.0",
    ] {
        assert_eq!(api_client(ua), None, "{ua:?}");
    }
}

/// The UA is attacker-controlled and the token is persisted into
/// queue.json and rendered in the drawer, so nothing that could hurt
/// either may survive classification.
#[test]
fn a_hostile_user_agent_yields_nothing_dangerous() {
    for bad in [
        "../../etc/passwd",
        "..\\..\\windows",
        "<script>alert(1)</script>",
        "a\"; DROP TABLE jobs;--",
        "\u{202e}gnp.exe",
        "Кино.2024.Фильм",
        "\0\0\0",
        "\n\r\tSonarr",
    ] {
        if let Some(tok) = api_client(bad) {
            assert!(
                tok.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{bad:?} -> {tok}"
            );
            assert!(tok.chars().count() <= 24, "{bad:?} -> {tok}");
        }
    }
    // 500 chars of one token must not persist 500 chars.
    let long = api_client(&format!("{}/1.0", "a".repeat(500))).unwrap();
    assert_eq!(long.chars().count(), 24);
    // Nor may a long name smuggle bytes past the cap by hiding them
    // behind characters the filter drops.
    let mixed = api_client(&"a/b".repeat(200)).unwrap();
    assert_eq!(mixed, "a");
}

/// Old records and unidentified callers keep today's behaviour: the
/// fallback is used verbatim, so nothing needs a queue.json migration.
#[test]
fn the_fallback_is_untouched_when_nobody_names_themselves() {
    assert_eq!(
        api_origin("Sonarr/4.0.19.2979 (macos 10.0)", "dashboard"),
        "arr:sonarr"
    );
    assert_eq!(
        api_origin("Mozilla/5.0 (X11; Linux x86_64)", "dashboard"),
        "dashboard"
    );
    assert_eq!(api_origin("", "arr"), "arr");
    assert_eq!(api_origin("nzb360/17.4 (Android 14)", "arr"), "arr:nzb360");
}

// ---- watchlist provenance (TODO 44's follow-up) ------------------------

/// The shape the dashboard parses: three `|`-separated fields, in the
/// order slot, quality, title.
#[test]
fn a_watchlist_origin_carries_slot_quality_and_item() {
    assert_eq!(
        watchlist_origin("s01e02", "1080p WEB", "Breaking Bad"),
        "watchlist:s01e02|1080p WEB|Breaking Bad"
    );
    // Every other slot shape the watcher can produce rides the same
    // field, unaltered - the dashboard is what decides which of them is
    // worth showing a person.
    assert_eq!(
        watchlist_origin("movie", "2160p REMUX", "Blade Runner 2049"),
        "watchlist:movie|2160p REMUX|Blade Runner 2049"
    );
    assert_eq!(
        watchlist_origin("d:20260721", "", "The Daily Show"),
        "watchlist:d:20260721||The Daily Show"
    );
}

/// An item with nothing to say reads exactly as it did before the
/// detail existed, rather than as `watchlist:||`.
#[test]
fn an_empty_detail_falls_back_to_the_bare_token() {
    assert_eq!(watchlist_origin("", "", ""), "watchlist");
    // Whitespace-only is empty too, or a blank title would leave a
    // trailing space nobody can see and the fallback would not fire.
    assert_eq!(watchlist_origin("  ", "\t", " "), "watchlist");
}

/// The title comes from the user's watchlist, or from a Plex/Trakt sync,
/// and is persisted and rendered - so the separator and the control
/// characters are stripped HERE, where the string is built, exactly as
/// `api_client` sanitises a user-agent at the point of classification.
#[test]
fn the_detail_fields_cannot_forge_a_separator_or_run_long() {
    let o = watchlist_origin("s01", "720p", "A|B");
    assert_eq!(o, "watchlist:s01|720p|AB");
    assert_eq!(o.split('|').count(), 3, "still exactly three fields: {o}");

    let o = watchlist_origin("s01", "720p", "line\nbreak\u{7}");
    assert_eq!(o, "watchlist:s01|720p|linebreak");

    // Per FIELD, not per string: a long title must not push the slot
    // and the quality out of the record.
    let o = watchlist_origin("s01e02", "1080p", &"x".repeat(500));
    let f: Vec<&str> = o.strip_prefix("watchlist:").unwrap().split('|').collect();
    assert_eq!(f[0], "s01e02");
    assert_eq!(f[1], "1080p");
    assert_eq!(f[2].chars().count(), 60);
}

/// Both spellings, or the give-up breaker stops arming for every grab
/// made after the detail landed - and a breaker that never arms reads
/// exactly like one that never had cause to.
#[test]
fn both_watchlist_spellings_answer_yes() {
    assert!(is_watchlist_origin("watchlist"));
    assert!(is_watchlist_origin("watchlist:s01e02|1080p|Breaking Bad"));
    assert!(is_watchlist_origin(&watchlist_origin(
        "movie", "2160p", "Dune"
    )));
    assert!(!is_watchlist_origin("watch"));
    assert!(!is_watchlist_origin("rss:https://example.com/feed"));
    // Not a prefix match on the bare word: `watchlisted` is not ours.
    assert!(!is_watchlist_origin("watchlisted"));
}
