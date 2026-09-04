//! §163 item 5. Every assertion here is about what does NOT come out of
//! the log door: this is the tail a user pastes into a GitHub issue, and
//! v1.2.1 shipped a provider hostname in a public artifact because
//! nothing scrubbed it on the way out.

use super::*;
use crate::testutil::test_daemon;

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-logscrub-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A daemon whose config names two providers, plus an indexer key and
/// the daemon's own API key.
fn seeded(dir: &std::path::Path) -> std::sync::Arc<Daemon> {
    let d = test_daemon(dir);
    std::fs::write(
        &d.cfg_path,
        r#"{"servers":[
             {"host":"news.example.com","username":"someuser",
              "password":"hunter2hunter2"},
             {"host":"eu.example.net","username":"anotheruser",
              "password":"correcthorse"}
           ]}"#,
    )
    .unwrap();
    *d.indexers.lock_ok() = vec![crate::newznab::IndexerConfig {
        kind: Default::default(),
        nzbindex: Default::default(),
        name: "idx".into(),
        url: "https://indexer.example/api".into(),
        // A made-up key, only ever compared against a made-up log line.
        apikey: "IDXKEY1234567890".into(), // leakcheck-allow-synthetic
        enabled: true,
        priority: 0,
        hits_per_day: 0,
        grabs_per_day: 0,
    }];
    *d.apikey.lock_ok() = Some("DAEMONAPIKEY0001".to_string());
    d
}

#[test]
fn the_log_door_anonymises_providers_and_blanks_secrets() {
    let dir = scratch("all");
    let d = seeded(&dir);
    let s = LogScrub::new(&d);

    // Hostnames become stable NUMBERED placeholders, not one shared
    // `***`: "server2 timed out" is the sentence the issue is about, and
    // three servers blanked identically make it unanswerable.
    let got = s.line("[pool] news.example.com: 40/60 sockets, eu.example.net idle");
    assert_eq!(
        got, "[pool] <server1>: 40/60 sockets, <server2> idle",
        "hosts must be distinguishable after scrubbing"
    );
    // Case-blind, because DNS is: a certificate error or a provider
    // banner spells the host back in whatever case it likes.
    assert_eq!(s.line("cert for News.Example.COM"), "cert for <server1>");
    // Usernames are identities too, and numbered with their server.
    assert_eq!(
        s.line("AUTHINFO USER someuser failed"),
        "AUTHINFO USER <user1> failed"
    );
    // Passwords keep no identity worth preserving.
    assert_eq!(s.line("pass=hunter2hunter2 rejected"), "pass=*** rejected");
    // Indexer keys and our own API key, wherever they appear - not just
    // in a URL, which is all `redact_apikey` can see.
    assert!(
        !s.line("grab failed for key IDXKEY1234567890")
            .contains("IDXKEY")
    );
    assert!(
        !s.line("client sent DAEMONAPIKEY0001")
            .contains("DAEMONAPIKEY")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The two existing helpers still run, first, so a credential spelled in
/// a shape no literal here knows about is cut anyway - the whole reason
/// `redact_url_creds` exists is that indexers spell their key `r`, `i`,
/// `api_key` or put it in the path.
#[test]
fn the_url_passes_run_before_the_literals() {
    let dir = scratch("url");
    let d = seeded(&dir);
    let s = LogScrub::new(&d);
    assert!(
        !s.line("fetch https://idx.example/nzb?r=UNKNOWNSPELLING")
            .contains("UNKNOWNSPELLING"),
        "an unrecognised credential spelling must still go"
    );
    assert!(
        !s.line("GET https://a/x?apikey=SECRETVALUE")
            .contains("SECRETVALUE"),
        "the apikey pass still runs"
    );
    // And a host that SURVIVES redact_url_creds (which keeps
    // scheme://host:port on purpose, because it names who failed) is
    // still anonymised by the pass that knows it is a provider.
    assert_eq!(
        s.line("connect nntps://news.example.com:563/ refused"),
        "connect nntps://<server1>:563/... refused"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Short strings are left alone. A daemon with no API key set, or a
/// provider with a two-character username, must not turn every log line
/// into asterisks - a scrub that redacts ordinary prose gets switched
/// off, which is the failure mode that leaves nothing scrubbed at all.
#[test]
fn a_short_or_absent_secret_redacts_nothing() {
    let dir = scratch("short");
    let d = test_daemon(&dir);
    std::fs::write(
        &d.cfg_path,
        r#"{"servers":[{"host":"nl","username":"me","password":"pw"}]}"#,
    )
    .unwrap();
    assert!(d.apikey.lock_ok().is_none(), "no key by default");
    let s = LogScrub::new(&d);
    let line = "[get] me and pw and nl are ordinary words here";
    assert_eq!(s.line(line), line);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tail is scrubbed line by line, and an ordinary line comes through
/// untouched - the pane has to stay readable or nobody will use it to
/// answer anything.
#[test]
fn an_ordinary_line_is_unchanged() {
    let dir = scratch("plain");
    let d = seeded(&dir);
    let s = LogScrub::new(&d);
    let tail = vec![
        "[extract] native unpack complete".to_string(),
        "[get] news.example.com stalled".to_string(),
    ];
    assert_eq!(
        s.tail(tail),
        vec![
            "[extract] native unpack complete".to_string(),
            "[get] <server1> stalled".to_string(),
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A notification target's credential never leaves the door.
///
/// `Target::token` is one field holding eleven different secrets - a
/// Plex token, a Jellyfin/Emby API key, a Telegram `<bot_token>/<chat
/// id>`, a Pushover pair, an ntfy or Gotify token, a Kodi or SMTP
/// `user:password` - and `Target::secret` is the webhook HMAC key. Both
/// are write-only in `get_config`, and until 23 Aug 2026 neither was in
/// this list at all: the only thing between a rejected delivery and the
/// ring was `notify.rs` scrubbing its own errors, per call site, by
/// hand.
#[test]
fn a_notification_targets_secrets_never_leave_the_door() {
    let dir = scratch("notify");
    let d = seeded(&dir);
    *d.notify_targets.lock_ok() = vec![
        serde_json::from_str(
            r#"{"kind":"plex","url":"http://10.0.0.5:32400",
                "token":"PLEXTOKEN0000001"}"#, // leakcheck-allow-synthetic
        )
        .unwrap(),
        serde_json::from_str(
            r#"{"kind":"webhook","url":"http://10.0.0.6/hook",
                "secret":"HMACKEY000000001"}"#, // leakcheck-allow-synthetic
        )
        .unwrap(),
    ];
    let s = LogScrub::new(&d);
    assert!(
        !s.line("notify: plex refused token PLEXTOKEN0000001")
            .contains("PLEXTOKEN"),
        "a target token is a credential wherever it is spelled"
    );
    assert!(
        !s.line("notify: signed with HMACKEY000000001")
            .contains("HMACKEY"),
        "the webhook HMAC key is a credential too"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The metadata keys, both of them.
///
/// `omdb_key` was in this list from the start and `tmdb_key` - its exact
/// sibling, a live key the user pastes into the same settings page - was
/// not, for no reason anyone recorded. Pinned as a pair so the next key
/// added beside them is noticed.
#[test]
fn both_metadata_keys_leave_blanked() {
    let dir = scratch("meta");
    let d = seeded(&dir);
    *d.omdb_key.lock_ok() = Some("OMDBKEY000000001".to_string()); // leakcheck-allow-synthetic
    *d.tmdb_key.lock_ok() = Some("TMDBKEY000000001".to_string()); // leakcheck-allow-synthetic
    let s = LogScrub::new(&d);
    assert!(
        !s.line("omdb: OMDBKEY000000001 rejected")
            .contains("OMDBKEY")
    );
    assert!(
        !s.line("tmdb: TMDBKEY000000001 rejected")
            .contains("TMDBKEY")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The per-install stream secret, which nothing deliberately prints.
///
/// That is the argument for the backstop knowing it rather than against:
/// one leak forges a `/stream/{id}?t=` token for every job this install
/// will ever have, and the .strm files in a library are advertised as
/// permanent.
#[test]
fn the_stream_secret_never_leaves_the_door() {
    let dir = scratch("streamsecret");
    // Seeded before the daemon is built: `seed_stream_secret` reads
    // settings.json and only mints a fresh one when it finds nothing.
    std::fs::write(
        dir.join("settings.json"),
        r#"{"stream_secret":"STREAMSECRET0001"}"#, // leakcheck-allow-synthetic
    )
    .unwrap();
    let d = test_daemon(&dir);
    assert_eq!(d.stream_secret, "STREAMSECRET0001");
    let s = LogScrub::new(&d);
    assert!(
        !s.line("mint: STREAMSECRET0001")
            .contains("STREAMSECRET0001")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The url pass is WIDE on purpose, and this is the case that pays for
/// it: for `Discord`, `Slack`, `Webhook` and `Apprise` targets the URL's
/// PATH is the credential, so a pass that kept paths would hand the
/// token straight out of the door.
///
/// A narrower export pass - strip userinfo and the query, keep scheme,
/// host, port and path - was costed on 23 Aug 2026 and declined; the
/// reasoning is on `LogScrub::line` and in TODO §163 item 5. This test
/// is the half of that decision a future session can run: it fails the
/// moment the path comes back.
#[test]
fn a_path_borne_credential_leaves_with_its_path_gone() {
    let dir = scratch("pathcred");
    let d = seeded(&dir);
    let s = LogScrub::new(&d);
    // A Discord incoming webhook, whose last path segment IS the bearer.
    let got = s.line("notify: POST https://discord.example/api/webhooks/12345/PATHTOKEN failed");
    assert!(!got.contains("PATHTOKEN"), "{got}");
    assert!(
        !got.contains("webhooks"),
        "the path names the shape too: {got}"
    );
    // An Apprise endpoint, whose config key is the path.
    assert!(
        !s.line("notify: http://10.0.0.7:8000/notify/APPRISECONFIGKEY refused")
            .contains("APPRISECONFIGKEY")
    );
    // And userinfo and the query, which a narrower pass would also cut -
    // asserted here so this test pins the WHOLE contract, not just the
    // part that distinguishes the two policies.
    let both = s.line("GET https://u:pw@idx.example/api?r=QUERYSECRET");
    assert!(
        !both.contains("pw@") && !both.contains("QUERYSECRET"),
        "{both}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
