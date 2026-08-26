//! TODO 297: the nzbindex adapter.
//!
//! The fixtures are the REAL responses, captured live on 26 Aug 2026
//! and trimmed to a few rows - not hand-written approximations of what
//! the docs say. That distinction earned its keep during the build: the
//! docs describe `/api/collection/<id>` as retrieving a collection and
//! it does, but it retrieves the RECORD and not the NZB, and the actual
//! download path needs a `.nzb` suffix that nothing in TODO 297 named.

use super::*;
use crate::newznab::{IndexerConfig, NzbIndexOpts, SearchQuery, SourceKind};

/// A real `/api/search` answer, three rows, captured 26 Aug 2026.
/// Deliberately keeps the obfuscated first row: that IS what this
/// source mostly returns, and a fixture of tidy release names would
/// test a site we are not talking to.
const SEARCH_JSON: &str = r#"{"data":{"content":[
{"id":"e5c7eed3-02ee-370e-8743-1e92c6a44204","name":"82339611-n-NqU \"hdue0sg1cvk\" yEnc  49581528","poster":"Zohl@WoPO.Sju","posted":1786867775,"size":50827878,"fileCount":1,"complete":true,"groups":["alt.binaries.boneless"]},
{"id":"f2dcc169-b483-33c4-bce7-95e48e11d2ac","name":"Kubuntu 11.04 Desktop i386 [02/18] - \"kubuntu-11.04-desktop-i386.part1.rar\" yEnc","poster":"News@Newsconnection.local","posted":1786284775,"size":291227883,"fileCount":8,"complete":false,"groups":["alt.binaries.boneless"]},
{"id":"1bb5c75d-43f3-337e-bfe0-abd79aa90034","name":"[AusGamers] Ubuntu v10.04 Beta 1 - File 01 of 27 yEnc","poster":"trog","posted":1786033010,"size":221216911,"fileCount":15,"complete":false,"groups":["alt.binaries.cd.image.linux"]}
],"page":{"size":3,"number":0,"totalElements":154,"totalPages":52}},"error":false,"errorMessage":""}"#;

fn cfg() -> IndexerConfig {
    IndexerConfig {
        name: "nzbindex".into(),
        url: "https://nzbindex.com".into(),
        kind: SourceKind::Nzbindex,
        nzbindex: NzbIndexOpts::default(),
        apikey: String::new(),
        enabled: true,
        priority: 0,
        hits_per_day: 0,
        grabs_per_day: 0,
    }
}

fn q(text: &str) -> SearchQuery {
    SearchQuery {
        q: text.into(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------- urls

#[test]
fn the_search_url_is_the_documented_endpoint_and_parameters() {
    let u = search_url(&cfg(), &q("ubuntu 24.04"));
    assert!(
        u.starts_with("https://nzbindex.com/api/search?q="),
        "endpoint(): {u}"
    );
    assert!(u.contains("q=ubuntu%2024.04"), "query not encoded: {u}");
    assert!(u.contains(&format!("max={DEFAULT_MAX}")), "no max: {u}");
    assert!(u.contains("sort=agedesc"), "no sort: {u}");
}

/// The one that would have shipped broken. `/api/download/<id>` 307s to
/// itself and answers 404; only the `.nzb` spelling returns an NZB.
#[test]
fn the_download_url_carries_the_load_bearing_nzb_suffix() {
    let u = download_url(&cfg(), "e5c7eed3-02ee-370e-8743-1e92c6a44204");
    assert_eq!(
        u, "https://nzbindex.com/api/download/e5c7eed3-02ee-370e-8743-1e92c6a44204.nzb",
        "the .nzb suffix is required - without it the API 404s"
    );
}

/// A site root, a trailing slash and a full endpoint must all land on
/// the same place: `endpoint()` is shared with the Newznab client and
/// people paste all three.
#[test]
fn the_endpoint_is_reached_however_the_user_spelled_the_url() {
    for spelling in [
        "https://nzbindex.com",
        "https://nzbindex.com/",
        "https://nzbindex.com/api",
        "https://nzbindex.com/api/",
    ] {
        let c = IndexerConfig {
            url: spelling.into(),
            ..cfg()
        };
        assert!(
            search_url(&c, &q("x")).starts_with("https://nzbindex.com/api/search?"),
            "{spelling}"
        );
        assert!(
            download_url(&c, "id").starts_with("https://nzbindex.com/api/download/"),
            "{spelling}"
        );
    }
}

#[test]
fn the_key_is_sent_when_there_is_one_and_omitted_when_there_is_not() {
    assert!(
        !search_url(&cfg(), &q("x")).contains("key="),
        "a blank key must not be sent - this API answers without one"
    );
    let c = IndexerConfig {
        apikey: "  s3cret/key  ".into(),
        ..cfg()
    };
    // Trimmed and percent-encoded, on every URL that reaches them.
    assert!(search_url(&c, &q("x")).contains("&key=s3cret%2Fkey"));
    assert!(download_url(&c, "id").contains("&key=s3cret%2Fkey"));
    assert!(probe_url(&c).contains("&key=s3cret%2Fkey"));
}

/// The raw-subject wariness, as shipped: complete-only is ON unless the
/// user turns it off.
#[test]
fn complete_only_is_the_default_and_is_a_setting() {
    assert!(
        search_url(&cfg(), &q("x")).contains("complete=1"),
        "an unfiltered nzbindex query lists collections that can never finish"
    );
    let c = IndexerConfig {
        nzbindex: NzbIndexOpts {
            complete_only: false,
            ..Default::default()
        },
        ..cfg()
    };
    assert!(!search_url(&c, &q("x")).contains("complete="));
}

/// Sizes are MEGABYTES and ages are DAYS - the one place in this
/// codebase where a size is not bytes. A unit slip here is a filter
/// that silently matches nothing.
#[test]
fn sizes_are_megabytes_and_ages_are_days_and_zero_means_unset() {
    let c = IndexerConfig {
        nzbindex: NzbIndexOpts {
            min_size_mb: 350,
            max_size_mb: 900,
            min_age_days: 3,
            max_age_days: 5,
            ..Default::default()
        },
        ..cfg()
    };
    let u = search_url(&c, &q("x"));
    for want in ["minsize=350", "maxsize=900", "minage=3", "maxage=5"] {
        assert!(u.contains(want), "{want} missing from {u}");
    }
    // All four default to 0, which is "no bound" and must send nothing:
    // `minsize=0` would be a filter where the user asked for none.
    let plain = search_url(&cfg(), &q("x"));
    for never in ["minsize", "maxsize", "minage", "maxage"] {
        assert!(!plain.contains(never), "{never} sent unset in {plain}");
    }
}

/// Their docs spell a group list `groups=one&groups=two`, repeated -
/// NOT comma-joined the way Newznab's `cat=` is.
#[test]
fn groups_repeat_the_parameter() {
    let c = IndexerConfig {
        nzbindex: NzbIndexOpts {
            groups: vec!["alt.binaries.boneless".into(), "alt.binaries.test".into()],
            ..Default::default()
        },
        ..cfg()
    };
    let u = search_url(&c, &q("x"));
    assert!(u.contains("&groups=alt.binaries.boneless"), "{u}");
    assert!(u.contains("&groups=alt.binaries.test"), "{u}");
    assert_eq!(u.matches("&groups=").count(), 2, "{u}");
}

/// The three deliberate losses. Each is because the far end has no such
/// concept - and each would be a silently wrong search if it were sent
/// anyway or if the caller's intent were dropped instead of folded.
#[test]
fn categories_and_ids_are_dropped_and_the_episode_folds_into_the_text() {
    let query = SearchQuery {
        q: "The Show".into(),
        // A Newznab caller's category filter: nzbindex has no category
        // space, so this must not become a parameter.
        cats: vec![5000],
        imdbid: "tt0110912".into(),
        tvdbid: "12345".into(),
        season: Some(1),
        ep: Some(2),
        ..Default::default()
    };
    let u = search_url(&cfg(), &query);
    for never in ["cat=", "imdbid", "tvdbid", "tt0110912", "12345"] {
        assert!(!u.contains(never), "{never} leaked into {u}");
    }
    // The episode is not lost, it moves into the text - which is what a
    // scene name carries anyway, and what `plan_query` does when a
    // Newznab indexer's caps cannot take the fields either.
    assert!(u.contains("q=The%20Show%20s01e02"), "{u}");
    // Season alone still narrows.
    let s_only = search_url(
        &cfg(),
        &SearchQuery {
            season: Some(3),
            ep: None,
            ..q("The Show")
        },
    );
    assert!(s_only.contains("q=The%20Show%20s03"), "{s_only}");
}

#[test]
fn an_offset_becomes_the_page_that_contains_it() {
    let paged = |limit: u32, offset: u32| {
        search_url(
            &cfg(),
            &SearchQuery {
                limit,
                offset,
                ..q("x")
            },
        )
    };
    assert!(!paged(100, 0).contains("page="), "page 0 need not be sent");
    assert!(paged(100, 200).contains("&page=2"));
    // Not a whole number of pages: land on the page CONTAINING the
    // offset rather than silently on page 0.
    assert!(paged(100, 250).contains("&page=2"));
}

// -------------------------------------------------------------- parse

#[test]
fn a_real_response_parses_into_result_rows() {
    let out = parse_results(SEARCH_JSON, &cfg()).expect("the real fixture must parse");
    assert_eq!(out.len(), 3);
    let first = &out[0];
    assert_eq!(first.title, "82339611-n-NqU \"hdue0sg1cvk\" yEnc  49581528");
    assert_eq!(first.guid, "e5c7eed3-02ee-370e-8743-1e92c6a44204");
    assert_eq!(first.size, 50_827_878, "their size is bytes");
    assert_eq!(first.posted, 1_786_867_775);
    // The link is the download URL built from the id: that is how the
    // existing grab path fetches an nzbindex row with no idea it is one.
    assert_eq!(
        first.link,
        "https://nzbindex.com/api/download/e5c7eed3-02ee-370e-8743-1e92c6a44204.nzb"
    );
    // No category space and no grab counter in this API. 0 is what the
    // Newznab parser leaves for an absent attr, so every downstream
    // reader already handles it.
    assert_eq!(first.cat, 0);
    assert_eq!(first.grabs, 0);
}

/// The one empty answer that is NOT an error: the API saying it has
/// nothing. This is the case the strictness below must not swallow.
#[test]
fn an_empty_content_array_is_no_matches_and_not_an_error() {
    let body = r#"{"data":{"content":[],"page":{"size":0,"number":0,
                   "totalElements":0,"totalPages":0}},"error":false,"errorMessage":""}"#;
    assert_eq!(parse_results(body, &cfg()).unwrap().len(), 0);
}

/// THE POINT OF THE STRICT PARSER. A hardcoded third-party schema will
/// move, and when it does the source has to say it is broken rather
/// than look like it found nothing. Every one of these would be an
/// empty `Ok(vec![])` under a tolerant parser - which is
/// indistinguishable, in the dashboard, from "nothing matched".
#[test]
fn a_schema_that_moved_is_reported_as_broken_and_never_as_no_matches() {
    let broken = [
        // Not JSON at all: a captive portal, a WAF block page, an
        // outage page, or their API moved to a path that serves HTML.
        ("<html>503 Service Unavailable</html>", "not JSON"),
        // `data` renamed or gone.
        (r#"{"results":[],"error":false}"#, "data gone"),
        // `content` renamed - the shape an API rename actually takes.
        (r#"{"data":{"items":[]},"error":false}"#, "content renamed"),
        // `content` present but not an array.
        (
            r#"{"data":{"content":{}},"error":false}"#,
            "content not a list",
        ),
        // The subtle one, and the only one a ROW-tolerant parser would
        // swallow: rows arrive, and none of them carries the fields we
        // need. This is exactly what `id` -> `collectionId` produces.
        (
            r#"{"data":{"content":[{"collectionId":"a","name":"x"},
                {"collectionId":"b","name":"y"}]},"error":false}"#,
            "id renamed",
        ),
        // ...and the same with the name gone.
        (
            r#"{"data":{"content":[{"id":"a","subject":"x"}]},"error":false}"#,
            "name renamed",
        ),
        // A row whose id is present but blank is no more fetchable than
        // one with no id at all.
        (
            r#"{"data":{"content":[{"id":"  ","name":"x"}]},"error":false}"#,
            "blank id",
        ),
    ];
    for (body, what) in broken {
        let e = parse_results(body, &cfg())
            .expect_err(&format!("{what}: a moved schema must be an error"));
        let msg = e.to_string();
        assert!(
            msg.contains("nzbindex"),
            "{what}: the message must name the source, got {msg}"
        );
        // The user has to be able to tell this from "no results", so the
        // message says what is actually wrong.
        assert!(
            msg.contains("changed") || msg.contains("not JSON"),
            "{what}: the message must say the API moved, got {msg}"
        );
    }
}

/// Their own error channel arrives as HTTP 200 the way Newznab's does,
/// so it is read before anything else - and a rate refusal has to map
/// to `Limit` or the per-entry backoff never engages.
#[test]
fn the_api_error_channel_maps_onto_the_shared_error_space() {
    use crate::newznab::NewznabError as E;
    let body = |msg: &str| format!(r#"{{"data":null,"error":true,"errorMessage":"{msg}"}}"#);
    assert!(matches!(
        parse_results(&body("Rate limit exceeded"), &cfg()),
        Err(E::Limit(..))
    ));
    assert!(matches!(
        parse_results(&body("too many requests"), &cfg()),
        Err(E::Limit(..))
    ));
    assert!(matches!(
        parse_results(&body("invalid api key"), &cfg()),
        Err(E::Auth(..))
    ));
    assert!(matches!(
        parse_results(&body("something else broke"), &cfg()),
        Err(E::Api(..))
    ));
    // `error: true` with nothing said is still an error, not a silent
    // empty list.
    let e = parse_results(r#"{"data":null,"error":true,"errorMessage":""}"#, &cfg())
        .expect_err("error:true must fail");
    assert!(e.to_string().contains("did not say what"), "{e}");
    // ...and `error: false` never fires it.
    assert!(parse_error(&serde_json::json!({"error": false})).is_none());
    assert!(parse_error(&serde_json::json!({})).is_none());
}

/// A row missing an OPTIONAL field is a usable row: only id and name
/// are required, because those are the two that decide whether a result
/// can be named and fetched.
#[test]
fn optional_fields_default_rather_than_dropping_the_row() {
    let body = r#"{"data":{"content":[{"id":"abc","name":"A Release"}]},"error":false}"#;
    let out = parse_results(body, &cfg()).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].size, 0);
    assert_eq!(out[0].posted, 0);
    assert_eq!(out[0].guid, "abc");
}

// ------------------------------------------------------------- config

/// An `indexers` setting saved before TODO 297 has no `kind` and no
/// `nzbindex` object. It must load as the Newznab entry it has always
/// been - this is the compatibility hinge for every existing install.
#[test]
fn an_entry_saved_before_this_landed_loads_as_newznab() {
    let old = r#"[{"name":"geek","url":"https://api.nzbgeek.info","apikey":"k",
                   "enabled":true,"priority":0,"hits_per_day":100,"grabs_per_day":10}]"#;
    let list: Vec<IndexerConfig> = serde_json::from_str(old).expect("the old shape must load");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].kind, SourceKind::Newznab);
    // ...and the nzbindex defaults come with it, inert.
    assert!(list[0].nzbindex.complete_only);
    assert_eq!(list[0].nzbindex.min_size_mb, 0);
}

/// The wire spelling of the kind, which the dashboard and the settings
/// JSON both use. Pinned because a rename would silently turn every
/// saved nzbindex entry back into a Newznab one.
#[test]
fn the_kind_round_trips_through_its_wire_spelling() {
    assert_eq!(SourceKind::Newznab.as_str(), "newznab");
    assert_eq!(SourceKind::Nzbindex.as_str(), "nzbindex");
    let c: IndexerConfig = serde_json::from_str(
        r#"{"name":"n","url":"https://nzbindex.com","kind":"nzbindex",
            "nzbindex":{"complete_only":false,"min_size_mb":50}}"#,
    )
    .expect("the new shape must load");
    assert_eq!(c.kind, SourceKind::Nzbindex);
    assert!(!c.nzbindex.complete_only);
    assert_eq!(c.nzbindex.min_size_mb, 50);
    // A partial `nzbindex` object keeps the DEFAULT for what it omits -
    // so a saved entry that predates a new knob does not get 0 for it.
    assert_eq!(c.nzbindex.max_size_mb, 0);
    let back = serde_json::to_string(&c).unwrap();
    assert!(back.contains(r#""kind":"nzbindex""#), "{back}");
}

/// The two kinds at one host are two far ends: caps and limit backoffs
/// are keyed on this, and "what can this source do" is a different
/// answer per protocol.
#[test]
fn the_identity_separates_the_two_kinds_at_one_host() {
    let n = IndexerConfig {
        kind: SourceKind::Newznab,
        ..cfg()
    };
    assert_ne!(n.identity(), cfg().identity());
}
