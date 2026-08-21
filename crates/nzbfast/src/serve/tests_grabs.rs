//! serve tests: grabs and the surfaces around them - failure links,
//! regrabs, the settings dashboard, and the update manifest.//!
//! Split out of serve/mod.rs's inline `mod tests` by TODO 106 phase 4;
//! attached to serve as a sibling child module, so `super` still means
//! `serve` exactly as it did inline.

use super::tests_jobs::{job, no_causes};
use super::*;

/// BUG (MEDIUM-HIGH, SSRF): the failure link arrives in a RESPONSE
/// HEADER from whatever server answered the NZB fetch, and the daemon
/// then GETs it with an SSRF guard that deliberately permits loopback
/// and RFC1918 (LAN indexers are the normal case). It may only point
/// back at the host that supplied it.
#[test]
fn a_failure_link_may_only_point_back_at_its_own_indexer() {
    // Same host, different port and path: still the same indexer.
    assert!(failure_link_allowed(
        "http://indexer.example:9118/fail?id=1",
        "indexer.example",
        false
    ));
    assert!(failure_link_allowed(
        "https://Indexer.Example/report",
        "indexer.example",
        false
    ));
    // LAN and loopback indexers keep working.
    assert!(failure_link_allowed(
        "http://127.0.0.1:9117/api?t=failure",
        "127.0.0.1",
        false
    ));
    assert!(failure_link_allowed(
        "http://192.168.1.40:8080/x",
        "192.168.1.40",
        false
    ));
    // Anywhere else is refused - including the classic SSRF targets.
    assert!(!failure_link_allowed(
        "http://127.0.0.1:8989/api/v3/command",
        "indexer.example",
        false
    ));
    assert!(!failure_link_allowed(
        "http://169.254.169.254/latest/meta-data/",
        "indexer.example",
        false
    ));
    assert!(!failure_link_allowed(
        "http://evil.example/x",
        "indexer.example",
        false
    ));
    // Userinfo cannot fake the host, and the LAST '@' wins so a
    // password containing '@' cannot smuggle one in either.
    assert!(!failure_link_allowed(
        "http://indexer.example@127.0.0.1/x",
        "indexer.example",
        false
    ));
    assert!(!failure_link_allowed(
        "http://u:p@a@127.0.0.1/x",
        "indexer.example",
        false
    ));
    // A job with no recorded origin (uploaded NZB, or a record from
    // before the field existed) reports nowhere.
    assert!(!failure_link_allowed(
        "http://indexer.example/fail",
        "",
        false
    ));
    // Non-http schemes and junk are not links at all.
    assert!(!failure_link_allowed(
        "file:///etc/passwd",
        "indexer.example",
        false
    ));
    assert!(!failure_link_allowed("", "", false));
}

/// BUG (LOW): host equality alone let an indexer reached over TLS hand
/// back an http link for the same host. The report GET carries the
/// user's indexer apikey in its query string, so that is a downgrade
/// of a relationship they had encrypted, chosen by the far end.
#[test]
fn a_failure_link_may_not_downgrade_https_to_http() {
    assert!(!failure_link_allowed(
        "http://indexer.example/fail",
        "indexer.example",
        true
    ));
    assert!(failure_link_allowed(
        "https://indexer.example/fail",
        "indexer.example",
        true
    ));
    // Scheme match is case-insensitive, as schemes are.
    assert!(failure_link_allowed(
        "HTTPS://indexer.example/fail",
        "indexer.example",
        true
    ));
    // Junk with a multi-byte character where the scheme should be:
    // refused, and without panicking on a str slice mid-character.
    assert!(!failure_link_allowed(
        "ht°ps://indexer.example/x",
        "indexer.example",
        true
    ));
    assert!(!failure_link_allowed("é", "indexer.example", true));
    // An http origin is not upgraded-only: it may hand back either.
    assert!(failure_link_allowed(
        "http://indexer.example/fail",
        "indexer.example",
        false
    ));
    assert!(failure_link_allowed(
        "https://indexer.example/fail",
        "indexer.example",
        false
    ));
}

/// BUG (MEDIUM): a transient failure is parked with an M32 automatic
/// retry armed - and was ALSO reported to the indexer as a dead post,
/// re-grabbed, and used to promote the held M14f duplicate. One
/// missing-article gap therefore put three grabs of the same title on
/// the user's block account, and told the indexer a live release was
/// dead over a gap propagation was expected to fill.
///
/// The retry decision has to be answerable BEFORE the hooks run:
/// `park` arms `auto_retry_at` after `run_post_job_hooks` has already
/// spawned, so a guard that reads the field is a race.
#[test]
fn a_failure_awaiting_its_automatic_retry_is_not_reported_dead() {
    let base = json!({
        "nzo_id": "SABnzbd_nzo_nzbfast1",
        "name": "Some.Release.1080p",
        "nzb_path": "/spool/x.nzb",
        "out_dir": "/downloads/Some.Release.1080p",
        "state": "Failed",
        "fail_message": "download incomplete: 12 articles missing",
    });
    let cooldown = 900;

    // First failure: eligible for the automatic retry, so nothing is
    // reported and no replacement is grabbed.
    let first = job(base.clone());
    assert_eq!(first.retries, 0);
    assert!(
        auto_retry_eligible(&first, cooldown),
        "a first transient failure retries"
    );
    assert_eq!(
        post_job_plan(&first, "regrab", cooldown),
        Some(false),
        "hooks still run, but the failure is not final yet"
    );

    // The retry ran, failed again: `retry` bumped `retries` and
    // cleared the stamp, so THIS failure is final and must report.
    let mut second = job(base.clone());
    second.retries = 1;
    assert!(
        !auto_retry_eligible(&second, cooldown),
        "only ONE automatic retry"
    );
    assert_eq!(
        post_job_plan(&second, "regrab", cooldown),
        Some(true),
        "the exhausted retry reports and re-grabs"
    );

    // Auto-retry switched off: the very first failure is final.
    assert!(!auto_retry_eligible(&first, 0));
    assert_eq!(post_job_plan(&first, "regrab", 0), Some(true));

    // A local fault is not transient, so it never held the report
    // back - and it is not reported either (fail_kind, tested above).
    let mut local = job(base.clone());
    local.fail_message = "no space left on device".into();
    assert!(!auto_retry_eligible(&local, cooldown));

    // Deleted mid-download: owes nobody anything, retry or not.
    let mut gone = job(base);
    gone.tombstone = true;
    assert!(!auto_retry_eligible(&gone, cooldown));
    assert_eq!(post_job_plan(&gone, "regrab", cooldown), None);
}

/// BUG: every dead post was downloaded TWICE. `MissingArticles` is
/// transient at any age, so the one automatic retry armed on a post
/// seven days old with 1965 of 4506 segments confirmed missing by four
/// backbones - and labelled the cooldown "propagation", for a post
/// whose propagation had finished six days earlier (job
/// SABnzbd_nzo_nzbfast1786807567, 15 Aug 2026: two ~150 s runs,
/// identical verdicts).
///
/// The asymmetry is the whole design: unknown age retries, and only the
/// missing-articles class is gated at all.
#[test]
fn a_post_too_old_for_propagation_does_not_retry_itself() {
    let cooldown = 900;
    let census = "download incomplete: 1 file(s) with missing segments, 0 decode/write \
                  errors; 1965 of 4506 segment(s) never arrived (1879 MB did)";
    let aged = |days: u32| {
        format!(
            "{census}; the post is {days} day(s) old, well past the minutes-to-hours \
             that propagation takes"
        )
    };
    let with_msg = |msg: String| {
        let mut j = job(json!({
            "nzo_id": "SABnzbd_nzo_nzbfast1786807567",
            "name": "Johnny.Vegas.Little.Shop.of.Antiques.S02E03",
            "nzb_path": "/spool/x.nzb",
            "out_dir": "/downloads/x",
            "state": "Failed",
        }));
        j.fail_message = msg;
        j
    };

    // Old enough that propagation cannot be the explanation: no second
    // download, and the failure is FINAL - which is what lets the
    // report, the re-grab and the M14f promotion run.
    let old = with_msg(aged(7));
    assert!(matches!(
        fail_kind(&old.fail_message),
        FailKind::MissingArticles
    ));
    assert!(
        !auto_retry_eligible(&old, cooldown),
        "a 7-day-old post is not waiting on propagation"
    );
    assert_eq!(post_job_plan(&old, "regrab", cooldown), Some(true));

    // The boundary, both sides of it. GONE_MIN_AGE_DAYS is the line the
    // project already draws; this must not invent a second one.
    let last_young = crate::diag::GONE_MIN_AGE_DAYS - 1;
    assert!(auto_retry_eligible(&with_msg(aged(last_young)), cooldown));
    assert!(!auto_retry_eligible(
        &with_msg(aged(crate::diag::GONE_MIN_AGE_DAYS)),
        cooldown
    ));

    // Unknown age keeps today's behaviour: a dateless NZB reads as age
    // 0 and writes no clause at all, and unknown is not old.
    assert!(auto_retry_eligible(&with_msg(census.to_string()), cooldown));

    // A stalled pool on THIS machine says nothing about the post, so
    // the transport retry is right at any age. Its message carries no
    // age clause either - the gate is belt and braces.
    let transport = with_msg(format!(
        "download failed on connection errors: 1 file(s) lost segments to transport \
         failures (40 in all - no server said any article was missing), 0 \
         decode/write errors{}",
        "; the post is 9 day(s) old, well past the minutes-to-hours that propagation takes"
    ));
    assert!(matches!(
        fail_kind(&transport.fail_message),
        FailKind::Transport
    ));
    assert!(
        auto_retry_eligible(&transport, cooldown),
        "transport is ours, not the post's"
    );

    // A repair verdict is not the missing-articles class: its retry
    // re-fetches gaps and can pull more recovery volumes.
    let unrepairable = with_msg(
        "verification failed and PAR2 repair could not complete: 1669 recovery \
         block(s) needed but the NZB only carries 40"
            .into(),
    );
    assert!(auto_retry_eligible(&unrepairable, cooldown));
}

/// BUG (MEDIUM): the config write logged the raw value with a
/// three-name deny-list, so every notification token and every feed
/// url (which carries the indexer apikey) went to stdout - which
/// logtee mirrors into the dashboard log pane users screenshot into
/// support threads, and into journald / `docker logs`.
#[test]
fn the_config_log_never_prints_a_credential() {
    assert_eq!(log_value("apikey", "s3cr3t"), "•••");
    assert_eq!(log_value("nzbkey", "s3cr3t"), "•••");
    assert_eq!(log_value("omdb_key", "s3cr3t"), "•••");

    // Notify targets: counts and kinds, never a url or a token.
    let targets = r#"[{"kind":"kodi","name":"Living room","url":"http://nas:8080/jsonrpc","token":"user:hunter2"},
                      {"kind":"plex","name":"Plex","url":"http://nas:32400","token":"xxPLEXTOKENxx"},
                      {"kind":"webhook","name":"Discord","url":"https://discord.com/api/webhooks/123/AAAsecretBBB","token":""}]"#;
    let shown = log_value("notify_targets", targets);
    assert_eq!(shown, "3 targets (kodi, plex, webhook)");
    for leak in ["hunter2", "PLEXTOKEN", "AAAsecretBBB", "discord.com", "nas"] {
        assert!(!shown.contains(leak), "{leak} reached the log via {shown}");
    }

    // Feeds: the url essentially always embeds `apikey=`.
    let feeds = r#"[{"url":"https://indexer.example/rss?t=tv&apikey=DEADBEEF","interval_secs":900},
                    {"url":"https://other.example/rss?apikey=CAFE","interval_secs":900}]"#;
    let shown = log_value("feeds", feeds);
    assert_eq!(shown, "2 feeds");
    assert!(!shown.contains("DEADBEEF") && !shown.contains("apikey"));

    // M35 indexer entries: the apikey is its own field.
    let idx = r#"[{"name":"geek","url":"https://api.nzbgeek.info","apikey":"SECRETKEY"}]"#;
    let shown = log_value("indexers", idx);
    assert_eq!(shown, "1 indexers");
    assert!(!shown.contains("SECRETKEY"));

    // Malformed JSON must not fall through to the raw value.
    assert!(!log_value("feeds", "{apikey=DEADBEEF").contains("DEADBEEF"));
    assert!(!log_value("indexers", "{apikey=DEADBEEF").contains("DEADBEEF"));
    assert!(!log_value("notify_targets", "hunter2").contains("hunter2"));

    // Switches, numbers and paths still read verbatim - the line is
    // there to be useful.
    assert_eq!(log_value("connections", "40"), "40");
    assert_eq!(
        log_value("out_dir", "/mnt/media/downloads"),
        "/mnt/media/downloads"
    );
    assert_eq!(log_value("auto_rename", "1"), "1");
    assert_eq!(log_value("failure_link", "regrab"), "regrab");

    // DEFAULT DENY: a setting name this function has never heard of -
    // i.e. the next credential-bearing one someone adds - gets a
    // shape summary, not its value.
    assert_eq!(
        log_value("some_future_token", "supersecret"),
        "(11 chars, not logged)"
    );
    assert_eq!(log_value("some_future_token", ""), "(empty)");
}

/// BUG (LOW): the failure-link replacement was enqueued with a
/// hardcoded priority 0 and password None, and took its category from
/// the (untrusted) response header. So a Force job's stand-in queued
/// at Normal, a passworded release's stand-in downloaded in full and
/// then failed extraction for a password the daemon already had, and
/// the indexer chose which of the user's destinations it landed in.
#[test]
fn a_regrabbed_replacement_keeps_the_password_the_priority_and_our_category() {
    let mut j = job(json!({
        "nzo_id": "SABnzbd_nzo_nzbfast1",
        "name": "Some.Release.1080p",
        "nzb_path": "/spool/x.nzb",
        "category": "movies",
        "out_dir": "/downloads/movies/Some.Release.1080p",
        "state": "Failed",
    }));
    j.priority = 2; // Force
    j.password = Some("hunter2".into());
    assert_eq!(
        replacement_inherits(&j),
        ("movies".to_string(), 2, Some("hunter2".to_string()))
    );

    // A held duplicate's -3 is a "parked" marker, not a speed: never
    // propagate it to a download that is meant to run.
    j.priority = -3;
    assert_eq!(replacement_inherits(&j).1, 0);
    // Low is clamped too: the floor is Normal, so a replacement can
    // never come back parked or deprioritized by accident.
    j.priority = -1;
    assert_eq!(replacement_inherits(&j).1, 0, "clamped at Normal");

    // No password, no category: nothing invented.
    let plain = job(json!({
        "nzo_id": "SABnzbd_nzo_nzbfast2",
        "name": "Other.Release",
        "nzb_path": "/spool/y.nzb",
        "out_dir": "/downloads/Other.Release",
        "state": "Failed",
    }));
    assert_eq!(replacement_inherits(&plain), (String::new(), 0, None));
}

/// BUG (MEDIUM): a config save whose value outgrew the 8 KB request
/// line (a watchlist of ~25 shows) got a correct 414 from the server
/// and vanished silently in the browser: `api()` called `r.json()`
/// with no `r.ok` check, the SyntaxError rejected a promise nothing
/// catches, and the one-click "watch this" then no-opped forever.
///
/// Source-level guard: the embedded dashboard is one file with ~60
/// call sites, so what matters is that the two fetch helpers funnel
/// through the checking reader.
#[test]
fn the_dashboard_turns_an_http_error_into_a_visible_one() {
    let src = DASHBOARD_HTML;
    assert!(src.contains("function httpFail(r){ return {status:false, error:'HTTP '+r.status}; }"));
    assert!(src.contains("async function readJson(r){"));
    // Neither helper may parse a response without going through it.
    for helper in [
        "async function api(mode, extra, authKey, post){",
        "async function apiPost(mode, body, authKey){",
    ] {
        let body = &src[src.find(helper).expect("helper present")..];
        let body = &body[..body.find("\n}").expect("helper ends")];
        assert!(
            body.contains("await readJson(r)"),
            "{helper} still parses unchecked"
        );
        assert!(
            !body.contains("await r.json()"),
            "{helper} still parses unchecked"
        );
    }
    // And the JSON-blob settings go up in a POST body, which has no
    // request-line limit to hit in the first place.
    assert!(src.contains("await apiPost('config', {name, value}, auth)"));
}

/// Codex sweep 2, 3 Aug MH1: a query string is not a private
/// channel. It reaches reverse-proxy access logs, the browser's own
/// network panel and history, and any Referer that follows - so a
/// setting whose VALUE is a credential must travel in a request
/// body, whatever its length. `setCfg` sent everything under ~1500
/// chars as `&value=`, and keys are short, so the one class that
/// must never be logged was the class that always was.
///
/// Source-level like its neighbour above, and for the same reason:
/// the property is about which branch a name takes, and the branch
/// is one line.
#[test]
fn a_secret_setting_never_travels_in_the_request_line() {
    let src = DASHBOARD_HTML;
    // The length rule is still there for big JSON blobs, and the
    // secret rule sits beside it as an OR - not an else.
    assert!(
        src.contains("(value.length > 1500 || SECRET_CFG.has(name))"),
        "setCfg no longer forces secrets into the body"
    );
    let set = src
        .split("const SECRET_CFG = new Set(")
        .nth(1)
        .and_then(|s| s.split(");").next())
        .expect("SECRET_CFG present");
    for name in [
        "apikey",
        "nzbkey",
        "omdb_key",
        "notify_targets",
        "arr_instances",
        "indexers",
    ] {
        assert!(set.contains(name), "{name} is not in SECRET_CFG: {set}");
    }
    // notify_test carries a webhook token AND a custom body
    // template. `method:'POST'` does not move query parameters into
    // the body, so it has to be an actual body call.
    assert!(
        src.contains("await apiPost('notify_test', {target: row})"),
        "notify_test still puts the whole target in the request line"
    );
}

/// BUG (MEDIUM): `apply_and_save` answers a write it could not persist
/// with `saved: false` - the value is live, and it reverts at the next
/// restart - and the dashboard threw that flag away. Every path toasted
/// a flat "Saved.", and the API-key ones went further: "New API key
/// created and copied. Paste it into Sonarr, Radarr…" for a key that
/// dies on the next start. The only warning was the eprintln, which is
/// stdout on a NAS, i.e. nobody.
///
/// Source-level guard, like the http-error one above: all three paths
/// that can see the flag must raise the durability bar, and none of
/// them may refuse the key - the daemon is already on it, so a page
/// that kept the old one would lock itself out.
#[test]
fn the_dashboard_says_when_a_change_is_live_but_not_durable() {
    let src = DASHBOARD_HTML;
    assert!(
        src.contains(r#"<div id="durnotice"></div>"#),
        "no durability bar in the page"
    );
    assert!(src.contains("function durNotice("), "no durability notice");
    assert!(
        src.contains("function durNoticeClear("),
        "the bar can never come down again"
    );

    // Function bodies run to the next top-level declaration: openApiFix
    // is a `busy()` wrapper and has no line that is just "}".
    let body_of = |sig: &str| -> &str {
        let s = &src[src.find(sig).unwrap_or_else(|| panic!("{sig} is gone")) + sig.len()..];
        let end = s
            .find("\nasync function ")
            .unwrap_or(s.len())
            .min(s.find("\nfunction ").unwrap_or(s.len()));
        &s[..end]
    };
    for (name, sig) in [
        ("setCfg", "async function setCfg(name, value){"),
        ("newApiKey", "async function newApiKey(){"),
        ("openApiFix", "async function openApiFix(btn){"),
    ] {
        let body = body_of(sig);
        // Strict ===, so an older daemon that omits the field keeps the
        // old behavior rather than warning on every save.
        assert!(
            body.contains("j.saved === false") || body.contains("j.saved===false"),
            "{name} still ignores saved:false"
        );
        assert!(
            body.contains("durNotice("),
            "{name} warns nobody about a lost write"
        );
    }
    // Both key paths still adopt the new key: the daemon is on it.
    // Adoption goes through adoptKey() now (it also bumps the epoch a
    // refused in-flight call is judged against), so either idiom counts -
    // what must never come back is a mint that leaves the page on the
    // key the daemon has just thrown away.
    for sig in [
        "async function newApiKey(){",
        "async function openApiFix(btn){",
    ] {
        let body = body_of(sig);
        assert!(
            body.contains("adoptKey(j.apikey)")
                || body.contains("localStorage.nzbfastKey = j.apikey")
                || body.contains("localStorage.nzbfastKey=j.apikey"),
            "a saved:false path stopped adopting the key, which locks the page out"
        );
        // And it must adopt INSIDE the rotation gate: every poll in
        // flight is refused the moment the daemon swaps its key, and
        // without the gate one of them opens the key modal over the one
        // screen that is showing the replacement.
        assert!(
            body.contains("keyRotateStart()") && body.contains("keyRotateEnd()"),
            "{sig} mints without the rotation gate: an old-key 403 can \
             open the key modal before the new key is adopted"
        );
    }
}

/// A refusal is only ever news about the key the request CARRIED.
///
/// The same-tab race behind the "keeps asking for a key and nothing
/// stops it" report: press Create new, and for as long as the mint is in
/// flight the daemon has already rotated while the page has not. Every
/// poll already out there - the loop runs at 1 Hz, so there is always
/// one - comes back refused, and the first of them used to open the
/// shared key modal, asking for a key that did not exist when it sent
/// its request. Worse, the call it parked there was often a
/// loadSettings, which resumed after the mint had painted the new key
/// into the Security box and blanked it: on a plain-http LAN origin
/// (what the Remote access QR codes hand out) navigator.clipboard does
/// not exist, so that box was the only copy of the key in the world.
///
/// Source-level guard, like its neighbours - the page is one file with
/// no test harness of its own, and every one of these pieces is load
/// bearing on its own.
#[test]
fn a_stale_refusal_can_never_ask_for_a_key() {
    for (name, src) in [("dashboard", DASHBOARD_HTML), ("wall", WALL_HTML)] {
        // Every adoption bumps an epoch, and every request records the
        // epoch it goes out under. Without the pair there is nothing to
        // tell "this key is wrong" from "this key is old".
        assert!(
            src.contains("function adoptKey(") && src.contains("keyEpoch++"),
            "{name}: key adoption no longer bumps an epoch"
        );
        assert!(
            src.contains("const epoch = keyEpoch"),
            "{name}: requests no longer record the key generation they were sent under"
        );
        assert!(
            src.contains("keyEpoch !== epoch"),
            "{name}: a refusal from an older key generation can reach the prompt again"
        );
        // localStorage is shared across every tab on this origin, but
        // each page cached its own copy at load: a key entered or minted
        // in one surface must re-pair the others rather than ask twice.
        assert!(
            src.contains("localStorage.nzbfastKey || ''") && src.contains("stored !== sent"),
            "{name}: a refused call no longer re-reads the shared store before asking"
        );
        assert!(
            src.contains("addEventListener('storage'"),
            "{name}: a sibling tab's re-pairing no longer reaches this page"
        );
    }
    // The dashboard is the surface that rotates, so it carries the gate
    // and the latch. (newApiKey/openApiFix are checked for the gate in
    // the durability test above.)
    let src = DASHBOARD_HTML;
    assert!(
        src.contains("function keyRotateStart(") && src.contains("function keyRotateEnd("),
        "the rotation gate is gone: an old-key 403 can open the modal mid-mint"
    );
    assert!(
        src.contains("if (keyRotating) await keyRotating"),
        "a refused call no longer waits out a rotation this page started"
    );
    // The minted key stays on screen until the user puts it away, even
    // if some other loadSettings lands in between.
    assert!(
        src.contains("mintedKey") && src.contains("function mintedShow("),
        "a freshly minted key is no longer held on screen"
    );
    assert!(
        src.contains("ak.value=mintedKey.s_apikey") && src.contains("nk.value=mintedKey.s_nzbkey"),
        "loadSettings blanks the key boxes again, minted value and all"
    );
    assert!(
        DASHBOARD_HTML
            .split("async function showApiKey(")
            .nth(1)
            .is_some_and(|b| b[..b.find("\nasync function ").unwrap_or(b.len())]
                .contains("mintedClear('s_apikey')")),
        "Hide no longer releases the latch, so the box can never be cleared"
    );
}

/// One design system, actually reaching every page. Each surface must
/// carry the tokens placeholder, and `ui_themed` must leave none of it
/// behind.
///
/// THE TRAP, hit while writing this: web/ui-tokens.html originally
/// named the placeholder in its own header comment, so substitution
/// re-emitted the literal into every served page. A single `.replace`
/// does not recurse, so nothing broke visibly - it just shipped a
/// stray marker. Hence the "no marker survives" half.
#[cfg(feature = "indexer")]
#[test]
fn every_served_page_gets_the_shared_design_tokens() {
    const MARK: &str = "__NZBFAST_UI_TOKENS__";
    assert!(
        !UI_TOKENS_HTML.contains(MARK),
        "ui-tokens.html names the placeholder, which re-emits it into every page"
    );
    // The tokens themselves, so a gutted file cannot pass.
    for tok in [
        "--surface:",
        "--surface-2:",
        "data-theme=\"contrast\"",
        "nzbfastTheme",
    ] {
        assert!(UI_TOKENS_HTML.contains(tok), "shared tokens lost {tok}");
    }
    // The wall and the manual were the two pages that did NOT read the
    // user's theme; keep them wired.
    //
    // Two halves, because the manuals are substituted at BUILD time now
    // (R10 / C9) and only the shell pages still pass through
    // `ui_themed` per request. The shell pages are checked as source -
    // placeholder in, no placeholder out - and every manual is checked
    // as the bytes that actually ship, inflated back out of its
    // compressed member.
    for (name, page) in [("dashboard", DASHBOARD_HTML), ("wall", WALL_HTML)] {
        assert!(page.contains(MARK), "{name} has no tokens placeholder");
        // No page may keep a private palette that would shadow the
        // shared one.
        assert!(
            !page.contains("--bg:#0a0b10") && !page.contains("--bg:#0f1116"),
            "{name} still carries its own background token"
        );
        assert!(
            !ui_themed(page).contains(MARK),
            "{name} kept a stray placeholder"
        );
    }
    for lang in UI_LOCALES {
        let Some(manual) = manual_i18n(lang) else {
            continue;
        };
        let shipped = String::from_utf8(inflate(manual.gz)).expect("a manual is UTF-8");
        assert!(
            !shipped.contains(MARK),
            "the {lang} manual ships with a stray placeholder"
        );
        assert!(
            !shipped.contains("--bg:#0a0b10") && !shipped.contains("--bg:#0f1116"),
            "the {lang} manual still carries its own background token"
        );
        assert!(
            shipped.contains("data-theme=\"contrast\"") && shipped.contains("--surface:"),
            "the {lang} manual did not get the shared design tokens"
        );
    }
}

/// BUG (HIGH): a second top-level `function num(v)` - a floor-and-clamp
/// helper for three server-form boxes - was declared in the same single
/// `<script>` block as the locale-aware `function num(v, d)` formatter.
/// Duplicate top-level declarations are legal JS and hoisting makes the
/// LAST one win, so the 1-arg version became the only `num` on the page
/// and every size, speed and percentage lost its decimals: a 1727.39 MB
/// queue item rendered as "1 GB", a 3.4 MB par2 volume as "3 MB", and
/// the Intl decimal-comma path went dead for comma locales.
///
/// `node --check` cannot catch this (the file is valid JS), so the
/// guard is a source-level one: no name may be declared twice at the
/// top level of a served page.
#[cfg(feature = "indexer")]
#[test]
fn no_served_page_declares_the_same_function_twice() {
    for (name, page) in [("dashboard", DASHBOARD_HTML), ("wall", WALL_HTML)] {
        // Column 0 only: that is exactly the top-level scope the whole
        // page shares. Nested declarations are indented and are fine.
        let mut seen: Vec<&str> = Vec::new();
        let mut dupes: Vec<&str> = Vec::new();
        for line in page.lines() {
            let rest = line
                .strip_prefix("function ")
                .or_else(|| line.strip_prefix("async function "));
            let Some(rest) = rest else { continue };
            let ident = rest.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'));
            let Some(ident) = ident.into_iter().next().filter(|s| !s.is_empty()) else {
                continue;
            };
            if seen.contains(&ident) {
                dupes.push(ident);
            } else {
                seen.push(ident);
            }
        }
        assert!(
            dupes.is_empty(),
            "{name}: {dupes:?} declared twice at the top level - the later one silently \
             shadows the earlier for the WHOLE page"
        );
    }

    // And the formatter specifically: it is the one that got shadowed,
    // and it must keep the digit-count argument that ~20 call sites pass.
    assert!(
        DASHBOARD_HTML.contains("function num(v,d){"),
        "the locale-aware number formatter is gone"
    );
    assert!(
        !DASHBOARD_HTML.contains("function num(v){"),
        "a 1-arg num() is back and shadows the formatter"
    );
}

#[test]
fn url_host_parses_the_shapes_that_show_up() {
    assert_eq!(url_host("http://a.example/x"), "a.example");
    assert_eq!(url_host("https://A.Example:443"), "a.example");
    assert_eq!(url_host("http://a.example?q=1"), "a.example");
    assert_eq!(url_host("http://a.example#f"), "a.example");
    assert_eq!(url_host("http://[::1]:8080/x"), "[::1]");
    assert_eq!(url_host("ftp://a.example/x"), "");
    assert_eq!(url_host("/relative"), "");
}

/// THE TRAP in masking the notification token: `saveNotify` rebuilds
/// the whole list from the DOM and the daemon replaces it wholesale,
/// so masking without merging would make the next Apply write
/// `token: ""` and destroy every stored credential.
#[test]
fn a_blank_token_keeps_the_stored_one() {
    use crate::notify::{Kind, Target};
    let t = |name: &str, kind: Kind, url: &str, token: &str| Target {
        name: name.into(),
        kind,
        url: url.into(),
        token: token.into(),
        body: String::new(),
        enabled: true,
        on_failure: false,
        category: String::new(),
        events: Vec::new(),
        email_to: String::new(),
        email_from: String::new(),
        secret: String::new(),
    };
    let old = vec![
        t("Plex", Kind::Plex, "http://nas:32400", "PLEXTOKEN"),
        t("Jelly", Kind::Jellyfin, "http://nas:8096", "JELLYKEY"),
    ];
    // Reordered and edited, both tokens blank as the UI sends them.
    let mut incoming = vec![
        t("Jelly", Kind::Jellyfin, "http://nas:8096", ""),
        // Port corrected: no exact match, but only one Plex named Plex.
        t("Plex", Kind::Plex, "http://nas:32401", ""),
        // Brand new row: nothing to carry forward.
        t("Hook", Kind::Webhook, "https://discord/x", ""),
    ];
    super::merge_notify_tokens(&mut incoming, &old);
    assert_eq!(
        incoming[0].token, "JELLYKEY",
        "reordering must not lose a token"
    );
    assert_eq!(
        incoming[1].token, "PLEXTOKEN",
        "editing the URL must not lose a token"
    );
    assert_eq!(incoming[2].token, "");

    // A token the user actually typed always wins.
    let mut typed = vec![t("Plex", Kind::Plex, "http://nas:32400", "NEW")];
    super::merge_notify_tokens(&mut typed, &old);
    assert_eq!(typed[0].token, "NEW");

    // Ambiguous (two same-kind targets with the same name, URL
    // changed): carry nothing rather than hand over the wrong one.
    let twins = vec![
        t("Plex", Kind::Plex, "http://a:32400", "A"),
        t("Plex", Kind::Plex, "http://b:32400", "B"),
    ];
    let mut moved = vec![t("Plex", Kind::Plex, "http://c:32400", "")];
    super::merge_notify_tokens(&mut moved, &twins);
    assert_eq!(moved[0].token, "");
}

/// BUG (LOW, credential leak): the (kind, name) fallback did not check
/// whether the stored target it landed on was ALREADY claimed by an
/// exact (kind, url, name) match on a different incoming row. Adding a
/// second same-kind target that happens to share a name with an
/// existing one therefore copied the first one's token onto it - a
/// credential sent to a server that was never meant to have it.
#[test]
fn a_token_is_never_carried_onto_a_second_target_of_the_same_name() {
    use crate::notify::{Kind, Target};
    let t = |name: &str, kind: Kind, url: &str, token: &str| Target {
        name: name.into(),
        kind,
        url: url.into(),
        token: token.into(),
        body: String::new(),
        enabled: true,
        on_failure: false,
        category: String::new(),
        events: Vec::new(),
        email_to: String::new(),
        email_from: String::new(),
        secret: String::new(),
    };
    // One stored Plex server.
    let old = vec![t("Living Room", Kind::Plex, "http://a:32400", "TOKEN-A")];
    // The user keeps it and adds a SECOND Plex server, reusing the
    // name (a rename they have not got round to, or just a habit).
    let mut incoming = vec![
        t("Living Room", Kind::Plex, "http://a:32400", ""),
        t("Living Room", Kind::Plex, "http://b:32400", ""),
    ];
    super::merge_notify_tokens(&mut incoming, &old);
    assert_eq!(
        incoming[0].token, "TOKEN-A",
        "the target it actually belongs to keeps it"
    );
    assert_eq!(
        incoming[1].token, "",
        "a brand new server must not inherit another's token"
    );

    // Same, with the exact-matching row placed second: the fallback
    // must not depend on the order rows arrive in.
    let mut reordered = vec![
        t("Living Room", Kind::Plex, "http://b:32400", ""),
        t("Living Room", Kind::Plex, "http://a:32400", ""),
    ];
    super::merge_notify_tokens(&mut reordered, &old);
    assert_eq!(
        reordered[0].token, "",
        "a brand new server must not inherit another's token"
    );
    assert_eq!(reordered[1].token, "TOKEN-A");

    // A row whose token the user TYPED still claims its stored twin:
    // that credential is being replaced, not made available to a
    // different server that shares the name.
    let mut typed = vec![
        t("Living Room", Kind::Plex, "http://a:32400", "TYPED"),
        t("Living Room", Kind::Plex, "http://b:32400", ""),
    ];
    super::merge_notify_tokens(&mut typed, &old);
    assert_eq!(typed[0].token, "TYPED");
    assert_eq!(
        typed[1].token, "",
        "the replaced credential is not up for grabs either"
    );

    // The legitimate case must still work: the ONLY row of that
    // (kind, name) had its host corrected, so the token follows it.
    let mut corrected = vec![t("Living Room", Kind::Plex, "http://a:32401", "")];
    super::merge_notify_tokens(&mut corrected, &old);
    assert_eq!(
        corrected[0].token, "TOKEN-A",
        "correcting a port must not drop the token"
    );
}

/// The unpack-space forecast has to count the decrypt's temp copy.
///
/// Real case (a tester, 2 Aug): a 13.85 GB RAR5 ENCRYPTED set on a
/// disk with 15.6 GB free. The volumes fit, so the download ran to
/// completion and the unpack then died with the disk full. Counting
/// "volumes + payload" would have told them to free ~12 GB, they
/// would have freed it, and the finish decrypt - which writes the
/// plaintext into a temp beside the ciphertext before renaming -
/// would have failed them a second time.
#[test]
fn an_encrypted_set_is_forecast_a_copy_higher_than_a_plain_one() {
    const GB: u64 = 1_000_000_000;
    // Nothing fetched yet: parts + payload.
    assert_eq!(
        unpack_space_needed(10 * GB, 10 * GB, "rar5 store on-disk"),
        20 * GB
    );
    // Same set, encrypted: the decrypt's temp is a third copy.
    assert_eq!(
        unpack_space_needed(10 * GB, 10 * GB, "rar5 store encrypted on-disk"),
        30 * GB
    );
    // The tester's job, fully downloaded (nothing left to fetch):
    // the honest answer is two more copies, not one.
    assert_eq!(
        unpack_space_needed(0, 13_850 * 1_000_000, "rar5 encrypted unlock-at-end"),
        27_700 * 1_000_000
    );
    // A NESTED set materializes one more layer than it looks: the
    // outer volumes stay on disk, level 0's output IS the inner
    // archive, and level 1's is the payload. So a fully-downloaded
    // 20 GB nested set needs the payload AND the intermediate, where
    // this used to promise only the payload - and the job then hit
    // ENOSPC at the second level with the whole download paid for.
    assert_eq!(
        unpack_space_needed(0, 20 * GB, "rar5 store on-disk inner-rar"),
        40 * GB
    );
    assert_eq!(
        unpack_space_needed(0, 20 * GB, "rar5 store on-disk inner-7z"),
        40 * GB
    );
    // Encrypted AND nested pays for both.
    assert_eq!(
        unpack_space_needed(0, 10 * GB, "rar5 encrypted on-disk inner-rar"),
        30 * GB
    );
    // The plain set beside them is untouched: whole tokens only.
    assert_eq!(
        unpack_space_needed(0, 20 * GB, "rar5 store on-disk"),
        20 * GB
    );
    // Which shapes get a forecast at all: the ones that materialize.
    assert!(shape_unpacks_on_disk("rar5 store encrypted on-disk"));
    assert!(shape_unpacks_on_disk("rar5 store encrypted unlock-at-end"));
    assert!(shape_unpacks_on_disk("rar4 mixed-pass"));
    // A clean one-pass set never holds both at once.
    assert!(!shape_unpacks_on_disk("rar5 store one-pass"));
    assert!(!shape_unpacks_on_disk(""));
    // Saturating, not panicking, on absurd sizes.
    assert_eq!(
        unpack_space_needed(u64::MAX, u64::MAX, "encrypted on-disk"),
        u64::MAX
    );
}

/// BUG (MEDIUM): deleting an active download aborts the pipeline,
/// which surfaces as an Err and files the job Failed - so a
/// cancellation ran the pp-script, sent a "Failed" notification and
/// reported a healthy post to the indexer as dead.
#[test]
fn a_deleted_job_owes_the_outside_world_nothing() {
    assert_eq!(post_job_duties(JobState::Failed, true, "regrab"), None);
    assert_eq!(post_job_duties(JobState::Failed, true, "report"), None);
    // The success race: the fetch returned Ok just before the abort
    // landed. Still deleted, still owes nothing.
    assert_eq!(post_job_duties(JobState::Completed, true, "report"), None);
    // An ordinary failure still reports; an ordinary completion does
    // not, and neither does a failure with the feature off.
    assert_eq!(
        post_job_duties(JobState::Failed, false, "report"),
        Some(true)
    );
    assert_eq!(post_job_duties(JobState::Failed, false, "off"), Some(false));
    assert_eq!(
        post_job_duties(JobState::Completed, false, "regrab"),
        Some(false)
    );
}

/// BUG (MEDIUM): a LOCAL fault reported to the indexer as a dead post.
/// The two policies that read `fail_message` - the auto-retry
/// cooldown and the dead-post report - now share one classifier.
#[test]
fn only_a_dead_post_is_reported_to_the_indexer() {
    // The feature's core cases must still report.
    assert!(
        fail_kind("download incomplete: 3 file(s) with missing segments, 0 decode/write errors")
            .post_unavailable()
    );
    assert!(fail_kind("verification failed and PAR2 repair could not complete").post_unavailable());
    assert!(
        fail_kind("pre-flight: articles missing beyond repair (12 segments)").post_unavailable()
    );
    assert!(fail_kind("content no longer retrievable").post_unavailable());

    // Local faults must not - none of these say anything about the post.
    for local in [
        crate::incomplete_reason(0, 7, &no_causes()),
        "No space left on device (os error 28)".to_string(),
        "Permission denied (os error 13)".to_string(),
        "no usable servers".to_string(),
        "password required to unpack".to_string(),
        "an archive in the output directory could not be unpacked".to_string(),
        "the nested-archive pass failed".to_string(),
    ] {
        assert!(
            !fail_kind(&local).post_unavailable(),
            "must not report: {local}"
        );
    }

    // And the auto-retry policy agrees with itself: waiting can fix a
    // missing article or an unfinished repair, but it cannot empty a
    // full disk - retrying that just runs into the same disk again.
    assert!(
        fail_kind("download incomplete: 1 file(s) with missing segments, 0 decode/write errors")
            .transient()
    );
    assert!(fail_kind("verification failed and PAR2 repair could not complete").transient());
    assert!(!fail_kind(&crate::incomplete_reason(0, 7, &no_causes())).transient());
    // Appended cause clauses (retention / dead server) must not shift
    // the classification: still MissingArticles, still transient.
    let hosts = ["news.x.example".to_string()];
    let with_causes = crate::incomplete_reason(
        2,
        0,
        &crate::LossCauses {
            missing_430: 4,
            takedown_430: 0,
            retention_excluded: 900,
            dead_servers: &hosts,
            ..no_causes()
        },
    );
    assert!(fail_kind(&with_causes).post_unavailable(), "{with_causes}");
    assert!(fail_kind(&with_causes).transient(), "{with_causes}");

    // All-transport losses are the provider's weather, not the
    // post's health: auto-retry yes, indexer dead-post report NO.
    let transport = crate::incomplete_reason(
        3,
        0,
        &crate::LossCauses {
            transport_failed: 12,
            ..no_causes()
        },
    );
    assert!(
        transport.starts_with("download failed on connection errors"),
        "{transport}"
    );
    assert!(!fail_kind(&transport).post_unavailable(), "{transport}");
    assert!(fail_kind(&transport).transient(), "{transport}");

    // A post where every backbone that answered said 430 to every
    // article is DEAD, not damaged. Reported to the indexer like any
    // missing-article failure - but NOT transient: the one automatic
    // retry exists because propagation fills gaps in, and there is no
    // gap here to fill. (Seen in the field, 31 Jul: six minutes and
    // 0 bytes, twice.)
    let gone = crate::incomplete_reason(
        94,
        0,
        &crate::LossCauses {
            missing_430: 12_018,
            takedown_430: 0,
            missing_segments: 12_018,
            total_segments: 12_018,
            bytes_arrived: 0,
            post_age_days: 21,
            ..no_causes()
        },
    );
    assert!(gone.starts_with("post is gone"), "{gone}");
    assert!(fail_kind(&gone).post_unavailable(), "{gone}");
    assert!(!fail_kind(&gone).transient(), "{gone}");
    // The build tag appends to it like anything else, and an *arr
    // still reads it as health so the grab moves to another release.
    assert!(
        !fail_kind(&crate::with_build(gone.clone())).transient(),
        "{gone}"
    );
    assert_eq!(
        super::nzbget_status(&job(json!({
            "nzo_id": "g", "name": "Show.2160p", "nzb_path": "/spool/g.nzb",
            "state": "Failed", "out_dir": "/dl/g", "fail_message": gone,
        }))),
        ("FAILURE/HEALTH", "NONE", "NONE")
    );
    // And the *arr-facing NZBGet mapping calls it health, so a
    // client moves on rather than blaming repair or the machine.
    assert_eq!(
        super::nzbget_status(&job(json!({
            "nzo_id": "t", "name": "Show.1080p", "nzb_path": "/spool/t.nzb",
            "state": "Failed", "out_dir": "/dl/t", "fail_message": transport,
        }))),
        ("FAILURE/HEALTH", "NONE", "NONE")
    );
    // The version tag a job failure now carries must not disturb any
    // of this - it appends after everything.
    let tagged = crate::with_build(transport);
    assert!(!fail_kind(&tagged).post_unavailable(), "{tagged}");
    assert!(!fail_kind("content no longer retrievable").transient());
    // A takedown verdict is a real dead post, but not worth retrying.
    assert!(!fail_kind("pre-flight: articles missing beyond repair").transient());
}

/// TODO §138 (issue #29): the opt-in give-up's sentence, end to end,
/// through the same classifier the download-proved verdict above uses.
///
/// The three consequences are the whole feature and they all hang off
/// the message OPENING, so this pins them from the producer rather than
/// from a literal: NOT transient (no automatic retry against a post
/// nothing carries), FAILURE/HEALTH to the *arr (blocklist the release
/// and search again, rather than blaming a repair that never ran), and
/// the `gone` token, which is what suppresses the drawer's Retry button.
#[test]
fn the_health_giveup_message_classifies_as_gone() {
    let h = crate::health::score(
        &[
            crate::health::ServerAnswer {
                host: "a".into(),
                cells: vec![crate::health::Avail::Missing; 8],
            },
            crate::health::ServerAnswer {
                host: "b".into(),
                cells: vec![crate::health::Avail::Missing; 8],
            },
        ],
        30,
        0,
        1,
    )
    .unwrap();
    assert!(h.no_server_can_supply());
    // The build tag rides along on the real path, so classify what the
    // runner actually stores rather than the bare sentence.
    let msg = crate::with_build(crate::health::giveup_reason(&h));
    assert!(!fail_kind(&msg).transient(), "{msg}");
    assert!(fail_kind(&msg).post_unavailable(), "{msg}");
    assert_eq!(fail_kind_token(fail_kind(&msg)), "gone", "{msg}");
    assert_eq!(
        super::nzbget_status(&job(json!({
            "nzo_id": "gu", "name": "Show.1080p", "nzb_path": "/spool/gu.nzb",
            "state": "Failed", "out_dir": "/dl/gu", "fail_message": msg,
        }))),
        ("FAILURE/HEALTH", "NONE", "NONE")
    );
}

/// The wire tokens the drawer switches on. Pinned because they are an
/// API: renaming one silently drops a remedy button rather than
/// breaking a build.
#[test]
fn fail_kind_tokens_are_stable() {
    for (msg, want) in [
        (
            "download incomplete: 3 file(s) with missing segments, 0 decode/write errors",
            "missing",
        ),
        (
            "download failed on connection errors: pool stalled",
            "transport",
        ),
        (
            "verification failed and PAR2 repair could not complete",
            "unrepairable",
        ),
        (
            "pre-flight: articles missing beyond repair (12 segments)",
            "preflight",
        ),
        ("content no longer retrievable", "gone"),
        ("No space left on device (os error 28)", "local"),
    ] {
        assert_eq!(fail_kind_token(fail_kind(msg)), want, "{msg}");
    }
}

/// The sub-cause inside the message. Each token is keyed on a clause
/// `incomplete_reason` (or the pool) writes verbatim, so the strings
/// here are built by the real producers wherever possible.
#[test]
fn fail_hint_names_the_sub_cause() {
    let retention = crate::incomplete_reason(
        2,
        0,
        &crate::LossCauses {
            missing_430: 1,
            takedown_430: 0,
            retention_excluded: 900,
            ..no_causes()
        },
    );
    assert_eq!(fail_hint(&retention), "retention", "{retention}");
    // A post carrying no parity at all: another release is the only
    // answer, even though the KIND is the retryable missing-articles.
    let nopar2 = crate::incomplete_reason(
        1,
        0,
        &crate::LossCauses {
            missing_430: 3,
            takedown_430: 0,
            par2_slots: 0,
            ..no_causes()
        },
    );
    assert_eq!(fail_hint(&nopar2), "nopar2", "{nopar2}");
    assert_eq!(fail_kind(&nopar2), FailKind::MissingArticles, "{nopar2}");
    // Both forms of the empty pool, including the build tag that gets
    // appended to every job failure.
    for msg in [
        "no usable servers: none are set up yet - add your provider in Server settings",
        "no usable servers: every one you have set up is out of the pool right now - \
         news.x.example (switched off)",
    ] {
        assert_eq!(fail_hint(msg), "servers", "{msg}");
    }
    // A plain failure has no sub-cause and falls back to its kind.
    assert_eq!(fail_hint("Permission denied (os error 13)"), "");
    let plain = crate::incomplete_reason(
        2,
        0,
        &crate::LossCauses {
            missing_430: 4,
            takedown_430: 0,
            par2_slots: 9,
            ..no_causes()
        },
    );
    assert_eq!(fail_hint(&plain), "", "{plain}");
}

/// ONE action per failure, and never the useless one: the audit found
/// every kind sharing a single Retry, including the two the daemon
/// itself classifies as unfixable by retrying.
#[test]
fn each_failure_gets_the_action_that_can_help() {
    let act = |msg: &str, pw: bool| fail_action(fail_kind(msg), fail_hint(msg), msg, pw);
    // Waiting genuinely helps these two, and only these two.
    assert_eq!(
        act(
            "download incomplete: 1 file(s) with missing segments, 0 decode/write errors",
            false
        ),
        "retry"
    );
    assert_eq!(
        act("download failed on connection errors: pool stalled", false),
        "retry"
    );
    // A dead post, a pre-flight verdict and an unrepairable set are
    // all answered by another release, never by asking again.
    for msg in [
        "content no longer retrievable",
        "pre-flight: articles missing beyond repair (12 segments)",
        "verification failed and PAR2 repair could not complete",
    ] {
        assert_eq!(act(msg, false), "search", "{msg}");
    }
    // Sub-causes outrank the kind.
    let retention = crate::incomplete_reason(
        2,
        0,
        &crate::LossCauses {
            missing_430: 1,
            takedown_430: 0,
            retention_excluded: 900,
            ..no_causes()
        },
    );
    assert_eq!(act(&retention, false), "retention", "{retention}");
    assert_eq!(
        act("no usable servers: none are set up yet", false),
        "servers"
    );
    // ...and the two that outrank everything. Both are `Local`, and
    // "show the folder" answers neither of them.
    assert_eq!(act("No space left on device (os error 28)", false), "space");
    assert_eq!(act("unpack failed", true), "password");
    // A full disk stays a full disk even for a locked archive: the
    // password prompt is the thing that can actually be completed.
    assert_eq!(
        act("No space left on device (os error 28)", true),
        "password"
    );
    // Everything else local: the folder is where the evidence is.
    assert_eq!(act("Permission denied (os error 13)", false), "path");
}

/// Six watch-folder states, four of which are SUCCESSES. The strip
/// showed one sentence for all six and offered a Delete that destroys
/// the only copy in exactly the states where it is not safe.
#[test]
fn watch_folder_states_are_told_apart() {
    use super::tasks::{watch_fail_ingested, watch_fail_kind, watchfail};
    for (msg, kind, ingested) in [
        (watchfail::TRUNCATED.to_string(), "truncated", false),
        (watchfail::ALREADY_QUEUED.to_string(), "queued", true),
        (watchfail::ALREADY_DONE.to_string(), "done", true),
        (watchfail::UNSAVED.to_string(), "unsaved", true),
        (
            format!("{}: Permission denied (os error 13)", watchfail::KEPT),
            "kept",
            true,
        ),
        (
            "not an NZB: no <nzb> element".to_string(),
            "rejected",
            false,
        ),
    ] {
        assert_eq!(watch_fail_kind(&msg), kind, "{msg}");
        assert_eq!(watch_fail_ingested(kind), ingested, "{msg}");
    }
}

#[test]
fn cat_dest_list_parses_and_round_trips() {
    let list = super::parse_cat_dests(" tv = /NAS/TV, movies=/NAS/Movies ; ; ").unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].0, "tv");
    assert_eq!(list[0].1, std::path::PathBuf::from("/NAS/TV"));
    assert_eq!(
        super::fmt_cat_dests(&list),
        "tv=/NAS/TV, movies=/NAS/Movies"
    );
    // Empty clears; malformed and duplicate entries are rejected.
    assert!(super::parse_cat_dests("").unwrap().is_empty());
    assert!(super::parse_cat_dests("no-equals-here").is_err());
    assert!(super::parse_cat_dests("tv=/a, tv=/b").is_err());
    // Category names get the enqueue-path sanitizing (a traversal
    // token can't map to a folder no job ever used).
    let odd = super::parse_cat_dests("t/v=/NAS/X").unwrap();
    assert_eq!(odd[0].0, nzbkit::disk::sanitize_filename("t/v"));
}

/// The two spellings of the failure header in the wild, and the
/// blank-header case (an indexer that sets it unconditionally).
#[test]
fn failure_link_header_aliases() {
    assert_eq!(
        super::pick_failure_link("http://a/fail", ""),
        "http://a/fail"
    );
    assert_eq!(
        super::pick_failure_link("", "http://b/fail"),
        "http://b/fail"
    );
    // Canonical wins when an indexer sends both.
    assert_eq!(
        super::pick_failure_link("http://a/fail", "http://b/fail"),
        "http://a/fail"
    );
    assert_eq!(super::pick_failure_link("", ""), "");
}

/// The body decides whether a replacement came back, not the status:
/// indexers answer 200 with a "nothing found" page all the time, and
/// queueing that as an NZB would fail a second job for no reason.
#[test]
fn only_an_xml_body_counts_as_a_replacement() {
    assert!(super::is_nzb_body(br#"<?xml version="1.0"?><nzb></nzb>"#));
    assert!(!super::is_nzb_body(
        b"<html><body>No results found</body></html>"
    ));
    assert!(!super::is_nzb_body(b""));
    // A bare <nzb> with no declaration is rejected too - same rule
    // FailureLink applies, and being stricter than the thing we are
    // matching would queue junk the reference implementation skips.
    assert!(!super::is_nzb_body(b"<nzb></nzb>"));
}

/// A replacement that also fails asks for another. The chain has to
/// stop on its own, unattended, before it walks an indexer's whole
/// run of dead posts through someone's block account.
#[test]
fn the_regrab_chain_stops_at_the_cap() {
    assert!(super::may_regrab("regrab", 0));
    assert!(super::may_regrab("regrab", super::FAILURE_REGRAB_MAX - 1));
    assert!(!super::may_regrab("regrab", super::FAILURE_REGRAB_MAX));
    assert!(!super::may_regrab("regrab", super::FAILURE_REGRAB_MAX + 9));
    // "report" reaches the indexer but never queues anything, and
    // "off" was already filtered out upstream - neither re-grabs.
    assert!(!super::may_regrab("report", 0));
    assert!(!super::may_regrab("off", 0));
}

/// End to end over a real socket: an indexer's X-DNZB headers have to
/// survive the fetch, or the failure link is never recorded and the
/// whole feature is silently dead. Loopback is deliberately reachable
/// through the SSRF guard (see the test below), so this exercises the
/// real `fetch_url`, agent and all.
#[test]
fn fetch_url_keeps_the_indexer_headers() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/getnzb/abc", listener.local_addr().unwrap());
    let t = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        let body = r#"<?xml version="1.0"?><nzb></nzb>"#;
        let _ = sock.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                 X-DNZB-Failure: http://indexer/fail?id=abc\r\n\
                 X-DNZB-Category: tv\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
    });
    let f = super::fetch_url(&url).expect("loopback fetch");
    t.join().unwrap();
    assert_eq!(f.failure_link, "http://indexer/fail?id=abc");
    assert_eq!(f.category, "tv");
    assert!(super::is_nzb_body(&f.bytes));
}

/// Issue #26 end to end at the fetch layer: a Prowlarr redirect grab is
/// `addurl` with an id-hash URL and no `nzbname`; the release name only
/// exists in the response's Content-Disposition. It has to survive the
/// fetch, or the job is titled after the hash.
#[test]
fn fetch_url_keeps_the_content_disposition_name() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/getnzb/chsfsd12das32da90aa3181?i=1&r=key",
        listener.local_addr().unwrap()
    );
    let t = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        let body = r#"<?xml version="1.0"?><nzb></nzb>"#;
        let _ = sock.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                 Content-Disposition: attachment; filename=\"Some.Release.2026.1080p-GRP.nzb\"\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
    });
    let f = super::fetch_url(&url).expect("loopback fetch");
    t.join().unwrap();
    assert_eq!(f.filename, "Some.Release.2026.1080p-GRP.nzb");
    assert_eq!(
        super::name_from_fetch(&f, &url).as_deref(),
        Some("Some.Release.2026.1080p-GRP.nzb")
    );
}

/// The three Content-Disposition shapes in the wild, plus the refusals:
/// path components are shorn (the header is attacker-influenced) and
/// RFC 5987 `filename*` wins over `filename` when both appear.
#[test]
fn content_disposition_filename_shapes() {
    let cd = super::content_disposition_filename;
    assert_eq!(
        cd("attachment; filename=\"A.Release.nzb\"").as_deref(),
        Some("A.Release.nzb")
    );
    assert_eq!(
        cd("attachment; filename=bare.nzb").as_deref(),
        Some("bare.nzb")
    );
    assert_eq!(
        cd("attachment; filename*=UTF-8''Sp%C3%A9cial%20Name.nzb").as_deref(),
        Some("Spécial Name.nzb")
    );
    // filename* wins regardless of parameter order, and `+` stays literal.
    assert_eq!(
        cd("attachment; filename=\"fallback.nzb\"; filename*=utf-8''Real+One.nzb").as_deref(),
        Some("Real+One.nzb")
    );
    // Path components shorn - a header must not steer names around.
    assert_eq!(
        cd("attachment; filename=\"../../etc/evil.nzb\"").as_deref(),
        Some("evil.nzb")
    );
    assert_eq!(
        cd("attachment; filename=\"C:\\\\spool\\\\evil.nzb\"").as_deref(),
        Some("evil.nzb")
    );
    // Nothing usable: absent, empty, or absurd.
    assert_eq!(cd("inline"), None);
    assert_eq!(cd("attachment; filename=\"\""), None);
    assert_eq!(
        cd(&format!("attachment; filename=\"{}\"", "x".repeat(300))),
        None
    );
    // Codex 7 Aug L3: a semicolon INSIDE the quoted value is part of
    // the name, not a parameter boundary - the blind split named the
    // job "Show" and skewed folder + duplicate identity off it.
    assert_eq!(
        cd("attachment; filename=\"Show; Part 2.nzb\"").as_deref(),
        Some("Show; Part 2.nzb")
    );
    // ...and an empty/malformed filename* must not suppress the valid
    // plain filename beside it.
    assert_eq!(
        cd("attachment; filename=\"Good.nzb\"; filename*=UTF-8''").as_deref(),
        Some("Good.nzb")
    );
    // Sweep 7 Aug: control characters out - a percent-encoded CR/LF or
    // ESC in the header must not reach logs through the job name.
    assert_eq!(
        cd("attachment; filename*=UTF-8''evil%0d%0afake%20log%20line.nzb").as_deref(),
        Some("evilfake log line.nzb")
    );
}

/// Without a Content-Disposition the fallback is the URL's last path
/// segment WITHOUT the query string - the old code kept `?t=get&id=...`
/// glued onto API-style links.
#[test]
fn name_from_fetch_strips_the_query() {
    let f = super::Fetched {
        bytes: Vec::new(),
        failure_link: String::new(),
        host: String::new(),
        https: false,
        category: String::new(),
        filename: String::new(),
        addrs: Vec::new(),
    };
    assert_eq!(
        super::name_from_fetch(&f, "https://x/api?t=get&id=abc").as_deref(),
        Some("api")
    );
    assert_eq!(
        super::name_from_fetch(&f, "https://x/getnzb/abc123.nzb?r=key#frag").as_deref(),
        Some("abc123.nzb")
    );
    assert_eq!(super::name_from_fetch(&f, "https://x/dir/"), None);
}

/// SSRF guard: cloud-metadata / link-local is refused; loopback, LAN
/// and CGNAT stay reachable (self-hosted indexers + Tailscale live
/// there), as do public hosts.
#[test]
fn ssrf_guard_blocks_metadata_but_allows_local() {
    use std::net::IpAddr;
    let blocked = [
        "169.254.169.254",        // cloud metadata (link-local)
        "169.254.1.1",            // link-local
        "0.0.0.0",                // unspecified
        "255.255.255.255",        // broadcast
        "fe80::1",                // v6 link-local
        "::ffff:169.254.169.254", // v4-mapped metadata
        "100.100.100.200",        // Alibaba metadata (inside CGNAT)
        "fd00:ec2::254",          // AWS IPv6 IMDS (inside ULA)
    ];
    for s in blocked {
        let ip: IpAddr = s.parse().unwrap();
        assert!(super::is_forbidden_fetch_ip(ip), "should block {s}");
    }
    // Legitimate for a self-hosted downloader - must stay reachable.
    let allowed = [
        "127.0.0.1",    // local indexer on loopback
        "10.0.0.5",     // LAN
        "192.168.1.10", // LAN
        "172.16.9.9",   // LAN
        "100.64.0.1",   // Tailscale CGNAT
        "::1",          // v6 loopback
        "fc00::1",      // v6 ULA (LAN)
        "8.8.8.8",      // public
        "2606:4700:4700::1111",
    ];
    for s in allowed {
        let ip: IpAddr = s.parse().unwrap();
        assert!(!super::is_forbidden_fetch_ip(ip), "should allow {s}");
    }
}

/// The other half of the SSRF picture (M12): which addresses count as
/// INSIDE the user's network, and so may only be reached by the source
/// that owns them. The always-forbidden set is folded in - a caller
/// consulting only this one must never get a weaker answer.
#[test]
fn private_fetch_ips_cover_the_lan_and_the_forbidden_set() {
    use std::net::IpAddr;
    let private = [
        "127.0.0.1",
        "127.0.0.53", // the other loopback service this rule is about
        "10.0.0.5",
        "192.168.1.10",
        "172.16.9.9",
        "172.31.255.254",
        "100.64.0.1",  // Tailscale CGNAT
        "100.127.0.1", // still 100.64/10
        "::1",
        "fc00::1",
        "fd12:3456::9",        // ULA
        "::ffff:192.168.1.10", // v4-mapped LAN
        "169.254.169.254",     // forbidden outright, private too
        "fe80::1",
    ];
    for s in private {
        let ip: IpAddr = s.parse().unwrap();
        assert!(super::is_private_fetch_ip(ip), "{s} is inside the network");
    }
    // Public - a sibling download host or CDN, which an indexer is
    // allowed to redirect a grab to.
    let public = [
        "8.8.8.8",
        "1.1.1.1",
        "172.32.0.1",  // just outside 172.16/12
        "100.63.0.1",  // just below the CGNAT block
        "100.128.0.1", // just above it
        "2606:4700:4700::1111",
        "::ffff:8.8.8.8",
    ];
    for s in public {
        let ip: IpAddr = s.parse().unwrap();
        assert!(!super::is_private_fetch_ip(ip), "{s} is public");
    }
}

/// `url_netloc` has to spell a URL the way ureq spells it for its
/// resolver (`host:port`, scheme default filled in), or the origin
/// comparison never matches and every private target is refused.
#[test]
fn url_netloc_matches_ureqs_spelling() {
    let n = super::url_netloc;
    assert_eq!(n("http://indexer.example/api?t=get"), "indexer.example:80");
    assert_eq!(n("https://indexer.example/api"), "indexer.example:443");
    assert_eq!(
        n("http://indexer.example:9696/1/api"),
        "indexer.example:9696"
    );
    assert_eq!(n("https://Indexer.Example:8443/"), "indexer.example:8443");
    assert_eq!(n("http://127.0.0.1:9117"), "127.0.0.1:9117");
    assert_eq!(n("http://[::1]:5076/api"), "[::1]:5076");
    assert_eq!(n("https://[fd00::1]/api"), "[fd00::1]:443");
    // userinfo is not the host - the LAST '@' separates it.
    assert_eq!(n("http://user:p@ss@127.0.0.1:9696/x"), "127.0.0.1:9696");
    // The backslash trap `url_host` documents: ureq dials 192.168.1.1,
    // so this must not answer `indexer.example`.
    assert_eq!(
        n("https://192.168.1.1\\@indexer.example/x"),
        "192.168.1.1:443"
    );
    // Unparseable - and an empty origin refuses every private target.
    assert_eq!(n("ftp://indexer.example/x"), "");
    assert_eq!(n(""), "");
}

/// An https indexer may not hand back a plain-http link to ITSELF: the
/// user's account apikey rides that query string. A different host is
/// left alone here - the origin rule confines it to public addresses.
#[test]
fn a_supplied_link_may_not_downgrade_its_own_origin() {
    let ok = super::supplied_link_scheme_ok;
    assert!(!ok(
        "http://indexer.example/getnzb/1",
        "https://indexer.example/api"
    ));
    assert!(!ok(
        "http://Indexer.Example:80/getnzb/1",
        "https://indexer.example/api"
    ));
    assert!(ok(
        "https://indexer.example/getnzb/1",
        "https://indexer.example/api"
    ));
    // A plain-http indexer was never carrying the key in the clear to
    // begin with; nothing to downgrade.
    assert!(ok(
        "http://indexer.example/getnzb/1",
        "http://indexer.example/api"
    ));
    // Sibling download host / CDN: not this rule's business.
    assert!(ok(
        "http://cdn.example/getnzb/1",
        "https://indexer.example/api"
    ));
}

/// M12, the rule itself: a link an indexer's RESPONSE supplied may reach
/// a private address only when that address IS the indexer. Cross-origin
/// public stays allowed (sibling download hosts and CDNs are real);
/// cross-origin private is the pivot being refused.
#[test]
fn an_enclosure_may_not_reach_a_private_address_its_indexer_does_not_own() {
    use ureq::Resolver;
    // Every origin here is a literal address, so what it answered the
    // search from is that same literal - the M9 half of the rule is
    // satisfied throughout and only the M12 half is under test.
    let bound = |url: &str, at: &str| {
        super::OriginBoundResolver::new(&super::SourceOrigin::witnessed(
            url,
            vec![at.parse().unwrap()],
        ))
    };
    let r = bound("http://127.0.0.1:9696/api", "127.0.0.1");
    // The indexer's own socket.
    assert!(r.resolve("127.0.0.1:9696").is_ok());
    // The finding's exact case: another service on the same loopback.
    assert!(r.resolve("127.0.0.1:9697").is_err());
    assert!(r.resolve("127.0.0.1:8080").is_err());
    // A different machine on the LAN.
    assert!(r.resolve("192.168.1.9:80").is_err());
    assert!(r.resolve("10.0.0.5:443").is_err());
    // Tailscale peers are inside the network too.
    assert!(r.resolve("100.64.0.1:80").is_err());
    // Public is fine - an indexer may serve its NZBs from elsewhere.
    assert!(r.resolve("8.8.8.8:443").is_ok());
    // ...but never from the metadata endpoint, guard unchanged.
    assert!(r.resolve("169.254.169.254:80").is_err());

    // A LAN indexer owns its own socket and nothing else.
    let lan = bound("http://192.168.1.9:5076/api", "192.168.1.9");
    assert!(lan.resolve("192.168.1.9:5076").is_ok());
    assert!(lan.resolve("192.168.1.9:5077").is_err());
    assert!(lan.resolve("127.0.0.1:5076").is_err());

    // The scheme's default port counts: an https indexer with no
    // explicit port owns :443.
    let dflt = bound("https://192.168.1.9/api", "192.168.1.9");
    assert!(dflt.resolve("192.168.1.9:443").is_ok());
    assert!(dflt.resolve("192.168.1.9:80").is_err());

    // An origin we could not parse refuses every private target rather
    // than guessing - the safe direction.
    let blind = bound("not a url", "127.0.0.1");
    assert!(blind.resolve("127.0.0.1:9696").is_err());
    assert!(blind.resolve("8.8.8.8:443").is_ok());
}

/// M9, the residual the origin rule alone left open: the netloc is a
/// NAME, and a name is resolved again at grab time. A source that
/// answered the search from a public address may not be followed to a
/// private one under that same name, however exactly the netlocs match.
///
/// The paired case is the one that must keep working: a LAN indexer
/// answers the search from its LAN address and is grabbed from it.
#[test]
fn a_source_may_not_move_inside_the_network_between_search_and_grab() {
    use ureq::Resolver;
    let at = |ip: &str| vec![ip.parse::<std::net::IpAddr>().unwrap()];
    let bound = |o: &super::SourceOrigin| super::OriginBoundResolver::new(o);

    // A LAN indexer, witnessed where it lives: unchanged, still works.
    let lan = super::SourceOrigin::witnessed("http://192.168.1.9:5076/api", at("192.168.1.9"));
    assert!(bound(&lan).resolve("192.168.1.9:5076").is_ok());

    // The same netloc, but the search was answered from a PUBLIC
    // address. The name now points inside the network: refused, and the
    // refusal says which half of the rule failed.
    let moved = super::SourceOrigin::witnessed("http://192.168.1.9:5076/api", at("203.0.113.7"));
    let Err(e) = bound(&moved).resolve("192.168.1.9:5076") else {
        panic!("a rebound source was followed inside the network");
    };
    assert!(
        e.to_string().contains("answered the search from"),
        "the refusal has to name the reason: {e}"
    );

    // A different private address at the same netloc is a rebind too -
    // the witness is per address, not per network.
    let neighbour =
        super::SourceOrigin::witnessed("http://192.168.1.9:5076/api", at("192.168.1.10"));
    assert!(bound(&neighbour).resolve("192.168.1.9:5076").is_err());

    // Nothing witnessed at all: private is refused, public is not.
    let blind = super::SourceOrigin::unwitnessed("http://192.168.1.9:5076/api");
    assert!(bound(&blind).resolve("192.168.1.9:5076").is_err());
    let pubsrc = super::SourceOrigin::unwitnessed("https://indexer.example/api");
    assert!(bound(&pubsrc).resolve("8.8.8.8:443").is_ok());
}

/// M12 end to end over real sockets: two loopback listeners, one
/// standing in for the indexer and one for the service next door. The
/// indexer's own enclosure is fetched; the neighbour's is refused before
/// a byte is read, so nothing on the box can be poked by a search
/// response.
#[test]
fn an_indexer_enclosure_fetch_stops_at_the_indexer() {
    use std::io::{Read, Write};
    let indexer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    // Bound, never served: the refusal happens at resolve time, so the
    // neighbour must not even be connected to. A listener that accepts
    // nothing proves it - a connection attempt would hang the fetch out
    // to its timeout instead of returning at once.
    let neighbour = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = super::SourceOrigin::witnessed(
        &format!("http://{}/api", indexer.local_addr().unwrap()),
        vec!["127.0.0.1".parse().unwrap()],
    );
    let mine = format!("http://{}/getnzb/abc", indexer.local_addr().unwrap());
    let theirs = format!("http://{}/getnzb/abc", neighbour.local_addr().unwrap());
    // Same host, different port: the two links differ ONLY in the way
    // the old code did not look at.
    assert_ne!(super::url_netloc(&theirs), super::url_netloc(&origin.url));

    let t = std::thread::spawn(move || {
        let (mut sock, _) = indexer.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        let body = r#"<?xml version="1.0"?><nzb></nzb>"#;
        let _ = sock.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
    });
    let f = super::fetch_url_from(&mine, &origin).expect("the indexer's own link");
    t.join().unwrap();
    assert!(super::is_nzb_body(&f.bytes));

    let Err(e) = super::fetch_url_from(&theirs, &origin) else {
        panic!("the service next door was fetched");
    };
    let msg = e.to_string();
    assert!(
        msg.contains("inside this network"),
        "the refusal has to name the reason: {msg}"
    );
}

/// M9 end to end, the two-resolution case: ONE netloc, answered from a
/// public address at search time and from loopback at grab time. The
/// first grab is refused without a byte being sent; the second, whose
/// witness is where the socket actually is, is served. Both run against
/// the same real listener, so the only thing that differs is what the
/// search recorded.
#[test]
fn an_indexer_that_moves_inside_the_network_after_its_search_is_refused() {
    use std::io::{Read, Write};
    let indexer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let at = indexer.local_addr().unwrap();
    let url = format!("http://{at}/api");
    let link = format!("http://{at}/getnzb/abc");
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    // Public at search time, loopback now. Same netloc either way, so
    // the origin rule alone would wave this through. Nothing is served
    // on the listener here on purpose: a refusal that happened after
    // the connect would hang out to the fetch timeout, not return.
    let moved = super::SourceOrigin::witnessed(&url, vec!["203.0.113.7".parse().unwrap()]);
    let Err(e) = super::fetch_url_from(&link, &moved) else {
        panic!("a source that moved onto loopback after its search was fetched");
    };
    let msg = e.to_string();
    assert!(
        msg.contains("answered the search from"),
        "the refusal has to name the reason: {msg}"
    );

    // The supported LAN shape: the search was answered from the address
    // the grab dials, so the grab goes through.
    let t = std::thread::spawn(move || {
        let (mut sock, _) = indexer.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        let body = r#"<?xml version="1.0"?><nzb></nzb>"#;
        let _ = sock.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
    });
    let here = super::SourceOrigin::witnessed(&url, vec![loopback]);
    let f = super::fetch_url_from(&link, &here).expect("the indexer where it actually answered");
    t.join().unwrap();
    assert!(super::is_nzb_body(&f.bytes));
    // ...and the fetch reports where it went, which is what a body full
    // of further links (an RSS feed) carries into ITS grabs.
    assert_eq!(f.addrs, vec![loopback]);
}

/// The capture end of the same rule: a search records the address its
/// indexer answered from, and hands it back on the origin the grab is
/// bound to. Without this the grab side is checking against nothing.
///
/// TWO searches, deliberately. A pooled connection skips the resolver,
/// so an agent that keeps idle connections witnesses the first request
/// and nothing after it - caps-then-search is exactly that shape, and it
/// refused a real loopback indexer's grab in `pull_search` before
/// `shared_indexer_agent` stopped pooling.
#[test]
fn every_search_carries_the_address_its_indexer_answered_from() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    // Keep-alive on purpose: this server will serve BOTH searches on one
    // connection if the client offers it, which is the shape that
    // silently skips the resolver. An unpooled client comes back for a
    // second connection instead, and the outer loop accepts it.
    let t = std::thread::spawn(move || {
        let mut served = 0;
        while served < 2 {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            while served < 2 {
                let mut buf = [0u8; 4096];
                match sock.read(&mut buf) {
                    Ok(n) if n > 0 => {}
                    _ => break,
                }
                let body = concat!(
                    r#"<?xml version="1.0"?><rss><channel><item>"#,
                    "<title>Show.S01E02.1080p.WEB</title>",
                    r#"<enclosure url="http://x/getnzb/abc" length="10"/>"#,
                    "</item></channel></rss>"
                );
                let _ = sock.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
                served += 1;
            }
        }
    });
    let cfg = crate::newznab::IndexerConfig {
        name: "loopback".into(),
        url: format!("http://{at}"),
        apikey: "K1".into(),
        enabled: true,
        priority: 0,
        hits_per_day: 0,
        grabs_per_day: 0,
    };
    let q = crate::newznab::SearchQuery::default();
    let loopback = vec!["127.0.0.1".parse::<std::net::IpAddr>().unwrap()];
    let (items, first) = super::indexer_search_one(&cfg, &q).expect("first search");
    let (_, second) = super::indexer_search_one(&cfg, &q).expect("second search");
    t.join().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(first.url, cfg.url);
    assert_eq!(first.addrs, loopback);
    assert_eq!(
        second.addrs, loopback,
        "a second search must witness too, or a pooled connection has \
         silently skipped the resolver"
    );
}

// A deterministic ephemeral keypair (fixed seed) drives the crypto-path
// tests, so they never depend on the production key and there is nothing
// to regenerate when the embedded key rotates.
fn test_vector() -> (String, Vec<u8>, String) {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pub_hex = hex::encode(sk.verifying_key().to_bytes());
    let manifest = br#"{"version":"9.9.9"}"#.to_vec();
    let sig_hex = hex::encode(sk.sign(&manifest).to_bytes());
    (pub_hex, manifest, sig_hex)
}

#[test]
fn manifest_signature_accepts_valid() {
    let (pk, manifest, sig) = test_vector();
    assert!(super::verify_with_key(&pk, &manifest, sig.as_bytes()).is_ok());
}

#[test]
fn manifest_signature_rejects_tampered_body() {
    let (pk, manifest, sig) = test_vector();
    let mut bad = manifest.clone();
    let n = bad.len() - 3;
    bad[n] ^= 0x01;
    assert!(super::verify_with_key(&pk, &bad, sig.as_bytes()).is_err());
}

#[test]
fn manifest_signature_rejects_tampered_sig() {
    let (pk, manifest, mut sig) = test_vector();
    let first = if sig.starts_with('f') { 'e' } else { 'f' };
    sig.replace_range(0..1, &first.to_string());
    assert!(super::verify_with_key(&pk, &manifest, sig.as_bytes()).is_err());
}

#[test]
fn manifest_signature_rejects_wrong_key() {
    // A valid signature under one key must NOT verify under a different
    // key - this is the property that stops a foreign manifest.
    let (_pk, manifest, sig) = test_vector();
    assert!(super::verify_manifest_sig(&manifest, sig.as_bytes()).is_err());
}

#[test]
fn manifest_signature_rejects_malformed_sig() {
    let (pk, manifest, _sig) = test_vector();
    assert!(super::verify_with_key(&pk, &manifest, b"not-hex").is_err());
    assert!(super::verify_with_key(&pk, &manifest, b"abcd").is_err());
    assert!(super::verify_with_key(&pk, &manifest, b"").is_err());
}

// ---- anti-rollback ratchet (READ-ONLY phase) ----------------------
//
// These pin the properties the LATER enforcing build will rely on. The
// one thing they must also prove is that this build does not enforce:
// a regression is recorded and warned about, never refused.

#[test]
fn manifest_serial_ratchet_advances_and_never_lowers() {
    use super::SerialStep::*;
    let m = |s: u64| serde_json::json!({ "version": "1.0.0", "serial": s });

    // A fresh install (seen = 0) takes whatever it is first told.
    assert_eq!(super::serial_ratchet(0, &m(100)), Advance(100));
    assert_eq!(super::serial_ratchet(100, &m(140)), Advance(140));

    // THE replay: an old, genuinely-signed manifest served again. The
    // signature is valid - only the serial catches this.
    assert_eq!(
        super::serial_ratchet(140, &m(100)),
        Regressed {
            got: 100,
            seen: 140
        }
    );

    // Re-serving the same manifest is the steady state, not a write.
    assert_eq!(super::serial_ratchet(140, &m(140)), Hold);
}

#[test]
fn manifest_serial_junk_and_absence_hold_the_ratchet() {
    use super::SerialStep::*;
    // Absent: normal during the rollout. Must HOLD, not clear - if it
    // cleared, replaying a pre-serial manifest would disarm the defence.
    assert_eq!(
        super::serial_ratchet(140, &serde_json::json!({ "version": "1.0.0" })),
        Hold
    );
    // Junk must not coerce into a huge serial, which would pin the
    // install above every real release it will ever be offered.
    assert_eq!(
        super::serial_ratchet(140, &serde_json::json!({ "serial": "999999" })),
        Hold
    );
    assert_eq!(
        super::serial_ratchet(140, &serde_json::json!({ "serial": -5 })),
        Hold
    );
    assert_eq!(
        super::serial_ratchet(140, &serde_json::json!({ "serial": 1.5 })),
        Hold
    );
    assert_eq!(
        super::serial_ratchet(140, &serde_json::json!({ "serial": null })),
        Hold
    );
}

#[test]
fn manifest_serial_is_not_enforced_in_this_build() {
    // The read-only guarantee, stated as a test so that flipping to
    // enforcement has to come here and change it deliberately rather
    // than inherit it. `serial_ratchet` reports a regression and that
    // is ALL it can do - there is no variant that refuses, so no
    // caller can act on one by accident.
    use super::SerialStep::*;
    let stale = serde_json::json!({ "version": "99.0.0", "serial": 1 });
    assert_eq!(
        super::serial_ratchet(500, &stale),
        Regressed { got: 1, seen: 500 }
    );
    assert!(
        super::version_newer("99.0.0", env!("CARGO_PKG_VERSION")),
        "the version comparison, which is what actually decides today, is untouched"
    );
}

#[test]
fn embedded_update_key_is_well_formed() {
    // The shipped key must be a valid 32-byte ed25519 public key, or every
    // update check dies at "update key is malformed".
    let raw = hex::decode(super::UPDATE_PUBKEY_HEX).expect("pubkey hex");
    assert_eq!(raw.len(), 32, "UPDATE_PUBKEY_HEX must be 32 bytes");
    let arr: [u8; 32] = raw.try_into().unwrap();
    assert!(ed25519_dalek::VerifyingKey::from_bytes(&arr).is_ok());
}

#[test]
fn parse_sizes() {
    assert_eq!(super::parse_size("500M"), Some(500_000_000));
    assert_eq!(super::parse_size("10G"), Some(10_000_000_000));
    assert_eq!(super::parse_size("1.5T"), Some(1_500_000_000_000));
    assert_eq!(super::parse_size("12345"), Some(12345));
    assert_eq!(super::parse_size("nope"), None);
}

// -- M34 index size cap ------------------------------------------------

/// The order setting is a closed set. Anything else is rejected at
/// the settings boundary, which is what lets `evict_policy` treat the
/// stored string as always-valid.
#[cfg(feature = "indexer")]
#[test]
fn evict_order_setting_accepts_exactly_the_five_orders() {
    use nzbkit::index::EvictOrder as O;
    assert!(matches!(
        super::parse_evict_order("ladder"),
        Some(O::Ladder)
    ));
    assert!(matches!(
        super::parse_evict_order("oldest"),
        Some(O::Oldest)
    ));
    assert!(matches!(
        super::parse_evict_order("newest"),
        Some(O::Newest)
    ));
    assert!(matches!(
        super::parse_evict_order("largest"),
        Some(O::Largest)
    ));
    assert!(matches!(
        super::parse_evict_order("smallest"),
        Some(O::Smallest)
    ));
    // Case and whitespace are the user's, not ours.
    assert!(matches!(
        super::parse_evict_order("  LaDdEr "),
        Some(O::Ladder)
    ));
    // Everything else, including the empty string, is refused rather
    // than silently defaulted - a typo must not quietly change which
    // rows get deleted.
    for bad in ["", "random", "ladder,oldest", "biggest", "asc"] {
        assert!(
            super::parse_evict_order(bad).is_none(),
            "{bad:?} must not parse"
        );
    }
    // The advertised list and the parser agree.
    for o in super::EVICT_ORDERS {
        assert!(
            super::parse_evict_order(o).is_some(),
            "{o} advertised but unparseable"
        );
    }
}

/// The kinds list is validated for a reason worth spelling out: it is
/// a RESTRICTION ("evict only these"), so a typo does not evict the
/// wrong thing - it evicts nothing, and the user is left staring at a
/// cap that never frees a byte with no error anywhere.
#[cfg(feature = "indexer")]
#[test]
fn evict_kinds_setting_validates_and_normalizes() {
    assert_eq!(super::parse_evict_kinds("").unwrap(), Vec::<String>::new());
    assert_eq!(
        super::parse_evict_kinds("   ").unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        super::parse_evict_kinds(" Movie , TV ").unwrap(),
        vec!["movie".to_string(), "tv".to_string()]
    );
    // Duplicates collapse; trailing separators are ignored.
    assert_eq!(
        super::parse_evict_kinds("tv,tv,,other,").unwrap(),
        vec!["tv".to_string(), "other".to_string()]
    );
    let e = super::parse_evict_kinds("movie,film").unwrap_err();
    assert!(e.contains("film"), "the error must name the offender: {e}");
}

/// The wizard's answer must not read as an established install: the
/// setup command runs as its own process, so its answer reaches
/// settings.json before the daemon has ever started, and the
/// first-run API key test keys off exactly that file.
#[test]
fn a_settings_file_of_wizard_answers_is_still_a_first_run() {
    let dir = std::env::temp_dir().join(format!("nzbfast-setupans-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("settings.json");
    let beyond = |text: &str| {
        std::fs::write(&p, text).unwrap();
        super::settings_beyond_setup_answers(&p)
    };
    assert!(
        !beyond(r#"{"index_interests":"linux,sports"}"#),
        "the wizard answer alone"
    );
    assert!(
        !beyond(r#"{"index_interests":""}"#),
        "answering \"nothing\" is an answer"
    );
    // Anything the daemon itself wrote means it has run.
    assert!(beyond(r#"{"index_interests":"linux","auto_speed":false}"#));
    assert!(beyond(r#"{"apikey":"k"}"#));
    // An empty object carries no wizard answer to explain itself, so
    // the old rule stands: the file exists, the install has run.
    assert!(beyond("{}"));
    // Unreadable or not-an-object: never mint over state we cannot
    // parse.
    assert!(beyond("[1,2,3]"));
    assert!(beyond("this is not json"));
    // A missing file is the caller's case, and answers false here.
    std::fs::remove_file(&p).unwrap();
    assert!(!super::settings_beyond_setup_answers(&p));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rename_punctuation_defaults_preserve_upgrades_only() {
    let dir = std::env::temp_dir().join(format!("nzbfast-rename-upgrade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("nzbfast.toml");
    let out = dir.join("downloads");
    let settings = dir.join("settings.json");

    assert!(
        !super::legacy_rename_punctuation(&config, &out, &settings),
        "a genuinely fresh install gets the new unpunctuated default"
    );
    std::fs::write(&settings, r#"{"index_interests":"tv"}"#).unwrap();
    assert!(
        !super::legacy_rename_punctuation(&config, &out, &settings),
        "the setup wizard runs before the daemon but is still a fresh install"
    );
    std::fs::write(&settings, "{}").unwrap();
    assert!(
        super::legacy_rename_punctuation(&config, &out, &settings),
        "an established settings file preserves the historical punctuation"
    );

    std::fs::remove_file(&settings).unwrap();
    std::fs::create_dir_all(config.with_file_name(".spool")).unwrap();
    assert!(
        super::legacy_rename_punctuation(&config, &out, &settings),
        "pre-settings installs are also identified by their existing spool"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
