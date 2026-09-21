//! TODO 19 (public request #4): the optional dashboard login, end to end.
//!
//! A sibling-dir child of daemon.rs (the daemon_authkey pattern) so the
//! parent stays inside its size-gate baseline; harness via `super::*`.
//!
//! One subject: what changes for a BROWSER when a username and password
//! are configured, and - the half that matters more - what does NOT
//! change for anything else. Sonarr, Radarr, nzb360 and LunaSea
//! authenticate with the API key and will never drive a form, so the
//! first test here is the one that says a daemon with no credentials
//! configured behaves exactly as it did before this item existed, and
//! the third is the one that says a key-only client is untouched while a
//! login IS configured.

use super::*;

/// A daemon with the full key set and nothing else.
async fn daemon_with_key(tag: &str) -> (Daemon, std::path::PathBuf) {
    // Two seconds, for the reason the TTL env hook below gives.
    daemon_with_key_ttl(tag, "2").await
}

/// The same daemon with the session TTL named.
///
/// Split out for `signing_every_browser_out_is_one_mode_and_a_same_site_gate`,
/// which holds TWO sessions open across a dozen round trips and would
/// otherwise be asserting a count that the two-second expiry can empty
/// underneath it on a loaded box - a green-for-the-wrong-reason arm on a
/// quick box and a flake on a slow one.
async fn daemon_with_key_ttl(tag: &str, ttl: &str) -> (Daemon, std::path::PathBuf) {
    daemon_with_key_env(tag, ttl, &[]).await
}

/// The same daemon again, with extra environment named.
///
/// The concurrency-cap legs need `NZBFAST_TEST_VERIFY_HOLD_MS`, which
/// has to be set on the daemon PROCESS: these tests drive a real binary
/// over a socket, so a hook the test process sets on itself would reach
/// nothing at all.
async fn daemon_with_key_env(
    tag: &str,
    ttl: &str,
    extra: &[(&str, &str)],
) -> (Daemon, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("nzbfast-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = dir.join("config.json");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            // Short enough that an expiry can be OBSERVED in a test that
            // finishes, rather than mocked out of the store and proved
            // about nothing. Production is 14 days; the hook is read per
            // check, so this is the same code path.
            .env("NZBFAST_TEST_SESSION_TTL_SECS", ttl);
        for (k, v) in extra {
            c.env(k, v);
        }
        c.arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("fullkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    (d, dir)
}

/// A request with an arbitrary header block, answered WITH its response
/// headers - the login legs read `Set-Cookie` and the status line, which
/// `http()` strips.
fn req(port: u16, line: &str, headers: &str, body: Option<&str>) -> String {
    let mut r = format!("{line} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{headers}");
    match body {
        Some(b) => r.push_str(&format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{b}",
            b.len()
        )),
        None => r.push_str("\r\n"),
    }
    String::from_utf8_lossy(&raw(port, r.as_bytes())).to_string()
}

fn status(resp: &str) -> u16 {
    resp.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

/// The `nzbfast_session_<port>=<id>` cookie out of a login answer, as a
/// `Cookie:` header line ready to send back, plus the CSRF token.
fn cookies_of(resp: &str) -> (String, String) {
    let mut jar = Vec::new();
    let mut csrf = String::new();
    for line in resp.lines() {
        let Some(v) = line
            .strip_prefix("Set-Cookie: ")
            .or_else(|| line.strip_prefix("set-cookie: "))
        else {
            continue;
        };
        let pair = v.split(';').next().unwrap_or("").trim().to_string();
        if let Some(t) = pair.split_once('=')
            && t.0.starts_with("nzbfast_csrf_")
        {
            csrf = t.1.to_string();
        }
        if !pair.is_empty() {
            jar.push(pair);
        }
    }
    (format!("Cookie: {}\r\n", jar.join("; ")), csrf)
}

/// Turn the login on through the API, exactly as the settings page does.
///
/// The value is percent-encoded because a password with a space in it is
/// the ordinary case and a raw space in a request LINE is not a request -
/// the daemon answers nothing at all, which reads here as "the setting
/// was refused" and is nothing of the sort.
fn configure_login(port: u16, user: &str, pass: &str) {
    let enc = |v: &str| {
        v.replace('%', "%25")
            .replace(' ', "%20")
            .replace('&', "%26")
    };
    for (name, value) in [("web_username", user), ("web_password", pass)] {
        let r = http(
            port,
            &format!(
                "/api?mode=config&name={name}&value={}&apikey=fullkey&output=json",
                enc(value)
            ),
            Some(("application/json", b"")),
        );
        assert!(r.contains("\"status\":true"), "setting {name}: {r}");
    }
}

/// THE control arm. With neither half configured, nothing this item
/// added is reachable: the shell is served without a redirect, `/login`
/// sends you to it rather than presenting a form nobody can satisfy, and
/// the API answers the key exactly as it always has.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_with_no_login_behaves_exactly_as_before() {
    let (d, _dir) = daemon_with_key("weblogin-off").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let shell = req(port, "GET /", "", None);
        assert_eq!(status(&shell), 200, "the shell was not served: {shell}");
        // A bookmark to /login on an install with no login is not a dead
        // link - it is a redirect to the dashboard.
        let form = req(port, "GET /login", "", None);
        assert_eq!(status(&form), 302, "{form}");
        assert!(form.contains("Location: /"), "{form}");
        let cfg = http(
            port,
            "/api?mode=get_config&apikey=fullkey&output=json",
            None,
        );
        assert!(cfg.contains("\"web_login\":false"), "{cfg}");
        assert!(cfg.contains("\"has_web_password\":false"), "{cfg}");
        // And no cookie is ever set by any of it.
        assert!(!shell.contains("Set-Cookie"), "{shell}");
    })
    .await
    .unwrap();
}

/// The form itself: the shell is withheld, a wrong password is refused
/// with ONE message, the right one mints a session, and the session then
/// opens both the shell and the API.
#[tokio::test(flavor = "multi_thread")]
async fn a_login_gates_the_shell_and_a_session_opens_it() {
    let (d, _dir) = daemon_with_key("weblogin-on").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        configure_login(port, "owner", "correct horse");

        // The shell is not served at all - 1.2 MB of UI whose every call
        // is about to be refused is worse than a redirect in every way.
        let shell = req(port, "GET /", "", None);
        assert_eq!(status(&shell), 302, "{shell}");
        assert!(shell.contains("Location: /login"), "{shell}");
        let form = req(port, "GET /login", "", None);
        assert_eq!(status(&form), 200, "{form}");
        assert!(form.contains("data-i18n=\"login.title\""), "{form}");

        // A wrong password, and a wrong USERNAME, answer the same way:
        // saying which half was wrong tells a guesser the other half is
        // right.
        for body in [
            "username=owner&password=wrong",
            "username=nope&password=correct+horse",
        ] {
            let bad = req(port, "POST /login", "", Some(body));
            assert_eq!(status(&bad), 401, "{bad}");
            assert!(bad.contains("login.bad"), "{bad}");
            assert!(
                !bad.contains("Set-Cookie"),
                "a refusal minted a session: {bad}"
            );
        }

        let ok = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=correct+horse"),
        );
        assert_eq!(status(&ok), 200, "{ok}");
        let (jar, csrf) = cookies_of(&ok);
        assert!(jar.contains("nzbfast_session_"), "no session cookie: {ok}");
        assert!(!csrf.is_empty(), "no csrf cookie: {ok}");
        // The session id is HttpOnly; its CSRF companion deliberately is
        // not, because the pages have to read and echo it.
        assert!(ok.contains("HttpOnly"), "{ok}");
        assert!(ok.contains("SameSite=Lax"), "{ok}");

        // The cookie alone opens the SHELL (a navigation carries no
        // header and needs none - nothing there mutates).
        let shell = req(port, "GET /", &jar, None);
        assert_eq!(status(&shell), 200, "{shell}");

        // On /api it is the cookie AND the token. Without the token the
        // request is refused rather than quietly downgraded: a request
        // that has the cookie and not the token is the CSRF shape.
        let no_tok = req(port, "GET /api?mode=get_config&output=json", &jar, None);
        assert!(
            no_tok.contains("\"status\":false"),
            "a cookie with no CSRF token was accepted: {no_tok}"
        );
        let with_tok = req(
            port,
            "GET /api?mode=get_config&output=json",
            &format!("{jar}X-CSRF-Token: {csrf}\r\n"),
            None,
        );
        assert!(with_tok.contains("\"web_login\":true"), "{with_tok}");
        assert!(
            with_tok.contains("\"web_username\":\"owner\""),
            "{with_tok}"
        );
        // The hash never leaves the daemon, only the fact that one exists.
        assert!(with_tok.contains("\"has_web_password\":true"), "{with_tok}");
        assert!(
            !with_tok.contains("$argon2"),
            "the hash was echoed: {with_tok}"
        );

        // And signing out puts it back.
        let out = req(port, "POST /logout", &jar, Some(""));
        assert_eq!(status(&out), 200, "{out}");
        assert!(
            out.contains("Max-Age=0"),
            "the cookies were not cleared: {out}"
        );
        let after = req(port, "GET /", &jar, None);
        assert_eq!(
            status(&after),
            302,
            "a dropped session still opened the shell: {after}"
        );
    })
    .await
    .unwrap();
}

/// The promise this whole item rests on: an API client is not touched.
/// Sonarr and the phone remotes hold the key, send no cookie, and must
/// see a daemon that behaves as though no login form existed.
#[tokio::test(flavor = "multi_thread")]
async fn the_api_key_is_unchanged_while_a_login_is_configured() {
    let (d, _dir) = daemon_with_key("weblogin-key").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        configure_login(port, "owner", "correct horse");
        // The SAB dialect an *arr and nzb360 speak, key in the query -
        // no cookie, no token, no form.
        let q = http(port, "/api?mode=queue&apikey=fullkey&output=json", None);
        assert!(
            q.contains("\"status\":true") || q.contains("\"queue\""),
            "{q}"
        );
        // And in the header, which is what the dashboard used to send
        // and what an auth proxy injects.
        let v = req(
            port,
            "GET /api?mode=get_config&output=json",
            "X-Api-Key: fullkey\r\n",
            None,
        );
        assert!(v.contains("\"web_login\":true"), "{v}");
        // A wrong key is still a wrong key, in SAB's own words.
        let bad = http(port, "/api?mode=queue&apikey=nope&output=json", None);
        assert!(bad.contains("API Key Incorrect"), "{bad}");
        // No key at all is still refused. The login form must not have
        // opened a keyless door beside the key.
        let none = http(port, "/api?mode=queue&output=json", None);
        assert!(none.contains("API Key Required"), "{none}");
    })
    .await
    .unwrap();
}

/// The store has an expiry and it is enforced on use. Two seconds here
/// (`NZBFAST_TEST_SESSION_TTL_SECS`); fourteen days in production.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_expires() {
    let (d, _dir) = daemon_with_key("weblogin-exp").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        configure_login(port, "owner", "correct horse");
        let ok = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=correct+horse"),
        );
        let (jar, csrf) = cookies_of(&ok);
        let hdrs = format!("{jar}X-CSRF-Token: {csrf}\r\n");
        let live = req(port, "GET /api?mode=get_config&output=json", &hdrs, None);
        assert!(live.contains("\"web_login\":true"), "{live}");
        std::thread::sleep(std::time::Duration::from_secs(3));
        // Expired: the cookie is no longer a credential, so /api falls
        // back to the key - which this request does not carry.
        let dead = req(port, "GET /api?mode=get_config&output=json", &hdrs, None);
        assert!(
            dead.contains("API Key Required"),
            "an expired session still authenticated: {dead}"
        );
        // ...and the shell goes back behind the form.
        let shell = req(port, "GET /", &jar, None);
        assert_eq!(status(&shell), 302, "{shell}");
    })
    .await
    .unwrap();
}

/// Changing either half of the credential signs every browser out. A
/// password change that left the old sessions standing would have
/// revoked nothing, which is the whole reason somebody changes one.
#[tokio::test(flavor = "multi_thread")]
async fn changing_the_credential_signs_every_browser_out() {
    let (d, _dir) = daemon_with_key("weblogin-rot").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        configure_login(port, "owner", "correct horse");
        let ok = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=correct+horse"),
        );
        let (jar, csrf) = cookies_of(&ok);
        let hdrs = format!("{jar}X-CSRF-Token: {csrf}\r\n");
        assert!(
            req(port, "GET /api?mode=get_config&output=json", &hdrs, None)
                .contains("\"web_login\":true")
        );
        configure_login(port, "owner", "a different one");
        let after = req(port, "GET /api?mode=get_config&output=json", &hdrs, None);
        assert!(
            after.contains("API Key Required"),
            "the old session survived a password change: {after}"
        );
        // The new password works; the old one does not.
        let old = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=correct+horse"),
        );
        assert_eq!(status(&old), 401, "{old}");
        let new = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=a+different+one"),
        );
        assert_eq!(status(&new), 200, "{new}");

        // Clearing the username takes the whole form away, and the
        // daemon goes back to the behaviour the control arm pins.
        let r = http(
            port,
            "/api?mode=config&name=web_username&value=&apikey=fullkey&output=json",
            Some(("application/json", b"")),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let shell = req(port, "GET /", "", None);
        assert_eq!(
            status(&shell),
            200,
            "the form outlived its username: {shell}"
        );
    })
    .await
    .unwrap();
}

/// The password floor, and the one refusal a user is most likely to
/// meet. Eight characters is not security theatre here: this credential
/// is the thing in front of an install somebody has published to the
/// internet, and a four-character one reads as protection while being
/// none.
#[tokio::test(flavor = "multi_thread")]
async fn a_short_password_is_refused_and_leaves_the_login_off() {
    let (d, _dir) = daemon_with_key("weblogin-short").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=web_password&value=abc&apikey=fullkey&output=json",
            Some(("application/json", b"")),
        );
        assert!(r.contains("\"status\":false"), "{r}");
        assert!(r.contains("at least 8 characters"), "{r}");
        let cfg = http(
            port,
            "/api?mode=get_config&apikey=fullkey&output=json",
            None,
        );
        assert!(cfg.contains("\"has_web_password\":false"), "{cfg}");
    })
    .await
    .unwrap();
}

/// WHAT THE LADDER ACTUALLY DOES TO `/login`, measured rather than read.
///
/// `route_login` counts a bad credential into `note_auth_failure`, the
/// shared ladder (`AUTH_FAIL_THRESHOLD = 10` inside a 60 s window, per
/// client address). The natural reading of that - the one the follow-up
/// handoff wrote down - is that an attacker gets ten guesses a minute.
///
/// THAT READING IS WRONG, and this test is here to keep it dead. The
/// ladder is consulted AFTER the credential has been verified, and
/// its answer only picks the status code and the message. Nothing is
/// skipped, no work is saved, and above all no ANSWER changes: a correct
/// password sent by the ten-thousandth request from a blocked address
/// still mints a session. So on `/login` the ladder is a label and a log
/// line, not a limiter - it does not bound the guess rate at all, and it
/// equally cannot lock the owner out of their own dashboard.
///
/// Both halves are asserted below, because both are load-bearing and
/// they pull in opposite directions: the first is the security gap, the
/// second is the property any stricter ladder would have to keep.
#[tokio::test(flavor = "multi_thread")]
async fn the_ladder_labels_a_guess_but_never_refuses_one() {
    let (d, _dir) = daemon_with_key("weblogin-ladder").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        configure_login(port, "owner", "correct horse");

        // Where the 429 falls. The count is incremented and THEN
        // compared, so the threshold attempt is itself refused: nine
        // 401s, and the tenth is the first 429.
        let mut first_429 = 0usize;
        for attempt in 1..=14usize {
            let bad = req(
                port,
                "POST /login",
                "",
                Some("username=owner&password=wrong"),
            );
            let st = status(&bad);
            if st == 429 {
                if first_429 == 0 {
                    first_429 = attempt;
                }
                assert!(bad.contains("login.blocked"), "attempt {attempt}: {bad}");
            } else {
                assert_eq!(st, 401, "attempt {attempt}: {bad}");
                assert!(bad.contains("login.bad"), "attempt {attempt}: {bad}");
            }
            assert!(
                !bad.contains("Set-Cookie"),
                "attempt {attempt} minted a session: {bad}"
            );
        }
        assert_eq!(
            first_429,
            nzbfast_daemon::httputil::AUTH_FAIL_THRESHOLD as usize,
            "the 429 did not fall on the threshold attempt"
        );

        // THE MEASUREMENT. The address is well past the threshold and
        // every further wrong password is answered 429 - and the RIGHT
        // password, from that same blocked address, is still checked and
        // still wins. An attacker's guess is never declined; it is only
        // labelled differently on the way out.
        let still_blocked = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=wrong"),
        );
        assert_eq!(status(&still_blocked), 429, "{still_blocked}");
        let ok = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=correct+horse"),
        );
        assert_eq!(
            status(&ok),
            200,
            "a blocked address was refused a CORRECT password - the ladder \
             has become a lockout and this test is the wrong shape for it: {ok}"
        );
        let (jar, _csrf) = cookies_of(&ok);
        assert!(
            jar.contains("nzbfast_session_"),
            "the winning guess minted no session: {ok}"
        );
        // ...and the session it minted is real, not a consolation 200.
        let shell = req(port, "GET /", &jar, None);
        assert_eq!(
            status(&shell),
            200,
            "the session from a blocked address did not open the shell: {shell}"
        );
    })
    .await
    .unwrap();
}

/// The second half of the same finding, and the one that is specific to
/// the deployment TODO 19 was built for: the bucket is keyed on
/// `req.remote_addr()` and nothing else, so behind a reverse proxy every
/// request on earth shares ONE bucket.
///
/// Every connection in this test comes from 127.0.0.1, which is exactly
/// the shape a proxied install has - two unrelated clients, one address.
/// So the attacker's knocking does move the owner's counter, and the
/// owner DOES see the 429 label. What the owner does not see is a
/// refusal: their correct password is checked and accepted from the
/// shared, blocked address. That is the property a stricter ladder has
/// to preserve, and it is why "honour X-Forwarded-For" is not a free
/// improvement - it is the decision underneath this one.
#[tokio::test(flavor = "multi_thread")]
async fn one_address_is_one_bucket_for_every_client_behind_it() {
    let (d, _dir) = daemon_with_key("weblogin-bucket").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        configure_login(port, "owner", "correct horse");
        // Client A: the attacker, spending the whole window.
        for _ in 0..nzbfast_daemon::httputil::AUTH_FAIL_THRESHOLD {
            let _ = req(
                port,
                "POST /login",
                "",
                Some("username=owner&password=wrong"),
            );
        }
        // Client B: the owner, a separate connection, who has typed
        // nothing wrong. Their FIRST mistyped password is answered 429
        // rather than 401 - they inherited the attacker's count, which
        // is the shared-bucket effect made visible.
        let typo = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=wrng"),
        );
        assert_eq!(
            status(&typo),
            429,
            "a fresh client did not inherit the shared bucket: {typo}"
        );
        // And their correct password still works, because the ladder
        // never refuses a credential that is right.
        let ok = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=correct+horse"),
        );
        assert_eq!(
            status(&ok),
            200,
            "the owner was locked out of their own dashboard by a \
             neighbour behind the same proxy address: {ok}"
        );
    })
    .await
    .unwrap();
}

/// The refusals chosen for a PASSWORD, end to end: the settings page
/// gets a reason it can show, and the login stays OFF rather than being
/// half-configured behind a credential that falls to a spray.
///
/// The reasoning is the measurement in the two tests above plus
/// `research/LOGIN-RATE-LIMIT-MEASURED-2026-09-20.md`. The ladder does
/// not bound an attacker's guess rate, so what does is the credential,
/// so the credentials a spray finds in under a second are refused where
/// they are set.
#[tokio::test(flavor = "multi_thread")]
async fn a_sprayed_password_is_refused_and_leaves_the_login_off() {
    let (d, _dir) = daemon_with_key("weblogin-weak").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        // Long enough to clear the eight-character floor, and on the
        // first page of every spray list there is.
        for pw in ["password", "12345678", "aaaaaaaa", "changeme"] {
            let r = http(
                port,
                &format!(
                    "/api?mode=config&name=web_password&value={pw}&apikey=fullkey&output=json"
                ),
                Some(("application/json", b"")),
            );
            assert!(r.contains("\"status\":false"), "{pw} was accepted: {r}");
            assert!(
                r.contains("pick something else"),
                "the refusal gave no reason: {r}"
            );
        }
        // Nothing was half-set by any of that.
        let cfg = http(
            port,
            "/api?mode=get_config&apikey=fullkey&output=json",
            None,
        );
        assert!(cfg.contains("\"has_web_password\":false"), "{cfg}");
        // And an ordinary password is still accepted, which is the half
        // that keeps this from being a rule nobody can satisfy.
        configure_login(port, "owner", "correct horse");
        let ok = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=correct+horse"),
        );
        assert_eq!(status(&ok), 200, "{ok}");
    })
    .await
    .unwrap();
}

/// The SECOND copy of the redirect: `/wall`.
///
/// `serve/http.rs` applies the gate twice - once for `/` and
/// `/index.html`, once for `/wall` and `/wall/` - and the two arms are
/// separate copies of the same four lines.
/// `a_login_gates_the_shell_and_a_session_opens_it` above holds the
/// first; until this test the second was held by nothing at all, so a
/// lane tidying that router could have deleted it (or moved it below the
/// `respond_shell` call) with every gate in this repo still green, while
/// an unauthenticated visitor got the poster wall - which on an indexed
/// install is the user's library, titles and artwork.
///
/// BOTH spellings, because the router matches both and a test that drives
/// one leaves the other free to rot.
///
/// WHAT THIS DOES NOT STAND UP: an index with rows in it. The route is
/// `#[cfg(feature = "indexer")]` and `respond_shell(Shell::Wall)` serves
/// the embedded page whatever the database holds, so the gate - which is
/// the subject here - is reached identically on an empty index and
/// building one (the `tests/integration/wall.rs` machinery: a mock NNTP
/// server, an OverEntry corpus and a scan) would be several hundred lines
/// to change nothing this test reads.
#[cfg(feature = "indexer")]
#[tokio::test(flavor = "multi_thread")]
async fn a_login_gates_the_poster_wall_too() {
    let (d, _dir) = daemon_with_key("weblogin-wall").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        // THE control arm, before anything is configured: the wall is a
        // plain page on an install with no login, under either spelling,
        // and nothing about this item touches it.
        for path in ["/wall", "/wall/"] {
            let open = req(port, &format!("GET {path}"), "", None);
            assert_eq!(status(&open), 200, "{path} was not served: {open}");
            assert!(
                !open.contains("Location:"),
                "{path} redirected with no login configured: {open}"
            );
            assert!(
                !open.contains("Set-Cookie"),
                "{path} minted something with no login configured: {open}"
            );
        }

        configure_login(port, "owner", "correct horse");

        // Now withheld, and sent to the form rather than to just any
        // "not a 200" - a redirect to the wrong place would satisfy a
        // status-only assertion and leak the page to whatever it named.
        for path in ["/wall", "/wall/"] {
            let gated = req(port, &format!("GET {path}"), "", None);
            assert_eq!(
                status(&gated),
                302,
                "{path} served the wall to a stranger: {gated}"
            );
            assert!(
                gated.contains("Location: /login"),
                "{path} redirected somewhere other than the form: {gated}"
            );
        }

        // And the session opens it, both ways round. A navigation carries
        // no CSRF token and needs none: nothing behind the wall mutates.
        let ok = req(
            port,
            "POST /login",
            "",
            Some("username=owner&password=correct+horse"),
        );
        assert_eq!(status(&ok), 200, "{ok}");
        let (jar, _csrf) = cookies_of(&ok);
        for path in ["/wall", "/wall/"] {
            let served = req(port, &format!("GET {path}"), &jar, None);
            assert_eq!(
                status(&served),
                200,
                "a live session did not open {path}: {served}"
            );
        }
    })
    .await
    .unwrap();
}

/// "Sign out every browser" - `mode=config&name=web_logout_all`.
///
/// `changing_the_credential_signs_every_browser_out` above is NOT this:
/// it moves `web_password` and watches the sessions fall over as a
/// consequence, and never sends this mode. The button in the Settings
/// security card sends exactly this, and until this test nothing in
/// `crates/*/tests/`, `journeys/` or any tool did.
///
/// TWO sessions, not one, is what makes the test worth writing: with one
/// session "dropped the whole table" and "dropped the caller" are the
/// same observation.
///
/// And the SAME-SITE refusal, which is the half that actually matters:
/// it is what stops an `<img src=".../api?mode=config&name=web_logout_all
/// &value=1">` on a page the owner happens to visit from signing them out
/// of their own dashboard. A happy-path-only test would pass with that
/// gate deleted.
#[tokio::test(flavor = "multi_thread")]
async fn signing_every_browser_out_is_one_mode_and_a_same_site_gate() {
    // Not the shared two-second TTL: this test holds two sessions open
    // across a dozen round trips and asserts a COUNT over them.
    let (d, _dir) = daemon_with_key_ttl("weblogin-out", "600").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        configure_login(port, "owner", "correct horse");

        // Two browsers.
        let sign_in = || {
            let r = req(
                port,
                "POST /login",
                "",
                Some("username=owner&password=correct+horse"),
            );
            assert_eq!(status(&r), 200, "{r}");
            cookies_of(&r)
        };
        let (jar_a, csrf_a) = sign_in();
        let (jar_b, csrf_b) = sign_in();
        assert_ne!(jar_a, jar_b, "the second sign-in reused the first session");
        let hdrs_a = format!("{jar_a}X-CSRF-Token: {csrf_a}\r\n");
        let hdrs_b = format!("{jar_b}X-CSRF-Token: {csrf_b}\r\n");

        // Read the count over the KEY, so the observation does not depend
        // on the sessions it is counting.
        let sessions = || {
            let cfg = http(
                port,
                "/api?mode=get_config&apikey=fullkey&output=json",
                None,
            );
            for n in [0usize, 1, 2] {
                if cfg.contains(&format!("\"web_sessions\":{n}")) {
                    return n;
                }
            }
            panic!("no readable web_sessions in: {cfg}");
        };
        assert_eq!(sessions(), 2, "two sign-ins did not make two sessions");
        for (who, h) in [("a", &hdrs_a), ("b", &hdrs_b)] {
            let live = req(port, "GET /api?mode=get_config&output=json", h, None);
            assert!(live.contains("\"web_login\":true"), "session {who}: {live}");
        }

        // THE CONFUSED DEPUTY. A browser on somebody else's page labels
        // the request `cross-site`, and this one carries a credential that
        // authenticates - so it reaches the arm and must be turned away
        // THERE. Both sessions must still be standing afterwards: a
        // refusal that had already emptied the table would have refused
        // nothing.
        let drive_by = req(
            port,
            "GET /api?mode=config&name=web_logout_all&value=1&apikey=fullkey&output=json",
            "Sec-Fetch-Site: cross-site\r\n",
            None,
        );
        assert!(
            drive_by.contains("\"status\":false"),
            "a cross-site request signed every browser out: {drive_by}"
        );
        assert_eq!(sessions(), 2, "a refused request dropped sessions anyway");
        assert!(
            req(port, "GET /api?mode=get_config&output=json", &hdrs_a, None)
                .contains("\"web_login\":true"),
            "a refused cross-site logout killed session a"
        );

        // The real press of the button: the owner's own tab, same-origin,
        // cookie and token.
        let out = req(
            port,
            "GET /api?mode=config&name=web_logout_all&value=1&output=json",
            &format!("{hdrs_a}Sec-Fetch-Site: same-origin\r\n"),
            None,
        );
        assert!(
            out.contains("\"status\":true"),
            "the owner's own tab was refused: {out}"
        );

        // EVERY browser, not just the caller. b never sent a thing.
        assert_eq!(sessions(), 0, "the session table was not emptied");
        for (who, h) in [("a", &hdrs_a), ("b", &hdrs_b)] {
            // With the session gone the cookie is not a credential, so
            // /api falls back to the key - which these do not carry.
            let dead = req(port, "GET /api?mode=get_config&output=json", h, None);
            assert!(
                dead.contains("API Key Required"),
                "session {who} outlived web_logout_all: {dead}"
            );
            let shell = req(port, "GET /", h, None);
            assert_eq!(
                status(&shell),
                302,
                "session {who} still opened the shell: {shell}"
            );
        }
    })
    .await
    .unwrap();
}

/// THE CONCURRENCY CAP: open question 3 of
/// `research/LOGIN-RATE-LIMIT-MEASURED-2026-09-20.md`, taken on 21 Sep
/// 2026.
///
/// An unauthenticated POST to `/login` allocates 19 MiB and burns ~16 ms
/// of CPU on the shared worker pool. Until this landed, nothing bounded
/// how many of those ran at once, so eight wrong passwords sent together
/// took all eight HTTP workers and 152 MiB with them, and every other
/// caller - the dashboard's own polling included - waited behind the
/// flood.
///
/// Eight simultaneous wrong passwords, against a cap of four. The count
/// is the measurement: exactly `VERIFY_PERMITS` of them are VERIFIED (a
/// 401 from the ladder), and the rest are answered 503 with
/// `Retry-After` without their password being looked at. A 503 is not a
/// refusal of a credential and is not counted into the ladder, which is
/// why the ladder's own numbers below are about the four and not the
/// eight.
///
/// Concurrency is made observable with `NZBFAST_TEST_VERIFY_HOLD_MS`
/// rather than raced for: a real verification is ~16 ms, far too short
/// for eight requests to reliably overlap on a loaded box, and a test
/// that has to win a race to see the property is a test that goes green
/// when the property is gone. The hook holds the PERMIT, so what it
/// lengthens is exactly the window the cap is about.
///
/// Threads report through a channel and are collected with
/// `recv_timeout`, never `join` (memory topic
/// `nzbfast-detached-worker-lost-wakeup`): a cap that wedged would then
/// fail this test with a message rather than hang the daemon suite.
#[tokio::test(flavor = "multi_thread")]
async fn only_four_password_checks_run_at_once_and_the_rest_are_asked_to_retry() {
    // Long enough that every one of the eight requests is certainly at
    // the gate while the first four hold it - three seconds against the
    // 250 ms wait the cap uses. It costs the test three seconds and buys
    // determinism on a box at 3x oversubscription.
    const HOLD_MS: u64 = 3000;
    let (d, _dir) = daemon_with_key_env(
        "weblogin-cap",
        "600",
        &[("NZBFAST_TEST_VERIFY_HOLD_MS", &HOLD_MS.to_string())],
    )
    .await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        configure_login(port, "owner", "correct horse");
        let permits = nzbfast_daemon::websession::VERIFY_PERMITS;
        let fired = permits * 2;

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(fired));
        let (tx, rx) = std::sync::mpsc::channel::<(usize, String)>();
        for i in 0..fired {
            let (b, tx) = (barrier.clone(), tx.clone());
            std::thread::spawn(move || {
                b.wait();
                let r = req(
                    port,
                    "POST /login",
                    "",
                    Some("username=owner&password=wrong"),
                );
                let _ = tx.send((i, r));
            });
        }
        drop(tx);

        let mut verified = 0usize;
        let mut busy = 0usize;
        for _ in 0..fired {
            let (i, r) = rx
                .recv_timeout(std::time::Duration::from_secs(60))
                .expect("a /login POST never answered - the cap has wedged");
            match status(&r) {
                503 => {
                    busy += 1;
                    assert!(
                        r.contains("login.busy"),
                        "request {i} was 503 with the wrong body: {r}"
                    );
                    // The header is the whole difference between "ask me
                    // again" and "go away": a machine client reads it.
                    assert!(
                        r.to_ascii_lowercase().contains("retry-after: 1"),
                        "request {i} was 503 with no Retry-After: {r}"
                    );
                    assert!(
                        !r.contains("login.bad") && !r.contains("login.blocked"),
                        "request {i} had its password judged as well as refused: {r}"
                    );
                }
                401 => {
                    verified += 1;
                    assert!(r.contains("login.bad"), "request {i}: {r}");
                }
                other => panic!("request {i} answered {other}: {r}"),
            }
            assert!(
                !r.contains("Set-Cookie"),
                "request {i} minted a session: {r}"
            );
        }
        assert_eq!(
            verified, permits,
            "{verified} password checks ran at once against a cap of {permits} \
             (and {busy} were asked to retry)"
        );
        assert_eq!(busy, fired - permits, "the rest were not asked to retry");
    })
    .await
    .unwrap();
}

/// THE PROPERTY THE CAP HAD TO KEEP, and the reason it is a short WAIT
/// and never a window: **a correct credential is never refused, from any
/// address, in any state.**
///
/// Everything the note above refused - pre-checking the ladder, a global
/// floor per unit time - was refused because behind a reverse proxy
/// every client shares one address, so a limiter that remembers an
/// address holds the OWNER out of their own dashboard while an attacker
/// knocks. This one remembers nothing: the only state is how many
/// verifications are running this instant, and the owner's correct
/// password is checked and accepted in the middle of a flood coming from
/// that very same address.
///
/// No hold hook here, deliberately: this leg is about the REAL cost of a
/// verification (~16 ms), because the question it answers is whether a
/// permit comes free fast enough for a human at a form. A 503 on the way
/// is allowed and is not a failure - the login page retries it by itself
/// and so does this test - but a 401 or a 429 for the right password
/// would be the lockout this whole design exists to avoid, and is
/// asserted against on every attempt.
#[tokio::test(flavor = "multi_thread")]
async fn the_owner_still_signs_in_while_that_same_address_floods_the_door() {
    let (d, _dir) = daemon_with_key_ttl("weblogin-cap-owner", "600").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        configure_login(port, "owner", "correct horse");

        // The flood: every worker the pool has, guessing, from the same
        // address the owner will sign in from. `until` stops it rather
        // than a join, so the test cannot be held open by a thread that
        // is mid-request when the assertions finish.
        let until = std::time::Instant::now() + std::time::Duration::from_secs(6);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
        for _ in 0..8 {
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                while std::time::Instant::now() < until {
                    let _ = req(
                        port,
                        "POST /login",
                        "",
                        Some("username=owner&password=wrong"),
                    );
                }
            });
        }
        barrier.wait();

        let started = std::time::Instant::now();
        let mut waits = Vec::new();
        let mut ok = None;
        // Up to eight tries, the same shape the login page's one retry
        // has: only a 503 is retried, and only after a pause a permit
        // turns over many times inside.
        for attempt in 1..=8usize {
            let t0 = std::time::Instant::now();
            let r = req(
                port,
                "POST /login",
                "",
                Some("username=owner&password=correct+horse"),
            );
            waits.push(t0.elapsed());
            match status(&r) {
                200 => {
                    ok = Some(r);
                    break;
                }
                503 => {
                    assert!(r.contains("login.busy"), "attempt {attempt}: {r}");
                    std::thread::sleep(std::time::Duration::from_millis(400));
                }
                other => panic!(
                    "the CORRECT password was answered {other} on attempt {attempt} - \
                     the cap has become a lockout, which is the one thing it must \
                     never be: {r}"
                ),
            }
        }
        let elapsed = started.elapsed();
        let ok = ok.unwrap_or_else(|| {
            panic!("the owner never got in under a flood, after {elapsed:?} and {waits:?}")
        });
        let (jar, _csrf) = cookies_of(&ok);
        assert!(
            jar.contains("nzbfast_session_"),
            "no session was minted: {ok}"
        );
        // ...and it is a real session, not a consolation 200.
        let shell = req(port, "GET /", &jar, None);
        assert_eq!(
            status(&shell),
            200,
            "the minted session does not open the shell: {shell}"
        );
        // Generous on purpose: this is a liveness bound, not a timing
        // measurement, and the box these run on is routinely at 3x
        // oversubscription. The number worth reading is in the note.
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "the owner took {elapsed:?} to sign in under a flood: {waits:?}"
        );
    })
    .await
    .unwrap();
}
