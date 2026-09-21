//! TODO 19 (public request #4): the dashboard's optional username and
//! password, the server-side session store behind them, and the cookie
//! plumbing both need.
//!
//! **This is a DASHBOARD credential layered over the API key, never a
//! replacement for it.** Sonarr, Radarr, nzb360 and LunaSea authenticate
//! with the key and will never drive a form (§18: nzb360 talks the SAB
//! dialect only), so every key-shaped door in the router keeps working
//! byte-for-byte whatever is configured here. With neither a username nor
//! a password set, nothing in this module is ever reached and the daemon
//! behaves exactly as it did before it existed.
//!
//! **Why a cookie needs more care than the key does.** The key is sent
//! explicitly by the caller, which is precisely what makes it immune to
//! CSRF: a page you merely visit cannot add an `X-Api-Key` header. A
//! cookie is sent by the browser AUTOMATICALLY, so introducing one
//! introduces an exposure we did not have - a cross-site form POST, or an
//! `<img src="…/api?mode=shutdown">`, arrives carrying the session. Three
//! things answer that, and the router applies all three to every request
//! authenticated by cookie:
//!
//!   1. `SameSite=Lax` on the cookie itself, which stops a modern browser
//!      attaching it to a cross-site POST or sub-resource GET at all;
//!   2. the same-site check the credential-mutation routes already use
//!      (`Sec-Fetch-Site`, and `Origin` against `Host`);
//!   3. a per-session CSRF token that must arrive in `X-CSRF-Token` and
//!      match the SERVER's record of it.
//!
//! (3) is the load-bearing one, and it is stronger than plain double
//! submit: the comparison is against the stored session, not against a
//! second cookie, so an attacker who can set cookies on the origin still
//! cannot forge a request. The token is published to the page in a
//! SECOND, readable cookie, because the pages are static files with no
//! server-side templating and both of them (dashboard and wall) need it.
//! The session id itself stays `HttpOnly`, so page script never sees it
//! and an XSS cannot exfiltrate a long-lived credential.
//!
//! **The cookie name carries the port** (`nzbfast_session_6789`). Cookies
//! are scoped by HOST and ignore the port, so two daemons on one machine -
//! the ordinary shape here, a live install on :6789 and a scratch one on a
//! test port - would otherwise clobber each other's session on every
//! login. The desktop surfaces already treat the origin INCLUDING the port
//! as the identity (memory topic `nzbfast-desktop-surfaces-index`), and
//! this keeps the cookie agreeing with them.

use super::*;

/// How long a session lives without being used, in seconds.
///
/// Fourteen days, and SLIDING: the expiry is pushed out on every
/// authenticated request, so somebody who keeps a dashboard tab open is
/// never logged out mid-use, and a browser that has not been back for a
/// fortnight has to sign in again. A downloader is not a bank; the point
/// of the form is that the origin is not keyless when it is published,
/// not that the owner re-types a password every morning.
pub const SESSION_TTL_SECS: u64 = 14 * 24 * 3600;

/// The live TTL. Production is [`SESSION_TTL_SECS`]; the test hook
/// shortens it so an expiry can be observed in a test that finishes,
/// rather than mocked out of the store and proved about nothing. Same
/// shape as `index_tip_floor_secs` - unset reads exactly as the constant.
pub fn session_ttl_secs() -> u64 {
    std::env::var("NZBFAST_TEST_SESSION_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(SESSION_TTL_SECS)
}

/// Ceiling on live sessions, so the store itself cannot be the attack.
///
/// A login costs an Argon2id verification, which is deliberately
/// expensive, so this is not reached by anything cheap - but a correct
/// password in a script loop would otherwise grow the map without bound.
/// At the cap the oldest entry is evicted, which is the right failure:
/// the owner's newest browser always gets in.
pub const SESSION_MAX: usize = 64;

/// One signed-in browser.
pub struct Session {
    /// Absolute deadline, pushed out on every use.
    pub expires: Instant,
    /// This session's CSRF token, published to the page in the readable
    /// companion cookie and required back in `X-CSRF-Token`.
    pub csrf: String,
}

/// The live sessions, by id.
#[derive(Default)]
pub struct Sessions(pub Mutex<std::collections::HashMap<String, Session>>);

/// What a presented cookie proved.
pub enum SessionCheck {
    /// No session cookie at all, or one naming a session that has
    /// expired or been logged out. Falls back to the key.
    None,
    /// A live session, but the request did not carry its CSRF token.
    /// The cookie proves nothing on its own - a request that HAS the
    /// cookie and not the token is the CSRF shape itself - so this
    /// authenticates nothing. It is distinct from [`Self::None`] so the
    /// caller can say so; the router treats both as "this credential did
    /// not authenticate", which leaves a key presented alongside a stale
    /// cookie still working.
    NoCsrf,
    /// A live session, CSRF token checked. Full access.
    Ok,
}

impl Sessions {
    /// Mint a session and return `(id, csrf)`.
    pub fn create(&self) -> Option<(String, String)> {
        let id = crate::bootstrap::random_apikey()?;
        let csrf = crate::bootstrap::random_apikey()?;
        let mut map = self.0.lock_ok();
        let now = Instant::now();
        map.retain(|_, s| s.expires > now);
        while map.len() >= SESSION_MAX {
            // Oldest deadline first. Every live session has the same
            // TTL, so the oldest deadline is the least recently used.
            let Some(victim) = map
                .iter()
                .min_by_key(|(_, s)| s.expires)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            map.remove(&victim);
        }
        map.insert(
            id.clone(),
            Session {
                expires: now + std::time::Duration::from_secs(session_ttl_secs()),
                csrf: csrf.clone(),
            },
        );
        Some((id, csrf))
    }

    /// Check a presented id, and slide its expiry when it is live.
    ///
    /// `csrf` is whatever arrived in `X-CSRF-Token`. The comparison is
    /// `ct_eq` like every other credential comparison in this tree.
    pub fn check(&self, id: Option<&str>, csrf: Option<&str>) -> SessionCheck {
        let Some(id) = id.filter(|i| !i.is_empty()) else {
            return SessionCheck::None;
        };
        let mut map = self.0.lock_ok();
        let now = Instant::now();
        let Some(s) = map.get_mut(id) else {
            return SessionCheck::None;
        };
        if s.expires <= now {
            map.remove(id);
            return SessionCheck::None;
        }
        if !csrf.is_some_and(|t| crate::httputil::ct_eq(t, &s.csrf)) {
            return SessionCheck::NoCsrf;
        }
        s.expires = now + std::time::Duration::from_secs(session_ttl_secs());
        SessionCheck::Ok
    }

    /// Whether this id names a live session, WITHOUT the CSRF check and
    /// without sliding it.
    ///
    /// The read-only media doors (`/m3u`, `/preview`, `/getnzb`) take
    /// this: a `<video src=…>` cannot carry a custom header, so demanding
    /// the token there would mean the player simply does not play. They
    /// are reads, a cross-site page cannot see the bytes (no
    /// `Access-Control-Allow-Credentials` is ever sent), and nothing
    /// behind them mutates.
    pub fn is_live(&self, id: Option<&str>) -> bool {
        let Some(id) = id.filter(|i| !i.is_empty()) else {
            return false;
        };
        let map = self.0.lock_ok();
        map.get(id).is_some_and(|s| s.expires > Instant::now())
    }

    /// Log one browser out.
    pub fn drop_one(&self, id: Option<&str>) {
        if let Some(id) = id {
            self.0.lock_ok().remove(id);
        }
    }

    /// Log EVERY browser out. Run whenever the password or the username
    /// changes: a credential change that leaves old sessions standing has
    /// not revoked anything, which is the whole reason somebody changes
    /// one.
    pub fn drop_all(&self) {
        self.0.lock_ok().clear();
    }

    /// How many sessions are live right now (expired ones are not
    /// counted, and are swept while we are here).
    pub fn live_count(&self) -> usize {
        let mut map = self.0.lock_ok();
        let now = Instant::now();
        map.retain(|_, s| s.expires > now);
        map.len()
    }
}

/// Is there a login form at all?
///
/// BOTH halves, and that is the whole rule: a username with no password
/// would be a form nobody can satisfy, and a password with no username
/// would be a form with nothing to type in the first box. Half-configured
/// therefore means OFF, and the daemon behaves exactly as it did before
/// this item existed. One function so the router, `get_config` and the
/// startup banner cannot each decide it differently.
pub fn login_on(d: &Daemon) -> bool {
    d.web_username.lock_ok().is_some() && d.web_password.lock_ok().is_some()
}

/// Hash a password for storage: Argon2id at the crate's defaults, with a
/// per-password random salt, in PHC string format.
///
/// `argon2` is already a dependency of the engine (nzbkit-base uses it
/// for archive key derivation), so this adds no new licence surface for
/// `cargo deny` to judge. PHC format means the parameters travel WITH the
/// hash, so raising them later re-verifies old hashes unchanged.
pub fn hash_password(pw: &str) -> std::result::Result<String, String> {
    use argon2::password_hash::PasswordHasher;
    argon2::Argon2::default()
        .hash_password(pw.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Check a password against a stored PHC hash.
///
/// A hash that will not PARSE answers false rather than erroring: the
/// value comes out of settings.json, which a user may have hand-edited,
/// and the honest behaviour for a corrupt credential is "this password
/// does not match" and not a 500.
pub fn verify_password(pw: &str, stored: &str) -> bool {
    use argon2::password_hash::PasswordVerifier;
    // The `PasswordVerifier<str>` impl parses the PHC string itself and
    // answers `Err` on a value it cannot read, which is the arm this
    // comment is about.
    argon2::Argon2::default()
        .verify_password(pw.as_bytes(), stored)
        .is_ok()
}

/// TODO 19, open question 3 of
/// `research/LOGIN-RATE-LIMIT-MEASURED-2026-09-20.md`, taken on 21 Sep
/// 2026: how many Argon2id verifications may be running at once, across
/// every `/login` POST the daemon is handling.
///
/// **Why there is a number here at all.** A verification is `m=19456`
/// KiB at the argon2 crate defaults - 19 MiB allocated and ~16 ms of CPU
/// burnt, measured in the note above - and it runs for an
/// UNAUTHENTICATED caller, on the shared HTTP worker pool. Without a cap,
/// every one of the eight workers `spawn_http_workers` starts can be
/// holding 19 MiB of KDF scratch at the same time purely because
/// somebody posted eight wrong passwords at once.
///
/// **Why FOUR: half the worker pool, so at most half of it can be inside
/// the KDF at any instant.** A/B measured 21 Sep 2026 against a release
/// build with this constant raised past the pool size, same box, same
/// 128-thread flood of wrong passwords for 20 s: capped, the daemon
/// burnt 3.39 cores and peaked at 184 MiB RSS; uncapped, 5.06 to 7.21
/// cores and 259 to 292 MiB. Four is also far more parallelism than a
/// real sign-in needs - a human logging in is one verification - so the
/// number binds under a flood and nowhere else, and raising it buys an
/// attacker throughput and the owner nothing.
///
/// **What it does NOT buy, measured on the same rig, so nobody claims it
/// later.** It does not keep HTTP workers free. A worker WAITING for a
/// permit is still a busy worker, and 128 queued connections saturate an
/// eight-worker pool whatever this number says: `mode=version` went from
/// a 0.3 ms median to a 601 ms one under that flood WITH the cap in
/// place. Bounding what a flood does to the pool is a different item
/// from bounding what it does to memory and CPU, and this is the second
/// one only.
pub const VERIFY_PERMITS: usize = 4;

/// How long a `/login` POST waits for one of [`VERIFY_PERMITS`] before it
/// is answered `503` instead.
///
/// **This is a WAIT, never a window.** The note above refuses every
/// per-address and per-window limiter, because behind a reverse proxy
/// all clients share one address and a limiter with a window holds the
/// OWNER out of their own dashboard. Nothing here remembers an address,
/// a count or a timestamp past the end of the request: the only state is
/// how many verifications are running THIS INSTANT, and it falls to zero
/// on its own the moment they finish.
///
/// **The property to keep, and the one line to check any change of this
/// code against:** a correct credential is never refused, from any
/// address, in any state, except for the milliseconds a permit takes to
/// free. A `503` is not a refusal of the credential - it says "ask me
/// again", it carries `Retry-After`, and the login page retries it by
/// itself. The credential is not even looked at, so no guess is
/// consumed, nothing is counted, and the next attempt from that same
/// caller starts from exactly where it would have anyway.
///
/// 250 ms, because a verification is ~16 ms: a permit turns over roughly
/// fifteen times inside the wait, so under anything but a deliberate
/// flood the wait is not reached at all.
pub const VERIFY_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// The in-flight counter behind [`VERIFY_PERMITS`], and its waiters.
///
/// A plain `Mutex<usize>` + `Condvar` rather than a dependency: this is
/// one counter with one condition, and the tree has no semaphore crate
/// to reach for.
struct VerifyGate {
    /// Verifications running right now. Never above [`VERIFY_PERMITS`].
    running: Mutex<usize>,
    /// Signalled by every release, so one waiter wakes per permit freed.
    freed: std::sync::Condvar,
}

static VERIFY_GATE: std::sync::LazyLock<VerifyGate> = std::sync::LazyLock::new(|| VerifyGate {
    running: Mutex::new(0),
    freed: std::sync::Condvar::new(),
});

/// A held permit. Releasing is the `Drop`, so an early return or a panic
/// inside the verification cannot leak one - a leaked permit here would
/// shrink the cap permanently and end with a daemon that answers 503 to
/// every sign-in forever.
struct VerifyPermit;

impl Drop for VerifyPermit {
    fn drop(&mut self) {
        let mut n = VERIFY_GATE.running.lock_ok();
        *n = n.saturating_sub(1);
        // One waiter, not all of them: exactly one permit came free.
        VERIFY_GATE.freed.notify_one();
    }
}

impl VerifyPermit {
    /// Take a permit, waiting at most [`VERIFY_WAIT`] for one. `None`
    /// means the caller should be answered `503`, having had its
    /// credential neither read nor counted.
    fn acquire() -> Option<Self> {
        let deadline = Instant::now() + VERIFY_WAIT;
        let mut n = VERIFY_GATE.running.lock_ok();
        loop {
            if *n < VERIFY_PERMITS {
                *n += 1;
                return Some(Self);
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            // `wait_timeout` and not `wait`: the timeout IS the feature.
            // The guard comes back either way, and a spurious wakeup
            // re-tests the condition at the top of the loop, which is
            // why this is a loop and not an `if`.
            let (guard, timed_out) = VERIFY_GATE
                .freed
                .wait_timeout(n, left)
                .unwrap_or_else(|e| e.into_inner());
            n = guard;
            if timed_out.timed_out() && *n >= VERIFY_PERMITS {
                return None;
            }
        }
    }
}

/// What [`verify_password_capped`] did.
pub enum VerifyOutcome {
    /// The verification ran. `true` means the password matched.
    Checked(bool),
    /// No permit came free inside [`VERIFY_WAIT`]. The password was not
    /// looked at, so this says nothing whatever about it.
    Busy,
}

/// [`verify_password`] behind the concurrency cap.
///
/// This is the entry point `/login` uses, and the plain
/// [`verify_password`] is left for the call sites that are not a public,
/// unauthenticated door: a settings write that hashes a NEW password is
/// already behind the API key, and the unit tests verify hashes they
/// just made.
pub fn verify_password_capped(pw: &str, stored: &str) -> VerifyOutcome {
    let Some(_permit) = VerifyPermit::acquire() else {
        return VerifyOutcome::Busy;
    };
    // The test hook, and the only reason it exists: the cap is a
    // property about what OVERLAPS, and a real verification is ~16 ms,
    // which is far too short for a test to reliably have four of them in
    // flight at once on a loaded box. Holding the permit for a named
    // number of milliseconds makes the overlap deterministic, so the
    // daemon test can count how many verifications ran together rather
    // than racing to observe them. Unset - production, always - this
    // reads as exactly no sleep at all, on the same shape as
    // `session_ttl_secs` above.
    if let Some(ms) = std::env::var("NZBFAST_TEST_VERIFY_HOLD_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    VerifyOutcome::Checked(verify_password(pw, stored))
    // `_permit` drops HERE, before the caller mints a session: the
    // permit covers the KDF and nothing else, so a successful sign-in
    // does not hold the cap while it writes cookies.
}

/// This daemon's session cookie name. See the module header for why the
/// port is in it.
pub fn session_cookie(port: u16) -> String {
    format!("nzbfast_session_{port}")
}

/// The readable companion carrying the CSRF token.
pub fn csrf_cookie(port: u16) -> String {
    format!("nzbfast_csrf_{port}")
}

/// One cookie's value out of a `Cookie:` header.
///
/// Deliberately hand-rolled and deliberately strict: split on `;`, then
/// on the FIRST `=`, and compare the name exactly. A cookie value may
/// contain `=` (base64 padding), which is why only the first one splits.
pub fn cookie_value(req: &tiny_http::Request, name: &str) -> Option<String> {
    let raw = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Cookie"))?
        .value
        .as_str()
        .to_string();
    for part in raw.split(';') {
        let part = part.trim();
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        if k.trim() == name {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// The `X-CSRF-Token` header, if the caller sent one.
pub fn csrf_header(req: &tiny_http::Request) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv("X-CSRF-Token"))
        .map(|h| h.value.as_str().trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The two `Set-Cookie` values a successful login answers with.
///
/// `Max-Age` is the TTL as of the LOGIN and does not slide with the
/// server-side expiry, which is the one place the two clocks disagree: a
/// browser kept in continuous use for longer than the TTL drops its
/// cookie while the session behind it is still live. That resolves the
/// safe way - the next request arrives with no cookie, gets the form, and
/// signs in again - and the alternative (re-issuing the cookie on every
/// authenticated request) would put a `Set-Cookie` on all 1 Hz of the
/// dashboard's polling to buy one re-login a fortnight.
///
/// `secure` comes from the daemon's own TLS switch and from
/// `X-Forwarded-Proto`, because the reverse-proxy deployment this whole
/// item is for terminates TLS upstream: marking the cookie `Secure` when
/// we ourselves were spoken to over plain http would make it
/// undeliverable on a direct LAN install, and NOT marking it behind a
/// proxy would let it travel in clear if the user ever reaches the origin
/// over http.
pub fn login_cookies(port: u16, id: &str, csrf: &str, secure: bool) -> [String; 2] {
    let sec = if secure { "; Secure" } else { "" };
    let max = session_ttl_secs();
    [
        format!(
            "{}={id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max}{sec}",
            session_cookie(port)
        ),
        // NOT HttpOnly, on purpose: the dashboard and the wall are static
        // pages that have to read this to echo it back in the header.
        // It is not a credential on its own - it authenticates nothing
        // without the HttpOnly session beside it.
        format!(
            "{}={csrf}; Path=/; SameSite=Lax; Max-Age={max}{sec}",
            csrf_cookie(port)
        ),
    ]
}

/// The two `Set-Cookie` values that clear the pair.
pub fn logout_cookies(port: u16) -> [String; 2] {
    [
        format!(
            "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            session_cookie(port)
        ),
        format!("{}=; Path=/; SameSite=Lax; Max-Age=0", csrf_cookie(port)),
    ]
}

/// The passwords an unauthenticated guesser tries FIRST, and the only
/// ones this daemon refuses outright.
///
/// Deliberately short, and deliberately not a strength meter. The
/// measurement behind it is in
/// `research/LOGIN-RATE-LIMIT-MEASURED-2026-09-20.md`: the bad-credential
/// ladder in front of `/login` does not bound the guess rate at all (it
/// labels a refusal, it does not decline to evaluate one), and it cannot
/// be made to without telling one client behind a reverse proxy from
/// another, which is a separate decision. What bounds an attacker
/// instead is the Argon2id verification, measured at 15 to 17 ms of CPU
/// per guess - so a single serial attacker gets on the order of 10^5 to
/// 10^6 guesses a day against a published origin.
///
/// A random eight-character password is far out of reach of that rate.
/// A password on a spray list falls to it in under a second. So the
/// floor that actually matters is not LENGTH, it is "not one of these",
/// and this list holds the entries that a rate of 10^6 a day makes
/// catastrophic rather than merely weak.
///
/// It is trivially evaded by `password1234`, and that is fine and stated
/// on purpose: refusing the catastrophic cases is worth doing even
/// though it is not a guarantee, and a longer list would buy a false
/// sense of one. Do not grow this into a vendored wordlist without
/// deciding that question first.
const WORST_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "password123",
    "passw0rd",
    "p@ssw0rd",
    "passwords",
    "12345678",
    "123456789",
    "1234567890",
    "123123123",
    "11111111",
    "00000000",
    "qwertyui",
    "qwerty123",
    "qwertyuiop",
    "1qaz2wsx",
    "zaq12wsx",
    "asdfghjk",
    "iloveyou",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "superman",
    "trustno1",
    "welcome1",
    "welcome123",
    "abc12345",
    "letmein1",
    "letmein123",
    "monkey12",
    "dragon123",
    "master123",
    "shadow123",
    "michael1",
    "jennifer",
    "changeme",
    "secret123",
    "admin123",
    "administrator",
    "nzbfast1",
    "nzbfast123",
    "usenet123",
    "download1",
    "starwars",
    "whatever",
    "computer",
    "internet",
];

/// Why a password was refused, or `None` when it is acceptable.
///
/// The message is returned to the settings page as a plain API error
/// beside the length floor's, and says WHICH rule was hit: "that one is
/// refused" with no reason is the refusal a user cannot act on.
///
/// `user` is the username being set alongside it. A password equal to
/// the username is the one weak case a list can never cover, because the
/// value that makes it weak is this install's own.
pub fn password_refusal(pw: &str, user: &str) -> Option<String> {
    if pw.chars().count() < 8 {
        return Some("at least 8 characters, or empty to remove it".into());
    }
    let low = pw.to_lowercase();
    if !user.is_empty() && low == user.to_lowercase() {
        return Some("that is the username - pick something else".into());
    }
    if WORST_PASSWORDS.contains(&low.as_str()) {
        return Some(
            "that is one of the first passwords a guesser tries - pick something else".into(),
        );
    }
    // The structural cases, which generalise where a list cannot: one
    // character repeated, and a straight run up or down the keyboard's
    // digits or the alphabet. `aaaaaaaa` and `abcdefgh` are on no list
    // long enough to be worth carrying and fall to a spray just as fast.
    let chars: Vec<char> = low.chars().collect();
    if chars.windows(2).all(|w| w[0] == w[1]) {
        return Some("that is one character repeated - pick something else".into());
    }
    let runs = |step: i32| {
        chars
            .windows(2)
            .all(|w| (w[1] as i32) - (w[0] as i32) == step && w[0].is_ascii_alphanumeric())
    };
    if runs(1) || runs(-1) {
        return Some("that is a straight run of characters - pick something else".into());
    }
    None
}

#[cfg(test)]
#[path = "websession_tests.rs"]
mod websession_tests;
