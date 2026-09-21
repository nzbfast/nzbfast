//! Outbound HTTP for user-supplied and third-party URLs: the SSRF
//! guard, the agents built on it, the resolution witness, and the
//! credential redaction every log line about a URL goes through.
//!
//! At the crate root rather than under `serve/` since TODO 276 item 3.
//! `wall`, `identify`, `xrel`, `srrdb`, `notify` and `rss` all reach for
//! `shared_enrich_agent` or `ssrf_safe_agent` before they talk to a
//! metadata provider or a webhook - seventeen call sites for the enrich
//! agent alone - and answering them from inside `serve` put six modules
//! that owe the daemon nothing inside the dependency cycle it sits in.
//! Nothing here knows what a `Job` or a `Daemon` is.
//!
//! `fetch.rs` keeps the half that does: the NZB-vs-error body
//! sniff, the failure-link allowlist, the regrab inheritance rules and
//! the fetch entry points, all of which are about a download the daemon
//! is running. It re-exports this module, so its own callers are
//! unchanged.

use nzbkit::urlauth::url_netloc;

/// SSRF guard for server-side fetches of user/attacker-supplied URLs
/// (addurl, /watch, poster-from-URL).
///
/// Scope is deliberate: this is a SELF-HOSTED app whose normal job is to
/// talk to indexers on loopback and the LAN (Prowlarr/nzbhydra, or
/// nzbfast's own newznab endpoint), and to be reached over Tailscale
/// (CGNAT 100.64/10). Blocking those would break the common single-box /
/// single-LAN topology. So loopback, RFC1918 and CGNAT are ALLOWED.
///
/// What is refused is the class that is never a legitimate fetch target
/// and is the high-value SSRF prize: the cloud-metadata endpoint and the
/// rest of link-local (169.254/16, fe80::/10), plus unspecified/broadcast.
/// That kills instance-credential theft on AWS/GCP/Azure without breaking
/// local indexers.
pub fn is_forbidden_fetch_ip(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr};
    match ip {
        IpAddr::V4(a) => {
            a.is_link_local()   // 169.254/16, incl. 169.254.169.254 metadata
                || a.is_unspecified() // 0.0.0.0
                || a.is_broadcast()
                || a.octets()[0] == 0 // 0.0.0.0/8 "this network"
                // Alibaba Cloud metadata lives at 100.100.100.200, which is
                // INSIDE the 100.64/10 CGNAT range we otherwise allow for
                // Tailscale - block just that host.
                || a == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_forbidden_fetch_ip(IpAddr::V4(v4));
            }
            let s = a.segments();
            a.is_unspecified()
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                // AWS IPv6 IMDS is fd00:ec2::/32, inside the fc00::/7 ULA
                // range we otherwise allow for v6 LANs - block that block.
                || (s[0] == 0xfd00 && s[1] == 0x0ec2)
        }
    }
}

/// The daemon-API reading of [`is_forbidden_fetch_ip`]: link-local is a
/// legitimate `--host`, the metadata endpoints inside it are not.
///
/// A `--host` names a machine the USER owns, and two real topologies
/// live in ranges the fetch guard refuses wholesale: a direct-cabled
/// LAN with no DHCP self-assigns 169.254/16 (mDNS then resolves
/// `nas.local` into it), and an IPv6 host always answers on fe80::/10.
/// The old `TcpStream::connect` submit reached both, so refusing them
/// here is a regression with no override. The cloud-metadata endpoints
/// that live inside 169.254/16 are carved out BY ADDRESS and stay
/// refused; everything outside link-local keeps the fetch guard's
/// answer, the v6 IMDS block (fd00:ec2::/32) included.
pub fn is_forbidden_daemon_ip(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr};
    match ip {
        IpAddr::V4(a) if a.is_link_local() => {
            // AWS/GCP/Azure IMDS, and the AWS ECS credentials endpoint.
            a == Ipv4Addr::new(169, 254, 169, 254) || a == Ipv4Addr::new(169, 254, 170, 2)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_forbidden_daemon_ip(IpAddr::V4(v4));
            }
            // fe80::/10 carries no metadata service.
            if (a.segments()[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            is_forbidden_fetch_ip(ip)
        }
        _ => is_forbidden_fetch_ip(ip),
    }
}

/// Is this address INSIDE the user's own network - the class
/// [`is_forbidden_fetch_ip`] deliberately lets through because a
/// self-hosted app's normal indexer lives there?
///
/// That function answers "never a legitimate target anywhere". This
/// answers the softer question the enclosure rule needs: "would reaching
/// this address let whatever answered a search pick a machine, or a
/// port, on the user's LAN?" Loopback, RFC1918, CGNAT (Tailscale) and
/// v6 ULA all qualify. The always-forbidden ranges are folded in too, so
/// a caller that only consults this one gets the union, never less.
pub fn is_private_fetch_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    if is_forbidden_fetch_ip(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_loopback()
                || a.is_private() // 10/8, 172.16/12, 192.168/16
                // 100.64/10 CGNAT - Tailscale, and carrier NAT
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_private_fetch_ip(IpAddr::V4(v4));
            }
            // fc00::/7 unique-local covers both fc00::/8 and fd00::/8.
            a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

// ---- Search-time address witness -----------------------------------
//
// ureq offers no way to ask a Response which address it was fetched
// over, and the search agent is deliberately shared process-wide (the
// Agent IS the connection pool). So the guard resolver records what it
// handed back, into a THREAD-LOCAL armed only for the duration of one
// fetch. ureq is blocking and resolves on the calling thread, so the
// scope that arms it is exactly the scope that reads it back - no
// cross-request table to bound, and no way for a concurrent search
// against another indexer to leak an address into this one's answer.
thread_local! {
    /// `Some` only inside [`witness_resolution`]. Each entry is one
    /// resolver call: the netloc asked for, and the addresses returned.
    static WITNESS: std::cell::RefCell<Option<Vec<(String, Vec<std::net::IpAddr>)>>> =
        const { std::cell::RefCell::new(None) };
}

/// Cap on recorded resolutions per witnessed fetch. One fetch resolves
/// once per hop and the redirect cap is 10, so this is slack, not a
/// policy: it exists only so a pathological redirect chain cannot grow
/// the buffer without bound.
const WITNESS_MAX: usize = 24;

/// Note one resolver answer, when a witness scope is armed.
fn note_resolution(netloc: &str, addrs: &[std::net::SocketAddr]) {
    WITNESS.with(|w| {
        if let Ok(mut w) = w.try_borrow_mut()
            && let Some(seen) = w.as_mut()
            && seen.len() < WITNESS_MAX
        {
            seen.push((
                netloc.to_ascii_lowercase(),
                addrs.iter().map(|a| a.ip()).collect(),
            ));
        }
    });
}

/// Run one fetch with recording armed, and hand back every address
/// `netloc` resolved to while it ran.
///
/// `netloc` is spelled the way [`url_netloc`] spells it, which is the
/// way ureq spells it - the comparison is against what the resolver was
/// asked for, so the two have to agree.
///
/// The result is the SEARCH-time truth that a later grab is checked
/// against; see [`SourceOrigin`]. A fetch that resolved something else
/// (a redirect hop, a sibling host) contributes nothing here.
pub fn witness_resolution<T>(netloc: &str, f: impl FnOnce() -> T) -> (T, Vec<std::net::IpAddr>) {
    // Save and restore rather than assume no nesting: a future caller
    // that wraps a witnessed fetch in another must not silently blank
    // the outer one's record.
    let prev = WITNESS.with(|w| w.borrow_mut().replace(Vec::new()));
    let out = f();
    let seen = WITNESS.with(|w| w.borrow_mut().take()).unwrap_or_default();
    WITNESS.with(|w| *w.borrow_mut() = prev);
    let want = netloc.to_ascii_lowercase();
    let mut addrs: Vec<std::net::IpAddr> = Vec::new();
    for (at, ips) in seen {
        if at == want {
            for ip in ips {
                if !addrs.contains(&ip) {
                    addrs.push(ip);
                }
            }
        }
    }
    (out, addrs)
}

/// A configured source that supplied a link in its own RESPONSE, and
/// where that source actually answered from.
///
/// `url` is what the user configured (an indexer's URL, an RSS feed's).
/// `addrs` is what its netloc resolved to when the SEARCH was made -
/// the fact a later grab is checked against, and the whole reason this
/// is a struct rather than the bare string it used to be. See
/// [`OriginBoundResolver`].
#[derive(Debug, Clone, Default)]
pub struct SourceOrigin {
    pub url: String,
    pub addrs: Vec<std::net::IpAddr>,
}

impl SourceOrigin {
    /// The origin of a link supplied by a response fetched at `addrs`.
    /// Build it at SEARCH time, from [`witness_resolution`], and carry
    /// it with the result: a rebuild at grab time re-resolves, which is
    /// exactly the window being closed.
    pub fn witnessed(url: &str, addrs: Vec<std::net::IpAddr>) -> Self {
        Self {
            url: url.to_string(),
            addrs,
        }
    }

    /// An origin with no witnessed address. Public targets are
    /// unaffected; every PRIVATE one is refused, because there is
    /// nothing to prove the source was ever there. Only for a caller
    /// that genuinely has no search behind it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn unwitnessed(url: &str) -> Self {
        Self::witnessed(url, Vec::new())
    }
}

/// project invariant 5, made structural: in a unit-test build every
/// destination outside loopback is REFUSED, whatever the environment
/// says.
///
/// `identity::may_call_out` turns the enrichment LANES off, which is
/// what makes the tests deterministic. This is the backstop underneath
/// it, and it exists because the lane gate is exactly the thing that
/// was forgotten: `expected::maybe_refresh` carried its own copy of the
/// env read, so when `1dbcca3c2` moved its pick to the front of the
/// confirm lane, three tests in the `--bin nzbfast` target dialled
/// api.tvmaze.com - two failed and one passed while doing it, which is
/// the shape nothing would ever have found. Measured 1 Sep 2026, and
/// the census that named all three is in
/// `research/RED-UNIT-ONE-PROCESS-1dbcca3c2-IS-ENRICH-DEPENDENT-2026-09-01.md`.
///
/// Loopback is allowed because it is what the fixtures ARE: the mock
/// newznab in `lane_proof_tests`, the keep-alive counter in
/// `tests_api`, every daemon a unit test opens. A live service is never
/// on loopback, so the two classes do not overlap.
///
/// **A LITERAL ADDRESS is allowed too, and that is the stated limit.**
/// It is not a hole so much as the difference between resolving and
/// reaching: the SSRF rules above are themselves unit-tested by calling
/// `resolve()` on literals - `8.8.8.8:443` must be allowed,
/// `169.254.169.254:80` must not, `192.168.1.9:5077` must not - and
/// those tests connect to nothing. Refusing them was the first cut of
/// this guard and it took two of them red, which is the shape a guard
/// that fires on what is fine always has. Every live service this crate
/// reaches is reached by NAME (api.tvmaze.com, api.xrel.to,
/// api.themoviedb.org, api.srrdb.com); there is no hard-coded public
/// address anywhere in it, so the carve-out costs the guard nothing it
/// was built to catch. A test that hard-codes a public IP and dials it
/// would slip through, and would be the thing to fix.
///
/// Compiled under `cfg(test)` for THIS crate OR the `test-support`
/// feature, so the shipped binary, the integration suites (which spawn
/// that binary) and nzbfast-ffi are all untouched. The feature is the
/// half that reaches nzbfast's own unit tests: they compile this crate
/// as a dependency since the crate-split step 2 cut, so `cfg(test)` is
/// off here for the very tests this guard exists for - see
/// `identity::may_call_out`, whose note carries the measurement and the
/// stated cost. The five `#[ignore]`d live provider rigs in
/// `wall/tests.rs` lift it with `identity::TEST_CALLOUT_ALLOW`, and
/// their doc comments carry the command line.
#[cfg(any(test, feature = "test-support"))]
pub fn deny_test_callout(netloc: &str, addrs: &[std::net::SocketAddr]) -> std::io::Result<()> {
    let host = netloc
        .strip_prefix('[')
        .and_then(|r| r.split_once(']').map(|(h, _)| h))
        .unwrap_or_else(|| netloc.rsplit_once(':').map(|(h, _)| h).unwrap_or(netloc));
    if host.parse::<std::net::IpAddr>().is_ok()
        || addrs.iter().all(|a| a.ip().is_loopback())
        || std::env::var_os(crate::identity::TEST_CALLOUT_ALLOW).is_some()
    {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "unit tests may not reach {netloc}: a test in the nzbfast bin \
             target must be hermetic. Gate the lane on \
             identity::may_call_out(), or - for a deliberate hand-run \
             live rig - set {}=1",
            crate::identity::TEST_CALLOUT_ALLOW
        ),
    ))
}

/// The non-test build has no such guard: this is the shipped resolver
/// path and it must stay exactly as fast as it was.
#[cfg(not(any(test, feature = "test-support")))]
#[inline]
pub fn deny_test_callout(_netloc: &str, _addrs: &[std::net::SocketAddr]) -> std::io::Result<()> {
    Ok(())
}

// ---- Refused answers, and the Retry-After they carry ---------------

/// A call that did not come back with a body: either the server
/// refused, or we never reached it.
///
/// **This type exists because ureq 3 threw the response away.** ureq 2
/// raised `Error::Status(code, response)`, and eight call sites across
/// this tree read `Retry-After` off that response to size a provider
/// backoff. ureq 3 raises `Error::StatusCode(u16)` and carries nothing
/// else, so the ureq 2 shape has no ureq 3 spelling: ported literally,
/// every one of those sites would fall back to its hardcoded 30 s / 5 s
/// forever, no test would fail, and the only symptom would be providers
/// being hammered on a schedule they had explicitly asked us not to
/// keep. So the refusal is caught BEFORE ureq turns it into an error.
///
/// The switch is per REQUEST and never per agent
/// ([`call_keeping_refusal`] sets it on the one request it is running),
/// which is the whole of why this is safe to add to a shared pool: the
/// enrich agent is process-wide and most of its callers want a 4xx to
/// be an `Err`, and they still get one.
pub enum Refusal {
    /// The server answered, with a 4xx or 5xx.
    Status {
        code: u16,
        /// `Retry-After` in delta-seconds, when it sent one in that
        /// form. An HTTP-date is legal and is not parsed - see
        /// [`Refusal::wait_secs`] for what happens then.
        retry_after: Option<u64>,
        /// The refusal itself, body unread. Boxed because it is much
        /// the largest thing here and most callers never look at it;
        /// `notify` and `predb_seed` are the two that do, through
        /// [`Refusal::body_text`]. `None` only for a refusal a test
        /// minted with `refusal_for_test`, which has no wire behind
        /// it to read a body from.
        resp: Option<Box<ureq::http::Response<ureq::Body>>>,
    },
    /// No reply at all: DNS, connect, TLS, timeout, or a guard above
    /// refusing to dial. Also the one a guard's own message arrives in.
    Transport(ureq::Error),
}

impl std::fmt::Debug for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Status {
                code, retry_after, ..
            } => f
                .debug_struct("Refusal::Status")
                .field("code", code)
                .field("retry_after", retry_after)
                .finish_non_exhaustive(),
            Refusal::Transport(e) => f.debug_tuple("Refusal::Transport").field(e).finish(),
        }
    }
}

impl Refusal {
    /// The status code, when the server answered at all.
    pub fn code(&self) -> Option<u16> {
        match self {
            Refusal::Status { code, .. } => Some(*code),
            Refusal::Transport(_) => None,
        }
    }

    /// How long this refusal asks us to wait, in seconds.
    ///
    /// The header when it sent a usable one, and otherwise the same
    /// fallback every call site picked independently before: a 429 is a
    /// bucket we emptied, a 503 is usually a blip. A transport failure
    /// asks for nothing and answers `None` - there is no service on the
    /// other end saying anything.
    pub fn wait_secs(&self) -> Option<u64> {
        match self {
            Refusal::Status {
                code, retry_after, ..
            } => Some(retry_after.unwrap_or(if *code == 429 { 30 } else { 5 })),
            Refusal::Transport(_) => None,
        }
    }

    /// The `Retry-After` the server sent, in seconds, when it sent a
    /// usable one. Unlike [`Refusal::wait_secs`] this applies no
    /// fallback - the callers with their own retry ladder supply
    /// theirs.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Refusal::Status { retry_after, .. } => *retry_after,
            Refusal::Transport(_) => None,
        }
    }

    /// Is this the provider saying "not now" rather than "no"?
    pub fn is_slow_down(&self) -> bool {
        matches!(self.code(), Some(429 | 503))
    }

    /// What the server said in the refusal's body, for the two callers
    /// that report it. Empty for a transport failure, and empty when
    /// the body cannot be read - a refusal is being reported either
    /// way, and a second failure reading it adds nothing.
    pub fn body_text(self) -> String {
        match self {
            Refusal::Status { resp, .. } => resp
                .and_then(|r| (*r).into_body().read_to_string().ok())
                .unwrap_or_default(),
            Refusal::Transport(_) => String::new(),
        }
    }
}

/// Safe to log anywhere, which is the point: [`error_brief`] is what
/// the transport arm prints, so no `{refusal}` in this tree can name a
/// request URL.
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Status { code, .. } => write!(f, "http status: {code}"),
            Refusal::Transport(e) => f.write_str(&error_brief(e)),
        }
    }
}

/// A one-line description of a ureq failure with no request URL in it.
///
/// A Discord/ntfy/Gotify webhook's PATH is its bearer token, a TMDB
/// query string carries the user's api_key, and these strings are
/// logged - logtee puts them in the dashboard ring and in the file
/// people paste into support threads. So the rule is: report the
/// failure, never the request.
///
/// ureq 2 made this a rebuild-from-parts job, because its `Transport`
/// error LED with the whole URL. ureq 3 is the other way round -
/// nearly every arm of its `Error` describes the failure and names
/// nothing about the request - so the work here is the two arms that
/// are NOT like that, and the rest pass through.
///
/// `ureq::Error` is `#[non_exhaustive]`, so the catch-all is doing
/// real work: a ureq minor that adds a URL-carrying arm would start
/// leaking through it. That is what
/// `notify::tests::a_transport_error_never_names_the_url` is for, and
/// why it asserts on the HOST and not just on the path.
pub fn error_brief(e: &ureq::Error) -> String {
    match e {
        // Formats the whole `Uri` - scheme, host, path and query.
        ureq::Error::BadUri(_) => "bad url".to_string(),
        ureq::Error::RequireHttpsOnly(_) => "configured for https only".to_string(),
        other => other.to_string(),
    }
}

/// `Retry-After` as delta-seconds, or `None`.
///
/// Only the delta-seconds form is read. The HTTP-date form is legal and
/// these services do not send it; a date parser here would be more code
/// than the fallback it replaces, and getting it subtly wrong is worse
/// than not having it - see [`Refusal::wait_secs`] for what a `None`
/// costs.
fn retry_after_of(headers: &ureq::http::HeaderMap) -> Option<u64> {
    headers
        .get("Retry-After")?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Run one request with its refusal still readable.
///
/// Status-as-error is turned off for THIS request, so a 4xx/5xx comes
/// back as a response we can read the headers of, and is then
/// classified into [`Refusal::Status`] with its `Retry-After` already
/// parsed. Every other call on the same agent is untouched.
///
/// The response body of a refusal is NOT read here: `notify` and
/// `predb_seed` want a few hundred bytes of it and the rest do not, so
/// it stays the caller's to take. See [`call_body`] for the common
/// case.
pub fn call_keeping_refusal(
    req: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
) -> Result<ureq::http::Response<ureq::Body>, Refusal> {
    classify(req.config().http_status_as_error(false).build().call())
}

/// [`call_keeping_refusal`] for a request that carries a body.
pub fn send_keeping_refusal(
    req: ureq::RequestBuilder<ureq::typestate::WithBody>,
    body: impl ureq::AsSendBody,
) -> Result<ureq::http::Response<ureq::Body>, Refusal> {
    classify(req.config().http_status_as_error(false).build().send(body))
}

/// As [`send_keeping_refusal`], for a POST with no body at all.
pub fn send_empty_keeping_refusal(
    req: ureq::RequestBuilder<ureq::typestate::WithBody>,
) -> Result<ureq::http::Response<ureq::Body>, Refusal> {
    classify(
        req.config()
            .http_status_as_error(false)
            .build()
            .send_empty(),
    )
}

/// The three helpers above are `classify`'s only callers and every one
/// of them turns status-as-error off, so a `ureq::Error::StatusCode`
/// cannot arrive here - which is what lets the `Err` arm be a single
/// catch-all without losing a code.
fn classify(
    r: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<ureq::http::Response<ureq::Body>, Refusal> {
    match r {
        Ok(resp) if resp.status().is_client_error() || resp.status().is_server_error() => {
            Err(Refusal::Status {
                code: resp.status().as_u16(),
                retry_after: retry_after_of(resp.headers()),
                resp: Some(Box::new(resp)),
            })
        }
        Ok(resp) => Ok(resp),
        Err(e) => Err(Refusal::Transport(e)),
    }
}

/// The common shape: run it, read the body as a string.
///
/// The 10 MB cap is ureq's own default and is the same one
/// `into_string()` applied in ureq 2, so this is not a new limit.
pub fn call_body(
    req: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
) -> Result<String, Refusal> {
    call_keeping_refusal(req)?
        .into_body()
        .read_to_string()
        .map_err(Refusal::Transport)
}

// ---- The ureq 3 resolver shim -------------------------------------
//
// ureq 2's `Resolver` took the netloc STRING every rule in this module
// is written in terms of and handed back a `Vec<SocketAddr>`. ureq 3's
// lives in `unversioned::resolver`, takes a `Uri`, the agent `Config`
// and a deadline, and answers with a fixed-capacity `ArrayVec` of at
// most 16. These three helpers are that translation, in one place, so
// the four guards below read the way they did and a future ureq bump
// has one site to re-check. ureq holds `unversioned::` OUTSIDE semver
// on purpose, so a bump is a reason to re-read it, and
// `tools/ureq-unversioned-gate.py` makes that a refusal.

use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

/// `host:port`, port always explicit - the spelling ureq 2 handed the
/// resolver, and the one [`url_netloc`] produces, so the two sides of
/// the origin comparison still agree.
///
/// Empty for a URI with no scheme or authority. That is a shape ureq
/// refuses before it dials, and an empty netloc fails every rule below
/// closed rather than open: `deny_test_callout` sees no literal and no
/// loopback, and `OriginBoundResolver` cannot match a non-empty origin.
fn uri_netloc(uri: &ureq::http::Uri) -> String {
    match (uri.scheme(), uri.authority()) {
        (Some(sch), Some(auth)) => DefaultResolver::host_and_port(sch, auth).unwrap_or_default(),
        _ => String::new(),
    }
}

/// One refusal. ureq 3 has no permission-denied variant of its own, and
/// `Error::Io` is the one its own docs tell a bespoke chain to map to -
/// so the `ErrorKind` and the message survive, and every call site that
/// formats the error with `{e}` still prints the reason.
fn refused(msg: String) -> ureq::Error {
    ureq::Error::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        msg,
    ))
}

/// The stock lookup each guard filters.
///
/// Delegating rather than calling `to_socket_addrs` directly is
/// deliberate: ureq 3 puts the resolve TIMEOUT and the agent's
/// `ip_family` setting inside `DefaultResolver`, so a hand-rolled
/// lookup would silently drop both. The 16-address cap it applies is
/// not a hole in the guard - ureq dials only what we hand back, so an
/// address it dropped is an address nothing reaches.
fn base_resolve(
    uri: &ureq::http::Uri,
    config: &ureq::config::Config,
    timeout: NextTimeout,
) -> Result<ResolvedSocketAddrs, ureq::Error> {
    DefaultResolver::default().resolve(uri, config, timeout)
}

/// The config every agent in this module is built on.
///
/// Three settings, and each of them is holding ureq 3 to what ureq 2
/// did rather than taking a new default:
///
/// - **`timeout_global`**, because ureq 2's `AgentBuilder::timeout` was
///   the whole-call budget and every caller picks its number for that.
///   ureq 3's per-phase timeouts would let a slow body run past it.
/// - **`max_redirects_will_error(false)`**, because ureq 2 handed back
///   the last response once the cap was reached and ureq 3 raises
///   `TooManyRedirects` instead. That matters most at `redirects = 0`,
///   which three callers here use to mean "do not follow, tell me what
///   it said" - `notify` reports the status it got, and turning that
///   into a transport error would relabel a working webhook as broken.
/// - **`proxy(None)`**, which is the one that is not cosmetic. ureq 3's
///   `Config::default()` calls `Proxy::try_from_env()`, where ureq 2
///   proxied only when asked. With a proxy in the environment ureq
///   resolves the PROXY's address, not the destination's - so every
///   guard below would be checking the wrong host, and the SSRF rule
///   this module exists for would be silently off for any daemon
///   started with `HTTPS_PROXY` set. Supporting a proxy safely means
///   deciding what the guard means when someone else does the dialling;
///   that is a design question, not a port, so the port keeps ureq 2's
///   answer.
fn agent_config(redirects: u32, timeout_secs: u64) -> ureq::config::Config {
    ureq::Agent::config_builder()
        .max_redirects(redirects)
        .max_redirects_will_error(false)
        .proxy(None)
        .timeout_global(Some(std::time::Duration::from_secs(timeout_secs)))
        .build()
}

/// One request header's value out of a raw HTTP request, found without
/// caring how the client spelled the NAME.
///
/// HTTP/1.1 field names are case-insensitive (RFC 9110 5.1) and ureq 3
/// writes them lowercased - the `http` crate normalises them - where
/// ureq 2 wrote back whatever the caller typed. Every real receiver
/// already handled both, so an assertion that pinned the CASE was
/// pinning ureq's spelling rather than the contract. This is that
/// assertion catching up: presence and exact VALUE still pinned, name
/// matched the way the protocol matches it.
///
/// Shared rather than copied into each test module: `notify` and the
/// daemon's `hooks` both capture a raw request off a scratch listener
/// and both were asserting by exact case.
#[cfg(any(test, feature = "test-support"))]
pub fn raw_header_of<'a>(req: &'a str, name: &str) -> Option<&'a str> {
    let head = req.split_once("\r\n\r\n").map(|(h, _)| h).unwrap_or(req);
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// One refusal built from a raw HTTP header block, for the tests that
/// pin the `Retry-After` path without a listener.
///
/// The header text goes through the SAME [`retry_after_of`] the wire
/// path uses, so a parser that stops reading the header reds these
/// tests rather than quietly falling back. It is the ureq 3 stand-in
/// for what `wall/tests.rs` used to do by parsing a whole
/// `ureq::Response` out of raw HTTP text.
#[cfg(any(test, feature = "test-support"))]
pub fn refusal_for_test(code: u16, headers: &str) -> Refusal {
    let mut map = ureq::http::HeaderMap::new();
    for line in headers.split("\r\n").filter(|l| !l.trim().is_empty()) {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (Ok(name), Ok(value)) = (
            k.trim().parse::<ureq::http::HeaderName>(),
            v.trim().parse::<ureq::http::HeaderValue>(),
        ) else {
            continue;
        };
        map.insert(name, value);
    }
    Refusal::Status {
        code,
        retry_after: retry_after_of(&map),
        resp: None,
    }
}

/// Resolve one `host:port` through `r`, for the SSRF tests.
///
/// The guards are all written in terms of a netloc and are tested with
/// literals; this is the ureq 2 -> ureq 3 translation for the test
/// side, and nothing else. It drives the REAL `resolve`, so a guard
/// that stops firing still reds the tests that call it.
#[cfg(any(test, feature = "test-support"))]
pub fn resolve_netloc<R: Resolver>(
    r: &R,
    netloc: &str,
) -> Result<Vec<std::net::SocketAddr>, ureq::Error> {
    let uri: ureq::http::Uri = format!("https://{netloc}/")
        .parse()
        .map_err(|_| ureq::Error::BadUri(netloc.to_string()))?;
    let config = ureq::Agent::config_builder().build();
    let timeout = NextTimeout {
        after: ureq::unversioned::transport::time::Duration::NotHappening,
        reason: ureq::Timeout::Global,
    };
    r.resolve(&uri, &config, timeout).map(|a| a.to_vec())
}

/// ureq resolver that refuses to hand back any internal address. Because
/// ureq connects to exactly the SocketAddrs returned here (no second
/// lookup), this closes the DNS-rebinding window AND re-checks on every
/// redirect hop, since each hop resolves through it.
#[derive(Debug, Default)]
pub struct SsrfGuardResolver;
impl Resolver for SsrfGuardResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let netloc = uri_netloc(uri);
        let addrs = base_resolve(uri, config, timeout)?;
        note_resolution(&netloc, &addrs);
        deny_test_callout(&netloc, &addrs).map_err(ureq::Error::Io)?;
        if addrs.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        if addrs.iter().any(|a| is_forbidden_fetch_ip(a.ip())) {
            return Err(refused(format!(
                "refusing to fetch an internal address ({netloc})"
            )));
        }
        Ok(addrs)
    }
}

/// [`SsrfGuardResolver`] with the daemon-API carve-out
/// ([`is_forbidden_daemon_ip`]): link-local is reachable, its metadata
/// endpoints are not. Only [`daemon_api_agent`] installs it - the
/// enrich and user-URL agents keep the full guard.
#[derive(Debug, Default)]
pub(crate) struct DaemonApiResolver;
impl Resolver for DaemonApiResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let netloc = uri_netloc(uri);
        let addrs = base_resolve(uri, config, timeout)?;
        deny_test_callout(&netloc, &addrs).map_err(ureq::Error::Io)?;
        if addrs.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        if addrs.iter().any(|a| is_forbidden_daemon_ip(a.ip())) {
            return Err(refused(format!(
                "refusing to fetch an internal address ({netloc})"
            )));
        }
        Ok(addrs)
    }
}

/// An agent whose every connection (initial + each redirect) is filtered
/// through the SSRF guard. Use for ANY fetch of a user/attacker-supplied
/// URL. `redirects` is capped by the caller.
pub fn ssrf_safe_agent(redirects: u32, timeout_secs: u64) -> ureq::Agent {
    ureq::Agent::with_parts(
        agent_config(redirects, timeout_secs),
        ureq::unversioned::transport::DefaultConnector::new(),
        SsrfGuardResolver,
    )
}

/// The SSRF guard PLUS the origin rule for links a configured source
/// handed back: a private/loopback destination is only reachable when it
/// is the very socket the source itself lives on.
///
/// Why this exists: [`is_forbidden_fetch_ip`] deliberately permits
/// loopback and the LAN, because a self-hosted downloader's indexer is
/// normally right there. That concession is safe for a URL the USER
/// typed and unsafe for one an indexer's search RESPONSE supplied - a
/// compromised (or merely hostile) indexer could hand back
/// `http://127.0.0.1:<other>/...` and make the daemon issue a blind GET
/// against a different service on the user's own box. Binding the fetch
/// to the origin is the same move `failure_link_allowed` already makes
/// for response-supplied failure links, for the same reason.
///
/// Cross-origin is NOT refused outright: an indexer serving its NZBs
/// from a sibling download host or a CDN is a real pattern, and those
/// are public addresses. Only cross-origin PRIVATE targets are refused.
///
/// Port-strict, unlike the failure-link host check. There the question
/// is whose server we call; here a neighbouring port on the same private
/// host IS the pivot being described, and every indexer shape in the
/// wild (Prowlarr, NZBHydra2, nzbfast's own newznab endpoint) serves its
/// downloads from the port it answers searches on.
///
/// **Same netloc is not the same machine** (M9). The netloc is a name,
/// and names are resolved fresh on every request. A hostile public
/// indexer can answer the SEARCH from a public address and then repoint
/// that hostname at loopback or the LAN before the GRAB: the resolver
/// dials exactly the new answer and, comparing netlocs alone, calls it
/// the source's own socket. So a private target must ALSO be one of the
/// addresses the source answered the search from - the `addrs` half of
/// [`SourceOrigin`], captured at search time and carried here.
///
/// Two dead ends, so they are not re-derived:
///
/// - Pinning the addresses when this resolver is BUILT does not help.
///   It is built per grab, by which time a hostile DNS already answers
///   privately. The address has to come from the earlier request.
/// - Refusing same-origin private targets outright does not work
///   either: a LAN NZBHydra or Prowlarr is a supported, common setup,
///   and breaking it is worse than the hole.
///
/// An unwitnessed origin therefore refuses private targets. That fails
/// closed, and safely: every producer of a `SourceOrigin` builds it
/// from the search that supplied the link, so the only way to arrive
/// here empty is a public source (unaffected) or a genuine renumber
/// between search and grab, which the next search re-witnesses.
#[derive(Debug)]
pub struct OriginBoundResolver {
    /// `host:port` of the configured source, lowercased, with the
    /// scheme's default port filled in - see [`url_netloc`]. Empty when
    /// the source URL could not be parsed, which refuses every private
    /// target rather than guessing: the safe direction.
    origin: String,
    /// The addresses that netloc answered the SEARCH from. A private
    /// target outside this set is a rebind, not the source.
    witnessed: Vec<std::net::IpAddr>,
}

impl OriginBoundResolver {
    /// Bind to `origin` - the source's configured URL and the addresses
    /// it answered the search from, not the link it handed back.
    pub fn new(origin: &SourceOrigin) -> Self {
        Self {
            origin: url_netloc(&origin.url),
            witnessed: origin.addrs.clone(),
        }
    }
}

impl Resolver for OriginBoundResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let netloc = uri_netloc(uri);
        let netloc = netloc.as_str();
        let addrs = base_resolve(uri, config, timeout)?;
        // Recorded here as well as in the plain guard so that
        // `Fetched.addrs` means the same thing whichever tier fetched
        // it: where the url we ASKED for resolved to.
        note_resolution(netloc, &addrs);
        deny_test_callout(netloc, &addrs).map_err(ureq::Error::Io)?;
        if addrs.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        if addrs.iter().any(|a| is_forbidden_fetch_ip(a.ip())) {
            return Err(refused(format!(
                "refusing to fetch an internal address ({netloc})"
            )));
        }
        // ureq builds netloc as `host_str():port_or_known_default()`, so
        // both sides carry an explicit port and a bracketed IPv6 literal
        // is spelled the same way `url_netloc` spells it.
        let same_origin = !self.origin.is_empty() && netloc.eq_ignore_ascii_case(&self.origin);
        let private: Vec<std::net::IpAddr> = addrs
            .iter()
            .map(|a| a.ip())
            .filter(|ip| is_private_fetch_ip(*ip))
            .collect();
        if !private.is_empty() && !same_origin {
            return Err(refused(format!(
                "refusing a link to {netloc}: it is inside this network \
                 and is not the source that supplied it{}",
                if self.origin.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", self.origin)
                }
            )));
        }
        // Same netloc, private address: allowed only for an address the
        // source answered the search from. EVERY private address in the
        // answer has to qualify, not just one - ureq picks which of them
        // to dial, so a resolver that returns the real public address
        // beside a loopback one would otherwise smuggle the loopback in.
        if let Some(bad) = private.iter().find(|ip| !self.witnessed.contains(ip)) {
            return Err(refused(format!(
                "refusing a link to {netloc}: it resolves to {bad} inside \
                 this network, which is not an address it answered the \
                 search from"
            )));
        }
        Ok(addrs)
    }
}

/// [`SsrfGuardResolver`] plus the PRODUCTION half of CONTRIBUTING.md
/// invariant 5: when `identity::may_call_out()` says no, every
/// destination outside loopback is refused.
///
/// This is to a running daemon what [`deny_test_callout`] is to a
/// unit-test build - the backstop under the lane gates, in the one
/// place a new call site cannot route around. It exists because the
/// lane gates demonstrably did not hold on their own. Measured 1 Sep
/// 2026 against a real daemon started with `NZBFAST_NO_ENRICH=1`:
/// three of the four wire destinations an ordinary dashboard session
/// reaches went out anyway - `www.wikidata.org` from the metadata
/// search box (`wall::get_json_ua`) and `image.tmdb.org` twice from the
/// art fetch (`wall::fetch_image`). Only TVmaze was stopped, and only
/// because TVmaze happens to go through `wall::get_json`, the single
/// helper of three that anybody had gated. Census, method and the
/// control arm: `research/PROD-ENRICH-CALLOUT-CENSUS-2026-09-01.md`.
///
/// Loopback is allowed, exactly as [`deny_test_callout`] allows it and
/// for the same reason: it is what the fixtures ARE - the keep-alive
/// counter in `tests_api` drives this very agent against a loopback
/// server, and `may_call_out()` is false in every unit-test build. A
/// live metadata provider is never on loopback, so the two classes do
/// not overlap.
///
/// Only [`shared_enrich_agent`] installs it, and that is the scope
/// line: an indexer search or an NZB grab is the user's OWN configured
/// source rather than enrichment, so those keep the plain guard and a
/// daemon test that searches a mock newznab is untouched. The one
/// caller that deliberately opts OUT of the enrich pool to escape this
/// is `wall::omdb::omdb_signup`, which says why at the site.
#[derive(Debug, Default)]
pub struct EnrichResolver;
impl Resolver for EnrichResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let addrs = SsrfGuardResolver.resolve(uri, config, timeout)?;
        if !crate::identity::may_call_out() && !addrs.iter().all(|a| a.ip().is_loopback()) {
            let netloc = uri_netloc(uri);
            return Err(refused(format!(
                "enrichment is switched off, so {netloc} was not contacted \
                 (project invariant 5 - unset NZBFAST_NO_ENRICH \
                 to allow it)"
            )));
        }
        Ok(addrs)
    }
}

/// An agent for fetching a link that `origin`'s RESPONSE supplied.
/// Every hop - the link itself and each redirect - goes through
/// [`OriginBoundResolver`].
pub fn origin_bound_agent(origin: &SourceOrigin, redirects: u32, timeout_secs: u64) -> ureq::Agent {
    ureq::Agent::with_parts(
        agent_config(redirects, timeout_secs),
        ureq::unversioned::transport::DefaultConnector::new(),
        OriginBoundResolver::new(origin),
    )
}

/// The ONE outbound HTTP agent the wall enricher shares (plan §4 C2).
///
/// In ureq the Agent *is* the connection pool, so `ureq::get(...)` -
/// which builds a throwaway agent per call - reconnects and re-does the
/// TLS handshake for every single request. The enricher makes several
/// requests per title (search, entity, summary, art) and runs over
/// thousands of titles a scan, all to a handful of hosts, so it was
/// paying a full handshake where a pooled connection costs nothing.
///
/// One agent, kept for the process's life, and callers still set their
/// own per-request `.timeout()` - which is why a single shared agent can
/// serve a 10 s metadata lookup and a 120 s dataset download alike.
///
/// It carries the SSRF resolver for the same reason the NZB fetcher
/// does: these hosts are ours today, but user-supplied sources are the
/// stated direction for this code, and a pool that guards by default
/// cannot be forgotten later.
///
/// Its resolver is [`EnrichResolver`] rather than the plain guard, so
/// every fetch on this pool - present and future - is refused when
/// enrichment is switched off. That is the point: the rule lives on the
/// pool the enrichment lanes share, where a call site added tomorrow
/// inherits it without knowing it exists.
pub fn shared_enrich_agent() -> ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT
        .get_or_init(|| {
            ureq::Agent::with_parts(
                agent_config(4, 30),
                ureq::unversioned::transport::DefaultConnector::new(),
                EnrichResolver,
            )
        })
        .clone()
}

/// The TLS link that hands ureq 3 nzbkit's own `rustls::ClientConfig`.
///
/// ureq 2 took one through `AgentBuilder::tls_config`. ureq 3 has no
/// such hook at all: its `TlsConfig` offers roots and a
/// `disable_verification()` that also waives the signature checks, and
/// neither is "use this config". The way 3.x leaves open is a bespoke
/// connector chained behind the plain TCP one, in place of
/// `DefaultConnector`'s rustls link - which is what the tray port
/// settled on first (`crates/nzbtray/src/main.rs`), and this is that
/// shape with nzbkit's config in place of the tray's loopback one.
///
/// Everything here is ureq's own `RustlsConnector` / `RustlsTransport`
/// restated, because the latter is private. Re-read `ureq/src/tls/
/// rustls.rs` at every ureq minor: this rides `unversioned::transport`,
/// which ureq explicitly does not hold to semver, and the handshake
/// dance has to keep matching. `tools/ureq-unversioned-gate.py` refuses a
/// ureq version this was not re-read against; its header has the rule.
///
/// Plain HTTP still works - a `--host http://...` never reaches the TLS
/// half, exactly as in ureq's own chain.
#[derive(Debug, Default)]
struct SharedTlsConnector;

impl<In: ureq::unversioned::transport::Transport> ureq::unversioned::transport::Connector<In>
    for SharedTlsConnector
{
    type Out = ureq::unversioned::transport::Either<In, SharedTlsTransport>;

    fn connect(
        &self,
        details: &ureq::unversioned::transport::ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        use ureq::unversioned::transport::Either;
        let Some(transport) = chained else {
            // Same contract as ureq's own rustls link: only ever
            // reached second in a chain.
            return Ok(None);
        };
        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }
        let name = tls_peer_name(details.uri)?;
        let mut conn =
            rustls::ClientConnection::new(nzbkit::nntp::shared_tls_client_config(), name)?;
        let mut sock = ureq::unversioned::transport::TransportAdapter::new(transport.boxed());
        sock.set_timeout(details.timeout);
        conn.complete_io(&mut sock)?;
        Ok(Some(Either::B(SharedTlsTransport {
            buffers: ureq::unversioned::transport::LazyBuffers::new(
                details.config.input_buffer_size(),
                details.config.output_buffer_size(),
            ),
            stream: rustls::StreamOwned { conn, sock },
        })))
    }
}

/// The TLS peer name for a URI, derived the way ureq's own connector
/// derives it.
///
/// ureq names the peer with its PRIVATE `AuthorityExt::host_bare()`
/// (`ureq/src/util.rs`), which strips the RFC 3986 brackets an IPv6
/// literal carries in a URI authority. `Authority::host()` keeps them,
/// and `ServerName::try_from("[::1]")` is `InvalidDnsNameError` - so
/// naming the peer with `host()` made `nzbfast stream --host
/// https://[::1]:PORT` fail "invalid dns name" before a byte was sent,
/// where ureq's own connector dials. Found by the re-read that
/// `tools/ureq-unversioned-gate.py` exists to force.
///
/// Stripping is the WHOLE fix: `ServerName::try_from` tries the DNS
/// grammar first and falls through to the IP-literal path, and an
/// all-numeric last label is not a valid DNS name, so `::1` and
/// `127.0.0.1` both come back as `ServerName::IpAddress` with no parse
/// of our own. A name that is neither takes the DNS path unchanged.
///
/// `LoopbackTlsConnector` in `crates/nzbtray/src/main.rs` restates
/// these three lines: the tray deliberately has no dependency edge to
/// this crate (its `Cargo.toml` says why), so the two copies move
/// together by hand. Same pairing as the connectors themselves.
///
/// ref-gate: `ureq/src/util.rs` is a file in the ureq CRATE, not in
/// this tree - read it under the cargo registry checkout the
/// `tools/ureq-unversioned-gate.py` digest arm already resolves.
fn tls_peer_name(
    uri: &ureq::http::Uri,
) -> Result<rustls::pki_types::ServerName<'static>, ureq::Error> {
    let host = uri
        .authority()
        .map(|a| a.host())
        .ok_or(ureq::Error::Tls("no authority for tls"))?;
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    Ok(rustls::pki_types::ServerName::try_from(bare)
        .map_err(|_| ureq::Error::Tls("invalid dns name"))?
        .to_owned())
}

/// The TLS half of [`SharedTlsConnector`]'s connection. ureq's own
/// `RustlsTransport` is private, so this is that type restated.
struct SharedTlsTransport {
    buffers: ureq::unversioned::transport::LazyBuffers,
    stream: rustls::StreamOwned<
        rustls::ClientConnection,
        ureq::unversioned::transport::TransportAdapter,
    >,
}

impl std::fmt::Debug for SharedTlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedTlsTransport")
    }
}

impl ureq::unversioned::transport::Transport for SharedTlsTransport {
    fn buffers(&mut self) -> &mut dyn ureq::unversioned::transport::Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        use std::io::Write as _;
        use ureq::unversioned::transport::Buffers as _;
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        use std::io::Read as _;
        use ureq::unversioned::transport::Buffers as _;
        self.stream.get_mut().set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

/// The agent the CLI uses to talk to a running nzbfast daemon
/// (`nzbfast stream`), and the only client path that speaks to OUR OWN
/// API rather than to a third party.
///
/// It exists so `--host` can name an `https://` base at all: a daemon
/// started with `--tls-cert`/`--tls-key` serves one listener and one
/// scheme, so a plaintext-only client cannot reach it by any spelling.
///
/// Three choices, none of them the builder's defaults:
///
/// - **nzbkit's shared TLS config**, not ureq's webpki-only one, for the
///   reason the SMTP sender already gives: the trust anchors are exactly
///   the download path's, so `NZBFAST_EXTRA_CA=<cert.pem>` reaches here
///   too. That matters more here than anywhere, because the pair the
///   `serve --tls-cert` help tells a user to make is SELF-SIGNED, and
///   without the extra anchor the very setup we document is unreachable.
///   ureq 3 has no `tls_config` hook for a whole `rustls::ClientConfig`
///   the way ureq 2 did, so it arrives through `SharedTlsConnector`.
/// - **No redirects.** The request carries `X-Api-Key`, and ureq
///   forwards a custom header across a redirect - including one to
///   another host. A daemon has no reason to redirect its own `/api`, so
///   a 3xx is reported rather than followed, and the key never leaves
///   the host the user named.
/// - **The daemon-API SSRF resolver**, which permits loopback, RFC1918,
///   CGNAT and link-local (a NAS, an auto-IP LAN with no DHCP,
///   Tailscale - every real `--host`) and refuses the cloud-metadata
///   endpoints by address ([`is_forbidden_daemon_ip`]). A `--host` is
///   typically typed by a script, and this costs a legitimate one
///   nothing.
pub fn daemon_api_agent(timeout_secs: u64) -> ureq::Agent {
    use ureq::unversioned::transport::Connector as _;
    ureq::Agent::with_parts(
        agent_config(0, timeout_secs),
        ureq::unversioned::transport::TcpConnector::default().chain(SharedTlsConnector),
        DaemonApiResolver,
    )
}

/// Cut every URL in a message down to `scheme://host`, dropping userinfo,
/// path and query.
///
/// `redact_apikey` guards the SEARCH path, where we built the URL and
/// therefore know the credential is spelled `apikey=`. The GRAB path has
/// no such guarantee: the NZB link comes out of the indexer's own XML,
/// and sites spell their credential `apikey`, `api_key`, `r`, `i`, or
/// put it in the path. Blanking one parameter name there is a guess.
/// The host is the only part of such a URL worth showing a user anyway -
/// it names who failed - so everything after it goes.
///
/// A URL is found by its `://`, not by the two lowercase spellings we
/// happen to write ourselves. This used to search for `http://` and
/// `https://` literally, which meant `HTTPS://idx.example/x?apikey=SECRET`
/// went through untouched: the rest of the URL layer compares schemes
/// with `eq_ignore_ascii_case` (`url_host`, `failure_link_allowed`), so a
/// mixed-case link out of an indexer's `X-DNZB-FailureLink` header, or a
/// feed URL an autocapitalising phone keyboard saved, passes every gate
/// and dies in `fetch_head` - whose refusal names the WHOLE url and is
/// logged, exported and returned to the browser. The same literal search
/// left `ftp://user:pw@host/p` unredacted, which `set_feeds` accepts.
pub fn redact_url_creds(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(sep) = rest.find("://") {
        // Walk back over the scheme. RFC 3986 spells it
        // ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) and every one of
        // those is ASCII, so scanning bytes can never land mid-codepoint
        // (these strings come out of response headers and indexer XML,
        // so that matters).
        let bytes = rest.as_bytes();
        let mut p = sep;
        while p > 0
            && matches!(bytes[p - 1],
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'-' | b'.')
        {
            p -= 1;
        }
        // A scheme starts with a letter, so drop any leading digits or
        // punctuation the walk-back picked up. It also stops at the
        // first byte that cannot be in a scheme, so "failed at http://x"
        // keeps its "failed at ".
        while p < sep && !bytes[p].is_ascii_alphabetic() {
            p += 1;
        }
        if p == sep {
            // A bare `://` with no scheme in front of it is prose, not a
            // URL. Copy it through and look past it.
            out.push_str(&rest[..sep + 3]);
            rest = &rest[sep + 3..];
            continue;
        }
        out.push_str(&rest[..p]);
        let url = &rest[p..];
        let scheme_len = sep - p + 3;
        // The authority ends at the first path/query/fragment character,
        // or at whatever ends the URL inside a longer sentence.
        let after = &url[scheme_len..];
        let end = after
            .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
            .unwrap_or(after.len());
        let authority = &after[..end];
        // Userinfo (user:pass@host) is a credential too.
        let host = authority.rsplit('@').next().unwrap_or(authority);
        // Anything else attached to the URL is dropped, up to whitespace.
        let tail = &after[end..];
        let stop = tail.find(char::is_whitespace).unwrap_or(tail.len());
        // ...unless the DROPPED part still holds an `@`, in which case
        // the authority ended early because the PASSWORD contains a
        // '/', '?' or '#'. Unescaped that is malformed by RFC 3986 - the
        // authority really does end at the delimiter - but a redactor
        // that leaks on malformed input is not a redactor: for
        // `http://user:pa/ss@host/p` the rule above yields a "host" of
        // `user:pa`, so the username and the head of the password went
        // into the log line under the name of a host.
        //
        // Ambiguous means redact everything: there is no way to tell
        // which side of that `@` is the credential without deciding
        // whose parser is right, and this function's whole job is that
        // nothing sensitive survives it.
        if tail[..stop].contains('@') {
            out.push_str(&url[..scheme_len]);
            out.push_str("...");
            rest = &tail[stop..];
            continue;
        }
        out.push_str(&url[..scheme_len]);
        out.push_str(host);
        if stop > 0 {
            out.push_str("/...");
        }
        rest = &tail[stop..];
    }
    out.push_str(rest);
    out
}

/// Percent-encode a query value (RFC 3986 unreserved set kept).
///
/// `newznab`'s until the crate-split prep (step 1 of
/// research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md). It is URL text for
/// an outbound request, which is this module's whole subject, and
/// leaving it up in the metadata layer had `xrel` - two layers below -
/// reaching up for it.
pub fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod ureq3_tests {
    use super::*;

    /// One loopback listener that answers every request with `reply`
    /// verbatim, once per connection. Returns its `host:port`.
    ///
    /// Raw bytes rather than a server crate on purpose: the thing under
    /// test is how a REFUSAL's headers reach the caller, so the reply
    /// has to be written exactly as an unhelpful provider would write
    /// it.
    fn one_shot(reply: &'static str, serves: usize) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let addr = l.local_addr().expect("its address").to_string();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for _ in 0..serves {
                let Ok((mut s, _)) = l.accept() else { return };
                // Read whatever the request is, then answer. A read that
                // stops at the headers is enough: nothing here sends a
                // body worth waiting for.
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(reply.as_bytes());
                let _ = s.flush();
            }
        });
        addr
    }

    /// **The port's load-bearing assertion.** ureq 2 raised
    /// `Error::Status(code, response)` and eight sites in this tree read
    /// `Retry-After` off that response; ureq 3's `Error::StatusCode(u16)`
    /// carries nothing, so a literal port would have every one of them
    /// silently fall back to its hardcoded 30 s and hammer a provider on
    /// a schedule it had asked us not to keep - with no test failing.
    ///
    /// This drives the REAL shared enrich agent against a real listener
    /// that refuses with a real header, so it fails if any link in that
    /// chain stops working: the per-request `http_status_as_error(false)`,
    /// the 4xx/5xx classification, or the header parse.
    #[test]
    fn a_429_still_hands_back_the_retry_after_it_was_sent() {
        let addr = one_shot(
            "HTTP/1.1 429 Too Many Requests\r\n\
             Retry-After: 900\r\n\
             Content-Length: 4\r\n\
             Connection: close\r\n\
             \r\n\
             slow",
            1,
        );
        let e = call_body(shared_enrich_agent().get(format!("http://{addr}/x")))
            .expect_err("a 429 is a refusal");
        assert_eq!(e.code(), Some(429));
        assert_eq!(
            e.retry_after(),
            Some(900),
            "the header the provider sent was not read: {e}"
        );
        assert_eq!(e.wait_secs(), Some(900));
        assert!(e.is_slow_down());
    }

    /// A refusal with no `Retry-After` falls back, and the fallback is
    /// the one every call site used to spell for itself.
    #[test]
    fn a_bare_429_falls_back_and_a_503_falls_back_lower() {
        for (code, want) in [(429u16, 30u64), (503, 5)] {
            let addr = one_shot(
                match code {
                    429 => {
                        "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    }
                    _ => {
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    }
                },
                1,
            );
            let e = call_body(shared_enrich_agent().get(format!("http://{addr}/x")))
                .expect_err("a refusal");
            assert_eq!(e.code(), Some(code));
            assert_eq!(e.retry_after(), None);
            assert_eq!(e.wait_secs(), Some(want), "fallback for {code}");
        }
    }

    /// The refusal's BODY survives too - `notify` reports up to 200
    /// characters of it, and `predb_seed` reads the JSON error.
    #[test]
    fn a_refusals_body_is_still_readable() {
        let addr = one_shot(
            "HTTP/1.1 401 Unauthorized\r\n\
             Content-Length: 11\r\n\
             Connection: close\r\n\
             \r\n\
             bad api key",
            1,
        );
        let e = call_keeping_refusal(shared_enrich_agent().get(format!("http://{addr}/x")))
            .expect_err("a 401 is a refusal");
        assert_eq!(e.code(), Some(401));
        assert!(!e.is_slow_down());
        assert_eq!(e.body_text(), "bad api key");
    }

    /// Turning status-as-error off is PER REQUEST. The enrich agent is
    /// shared process-wide and most of its callers want a 4xx to be an
    /// `Err`; a port that had set this on the agent would have changed
    /// every one of them at once, silently.
    #[test]
    fn the_shared_agent_still_raises_a_plain_4xx_as_an_error() {
        let addr = one_shot(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        );
        let e = shared_enrich_agent()
            .get(format!("http://{addr}/x"))
            .call()
            .expect_err("a bare .call() on the shared pool still errors on a 4xx");
        assert!(
            matches!(e, ureq::Error::StatusCode(404)),
            "the agent's own default moved: {e}"
        );
    }

    /// `error_brief` is what every `{refusal}` in this tree prints, and
    /// the one ureq 3 arm that formats the whole request must not reach
    /// a log. A webhook's PATH is its bearer token.
    #[test]
    fn a_bad_uri_error_never_names_the_request() {
        let e = ureq::Error::BadUri(
            "https://discord.example/api/webhooks/1/SUPERSECRET?k=alsosecret is missing scheme"
                .into(),
        );
        let brief = error_brief(&e);
        assert!(!brief.contains("SUPERSECRET"), "{brief}");
        assert!(!brief.contains("alsosecret"), "{brief}");
        assert!(!brief.contains("discord.example"), "{brief}");
        // Still says something.
        assert_eq!(brief, "bad url");
    }

    /// The guards' own refusals arrive as `Error::Io` with the kind and
    /// the message intact, which is what `nettools` matches on to tell
    /// "we refused this address" from "nothing is listening".
    #[test]
    fn a_guard_refusal_keeps_its_kind_and_its_words() {
        let e = super::refused("refusing to fetch an internal address (x:1)".into());
        let ureq::Error::Io(io) = &e else {
            panic!("a guard refusal must stay an io error: {e}");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            e.to_string()
                .contains("refusing to fetch an internal address")
        );
    }

    /// ureq 3's `Config::default()` reads `HTTP_PROXY`/`HTTPS_PROXY`
    /// from the environment where ureq 2 proxied only when asked. With
    /// a proxy in play ureq resolves the PROXY's address rather than
    /// the destination's, so every guard in this module would be
    /// checking the wrong host - the SSRF rule silently off for any
    /// daemon started with the variable set. Every agent built here
    /// therefore pins it off, and this is the assertion that keeps it
    /// pinned.
    #[test]
    fn no_agent_built_here_inherits_a_proxy_from_the_environment() {
        for agent in [
            ssrf_safe_agent(4, 30),
            shared_enrich_agent(),
            daemon_api_agent(10),
            origin_bound_agent(&SourceOrigin::default(), 4, 30),
        ] {
            assert!(
                agent.config().proxy().is_none(),
                "an agent picked up a proxy, which moves what the SSRF guard checks"
            );
        }
    }

    /// **The IPv6 defect the `unversioned::` gate's baseline re-read
    /// found.** ureq derives the TLS peer name with its private
    /// `host_bare()`; both restated connectors used `Authority::host()`,
    /// which keeps the RFC 3986 brackets, and `[::1]` is not a valid DNS
    /// name - so a daemon on `https://[::1]:PORT` was refused "invalid
    /// dns name" before a packet left the box.
    ///
    /// Both literals land on `ServerName::IpAddress` and neither needs a
    /// parse of our own: `try_from` tries the DNS grammar first, and an
    /// all-numeric last label fails it. That is the whole reason the fix
    /// is a bracket strip rather than an `IpAddr::from_str` ladder, so
    /// the variant is asserted rather than merely "it did not error".
    #[test]
    fn an_ipv6_literal_names_the_tls_peer_without_its_brackets() {
        use rustls::pki_types::ServerName;
        let name = |u: &str| tls_peer_name(&u.parse::<ureq::http::Uri>().expect("a uri"));

        let v6 = name("https://[::1]:6789/api").expect("an ipv6 literal names a peer");
        assert!(
            matches!(&v6, ServerName::IpAddress(_)),
            "an ipv6 literal must reach rustls as an address, not a name: {v6:?}"
        );
        assert!(
            matches!(
                name("https://[fe80::1000:ff:fe00:1234]:8443/").expect("a full literal"),
                ServerName::IpAddress(_)
            ),
            "only the loopback spelling was handled"
        );

        let v4 = name("https://127.0.0.1:6789/api").expect("an ipv4 literal names a peer");
        assert!(
            matches!(&v4, ServerName::IpAddress(_)),
            "an ipv4 literal must reach rustls as an address: {v4:?}"
        );

        // A real name still takes the DNS path, brackets or not.
        let dns = name("https://daemon.example:6789/api").expect("a dns name");
        assert!(matches!(&dns, ServerName::DnsName(_)), "{dns:?}");

        // And a genuinely unusable authority is still refused here
        // rather than reaching the handshake. Note that the brackets
        // themselves do not make a host an address: `[not-an-address]`
        // strips to a perfectly valid DNS name and takes the DNS path,
        // which is why the invalid case has to fail the DNS grammar
        // too (a leading hyphen does).
        assert!(matches!(
            name("https://[-bad-]/"),
            Err(ureq::Error::Tls("invalid dns name"))
        ));
        assert!(matches!(
            tls_peer_name(
                &"/api?mode=version"
                    .parse::<ureq::http::Uri>()
                    .expect("a uri")
            ),
            Err(ureq::Error::Tls("no authority for tls"))
        ));
    }

    /// The end-to-end half: the REAL `daemon_api_agent` chain against a
    /// listener on IPv6 loopback. Before the bracket strip this died in
    /// `SharedTlsConnector::connect` with no connection made at all;
    /// the assertion is therefore that the listener saw a TLS
    /// ClientHello (record type 0x16), which can only happen once the
    /// peer name has been accepted and `complete_io` has run.
    ///
    /// The listener answers nothing, so the CALL always fails - a
    /// trusted end-entity certificate for `::1` would need a CA minted
    /// and `NZBFAST_EXTRA_CA` set, and that variable is read
    /// process-wide by a shared config cache, so a `set_var` here would
    /// reach every other test in this one-process crate. What is under
    /// test is the name, and the ClientHello proves the name.
    ///
    /// Hermetic by construction (invariant 5a): the host is an IP
    /// literal, so `deny_test_callout` permits it and nothing resolves.
    #[test]
    fn a_daemon_on_ipv6_loopback_gets_a_real_handshake_attempt() {
        for bind in ["[::1]:0", "127.0.0.1:0"] {
            let l = std::net::TcpListener::bind(bind)
                .unwrap_or_else(|e| panic!("a loopback listener on {bind}: {e}"));
            let addr = l.local_addr().expect("its address").to_string();
            let seen = std::thread::spawn(move || {
                use std::io::Read as _;
                let Ok((mut s, _)) = l.accept() else {
                    return Vec::new();
                };
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).unwrap_or(0);
                buf[..n].to_vec()
            });

            let e = daemon_api_agent(10)
                .get(format!("https://{addr}/api?mode=version"))
                .call()
                .expect_err("the listener never completes a handshake");
            assert!(
                !matches!(e, ureq::Error::Tls("invalid dns name")),
                "{bind} was refused before it was dialled: {e}"
            );

            let hello = seen.join().expect("the listener thread");
            assert_eq!(
                hello.first(),
                Some(&0x16u8),
                "{bind} saw no TLS ClientHello - the handshake was never reached"
            );
        }
    }

    /// ureq 2 handed back the last response once the redirect cap was
    /// reached; ureq 3 raises `TooManyRedirects` instead. Three callers
    /// use `redirects = 0` to mean "do not follow, tell me what it
    /// said" - `nzbfast stream` reports a 3xx as its own diagnostic and
    /// `notify` reports the status it got.
    #[test]
    fn a_redirect_at_the_cap_is_still_the_response_and_not_an_error() {
        let addr = one_shot(
            "HTTP/1.1 302 Found\r\n\
             Location: http://example.invalid/\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n",
            1,
        );
        let resp = ssrf_safe_agent(0, 10)
            .get(format!("http://{addr}/x"))
            .call()
            .expect("a 3xx at the cap comes back as a response");
        assert_eq!(resp.status().as_u16(), 302);
    }
}
