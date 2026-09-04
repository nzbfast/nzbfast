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

/// CLAUDE.md invariant 5, made structural: in a unit-test build every
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

/// ureq resolver that refuses to hand back any internal address. Because
/// ureq connects to exactly the SocketAddrs returned here (no second
/// lookup), this closes the DNS-rebinding window AND re-checks on every
/// redirect hop, since each hop resolves through it.
pub struct SsrfGuardResolver;
impl ureq::Resolver for SsrfGuardResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<std::net::SocketAddr> = netloc.to_socket_addrs()?.collect();
        note_resolution(netloc, &addrs);
        deny_test_callout(netloc, &addrs)?;
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no address",
            ));
        }
        if addrs.iter().any(|a| is_forbidden_fetch_ip(a.ip())) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to fetch an internal address ({netloc})"),
            ));
        }
        Ok(addrs)
    }
}

/// [`SsrfGuardResolver`] with the daemon-API carve-out
/// ([`is_forbidden_daemon_ip`]): link-local is reachable, its metadata
/// endpoints are not. Only [`daemon_api_agent`] installs it - the
/// enrich and user-URL agents keep the full guard.
pub(crate) struct DaemonApiResolver;
impl ureq::Resolver for DaemonApiResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<std::net::SocketAddr> = netloc.to_socket_addrs()?.collect();
        deny_test_callout(netloc, &addrs)?;
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no address",
            ));
        }
        if addrs.iter().any(|a| is_forbidden_daemon_ip(a.ip())) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to fetch an internal address ({netloc})"),
            ));
        }
        Ok(addrs)
    }
}

/// An agent whose every connection (initial + each redirect) is filtered
/// through the SSRF guard. Use for ANY fetch of a user/attacker-supplied
/// URL. `redirects` is capped by the caller.
pub fn ssrf_safe_agent(redirects: u32, timeout_secs: u64) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .resolver(SsrfGuardResolver)
        .redirects(redirects)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
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
/// to the origin is the same move [`failure_link_allowed`] already makes
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

impl ureq::Resolver for OriginBoundResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<std::net::SocketAddr> = netloc.to_socket_addrs()?.collect();
        // Recorded here as well as in the plain guard so that
        // `Fetched.addrs` means the same thing whichever tier fetched
        // it: where the url we ASKED for resolved to.
        note_resolution(netloc, &addrs);
        deny_test_callout(netloc, &addrs)?;
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no address",
            ));
        }
        if addrs.iter().any(|a| is_forbidden_fetch_ip(a.ip())) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to fetch an internal address ({netloc})"),
            ));
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing a link to {netloc}: it is inside this network \
                     and is not the source that supplied it{}",
                    if self.origin.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", self.origin)
                    }
                ),
            ));
        }
        // Same netloc, private address: allowed only for an address the
        // source answered the search from. EVERY private address in the
        // answer has to qualify, not just one - ureq picks which of them
        // to dial, so a resolver that returns the real public address
        // beside a loopback one would otherwise smuggle the loopback in.
        if let Some(bad) = private.iter().find(|ip| !self.witnessed.contains(ip)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing a link to {netloc}: it resolves to {bad} inside \
                     this network, which is not an address it answered the \
                     search from"
                ),
            ));
        }
        Ok(addrs)
    }
}

/// [`SsrfGuardResolver`] plus the PRODUCTION half of CLAUDE.md
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
pub struct EnrichResolver;
impl ureq::Resolver for EnrichResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        let addrs = <SsrfGuardResolver as ureq::Resolver>::resolve(&SsrfGuardResolver, netloc)?;
        if !crate::identity::may_call_out() && !addrs.iter().all(|a| a.ip().is_loopback()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "enrichment is switched off, so {netloc} was not contacted \
                     (CLAUDE.md invariant 5 - unset NZBFAST_NO_ENRICH \
                     to allow it)"
                ),
            ));
        }
        Ok(addrs)
    }
}

/// An agent for fetching a link that `origin`'s RESPONSE supplied.
/// Every hop - the link itself and each redirect - goes through
/// [`OriginBoundResolver`].
pub fn origin_bound_agent(origin: &SourceOrigin, redirects: u32, timeout_secs: u64) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .resolver(OriginBoundResolver::new(origin))
        .redirects(redirects)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
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
            ureq::AgentBuilder::new()
                .resolver(EnrichResolver)
                .redirects(4)
                .timeout(std::time::Duration::from_secs(30))
                .build()
        })
        .clone()
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
    ureq::AgentBuilder::new()
        .resolver(DaemonApiResolver)
        .redirects(0)
        .tls_config(nzbkit::nntp::shared_tls_client_config())
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
}

/// Cut every URL in a message down to `scheme://host`, dropping userinfo,
/// path and query.
///
/// [`redact_apikey`] guards the SEARCH path, where we built the URL and
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
        out.push_str(&url[..scheme_len]);
        out.push_str(host);
        // Anything else attached to the URL is dropped, up to whitespace.
        let tail = &after[end..];
        let stop = tail.find(char::is_whitespace).unwrap_or(tail.len());
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
