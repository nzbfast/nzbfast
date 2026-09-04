//! Hand-rolled http(s) URL authority parsing - the host / netloc
//! extraction behind the daemon's origin-bound fetch rules
//! (`failure_link_allowed`, `OriginBoundResolver` in nzbfast's
//! fetch.rs). Lives here rather than in the daemon so the fuzz
//! harness (`crates/nzbkit/fuzz`, target `url_authority_diff`) can
//! reach it: these functions run over attacker-influenced strings, and
//! the fuzz target pins them differentially against the `url` crate -
//! the parser ureq actually dials with.
//!
//! Hand-rolled because the daemon has no URL crate (the `url` crate is
//! a fuzz-harness-only dependency). These parse less than a real one,
//! and everything they cannot parse comes back empty, which fails the
//! origin match - the safe direction.

/// The host of an http(s) URL, lowercased, without userinfo and without
/// the port - or empty when there isn't one. Deliberately port-blind: an
/// indexer that serves NZBs on :9117 and reports failures on :9118 is
/// still the same machine, and the check is about WHOSE server we call,
/// not which socket.
pub fn url_host(url: &str) -> String {
    let rest = match url.split_once("://") {
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") =>
        {
            rest
        }
        _ => return String::new(),
    };
    // Authority ends at the first '/', '?', '#' - or '\', which for a
    // special scheme (http/https both are) the WHATWG URL parser treats
    // exactly like '/'. Leaving it out made this disagree with the
    // parser that actually dials: ureq hands the string to `url`, whose
    // userinfo scan and host scan BOTH break at a backslash, so
    // `https://192.168.1.1\@indexer.example/x` connects to 192.168.1.1
    // while this function - splitting only on '/?#', then taking the
    // part after the last '@' - answered `indexer.example`. That is the
    // whole failure-link origin check inverted: the one guard stopping
    // an indexer aiming the daemon at an arbitrary LAN address (loopback
    // and RFC1918 are deliberately allowed) passed a link that went
    // somewhere else, and the refusal/report log lines printed the host
    // it did NOT visit.
    let auth = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    // `user:pass@host` - the LAST '@' separates them, so a password
    // containing '@' cannot smuggle a fake host in front of the real one.
    let hostport = match auth.rsplit_once('@') {
        Some((_, h)) => h,
        None => auth,
    };
    // `[::1]:8080` - the bracketed literal is the host; a bare IPv6 with
    // no brackets is not a legal authority and drops out as empty below.
    let host = if let Some(end) = hostport.find(']') {
        if hostport.starts_with('[') {
            &hostport[..=end]
        } else {
            ""
        }
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    host.to_ascii_lowercase()
}

/// `host:port` of an http(s) URL - [`url_host`] plus the port, with the
/// scheme's default filled in when the URL omits it - or empty when the
/// URL does not parse. This is the spelling ureq hands its resolver, so
/// `OriginBoundResolver` can compare the two as strings.
///
/// Port-bearing where `url_host` is port-blind, deliberately: see that
/// resolver for why the enclosure rule counts a neighbouring port on the
/// same private host as a different destination.
///
/// One known divergence: the `url` crate punycodes a non-ASCII host and
/// this does not, so an IDN origin never matches and its own links are
/// treated as cross-origin. That only costs a private IDN indexer, and
/// it costs it the safe way - refused, not waved through.
pub fn url_netloc(url: &str) -> String {
    let host = url_host(url);
    if host.is_empty() {
        return String::new();
    }
    // `host` was cut out of this authority by `url_host`, so it is a
    // prefix of it (ASCII lowercasing preserves byte length) and what
    // follows is either empty or `:port`.
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or("");
    let auth = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    let hostport = match auth.rsplit_once('@') {
        Some((_, h)) => h,
        None => auth,
    };
    let https = url.len() >= 8 && url.as_bytes()[..8].eq_ignore_ascii_case(b"https://");
    // A port that is present but not a number is not something we can
    // reason about - and ureq will refuse the URL outright anyway - so
    // fall back to the scheme default and let the fetch fail there.
    let port = hostport
        .get(host.len()..)
        .and_then(|t| t.strip_prefix(':'))
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(if https { 443 } else { 80 });
    format!("{host}:{port}")
}
