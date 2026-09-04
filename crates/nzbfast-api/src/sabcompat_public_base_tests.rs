//! Tests for `public_base`'s scheme+authority arithmetic.
//!
//! Split out of sabcompat.rs to keep it under the TODO 106 ceiling.
//! The seam these drive (`public_base_from`) exists because a
//! native-TLS listener is otherwise only reachable through a whole
//! daemon with a certificate on disk.

use super::public_base_from;

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

/// A proxy that terminated TLS still decides the scheme, whichever
/// way this listener itself is bound - that is the whole point of
/// the forwarded headers, and the case the daemon cannot see.
#[test]
fn forwarded_headers_win_over_the_listener() {
    assert_eq!(
        public_base_from(
            s("nzb.example.com"),
            s("127.0.0.1:6789"),
            s("https"),
            "http",
            6789
        ),
        "https://nzb.example.com"
    );
    // ...including downwards: a proxy that speaks plain http to its
    // clients while re-encrypting to us is unusual but legal, and
    // echoing our own https would hand out links it cannot serve.
    assert_eq!(
        public_base_from(s("nzb.example.com"), None, s("http"), "https", 6789),
        "http://nzb.example.com"
    );
    // Multi-hop: the first entry is the client-facing one.
    assert_eq!(
        public_base_from(
            s("nzb.example.com, inner.lan"),
            None,
            s("https, http"),
            "http",
            6789
        ),
        "https://nzb.example.com"
    );
}

/// M2: with no proxy in front, the fallback is what we actually
/// bound. This is the regression - it used to be a hardcoded `http`,
/// so a native-TLS daemon handed *arrs and players plaintext links
/// to a socket that only speaks TLS.
#[test]
fn a_direct_request_gets_the_listeners_own_scheme() {
    assert_eq!(
        public_base_from(None, s("127.0.0.1:6789"), None, "https", 6789),
        "https://127.0.0.1:6789"
    );
    assert_eq!(
        public_base_from(None, s("127.0.0.1:6789"), None, "http", 6789),
        "http://127.0.0.1:6789"
    );
    // No Host either (HTTP/1.0, or a bare probe): still our scheme.
    assert_eq!(
        public_base_from(None, None, None, "https", 6789),
        "https://127.0.0.1:6789"
    );
}

/// An unrecognised forwarded scheme is dropped, not echoed into a
/// URL - and dropping it now lands on our own scheme, not on http.
#[test]
fn a_junk_scheme_falls_back_to_the_listener() {
    assert_eq!(
        public_base_from(None, s("h:1"), s("javascript"), "https", 6789),
        "https://h:1"
    );
    assert_eq!(
        public_base_from(None, s("h:1"), s(""), "https", 6789),
        "https://h:1"
    );
}

/// An empty `X-Forwarded-Host` must not blank the authority - it
/// falls through to `Host`, as it always did.
#[test]
fn an_empty_forwarded_host_falls_through() {
    assert_eq!(
        public_base_from(s(""), s("127.0.0.1:6789"), None, "https", 6789),
        "https://127.0.0.1:6789"
    );
}
