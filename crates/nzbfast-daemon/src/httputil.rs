//! HTTP request plumbing: the wrong-key throttle, key extraction and
//! constant-time comparison, query/form/multipart parsing, and the JSON
//! response helper.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Wrong keys tolerated from one address inside [`AUTH_FAIL_WINDOW`] before
/// it is refused outright. Generous: a misconfigured *arr retries a handful
/// of times, and locking that out helps nobody.
pub const AUTH_FAIL_THRESHOLD: u32 = 10;
/// How long the failure count is remembered. Also the block duration - the
/// count resets by simply going quiet, so there is no permanent lockout and
/// no state to unstick.
pub(super) const AUTH_FAIL_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Ceiling on tracked addresses, so the map itself cannot be the attack.
pub const AUTH_FAIL_MAX_TRACKED: usize = 4096;

impl Daemon {
    /// Record a rejected API key and decide whether this address has had
    /// enough. `true` = refuse without doing any further work.
    ///
    /// Deliberately refuses FAST rather than sleeping. The obvious throttle
    /// is a delay before answering, but responses are written on the small
    /// shared worker pool, so a delay is exactly the worker-occupancy problem
    /// a slowloris exploits - it would harden the key and hand over the
    /// dashboard. Refusing immediately costs an attacker the same round trip
    /// and costs us nothing.
    ///
    /// Returns false (allow) when the address is unknown or the table is
    /// full: failing open on *accounting* is fine, the key check itself still
    /// has to pass.
    pub fn note_auth_failure(&self, addr: Option<std::net::IpAddr>, what: &str) -> bool {
        note_auth_failure_in(&self.auth_fails, addr, what)
    }
}

/// The accounting itself, split out from `Daemon` so it can be tested
/// without standing up a whole daemon.
pub fn note_auth_failure_in(
    table: &Mutex<std::collections::HashMap<std::net::IpAddr, (u32, Instant)>>,
    addr: Option<std::net::IpAddr>,
    what: &str,
) -> bool {
    {
        let Some(ip) = addr else { return false };
        let now = Instant::now();
        let mut fails = table.lock_ok();
        if fails.len() >= AUTH_FAIL_MAX_TRACKED {
            fails.retain(|_, (_, seen)| now.duration_since(*seen) < AUTH_FAIL_WINDOW);
            if fails.len() >= AUTH_FAIL_MAX_TRACKED {
                return false;
            }
        }
        let entry = fails.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= AUTH_FAIL_WINDOW {
            *entry = (0, now);
        }
        entry.0 += 1;
        let count = entry.0;
        // Log the first, then only on crossing, so a flood cannot be used to
        // fill the disk through the log.
        if count == 1 {
            warn!(target: "auth", "rejected key for {what} from {ip}");
        } else if count == AUTH_FAIL_THRESHOLD {
            warn!(
                target: "auth",
                "{count} rejected keys from {ip} in under {}s - refusing it for {}s",
                AUTH_FAIL_WINDOW.as_secs(),
                AUTH_FAIL_WINDOW.as_secs()
            );
        }
        count >= AUTH_FAIL_THRESHOLD
    }
}

/// The client address of a request, when the transport knows one.
pub fn peer_ip(req: &tiny_http::Request) -> Option<std::net::IpAddr> {
    req.remote_addr().map(|a| a.ip())
}

/// Constant-time-ish string equality for the stream token - a plain ==
/// short-circuits on the first differing byte.
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Issue #4: the API key may ride a header instead of the query string,
/// which keeps it out of reverse-proxy access logs, browser history and
/// outbound Referer headers - the leak paths of a `?apikey=` URL on an
/// internet-published install. `X-Api-Key: <key>` (the *arr convention)
/// or `Authorization: Bearer <key>` (what auth proxies inject). The
/// query string still wins when both are present and stays supported
/// forever - Sonarr/Radarr and plain links can only do URLs.
pub fn header_apikey(req: &tiny_http::Request) -> Option<String> {
    let hv = |name: &'static str| {
        req.headers()
            .iter()
            .find(|h| h.field.equiv(name))
            .map(|h| h.value.as_str().trim().to_string())
            .filter(|v| !v.is_empty())
    };
    hv("X-Api-Key").or_else(|| {
        hv("Authorization").and_then(|v| {
            // RFC 7235: the scheme token is case-insensitive. Matching
            // only the two spellings we happened to think of rejected a
            // compliant `BEARER <key>` from an auth proxy that
            // normalizes headers.
            let (scheme, rest) = v.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| rest.trim().to_string())
                .filter(|s| !s.is_empty())
        })
    })
}

/// The credentials part of an `Authorization` header whose scheme is
/// `scheme`, compared the way RFC 7235 requires: the scheme token is
/// case-INSENSITIVE.
///
/// Split out because /jsonrpc did this twice with a literal
/// `strip_prefix("Basic ")`, so a client sending `basic` or `BASIC` - both
/// compliant, and what some proxies and HTTP libraries emit - got a 401
/// with correct credentials. The Bearer parser above already got this
/// right (Codex sweep 12 Aug F18).
pub fn auth_credentials(req: &tiny_http::Request, scheme: &str) -> Option<String> {
    let v = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))?
        .value
        .as_str();
    auth_scheme_value(v, scheme)
}

/// [`auth_credentials`] over the header VALUE, so the rule is testable
/// without standing up a socket.
pub(super) fn auth_scheme_value(header: &str, scheme: &str) -> Option<String> {
    // split_whitespace, not split_once(' '): a header is allowed more than
    // one space between the token and the credentials, and it handles a
    // leading one too.
    let mut parts = header.split_whitespace();
    let got = parts.next()?;
    if !got.eq_ignore_ascii_case(scheme) {
        return None;
    }
    let cred = parts.next()?;
    (!cred.is_empty()).then(|| cred.to_string())
}

/// The `Origin` a browser stamped on this request, if any.
///
/// Absent on curl, on the *arrs, and on every server-side caller - which
/// is the point: [`cors_headers`] only has work to do when a browser is
/// asking.
pub fn origin_hdr(req: &tiny_http::Request) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv("Origin"))
        .map(|h| h.value.as_str().trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Default `cors_origin`: what real SABnzbd answers on its API.
///
/// §141 (issue #33). We sent no Access-Control header anywhere, so
/// Firefox blocked the NZB Unity extension against us while SABnzbd on
/// the same box worked - and under §105.4 anything real SAB sends and we
/// omit is our bug, because a client cannot tell a missing feature from
/// a broken daemon. The permissive default costs no authentication: the
/// API key travels explicitly on every request, and CORS gates what a
/// browser PAGE may READ, it is not the authentication layer. Narrowing
/// it on security grounds would reintroduce exactly the breakage the
/// issue reports.
pub const CORS_DEFAULT: &str = "*";

/// The `Access-Control-*` headers the SAB-compatible API answers with.
///
/// `allow` is the `cors_origin` setting: `*` (the default), a
/// comma-separated list of origins, or empty for no header at all.
/// `origin` is the caller's own `Origin`. In list mode the answer names
/// ONE origin - a browser accepts exactly one value - so the caller's is
/// matched against the list and the CONFIGURED spelling is what goes out.
/// Echoing the request's own bytes back would put attacker text in a
/// response header, and tiny_http header values are `AsciiString` with
/// CR and LF firmly inside ASCII: that is the response-splitting shape
/// the `/watch` redirect already learned once. `Vary: Origin` rides
/// every list-mode answer so a shared cache cannot serve one origin's
/// permission to another.
///
/// `preflight` adds the OPTIONS-only trio. Without an answer to the
/// preflight Firefox never sends the real request, so the header on the
/// real response would never be seen.
pub fn cors_headers(allow: &str, origin: Option<&str>, preflight: bool) -> Vec<tiny_http::Header> {
    let allow = allow.trim();
    if allow.is_empty() {
        return Vec::new();
    }
    let wildcard = allow == "*";
    let value = if wildcard {
        Some("*".to_string())
    } else {
        origin.and_then(|o| {
            allow
                .split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                // Scheme and host are case-insensitive (RFC 6454); the
                // configured spelling is the one emitted either way.
                .find(|e| e.eq_ignore_ascii_case(o))
                .map(str::to_string)
        })
    };
    // `from_bytes` refuses a value that is not printable ASCII, and
    // `set_cors_origin` has already gated the charset - but this is a
    // response header built on a worker with no catch_unwind around it,
    // so a bad value drops the header rather than killing the worker for
    // the life of the process.
    let mk =
        |name: &str, v: &str| tiny_http::Header::from_bytes(name.as_bytes(), v.as_bytes()).ok();
    let mut out = Vec::new();
    if let Some(v) = &value {
        out.extend(mk("Access-Control-Allow-Origin", v));
    }
    if !wildcard {
        out.extend(mk("Vary", "Origin"));
    }
    if preflight {
        out.extend(mk("Access-Control-Allow-Methods", "GET, POST, OPTIONS"));
        // The three ways a key reaches us off the query string, plus the
        // content types the addons post. `Content-Type` is only
        // preflight-free for the form encodings; NZB Unity's JSON probes
        // are not, which is how a browser ends up here at all.
        out.extend(mk(
            "Access-Control-Allow-Headers",
            "Content-Type, X-Api-Key, Authorization",
        ));
        // A day: the addons repeat the same call constantly and each
        // uncached preflight is a second round trip.
        out.extend(mk("Access-Control-Max-Age", "86400"));
    }
    out
}

/// Hang [`cors_headers`] on a response. Separate from building them so
/// the two `/api` exits - the 403 refusal and the dispatched answer -
/// cannot disagree about the header set.
pub fn with_cors<R: std::io::Read>(
    resp: tiny_http::Response<R>,
    headers: Vec<tiny_http::Header>,
) -> tiny_http::Response<R> {
    let mut resp = resp;
    for h in headers {
        resp.add_header(h);
    }
    resp
}

pub fn parse_query(q: &str) -> std::collections::HashMap<String, String> {
    q.split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((k.to_string(), urldecode(v)))
        })
        .collect()
}

/// [`parse_query`] for a REQUEST BODY, bounded the way `multipart_fields`
/// is and for exactly the same reason.
///
/// A query string is bounded by tiny_http's header limit before it ever
/// reaches `parse_query`. A body is not: the /api pre-drain reads up to
/// `API_BODY_MAX` (256 MiB) BEFORE authenticating, so a form of that size
/// full of tiny `k=` pairs turned into tens of millions of live `String`
/// allocations - several GB of resident set, from an unauthenticated
/// request, decided long before the 403. The multipart sibling has
/// carried these two caps since it was written; the form path beside it
/// never got them.
///
/// Same figures as `multipart_fields`: 256 fields, 4096 bytes a value.
/// Every real caller is far inside both - the largest legitimate body
/// field is an NZB, which arrives as a multipart FILE part, not here.
pub fn parse_form_body(q: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for kv in q.split('&') {
        if out.len() >= 256 {
            break;
        }
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        if k.is_empty() || k.len() > 256 || v.len() > 4096 {
            continue;
        }
        out.push((k.to_string(), urldecode(v)));
    }
    out
}

pub(super) fn urldecode(s: &str) -> String {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 3 <= b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// NZBGet's in-URL credential form, `/<user>:<pass>/jsonrpc[/…]`, with
/// the password percent-decoded. This is how NZBGet itself documents
/// authenticated RPC and the only form LunaSea sends (it never sets an
/// Authorization header), so the /jsonrpc facade must recognise it or
/// a keyed daemon is unreachable from that app (§18). The username is
/// ignored, matching the facade's Basic-auth arm: nzbfast has keys,
/// not accounts. Only the exact two-segment prefix matches - anything
/// else stays on the normal 404 path.
pub fn jsonrpc_path_password(path: &str) -> Option<String> {
    let mut seg = path.strip_prefix('/')?.split('/');
    let cred = seg.next()?;
    if seg.next()? != "jsonrpc" {
        return None;
    }
    let (_user, pass) = cred.split_once(':')?;
    Some(urldecode(pass))
}

/// A multipart part's header block is a handful of short ASCII lines
/// (Content-Disposition with a name/filename, maybe a Content-Type).
/// Bounding it BEFORE decoding matters more than usual here: this runs
/// pre-authentication on a body of up to 256 MiB, and
/// `String::from_utf8_lossy` expands each invalid byte to a 3-byte
/// replacement character - so one part whose "header" is the whole body
/// used to allocate ~3x the body on top of it (Codex H8). 8 KiB is far
/// past any legitimate filename.
pub(super) const MAX_PART_HEADER: usize = 8 << 10;

/// Extract (filename, bytes) of the first file part in a multipart body.
pub fn multipart_file(body: &[u8], boundary: &str) -> Option<(String, Vec<u8>)> {
    if !valid_boundary(boundary) {
        return None;
    }
    let delim = format!("--{boundary}");
    let mut found = None;
    for_each_split(body, delim.as_bytes(), |part| {
        let Some(hdr_end) = find_bytes(part, b"\r\n\r\n") else {
            return true; // preamble/epilogue segments have no header block
        };
        if hdr_end > MAX_PART_HEADER {
            return true; // attacker-sized header: never decode it
        }
        let headers = String::from_utf8_lossy(&part[..hdr_end]);
        if let Some(fn_pos) = headers.find("filename=\"") {
            let rest = &headers[fn_pos + 10..];
            let fname = rest.split('"').next().unwrap_or("upload.nzb").to_string();
            let mut content = &part[hdr_end + 4..];
            // Strip the trailing \r\n before the next boundary.
            if content.ends_with(b"\r\n") {
                content = &content[..content.len() - 2];
            }
            found = Some((fname, content.to_vec()));
            return false;
        }
        true
    });
    found
}

/// Extract (name, value) of every NON-file field of a multipart body -
/// the parts carrying no `filename=`. SAB-compat: browser addons send
/// api parameters (mode, apikey, cat, nzbname) this way on POST. Values
/// keep multipart's trailing-CRLF strip; anything file-sized is skipped
/// - a parameter is short, and treating a mis-labelled upload as one
/// would copy megabytes into a HashMap key nobody reads.
pub fn multipart_fields(body: &[u8], boundary: &str) -> Vec<(String, String)> {
    if !valid_boundary(boundary) {
        return Vec::new();
    }
    let delim = format!("--{boundary}");
    let mut out: Vec<(String, String)> = Vec::new();
    for_each_split(body, delim.as_bytes(), |part| {
        // A form carrying thousands of fields is not a form. This runs
        // before authentication, on a body of up to 256 MiB, so the
        // parser's own working set has to be bounded by something other
        // than the attacker's segment count.
        if out.len() >= 256 {
            return false;
        }
        let Some(hdr_end) = find_bytes(part, b"\r\n\r\n") else {
            return true; // preamble/epilogue segments have no header block
        };
        if hdr_end > MAX_PART_HEADER {
            return true; // attacker-sized header: never decode it
        }
        let headers = String::from_utf8_lossy(&part[..hdr_end]);
        if headers.contains("filename=\"") {
            return true; // the file part is multipart_file's business
        }
        let Some(np) = headers.find("name=\"") else {
            return true;
        };
        let name = headers[np + 6..]
            .split('"')
            .next()
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            return true;
        }
        let mut content = &part[hdr_end + 4..];
        if content.ends_with(b"\r\n") {
            content = &content[..content.len() - 2];
        }
        if content.len() > 4096 {
            return true;
        }
        out.push((name, String::from_utf8_lossy(content).into_owned()));
        true
    });
    out
}

/// Minimal magic-number sniff for user-supplied poster bytes (M21
/// wall_art): JPEG / PNG / GIF / WebP. Anything else is refused before
/// it can land in the art cache.
#[cfg(feature = "indexer")]
pub fn looks_image(b: &[u8]) -> bool {
    b.starts_with(&[0xFF, 0xD8, 0xFF])
        || b.starts_with(&[0x89, b'P', b'N', b'G'])
        || b.starts_with(b"GIF8")
        || (b.len() >= 12 && b.starts_with(b"RIFF") && &b[8..12] == b"WEBP")
}

/// Split `hay` on `needle`, calling `f` with each segment; stops early
/// when `f` returns false.
///
/// Deliberately not the `Vec<&[u8]>` this replaced. That vector was the
/// multipart parser's amplifier: one fat pointer per delimiter, 16 bytes
/// on 64-bit, so a body made of nothing but delimiters turned a 256 MiB
/// read into roughly 2 GiB of Vec on top of it - allocated before
/// authentication, and outside the body budget that bounds the read
/// itself. Iterating costs a constant.
pub(super) fn for_each_split<'a>(
    hay: &'a [u8],
    needle: &[u8],
    mut f: impl FnMut(&'a [u8]) -> bool,
) {
    // An empty needle matches everywhere: `find_bytes` returns Some(0)
    // for every position and the walk never advances. Callers reject
    // empty boundaries before this, but the primitive must not depend
    // on that.
    if needle.is_empty() {
        f(hay);
        return;
    }
    let mut start = 0;
    while let Some(pos) = find_bytes(&hay[start..], needle) {
        if !f(&hay[start..start + pos]) {
            return;
        }
        start += pos + needle.len();
    }
    f(&hay[start..]);
}

/// Is this a multipart boundary we will parse at all?
///
/// RFC 2046 puts a boundary at 1-70 characters of a restricted set. The
/// length bound is what matters here: an EMPTY boundary - which
/// `Content-Type: multipart/form-data; boundary=` supplies, and which
/// nothing legitimate sends - makes the delimiter `--`, so a body of
/// repeated hyphens splits into a segment every two bytes.
pub fn valid_boundary(b: &str) -> bool {
    !b.is_empty() && b.len() <= 70 && !b.contains('\r') && !b.contains('\n')
}

/// The multipart boundary in a `Content-Type`, or None when the header
/// does not carry a usable one.
///
/// ONE copy, because there were three and they disagreed. The parameter
/// NAME is case-insensitive like the media type around it, but the
/// VALUE is a literal delimiter that has to keep its case - so the
/// position is found in a lowercased copy and the text is cut from the
/// original. The gateway learned that in Codex sweep 2's H1 while the
/// two handler-side copies stayed case-sensitive, which left `Boundary=`
/// parsing at the gateway (fields merged, auth decided) and failing in
/// the handler (no file part at all).
///
/// [`valid_boundary`] is applied here rather than by callers: an empty
/// `boundary=` makes the delimiter `--`, so a body of hyphens splits
/// once every two bytes. Nothing legitimate sends one, and refusing it
/// at the source means no caller can forget to.
pub fn multipart_boundary(ctype: &str) -> Option<String> {
    let at = ctype.to_ascii_lowercase().find("boundary=")? + "boundary=".len();
    // The value ends at the parameter separator, not at the end of the
    // header. Taking the rest of the line swept up whatever followed:
    // an ordinary `boundary="----abc"; charset=UTF-8` became
    // `----abc"; charset=UTF-8` (the leading quote trimmed, the trailing
    // one buried mid-string), which appears nowhere in the body. The
    // split then found no delimiter, so the upload's file part was
    // silently dropped as "no nzb file in request" - and a caller whose
    // apikey travelled in the body had it stop being found at all,
    // presenting a content-type problem as an authentication failure,
    // which is the hardest possible thing to support.
    //
    // Cut from the ORIGINAL, so the delimiter keeps its case; `at` is
    // valid there because the needle is ASCII and lowercasing does not
    // move byte offsets for it.
    let rest = ctype[at..].trim_start();
    let value = match rest.strip_prefix('"') {
        // Quoted: to the closing quote. A quoted value may legally hold
        // characters that would otherwise end the parameter.
        Some(q) => q.split('"').next().unwrap_or_default(),
        None => rest.split(';').next().unwrap_or_default().trim_end(),
    };
    Some(value.to_string()).filter(|b| valid_boundary(b))
}

pub fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn json_resp(v: Value) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let data = v.to_string().into_bytes();
    tiny_http::Response::from_data(data).with_header(
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
    )
}

/// May a scan pass that began at `pass_era` hand its freshly-opened
/// connection to the daemon, given the current `era` and switch state?
///
/// Both conditions, because they fail differently. A stale era means the
/// database itself was replaced (wiped) under the pass, so the
/// connection points at a file nobody wants back. `!enabled` means no
/// source wants the database any more - the user switched the last one
/// off during the pass: the era may well still match - switching off
/// does bump it, but a pass could equally have started while off - and
/// "closed" has to stay closed.
#[cfg(feature = "indexer")]
pub fn may_publish_index(era: u64, pass_era: u64, enabled: bool) -> bool {
    era == pass_era && enabled
}

// `query_escape` came from `http.rs` on 2 Sep 2026 and is here because
// this module is BELOW the HTTP wiring: `bootstrap` builds a handoff URL
// with it and `sabcompat::newznab` builds a newznab feed URL with it,
// and neither has any other business with the request loop. It is the
// same nine lines, unchanged.
/// Percent-encode one query VALUE for a URL the daemon generates.
/// Generated hex keys pass through unchanged; a user-chosen key holding
/// `&`, `+`, `%` or `#` sent raw changes the parsed query and breaks
/// every link that carries it (Codex sweep 10 Aug L1). Everything
/// outside the RFC 3986 unreserved set is encoded.
pub fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

// A FREE FUNCTION and not an inherent method, since the serve split
// (lane 1b): an inherent impl must live in its type's crate, so an
// `impl Daemon` block would pin its carrier module into the daemon
// crate whatever else that module depends on. Nothing about this wanted
// to be a method - it reads one field.
//
// AND IT IS HERE RATHER THAN IN `startup`, which is where it sat while
// it was a method, for the reason the lift made visible: every caller
// is building a LINK - the six in this module, four settings setters,
// the SAB facade and the worker prestart banner - and `startup` is
// wiring that stays in the bin. As a method that dependency was
// invisible to `tools/modgraph.py --serve`; as a free function it read
// as six daemon-layer modules depending on the wiring, which is what
// the arm is for. `resolve_tls_pair` in `startup` still SETTLES the
// pair; this only reports what it settled.
/// The scheme THIS listener answers on, for every link we hand a
/// client. Bind-time state like `port`, and the pair is
/// both-or-neither (see `resolve_tls_pair`), so `tls_cert` decides.
///
/// Links used to say `http` unconditionally, which a reverse proxy
/// could correct with `X-Forwarded-Proto` but a DIRECT TLS listener
/// could not: `/m3u`, `.strm` and the newznab items all pointed at
/// plaintext on a TLS-only socket and got a reset.
pub fn scheme(d: &Daemon) -> &'static str {
    if d.tls_cert.is_some() {
        "https"
    } else {
        "http"
    }
}

#[cfg(test)]
mod auth_scheme_tests {
    use super::auth_scheme_value;

    /// RFC 7235 says the scheme token is case-insensitive, and the two
    /// /jsonrpc credential checks compared it with a literal
    /// `strip_prefix("Basic ")` - so a client sending `basic` or `BASIC`,
    /// both compliant and both emitted in the wild by proxies and HTTP
    /// libraries that normalize headers, got a 401 with correct
    /// credentials (Codex sweep 12 Aug F18).
    #[test]
    fn the_scheme_token_is_case_insensitive() {
        for spelling in ["Basic", "basic", "BASIC", "bAsIc"] {
            assert_eq!(
                auth_scheme_value(&format!("{spelling} dXNlcjpwYXNz"), "basic").as_deref(),
                Some("dXNlcjpwYXNz"),
                "{spelling} must be accepted"
            );
        }
    }

    /// ...and the credentials themselves are NOT: only the token is.
    /// A different scheme, a missing credential or a bare token is no
    /// match at all rather than an empty one.
    #[test]
    fn anything_that_is_not_this_scheme_is_no_match() {
        assert_eq!(auth_scheme_value("Bearer abc", "basic"), None);
        assert_eq!(auth_scheme_value("Basic", "basic"), None);
        assert_eq!(auth_scheme_value("", "basic"), None);
        assert_eq!(auth_scheme_value("   ", "basic"), None);
        // Extra whitespace between the token and the credentials is legal.
        assert_eq!(
            auth_scheme_value("  Basic   dXNlcjpwYXNz  ", "basic").as_deref(),
            Some("dXNlcjpwYXNz")
        );
    }
}
