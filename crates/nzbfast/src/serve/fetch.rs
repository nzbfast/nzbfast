//! Server-side URL fetches of user-supplied links: the SSRF guard and
//! the agents built on it, the NZB-vs-error body sniff, the failure-link
//! allowlist, and the regrab chain's inheritance rules.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.
//!
//! Two tiers of guard live here, and which one a caller wants depends on
//! who chose the URL:
//!
//! - [`fetch_url`] for a link the USER supplied (addurl, /watch). The
//!   SSRF guard refuses cloud metadata and link-local and nothing else;
//!   loopback and the LAN are legitimate targets for a self-hosted app.
//! - [`fetch_url_from`] for a link a configured source's own RESPONSE
//!   supplied (a newznab `<enclosure url>`, an RSS item link). Same
//!   guard, plus the destination is bound to the origin that offered it,
//!   so the loopback/LAN concession above cannot be borrowed by a
//!   hostile indexer to reach a service it does not own. See
//!   [`OriginBoundResolver`]; [`failure_link_allowed`] is the same idea
//!   applied to a response HEADER.
//!
//! The origin a link is bound to is a [`SourceOrigin`]: the source's
//! configured URL AND the addresses it actually answered the search
//! from, captured by [`witness_resolution`]. Both halves are needed -
//! see [`OriginBoundResolver`] for why the URL alone leaves a
//! cross-request rebinding window open.

use super::*;

// The SSRF guard, the agents and the resolution witness moved to
// `crate::netfetch` (TODO 276 item 3) and are re-exported through
// `serve`'s glob of this module, so every caller inside `serve` still
// spells them the way it always did.
pub(crate) use crate::netfetch::*;

/// An NZB fetched by URL, plus what the indexer said about it in the
/// response headers.
pub struct Fetched {
    pub bytes: Vec<u8>,
    /// `X-DNZB-Failure`: where to report this download failing, and where
    /// the indexer hands back a replacement NZB for the same title. See
    /// [`Daemon::report_failure`].
    pub failure_link: String,
    /// Host of the URL that was REQUESTED (not the last redirect hop):
    /// the only host `failure_link` may point back at. See
    /// [`Daemon::report_failure`].
    pub host: String,
    /// Was the REQUESTED url https? A failure link may not downgrade the
    /// scheme it was handed over. See [`failure_link_allowed`].
    pub https: bool,
    /// `X-DNZB-Category`, when the indexer sends one. Parsed, but never
    /// used to route a download: the category picks the output subfolder,
    /// the library flag and the move-completed destination, and those are
    /// the user's choice, not the responding server's. Kept (and
    /// asserted on) so the header parse stays covered if a future caller
    /// has a legitimate use for it.
    // Not #[expect]: the assertion named above IS a read, so the
    // expectation is unfulfilled under cfg(test).
    #[allow(dead_code)]
    pub category: String,
    /// Every address the REQUESTED url's netloc resolved to during this
    /// fetch (not the redirect chain's). A caller whose body supplies
    /// further links - the RSS poller, whose feed body names item links
    /// - carries this into [`SourceOrigin::witnessed`] so the later grab
    /// can tell the source from a rebind. See [`OriginBoundResolver`].
    pub addrs: Vec<std::net::IpAddr>,
    /// Filename from the response's `Content-Disposition`, or empty.
    /// This is where indexers put the real release name - a grab
    /// proxied by Prowlarr with its per-indexer Redirect setting
    /// arrives as `addurl` with no `nzbname` and a download URL whose
    /// last path segment is the indexer's NZB id hash, so this header
    /// is the only place the human name exists (issue #26).
    pub filename: String,
}

/// The filename out of a `Content-Disposition` header, or None. Handles
/// the three shapes in the wild: `filename="quoted"`, a bare
/// `filename=token`, and RFC 5987 `filename*=UTF-8''percent-encoded`
/// (which wins over `filename` when both appear, per RFC 6266).
///
/// The value is attacker-influenced (it comes from whatever answered the
/// fetch), so any path components are shorn and an outsized value is
/// refused; the enqueue path re-sanitizes before anything touches the
/// filesystem, same as `nzbname`.
pub(crate) fn content_disposition_filename(hdr: &str) -> Option<String> {
    let mut plain: Option<String> = None;
    let mut ext: Option<String> = None;
    for part in split_disposition_params(hdr) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let v = v.trim();
        if key == "filename*" {
            // ext-value = charset "'" [language] "'" value-chars. Only
            // UTF-8 arrives in practice; a mislabelled charset still
            // decodes lossily rather than dropping the name.
            if let Some((_, data)) = v.rsplit_once('\'') {
                ext = Some(percent_decode(data));
            }
        } else if key == "filename" {
            let v = match v.strip_prefix('"') {
                Some(rest) => rest.split('"').next().unwrap_or(""),
                None => v,
            };
            plain = Some(v.to_string());
        }
    }
    // filename* wins per RFC 6266, but only when it actually carried a
    // name: a malformed or empty ext-value must not suppress a perfectly
    // valid plain `filename` beside it.
    let name = ext.filter(|s| !s.trim().is_empty()).or(plain)?;
    let name = name.rsplit(['/', '\\']).next().unwrap_or("").trim();
    // Control characters out: percent-decoding happily produces CR/LF/
    // ESC, and while the filesystem paths re-sanitize downstream, the
    // raw string becomes the job's display name - which reaches logs
    // and would otherwise carry ANSI escapes or forged log lines from
    // whatever answered the fetch.
    let name: String = name.chars().filter(|c| !c.is_control()).collect();
    let name = name.trim();
    (!name.is_empty() && name.len() <= 255).then(|| name.to_string())
}

/// Split a Content-Disposition header into its `;`-separated params,
/// honouring quoted-string boundaries: `filename="Show; Part 2.nzb"`
/// is ONE parameter, and splitting it blind named the job `Show` -
/// wrong output folder, wrong duplicate identity. (Backslash escapes
/// inside the quoted string are not interpreted: no client emits them
/// in filenames, and a stray quote merely mis-splits back to the old
/// behaviour, never past the header.)
fn split_disposition_params(hdr: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut quoted) = (0usize, false);
    for (i, b) in hdr.bytes().enumerate() {
        match b {
            b'"' => quoted = !quoted,
            b';' if !quoted => {
                parts.push(&hdr[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&hdr[start..]);
    parts
}

/// Percent-decode only - NOT `urldecode`, whose `+` → space rule belongs
/// to form encoding and would corrupt a literal `+` in a filename.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 3 <= b.len()
            && let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The job name for a URL grab that carried no explicit name: the
/// fetched `Content-Disposition` filename when the server sent one
/// (that is the name SABnzbd shows for the same grab), else the URL's
/// last path segment shorn of query and fragment - the old fallback
/// kept the whole `?t=get&id=...` tail on API-style links.
pub(super) fn name_from_fetch(f: &Fetched, url: &str) -> Option<String> {
    if !f.filename.is_empty() {
        return Some(f.filename.clone());
    }
    let path = url.split(['?', '#']).next().unwrap_or("");
    let tail = path.rsplit('/').next().unwrap_or("").trim();
    (!tail.is_empty()).then(|| tail.to_string())
}

/// One `X-DNZB-*` header, trimmed, or empty.
pub(super) fn dnzb(resp: &ureq::Response, name: &str) -> String {
    resp.header(name).unwrap_or_default().trim().to_string()
}

/// The failure-report link out of the two spellings in the wild.
/// `X-DNZB-Failure` is what indexers actually send (it is the header
/// NZBGet's own FailureLink reads, via the `*DNZB:Failure` parameter);
/// `X-DNZB-FailureLink` is what the feature is usually CALLED, and a few
/// indexers send that name instead. The canonical one wins, and a header
/// present but blank counts as absent.
pub(super) fn pick_failure_link(canonical: &str, alias: &str) -> String {
    if canonical.is_empty() {
        alias.to_string()
    } else {
        canonical.to_string()
    }
}

// The authority parsers behind these checks live in nzbkit::urlauth so
// the fuzz harness can reach them: `url_authority_diff` pins them
// differentially against the `url` crate - the parser ureq actually
// dials with. They are still hand-rolled (the daemon links no URL
// crate); see the module docs there for the parsing contract and the
// backslash-authority trap.
pub(super) use nzbkit::urlauth::{url_host, url_netloc};

/// May a link that `origin_url`'s response supplied be fetched over
/// plain http? Only when the origin was itself plain http, or the link
/// names a DIFFERENT host (a sibling download host or CDN - which
/// [`OriginBoundResolver`] still confines to public addresses).
///
/// The one shape refused is the same-host downgrade, which is never
/// legitimate and is the same rule [`failure_link_allowed`] applies: the
/// user's indexer apikey rides that query string, and "the same indexer,
/// in the clear" is a different party to everything on the path to it.
pub(super) fn supplied_link_scheme_ok(link: &str, origin_url: &str) -> bool {
    let is_https = |u: &str| u.len() >= 8 && u.as_bytes()[..8].eq_ignore_ascii_case(b"https://");
    if !is_https(origin_url) {
        return true;
    }
    is_https(link) || url_host(link) != url_host(origin_url)
}

/// May this job's `failure_link` be called? Only when it points back at
/// the host that supplied it. The link arrives in a RESPONSE HEADER from
/// whatever server answered the NZB fetch, and the daemon then calls it
/// from inside the user's network with an SSRF guard that permits
/// loopback and RFC1918 (LAN indexers are the normal case). Binding it to
/// the origin keeps that concession from becoming "any indexer can aim
/// the daemon at any address on your LAN".
///
/// Same host is necessary but not sufficient: an https origin may not be
/// handed an http link. The daemon's own indexer apikey rides in that
/// query string, and "the same indexer, in the clear" is a different
/// party to anything on the path between here and it.
pub(super) fn failure_link_allowed(link: &str, origin_host: &str, origin_https: bool) -> bool {
    // Both sides come out of `url_host`, so this is a comparison of
    // normalized hosts. An empty origin (an NZB the user uploaded, or a
    // record written before this field existed) matches nothing.
    let h = url_host(link);
    if h.is_empty() || h != origin_host {
        return false;
    }
    // Byte compare, not `&link[..8]`: the link comes out of a response
    // header, and slicing a str at a byte index that lands inside a
    // multi-byte character panics.
    !origin_https || link.len() >= 8 && link.as_bytes()[..8].eq_ignore_ascii_case(b"https://")
}

/// Does this response body carry a replacement NZB? Indexers answer 200
/// with a human "nothing found" page at least as often as they answer
/// with XML, so the body decides and the status does not. Same test
/// FailureLink applies.
pub(super) fn is_nzb_body(bytes: &[u8]) -> bool {
    bytes.starts_with(b"<?xml")
}

/// What a re-grabbed replacement inherits from the job it stands in for:
/// `(category, priority, password)`.
///
/// All three used to be dropped on the floor (`cat` fell back to the
/// indexer's own `X-DNZB-Category`, priority was a hardcoded 0, password
/// a hardcoded None), which meant: a Force job's replacement queued at
/// Normal behind work the user had deprioritized; a passworded release's
/// replacement downloaded in full and then failed extraction for a
/// password the daemon was holding (the name-convention fallback cannot
/// recover it - by then `name` is the stem AFTER `smart::name_password`
/// stripped the marker); and the responding server, not the user, chose
/// the output subfolder, the library flag and the move-completed
/// destination.
///
/// Priority is clamped at Normal: a held duplicate carries -3, which is a
/// "parked, do not run" marker, not a speed.
pub(super) fn replacement_inherits(j: &Job) -> (String, i32, Option<String>) {
    (j.category.clone(), j.priority.max(0), j.password.clone())
}

/// May we queue a replacement right now - the mode asks for one, and this
/// chain has not already spent its allowance?
pub(super) fn may_regrab(mode: &str, depth: u8) -> bool {
    mode == "regrab" && depth < FAILURE_REGRAB_MAX
}

/// Ceiling on a fetched NZB. Every caller of [`fetch_url`] - the RSS
/// poller, `/watch`, `addurl`, the failure-link re-grab - takes its URL
/// from somewhere the user does not fully control, and none of them has
/// an opt-in for "this one is allowed to be huge", so the old 256 MB was
/// a quarter of a gigabyte of RAM available to anything that can answer a
/// request.
///
/// 64 MB, not the "a few MB" an NZB usually is: a real 4K remux triple
/// feature off the bench farm measures 23.7 MB of XML, and obfuscated
/// message-ids inflate that further, so the headroom is deliberate. This
/// is a runaway-response guard, not a size policy. An uploaded file goes
/// through addfile, which keeps its own (much larger) body cap.
pub(super) const FETCH_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The bit of [`fetch_url`] both it and [`ping_url`] share: scheme check,
/// SSRF-guarded GET, and the indexer headers off the response.
///
/// `origin` is `Some` when the link did not come from the user but out
/// of a RESPONSE from a configured source - a Newznab `<enclosure url>`,
/// an RSS item link - and names that source's own URL and search-time
/// addresses. It binds the fetch to that origin; see
/// [`OriginBoundResolver`].
pub(super) fn fetch_head(
    url: &str,
    origin: Option<&SourceOrigin>,
) -> Result<(ureq::Response, String, String)> {
    // Deliberately case-SENSITIVE, unlike every other scheme test in this
    // file. `HTTPS://host/...` passes `failure_link_allowed` and
    // `supplied_link_scheme_ok` (both `eq_ignore_ascii_case`) and dies
    // here instead, which is the safe direction: accepting it would reach
    // the `https:` flag below, which asks `starts_with("https://")` and
    // would therefore record such a job as a PLAIN-HTTP origin - and a
    // plain-http origin is what lets a plain-http failure link through
    // the downgrade guard. Loosen this and that flag must be loosened in
    // the same change. The message names the whole url, so every caller
    // that logs or returns it runs it through `redact_url_creds`, which
    // is scheme-agnostic for exactly this reason - but a string this
    // guard REJECTS need not be a well-formed url at all, and the
    // redactor finds one by its `://`. A single-slash `https:/host/x?
    // apikey=...` has no such marker and used to travel whole into the
    // API answer and the log. So name at most scheme and authority,
    // which is all the redactor would have left of a good url anyway,
    // and keep it as the belt rather than the only guard (Fable sweep
    // 15 Aug).
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        // Scheme and HOST, never the userinfo, path or query. On a
        // well-formed url that is exactly what the redactor would have
        // left, so the host still names the problem; on a malformed one
        // with no `://` for the redactor to find, this cut is the only
        // thing that keeps the credential out.
        //
        // The userinfo half of that has to be done here too, and was
        // not: `https:user:pw@idx.example/feed` has no `://`, so the
        // authority started at 0, the cut landed at the first slash,
        // and `https:user:pw@idx.example` went whole into the bail -
        // then through `redact_url_creds`, which finds a url by its
        // `://` and so had nothing to strip. Feed health stores that
        // string in the settings row and the log ring (sweep 2 L3).
        let after_scheme = url.find("://").map(|i| i + 3).unwrap_or(0);
        let cut = url[after_scheme..]
            .find(['/', '?', '#'])
            .map(|i| after_scheme + i)
            .unwrap_or(url.len());
        // Where the authority begins. With no `://` to anchor it, the
        // scheme is whatever precedes the first `:` and everything from
        // there to the last `@` is userinfo - the same shape the
        // redactor drops on a url it can parse.
        let authority = if after_scheme > 0 {
            after_scheme
        } else {
            url[..cut].find(':').map(|i| i + 1).unwrap_or(0)
        };
        let host = url[authority..cut].rsplit('@').next().unwrap_or("");
        anyhow::bail!("addurl: unsupported url {}{}", &url[..authority], host);
    }
    // Release assets redirect to a CDN host; follow the whole chain, but
    // every hop is SSRF-filtered so a public URL can't 302 into 127.0.0.1
    // or 169.254.169.254.
    let agent = match origin {
        None => ssrf_safe_agent(10, 60),
        Some(origin) => {
            if !supplied_link_scheme_ok(url, &origin.url) {
                anyhow::bail!(
                    "{}: an https source may not hand back a plain-http link to itself",
                    url_host(url)
                );
            }
            origin_bound_agent(origin, 10, 60)
        }
    };
    let resp = agent.get(url).call()?;
    let failure_link = pick_failure_link(
        &dnzb(&resp, "X-DNZB-Failure"),
        &dnzb(&resp, "X-DNZB-FailureLink"),
    );
    let category = dnzb(&resp, "X-DNZB-Category");
    Ok((resp, failure_link, category))
}

/// Fetch a link the USER supplied (addurl, /watch, a failure link that
/// already passed [`failure_link_allowed`]). For one that a search
/// response supplied, use [`fetch_url_from`] instead.
pub(super) fn fetch_url(url: &str) -> Result<Fetched> {
    fetch_url_inner(url, None)
}

/// Fetch a link that `origin`'s own response handed back - a Newznab
/// enclosure, an RSS item link. Identical to [`fetch_url`] except that
/// the destination is bound to the origin that offered it, so a
/// compromised indexer cannot aim the daemon at another service on the
/// user's LAN. See [`OriginBoundResolver`] for the exact rule.
pub(super) fn fetch_url_from(url: &str, origin: &SourceOrigin) -> Result<Fetched> {
    fetch_url_inner(url, Some(origin))
}

fn fetch_url_inner(url: &str, origin: Option<&SourceOrigin>) -> Result<Fetched> {
    use std::io::Read;
    // Witnessed unconditionally: this is the one place that knows both
    // the requested url and the resolver's answer, and a caller whose
    // body will supply further links (the RSS poller) needs the answer
    // even though the fetch itself may be plain `fetch_url`.
    let (head, addrs) = witness_resolution(&url_netloc(url), || fetch_head(url, origin));
    let (resp, failure_link, category) = head?;
    let filename = resp
        .header("Content-Disposition")
        .and_then(content_disposition_filename)
        .unwrap_or_default();
    // Refuse an oversized body BEFORE reading it, when the server was
    // honest enough to declare one; the take() below is the backstop for
    // when it wasn't.
    if let Some(len) = resp
        .header("Content-Length")
        .and_then(|l| l.trim().parse::<u64>().ok())
        && len > FETCH_MAX_BYTES
    {
        anyhow::bail!("{url}: {len} bytes is too large for an NZB");
    }
    let mut bytes = Vec::new();
    resp.into_reader()
        .take(FETCH_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > FETCH_MAX_BYTES {
        anyhow::bail!("{url}: response is too large for an NZB");
    }
    // The host we ASKED for, deliberately - not resp.get_url(), which is
    // the last hop of the redirect chain. Otherwise an indexer (or
    // anything that can answer for it) launders an arbitrary origin by
    // bouncing the fetch through one redirect.
    Ok(Fetched {
        bytes,
        failure_link,
        host: url_host(url),
        https: url.starts_with("https://"),
        category,
        filename,
        addrs,
    })
}

/// GET a URL for its SIDE EFFECT only, and never read the body.
///
/// `failure_link` in `report` mode: the report IS the request, nothing
/// inspects what comes back, and a 404 is a normal answer. Returning
/// `Ok(None)` keeps the caller's one error arm (which is where the 404
/// handling lives) doing the work for both modes.
pub(super) fn ping_url(url: &str) -> Result<Option<Fetched>> {
    fetch_head(url, None)?;
    Ok(None)
}
