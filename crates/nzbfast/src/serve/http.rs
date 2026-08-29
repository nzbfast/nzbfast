//! The HTTP surface (TODO 106 phase 2.3, cut C): the 8-worker pool
//! over the shared tiny_http listener and the whole request router.
//! Body is a verbatim move from serve(); see
//! research/SEAM-TABLE-serve-fns-2026-08-05.md.

use super::*;

/// The FULL API key only - the add-only NZB key does not open this door.
///
/// The playback family (`/stream`, `/m3u`, `/watch`, `/preview/probe`)
/// hands out the user's finished media, and `/stream` against a
/// never-fetched library entry additionally force-starts the job: a
/// queue mutation past a user pause. `/jobnzb` already refuses the
/// add-only credential on the narrower ground that "a job's spool says
/// what this user downloads", and serving the bytes is strictly more
/// than reading the spool - so accepting the nzbkey here let a
/// credential that ships to browser push extensions walk the entire
/// library, `nzo_id`s being a plain incrementing counter.
///
/// Same three arms as `route_jobnzb`: a keyless install stays open, a
/// configured apikey must match, and an install with ONLY an nzbkey
/// (the lockout state) opens nothing. Players are unaffected - they
/// carry the per-job `?t=` stream token, which is checked separately.
/// Percent-encode one query VALUE for a URL the daemon generates.
/// Generated hex keys pass through unchanged; a user-chosen key holding
/// `&`, `+`, `%` or `#` sent raw changes the parsed query and breaks
/// every link that carries it (Codex sweep 10 Aug L1). Everything
/// outside the RFC 3986 unreserved set is encoded.
pub(super) fn query_escape(s: &str) -> String {
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

fn full_key_ok(given: Option<&str>, apikey: &Option<String>, nzbkey: &Option<String>) -> bool {
    match (apikey, nzbkey) {
        (None, None) => true,
        (Some(k), _) => given.is_some_and(|g| ct_eq(g, k)),
        (None, Some(_)) => false,
    }
}

fn route_stream(req: tiny_http::Request, d: &Arc<Daemon>, path: &str, query: &str) {
    // M11: progressive playback of the active download's media
    // file; M14i: /stream/<nzo_id> fetches a parked library job
    // on demand. Byte-serving stays unauthenticated (media
    // players don't do API keys), but the M14i library trigger
    // is a state mutation - force-starting a parked job past a
    // user pause - so it needs the API key or the per-job
    // `?t=` token the authenticated handoffs (/m3u, .strm)
    // embed. Own thread - a stream can outlive many API polls.
    let want = path
        .strip_prefix("/stream/")
        .map(|s| s.trim_matches('/').to_string())
        .filter(|s| !s.is_empty());
    let mut sp = parse_query(query);
    if let Some(k) = header_apikey(&req) {
        sp.entry("apikey".to_string()).or_insert(k);
    }
    let given = sp.get("apikey").map(String::as_str);
    let key_ok = {
        let a = d.apikey.lock_ok().clone();
        let n = d.nzbkey.lock_ok().clone();
        full_key_ok(given, &a, &n)
    };
    let token_ok = want
        .as_deref()
        .zip(sp.get("t").map(String::as_str))
        .is_some_and(|(id, t)| ct_eq(t, &d.stream_token(id)));
    let authed = key_ok || token_ok;
    let d = d.clone();
    // Cap concurrent /stream worker threads. Each dedicates an OS
    // thread + open FD + socket and can block for minutes on an
    // uncovered span, and byte-serving is unauthenticated by
    // design - so an unbounded spawn is a trivial resource-
    // exhaustion DoS (open thousands of connections, exhaust
    // threads/FDs). 64 is far above any real household (a handful
    // of simultaneous previews); past it we shed load with 503.
    static STREAM_THREADS: AtomicUsize = AtomicUsize::new(0);
    const MAX_STREAM_THREADS: usize = 64;
    if STREAM_THREADS.fetch_add(1, Ordering::AcqRel) >= MAX_STREAM_THREADS {
        STREAM_THREADS.fetch_sub(1, Ordering::AcqRel);
        let _ = req.respond(
            tiny_http::Response::from_string("too many concurrent streams").with_status_code(503),
        );
        return;
    }
    std::thread::spawn(move || {
        // Decrement on exit, including a panic in stream_request.
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                STREAM_THREADS.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _g = Guard;
        stream_request(d, req, want, authed);
    });
}

fn route_preview_probe(req: tiny_http::Request, d: &Arc<Daemon>, id: &str, query: &str) {
    // §73 phase 1: what the downloading file IS -
    // container, tracks, codecs, languages, HDR - so the
    // dashboard can say "this is the right file" (or the
    // wrong one) before the download finishes.
    //
    // Same auth as /stream: either key, or the per-job
    // token the player handoffs already embed. This
    // reads only container headers and never blocks, so
    // unlike /stream it cannot sit on a thread for
    // minutes - but it does open a file and do disk I/O,
    // so it takes its own smaller cap.
    let id = id.trim_matches('/').to_string();
    if id.is_empty() {
        let _ =
            req.respond(tiny_http::Response::from_string("nzo_id required").with_status_code(404));
        return;
    }
    let mut sp = parse_query(query);
    if let Some(k) = header_apikey(&req) {
        sp.entry("apikey".to_string()).or_insert(k);
    }
    let given = sp.get("apikey").map(String::as_str);
    let key_ok = {
        let a = d.apikey.lock_ok().clone();
        let n = d.nzbkey.lock_ok().clone();
        full_key_ok(given, &a, &n)
    };
    let token_ok = sp.get("t").is_some_and(|t| ct_eq(t, &d.stream_token(&id)));
    if !(key_ok || token_ok) {
        let blocked = d.note_auth_failure(peer_ip(&req), "preview probe");
        let _ = req.respond(if blocked {
            tiny_http::Response::from_string("too many bad keys").with_status_code(429)
        } else {
            tiny_http::Response::from_string(
                "inspecting a download needs an apikey or stream token (?t=)",
            )
            .with_status_code(401)
        });
        return;
    }
    // §73 phase 2: the setting gates the ENDPOINT, not just the panel.
    // "off" means no half-downloaded file is opened and parsed for
    // anyone - a user who turns the feature off has turned it off, not
    // hidden it. Checked after auth so an unauthenticated caller learns
    // nothing about this install's settings.
    if preview_mode(d) == "off" {
        let _ = req.respond(
            json_resp(serde_json::json!({"error": "preview is off"})).with_status_code(403),
        );
        return;
    }
    static PROBE_THREADS: AtomicUsize = AtomicUsize::new(0);
    const MAX_PROBE_THREADS: usize = 8;
    if PROBE_THREADS.fetch_add(1, Ordering::AcqRel) >= MAX_PROBE_THREADS {
        PROBE_THREADS.fetch_sub(1, Ordering::AcqRel);
        // JSON, not plain text: the dashboard's `probeFetch` parses every
        // refusal body, and a bare "busy" landed there as `{}` - read as
        // "no video file to read here" and settled, never polled again.
        // `pending` is the key it already keeps asking about, and the cap
        // is exactly that kind of transient.
        let _ = req.respond(
            json_resp(serde_json::json!({"error": "busy", "pending": true}))
                .with_status_code(503)
                .with_header(
                    tiny_http::Header::from_bytes(&b"Retry-After"[..], &b"2"[..]).unwrap(),
                ),
        );
        return;
    }
    let d = d.clone();
    std::thread::spawn(move || {
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                PROBE_THREADS.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _g = Guard;
        preview_probe_request(d, req, id);
    });
}

/// `GET /preview/media/{nzo_id}` - §73 phase 3: the same file, rewrapped
/// into fragmented MP4 so a browser that will not open the container can
/// still play what is inside it.
///
/// Same auth as the probe, and then one gate more. The `preview` setting
/// stops this at `metadata-only` as well as at `off`: the panel's job is
/// to say what a file IS, and a user who chose that and not "full" has
/// chosen not to have a player - the setting means what it says at both
/// values, not just the one that turns everything off.
///
/// Its own thread and its own cap. Unlike the probe, one of these holds
/// a socket for as long as somebody is watching, so it is sized like the
/// `/stream` family rather than like an API poll - but lower, because a
/// remux session also holds an open fragment in memory.
fn route_preview_media(req: tiny_http::Request, d: &Arc<Daemon>, id: &str, query: &str) {
    let id = id.trim_matches('/').to_string();
    if id.is_empty() {
        let _ =
            req.respond(tiny_http::Response::from_string("nzo_id required").with_status_code(404));
        return;
    }
    let mut sp = parse_query(query);
    if let Some(k) = header_apikey(&req) {
        sp.entry("apikey".to_string()).or_insert(k);
    }
    let given = sp.get("apikey").map(String::as_str);
    let key_ok = {
        let a = d.apikey.lock_ok().clone();
        let n = d.nzbkey.lock_ok().clone();
        full_key_ok(given, &a, &n)
    };
    let token_ok = sp.get("t").is_some_and(|t| ct_eq(t, &d.stream_token(&id)));
    if !(key_ok || token_ok) {
        let blocked = d.note_auth_failure(peer_ip(&req), "preview media");
        let _ = req.respond(if blocked {
            tiny_http::Response::from_string("too many bad keys").with_status_code(429)
        } else {
            tiny_http::Response::from_string(
                "previewing a download needs an apikey or stream token (?t=)",
            )
            .with_status_code(401)
        });
        return;
    }
    // Checked after auth, so an unauthenticated caller learns nothing
    // about this install's settings.
    let mode = preview_mode(d);
    if mode != "full" {
        let _ = req.respond(
            json_resp(serde_json::json!({
                "error": "preview player is off",
                "preview": mode,
            }))
            .with_status_code(403),
        );
        return;
    }
    // A range this response cannot honour is refused HERE - before a
    // thread is spawned and before a byte of remuxing - because
    // ignoring it is ruinous, not merely untidy.
    //
    // Safari's media loader (AppleCoreMedia) opens every file with
    // `Range: bytes=0-1`, a two-byte probe whose `206` + `Content-Range`
    // is how it learns the resource length. A produced stream has no
    // length and no ranges, and `Accept-Ranges: none` says so - but
    // IGNORING the header (which RFC 9110 permits, and which this
    // endpoint used to do) means answering a two-byte probe with the
    // entire file. Measured on 11 Aug 2026 against a 2.5 GB episode:
    // Safari never learned a length, discarded everything, and retried
    // every ~4 seconds - 99 probes and 123.7 GB transferred in six
    // minutes, remuxing from scratch each time, for a black screen.
    //
    // `bytes=0-` is the whole resource and a 200 does satisfy it. That
    // is what Chromium sends before playing this happily, so its path
    // is deliberately untouched.
    if let Some(r) = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Range"))
        .map(|h| h.value.as_str().trim().to_string())
        && r.strip_prefix("bytes=").map(str::trim) != Some("0-")
    {
        let _ = req.respond(
            json_resp(serde_json::json!({
                "error": "range_unavailable",
                "hint": "this response is produced as it is read, so it has no byte ranges; \
                         request it without a Range header, or seek with start_ms",
                "range": r,
            }))
            .with_status_code(416)
            .with_header(
                tiny_http::Header::from_bytes(&b"Accept-Ranges"[..], &b"none"[..]).unwrap(),
            ),
        );
        return;
    }
    static REMUX_THREADS: AtomicUsize = AtomicUsize::new(0);
    const MAX_REMUX_THREADS: usize = 16;
    if REMUX_THREADS.fetch_add(1, Ordering::AcqRel) >= MAX_REMUX_THREADS {
        REMUX_THREADS.fetch_sub(1, Ordering::AcqRel);
        let _ = req.respond(
            tiny_http::Response::from_string("too many concurrent previews")
                .with_status_code(503)
                .with_header(
                    tiny_http::Header::from_bytes(&b"Retry-After"[..], &b"2"[..]).unwrap(),
                ),
        );
        return;
    }
    let d = d.clone();
    let query = query.to_string();
    std::thread::spawn(move || {
        // Decrement on exit, including a panic in the handler.
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                REMUX_THREADS.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _g = Guard;
        preview_media_request(d, req, id, query);
    });
}

#[cfg(feature = "indexer")]
fn route_art(req: tiny_http::Request, d: &Arc<Daemon>, f: &str) {
    // M13: cached TMDB posters/backdrops. Names are our own
    // sanitized art_name() output - refuse anything else. A
    // "thumb_" request also joins the source name it strips
    // to, so both components go through the check.
    let safe = art_name_ok(f)
        && match f.strip_prefix("thumb_") {
            Some(src) => art_name_ok(src),
            None => true,
        };
    // M28: "thumb_<name>" is a lazy server-side thumbnail -
    // generated from the full poster on first request, then
    // cached on disk like any other art file. The grid loads
    // ~20 KB thumbs instead of the original (≤4 MB) JPEGs.
    let art_root = d.spool.join("art");
    let bytes = if !safe {
        None
    } else if let Some(src) = f.strip_prefix("thumb_") {
        std::fs::read(art_root.join(f)).ok().or_else(|| {
            let t = make_thumb(&std::fs::read(art_root.join(src)).ok()?)?;
            let _ = std::fs::write(art_root.join(f), &t);
            Some(t)
        })
    } else {
        std::fs::read(art_root.join(f)).ok()
    };
    match bytes {
        Some(bytes) => {
            let _ = req.respond(
                tiny_http::Response::from_data(bytes)
                    .with_header(
                        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"image/jpeg"[..])
                            .unwrap(),
                    )
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Cache-Control"[..],
                            &b"max-age=604800"[..],
                        )
                        .unwrap(),
                    ),
            );
        }
        None => {
            let _ = req.respond(tiny_http::Response::from_string("").with_status_code(404));
        }
    }
}

fn route_m3u(req: tiny_http::Request, d: &Arc<Daemon>, id: &str, query: &str) {
    // M11: player handoff - a one-line playlist pointing at the
    // stream; the OS opens it in the default player (VLC/IINA/
    // Infuse), which then speaks HTTP ranges to /stream. The
    // playlist embeds the per-job stream token (that's what
    // lets the keyless player start a parked library job), so
    // minting one requires either key - the wall's ▶ Play
    // passes ?apikey= - or that job's own token, which mints
    // nothing new. Keyless installs stay open, as ever.
    let id = id.trim_matches('/');
    let mut sp = parse_query(query);
    if let Some(k) = header_apikey(&req) {
        sp.entry("apikey".to_string()).or_insert(k);
    }
    let given = sp.get("apikey").map(String::as_str);
    let key_ok = {
        let a = d.apikey.lock_ok().clone();
        let n = d.nzbkey.lock_ok().clone();
        full_key_ok(given, &a, &n)
    };
    // The job's OWN `?t=` capability token authenticates here as well as
    // the full key, and widens nothing: the whole answer is a
    // `/stream/<id>?t=` line bearing that same token, so a caller who can
    // present it already holds everything the playlist would hand back.
    // What it buys is the one thing the key cannot - `nzbfast stream`
    // gives this URL to a media player as ARGV, where every other local
    // account can read it (`/proc/<pid>/cmdline`, `ps`, WMI). That is the
    // disclosure TODO 23 low1 closed on the browser launch and left open
    // on the player launch, so the stream=1 add now answers with a
    // tokened `m3u` link and no credential travels as an argument at all.
    //
    // An EMPTY id is the "whatever is downloading now" playlist: not a
    // job, no per-job token, so it stays full-key.
    let token_ok = !id.is_empty() && sp.get("t").is_some_and(|t| ct_eq(t, &d.stream_token(id)));
    if !(key_ok || token_ok) {
        let blocked = d.note_auth_failure(peer_ip(&req), "m3u/watch");
        let _ = req.respond(if blocked {
            tiny_http::Response::from_string("too many bad keys").with_status_code(429)
        } else {
            tiny_http::Response::from_string("apikey required").with_status_code(401)
        });
        return;
    }
    // Scheme AND authority from `public_base`, not a bare Host with
    // `http://` welded on: this playlist is handed to VLC/IINA/Infuse,
    // which has no way to guess that the listener it came from speaks
    // TLS. Behind a proxy the forwarded headers still win, and a direct
    // native-TLS daemon now names its own https instead of pointing the
    // player at plaintext on a socket that will reset it.
    let base = public_base(&req, d);
    let target = if id.is_empty() {
        format!("{base}/stream")
    } else {
        format!("{base}/stream/{id}?t={}", d.stream_token(id))
    };
    let _ = req.respond(
        tiny_http::Response::from_string(format!("#EXTM3U\n{target}\n"))
            .with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"audio/x-mpegurl"[..])
                    .unwrap(),
            )
            .with_header(
                tiny_http::Header::from_bytes(
                    &b"Content-Disposition"[..],
                    &b"attachment; filename=\"nzbfast.m3u\""[..],
                )
                .unwrap(),
            ),
    );
}

/// `GET /metrics`: the Prometheus scrape.
///
/// AUTH IS THE FULL API KEY BY DEFAULT, with `metrics_open` to lift it,
/// and both halves of that were a decision rather than a default.
///
/// Behind the key, because the body is a read of this daemon's state -
/// queue depth, provider hostnames, memory - and every other read of
/// that state on this port already needs the key. Prometheus can send
/// one: a scrape config takes `authorization` or a `params:` entry, and
/// `?apikey=` and the `X-Api-Key` header both work here, the same two
/// spellings the rest of the API takes.
///
/// And a switch to open it, because the CONVENTION is an
/// unauthenticated scrape and there are real installs where the key is
/// the wrong tool - a scrape config in a shared repository has nowhere
/// tidy to keep a secret, and an exporter on a private network has
/// already been isolated by the network. An operator in that position
/// should not have to choose between scraping and having an API key at
/// all. What opening it publishes is written at `Daemon::metrics_open`
/// and in the manual: no job names and no paths, but each configured
/// provider's HOSTNAME as a label.
///
/// A keyless install stays open either way, which is not this route
/// being lax - it is `full_key_ok`'s first arm, and on such an install
/// every other endpoint is already answering the same caller.
///
/// GET only. A scrape is a read, and a POST that answered would be a
/// route a browser form could reach cross-origin.
fn route_metrics(req: tiny_http::Request, d: &Arc<Daemon>, query: &str) {
    if req.method() != &tiny_http::Method::Get {
        let _ = req.respond(tiny_http::Response::from_string("GET required").with_status_code(405));
        return;
    }
    let open = d.metrics_open.load(Ordering::Relaxed);
    let ok = open || {
        let mut sp = parse_query(query);
        if let Some(k) = header_apikey(&req) {
            sp.entry("apikey".to_string()).or_insert(k);
        }
        let given = sp.get("apikey").map(String::as_str);
        let a = d.apikey.lock_ok().clone();
        let n = d.nzbkey.lock_ok().clone();
        full_key_ok(given, &a, &n)
    };
    if !ok {
        // Counted into the same bad-key ladder as every other
        // credentialed route: a scraper misconfigured with the wrong key
        // retries forever, which is exactly the shape the ladder exists
        // to damp, and leaving this route out of it would give a guesser
        // one door with no rate limit on it.
        let blocked = d.note_auth_failure(peer_ip(&req), "metrics");
        let _ = req.respond(if blocked {
            tiny_http::Response::from_string("too many bad keys").with_status_code(429)
        } else {
            tiny_http::Response::from_string("apikey required").with_status_code(401)
        });
        return;
    }
    // Built by hand rather than through `respond_page`, and the reason
    // is the ETag that helper attaches: a scraper sending
    // `If-None-Match` would be answered 304 with no body, and a metrics
    // series that stops moving is a monitoring failure that looks like a
    // quiet system. It cannot happen today - `uptime_seconds` changes on
    // every scrape, so the hash never repeats - but a body whose
    // freshness is an accident of one gauge is not a contract. The gzip
    // goes with it: this body is a few kilobytes, against a scrape every
    // fifteen seconds on a local network.
    let body = metrics::render(d);
    let mut resp = tiny_http::Response::from_string(body).with_header(
        tiny_http::Header::from_bytes(
            &b"Content-Type"[..],
            metrics::METRICS_CONTENT_TYPE.as_bytes(),
        )
        .expect("static content type header"),
    );
    if let Ok(h) = tiny_http::Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]) {
        resp.add_header(h);
    }
    let _ = req.respond(resp);
}

fn route_watch(req: tiny_http::Request, d: &Arc<Daemon>, query: &str) {
    // One-link streaming: GET /watch?url=<nzb-url> enqueues at
    // Force priority and redirects to the .m3u - bookmark it,
    // paste it in a player, or wire it into an indexer's
    // "open with". Same key rule as /m3u: either key when
    // configured; keyless installs stay open.
    let mut sp = parse_query(query);
    if let Some(k) = header_apikey(&req) {
        sp.entry("apikey".to_string()).or_insert(k);
    }
    let given = sp.get("apikey").map(String::as_str);
    let ok = {
        let a = d.apikey.lock_ok().clone();
        let n = d.nzbkey.lock_ok().clone();
        full_key_ok(given, &a, &n)
    };
    if !ok {
        let blocked = d.note_auth_failure(peer_ip(&req), "m3u/watch");
        let _ = req.respond(if blocked {
            tiny_http::Response::from_string("too many bad keys").with_status_code(429)
        } else {
            tiny_http::Response::from_string("apikey required").with_status_code(401)
        });
        return;
    }
    let Some(url) = sp.get("url").filter(|u| !u.is_empty()).cloned() else {
        let _ = req.respond(tiny_http::Response::from_string("missing url=").with_status_code(400));
        return;
    };
    // Same naming ladder as addurl (issue #26): an explicit name wins,
    // then the fetched Content-Disposition filename, then the URL tail.
    let explicit = sp
        .get("name")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let resp = match fetch_url(&url).and_then(|f| {
        let name = explicit
            .clone()
            .or_else(|| name_from_fetch(&f, &url))
            .unwrap_or_else(|| "watch.nzb".to_string());
        d.enqueue_fetched(&f, &name, "", 2, None, None, 0, "url", DupeExempt::Nobody)
    }) {
        Ok(Enqueued { nzo_id: id, .. }) => {
            // Reflect the key into the redirect ONLY when it really
            // is a configured key. On a keyless install `ok` above
            // is true for ANY `apikey=` value, and this value went
            // verbatim into a `Location:` header - tiny_http
            // validates header values with `AsciiString::from_ascii`
            // and CR/LF are ASCII, so `apikey=%0d%0aHTTP/1.1 200...`
            // wrote a second, attacker-controlled response onto the
            // daemon's own origin (response splitting), and a
            // non-ASCII byte made the `from_bytes(..).unwrap()`
            // below panic, permanently killing one of the four HTTP
            // workers. A configured key is echoed back unchanged;
            // anything else is dropped.
            let key_q = given
                .filter(|g| {
                    let a = d.apikey.lock_ok().clone();
                    let n = d.nzbkey.lock_ok().clone();
                    a.as_deref().is_some_and(|k| ct_eq(g, k))
                        || n.as_deref().is_some_and(|k| ct_eq(g, k))
                })
                // Belt and braces: a key set through mode=config is
                // not charset-validated, so keep the header to a
                // charset that cannot carry a delimiter at all.
                .filter(|g| {
                    g.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                })
                .map(|k| format!("?apikey={k}"))
                .unwrap_or_default();
            // A get-NZB link carries the indexer credential in
            // its query (`apikey=`, `api_key=`, `r=`, …), and
            // this line lands in stdout, container logs and the
            // in-UI log viewer. Same treatment the failure-link
            // and RSS-origin paths already give a remote URL.
            info!(target: "watch", "{} → {id} (streaming)", redact_url_creds(&url));
            tiny_http::Response::from_string("")
                .with_status_code(303)
                .with_header(
                    tiny_http::Header::from_bytes(
                        &b"Location"[..],
                        format!("/m3u/{id}{key_q}").into_bytes(),
                    )
                    .unwrap(),
                )
        }
        Err(e) => {
            tiny_http::Response::from_string(format!("watch failed: {e}")).with_status_code(502)
        }
    };
    let _ = req.respond(resp);
}

#[cfg(feature = "indexer")]
fn route_getnzb(
    req: tiny_http::Request,
    d: &Arc<Daemon>,
    rest: &str,
    nz_authed: &impl Fn() -> bool,
) {
    if !nz_authed() {
        let blocked = d.note_auth_failure(peer_ip(&req), "getnzb");
        let _ = req.respond(if blocked {
            tiny_http::Response::from_string("too many bad keys").with_status_code(429)
        } else {
            tiny_http::Response::from_string("bad apikey").with_status_code(401)
        });
        return;
    }
    let id: i64 = rest.trim_end_matches(".nzb").parse().unwrap_or(-1);
    let r = d.with_index_read(|ix| ix.make_nzb(id).ok());
    match r {
        Some(xml) => {
            // M34: pulling the NZB is the strongest "I want
            // this" signal there is - the size cap protects
            // it for the next OPENED_PROTECT_DAYS days.
            d.touch_opened_release(id);
            let _ = req.respond(
                tiny_http::Response::from_string(xml)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"application/x-nzb"[..],
                        )
                        .unwrap(),
                    )
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Disposition"[..],
                            format!("attachment; filename=\"{id}.nzb\"").into_bytes(),
                        )
                        .unwrap(),
                    ),
            );
        }
        None => {
            let _ =
                req.respond(tiny_http::Response::from_string("not found").with_status_code(404));
        }
    }
}

fn route_jobnzb(
    req: tiny_http::Request,
    d: &Arc<Daemon>,
    rest: &str,
    params: &std::collections::HashMap<String, String>,
    cur_apikey: &Option<String>,
    cur_nzbkey: &Option<String>,
) {
    let given = params.get("apikey").map(String::as_str);
    let full_ok = match (&cur_apikey, &cur_nzbkey) {
        (None, None) => true,
        (Some(k), _) => given.is_some_and(|g| ct_eq(g, k)),
        (None, Some(_)) => false,
    };
    if !full_ok {
        let blocked = d.note_auth_failure(peer_ip(&req), "jobnzb");
        let _ = req.respond(if blocked {
            tiny_http::Response::from_string("too many bad keys").with_status_code(429)
        } else {
            tiny_http::Response::from_string("bad apikey").with_status_code(401)
        });
        return;
    }
    let id = rest.trim_end_matches(".nzb");
    let rec = {
        let pick = |j: &Arc<Mutex<Job>>| {
            let g = j.lock_ok();
            (g.nzo_id == id).then(|| (g.name.clone(), g.nzb_path.clone()))
        };
        let q = d.queue.lock_ok().iter().find_map(pick);
        q.or_else(|| d.history.lock_ok().iter().find_map(pick))
    };
    match rec.and_then(|(name, p)| std::fs::read(p).ok().map(|b| (name, b))) {
        Some((name, bytes)) => {
            // The name is the poster's text: keep it a
            // single header-safe token so it cannot
            // smuggle a quote or CR/LF into the header.
            //
            // ASCII-only, and that is load-bearing rather
            // than tidiness: tiny_http header values are
            // `AsciiString`, so `Header::from_bytes` REFUSES
            // any byte >= 0x80 and the `.unwrap()` below
            // panics. `sanitize_filename` maps separators and
            // control chars and passes everything else
            // through, so an accented or CJK release name -
            // "Amélie.2001.1080p" - reached it intact and
            // killed this worker thread for the life of the
            // process. There is no catch_unwind around the
            // worker loop, so a handful of such clicks take
            // the whole HTTP surface down until a restart.
            let fname: String = nzbkit::disk::sanitize_filename(&name)
                .chars()
                .map(|c| if c.is_ascii() { c } else { '_' })
                .filter(|c| !c.is_control() && *c != '"')
                .collect();
            // Every char can legitimately filter out (a name
            // that was entirely non-ASCII collapses to
            // underscores, but a name of only quotes does
            // not), and an empty filename is a malformed
            // header rather than a panic - still worth not
            // emitting.
            let fname = if fname.trim().is_empty() {
                "download".to_string()
            } else {
                fname
            };
            let _ = req.respond(
                tiny_http::Response::from_data(bytes)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"application/x-nzb"[..],
                        )
                        .unwrap(),
                    )
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Disposition"[..],
                            format!("attachment; filename=\"{fname}.nzb\"").into_bytes(),
                        )
                        .unwrap(),
                    ),
            );
        }
        None => {
            let _ =
                req.respond(tiny_http::Response::from_string("not found").with_status_code(404));
        }
    }
}

fn handle_api(
    req: tiny_http::Request,
    d: &Arc<Daemon>,
    cfg_path: &std::path::Path,
    params: std::collections::HashMap<String, String>,
) {
    let mut req = req;
    let mut params = params;
    // §141 (issue #33): decided before anything is read, and applied to
    // BOTH exits below. The refusal needs it as much as the answer does -
    // without the header on the 403 a browser extension cannot read the
    // "API Key Incorrect" body either, so a mistyped key presents as an
    // unreachable daemon instead of a bad key.
    let cors = cors_headers(
        &d.cors_origin.lock_ok().clone(),
        origin_hdr(&req).as_deref(),
        false,
    );
    let mut api_body: Option<Vec<u8>> = None;
    // Keeps the body-budget reservation alive for as long as
    // `api_body` (and the parse of it) is - see [`BodyHold`].
    let mut _api_body_hold: Option<BodyHold> = None;
    if req.method() == &tiny_http::Method::Post {
        let ctype = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Content-Type"))
            .map(|h| h.value.as_str().to_string())
            .unwrap_or_default();
        // Media types are case-insensitive (RFC 9110), so the
        // comparisons below are made against a lowercased copy.
        let ctype_lc = ctype.to_ascii_lowercase();
        // Decided BEFORE the body is read, because the read
        // is what an unauthenticated caller gets to trigger
        // here (SAB parity: the key may be a form field, so
        // the body has to be parsed to find it), and a
        // nonsense boundary must not get that far.
        let boundary = multipart_boundary(&ctype);
        // The only content type that still changes anything:
        // a form body's fields are MERGED into `params`
        // (SAB parity - the key may be one of them). JSON
        // and untyped bodies are read and handed straight
        // to the handler.
        let form_body = ctype_lc.starts_with("application/x-www-form-urlencoded");
        // The endpoint's OWN limit, decided before the read
        // (Codex sweep 2, 3 Aug M1). This buffer used to be
        // capped at a flat 256 MiB and every handler applied
        // its real limit - 8 MiB for a config import, 1 MiB
        // for a server save or a wall fix - only in the
        // fallback branch that ran when the pre-read had NOT
        // happened. Once the pre-read covers everything that
        // branch is dead, so the cap has to be right here or
        // it is nowhere: a nominal 1 MiB endpoint would
        // otherwise receive and parse 256 MiB, and the body
        // budget deliberately lets its oldest live holder
        // reach the per-request cap, so it cannot stand in
        // for the limit either.
        //
        // `mode` from the QUERY only - the body has not been
        // read yet, and a mode arriving as a form field is
        // precisely the SAB-parity addfile shape, which
        // needs the ceiling anyway.
        let cap = match params.get("mode").map(String::as_str) {
            Some(m) => api_body_cap(m),
            None if boundary.is_some() || form_body => API_BODY_MAX,
            // No mode in the query and not a form: nothing
            // can dispatch, so nothing needs a large body.
            None => API_BODY_DEFAULT,
        };
        {
            let (raw, hold) = read_body_capped_hold(req.as_reader(), cap);
            _api_body_hold = Some(hold);
            match &boundary {
                Some(b) => {
                    for (k, v) in multipart_fields(&raw, b) {
                        params.entry(k).or_insert(v);
                    }
                }
                None if form_body => {
                    if let Ok(s) = std::str::from_utf8(&raw) {
                        // Bounded: this runs pre-auth on a body
                        // of up to 256 MiB, exactly like the
                        // multipart arm above.
                        for (k, v) in parse_form_body(s) {
                            params.entry(k).or_insert(v);
                        }
                    }
                }
                // A JSON body, or one that named no type at
                // all: nothing to merge into `params`, but it
                // is read all the same so the handler never
                // has to.
                None => {}
            }
            api_body = Some(raw);
        }
    }
    // Re-read the pair AFTER the body, not at the top of the
    // request. That body is client-paced, so the snapshot taken
    // before it can be arbitrarily stale by the time it is used:
    // a caller who starts a form POST under the old key, stalls,
    // and finishes after the owner rotates was still authorised -
    // and `apikey_show` / `config name=apikey` then handed them
    // the NEW key, undoing the rotation. Decide against the key
    // as of the DECISION. Shadowed rather than mutated so the
    // earlier `nz_authed` / `handle_jsonrpc` uses, which both
    // returned before this point, are untouched.
    let cur_apikey = d.apikey.lock_ok().clone();
    let cur_nzbkey = d.nzbkey.lock_ok().clone();
    let mode = params.get("mode").cloned().unwrap_or_default();
    // Two-tier keys (SABnzbd model): the full API key unlocks
    // everything; the NZB key can only add jobs.
    let given = params.get("apikey").map(String::as_str);
    let full = match (&cur_apikey, &cur_nzbkey) {
        // Fully open ONLY when NEITHER key is configured - matches
        // the /stream, /m3u, /newznab pattern. The old `match
        // &cur_apikey { None => true }` made `full` unconditionally
        // true whenever no full key was set, silently voiding the
        // nzbkey as a credential and leaving the whole API (queue
        // delete, config writes, shutdown) open to any LAN host.
        (None, None) => true,
        (Some(k), _) => given.is_some_and(|g| ct_eq(g, k)),
        (None, Some(_)) => false,
    };
    // Whoever sent this already holds the key, so the first-run token
    // stops being worth one (`disarm_handoff_in`). A relaxed load on
    // every run that armed nothing.
    if full && cur_apikey.is_some() {
        note_full_key_request();
    }
    // SABnzbd's nzb_key stops at addfile/addurl/version, which
    // fails every push extension's "test connection" button:
    // NZB Donkey probes mode=status, NZB Unity probes
    // mode=fullstatus, and both fetch get_cats for their
    // category dropdown - so an add-only key looked broken in
    // the very tools it exists for. Allow those three reads: a
    // version string, paused/warning/disk numbers and the
    // category names give no control, and this key can already
    // inject arbitrary downloads. Queue/history contents,
    // config and every mutation stay full-key.
    let add_only = matches!(
        mode.as_str(),
        "addfile" | "addurl" | "version" | "status" | "fullstatus" | "get_cats"
    );
    // SABnzbd answers `mode=version` with no key at all, and two
    // of our own probes rely on that: the container HEALTHCHECK
    // curls it keyless from loopback every 30s, and the tray/.app
    // identify a daemon with a keyless `mode=version&hs=` probe.
    // Requiring a key here meant every keyed Docker install
    // logged "[auth] rejected key for api from 127.0.0.1" once a
    // minute forever - its own healthcheck - which users read as
    // the API being broken. Keyless ONLY: a key that was
    // presented and is wrong is still rejected, so a
    // misconfigured *arr fails its connection test instead of
    // turning green on the version call. The keyless body leaks
    // nothing the keyless refusal did not already carry (both
    // answer `nzbfast` plus the hs proof).
    let version_probe = mode == "version" && given.is_none();
    // Bootstrap the FIRST full API key when none is configured yet.
    // With only the add-only NZB key set, `config` needs `full` (which
    // the NZB key cannot grant), so an admin who set the NZB key first
    // would be permanently locked out of ever setting an API key from
    // the UI. Allow EXACTLY the first `config name=apikey` write, proven
    // by presenting the valid NZB key. Loopback source address is NOT a
    // credential: a browser request from any website still connects to
    // 127.0.0.1 from a loopback address, so trusting the source address
    // let a malicious page install its own full key via a cross-site GET
    // (<img src=".../api?mode=config&name=apikey&value=attacker">). The
    // admin who set the NZB key knows it and can present it here; a
    // remote page cannot. Once an apikey exists this path is dead (apikey
    // is Some => `full` is required to change it), so the NZB key stays
    // strictly add-only in the configured steady state.
    let bootstrap_apikey = cur_apikey.is_none()
        && mode == "config"
        && params.get("name").map(String::as_str) == Some("apikey")
        && cur_nzbkey
            .as_deref()
            .is_some_and(|k| given.is_some_and(|g| ct_eq(g, k)));
    // Authorized by the ADD-ONLY key rather than the full one.
    // The allowlist's contract is explicit that "queue/history
    // contents, config and every mutation stay full-key", and
    // two of the allowed reads quietly broke it: `status` and
    // `fullstatus` carry `complete_dir`, and their warnings
    // list names up to five queued releases waiting on a
    // password. Handlers need to know which credential got
    // them here to keep that promise - and `full` first, so a
    // real API key is never demoted by the mode it happens to
    // be calling.
    let via_add_only = !full
        && add_only
        && cur_nzbkey
            .as_deref()
            .is_some_and(|k| given.is_some_and(|g| ct_eq(g, k)));
    let authed = full || version_probe || via_add_only || bootstrap_apikey;
    if !authed {
        // Accounted like every other credentialed door (/m3u, /watch,
        // /newznab, /getnzb, /stream, /jsonrpc all do this): the key
        // is 192 bits so brute force is not the worry, but this is the
        // busiest endpoint and a key-spraying host was leaving no
        // trace on it at all. Rate-limiting decisions stay with
        // `note_auth_failure`; the answer below is unchanged.
        // Say WHICH failure this was: a Reddit-grade log excerpt
        // of bare "rejected key for api" lines cannot be
        // diagnosed, and "no key sent" vs "wrong key" is exactly
        // the fork a support answer needs.
        let _ = d.note_auth_failure(
            peer_ip(&req),
            if given.is_none() {
                "api (no key sent)"
            } else {
                "api (wrong key)"
            },
        );
        // Exact SAB phrases - the *arrs substring-match these to
        // tell "wrong key" from "no key" in their Test() dialog.
        let msg = if given.is_none() {
            "API Key Required"
        } else {
            "API Key Incorrect"
        };
        // ...and our own marker beside them, because the phrases
        // alone are SABnzbd's. The tray and the .app probe a port
        // WITHOUT a key (sending it would hand the key, and with it
        // mode=server_secret, to whatever bound the port first), so
        // a refusal is all they get to identify us by - and a match
        // means attach-and-never-kill. `nzbfast` is the same field
        // the version body carries, so both wrappers already accept
        // it and neither can mistake a real SABnzbd for us.
        // ...and, when the caller sent a challenge, the proof that
        // we hold the token in runtime.json. This is the reply a
        // wrapper's probe actually gets (it deliberately carries no
        // key), so the proof has to ride the REFUSAL, not the
        // authenticated version body. Nothing here leaks: the
        // answer is a hash, and a caller that cannot read the token
        // file cannot check or forge it.
        let mut refusal = json!({
            "status": false,
            "error": msg,
            "nzbfast": env!("CARGO_PKG_VERSION"),
        });
        if let Some(proof) = launcher_proof(&d.launcher_token, params.get("hs").map(String::as_str))
        {
            refusal["hs_proof"] = json!(proof);
        }
        // 403 like SABnzbd (interface.py sets it on every
        // check_apikey failure). The 200 we used to send made
        // NZB Unity's connection test report SUCCESS on a
        // wrong key - it only fails on a non-2xx or non-JSON
        // answer - and then every real call fell over. The
        // body is unchanged: the *arrs and the wrapper probes
        // read the phrases and the hs proof from it, not the
        // status line.
        let _ = req.respond(with_cors(json_resp(refusal).with_status_code(403), cors));
        return;
    }
    // For stream-mode adds: absolute player-handoff links need the
    // host the CLIENT used to reach us.
    let host_hdr = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Host"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_else(|| format!("127.0.0.1:{}", d.port));
    // Which automation is talking to us, for the job's origin.
    let ua_hdr = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("User-Agent"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default();
    // Client-facing scheme+authority for handed-off links (stream/m3u):
    // forwarded headers win over the raw Host so a reverse-proxied
    // HTTPS deployment gets links its players can actually reach.
    let base = public_base(&req, d);
    let ctx = api::ApiCtx {
        cfg_path,
        host_hdr: &host_hdr,
        base: &base,
        ua_hdr: &ua_hdr,
        bootstrap_apikey,
        via_add_only,
    };
    let body = api::dispatch(d, &mut req, &params, &mode, &ctx, &mut api_body)
        .unwrap_or_else(|| json!({"status": false, "error": format!("unimplemented mode {mode}")}));
    let _ = req.respond(with_cors(json_resp(body), cors));
}

pub(super) fn spawn_http_workers(server: tiny_http::Server, daemon: Arc<Daemon>, config: PathBuf) {
    // A small worker pool over the shared listener (tiny_http's recv() is
    // thread-safe): slow handlers - sysbench (~30-60 s), server_test (12 s),
    // addurl fetches, large index searches - must not freeze queue/stats
    // polling, or the dashboard appears to hang while they run. Eight, not
    // four: with 4, one dashboard tab's repeating index_stats poll queued
    // behind a long-held index lock wedged every worker within a minute
    // (28 Jul hang). index_stats no longer blocks, but other index reads
    // (wall2, search) still can - the extra headroom keeps / and the queue
    // endpoints answering while they wait.
    let server = std::sync::Arc::new(server);
    for _ in 0..8 {
        let server = server.clone();
        let d = daemon.clone();
        let cfg_path = config.clone();
        tokio::task::spawn_blocking(move || {
            // Snapshot this run's stop baseline at spawn: the epoch is
            // monotonic, so a stop for THIS run stays visible even after
            // an embedded host re-arms and starts the next run while
            // these workers are still winding up.
            let stop_baseline = super::STOP_BASELINE.load(std::sync::atomic::Ordering::SeqCst);
            loop {
                // The socket has been listening since partway through
                // startup (see the bind note beside spool_dir), and
                // tiny_http's accept thread has been parsing into its queue
                // since then. This is the first line that ANSWERS anything,
                // so it must stay below first_run_apikey - as must the bind
                // itself.
                let req = match server.recv_timeout(super::HTTP_IDLE_TICK) {
                    Ok(Some(r)) => r,
                    // Timed out: check for an embedded stop (see
                    // `super::request_stop`), then back to waiting.
                    Ok(None) => {
                        if super::STOP_EPOCH.load(std::sync::atomic::Ordering::SeqCst)
                            > stop_baseline
                        {
                            break;
                        }
                        continue;
                    }
                    Err(_) => break,
                };
                let url = req.url().to_string();
                let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
                // SABnzbd answers `/api/` exactly as it answers `/api`, and
                // clients written against "the SABnzbd API" lean on that:
                // Homepage's sabnzbd widget builds its URL with the slash and
                // got a flat 404 from us (issue #22), which reads as "this
                // API is broken" rather than "this API is picky". The same
                // miss hit /newznab/api/, i.e. an *arr pointing an indexer
                // here. Normalize ONE trailing slash for route matching.
                // "/" must survive the trim - trimmed to "" it would
                // match no arm at all. It is the dashboard shell only
                // when `dashboard` is on (TODO 281 IO3b made that a
                // droppable feature); in the slim build it falls through
                // to the 404 at the foot of this loop, which is still an
                // answer and not a panic. Every sub-path arm below
                // already trims its own remainder, so this only ever
                // reaches the exact-match arms.
                let path = match path.strip_suffix('/') {
                    Some("") | None => path,
                    Some(trimmed) => trimmed,
                };
                // TODO 281 IO3b: the whole browser-facing surface -
                // this shell, the stylesheet, the catalogues, the manuals
                // and the favicons - is `dashboard`-gated. Without it an
                // unknown path falls through to the 404 at the foot of
                // this loop, which is the honest answer for a build that
                // carries no page: there is no hidden door to find.
                #[cfg(feature = "dashboard")]
                if path == "/" || path == "/index.html" {
                    // The daemon state the page needs BEFORE its first
                    // paint - locale, indexer switches - is stamped in by
                    // `ShellKey`, which owns every such input and is the
                    // key the built page is cached under, so a
                    // revalidation answers 304 without rebuilding 1.2 MB.
                    // Cache-Control stays no-cache (a stale cached page
                    // keeps polling with old JS).
                    respond_shell(req, &d, Shell::Dashboard);
                    continue;
                }
                // The user's own stylesheet (TODO §140 / issue #31), read
                // from the config folder per request - see `user_css` for
                // why this one asset is not embedded. Unauthenticated like
                // the icons and the page that links it: same origin, same
                // reachability, and the content is the user's own CSS.
                // Missing file = an empty 200, so a browser console stays
                // clean for the 99% who never wrote one.
                #[cfg(feature = "dashboard")]
                if path == "/custom.css" {
                    respond_page(req, user_css(&d.cfg_path), "text/css; charset=utf-8");
                    continue;
                }
                // The one-time credential handoff for the browser this
                // daemon opened for itself: the launch URL carries a
                // token, not the API key, so the key never lands in a
                // child process's argv where a local neighbour can read
                // it. See `route_handoff` for why an unauthenticated
                // route is the right shape here, and why every run that
                // armed no handoff simply refuses.
                if path == "/handoff" {
                    route_handoff(req, &d);
                    continue;
                }
                // §5 i18n catalogues (key→string JSON, embedded like the HTML).
                #[cfg(feature = "dashboard")]
                if let Some(lang) = path
                    .strip_prefix("/i18n/")
                    .and_then(|f| f.strip_suffix(".json"))
                {
                    match i18n_catalog(lang) {
                        Some(cat) => respond_static(req, cat, "application/json"),
                        // English is the source language: it lives inline
                        // in the pages, so its catalogue is the empty
                        // object and is not worth a gzip member.
                        None if lang == "en" => {
                            respond_page(req, "{}".to_string(), "application/json");
                        }
                        None => {
                            let _ = req.respond(
                                tiny_http::Response::from_string("{}").with_status_code(404),
                            );
                        }
                    }
                    continue;
                }
                // Browser icons and the web manifest, embedded like the pages.
                // Unauthenticated on purpose: a browser fetches a favicon and a
                // manifest without our session, and they carry nothing private.
                #[cfg(feature = "dashboard")]
                if let Some((body, mime)) = web_icon(path) {
                    let _ = req.respond(
                        tiny_http::Response::from_data(body)
                            .with_header(
                                tiny_http::Header::from_bytes(
                                    &b"Content-Type"[..],
                                    mime.as_bytes(),
                                )
                                .unwrap(),
                            )
                            // Immutable content, but a daemon upgrade can change
                            // the artwork - a day is long enough to keep the tab
                            // strip quiet and short enough to pick that up.
                            .with_header(
                                tiny_http::Header::from_bytes(
                                    &b"Cache-Control"[..],
                                    &b"max-age=86400"[..],
                                )
                                .unwrap(),
                            ),
                    );
                    continue;
                }
                if path == "/stream" || path.starts_with("/stream/") {
                    route_stream(req, &d, path, query);
                    continue;
                }
                // The Prometheus scrape. Ahead of the API dispatcher and
                // not an arm of it: it answers text, takes no `mode=`,
                // and is a GET or nothing.
                if path == "/metrics" {
                    route_metrics(req, &d, query);
                    continue;
                }
                if let Some(id) = path.strip_prefix("/preview/probe/") {
                    route_preview_probe(req, &d, id, query);
                    continue;
                }
                if let Some(id) = path.strip_prefix("/preview/media/") {
                    route_preview_media(req, &d, id, query);
                    continue;
                }
                #[cfg(feature = "dashboard")]
                if path == "/manual" || path == "/manual/" || path.starts_with("/manual/") {
                    // The full user manual, embedded like the dashboard so
                    // every install carries its own docs. §5 i18n: /manual/<lang>
                    // serves the translated manual; /manual stays English (each
                    // page carries the EN·FR·DE·IT·ES·NL switcher). A UI locale
                    // without a translated manual yet (Tier 1b: pt/sv/da/nb/…)
                    // falls back to English so the dashboard's 📖 pill - which
                    // links /manual/<active locale> - never 404s.
                    let page = match path.trim_start_matches("/manual").trim_matches('/') {
                        "" => Some(MANUAL_EN),
                        lang => manual_i18n(lang)
                            .or_else(|| UI_LOCALES.contains(&lang).then_some(MANUAL_EN)),
                    };
                    let Some(page) = page else {
                        let _ = req.respond(
                            tiny_http::Response::from_string("not found").with_status_code(404),
                        );
                        continue;
                    };
                    // Compressed and hashed at build time (the design
                    // tokens are folded in there too), so this is a
                    // header read and a write.
                    respond_static(req, page, "text/html");
                    continue;
                }
                #[cfg(feature = "indexer")]
                if path == "/wall" || path == "/wall/" {
                    // M13: the poster wall, stamped and cached exactly as
                    // the dashboard above.
                    respond_shell(req, &d, Shell::Wall);
                    continue;
                }
                #[cfg(feature = "indexer")]
                if let Some(f) = path.strip_prefix("/art/") {
                    route_art(req, &d, f);
                    continue;
                }
                if let Some(id) = path.strip_prefix("/m3u/") {
                    route_m3u(req, &d, id, query);
                    continue;
                }
                if path == "/watch" {
                    route_watch(req, &d, query);
                    continue;
                }
                // §141 (issue #33): the CORS preflight for the
                // SAB-compatible API, answered ABOVE the key check on
                // purpose. A browser sends OPTIONS before the
                // extension's real request whenever it carries an
                // X-Api-Key or a JSON body, and it sends it WITHOUT
                // credentials - so a 403 here means Firefox never sends
                // the real request at all and the header on the real
                // response is never reached. 204 with no body: a
                // preflight answer carries permissions, not content.
                if path == "/api" && req.method() == &tiny_http::Method::Options {
                    let hdrs = cors_headers(
                        &d.cors_origin.lock_ok().clone(),
                        origin_hdr(&req).as_deref(),
                        true,
                    );
                    let _ = req.respond(with_cors(tiny_http::Response::empty(204), hdrs));
                    continue;
                }
                let mut params = parse_query(query);
                // Header key fills a MISSING apikey only, so the precedence
                // is query > header > POST body (the body merge below also
                // never overwrites) - an explicit URL key always wins.
                if let Some(k) = header_apikey(&req) {
                    params.entry("apikey".to_string()).or_insert(k);
                }
                // M12 newznab facade: Sonarr/Radarr point an indexer at us.
                // `/api?t=...` (their convention) or the explicit /newznab/api;
                // the `t` param disambiguates from the SABnzbd facade's `mode`.
                #[cfg(feature = "indexer")]
                let is_newznab =
                    path == "/newznab/api" || (path == "/api" && params.contains_key("t"));
                // Keys are live settings (rotatable from the dashboard) -
                // read the current pair once per request.
                let cur_apikey = d.apikey.lock_ok().clone();
                let cur_nzbkey = d.nzbkey.lock_ok().clone();
                #[cfg(feature = "indexer")]
                let nz_authed = || {
                    let given = params.get("apikey").map(String::as_str);
                    match (&cur_apikey, &cur_nzbkey) {
                        (None, None) => true,
                        (a, n) => {
                            a.as_deref()
                                .is_some_and(|k| given.is_some_and(|g| ct_eq(g, k)))
                                || n.as_deref()
                                    .is_some_and(|k| given.is_some_and(|g| ct_eq(g, k)))
                        }
                    }
                };
                #[cfg(feature = "indexer")]
                if is_newznab {
                    if !nz_authed() {
                        let blocked = d.note_auth_failure(peer_ip(&req), "newznab");
                        let _ = req.respond(if blocked {
                        tiny_http::Response::from_string("too many bad keys")
                            .with_status_code(429)
                    } else {
                        tiny_http::Response::from_string(
                            r#"<?xml version="1.0"?><error code="100" description="Incorrect user credentials"/>"#,
                        )
                        .with_status_code(401)
                    });
                        continue;
                    }
                    let base = public_base(&req, &d);
                    let key = params.get("apikey").cloned().unwrap_or_default();
                    let xml = newznab_xml(&d, &params, &base, &key);
                    let _ = req.respond(
                        tiny_http::Response::from_string(xml).with_header(
                            tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/rss+xml; charset=utf-8"[..],
                            )
                            .unwrap(),
                        ),
                    );
                    continue;
                }
                #[cfg(feature = "indexer")]
                if let Some(rest) = path.strip_prefix("/getnzb/") {
                    route_getnzb(req, &d, rest, &nz_authed);
                    continue;
                }
                // A job's own spooled .nzb back out - the queue/history
                // drawer's "Download .nzb". Works for EVERY origin,
                // including jobs whose watch-folder original is long
                // gone; nzbfast keeps a spool copy for the job's whole
                // life (a cleared/deleted record removes it, hence the
                // 404 arm). FULL key only, unlike /getnzb above: the
                // add-only nzbkey may pull index-built NZBs, but a
                // job's spool says what this user downloads, which is
                // exactly what an add-only credential must not read.
                if let Some(rest) = path.strip_prefix("/jobnzb/") {
                    route_jobnzb(req, &d, rest, &params, &cur_apikey, &cur_nzbkey);
                    continue;
                }
                // M21: NZBGet JSON-RPC facade - remote-control apps built for
                // NZBGet (LunaSea, NZBDonkey, …) work unmodified. Auth is
                // HTTP Basic (any username, password = an API key) OR
                // NZBGet's own URL form `/<user>:<pass>/jsonrpc`, which is
                // the only shape LunaSea ever sends (§18): it builds the
                // credentials into the path and sets no Authorization
                // header, so a daemon without this route answers 404 and
                // the app reports the server as unreachable.
                let jr_path_pw = jsonrpc_path_password(path);
                if path == "/jsonrpc" || path.starts_with("/jsonrpc/") || jr_path_pw.is_some() {
                    handle_jsonrpc(
                        &d,
                        req,
                        cur_apikey.as_deref(),
                        cur_nzbkey.as_deref(),
                        jr_path_pw.as_deref(),
                    );
                    continue;
                }
                if path != "/api" {
                    let _ = req
                        .respond(tiny_http::Response::from_string("nzbfast").with_status_code(404));
                    continue;
                }
                // SABnzbd merges GET and POST parameters; the browser addons
                // (NZBDonkey, NZB Unity) rely on that and send mode/apikey/cat
                // as POST form fields with nothing in the query string - so a
                // key that authenticates against SAB never reached our
                // query-only parse and was rejected ("[auth] rejected key for
                // api"). Read the body ONCE here and merge any form fields in
                // (query wins); the addfile/wall_art arms consume the file
                // part from this same buffer. This does buffer a capped body
                // before auth - SAB parity, loopback-bound by default, and the
                // auth-fail limiter still counts the failure afterwards.
                //
                // EVERY post, whatever it calls itself (Codex sweep 2, 3 Aug
                // H1). The read used to happen only for three recognized
                // content types, and a handler whose body was not pre-read
                // fell back to reading the socket itself - AFTER dispatch,
                // which is after the authorization decision. So a caller
                // holding key A could send `?mode=server_save&apikey=A` with
                // NO Content-Type at all, stall the body, wait for the owner
                // to rotate A to B, and then complete the destructive write
                // under the revoked key. `Application/JSON` was a second way
                // in: media types are case-insensitive and the classifier
                // was not. Making the read unconditional retires the
                // fallback entirely, so no handler can reach the socket
                // after auth - see the `unwrap_or_default()` in each of
                // them.
                handle_api(req, &d, &cfg_path, params);
            }
        });
    }
}

/// Tests for the pure request-parsing helpers this router leans on.
/// They live in serve/mod.rs; this module is a descendant, so the
/// private items are in scope through the glob import above.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_query_decodes_values_and_last_key_wins() {
        let p = parse_query("a=1&b=hello%20world&c=x%2Fy&d=a+b");
        assert_eq!(p["a"], "1");
        assert_eq!(p["b"], "hello world");
        assert_eq!(p["c"], "x/y");
        assert_eq!(p["d"], "a b");
        // A valueless key has no '=' and is dropped, not kept empty.
        let p = parse_query("bare&k=v");
        assert!(!p.contains_key("bare"));
        assert_eq!(p["k"], "v");
        // Repeated keys: the map keeps the last occurrence.
        assert_eq!(parse_query("a=1&a=2")["a"], "2");
        // Empty query: empty map.
        assert!(parse_query("").is_empty());
        // The KEY is not decoded - only the value is.
        let p = parse_query("a%20b=c");
        assert!(p.contains_key("a%20b"));
    }

    #[test]
    fn parse_form_body_is_bounded() {
        // Ordinary fields decode like the query parser, kept in order.
        let f = parse_form_body("a=1&b=x%20y&a=2");
        assert_eq!(
            f,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "x y".to_string()),
                ("a".to_string(), "2".to_string()),
            ]
        );
        // Pairs without '=', empty keys, oversized keys and oversized
        // values are all skipped rather than kept.
        let big_key = "k".repeat(257);
        let big_val = "v".repeat(4097);
        let body = format!("bare&=v&{big_key}=v&ok=1&k={big_val}");
        assert_eq!(
            parse_form_body(&body),
            vec![("ok".to_string(), "1".to_string())]
        );
        // The field count is capped at 256 whatever the caller sent.
        let flood: String = (0..1000).map(|i| format!("f{i}=v&")).collect();
        assert_eq!(parse_form_body(&flood).len(), 256);
    }

    /// The parameter-separator shapes the mod.rs boundary test does not
    /// cover: a trailing parameter after the boundary, quoted and not.
    #[test]
    fn multipart_boundary_stops_at_the_parameter_separator() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"----abc\"; charset=UTF-8"),
            Some("----abc".to_string())
        );
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=----abc; charset=UTF-8"),
            Some("----abc".to_string())
        );
        assert_eq!(multipart_boundary("text/plain; charset=UTF-8"), None);
    }

    /// Only the modes that legitimately carry bulk get more than the
    /// default; everything else is at the 1 MiB floor.
    #[test]
    fn api_body_caps_by_mode() {
        assert_eq!(api_body_cap("addfile"), API_BODY_MAX);
        assert_eq!(api_body_cap("addfile"), 256 << 20);
        // Same payload as addfile - a whole NZB, bare or multipart - so
        // the same ceiling. On the default it truncated at 1 MiB and
        // then reported a valid NZB as invalid, while addfile took the
        // identical bytes.
        assert_eq!(api_body_cap("nzb_preview"), API_BODY_MAX);
        assert_eq!(api_body_cap("backup_import"), 8 << 20);
        assert_eq!(api_body_cap("wall_art"), 10 << 20);
        assert_eq!(api_body_cap("queue"), API_BODY_DEFAULT);
        assert_eq!(api_body_cap(""), 1 << 20);
    }

    /// The header names and values, spelled out.
    fn cors(allow: &str, origin: Option<&str>, preflight: bool) -> Vec<(String, String)> {
        cors_headers(allow, origin, preflight)
            .iter()
            .map(|h| (h.field.as_str().as_str().to_string(), h.value.to_string()))
            .collect()
    }

    fn value_of(hs: &[(String, String)], name: &str) -> Option<String> {
        hs.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    /// §141 (issue #33). The default is SABnzbd's, and it is the same
    /// answer whether or not the caller named an origin - `curl` gets it
    /// too, which is how the reporter checked SAB in the first place.
    #[test]
    fn cors_default_is_the_wildcard_sabnzbd_sends() {
        for origin in [None, Some("moz-extension://abc")] {
            let h = cors(CORS_DEFAULT, origin, false);
            assert_eq!(
                value_of(&h, "Access-Control-Allow-Origin"),
                Some("*".to_string())
            );
            // One answer for everyone: nothing varies by Origin.
            assert_eq!(value_of(&h, "Vary"), None);
            // Illegal beside `*`, and pointless for a key that travels
            // in the request rather than in a cookie.
            assert_eq!(value_of(&h, "Access-Control-Allow-Credentials"), None);
        }
    }

    /// Empty is off: the state the daemon shipped in before §141, kept
    /// reachable for anyone who wants it.
    #[test]
    fn an_empty_cors_origin_sends_nothing_at_all() {
        assert!(cors("", Some("https://a.example"), false).is_empty());
        assert!(cors("   ", Some("https://a.example"), true).is_empty());
    }

    /// A list answers the caller's own origin, by the CONFIGURED
    /// spelling - never by echoing the request's bytes back into a
    /// response header - and always with `Vary: Origin`.
    #[test]
    fn a_restricted_cors_origin_answers_only_its_own_list() {
        let allow = "https://a.example, https://b.example:8080";
        for o in ["https://a.example", "https://b.example:8080"] {
            let h = cors(allow, Some(o), false);
            assert_eq!(
                value_of(&h, "Access-Control-Allow-Origin"),
                Some(o.to_string())
            );
            assert_eq!(value_of(&h, "Vary"), Some("Origin".to_string()));
        }
        // A stranger, a caller with no Origin at all, and a prefix of a
        // listed origin all get no permission - but the answer still
        // varies by Origin, so a cache cannot hand one to the other.
        for o in [
            Some("https://evil.example"),
            None,
            Some("https://a.example.evil.net"),
            Some("https://a.example:443"),
        ] {
            let h = cors(allow, o, false);
            assert_eq!(value_of(&h, "Access-Control-Allow-Origin"), None, "{o:?}");
            assert_eq!(value_of(&h, "Vary"), Some("Origin".to_string()), "{o:?}");
        }
        // Scheme and host are case-insensitive (RFC 6454); what goes out
        // is still the configured spelling.
        let h = cors(allow, Some("HTTPS://A.EXAMPLE"), false);
        assert_eq!(
            value_of(&h, "Access-Control-Allow-Origin"),
            Some("https://a.example".to_string())
        );
    }

    /// The preflight trio rides OPTIONS only. Without an answer here
    /// Firefox never sends the real request, so the header on the real
    /// response would never be reached.
    #[test]
    fn only_the_preflight_carries_methods_and_headers() {
        let plain = cors(CORS_DEFAULT, None, false);
        for h in [
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Max-Age",
        ] {
            assert_eq!(value_of(&plain, h), None, "{h} on a plain answer");
        }
        let pre = cors(CORS_DEFAULT, None, true);
        let methods = value_of(&pre, "Access-Control-Allow-Methods").unwrap();
        assert!(
            methods.contains("GET") && methods.contains("POST"),
            "{methods}"
        );
        let allowed = value_of(&pre, "Access-Control-Allow-Headers")
            .unwrap()
            .to_ascii_lowercase();
        for h in ["x-api-key", "authorization", "content-type"] {
            assert!(allowed.contains(h), "{h} missing from {allowed}");
        }
        assert!(value_of(&pre, "Access-Control-Max-Age").is_some());
    }

    #[test]
    fn ct_eq_compares_whole_strings() {
        assert!(ct_eq("secret", "secret"));
        assert!(ct_eq("", ""));
        assert!(!ct_eq("secret", "secreT"));
        assert!(!ct_eq("secret", "secre"));
        assert!(!ct_eq("", "x"));
    }

    /// No token, no answer - and the nonce is charset- and length-gated
    /// before anything is hashed.
    #[test]
    fn launcher_proof_refuses_without_a_token() {
        assert_eq!(launcher_proof("", Some("abcdefgh")), None);
        assert_eq!(launcher_proof("tok", None), None);
        // Too short, too long, or non-alphanumeric: refused.
        assert_eq!(launcher_proof("tok", Some("abc")), None);
        assert_eq!(launcher_proof("tok", Some(&"a".repeat(129))), None);
        assert_eq!(launcher_proof("tok", Some("abcd-efgh")), None);
        // The answer is sha256(token ":" nonce), hex-encoded.
        let expect = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"tok:abcdefgh");
            hex::encode(h.finalize())
        };
        assert_eq!(launcher_proof("tok", Some("abcdefgh")), Some(expect));
    }

    /// TODO 23 low1: the API key must never reach the browser child's
    /// argv. It used to, as `?apikey=` in the launch URL, which on Linux
    /// put it in a world-readable `/proc/<pid>/cmdline`.
    ///
    /// Asserted against the argv the spawn really uses, on every element
    /// including the program name, because the leak was one `format!`
    /// away from looking correct.
    #[test]
    fn the_browser_argv_never_carries_the_api_key() {
        const KEY: &str = "1f8b0e5c2d4a6b8c0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b";
        let slot = std::sync::Mutex::new(None);
        let (prog, args) = dashboard_argv_in(&slot, 6789, false, Some(KEY));
        assert!(!prog.contains(KEY), "{prog}");
        for a in &args {
            assert!(!a.contains(KEY), "key in argv: {a}");
        }
        // What DID go out is a handoff token, and it redeems for the key.
        let url = args.last().expect("a url");
        let token = url
            .split_once("?handoff=")
            .map(|(_, t)| t.to_string())
            .unwrap_or_else(|| panic!("no handoff token in {url}"));
        assert!(!token.is_empty() && token != KEY);
        assert_eq!(redeem_handoff_in(&slot, &token), Redeem::Key(KEY.into()));
    }

    /// One exchange, and only for the token that was armed. A miss must
    /// not burn the hit: any local process could otherwise disarm the
    /// launch in flight by posting one byte.
    #[test]
    fn a_handoff_is_redeemable_once_and_a_miss_does_not_burn_it() {
        let slot = std::sync::Mutex::new(None);
        assert_eq!(
            redeem_handoff_in(&slot, "anything"),
            Redeem::Refused,
            "nothing armed"
        );
        let token = arm_handoff_in(&slot, "the-key").expect("armed");
        assert_eq!(redeem_handoff_in(&slot, "wrong"), Redeem::Refused);
        assert_eq!(redeem_handoff_in(&slot, ""), Redeem::Refused);
        assert_eq!(
            redeem_handoff_in(&slot, &token),
            Redeem::Key("the-key".into())
        );
    }

    /// The second presentation of the RIGHT token is not "nothing
    /// armed": the slot remembers the token it traded, so a replay is
    /// told apart from a miss. Exactly one of the two presenters was the
    /// browser this daemon spawned, and `route_handoff` rotates the key
    /// on this answer. A wrong token after the trade is still a plain
    /// refusal, and still burns nothing: the mark survives it.
    #[test]
    fn a_second_redeem_with_the_right_token_is_a_replay() {
        let slot = std::sync::Mutex::new(None);
        let token = arm_handoff_in(&slot, "the-key").expect("armed");
        assert_eq!(
            redeem_handoff_in(&slot, &token),
            Redeem::Key("the-key".into())
        );
        assert_eq!(redeem_handoff_in(&slot, "wrong"), Redeem::Refused);
        assert_eq!(redeem_handoff_in(&slot, &token), Redeem::Replay, "replayed");
        // And again: the mark is not consumed by being seen.
        assert_eq!(redeem_handoff_in(&slot, &token), Redeem::Replay);
        // What the slot keeps is a hash, never the key, so a replay is
        // never a second copy of the credential.
        assert!(slot.lock_ok().as_ref().is_some_and(|h| h.holds_no_key()));
    }

    /// A request that authenticates with the full key proves its sender
    /// already has what the token was minted to deliver, so the token
    /// stops being worth a key. The mark stays: a later presentation is
    /// a replay, not a miss. And a slot that was already traded is left
    /// alone, because in the sequence where a reader traded first, that
    /// reader's own authenticated requests must not erase the evidence
    /// the browser's late arrival is judged against.
    #[test]
    fn a_full_key_request_disarms_an_armed_handoff_but_keeps_the_mark() {
        let slot = std::sync::Mutex::new(None);
        disarm_handoff_in(&slot);
        assert!(slot.lock_ok().is_none(), "nothing to disarm");
        let token = arm_handoff_in(&slot, "the-key").expect("armed");
        disarm_handoff_in(&slot);
        assert_eq!(redeem_handoff_in(&slot, &token), Redeem::Replay);
        assert_eq!(redeem_handoff_in(&slot, "wrong"), Redeem::Refused);
        // Traded first, then an authenticated request, then the token
        // again: still a replay.
        let slot = std::sync::Mutex::new(None);
        let token = arm_handoff_in(&slot, "k2").expect("armed");
        assert_eq!(redeem_handoff_in(&slot, &token), Redeem::Key("k2".into()));
        disarm_handoff_in(&slot);
        assert_eq!(redeem_handoff_in(&slot, &token), Redeem::Replay);
    }

    /// F-09: the handoff token only ever exists in the argv of a browser
    /// this daemon spawned on this machine, so a redeemer from anywhere
    /// else is by construction not that browser. On a `--bind 0.0.0.0`
    /// install the door is otherwise network-reachable.
    ///
    /// The refusal comes BEFORE the redeem, so the remote attempt must
    /// not burn the token: the local browser arriving second still gets
    /// its key. The loopback presenters here are real sockets this
    /// process opened to itself, so the account lookup runs for real and
    /// finds our own uid (or, on a platform with no arm, nothing).
    #[test]
    fn a_handoff_is_redeemable_only_from_this_machine() {
        let slot = std::sync::Mutex::new(None);
        let token = arm_handoff_in(&slot, "the-key").expect("armed");
        let lan: std::net::SocketAddr = "192.168.1.44:41000".parse().unwrap();
        let wan: std::net::SocketAddr = "203.0.113.7:41000".parse().unwrap();
        assert_eq!(
            redeem_handoff_from(&slot, Some(lan), 6789, &token),
            Redeem::Refused
        );
        assert_eq!(
            redeem_handoff_from(&slot, Some(wan), 6789, &token),
            Redeem::Refused
        );
        // No address at all is not evidence of locality either.
        assert_eq!(
            redeem_handoff_from(&slot, None, 6789, &token),
            Redeem::Refused
        );
        // None of that burned it, and the loopback caller still trades.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let _c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (_s, lo) = l.accept().unwrap();
        assert_eq!(
            redeem_handoff_from(&slot, Some(lo), port, &token),
            Redeem::Key("the-key".into())
        );
        // A remote presenter of a spent token is refused, not told it
        // was spent: the replay answer is for this machine only too.
        assert_eq!(
            redeem_handoff_from(&slot, Some(lan), 6789, &token),
            Redeem::Refused
        );
        // IPv6 loopback is this machine too, and one use is still one use.
        let slot = std::sync::Mutex::new(None);
        let token = arm_handoff_in(&slot, "k6").expect("armed");
        let l6 = std::net::TcpListener::bind("[::1]:0").unwrap();
        let port6 = l6.local_addr().unwrap().port();
        let _c6 = std::net::TcpStream::connect(("::1", port6)).unwrap();
        let (_s6, lo6) = l6.accept().unwrap();
        assert_eq!(
            redeem_handoff_from(&slot, Some(lo6), port6, &token),
            Redeem::Key("k6".into())
        );
        assert_eq!(
            redeem_handoff_from(&slot, Some(lo6), port6, &token),
            Redeem::Replay
        );
    }

    /// The residual the replay mark could not reach: an argv reader in
    /// ANOTHER local account that trades first on a launch where the
    /// browser never arrives. Loopback is every local account's, so the
    /// kernel is asked who owns the presenting socket, and a socket of
    /// another account is refused outright - before the key is taken,
    /// so the browser still trades after it, and without the slot
    /// forgetting anything, so the late browser is a `Key` and not a
    /// `Replay`. A foreign presenter of an already-spent token is still
    /// `Foreign`, not `Replay`: it never held the key, so there is
    /// nothing to rotate. And the lookup is never made for a wrong
    /// token, so a spray cannot make the daemon walk the table.
    #[test]
    fn a_presenter_from_another_local_account_is_refused_without_burning_the_token() {
        use super::super::peeracct::PeerAccount;
        let asked = std::cell::Cell::new(0);
        let other = || {
            asked.set(asked.get() + 1);
            PeerAccount::Other("uid 1001".into())
        };
        let slot = std::sync::Mutex::new(None);
        let token = arm_handoff_in(&slot, "the-key").expect("armed");
        assert_eq!(
            redeem_handoff_as(&slot, "wrong", other),
            Redeem::Refused,
            "a miss is refused before anyone is asked"
        );
        assert_eq!(asked.get(), 0);
        assert_eq!(
            redeem_handoff_as(&slot, &token, other),
            Redeem::Foreign("uid 1001".into())
        );
        assert_eq!(asked.get(), 1);
        assert!(
            slot.lock_ok().as_ref().is_some_and(|h| !h.holds_no_key()),
            "the foreign presenter burned nothing"
        );
        // The browser, arriving after the reader: a Key, not a Replay.
        assert_eq!(
            redeem_handoff_as(&slot, &token, || PeerAccount::Ours),
            Redeem::Key("the-key".into())
        );
        // The reader again, now that it is spent: still Foreign, and the
        // replay answer (which rotates the key) is not given to it.
        assert_eq!(
            redeem_handoff_as(&slot, &token, other),
            Redeem::Foreign("uid 1001".into())
        );
        // Our own account presenting twice is the replay it always was.
        assert_eq!(
            redeem_handoff_as(&slot, &token, || PeerAccount::Ours),
            Redeem::Replay
        );
        // A box where the owner cannot be read keeps the old rule: the
        // token trades, once.
        let slot = std::sync::Mutex::new(None);
        let token = arm_handoff_in(&slot, "k2").expect("armed");
        assert_eq!(
            redeem_handoff_as(&slot, &token, || PeerAccount::Unknown),
            Redeem::Key("k2".into())
        );
        assert_eq!(
            redeem_handoff_as(&slot, &token, || PeerAccount::Unknown),
            Redeem::Replay
        );
    }

    /// No key to hand over (every run after the first) means no token
    /// and a plain URL - not an empty `?handoff=`, which would send the
    /// page off to trade a token that was never minted.
    #[test]
    fn a_keyless_launch_opens_a_plain_url() {
        let slot = std::sync::Mutex::new(None);
        let (_, args) = dashboard_argv_in(&slot, 6789, true, None);
        let url = args.last().expect("a url");
        assert_eq!(url, "https://localhost:6789/");
        assert!(slot.lock_ok().is_none(), "nothing armed");
    }
}
