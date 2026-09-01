use super::super::*;
use super::ApiCtx;

/// Most of a log file we will read to answer for its last `n` lines.
///
/// The launchers rotate at 5 MB and a caller may ask for 2000 lines, so
/// reading the file whole would pull megabytes into memory to throw
/// nearly all of them away - on the API thread, on every refresh of a
/// panel a user can leave open.
const LOG_TAIL_BYTES: u64 = 1 << 20;

/// What the log panel shows: the lines, and whether this daemon can show
/// a log at all (which is the difference between "nothing logged yet"
/// and "no log capture here" in the UI).
///
/// Split out from the request handler and taking the ring's state as
/// ARGUMENTS because the interesting case cannot be reproduced on the
/// platform this is developed on: unix always has a live tee, so the
/// fallback branch would never be reached by any test running here, and
/// the platform where it matters is the one that has historically hidden
/// real bugs from us. As a function of its inputs it is testable
/// everywhere.
fn log_payload(
    n: usize,
    ring: Vec<String>,
    active: bool,
    dir: Option<&std::path::Path>,
) -> (Vec<String>, bool) {
    if !ring.is_empty() {
        return (ring, active);
    }
    match dir.and_then(|d| tail_log_file(&d.join("daemon.log"), n)) {
        // A readable log file IS this daemon showing you its log, so the
        // flag turns true even when the file is empty - otherwise a
        // quiet Windows daemon still reads as "not available on this
        // platform", which is the bug being fixed.
        Some(lines) => (lines, true),
        None => (ring, active),
    }
}

/// Last `n` lines of a log file, or `None` if it cannot be read.
///
/// `Some(vec![])` for a file that exists and is empty: the caller tells
/// "nothing logged yet" from "no log here at all" by which of those it
/// gets back, and those are different sentences in the UI.
fn tail_log_file(path: &std::path::Path, n: usize) -> Option<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let from = len.saturating_sub(LOG_TAIL_BYTES);
    f.seek(SeekFrom::Start(from)).ok()?;
    let mut buf = Vec::new();
    f.take(LOG_TAIL_BYTES).read_to_end(&mut buf).ok()?;
    // Lossy: a legacy-encoded RAR/PAR2 filename printed by a child
    // process reaches this file, and one undecodable byte must not cost
    // the whole panel (the same reasoning the unix tee's reader uses).
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    // A window that did not start at byte 0 almost certainly opened
    // mid-line; drop that fragment rather than serving half a line.
    if from > 0 {
        lines.next();
    }
    let all: Vec<&str> = lines.collect();
    Some(
        all[all.len().saturating_sub(n)..]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    )
}

/// The download root as the caller is allowed to see it.
///
/// `status` and `fullstatus` are in the add-only allowlist so a push
/// extension's "test connection" button works, and that tier's contract
/// is "a version string, paused/warning/disk numbers and the category
/// names". The absolute download path is none of those, and `config`
/// already withholds a path on its own success arm precisely so the
/// daemon does not volunteer its filesystem layout to every API caller.
/// Empty rather than absent: Sonarr and Radarr resolve a relative
/// `completedir` and a missing key reads differently from a blank one.
fn out_dir_for(d: &Daemon, ctx: &ApiCtx<'_>) -> String {
    if ctx.via_add_only {
        String::new()
    } else {
        d.out_dir().to_string_lossy().into_owned()
    }
}

fn m_version(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let mut v = json!({
            "version": SAB_VERSION,
            "nzbfast": env!("CARGO_PKG_VERSION"),
            "beta": env!("NZBFAST_BETA"),
        });
        // Same handshake as the keyless refusal above answers,
        // for a keyless install (where this arm IS what a
        // wrapper's probe reaches).
        if let Some(proof) = launcher_proof(&d.launcher_token, params.get("hs").map(String::as_str))
        {
            v["hs_proof"] = json!(proof);
        }
        v
    })
}

fn m_warm_bench(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let host = params.get("host").cloned().unwrap_or_default();
        let server = nzbkit::config::Config::load(ctx.cfg_path)
            .ok()
            .and_then(|c| c.servers.iter().find(|s| s.host == host).cloned());
        match server {
            None => json!({"status": false, "error": "no such server"}),
            Some(server) => {
                // block_on + a hard ceiling, like the
                // test-server and sysbench handlers: a
                // black-holed host must not wedge the API
                // thread. One connect per fresh-first pair and
                // two per warm-first pair, each already
                // bounded, so this only trips on a host that
                // is pathologically slow rather than dead.
                let r = tokio::runtime::Handle::current().block_on(async {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(120),
                        nzbkit::warmbench::measure(&server, nzbkit::warmbench::PAIRS),
                    )
                    .await
                });
                match r {
                    Err(_) => json!({
                        "status": false,
                        "error": "timed out measuring this server"
                    }),
                    Ok(r) => json!({
                        "status": true,
                        "host": host,
                        "verdict": match r.verdict {
                            nzbkit::warmbench::Verdict::Worthwhile => "worthwhile",
                            nzbkit::warmbench::Verdict::NoMeasurableBenefit => "none",
                            nzbkit::warmbench::Verdict::Failed => "failed",
                        },
                        "recommend_on": r.recommends_on(),
                        "samples": r.samples,
                        "fresh_ms": r.fresh_ms,
                        "warm_ms": r.warm_ms,
                        "saved_ms": r.saved_ms,
                        "ci_low_ms": r.ci_low_ms,
                        "ci_high_ms": r.ci_high_ms,
                        "detail": r.detail,
                    }),
                }
            }
        }
    })
}

fn m_log(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let n: usize = params
            .get("value")
            .and_then(|v| v.parse().ok())
            .unwrap_or(200)
            .min(2000);
        // The folder beside the settings file, which is where every
        // launcher puts daemon.log: derived entirely from our own
        // config path, never from anything the caller sent.
        let (lines, capturing) = log_payload(
            n,
            nzbkit::logtee::tail(n),
            nzbkit::logtee::active(),
            d.settings_path.parent(),
        );
        // §163 item 5: scrubbed on the way out, on BOTH sources - the
        // ring and the daemon.log fallback carry the same lines, and
        // this is the pane whose contents get pasted into issues.
        let lines = super::super::logscrub::LogScrub::new(d).tail(lines);
        json!({ "lines": lines, "capturing": capturing })
    })
}

fn m_open_dir(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let key = params.get("value").map(String::as_str).unwrap_or("");
        // Containing folder of a file setting. Absolutised
        // first: parent() of a bare relative name is "", which
        // exists() rejects and reads as a nonsense error.
        let parent_of = |p: &std::path::Path| -> Option<PathBuf> {
            let abs = if p.is_absolute() {
                p.to_path_buf()
            } else {
                std::env::current_dir().ok()?.join(p)
            };
            abs.parent().map(|x| x.to_path_buf())
        };
        let target: Option<PathBuf> = match key {
            "out_dir" => Some(d.out_dir().clone()),
            "move_completed" => d.move_completed.read_ok().clone(),
            "watch" => d.watch_dir.lock_ok().clone(),
            // The chain's FIRST link names the scripts folder - the
            // same one `nzbop_options` reports as NZBOP_ScriptDir.
            "script" => d.scripts.lock_ok().first().and_then(|p| parent_of(p)),
            "password_file" => parent_of(&d.password_file.lock_ok()),
            #[cfg(feature = "indexer")]
            "index_db" => parent_of(&d.index_db),
            "config" => parent_of(&d.settings_path),
            _ => None,
        };
        // Report the absolute path - "scratchdl" tells the user
        // nothing about which folder actually opened.
        let target = target.map(|p| p.canonicalize().unwrap_or(p));
        match target {
            None => json!({"status": false, "error": format!("{key} is not set")}),
            Some(p) if !p.exists() => json!({
                "status": false,
                "error": format!("{} does not exist yet", p.to_string_lossy()),
            }),
            Some(p) => json!({"status": os_open(&p), "path": p.to_string_lossy()}),
        }
    })
}

fn m_fs_list(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(fs_list(d, params))
}

/// Read one directory into the browser's `entries` shape (folders first,
/// then case-insensitive by name; dotfiles hidden like most pickers).
/// `Err` when the directory cannot be read at all - the caller uses that
/// to fall back to a readable ancestor rather than dead-end the picker,
/// and surfaces the io error (ENOENT vs EACCES) if nothing works.
fn fs_listing(dir: &std::path::Path, want_files: bool) -> std::io::Result<(Vec<Value>, bool)> {
    let rd = std::fs::read_dir(dir)?;
    let mut entries: Vec<(bool, String)> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                return None; // hide dotfiles, like most pickers
            }
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            (is_dir || want_files).then_some((is_dir, name))
        })
        .collect();
    // Folders first, then case-insensitive by name.
    entries.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase()))
    });
    let entries: Vec<Value> = entries
        .into_iter()
        .map(|(is_dir, name)| json!({"name": name, "dir": is_dir}))
        .collect();
    Ok((entries, path_writable(dir)))
}

/// Nearest ancestor of `start` that `read_dir` accepts, walking up to the
/// filesystem root. Keeps the directory browser off a dead end when the
/// requested path is gone - an unmounted external drive, a deleted folder,
/// or a config carried over from another machine that points at a volume
/// which does not exist here.
fn nearest_listable(start: &std::path::Path) -> Option<PathBuf> {
    let mut cur = start.parent();
    while let Some(p) = cur {
        if std::fs::read_dir(p).is_ok() {
            return Some(p.to_path_buf());
        }
        cur = p.parent();
    }
    None
}

/// The directory browser. The requested path is best-effort: when it is
/// gone or unreadable we fall back to the nearest readable ancestor (or
/// HOME) and say so in `note`, and even the give-up branch still hands back
/// `roots`/`parent` so the user can always navigate to another drive to
/// repoint their download folder. Read-only; the full-key auth gate is
/// applied by the dispatcher before we are reached.
fn fs_list(d: &Arc<Daemon>, params: &std::collections::HashMap<String, String>) -> Value {
    let want_files = params.get("fmode").map(String::as_str) == Some("file");
    let raw = params.get("path").map(String::as_str).unwrap_or("");
    // Empty path → start where the user is now: the current download
    // root, so "here's where it points today" needs no typing.
    let start = if raw.is_empty() {
        d.out_dir()
            .canonicalize()
            .unwrap_or_else(|_| d.out_dir().clone())
    } else {
        PathBuf::from(raw)
    };
    let mut dir = if start.is_absolute() {
        start
    } else {
        std::env::current_dir().unwrap_or_default().join(start)
    };
    // A file path browses its containing folder.
    if dir.is_file()
        && let Some(p) = dir.parent()
    {
        dir = p.to_path_buf();
    }
    let dir = dir.canonicalize().unwrap_or(dir);

    // The requested directory, or - if it is unreadable - the nearest
    // readable ancestor, or HOME. `note` is set only on a fallback. Each
    // candidate is tried in turn: an ancestor proven readable can still
    // vanish between the probe and the listing, and that must not stop
    // HOME from being tried.
    let (listed, read_err) = match fs_listing(&dir, want_files) {
        Ok((entries, writable)) => (Some((dir.clone(), entries, writable, None)), None),
        Err(e) => {
            let home = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from);
            let picked = nearest_listable(&dir)
                .into_iter()
                .chain(home)
                .find_map(|c| {
                    let (entries, writable) = fs_listing(&c, want_files).ok()?;
                    let note = format!(
                        "{} is not available - showing {} instead.",
                        dir.to_string_lossy(),
                        c.to_string_lossy()
                    );
                    Some((c, entries, writable, Some(note)))
                });
            (picked, Some(e))
        }
    };

    match listed {
        Some((shown, entries, writable, note)) => {
            let mut v = json!({
                "status": true,
                "path": shown.to_string_lossy(),
                "parent": shown.parent().map(|p| p.to_string_lossy().to_string()),
                "writable": writable,
                "entries": entries,
                "roots": fs_roots(&d.out_dir()),
            });
            if let Some(note) = note {
                v["note"] = json!(note);
            }
            v
        }
        // Nothing was readable anywhere - still hand back navigation
        // targets so the user is never stranded and can pick another drive.
        None => json!({
            "status": false,
            "path": dir.to_string_lossy(),
            "parent": dir.parent().map(|p| p.to_string_lossy().to_string()),
            // Keep the io detail (ENOENT vs EACCES) - support logs need it.
            "error": match read_err {
                Some(e) => format!("{} is not available: {e}", dir.to_string_lossy()),
                None => format!("{} is not available", dir.to_string_lossy()),
            },
            "roots": fs_roots(&d.out_dir()),
        }),
    }
}

fn m_fs_mkdir(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let parent = params.get("path").map(String::as_str).unwrap_or("");
        let name = params.get("value").map(|s| s.trim()).unwrap_or("");
        if parent.is_empty()
            || name.is_empty()
            || name == ".."
            || name.contains('/')
            || name.contains('\\')
        {
            json!({"status": false, "error": "invalid folder name"})
        } else {
            let target = PathBuf::from(parent).join(name);
            match std::fs::create_dir(&target) {
                Ok(()) => json!({"status": true, "path": target.to_string_lossy()}),
                Err(e) => json!({"status": false, "error": e.to_string()}),
            }
        }
    })
}

fn m_remote_info(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let port = d.port;
        // §129 2a: with native TLS on, every advertised URL (and its QR
        // code) must say https - the http:// sibling answers nothing.
        let scheme = if d.tls_cert.is_some() {
            "https"
        } else {
            "http"
        };
        let mut urls: Vec<Value> = Vec::new();
        // The address the browser ACTUALLY reached us on (Host
        // header) is authoritative - it works by definition, and
        // unlike interface auto-detection it stays correct behind
        // Docker/NAT/reverse proxies, where local_addr() would be a
        // container bridge IP (172.17.x) no other device can reach.
        // An IPv6 literal is bracketed, and its own colons are not the
        // port separator: `rsplit_once(':')` on a portless "[::1]" hands
        // back "[:", which is neither a host nor loopback - so a daemon
        // reached over IPv6 on 80/443 advertised its loopback URL as the
        // LAN one. Split after the bracket; a name or an IPv4 has no
        // colon but the port's.
        let host_only = match ctx.host_hdr.strip_prefix('[') {
            Some(rest) => rest.split_once(']').map(|(h, _)| h).unwrap_or(rest),
            None => ctx
                .host_hdr
                .split_once(':')
                .map(|(h, _)| h)
                .unwrap_or(ctx.host_hdr),
        };
        let is_loopback = matches!(host_only, "localhost" | "127.0.0.1" | "::1");
        let containerized = std::path::Path::new("/.dockerenv").exists();
        if !ctx.host_hdr.is_empty() && !is_loopback {
            urls.push(json!({"kind": "connected",
                            "url": format!("{scheme}://{}/", ctx.host_hdr),
                            "label": "Wi-Fi / same network"}));
        } else {
            // Reached via localhost - auto-detect a shareable LAN
            // IP (bare metal only; a container would just detect
            // its own bridge address). No packet is sent, and the
            // socket that asks is bound at most once a minute rather
            // than once a call (TODO 33 - it is a wildcard bind, which
            // is a macOS firewall dialog).
            if let Some(a) = crate::serve::lanaddr::route_src("8.8.8.8:53") {
                urls.push(json!({"kind": "lan",
                                "url": format!("{scheme}://{a}:{port}/"),
                                "label": "Wi-Fi / same network"}));
            }
        }
        // mDNS name - phones resolve .local natively. Skipped in a
        // container, where `hostname` is the container name, not
        // the host's - that .local would not resolve on the LAN.
        if !containerized && let Ok(out) = std::process::Command::new("hostname").output() {
            let mut h = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !h.is_empty() {
                if !h.ends_with(".local") {
                    h = format!("{}.local", h.trim_end_matches(".local"));
                }
                urls.push(json!({"kind": "mdns",
                                    "url": format!("{scheme}://{h}:{port}/"),
                                    "label": "Name on your network"}));
            }
        }
        // Tailscale (CGNAT 100.64/10): if present, this URL
        // works from ANYWHERE the phone is on the tailnet -
        // the zero-port-forwarding external answer.
        // Cached like the LAN lookup above, and this is the site that
        // needed it most: the answer is asked for on every call whether
        // the panel is loopback-reached or not, and on a machine with
        // no Tailscale - almost all of them - the answer is a miss that
        // never changes.
        let ts = crate::serve::lanaddr::route_src("100.100.100.100:53").filter(|ip| match ip {
            std::net::IpAddr::V4(v) => {
                let o = v.octets();
                o[0] == 100 && (64..128).contains(&o[1])
            }
            _ => false,
        });
        if let Some(ip) = ts {
            urls.push(json!({"kind": "tailscale",
                            "url": format!("{scheme}://{ip}:{port}/"),
                            "label": "Tailscale - works from anywhere"}));
        }
        json!({"urls": urls, "port": port,
                        "has_apikey": d.apikey.lock_ok().is_some()})
    })
}

fn m_qr(
    _d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let url = params.get("value").cloned().unwrap_or_default();
        match qrcodegen::QrCode::encode_text(&url, qrcodegen::QrCodeEcc::Medium) {
            Err(_) => json!({"status": false, "error": "text too long"}),
            Ok(qr) => {
                let n = qr.size();
                let mut p = String::new();
                for y in 0..n {
                    for x in 0..n {
                        if qr.get_module(x, y) {
                            p.push_str(&format!("M{x},{y}h1v1h-1z"));
                        }
                    }
                }
                json!({"svg": format!(
                    "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"-2 -2 {v} {v}\" shape-rendering=\"crispEdges\"><path d=\"{p}\" fill=\"currentColor\"/></svg>",
                    v = n + 4
                )})
            }
        }
    })
}

fn m_notify_test(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        if req.method() != &tiny_http::Method::Post {
            json!({"status": false, "error": "POST required"})
        } else {
            // From the BODY, with `&value=` kept only for callers
            // that already had it (Codex sweep 2, 3 Aug MH1). The
            // target carries a webhook token and a custom body
            // template, and a POST is not private when its
            // parameters ride the query string - reverse proxies log
            // that line, and so does the browser. Being a POST was
            // never the point: it exists so a page you merely visit
            // cannot fire this with an <img>.
            let raw = api_body
                .take()
                .filter(|b| !b.is_empty())
                .and_then(|b| {
                    serde_json::from_slice::<Value>(&b)
                        .ok()
                        .and_then(|v| v.get("target").cloned())
                        .map(|t| t.to_string())
                })
                .or_else(|| params.get("value").cloned())
                .unwrap_or_default();
            match serde_json::from_str::<crate::notify::Target>(&raw) {
                Err(e) => json!({"status": false, "error": format!("bad target: {e}")}),
                Ok(mut t) => {
                    // The token is never handed back to the
                    // UI, so an unchanged row tests with a
                    // blank one. Borrow the stored token for
                    // the matching target, exactly as
                    // server_test borrows a saved password.
                    if (t.token.is_empty() || t.secret.is_empty())
                        && let Some(prev) = d
                            .notify_targets
                            .lock_ok()
                            .iter()
                            .find(|p| p.kind == t.kind && p.url == t.url && p.name == t.name)
                    {
                        if t.token.is_empty() {
                            t.token = prev.token.clone();
                        }
                        // §129 4a: the signing secret rides the same
                        // blank-means-keep rule as the token.
                        if t.secret.is_empty() {
                            t.secret = prev.secret.clone();
                        }
                    }
                    // §G: a Test IS a delivery, so it updates the
                    // row's last-send line too. Without this a user
                    // who fixed a token and tested it successfully
                    // still had a red "last send failed" sitting on
                    // the row until the next download finished.
                    let r = crate::notify::test(&t);
                    d.notify_health.lock_ok().insert(
                        crate::notify::target_key(&t),
                        crate::notify::Outcome {
                            at: unix_now(),
                            code: *r.as_ref().unwrap_or(&0),
                            error: r.as_ref().err().cloned().unwrap_or_default(),
                            test: true,
                        },
                    );
                    match r {
                        Ok(code) => json!({"status": true, "code": code}),
                        Err(e) => json!({"status": false, "error": e}),
                    }
                }
            }
        }
    })
}

/// SAB's `status["servers"]` - one object per CONFIGURED server, with
/// the running job's own gauges laid over it.
///
/// Empty until 31 Aug 2026, on an install with two servers configured
/// and downloading, so a SAB remote app's Servers pane was permanently
/// blank on a working daemon. Type-correct, which is the only reason it
/// was not one of the five crash shapes fixed beside it, but it is GH
/// #69 finding 3's defect one mode over: a configured server absent
/// from a payload that is about servers.
///
/// THE LIST COMES FROM THE CONFIG AND THE LIVE POOL ONLY DECORATES IT,
/// and getting that backwards is finding 3's mistake made a second
/// time. `hub.pool_live` belongs to the ACTIVE RUN and does not exist
/// between jobs, so a list built FROM it answers `[]` again the moment
/// nothing is downloading - which is most of the time, and is exactly
/// when somebody opens the pane to find out why. A configured server
/// that has never been dialled is still a configured server; it reports
/// zero connections and no throughput, which is true, rather than
/// vanishing.
///
/// ROWS ARE MATCHED BY `row_key`, NEVER BY HOSTNAME. Two accounts on
/// one provider are supported and tested - a flat-rate account plus a
/// small block fill at the same host is the ordinary shape - so a map
/// keyed by host ALIASES them and hands one row's connections to the
/// other. `nzbkit::pool::row_keys` carries the whole argument. The keys
/// are minted here over the ENABLED servers because that is the list
/// `get/plan.rs` hands the fleet build, which is what `LiveStats::
/// for_servers` keyed the live rows from; `serve/tasks/tuner.rs` mints
/// them the same way for the same reason. A row that fails to match -
/// the config was edited under a running job, or a host was excluded
/// for it - simply gets the idle answer, which is the safe direction.
///
/// WITHHELD FROM THE ADD-ONLY TIER, which is a decision about the tier
/// and not about the shape. `status` and `fullstatus` are on that key's
/// allowlist so a push extension's "test connection" button works, and
/// its stated promise is a version string, paused/warning/disk numbers
/// and the category names. A list of the user's provider hostnames is
/// none of those. Our own tree answers the wider question both ways -
/// `out_dir_for` above blanks the download path for this tier, while
/// `sab_warnings` deliberately DOES name an exhausted provider's host
/// to it, with a stated reason - so there is no house rule to appeal
/// to, and whether the tier may see hostnames is J4 of
/// `research/SAB-MODE-SHAPE-AUDIT-2026-08-31.md` - a product decision,
/// deliberately left open. Today's `[]` is what that tier already gets,
/// so filling the array for full-key callers changes nothing it can see. `daemon_facade` pins the empty
/// answer so that whichever way J4 is settled, the change is deliberate
/// and shows up in a diff.
fn sab_servers(d: &Daemon, ctx: &ApiCtx<'_>) -> Vec<Value> {
    if ctx.via_add_only {
        return Vec::new();
    }
    // An unreadable config is an empty server list here, the same way
    // `sab_warnings` treats it: either way there is nothing to report.
    let Ok(cfg) = nzbkit::config::Config::load(ctx.cfg_path) else {
        return Vec::new();
    };

    /// What the running job's fleet says about one configured row.
    struct Live {
        connected: u64,
        bps: Option<f64>,
        warning: String,
        error: String,
    }
    // Everything copied out under the pool's lock and rendered after,
    // the discipline `serve/metrics.rs::server_metrics` records: these
    // gauges are written by the fetch path, so the shorter the hold the
    // better.
    let live: std::collections::HashMap<String, Live> = d
        .hub
        .pool_live
        .lock_ok()
        .as_ref()
        .map(|l| {
            l.servers
                .iter()
                // A hand-built `ServerLive` (the ring rigs use
                // `..Default::default()`) carries no key. It can never
                // equal a minted `N#host`, and two of them would
                // collide with each other, so drop them rather than
                // letting one decorate an unrelated row.
                .filter(|s| !s.row_key.is_empty())
                .map(|s| {
                    // SAB's two strings for "this server is not well",
                    // mapped onto its own split: `errormsg` is set when
                    // the server is out of action, `warning` for the
                    // transient case. A PERMANENT auth refusal is a
                    // credential only the user can fix, so it is the
                    // error; a live outage - unreachable, at capacity,
                    // or a refusal that retrying may clear - is the
                    // warning. Both are the provider's or the OS's own
                    // words, never our paraphrase, for the reason
                    // `ServerLive::refusal` gives at its own site.
                    let refusal = s.refusal.lock_ok().clone();
                    let error = refusal
                        .as_ref()
                        .filter(|r| r.permanent)
                        .map(|r| r.line.clone())
                        .unwrap_or_default();
                    // Gated on `down_secs()` as well as the reason,
                    // the way `outage::outages_in` gates it: the
                    // reason outlives the episode it described. And
                    // EXCLUSIVE with the error above - a permanent
                    // refusal raises a refusal record AND a `refused`
                    // outage carrying the same sentence, so filling
                    // both fields would just print the provider's line
                    // to the user twice.
                    let warning = if error.is_empty() {
                        s.down_secs()
                            .and_then(|_| s.down_reason.lock_ok().clone())
                            .map(|r| r.detail)
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    (
                        s.row_key.clone(),
                        Live {
                            connected: s.connected.load(Ordering::Relaxed) as u64,
                            bps: s.srv_rate_bps(),
                            warning,
                            error,
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let enabled: Vec<usize> = cfg
        .servers
        .iter()
        .enumerate()
        .filter(|(_, s)| s.enabled)
        .map(|(i, _)| i)
        .collect();
    let keys = nzbkit::pool::row_keys(enabled.iter().map(|&i| cfg.servers[i].host.as_str()));
    let mut key_of: Vec<Option<&str>> = vec![None; cfg.servers.len()];
    for (k, &i) in keys.iter().zip(&enabled) {
        key_of[i] = Some(k.as_str());
    }

    cfg.servers
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let l = key_of[i].and_then(|k| live.get(k));
            json!({
                // SAB's `displayname`, which defaults to the host and is
                // the only name a server has here.
                "servername": s.host,
                // SAB's `active` is false once it has taken a server out
                // of the pool. A switched-off server stays configured
                // and testable and never joins one, which is the same
                // statement. Block-exhausted and job-excluded hosts are
                // deliberately NOT folded in: `get/plan.rs`'s exclusion
                // list carries three reasons and one of them is "busy
                // with the active job", so reading it here would paint a
                // perfectly healthy provider as deactivated. That
                // condition reaches the user through `mode=warnings`,
                // which names the host and says what to do about it.
                "serveractive": s.enabled,
                "serveractiveconn": l.map(|l| l.connected).unwrap_or(0),
                // SAB's `threads` is the CONFIGURED count, not the live
                // one - `serveractiveconn` beside it is the live half -
                // so this stays the configured number even mid-run,
                // where the tuner may be holding fewer.
                "servertotalconn": s.connections,
                // One entry per busy thread, each naming the article and
                // job it is on. The pool keeps no per-worker article
                // attribution to publish, and inventing rows would be
                // worse than the empty list SAB itself sends for a
                // server with nothing in flight.
                "serverconnections": [],
                "serverssl": s.tls,
                // SAB fills this with the negotiated protocol and cipher
                // once a session exists and leaves it `""` until then -
                // an empty STRING, not null, which is the shape a client
                // declaring a non-nullable field needs. We do not
                // publish a per-server cipher, so it is always the
                // before-connection value.
                "serversslinfo": "",
                // Null in SAB too until a connection exists and the
                // address has been resolved. We keep no per-server
                // resolved address to publish, so it stays null - which
                // is a value SAB sends routinely and clients handle,
                // rather than an invented address.
                "serveripaddress": Value::Null,
                "servercanonname": Value::Null,
                "serverwarning": l.map(|l| l.warning.clone()).unwrap_or_default(),
                "servererror": l.map(|l| l.error.clone()).unwrap_or_default(),
                // Same convention as SAB's: 0 is the primary and a
                // higher number is consulted later. `level` is that
                // number here (M14e, NZBGet's "Level").
                "serverpriority": s.level,
                // SAB's per-server "deactivate this one when it
                // misbehaves" flag, which is off by default there. No
                // server here carries such a flag - a provider granting
                // nothing is routed around and reported, never
                // deactivated - so `false` is the true answer and is
                // also what a default SAB install sends.
                "serveroptional": false,
                // A STRING, through SAB's `to_units` with no postfix
                // ("0", "417 K", "1.4 M"), not a number. `sab_units` is
                // the port; see its own doc for the three ways the
                // hand-rolled version of this format was wrong.
                //
                // The windowed delivered rate, decayed to now, which is
                // the quantity SAB's `BPSMeter.server_bps` holds. Zero
                // with no run on the wire, and zero for a configured
                // server this run has never asked for a body.
                "serverbps": sab_units(l.and_then(|l| l.bps).unwrap_or(0.0)),
            })
        })
        .collect()
}

/// The body BOTH `mode=status` and `mode=fullstatus` answer with.
///
/// SAB maps both mode names to the SAME function - `_api_table` has
/// `("fullstatus", "")` and `("status", "")` both pointing at
/// `_api_fullstatus` - so a client is entitled to read either and find
/// the same object. We had two arms with two DIFFERENT key sets, each
/// missing keys the other carried: `fullstatus` had no `warnings`,
/// `have_warnings`, `pause_int`, `cache_art`, `cache_size`,
/// `finishaction`, `servers` or `diskspace1_norm`, and `status` had no
/// `diskspace2` or `speedlimit`. Each hole is GH #69's absent-key half
/// - a statically-typed client dies on a missing non-nullable field -
/// and which hole you met depended only on which of two spellings your
/// client happened to send. NZB Donkey probes `mode=status` and NZB
/// Unity probes `mode=fullstatus` (`serve/http.rs`), so both spellings
/// have real callers.
///
/// The key set is SAB's `build_header` API half in full, plus
/// `warnings` and `servers` from `build_status`, plus our two
/// `complete_dir` spellings. That boundary is deliberate: the rest of
/// `build_status` is measurements this daemon does not take (pystone,
/// disk and internet speed probes), machine facts a remote app does not
/// render (socks5 proxy, public IPv4/IPv6, dnslookup), and paths we
/// decline to volunteer (logfile, configfn, webdir). Answering those
/// with invented zeros would be worse than the absence, because unlike
/// the header fields below there is no value that is TRUE of us.
///
/// `unlimited_abs_as_empty` is the one field the two arms still spell
/// differently, and it is a deliberate deviation from SAB rather than an
/// oversight - see the `fullstatus` arm. It is a parameter so that the
/// divergence is one named argument rather than two whole payloads.
fn sab_status_body(d: &Arc<Daemon>, ctx: &ApiCtx<'_>, unlimited_abs_as_empty: bool) -> Value {
    // §91: one statvfs feeds both the low-disk warning's own sentence
    // and the `diskspace1` figure beside it.
    let (_, total_b) = disk_stat_walk(&d.out_dir()).unwrap_or((0, 0));
    let free_now = free_bytes(&d.out_dir());
    let warns = sab_warnings(d, ctx.cfg_path, ctx.via_add_only, free_now);
    let free = free_now.unwrap_or(0) as f64 / 1e9;
    let total = total_b as f64 / 1e9;
    let line = d.line_speed.load(Ordering::Relaxed);
    let abs = d.hub.rate.get();
    json!({"status": {
        // SAB's is `calc_age(START)` - a "2d"/"5h"/"13m" token, never a
        // bare count. This answered a literal "0" until 31 Aug 2026,
        // which is not a value that vocabulary can produce.
        "uptime": sab_elapsed(d.boot_at.elapsed().as_secs() as i64),
        "color_scheme": "",
        "version": SAB_VERSION,
        "paused": d.paused.load(Ordering::Relaxed),
        // One pause switch here, where SAB has a second global for
        // "paused including post-processing". Mirroring `paused` is the
        // true answer for a daemon with one, and absent was the wrong
        // one.
        "paused_all": d.paused.load(Ordering::Relaxed),
        "pause_int": pause_int(d),
        "have_warnings": warns.len().to_string(),
        "warnings": warns,
        // One filesystem serves both of SAB's disks here.
        "diskspace1": format!("{free:.2}"),
        "diskspace2": format!("{free:.2}"),
        // `sab_units` over the RAW byte count, exactly as the queue
        // header does - GH #69's own fix, which was applied to the queue
        // path and left behind here (read-only sweep finding 12, 31 Aug
        // 2026). `format!("{free:.1} G")` over a GB figure prints
        // "2000.0 G" for the 2 TB the queue calls "1.8 T", so one daemon
        // reported two different disk figures to a client that reads
        // `mode=status` rather than the queue header.
        "diskspace1_norm": sab_units(free_now.unwrap_or(0) as f64),
        "diskspace2_norm": sab_units(free_now.unwrap_or(0) as f64),
        "diskspacetotal1": format!("{total:.2}"),
        "diskspacetotal2": format!("{total:.2}"),
        // Percentage of the line speed, "0" when either half is
        // unknown - the queue body's convention.
        "speedlimit": if line > 0 && abs > 0 {
            format!("{}", (abs as f64 * 100.0 / line as f64).round() as u64)
        } else {
            "0".to_string()
        },
        "speedlimit_abs": if unlimited_abs_as_empty && abs == 0 {
            String::new()
        } else {
            abs.to_string()
        },
        // Withheld from the add-only tier: config.rs already refuses to
        // "volunteer its filesystem layout to every API caller", and a
        // push extension needs the numbers, not the path.
        "complete_dir": out_dir_for(d, ctx),
        "completedir": out_dir_for(d, ctx),
        "cache_art": "0",
        "cache_size": "0 B",
        "finishaction": Value::Null,
        // No download quota here, so these are exactly what SAB reports
        // for an install with none configured - not placeholders.
        "quota": "0 B",
        "have_quota": false,
        "left_quota": "0 B",
        "servers": sab_servers(d, ctx),
    }})
}

fn m_status(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(sab_status_body(d, ctx, false))
}

fn m_shutdown(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        if req.method() != &tiny_http::Method::Post {
            json!({"status": false, "error": "POST required"})
        } else {
            // Same wind-down SIGTERM now takes (issue #13) -
            // this path used to exit without closing the
            // provider's sessions either, it just did it
            // where nobody was measuring.
            let d = d.clone();
            let rt = tokio::runtime::Handle::current();
            std::thread::spawn(move || {
                // Let the JSON answer reach the caller first.
                std::thread::sleep(std::time::Duration::from_millis(500));
                wind_down_and_exit(&d, &rt, "api shutdown");
            });
            json!({"status": true})
        }
    })
}

fn m_restart_daemon(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        if req.method() != &tiny_http::Method::Post {
            json!({"status": false, "error": "POST required"})
        } else if !cfg!(unix) {
            json!({"status": false, "error": "restart-unsupported"})
        } else {
            // Capture the command line BEFORE anything else: on
            // failure we have to be able to say what we tried.
            let exe = std::env::current_exe().ok();
            let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
            let cwd = std::env::current_dir().ok();
            match exe {
                None => json!({
                    "status": false,
                    "error": "could not find our own executable",
                }),
                Some(exe) => {
                    let d = d.clone();
                    let rt = tokio::runtime::Handle::current();
                    std::thread::spawn(move || {
                        // Let the JSON answer reach the browser
                        // before the process image is replaced.
                        std::thread::sleep(std::time::Duration::from_millis(400));
                        // Sockets are CLOEXEC, so exec drops
                        // every provider session as abruptly
                        // as a kill does - and the replacement
                        // process then reopens the pool into an
                        // account that still counts them
                        // (issue #13). Hand them back first -
                        // but never at the cost of the restart
                        // itself, so a failure here still
                        // re-execs.
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            wind_down(&d, &rt, "api restart")
                        }));
                        restart_in_place(&exe, &args, cwd.as_deref());
                    });
                    json!({"status": true})
                }
            }
        }
    })
}

fn m_sysbench(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    _params: &std::collections::HashMap<String, String>,
    ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        // Single-flight (Codex sweep 10 Aug M14): a second tab, or a
        // manual run coinciding with the schedule, ran the workload
        // concurrently - the runs distorted each other's numbers and
        // doubled the compute/disk/provider traffic.
        let Some(_running) = d.bench_begin() else {
            return Some(json!({
                "status": false,
                "error": "a system benchmark is already running - wait for it to finish",
            }));
        };
        let now = epoch_secs();
        match measure_system(d, ctx.cfg_path, &tokio::runtime::Handle::current()) {
            Err(e) => {
                d.bench_append(json!({"ts": now, "source": "manual", "error": e.clone()}));
                json!({"status": false, "error": e})
            }
            Ok(v) => {
                d.bench_last.store(now, Ordering::Relaxed);
                d.bench_append(json!({
                    "ts": now, "source": "manual",
                    // See the scheduled twin in tasks.rs: history rows are
                    // only comparable when the probed set matches.
                    "network_host": v.network_host,
                    "network_conns": v.network_conns,
                    "network_gbps": v.network_gbps,
                    "compute_gbps": v.compute_gbps,
                    "disk_gbps": v.disk_gbps,
                    "expected_gbps": v.expected_gbps,
                    "bottleneck": v.bottleneck,
                }));
                serde_json::to_value(&v).unwrap_or(json!({"status": false}))
            }
        }
    })
}

pub(in crate::serve) fn dispatch(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    mode: &str,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(match mode {
        // `version` stays the SAB-compat string (the *arrs
        // feature-gate on it); `nzbfast` is our real release
        // version, which is what the UI shows. `beta` is the
        // between-releases build serial (build.rs, from
        // packaging/beta-serial.txt) - "" on a real release.
        // KEPT OUT of `nzbfast` itself: the update check and
        // every wrapper parse that field as a bare semver.
        "version" => return m_version(d, req, params, ctx, api_body),
        // §36: does parking connections help THIS server's link?
        // Measures time-to-usable-connection fresh vs claimed,
        // paired and alternated, and reports the interval that
        // decided it. Inconclusive resolves to OFF - a link we
        // cannot separate is one where the pool earns nothing.
        // Benchmarking whole downloads was tried and abandoned:
        // 60 paired reps over two hours on a real link still
        // could not separate the arms.
        "warm_bench" => return m_warm_bench(d, req, params, ctx, api_body),
        // In-UI log viewer: last N captured stdout/stderr lines.
        //
        // The self-tee works by dup2-ing our own stdout and stderr onto a
        // pipe, which is a unix fd trick with no equivalent here off
        // unix - so on Windows the ring has ALWAYS been empty and this
        // panel has never shown a Windows user anything but "log capture
        // is not available on this platform" (tester report, 4 Aug).
        //
        // Meanwhile the very same output has been on their disk the whole
        // time: the tray launcher spawns the daemon with both streams
        // appended to daemon.log in the data folder, and rotates it at
        // 5 MB. So when the ring has nothing, read that instead. The
        // fallback is keyed on the ring being EMPTY rather than on
        // cfg(windows) - a unix daemon whose pipe() failed at startup is
        // in exactly the same position, and would rather show the file
        // than nothing.
        "log" => return m_log(d, req, params, ctx, api_body),
        // "Create report": one download's facts and its own log span,
        // as text to paste into a bug report. `mode=log` next door
        // hands over the daemon's whole ring, which is the thing this
        // exists to avoid asking people for.
        "report" => {
            let id = params.get("value").map(String::as_str).unwrap_or("");
            match d.job_report(id) {
                Some(text) => json!({"status": true, "report": text}),
                None => json!({"status": false, "error": "no such job"}),
            }
        }
        // M18b: per-provider data-usage history (UTC days), plus the
        // prepaid-block standings a client needs to render the same
        // balance the dashboard does.
        //
        // `blocks` is FROM OUR OWN ACCOUNTING and carries no
        // provider-reported figure - the design's section 3 rules that
        // out, and a client must not add one on top either. `band` is
        // the daemon's answer to "is this one low", so the page never
        // re-derives the 85% threshold; an empty array is the normal
        // case (nobody has bought a block).
        //
        // Design: research/BLOCK-ACCOUNT-ECONOMICS-2026-08-27.md § 5.
        "usage" => {
            let blocks: Vec<Value> = nzbkit::config::Config::load(ctx.cfg_path)
                .map(|c| {
                    d.block_standings(&c)
                        .into_iter()
                        .map(|b| {
                            json!({
                                "host": b.host,
                                "enabled": b.enabled,
                                "block_bytes": b.total,
                                "block_used": b.spent,
                                "block_left": b.left,
                                "pct": b.pct(),
                                "band": b.band_word(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            // ...and the 30-day provider-quality roll-up beside them.
            // On THIS mode rather than a door of its own: the card that
            // renders it is the per-provider card this payload already
            // feeds, so the section costs no second poll, and the
            // arithmetic lives in exactly one place either way
            // (`provquality::report`). It reads only the quality
            // ledger's own mutex - no index door, TODO 166.
            json!({"days": Value::Object(d.usage.lock_ok().clone()), "blocks": blocks,
                   "quality": d.provquality.report_json(crate::serve::unix_now())})
        }
        // Reveal a configured folder in the OS file manager, for
        // the 📂 buttons beside the path settings.
        //
        // Resolved by KEY from our own config - deliberately never
        // from a path supplied by the caller, which would make this
        // an open-anything-on-the-host endpoint. `script` is a file,
        // so its containing folder is opened.
        "open_dir" => return m_open_dir(d, req, params, ctx, api_body),
        // Directory browser for the path settings - so the download
        // folder (or watch folder, script, index db) can be picked
        // off ANY mounted drive without typing a path.
        //
        // Unlike `open_dir`, this necessarily takes a caller-supplied
        // path, so it is deliberately kept READ-ONLY: it returns only
        // entry NAMES and a dir/file flag - never file contents, sizes
        // or anything else - and it is behind the full API key (the
        // whole `body` match is). The only write it permits is
        // `fs_mkdir` (one new subfolder), which the download-setup
        // flow needs. That is the same trust level the dashboard
        // already has (it can set the download dir to any path and
        // run post-processing scripts).
        "fs_list" => return m_fs_list(d, req, params, ctx, api_body),
        // Create ONE subfolder under an existing directory (the "New
        // folder" button - needed to make a downloads dir on a fresh
        // drive). Name is a single component; separators and ".." are
        // rejected so it can never escape the parent.
        "fs_mkdir" => return m_fs_mkdir(d, req, params, ctx, api_body),
        // M22: near-automatic phone access - every address this
        // daemon answers on, for the Remote access card + QRs.
        "remote_info" => return m_remote_info(d, req, params, ctx, api_body),
        // QR for any of the above (SVG, currentColor).
        "qr" => return m_qr(d, req, params, ctx, api_body),
        // Fire one notification target now, so a wrong token or
        // a typo'd port is found here rather than by a library
        // that quietly never rescans. Takes the row being edited,
        // NOT the saved list - the point is to try it before
        // saving it.
        //
        // POST-only, like `shutdown`: it sends a request the
        // caller chose to a URL the caller chose and hands back
        // the status plus the remote's error body, which is a
        // usable port scanner if any page you visit can fire it
        // with an <img> or a link prefetch. The echoed body stays
        // - a Discord or ntfy 400 explains itself only in its
        // body, and the caller already holds the API key.
        "notify_test" => return m_notify_test(d, req, params, ctx, api_body),
        // SAB remote-app surface: harmless acks + real stats.
        //
        // This used to be a permanent `[]`, so the conditions a
        // user most needs to see - no server configured, the
        // queue held on low disk, a job sitting waiting for a
        // password - were invisible to every client that has a
        // warnings pane, which is all of them.
        "warnings" => json!({
            "warnings": sab_warnings(d, ctx.cfg_path, ctx.via_add_only, free_bytes(&d.out_dir()))
        }),
        // What the mobile remotes poll instead of `fullstatus`.
        // Same numbers, plus the warning count they badge.
        "status" => return m_status(d, req, params, ctx, api_body),
        // SAB's own mode=restart restarts SABnzbd. We ack it and do
        // NOTHING: Sonarr, Radarr and the SAB remote apps call it,
        // and bouncing the daemon underneath them is not what any of
        // them mean by it. Our real restart is mode=restart_daemon,
        // deliberately a name no SAB client will ever send.
        "restart" => json!({"status": true}),
        // Real shutdown (the native wrappers' clean-quit path):
        // persist the queue, park in-flight transfers (they resume
        // from the journal on next start), ack, then exit once the
        // response has flushed. POST-only so a stray GET (link
        // prefetch, curl tab-complete) can't kill the daemon.
        "shutdown" => return m_shutdown(d, req, params, ctx, api_body),
        // Restart in place: persist, then replace this process with
        // a fresh copy of the same command line.
        //
        // Worth having because the settings UI says "applies after
        // restart" in several places and, until now, offered no way
        // to do that short of a terminal.
        //
        // Unix only, and deliberately so. `exec` replaces the
        // process image, which is the one restart that cannot race
        // itself for the listening port - a spawn-then-exit would
        // have the new process trying to bind while the old one
        // still holds it. Windows has no exec; its tray already has
        // a Restart item, and the honest answer is better than a
        // button that half works.
        "restart_daemon" => return m_restart_daemon(d, req, params, ctx, api_body),
        // SAB answers `fullstatus` and `status` from the SAME function
        // (`_api_fullstatus`, reached under both names in its
        // `_api_table`), so both spellings answer the same body here -
        // see `sab_status_body`, which also records what the two arms
        // used to be missing from each other.
        //
        // §18: LunaSea's statistics page reads the two speed caps and
        // both disks out of fullstatus, and its parser routes each
        // through Dart's tryParse - which takes a String - so a missing
        // key OR a JSON number throws and the page errors. Strings, as
        // real SAB sends them.
        //
        // The `true` is the one field this arm still spells differently
        // from `mode=status`: "" is SAB's "no cap set" as LunaSea reads
        // it, and it shows that as unlimited where SAB's own literal
        // "0" would read as a 0 B/s cap. A deliberate deviation with a
        // named client behind it - and `mode=status` keeps "0" because
        // the queue payload sends "0" and three integration suites pin
        // that. Unifying the two on either spelling is a judgement about
        // what live clients do with the value, not about the shape, so
        // it is deliberately NOT taken here: it stays one named argument
        // rather than two whole payloads until somebody measures it.
        "fullstatus" => sab_status_body(d, ctx, true),
        "sysbench" => return m_sysbench(d, req, params, ctx, api_body),
        // Update checker: force a check now. Notify-only - there
        // is no apply/install path; the banner links to the
        // download page.
        "update_check" => match check_update(d) {
            Err(e) => json!({"status": false, "error": e}),
            Ok(m) => json!({
                "status": true,
                "current": env!("CARGO_PKG_VERSION"),
                "available": m.as_ref().and_then(|v| v.get("version")).cloned(),
                "manifest": m,
            }),
        },
        // Scheduled-benchmark history (manual + scheduled runs).
        "bench_history" => json!({
            "history": d.bench_history(),
            "interval": d.bench_interval.load(Ordering::Relaxed),
            "last": d.bench_last.load(Ordering::Relaxed),
        }),
        _ => return None,
    })
}

/// The instrument-first perf counters, as one stats-payload object.
///
/// These exist to answer optimization questions with evidence rather than
/// with a guess, and neither has an implementation behind it yet:
///
/// - `crc_reuse` - what share of verified bytes an article's already-
///   verified yEnc CRC32 could be reused for, which decides whether
///   plumbing that CRC into block verification is worth doing at all.
/// - `filename_fallback` - how much real traffic the unindexed filename
///   scan in the NZBLNK header ladder takes, and what it costs, which
///   decides whether a dedicated filename index earns its ingest writes.
///
/// Process-lifetime figures, alongside `nested_prevalence`. They live
/// here rather than inline in the stats arm because that arm's file is
/// one line under its size ceiling.
pub(super) fn instrument_counters() -> Value {
    let g = nzbkit::live::crc_reuse_geometry_total();
    let crc_reuse = json!({
        "spans": g.spans,
        "spans_bytes": g.spans_bytes,
        "qualifying": g.qualifying,
        "qualifying_bytes": g.qualifying_bytes,
    });
    #[cfg(feature = "indexer")]
    let filename_fallback = {
        let f = nzbkit::index::filename_fallback_stats();
        json!({
            "calls": f.calls,
            "hits": f.hits,
            "misses": f.misses,
            "hit_ms": f.hit_nanos / 1_000_000,
            "miss_ms": f.miss_nanos / 1_000_000,
        })
    };
    #[cfg(not(feature = "indexer"))]
    let filename_fallback = Value::Null;
    // Memory-floor gauges (instrument-first, memgauge.rs): per-subsystem
    // current/peak bytes plus the gauge snapshot taken at the sampled RSS
    // high-water. The CLI prints the same record as the mem-floor lines.
    // The record is per job (F-19): `at_peak` reports the NEWEST job's,
    // the one whose download is (or was last) running, and `jobs` adds
    // a row per live job so an older job whose tail overlaps it - the
    // one holding the repair high-water - is reachable here too.
    let mem_floor = mem_floor_json(nzbkit::memgauge::peak_attribution());
    json!({
        "crc_reuse": crc_reuse,
        "filename_fallback": filename_fallback,
        "mem_floor": mem_floor,
    })
}

/// The `mem_floor` object: every live gauge, `at_peak` (the newest job's
/// sampled RSS high-water, null until a job has sampled once), `jobs`,
/// one row per job whose sampler is still alive, and `recent`, the last
/// few FINISHED jobs.
///
/// `jobs` exists because `at_peak` can only name one job and the daemon
/// routinely runs two: job B's download overlaps job A's repair tail, so
/// the record `at_peak` follows is B's while the high-water worth
/// reading is A's. A's own summary prints it (get/tail.rs
/// `print_mem_floor`); before this it was reachable nowhere else.
/// `at_peak` keeps its exact previous shape and meaning - the CLI and
/// every existing reader are untouched - and `jobs` is empty between
/// jobs, when `at_peak` still answers with the last one.
///
/// `recent` covers what neither of those does (TODO 224): a poll that
/// arrives AFTER a job's sampler retired. `at_peak` by then names the
/// next job, and A's row has left `jobs`, so a repair that peaked at
/// 900 MB and finished four seconds before the poll was invisible. Rows
/// carry the same `{label, at_peak}` shape as `jobs`, oldest first, and
/// the ring is capped in memgauge - a separate key on purpose, so
/// neither existing key changes meaning.
fn mem_floor_json(at_peak: Option<nzbkit::memgauge::PeakAttribution>) -> Value {
    let names = [
        nzbkit::memgauge::Sub::RawFree,
        nzbkit::memgauge::Sub::RawOut,
        nzbkit::memgauge::Sub::OutFree,
        nzbkit::memgauge::Sub::OutOut,
        nzbkit::memgauge::Sub::Channel,
        nzbkit::memgauge::Sub::WireEst,
        nzbkit::memgauge::Sub::Par2Capture,
        nzbkit::memgauge::Sub::JobMeta,
        nzbkit::memgauge::Sub::VerifierMeta,
        nzbkit::memgauge::Sub::Holds,
        nzbkit::memgauge::Sub::RepairScan,
        nzbkit::memgauge::Sub::RepairWork,
    ];
    let gauges = gauges_json(&nzbkit::memgauge::snapshot(), &names);
    let job_rows = |jobs: Vec<nzbkit::memgauge::JobPeak>| -> Vec<Value> {
        jobs.into_iter()
            .map(|j| json!({"label": j.label, "at_peak": at_peak_json(j.at_peak, &names)}))
            .collect()
    };
    json!({
        "gauges": gauges,
        "at_peak": at_peak_json(at_peak, &names),
        "jobs": job_rows(nzbkit::memgauge::live_peak_attributions()),
        "recent": job_rows(nzbkit::memgauge::recent_peak_attributions()),
    })
}

/// One sampled high-water as JSON, null when the job has not yet
/// completed a sampler tick. Shared by `mem_floor.at_peak` and every
/// `mem_floor.jobs[].at_peak`, so the two can never drift apart.
fn at_peak_json(
    at_peak: Option<nzbkit::memgauge::PeakAttribution>,
    names: &[nzbkit::memgauge::Sub],
) -> Value {
    let Some(p) = at_peak else {
        return Value::Null;
    };
    json!({
        "rss": p.rss,
        "footprint": p.footprint,
        "retained": p.rss.saturating_sub(p.footprint),
        // The snapshot the record exists to carry: what every gauge
        // held AT the high-water (bug sweep 22 Aug 2026, F-20 - it used
        // to be dropped, leaving only the live gauges above, which by
        // the time of the poll say nothing about the peak).
        "gauges": gauges_json(&p.gauges, names),
        "unattributed": p.footprint.saturating_sub(attributed_sum(&p.gauges)),
    })
}

/// One `{name: {cur, peak}}` object per gauge, for the live snapshot and
/// the at-peak record alike.
fn gauges_json(
    g: &nzbkit::memgauge::MemGauges,
    names: &[nzbkit::memgauge::Sub],
) -> serde_json::Map<String, Value> {
    names
        .iter()
        .map(|&s| {
            (
                s.name().to_string(),
                json!({"cur": g.cur_of(s), "peak": g.peak_of(s)}),
            )
        })
        .collect()
}

/// The summed attributable gauges, the same list the CLI's mem-floor
/// block sums (get/tail.rs `print_mem_floor`): `channel` is a subset of
/// raw outstanding and `wire est` overlaps the raw pool, so both are
/// excluded from the sum and shown for comparison only.
fn attributed_sum(g: &nzbkit::memgauge::MemGauges) -> u64 {
    use nzbkit::memgauge::Sub;
    [
        Sub::RawFree,
        Sub::RawOut,
        Sub::OutFree,
        Sub::OutOut,
        Sub::Par2Capture,
        Sub::JobMeta,
        Sub::VerifierMeta,
        Sub::Holds,
        Sub::RepairScan,
        Sub::RepairWork,
    ]
    .into_iter()
    .map(|s| g.cur_of(s))
    .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bug sweep 22 Aug 2026, F-20: the at-peak record carries the gauge
    /// snapshot, not just the three RSS figures. Fed a job-owned record
    /// (F-19) rather than the process-wide reader, so no other test's
    /// sampler can swap the record out from under it.
    #[test]
    fn mem_floor_at_peak_carries_the_gauge_snapshot() {
        use nzbkit::memgauge::{self, PeakRecord, Sub};
        memgauge::add(Sub::Holds, 4096);
        let record = PeakRecord::new();
        record.note_rss_sample();
        let v = json!({"mem_floor": mem_floor_json(record.peak_attribution())});
        let at = &v["mem_floor"]["at_peak"];
        assert!(at.is_object(), "one sample is a peak: {v}");
        assert!(
            at["gauges"]["holds"]["cur"].as_u64().is_some(),
            "at_peak.gauges.holds.cur present: {at}"
        );
        assert!(at["unattributed"].as_u64().is_some());
        memgauge::sub(Sub::Holds, 4096);
    }

    /// The per-job view: a job whose sampler is live shows up in
    /// `mem_floor.jobs` under its label, carrying the same `at_peak`
    /// shape as the top-level one - which itself is untouched.
    #[test]
    fn mem_floor_jobs_lists_each_live_job() {
        use nzbkit::memgauge::{self, PeakRecord};
        let record = std::sync::Arc::new(PeakRecord::new());
        record.note_rss_sample();
        memgauge::register_peak_record(4242, "nzo_sys_test", &record);
        let v = mem_floor_json(None);
        assert!(v["at_peak"].is_null(), "the top-level record is unchanged");
        let row = v["jobs"]
            .as_array()
            .expect("jobs is an array")
            .iter()
            .find(|j| j["label"] == "nzo_sys_test")
            .cloned()
            .unwrap_or_else(|| panic!("the live job is listed: {v}"));
        assert!(
            row["at_peak"]["gauges"]["holds"]["cur"].as_u64().is_some(),
            "a job row carries the full at_peak shape: {row}"
        );
        memgauge::unregister_peak_record(4242);
    }

    /// TODO 224: a job that has FINISHED is still readable, under
    /// `recent` rather than `jobs`, so a poll arriving after the tail
    /// can still correlate a high-water with the job id that made it.
    #[test]
    fn mem_floor_recent_keeps_finished_jobs() {
        use nzbkit::memgauge::{self, PeakRecord};
        let record = std::sync::Arc::new(PeakRecord::new());
        record.note_rss_sample();
        memgauge::register_peak_record(4243, "nzo_sys_recent", &record);
        memgauge::unregister_peak_record(4243);
        drop(record);
        let v = mem_floor_json(None);
        assert!(
            !v["jobs"]
                .as_array()
                .expect("jobs is an array")
                .iter()
                .any(|j| j["label"] == "nzo_sys_recent"),
            "the finished job is no longer running: {v}"
        );
        let row = v["recent"]
            .as_array()
            .expect("recent is an array")
            .iter()
            .find(|j| j["label"] == "nzo_sys_recent")
            .cloned()
            .unwrap_or_else(|| panic!("the finished job is remembered: {v}"));
        assert!(
            row["at_peak"]["gauges"]["holds"]["cur"].as_u64().is_some(),
            "a recent row carries the full at_peak shape: {row}"
        );
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("nzbfast-logtail-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-logdir-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The Windows case, reproduced here: no tee, so an empty ring and
    /// `active` false - but daemon.log is sitting beside the config
    /// where the launcher has been appending to it all along. The panel
    /// must show that file and stop claiming there is no log.
    #[test]
    fn an_empty_ring_falls_back_to_the_log_file() {
        let d = tmpdir("fallback");
        std::fs::write(d.join("daemon.log"), b"started\nlistening\n").unwrap();
        let (lines, capturing) = log_payload(200, Vec::new(), false, Some(d.as_path()));
        assert_eq!(lines, vec!["started".to_string(), "listening".to_string()]);
        assert!(capturing, "a readable log file means a log CAN be shown");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A file that exists but is quiet is "nothing logged yet", not "no
    /// log capture on this platform" - the whole point of the flag.
    #[test]
    fn an_empty_log_file_still_counts_as_capturing() {
        let d = tmpdir("quiet");
        std::fs::write(d.join("daemon.log"), b"").unwrap();
        let (lines, capturing) = log_payload(200, Vec::new(), false, Some(d.as_path()));
        assert!(lines.is_empty());
        assert!(capturing);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// No tee and no file (a bare exe run from a console) keeps the
    /// honest "not available" answer rather than inventing one.
    #[test]
    fn no_ring_and_no_file_reports_no_capture() {
        let d = tmpdir("bare");
        let (lines, capturing) = log_payload(200, Vec::new(), false, Some(d.as_path()));
        assert!(lines.is_empty());
        assert!(!capturing);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Unix is untouched: a live ring is served as-is and the file on
    /// disk is never consulted, so the fallback cannot shadow the tee.
    #[test]
    fn a_live_ring_wins_over_the_file() {
        let d = tmpdir("ringwins");
        std::fs::write(d.join("daemon.log"), b"stale from the file\n").unwrap();
        let (lines, capturing) = log_payload(
            200,
            vec!["from the ring".to_string()],
            true,
            Some(d.as_path()),
        );
        assert_eq!(lines, vec!["from the ring".to_string()]);
        assert!(capturing);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A missing file is not an empty one. The UI says "nothing logged
    /// yet" for one and "no log capture" for the other, so the caller
    /// has to be able to tell them apart.
    #[test]
    fn a_missing_log_is_none_and_an_empty_one_is_some() {
        assert!(tail_log_file(&tmp("absent"), 10).is_none());
        let p = tmp("empty");
        std::fs::write(&p, b"").unwrap();
        assert_eq!(tail_log_file(&p, 10), Some(Vec::new()));
        let _ = std::fs::remove_file(&p);
    }

    /// The last `n`, oldest first - the order the panel prints.
    #[test]
    fn it_returns_the_last_n_lines_oldest_first() {
        let p = tmp("short");
        std::fs::write(&p, b"one\ntwo\nthree\nfour\n").unwrap();
        assert_eq!(
            tail_log_file(&p, 2),
            Some(vec!["three".to_string(), "four".to_string()])
        );
        // Asking for more than the file holds returns what there is.
        assert_eq!(tail_log_file(&p, 99).map(|v| v.len()), Some(4));
        let _ = std::fs::remove_file(&p);
    }

    /// A file past the byte cap is read from its END, and the partial
    /// line the window opens on is dropped rather than served as a line.
    /// This is the case a 5 MB rotated log actually hits.
    #[test]
    fn a_huge_file_is_tailed_not_swallowed() {
        let p = tmp("huge");
        let mut body = String::new();
        // Comfortably past LOG_TAIL_BYTES so the read really is a window.
        for i in 0..80_000 {
            body.push_str(&format!("line {i} padded out to make this file large\n"));
        }
        assert!(body.len() as u64 > LOG_TAIL_BYTES);
        std::fs::write(&p, body.as_bytes()).unwrap();
        let got = tail_log_file(&p, 3).expect("a large file still reads");
        assert_eq!(
            got,
            vec![
                "line 79997 padded out to make this file large".to_string(),
                "line 79998 padded out to make this file large".to_string(),
                "line 79999 padded out to make this file large".to_string(),
            ]
        );
        // Every line handed back is whole - no leading fragment survived.
        assert!(got.iter().all(|l| l.starts_with("line ")));
        let _ = std::fs::remove_file(&p);
    }

    /// One undecodable byte costs that character, never the panel: a
    /// child process printing a legacy-encoded filename lands in this
    /// same file.
    #[test]
    fn invalid_utf8_does_not_lose_the_log() {
        let p = tmp("latin1");
        std::fs::write(&p, b"before\nca\xe9 nam\xe9\nafter\n").unwrap();
        let got = tail_log_file(&p, 10).expect("still readable");
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], "before");
        assert_eq!(got[2], "after");
        assert!(got[1].contains('\u{fffd}'), "expected a replacement char");
        let _ = std::fs::remove_file(&p);
    }

    fn params(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// The download-folder browser must never dead-end. A `path` that does
    /// not exist (an unmounted drive, a folder deleted since it was set)
    /// used to answer a bare `{status:false,error}` with NO `roots` - so
    /// the modal came up with nothing to click and the user could not
    /// navigate to another drive to repoint their download folder. It now
    /// falls back to the nearest readable ancestor with a `note`, and
    /// always carries the roots list.
    #[test]
    fn fs_list_on_a_missing_path_falls_back_to_an_ancestor_with_roots() {
        use crate::serve::testutil::test_daemon;
        let dir = std::env::temp_dir().join(format!("nzbfast-fslist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = test_daemon(&dir);

        // A deep path whose leaf and intermediate dirs do not exist.
        let missing = dir.join("gone-drive").join("deeper").join("still");
        let v = fs_list(&d, &params(&[("path", &missing.to_string_lossy())]));

        // The caller is not stranded: a listing, a note, and roots.
        assert_eq!(v["status"], true, "must not dead-end: {v}");
        assert!(
            v["note"].is_string(),
            "a fallback must explain what happened: {v}"
        );
        let roots = v["roots"].as_array().expect("roots must be present");
        assert!(!roots.is_empty(), "roots must offer somewhere to go: {v}");
        // The folder actually shown exists and is a real ancestor to walk
        // back down from.
        let shown = std::path::Path::new(v["path"].as_str().unwrap());
        assert!(shown.is_dir(), "the fallback folder must be real: {v}");
        assert!(
            missing.starts_with(shown) || shown == std::path::Path::new("/"),
            "the fallback must be an ancestor of the requested path: {v}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The empty-path case is the one a person hits on open: it resolves to
    /// the current download root, and if THAT is gone (a config carried
    /// over from another machine, an unmounted volume) the picker still has
    /// to open on something rather than trapping the user on an error.
    #[test]
    fn fs_list_empty_path_when_download_root_is_gone_still_opens() {
        use crate::serve::testutil::test_daemon;
        let dir = std::env::temp_dir().join(format!("nzbfast-fsgone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = test_daemon(&dir);
        // Point the download root at a directory that does not exist.
        *d.out_root.write_ok() = dir.join("unmounted");

        let v = fs_list(&d, &params(&[("path", "")]));
        assert_eq!(v["status"], true, "an empty path must never dead-end: {v}");
        assert!(v["note"].is_string(), "the fallback must be explained: {v}");
        assert!(
            !v["roots"].as_array().unwrap().is_empty(),
            "roots must be present even when the download root is gone: {v}"
        );
        assert!(
            std::path::Path::new(v["path"].as_str().unwrap()).is_dir(),
            "the picker must open on a real folder: {v}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The healthy path is unchanged: a real directory lists its contents
    /// (folders only, dotfiles hidden), carries no fallback note, and still
    /// includes the roots.
    #[test]
    fn fs_list_on_a_real_directory_lists_it_without_a_note() {
        use crate::serve::testutil::test_daemon;
        let dir = std::env::temp_dir().join(format!("nzbfast-fsok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = test_daemon(&dir);
        // Browse a dedicated folder (the fixture puts out/spool in `dir`).
        let browse = dir.join("library");
        std::fs::create_dir_all(browse.join("Movies")).unwrap();
        std::fs::create_dir_all(browse.join("TV")).unwrap();
        std::fs::write(browse.join("readme.txt"), b"hi").unwrap();
        std::fs::write(browse.join(".hidden"), b"x").unwrap();

        let v = fs_list(&d, &params(&[("path", &browse.to_string_lossy())]));
        assert_eq!(v["status"], true, "{v}");
        assert!(v.get("note").is_none(), "no fallback, so no note: {v}");
        let names: Vec<&str> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        // Directory mode hides files and dotfiles; folders come first.
        assert_eq!(names, vec!["Movies", "TV"], "{v}");
        assert!(!v["roots"].as_array().unwrap().is_empty(), "{v}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
