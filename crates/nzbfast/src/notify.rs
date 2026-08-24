//! Post-job notifications: tell a media server - or anything that speaks
//! HTTP - that a download landed.
//!
//! This is the native answer to the notifier half of NZBGet's extension
//! catalogue (RefreshKodi, NotifyPlex, NotifyEmbyJellyfin and friends):
//! the common case is one library rescan, and asking people to install
//! Python and wire up a script for that is a poor trade. The generic
//! `Webhook` kind covers everything else - Discord, ntfy, Gotify, Home
//! Assistant - so the script hook stays for genuine post-processing
//! rather than being the only way to send an HTTP request.
//!
//! # Reaching the LAN, without reaching the metadata service
//!
//! A notification target is `http://192.168.1.40:8080` or
//! `http://localhost:32400` essentially every time, so this is one of
//! the few outbound paths that MUST work against private addresses. It
//! still goes through [`crate::netfetch::ssrf_safe_agent`], because that
//! guard is not a private-address blocker: it allows loopback, LAN and
//! CGNAT (self-hosted indexers and Tailscale live there) and refuses
//! only link-local and the cloud metadata endpoints, which no media
//! server has ever been hosted on.
//!
//! Redirects are set to zero on top of that. A target that answers 302
//! is not a media server we know, and following the hop is exactly the
//! move that would turn a URL pointing somewhere harmless into a request
//! somewhere else.

use std::time::Duration;
use tracing::{info, warn};

use serde::{Deserialize, Serialize};

/// How long any one notification may take before we give up on it. These
/// are LAN calls to a media server; a library scan returns immediately
/// and only the scan itself runs long.
const TIMEOUT: Duration = Duration::from_secs(10);

/// What kind of thing sits at the other end.
///
/// §129 2e (decision 3): the preset kinds below Webhook are each one
/// templated HTTP POST in the service's own shape - the native answer
/// to Apprise without the Python dependency. `body`, when set, is the
/// MESSAGE TEXT template for a preset (placeholders apply), not the
/// whole request body; the preset supplies the service's JSON around
/// it. An "Apprise API server" preset covers everything else Apprise
/// speaks, for users who run one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Kodi's JSON-RPC endpoint: `VideoLibrary.Scan`.
    Kodi,
    /// Plex Media Server: refresh every library section.
    Plex,
    /// Jellyfin or Emby: refresh the library.
    Jellyfin,
    /// Anything else: a rendered POST of your own.
    Webhook,
    /// Discord incoming webhook: url = the webhook URL.
    Discord,
    /// Slack incoming webhook: url = the webhook URL.
    Slack,
    /// Telegram bot: token = `<bot_token>/<chat_id>` (slash-separated -
    /// bot tokens carry a colon of their own). url empty = the public
    /// api.telegram.org.
    Telegram,
    /// Pushover: token = `<app_token>/<user_key>`. url empty = the
    /// public api.pushover.net.
    Pushover,
    /// ntfy: url = the topic URL (`https://ntfy.sh/mytopic` or
    /// self-hosted); token = an access token, if the topic needs one.
    Ntfy,
    /// Gotify: url = the server, token = an application token.
    Gotify,
    /// An Apprise API server: url = its notify endpoint
    /// (`http://host:8000/notify/<config-key>`).
    Apprise,
    /// Native SMTP: url = `smtp://host:port` (STARTTLS when the server
    /// offers it) or `smtps://host:port` (TLS from the first byte);
    /// token = `user:password` when the server wants a login.
    Email,
}

fn yes() -> bool {
    true
}

/// One configured notification target, as stored in settings.json
/// ("notify_targets").
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    /// Display label. Cosmetic - the dashboard shows it in the log line.
    #[serde(default)]
    pub name: String,
    pub kind: Kind,
    /// Server base URL (`http://192.168.1.40:8080`), or the full URL to
    /// call for a `Webhook`. A trailing slash is tolerated.
    pub url: String,
    /// Plex token, Jellyfin/Emby API key, or `user:password` for a Kodi
    /// with authentication turned on. Unused by `Webhook`.
    #[serde(default)]
    pub token: String,
    /// `Webhook` only: the request body, with `{name}`-style placeholders
    /// (see [`Ctx::render_body`]). Empty sends our own JSON payload.
    #[serde(default)]
    pub body: String,
    /// A target you added is on unless you turn it off, so a list loaded
    /// from an older settings.json without the field still fires.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Also fire for a job that FAILED. Off by default: a library scan
    /// after a failure is pure noise, but a Discord webhook usually wants
    /// to hear about it.
    #[serde(default)]
    pub on_failure: bool,
    /// Only fire for this category. Empty = every category.
    #[serde(default)]
    pub category: String,
    /// §129 2e: event-level routing. Empty = the legacy contract
    /// (completed jobs, plus failed ones when `on_failure`). Tokens:
    /// "completed", "failed", "repaired" (a completion whose download
    /// needed PAR2 repair), "disk" (the low-disk guard fired), "quota"
    /// (the quota guard fired).
    #[serde(default)]
    pub events: Vec<String>,
    /// Email only: the recipient. Required for [`Kind::Email`].
    #[serde(default)]
    pub email_to: String,
    /// Email only: the From address. Empty = "nzbfast@localhost".
    #[serde(default)]
    pub email_from: String,
    /// §129 4a, `Webhook` only: HMAC key. When set, every request this
    /// target receives carries `X-NzbFast-Signature: sha256=<hex
    /// HMAC-SHA256 of the exact body bytes>` - the GitHub-webhook shape,
    /// so existing verification snippets port. Write-only like `token`:
    /// get_config says only `has_secret`, and a blank secret on save
    /// keeps the stored one.
    #[serde(default)]
    pub secret: String,
}

/// §129 4a: the signature header value for `body` under `secret` -
/// `sha256=<lowercase hex>` over the exact bytes sent. One helper for
/// the notification webhook and the lifecycle dispatcher, so the two
/// can never drift.
pub fn sign(secret: &str, body: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as hmac::digest::KeyInit>::new_from_slice(secret.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// How one target's last delivery went, as its settings row reports it.
///
/// A failed notification was log-only: `fire` warned and moved on, which
/// is right for the download but wrong for the user, whose Plex token
/// expired three weeks ago and whose library has not been rescanned
/// since. Nothing in the UI said so.
#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    /// Unix seconds when the attempt finished.
    pub at: i64,
    /// The HTTP status the target answered with, or 0 when it never
    /// answered at all (DNS, refused, timeout).
    pub code: u16,
    /// Empty on success. Otherwise the failure as [`send`] reports it,
    /// which by construction never contains the url - see the transport
    /// arm at the bottom of `send`.
    pub error: String,
    /// True when this was a Test rather than a finished download. The row
    /// says which, because "it worked when I pressed Test" and "the last
    /// real download told it" are different claims.
    pub test: bool,
}

/// The map key a caller stores an [`Outcome`] under.
///
/// Kind + url + name is the same triple `notify_test` already uses to
/// find a saved target when the UI sends a blank token, so a row keeps
/// its outcome across edits that do not change its identity.
///
/// The key CONTAINS the url, which for a Discord/ntfy/Gotify webhook is
/// itself the bearer credential. It is a lookup key and nothing else:
/// never log it, never put it in a response.
pub fn target_key(t: &Target) -> String {
    // \u{1} cannot appear in any of the three, so the parts cannot run
    // together into a colliding key.
    format!("{:?}\u{1}{}\u{1}{}", t.kind, t.url, t.name)
}

/// The finished job, flattened for templating and for the default
/// webhook payload. Taken under the job lock once, so nothing here can
/// deadlock against a notification that runs long.
#[derive(Clone, Debug)]
pub struct Ctx {
    pub name: String,
    pub status: &'static str,
    pub category: String,
    pub dir: String,
    pub bytes: u64,
    pub error: String,
    pub nzo_id: String,
    /// §129 2e: which event this is - "completed", "failed", or a
    /// warning token ("disk", "quota"). What [`Target::events`] routes
    /// on.
    pub event: String,
    /// The download needed PAR2 repair on the way to Completed - the
    /// "repaired" routing token.
    pub repaired: bool,
}

impl Ctx {
    /// §129 2e: a non-job event (the disk or quota guard firing), for
    /// targets routed onto those tokens. The message rides in `name`
    /// so every template placeholder still means something.
    pub fn for_event(event: &str, message: &str) -> Ctx {
        Ctx {
            name: message.to_string(),
            status: "Warning",
            category: String::new(),
            dir: String::new(),
            bytes: 0,
            error: String::new(),
            nzo_id: String::new(),
            event: event.to_string(),
            repaired: false,
        }
    }

    fn ok(&self) -> bool {
        self.status == "Completed"
    }

    /// The one-line human message the preset services send when the
    /// target has no body template of its own.
    fn message(&self) -> String {
        match self.event.as_str() {
            "completed" if self.repaired => {
                format!("{} finished downloading (repaired on the way)", self.name)
            }
            "completed" => format!("{} finished downloading", self.name),
            "failed" => format!("{} failed: {}", self.name, self.error),
            _ => self.name.clone(),
        }
    }

    /// Substitute `{name}`/`{status}`/… into a webhook body, escaping each
    /// value for JSON. A release name legitimately contains quotes and
    /// backslashes ("Hackers.1995.DVDRip" is the polite case), and a
    /// failure message contains whatever the server said - pasting either
    /// raw into a JSON template produces a body the far end rejects, and
    /// lets a crafted release name forge extra fields in it.
    ///
    /// Non-JSON bodies (a form post, plain text) get JSON escaping too.
    /// It is the wrong escape for them in principle, but it only ever
    /// touches quotes, backslashes and control characters, so in practice
    /// it passes text through and refuses to break the common case.
    fn render_body(&self, template: &str) -> String {
        self.render(template, |v| {
            let quoted = serde_json::Value::String(v.to_string()).to_string();
            // to_string() wraps in quotes; the template supplies its own.
            quoted[1..quoted.len() - 1].to_string()
        })
    }

    /// Substitute into plain text (a preset's message, an email body):
    /// values pass through untouched - the JSON that later wraps the
    /// text escapes at embed time via `serde_json::json!`.
    fn render_plain(&self, template: &str) -> String {
        self.render(template, |v| v.to_string())
    }

    /// Substitute into a URL, percent-encoding each value. Without this a
    /// name containing `&` or `#` silently truncates or forges the query
    /// string it lands in.
    fn render_url(&self, template: &str) -> String {
        self.render(template, percent_encode)
    }

    /// One left-to-right pass over the template, so a value we substitute
    /// is never rescanned for placeholders. Replacing key by key over an
    /// accumulating string meant a release name of `Some.Release.{dir}`
    /// came out of the `{name}` pass carrying a live `{dir}` (neither JSON
    /// escaping nor percent-encoding of `{` applies to the body), and the
    /// `{dir}` pass then expanded it into the local download path - a
    /// webhook whose template deliberately exposed only `{name}` got the
    /// filesystem too. It is a plain rendering bug either way: a release
    /// with `{error}` in the name rendered wrongly for everybody.
    ///
    /// An unknown `{...}` is emitted verbatim and the scan resumes just
    /// after the brace, so someone else's templating syntax passes through
    /// untouched.
    fn render(&self, template: &str, esc: impl Fn(&str) -> String) -> String {
        let bytes = self.bytes.to_string();
        let table = [
            ("name", self.name.as_str()),
            ("status", self.status),
            ("category", self.category.as_str()),
            ("dir", self.dir.as_str()),
            ("bytes", bytes.as_str()),
            ("error", self.error.as_str()),
            ("id", self.nzo_id.as_str()),
        ];
        let mut out = String::with_capacity(template.len());
        let mut rest = template;
        while let Some(i) = rest.find('{') {
            out.push_str(&rest[..i]);
            rest = &rest[i..];
            match rest.find('}').and_then(|j| {
                table
                    .iter()
                    .find(|(k, _)| *k == &rest[1..j])
                    .map(|(_, v)| (j, *v))
            }) {
                Some((j, v)) => {
                    out.push_str(&esc(v));
                    rest = &rest[j + 1..];
                }
                None => {
                    out.push('{');
                    rest = &rest[1..];
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// The body a `Webhook` with no template of its own sends.
    fn default_payload(&self) -> String {
        serde_json::json!({
            "name": self.name,
            "status": self.status,
            "category": self.category,
            "dir": self.dir,
            "bytes": self.bytes,
            "error": self.error,
            "id": self.nzo_id,
        })
        .to_string()
    }
}

/// Percent-encode everything outside the unreserved set (RFC 3986). Small
/// and local: the one dependency that could do this is not already in the
/// tree, and the rule is four lines.
fn percent_encode(s: &str) -> String {
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

/// Should this target hear about this event at all?
///
/// §129 2e: an `events` list routes precisely; an empty list is the
/// legacy contract - completed jobs, failed ones only with
/// `on_failure`, and never the warning events (they did not exist).
fn wants(t: &Target, cx: &Ctx) -> bool {
    if !t.enabled {
        return false;
    }
    let routed = if t.events.is_empty() {
        match cx.event.as_str() {
            "completed" => true,
            "failed" => t.on_failure,
            _ => false,
        }
    } else {
        t.events.iter().any(|e| match e.as_str() {
            "repaired" => cx.event == "completed" && cx.repaired,
            e => e == cx.event,
        })
    };
    if !routed {
        return false;
    }
    // An empty category on the job means "no category", which only an
    // unfiltered target matches. Warning events carry no category and
    // reach unfiltered targets only.
    t.category.is_empty() || t.category.eq_ignore_ascii_case(&cx.category)
}

/// Fire every target that wants this job, in order. Blocking: call from
/// the blocking pool. Never panics and never propagates an error - a
/// media server being down is not a download problem, so it is logged and
/// dropped.
///
/// Returns what each attempted target's delivery did, keyed by
/// [`target_key`], for the caller to store and the settings row to show.
/// Targets that did not want this job are absent rather than recorded as
/// anything: a category-filtered target has not failed.
pub fn fire(targets: &[Target], cx: &Ctx, now: i64) -> Vec<(String, Outcome)> {
    let mut out = Vec::new();
    for t in targets.iter().filter(|t| wants(t, cx)) {
        let label = if t.name.is_empty() {
            format!("{:?}", t.kind)
        } else {
            t.name.clone()
        };
        let o = match send(t, cx) {
            Ok(code) => {
                info!(target: "notify", "{label}: {code} for {:?}", cx.name);
                Outcome {
                    at: now,
                    code,
                    error: String::new(),
                    test: false,
                }
            }
            Err(e) => {
                warn!(target: "notify", "{label} failed: {e}");
                Outcome {
                    at: now,
                    code: 0,
                    error: e,
                    test: false,
                }
            }
        };
        out.push((target_key(t), o));
    }
    out
}

/// Send one target a sample notification and report what happened, for
/// the dashboard's Test button. Without this the first feedback on a
/// wrong token or a typo'd port is a library that quietly never rescans
/// after a download that already took an hour.
///
/// Deliberately ignores `enabled`, `on_failure` and `category`: the user
/// pressed Test on THIS row, and silently doing nothing because the row
/// is switched off would read as a failure of the connection.
pub fn test(t: &Target) -> Result<u16, String> {
    send(
        t,
        &Ctx {
            name: "Test Notification".into(),
            status: "Completed",
            category: t.category.clone(),
            dir: String::new(),
            bytes: 0,
            error: String::new(),
            nzo_id: "test".into(),
            event: "completed".into(),
            repaired: false,
        },
    )
}

/// SSRF-guarded like every other outbound fetch, with redirects off. See
/// the module note: the guard still permits the LAN and loopback
/// addresses these targets actually live on.
fn agent() -> ureq::Agent {
    crate::netfetch::ssrf_safe_agent(0, TIMEOUT.as_secs())
}

/// Build and send one notification. Returns the HTTP status on success.
fn send(t: &Target, cx: &Ctx) -> Result<u16, String> {
    let base = t.url.trim().trim_end_matches('/');
    // Email speaks smtp://, and Telegram/Pushover default their public
    // API host on an empty url - neither belongs under the HTTP scheme
    // gate below.
    if t.kind == Kind::Email {
        return smtp::send_email(t, cx);
    }
    let url_optional = matches!(t.kind, Kind::Telegram | Kind::Pushover);
    if base.is_empty() && !url_optional {
        return Err("no url configured".into());
    }
    if !base.is_empty() && !(base.starts_with("http://") || base.starts_with("https://")) {
        // Deliberately does not echo the URL back. A webhook URL pasted
        // without its scheme is still a bearer capability, and this
        // message goes to the log ring the dashboard shows and the log
        // file people paste into support threads. The user is looking at
        // the field they just typed.
        return Err("url must start with http:// or https://".into());
    }
    let a = agent();
    let resp = match t.kind {
        // Kodi's JSON-RPC. A whole-library scan, not a scan of this
        // job's directory: the path we downloaded to is our path, and
        // Kodi's view of the same share is routinely mounted somewhere
        // else entirely (or on another machine), so a directory-scoped
        // scan would silently do nothing. RefreshKodi makes the same call.
        Kind::Kodi => {
            let req = a
                .post(&format!("{base}/jsonrpc"))
                .set("Content-Type", "application/json");
            let req = match basic_auth(&t.token) {
                Some(h) => req.set("Authorization", &h),
                None => req,
            };
            req.send_string(r#"{"jsonrpc":"2.0","id":1,"method":"VideoLibrary.Scan"}"#)
        }
        // Refreshes every section. Plex has no "rescan what changed"
        // call that does not need the section id, and a section id is
        // one more thing to look up and get wrong.
        Kind::Plex => {
            if t.token.is_empty() {
                return Err("Plex needs a token (X-Plex-Token)".into());
            }
            a.get(&format!("{base}/library/sections/all/refresh"))
                .set("X-Plex-Token", &t.token)
                .call()
        }
        // X-Emby-Token is honoured by both Emby and Jellyfin, so one
        // kind covers the pair.
        Kind::Jellyfin => {
            if t.token.is_empty() {
                return Err("Jellyfin/Emby needs an API key".into());
            }
            a.post(&format!("{base}/Library/Refresh"))
                .set("X-Emby-Token", &t.token)
                .set("Content-Length", "0")
                .send_string("")
        }
        Kind::Webhook => {
            let url = cx.render_url(base);
            let body = if t.body.trim().is_empty() {
                cx.default_payload()
            } else {
                cx.render_body(&t.body)
            };
            let req = a.post(&url).set("Content-Type", "application/json");
            // §129 4a: a secret signs the notification sends too, so a
            // receiver can verify everything from this target one way.
            let req = if t.secret.is_empty() {
                req
            } else {
                req.set("X-NzbFast-Signature", &sign(&t.secret, body.as_bytes()))
            };
            req.send_string(&body)
        }
        // §129 2e presets: `body` is the MESSAGE TEXT template here
        // (placeholders apply), never the raw request - the preset owns
        // the service's JSON shape so a quote in a release name cannot
        // break it.
        Kind::Discord => a
            .post(base)
            .set("Content-Type", "application/json")
            .send_string(&serde_json::json!({"content": preset_text(t, cx)}).to_string()),
        Kind::Slack => a
            .post(base)
            .set("Content-Type", "application/json")
            .send_string(&serde_json::json!({"text": preset_text(t, cx)}).to_string()),
        Kind::Telegram => {
            let Some((bot, chat)) = t.token.split_once('/') else {
                return Err("Telegram needs token = <bot_token>/<chat_id>".into());
            };
            let api = if t.url.trim().is_empty() {
                "https://api.telegram.org".to_string()
            } else {
                base.to_string()
            };
            a.post(&format!("{api}/bot{bot}/sendMessage"))
                .set("Content-Type", "application/json")
                .send_string(
                    &serde_json::json!({"chat_id": chat, "text": preset_text(t, cx)}).to_string(),
                )
        }
        Kind::Pushover => {
            let Some((app, user)) = t.token.split_once('/') else {
                return Err("Pushover needs token = <app_token>/<user_key>".into());
            };
            let api = if t.url.trim().is_empty() {
                "https://api.pushover.net".to_string()
            } else {
                base.to_string()
            };
            a.post(&format!("{api}/1/messages.json"))
                .set("Content-Type", "application/json")
                .send_string(
                    &serde_json::json!({
                        "token": app, "user": user,
                        "title": "nzbfast", "message": preset_text(t, cx),
                    })
                    .to_string(),
                )
        }
        Kind::Ntfy => {
            let req = a.post(base).set("X-Title", "nzbfast");
            let req = if t.token.is_empty() {
                req
            } else {
                req.set("Authorization", &format!("Bearer {}", t.token))
            };
            req.send_string(&preset_text(t, cx))
        }
        Kind::Gotify => {
            if t.token.is_empty() {
                return Err("Gotify needs an application token".into());
            }
            // The token rides a header, not the query string, so it
            // stays out of access logs on the way.
            a.post(&format!("{base}/message"))
                .set("X-Gotify-Key", &t.token)
                .set("Content-Type", "application/json")
                .send_string(
                    &serde_json::json!({
                        "title": "nzbfast", "message": preset_text(t, cx),
                        "priority": if cx.ok() { 4 } else { 7 },
                    })
                    .to_string(),
                )
        }
        Kind::Apprise => a
            .post(base)
            .set("Content-Type", "application/json")
            .send_string(
                &serde_json::json!({
                    "title": "nzbfast",
                    "body": preset_text(t, cx),
                    "type": if cx.ok() { "success" } else { "failure" },
                })
                .to_string(),
            ),
        // Handled above, before the HTTP scheme gate.
        Kind::Email => unreachable!("email returns before the scheme gate"),
    };
    match resp {
        Ok(r) => Ok(r.status()),
        // A 2xx-shaped failure still carries a status worth reporting;
        // anything else (DNS, refused, timeout) only has a message.
        Err(ureq::Error::Status(code, r)) => {
            let detail = r.into_string().unwrap_or_default();
            let detail = detail.trim();
            let detail: String = detail.chars().take(200).collect();
            Err(format!(
                "HTTP {code}{}",
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            ))
        }
        Err(ureq::Error::Transport(t)) => Err(transport_brief(&t)),
    }
}

/// A transport error's Display starts with the whole request URL,
/// path and query included. For a Discord/ntfy/Gotify webhook that
/// path IS the secret, and this string is logged. Rebuild the
/// message from the parts that describe the failure instead: the
/// kind, ureq's own message, and the underlying io/DNS error, which
/// names host:port at worst. Shared with the §129 4a lifecycle
/// dispatcher, which logs through the same rule.
pub fn transport_brief(t: &ureq::Transport) -> String {
    format!(
        "{}{}{}",
        t.kind(),
        t.message().map(|m| format!(": {m}")).unwrap_or_default(),
        std::error::Error::source(&t)
            .map(|s| format!(": {s}"))
            .unwrap_or_default(),
    )
}

/// A preset's message text: the target's own `body` template rendered
/// plain, or the stock one-liner.
fn preset_text(t: &Target, cx: &Ctx) -> String {
    if t.body.trim().is_empty() {
        cx.message()
    } else {
        cx.render_plain(&t.body)
    }
}

/// §129 2e: the native SMTP sender - a minimal blocking client (EHLO,
/// STARTTLS or implicit TLS, AUTH PLAIN, one message), so email
/// notifications need no external binary and no Python. TLS is
/// nzbkit's shared client config, so the trust anchors are exactly the
/// download path's - `NZBFAST_EXTRA_CA` included.
mod smtp {
    use super::{Ctx, Target, b64, preset_text};
    use std::io::{Read, Write};
    use std::net::TcpStream;

    trait Rw: Read + Write {}
    impl<T: Read + Write> Rw for T {}

    struct Conn {
        s: Box<dyn Rw>,
        buf: Vec<u8>,
    }

    impl Conn {
        fn line(&mut self) -> Result<String, String> {
            loop {
                if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = self.buf.drain(..=i).collect();
                    return Ok(String::from_utf8_lossy(&line).trim_end().to_string());
                }
                // Bounded: a server that talks forever without a newline
                // is not an SMTP server.
                if self.buf.len() > 64 * 1024 {
                    return Err("oversized reply".into());
                }
                let mut tmp = [0u8; 512];
                let n = self.s.read(&mut tmp).map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("connection closed".into());
                }
                self.buf.extend_from_slice(&tmp[..n]);
            }
        }

        /// One full (possibly multiline) reply. Err on 4xx/5xx, with
        /// the server's own words - they name the actual problem
        /// ("relay denied", "authentication failed") better than we
        /// could.
        fn reply(&mut self, what: &str) -> Result<(u16, String), String> {
            let mut all = String::new();
            loop {
                let l = self.line()?;
                let cont = l.len() >= 4 && l.as_bytes()[3] == b'-';
                all.push_str(&l);
                all.push('\n');
                if cont {
                    continue;
                }
                let code: u16 = l
                    .get(..3)
                    .and_then(|c| c.parse().ok())
                    .ok_or_else(|| format!("{what}: malformed reply {l:?}"))?;
                if code >= 400 {
                    return Err(format!("{what}: {l}"));
                }
                return Ok((code, all));
            }
        }

        fn cmd(&mut self, c: &str, what: &str) -> Result<(u16, String), String> {
            self.s
                .write_all(c.as_bytes())
                .and_then(|_| self.s.write_all(b"\r\n"))
                .and_then(|_| self.s.flush())
                .map_err(|e| format!("{what}: {e}"))?;
            self.reply(what)
        }
    }

    fn tls(host: &str, tcp: TcpStream) -> Result<Box<dyn Rw>, String> {
        // nzbkit's shared client config, not a private webpki-only one:
        // the mail link trusts exactly what the NNTP path trusts, which
        // is what makes `NZBFAST_EXTRA_CA` (a self-hosted mail relay
        // with a private CA is the same story as a private indexer)
        // apply here without a second mechanism.
        let cfg = nzbkit::nntp::shared_tls_client_config();
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| "bad smtp host name".to_string())?;
        let conn = rustls::ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
        Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
    }

    /// An address that can sit inside `<...>` and a header line without
    /// smuggling more headers in.
    fn clean_addr<'a>(a: &'a str, what: &str) -> Result<&'a str, String> {
        let a = a.trim();
        if a.is_empty()
            || a.chars()
                .any(|c| c.is_control() || c == '<' || c == '>' || c == ' ')
        {
            return Err(format!("{what} is not a plain address"));
        }
        Ok(a)
    }

    pub(super) fn send_email(t: &Target, cx: &Ctx) -> Result<u16, String> {
        let url = t.url.trim().trim_end_matches('/');
        let (tls_first, rest) = if let Some(r) = url.strip_prefix("smtps://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("smtp://") {
            (false, r)
        } else {
            return Err("email url must be smtp://host:port or smtps://host:port".into());
        };
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>().map_err(|_| "bad smtp port".to_string())?,
            ),
            None => (rest.to_string(), if tls_first { 465 } else { 587 }),
        };
        let to = clean_addr(&t.email_to, "the To address")?;
        let from = if t.email_from.trim().is_empty() {
            "nzbfast@localhost"
        } else {
            clean_addr(&t.email_from, "the From address")?
        };
        // Resolve ourselves and refuse the addresses every other
        // outbound path refuses (link-local and the cloud-metadata
        // endpoints - see serve::is_forbidden_fetch_ip). SMTP is raw TCP
        // rather than a ureq call, so without this it would be the one
        // outbound fetch of a user-typed host that skips the SSRF guard.
        use std::net::ToSocketAddrs;
        let addrs: Vec<std::net::SocketAddr> = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("resolve {host}: {}", e.kind()))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("{host} did not resolve"));
        }
        if addrs
            .iter()
            .any(|a| crate::netfetch::is_forbidden_fetch_ip(a.ip()))
        {
            return Err("refusing to connect to an internal address".into());
        }
        let mut tcp = None;
        let mut last: Option<std::io::Error> = None;
        for a in &addrs {
            match TcpStream::connect_timeout(a, super::TIMEOUT) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let Some(tcp) = tcp else {
            return Err(format!(
                "connect {host}:{port}: {}",
                last.map(|e| e.to_string()).unwrap_or_default()
            ));
        };
        let _ = tcp.set_read_timeout(Some(super::TIMEOUT));
        let _ = tcp.set_write_timeout(Some(super::TIMEOUT));
        let mut c;
        if tls_first {
            c = Conn {
                s: tls(&host, tcp)?,
                buf: Vec::new(),
            };
            c.reply("greeting")?;
            c.cmd("EHLO nzbfast", "EHLO")?;
        } else {
            let mut plain = Conn {
                s: Box::new(tcp.try_clone().map_err(|e| e.to_string())?),
                buf: Vec::new(),
            };
            plain.reply("greeting")?;
            let (_, ehlo) = plain.cmd("EHLO nzbfast", "EHLO")?;
            if ehlo.to_ascii_uppercase().contains("STARTTLS") {
                plain.cmd("STARTTLS", "STARTTLS")?;
                drop(plain);
                c = Conn {
                    s: tls(&host, tcp)?,
                    buf: Vec::new(),
                };
                c.cmd("EHLO nzbfast", "EHLO")?;
            } else if !t.token.is_empty() {
                // Never send a login in the clear. The localhost-relay
                // case (no login) still works plain.
                return Err(
                    "the server offers no STARTTLS - use smtps:// or drop the login".into(),
                );
            } else {
                c = plain;
            }
        }
        if !t.token.is_empty() {
            let Some((u, p)) = t.token.split_once(':') else {
                return Err("email token must be user:password".into());
            };
            let auth = b64(format!("\0{u}\0{p}").as_bytes());
            c.cmd(&format!("AUTH PLAIN {auth}"), "AUTH")?;
        }
        c.cmd(&format!("MAIL FROM:<{from}>"), "MAIL FROM")?;
        c.cmd(&format!("RCPT TO:<{to}>"), "RCPT TO")?;
        c.cmd("DATA", "DATA")?;
        let subject: String = format!("nzbfast: {} - {}", cx.name, cx.status)
            .chars()
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .take(200)
            .collect();
        // CRLF line endings and dot-stuffing, per RFC 5321.
        let text = preset_text(t, cx);
        let mut body = String::new();
        for l in text.replace("\r\n", "\n").split('\n') {
            if l.starts_with('.') {
                body.push('.');
            }
            body.push_str(l);
            body.push_str("\r\n");
        }
        let (code, _) = c.cmd(
            &format!(
                "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\n\
                 MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}."
            ),
            "message",
        )?;
        let _ = c.cmd("QUIT", "QUIT");
        Ok(code)
    }
}

/// `user:password` → a Basic header. Kodi ships with authentication on
/// and a blank password, so `kodi:` is a real, working value and an empty
/// token means "no auth header at all".
fn basic_auth(token: &str) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    Some(format!("Basic {}", b64(token.as_bytes())))
}

/// Standard base64. Local for the same reason as [`percent_encode`].
fn b64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in input.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx() -> Ctx {
        Ctx {
            name: "The Movie & Friends \"2024\"".into(),
            status: "Completed",
            category: "movies".into(),
            dir: "/downloads/The Movie".into(),
            bytes: 1234,
            error: String::new(),
            nzo_id: "abc123".into(),
            event: "completed".into(),
            repaired: false,
        }
    }

    fn target(kind: Kind) -> Target {
        Target {
            name: String::new(),
            kind,
            url: "http://10.0.0.5:8080".into(),
            token: String::new(),
            body: String::new(),
            enabled: true,
            on_failure: false,
            category: String::new(),
            events: Vec::new(),
            email_to: String::new(),
            email_from: String::new(),
            secret: String::new(),
        }
    }

    /// §129 2e: event routing - an empty list keeps the legacy
    /// contract, a list routes precisely, "repaired" narrows completed.
    #[test]
    fn event_routing() {
        let mut t = target(Kind::Discord);
        let done = cx();
        let mut failed = cx();
        failed.status = "Failed";
        failed.event = "failed".into();
        let mut repaired = cx();
        repaired.repaired = true;
        let disk = Ctx::for_event("disk", "downloads paused - low disk");
        // Legacy: completed yes, failed only with on_failure, warnings never.
        assert!(wants(&t, &done));
        assert!(!wants(&t, &failed));
        assert!(!wants(&t, &disk));
        t.on_failure = true;
        assert!(wants(&t, &failed));
        // Routed: only what the list names.
        t.events = vec!["failed".into(), "disk".into()];
        assert!(!wants(&t, &done));
        assert!(wants(&t, &failed));
        assert!(wants(&t, &disk));
        // "repaired" is completed-and-repaired, not every completion.
        t.events = vec!["repaired".into()];
        assert!(!wants(&t, &done));
        assert!(wants(&t, &repaired));
        // The category filter still applies to job events, and a
        // warning (no category) only reaches unfiltered targets.
        t.events = vec!["completed".into(), "disk".into()];
        t.category = "tv".into();
        assert!(!wants(&t, &done), "movies job vs tv filter");
        assert!(!wants(&t, &disk), "warnings carry no category");
        t.category = String::new();
        assert!(wants(&t, &done));
    }

    /// The preset message text: stock line by default, the target's own
    /// template when set, warning events pass their message through.
    #[test]
    fn preset_text_shapes() {
        let mut t = target(Kind::Discord);
        assert!(preset_text(&t, &cx()).contains("finished downloading"));
        let mut failed = cx();
        failed.status = "Failed";
        failed.event = "failed".into();
        failed.error = "articles missing".into();
        assert!(preset_text(&t, &failed).contains("articles missing"));
        t.body = "{name} -> {status}".into();
        assert_eq!(
            preset_text(&t, &cx()),
            "The Movie & Friends \"2024\" -> Completed",
            "plain rendering, no JSON escaping - json! escapes at embed time"
        );
        let disk = Ctx::for_event("disk", "downloads paused - low disk");
        t.body = String::new();
        assert_eq!(preset_text(&t, &disk), "downloads paused - low disk");
    }

    /// Email guardrails that must not depend on a live server: scheme
    /// and address validation, and the cleartext-login refusal path is
    /// covered by the scheme check (smtp:// + token + no STARTTLS needs
    /// a server; the pure checks live here).
    #[test]
    fn email_validation() {
        let mut t = target(Kind::Email);
        t.url = "http://mail.example.com".into();
        t.email_to = "me@example.com".into();
        let e = send(&t, &cx()).unwrap_err();
        assert!(e.contains("smtp://"), "{e}");
        t.url = "smtp://mail.example.com:587".into();
        t.email_to = "evil\r\nBcc: everyone".into();
        let e = send(&t, &cx()).unwrap_err();
        assert!(e.contains("not a plain address"), "{e}");
    }

    /// SMTP is raw TCP, not a ureq call, so it carries its own copy of
    /// the outbound SSRF rule: the metadata/link-local class every
    /// other fetch of a user-typed host already refuses. Loopback stays
    /// allowed - a localhost relay is the normal no-login setup (and
    /// what the live-server tests in this module bind to).
    #[test]
    fn email_refuses_the_forbidden_address_class() {
        let mut t = target(Kind::Email);
        t.email_to = "me@example.com".into();
        t.url = "smtp://169.254.169.254:587".into();
        let e = send(&t, &cx()).unwrap_err();
        assert!(e.contains("internal address"), "{e}");
        // The refusal is pre-dial: an unspecified address never
        // resolves into a connect attempt either.
        t.url = "smtp://0.0.0.0:587".into();
        assert!(send(&t, &cx()).unwrap_err().contains("internal address"));
    }

    #[test]
    fn body_substitution_is_json_escaped() {
        // The quotes in the release name must not close the JSON string
        // they land in: that is a broken request at best, and a name that
        // forges extra fields at worst.
        let out = cx().render_body(r#"{"content":"{name} finished"}"#);
        assert_eq!(
            out,
            r#"{"content":"The Movie & Friends \"2024\" finished"}"#
        );
        serde_json::from_str::<serde_json::Value>(&out).expect("still valid JSON");
    }

    #[test]
    fn url_substitution_is_percent_encoded() {
        let out = cx().render_url("http://h/notify?t={name}&s={status}");
        assert!(!out.contains(' '), "spaces encoded: {out}");
        assert!(
            out.contains("%26"),
            "the & in the name is encoded, not a new param: {out}"
        );
        assert!(
            out.ends_with("&s=Completed"),
            "our own separators survive: {out}"
        );
    }

    #[test]
    fn unknown_placeholders_are_left_alone() {
        // Someone else's templating syntax passing through must not be
        // mangled into something unrecognisable.
        assert_eq!(
            cx().render_body("{nope} {name}"),
            "{nope} The Movie & Friends \\\"2024\\\""
        );
    }

    #[test]
    fn default_payload_is_valid_json() {
        let v: serde_json::Value = serde_json::from_str(&cx().default_payload()).unwrap();
        assert_eq!(v["status"], "Completed");
        assert_eq!(v["bytes"], 1234);
    }

    #[test]
    fn failure_only_reaches_targets_that_asked() {
        let mut failed = cx();
        failed.status = "Failed";
        failed.event = "failed".into();
        let t = target(Kind::Kodi);
        assert!(wants(&t, &cx()), "completion fires");
        assert!(!wants(&t, &failed), "failure does not, by default");
        let mut t2 = t.clone();
        t2.on_failure = true;
        assert!(wants(&t2, &failed), "unless it opted in");
        let mut off = t.clone();
        off.enabled = false;
        assert!(!wants(&off, &cx()));
    }

    #[test]
    fn category_filter_matches_case_insensitively() {
        let mut t = target(Kind::Plex);
        t.category = "Movies".into();
        assert!(wants(&t, &cx()), "movies == Movies");
        let mut tv = cx();
        tv.category = "tv".into();
        assert!(!wants(&t, &tv));
        // An uncategorised job only matches an unfiltered target.
        let mut none = cx();
        none.category = String::new();
        assert!(!wants(&t, &none));
        assert!(wants(&target(Kind::Plex), &none));
    }

    #[test]
    fn a_target_missing_enabled_still_fires() {
        // Round-trip from a settings.json written before the field
        // existed, and from a hand-edited one.
        let t: Target = serde_json::from_str(r#"{"kind":"kodi","url":"http://h:8080"}"#).unwrap();
        assert!(t.enabled);
        assert_eq!(t.kind, Kind::Kodi);
        assert!(wants(&t, &cx()));
    }

    #[test]
    fn bad_urls_are_rejected_before_any_request() {
        let mut t = target(Kind::Webhook);
        t.url = "  ".into();
        assert!(send(&t, &cx()).is_err());
        // No scheme: ureq would treat it as a relative URL and the error
        // would name something the user never typed.
        t.url = "10.0.0.5:8080".into();
        let e = send(&t, &cx()).unwrap_err();
        assert!(e.contains("http://"), "{e}");
        // file:// is not a notification.
        t.url = "file:///etc/passwd".into();
        assert!(send(&t, &cx()).is_err());
    }

    #[test]
    fn token_backed_kinds_refuse_to_call_without_one() {
        assert!(
            send(&target(Kind::Plex), &cx())
                .unwrap_err()
                .contains("token")
        );
        assert!(
            send(&target(Kind::Jellyfin), &cx())
                .unwrap_err()
                .contains("API key")
        );
    }

    /// Accept ONE request, hand back the raw head+body, and answer 200.
    /// A real socket rather than a mocked client because the thing worth
    /// pinning here is the bytes a media server actually receives: a
    /// wrong path or a missing auth header is exactly the bug that turns
    /// into "the scan never happens" with nothing in the log.
    fn capture_one() -> (String, std::sync::mpsc::Receiver<String>) {
        capture_answering("200 OK", "ok")
    }

    /// The same one-shot server, answering a status of the test's
    /// choosing - the outcome-recording tests need a target that takes
    /// the request and then rejects it, which is what an expired Plex
    /// token or a revoked webhook actually does.
    fn capture_answering(
        status: &'static str,
        body: &'static str,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            // Read the HEAD, then exactly Content-Length more. Responding
            // after a single read() passed when run alone and failed under
            // `cargo test` parallelism: a POST body can land in a second
            // segment, and answering early meant closing the socket while
            // the client was still writing, which surfaces on the client
            // as an incomprehensible header error.
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let head_end = loop {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break raw.len(),
                    Ok(n) => raw.extend_from_slice(&buf[..n]),
                }
                if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p + 4;
                }
            };
            let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
            let want: usize = head
                .split("\r\n")
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            while raw.len() < head_end + want {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&buf[..n]),
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&raw).into_owned());
            let _ = sock.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = sock.flush();
        });
        (url, rx)
    }

    fn recv(rx: &std::sync::mpsc::Receiver<String>) -> String {
        rx.recv_timeout(Duration::from_secs(5))
            .expect("server saw a request")
    }

    #[test]
    fn kodi_gets_a_jsonrpc_scan_with_basic_auth() {
        let (url, rx) = capture_one();
        let mut t = target(Kind::Kodi);
        t.url = url;
        t.token = "kodi:secret".into();
        assert_eq!(send(&t, &cx()).unwrap(), 200);
        let req = recv(&rx);
        assert!(req.starts_with("POST /jsonrpc "), "{req}");
        assert!(req.contains(r#""method":"VideoLibrary.Scan""#), "{req}");
        assert!(
            req.contains("Authorization: Basic a29kaTpzZWNyZXQ="),
            "{req}"
        );
    }

    #[test]
    fn plex_refreshes_all_sections_with_its_token() {
        let (url, rx) = capture_one();
        let mut t = target(Kind::Plex);
        t.url = format!("{url}/"); // trailing slash must not double up
        t.token = "tok123".into();
        assert_eq!(send(&t, &cx()).unwrap(), 200);
        let req = recv(&rx);
        assert!(
            req.starts_with("GET /library/sections/all/refresh "),
            "{req}"
        );
        assert!(req.contains("X-Plex-Token: tok123"), "{req}");
    }

    #[test]
    fn jellyfin_posts_a_library_refresh_with_its_key() {
        let (url, rx) = capture_one();
        let mut t = target(Kind::Jellyfin);
        t.url = url;
        t.token = "apikey".into();
        assert_eq!(send(&t, &cx()).unwrap(), 200);
        let req = recv(&rx);
        assert!(req.starts_with("POST /Library/Refresh "), "{req}");
        assert!(req.contains("X-Emby-Token: apikey"), "{req}");
    }

    #[test]
    fn a_webhook_sends_its_rendered_template() {
        let (url, rx) = capture_one();
        let mut t = target(Kind::Webhook);
        t.url = url;
        t.body = r#"{"text":"{name} -> {status}"}"#.into();
        assert_eq!(send(&t, &cx()).unwrap(), 200);
        let req = recv(&rx);
        let body = req.split("\r\n\r\n").nth(1).unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(body).expect("valid JSON on the wire");
        assert_eq!(v["text"], "The Movie & Friends \"2024\" -> Completed");
    }

    /// §129 4a: a secret adds the GitHub-shaped signature header, and it
    /// verifies against the exact body bytes that went on the wire.
    #[test]
    fn a_secret_signs_the_webhook_send() {
        let (url, rx) = capture_one();
        let mut t = target(Kind::Webhook);
        t.url = url;
        t.secret = "hunter2".into();
        assert_eq!(send(&t, &cx()).unwrap(), 200);
        let req = recv(&rx);
        let (head, body) = req.split_once("\r\n\r\n").unwrap_or_default();
        let sig = head
            .lines()
            .find_map(|l| l.strip_prefix("X-NzbFast-Signature: "))
            .expect("signature header present");
        assert_eq!(sig, sign("hunter2", body.as_bytes()));
        // A known-answer pin so the scheme cannot silently change:
        // HMAC-SHA256("key", "body") in the sha256=<hex> dressing.
        assert_eq!(
            sign("key", b"body"),
            "sha256=515aae133b435d4000956731f68ae5cf5eb85d4f0dc6a546d2bfcd3595ec1ae1"
        );
    }

    #[test]
    fn a_webhook_without_a_template_sends_the_job() {
        let (url, rx) = capture_one();
        let mut t = target(Kind::Webhook);
        t.url = url;
        assert_eq!(send(&t, &cx()).unwrap(), 200);
        let body = recv(&rx)
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_string();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["name"], "The Movie & Friends \"2024\"");
        assert_eq!(v["id"], "abc123");
    }

    #[test]
    fn a_refused_target_is_an_error_not_a_panic() {
        // Nothing listening: a media server that is off must cost the
        // job nothing. `fire` swallows it entirely.
        let mut t = target(Kind::Webhook);
        t.url = "http://127.0.0.1:1".into();
        assert!(send(&t, &cx()).is_err());
        fire(&[t], &cx(), 100);
    }

    #[test]
    fn a_delivery_that_worked_is_recorded_with_its_status() {
        let (url, rx) = capture_answering("204 No Content", "");
        let mut t = target(Kind::Webhook);
        t.url = url;
        let out = fire(&[t.clone()], &cx(), 1_700_000_000);
        recv(&rx);
        assert_eq!(out.len(), 1, "one target, one outcome");
        assert_eq!(out[0].0, target_key(&t), "stored under its own identity");
        assert_eq!(out[0].1.code, 204);
        assert_eq!(out[0].1.error, "", "a 2xx is not a failure");
        assert_eq!(out[0].1.at, 1_700_000_000);
        assert!(!out[0].1.test, "a fire is a real delivery, not a test");
    }

    #[test]
    fn a_rejected_delivery_records_what_the_target_said() {
        // The case this whole row exists for: the token expired, the
        // media server says so on every download, and the only place it
        // was ever written was a log line.
        let (url, rx) = capture_answering("401 Unauthorized", "bad token");
        let mut t = target(Kind::Webhook);
        t.url = url;
        let out = fire(&[t], &cx(), 42);
        recv(&rx);
        assert_eq!(out.len(), 1);
        let o = &out[0].1;
        assert_eq!(o.code, 0, "no status is claimed for a refused send");
        assert!(o.error.contains("HTTP 401"), "{}", o.error);
        assert!(
            o.error.contains("bad token"),
            "the target's own words: {}",
            o.error
        );
    }

    #[test]
    fn an_unreachable_target_records_a_failure_that_names_no_url() {
        // Same secrecy contract as the log: a webhook path IS the
        // credential, and this string is shipped to the browser in
        // get_config and rendered on the settings row.
        let mut t = target(Kind::Webhook);
        t.url = "http://127.0.0.1:1/api/webhooks/12345/SUPERSECRETTOKEN".into();
        let out = fire(&[t], &cx(), 7);
        assert_eq!(out.len(), 1);
        let o = &out[0].1;
        assert_eq!(o.code, 0);
        assert!(!o.error.is_empty(), "an unreachable target is a failure");
        assert!(!o.error.contains("SUPERSECRETTOKEN"), "{}", o.error);
        assert!(!o.error.contains("webhooks"), "{}", o.error);
    }

    #[test]
    fn a_target_that_did_not_want_this_job_records_nothing() {
        // Absence, not a recorded success: a category-filtered target
        // that sat out this download has not delivered anything, and a
        // row claiming it did would be a lie in the other direction.
        let mut t = target(Kind::Webhook);
        t.url = "http://127.0.0.1:1".into();
        t.category = "tv".into();
        assert!(fire(&[t.clone()], &cx(), 1).is_empty(), "category filtered");
        t.category = String::new();
        t.enabled = false;
        assert!(fire(&[t.clone()], &cx(), 1).is_empty(), "switched off");
        t.enabled = true;
        let mut failed = cx();
        failed.status = "Failed";
        failed.event = "failed".into();
        assert!(
            fire(&[t], &failed, 1).is_empty(),
            "did not ask about failures"
        );
    }

    #[test]
    fn each_target_keeps_its_own_outcome() {
        // Two rows pointing at the same media server with different
        // tokens are two targets, and one of them failing must not paint
        // the other one red.
        let a = target(Kind::Kodi);
        let mut b = a.clone();
        b.name = "upstairs".into();
        let mut c = a.clone();
        c.url = "http://10.0.0.6:8080".into();
        let mut d = a.clone();
        d.kind = Kind::Webhook;
        let keys = [
            target_key(&a),
            target_key(&b),
            target_key(&c),
            target_key(&d),
        ];
        let uniq: std::collections::HashSet<&String> = keys.iter().collect();
        assert_eq!(uniq.len(), 4, "name, url and kind each identify a row");
        // The token is deliberately NOT part of the identity: fixing a
        // password must not orphan the row's history.
        let mut retoken = a.clone();
        retoken.token = "new".into();
        assert_eq!(target_key(&a), target_key(&retoken));
    }

    #[test]
    fn a_transport_error_never_names_the_url() {
        // ureq's own Display for a transport error leads with the full
        // request URL. A webhook's path and query are its bearer token, and
        // this string is printed to stderr, which logtee puts in both the
        // dashboard log ring and the log file people paste into support
        // threads. The failure has to be reportable without it.
        let mut t = target(Kind::Webhook);
        t.url = "http://127.0.0.1:1/api/webhooks/12345/SUPERSECRETTOKEN?k=SECRETQUERY".into();
        let e = send(&t, &cx()).unwrap_err();
        assert!(!e.contains("SUPERSECRETTOKEN"), "path token leaked: {e}");
        assert!(!e.contains("SECRETQUERY"), "query secret leaked: {e}");
        assert!(!e.contains("webhooks"), "path leaked: {e}");
        assert!(!e.contains("127.0.0.1"), "host leaked from the URL: {e}");
        // Still worth reading: it must say what went wrong.
        assert!(
            e.to_lowercase().contains("refused") || e.to_lowercase().contains("connect"),
            "{e}"
        );
    }

    #[test]
    fn a_url_without_a_scheme_is_not_echoed_back() {
        let mut t = target(Kind::Webhook);
        t.url = "discord.com/api/webhooks/12345/SUPERSECRETTOKEN".into();
        let e = send(&t, &cx()).unwrap_err();
        assert!(e.contains("http://"), "still says what is wanted: {e}");
        assert!(
            !e.contains("SUPERSECRETTOKEN"),
            "the typed URL is a secret too: {e}"
        );
    }

    #[test]
    fn a_substituted_value_is_not_rescanned_for_placeholders() {
        // A release name is attacker-chosen and is not sanitised for
        // braces. Substituting key by key over one string let the {dir} in
        // this name expand on the following pass, handing the local path to
        // a webhook whose template only ever mentioned {name}.
        let mut c = cx();
        c.name = "Some.Release.{dir}.{error}".into();
        let out = c.render_body(r#"{"text":"{name}"}"#);
        assert!(
            out.contains("{dir}"),
            "the name's braces survive verbatim: {out}"
        );
        assert!(
            !out.contains("/downloads"),
            "the download path leaked: {out}"
        );
        let v: serde_json::Value = serde_json::from_str(&out).expect("still valid JSON");
        assert_eq!(v["text"], "Some.Release.{dir}.{error}");
    }

    #[test]
    fn basic_auth_encodes_the_kodi_default() {
        // Kodi's out-of-the-box user with a blank password.
        assert_eq!(basic_auth("kodi:"), Some("Basic a29kaTo=".into()));
        assert_eq!(
            basic_auth(""),
            None,
            "no token = no header, not an empty one"
        );
        assert_eq!(b64(b"a"), "YQ==");
        assert_eq!(b64(b"ab"), "YWI=");
        assert_eq!(b64(b"abc"), "YWJj");
        assert_eq!(b64(b"user:pass"), "dXNlcjpwYXNz");
    }
}
