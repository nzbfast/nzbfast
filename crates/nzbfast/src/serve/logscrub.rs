//! §163 item 5: anonymise a log tail on the way OUT of the API.
//!
//! [`redact_apikey`] and [`redact_url_creds`] guard specific call sites
//! on the way IN, which covers everything we knew was a credential at
//! the moment we wrote the line. Anything that reached the ring by
//! another path - a library's Display, a child process's stderr, a line
//! written before either helper existed - left by this door untouched,
//! and this door is the one a user copies into a GitHub issue. v1.2.1
//! shipped with a provider hostname in a public artifact for exactly
//! that reason.
//!
//! So the scrub is applied at the EXIT instead of trusting the entrance:
//! `mode=log` (the dashboard's log pane) and the JSON-RPC `log`/
//! `loadlog` methods both go through here.

use super::Daemon;
use nzbkit::sync::MutexExt as _;

/// The identities and secrets of one running daemon, as an ordered list
/// of literal replacements plus the two URL passes.
///
/// Built once per request rather than per line: a 1,000-line tail with
/// six servers would otherwise re-read the config a thousand times.
pub(crate) struct LogScrub {
    /// `(needle, replacement, case_blind)`, longest needle first.
    subs: Vec<(String, String, bool)>,
}

/// Shortest literal worth blanking. `scrub_indexer_body_error` uses 8
/// for API keys on the grounds that blanking a 3-character string
/// redacts ordinary prose; identities are held to a lower bar because
/// a 4-character username is still a username, and the cost of a false
/// positive here is one unreadable word in a log rather than a wrong
/// answer anywhere.
const MIN_KEY: usize = 8;
const MIN_IDENT: usize = 4;

impl LogScrub {
    /// Everything this install would rather not publish: its provider
    /// hosts, usernames and passwords, its indexer keys, its
    /// notification targets' tokens and webhook secrets, and its own API
    /// keys.
    ///
    /// Hosts and usernames become NUMBERED placeholders rather than
    /// `***`, because a scrubbed log still has to be readable: "server2
    /// timed out on 40 of 60 sockets" is the sentence someone opened the
    /// issue about, and three servers all blanked to the same token make
    /// it unanswerable. The numbering is config order, so it is stable
    /// across a session and across two pastes of the same log.
    pub(crate) fn new(d: &Daemon) -> LogScrub {
        let mut subs: Vec<(String, String, bool)> = Vec::new();
        let mut push = |needle: Option<String>, with: String, min: usize, blind: bool| {
            if let Some(n) = needle.filter(|n| n.chars().count() >= min) {
                subs.push((n, with, blind));
            }
        };
        if let Ok(cfg) = nzbkit::config::Config::load(&d.cfg_path) {
            for (i, s) in cfg.servers.iter().enumerate() {
                let n = i + 1;
                // A host is matched case-blind: DNS is, and a line that
                // spells it back from a certificate or an error message
                // does not have to agree with config.json about case.
                push(
                    Some(s.host.clone()),
                    format!("<server{n}>"),
                    MIN_IDENT,
                    true,
                );
                push(s.username.clone(), format!("<user{n}>"), MIN_IDENT, true);
                // Passwords keep no identity worth preserving, and they
                // are matched exactly: a password IS case-significant,
                // and folding case here would blank more than it should.
                push(s.password.clone(), "***".into(), MIN_IDENT, false);
            }
        }
        for i in d.indexers.lock_ok().iter() {
            push(Some(i.apikey.clone()), "***".into(), MIN_KEY, false);
        }
        // Every notification target's credential. `Target::token` is a
        // Plex token, a Jellyfin/Emby API key, a Telegram
        // `<bot_token>/<chat_id>`, a Pushover pair, an ntfy or Gotify
        // token, or a Kodi/SMTP `user:password` - one field, eleven
        // different secrets, and `notify.rs` is the only thing standing
        // between any of them and the ring today. The target's URL is
        // deliberately NOT a literal here: for Discord, Slack, Webhook
        // and Apprise the URL's PATH is the credential, and a whole-URL
        // literal only matches a line that spells it exactly. That case
        // is the url pass's, and it is why the url pass stays wide (see
        // the note on `line`).
        for t in d.notify_targets.lock_ok().iter() {
            push(Some(t.token.clone()), "***".into(), MIN_KEY, false);
            // `secret` is the webhook HMAC key - write-only in
            // get_config for the same reason `token` is.
            push(Some(t.secret.clone()), "***".into(), MIN_KEY, false);
        }
        for k in [
            d.apikey.lock_ok().clone(),
            d.nzbkey.lock_ok().clone(),
            d.omdb_key.lock_ok().clone(),
            // `tmdb_key` is `omdb_key`'s exact sibling - a live,
            // user-pasted metadata key - and was missing from this list
            // until 23 Aug 2026 for no reason anyone recorded.
            d.tmdb_key.lock_ok().clone(),
            // Not a key the user typed: the per-install secret behind
            // every `/stream/{id}?t=` token. It is never deliberately
            // printed, which is exactly the argument for having the
            // backstop know it - one leak forges playback tokens for
            // every job this install will ever have.
            Some(d.stream_secret.clone()),
        ] {
            push(k, "***".into(), MIN_KEY, false);
        }
        // Longest first: a provider whose username is a prefix of its
        // hostname would otherwise have the shorter needle eat the
        // longer one's match and leave the tail of a hostname behind.
        subs.sort_by_key(|(n, _, _)| std::cmp::Reverse(n.len()));
        LogScrub { subs }
    }

    /// One line, scrubbed.
    ///
    /// The two URL passes run FIRST and the literals after, so a host
    /// that survives `redact_url_creds` (which keeps `scheme://host` on
    /// purpose - it names who failed) is still anonymised by the pass
    /// that knows it is a provider.
    ///
    /// **`redact_url_creds` cuts every URL to `scheme://host:port` and
    /// appends `/...`, credential or not, and that WIDTH IS DELIBERATE
    /// here.** A narrower export pass - strip userinfo and the query,
    /// keep the path - was costed on 23 Aug 2026 and declined; the
    /// reasoning is in TODO §163 item 5 and the short form is:
    ///
    /// - Every site where a third-party URL's path would tell a reader
    ///   anything already runs `redact_url_creds` ON THE WAY IN, and
    ///   those ~8 sites are staying. Their paths are gone before the
    ///   line reaches the ring, so a narrower pass here cannot give any
    ///   of them back. The only lines it could change are the ones that
    ///   arrived UNGUARDED.
    /// - Measured over 112,274 real log lines from three installs, the
    ///   unguarded set is 39 lines, 0.03%, and every one is either the
    ///   startup banner (`http://localhost:<port>/`, `/api`) or the
    ///   hardcoded update-check URL. None carried userinfo, a query, or
    ///   a third-party host. Their paths are constants the reader
    ///   already has.
    /// - The unguarded set is also exactly where an unknown credential
    ///   would surface, and for four of the eleven `notify::Kind`s -
    ///   Discord, Slack, Webhook, Apprise - the URL's PATH *is* the
    ///   credential. `notify.rs` guards that per-call-site by hand; this
    ///   door is the backstop for the site that forgets.
    ///
    /// So: keep the wide cut, and pay for it in a truncated banner.
    pub(crate) fn line(&self, s: &str) -> String {
        let mut out = super::indexers::redact_url_creds(&super::indexers::redact_apikey(s));
        for (needle, with, blind) in &self.subs {
            out = if *blind {
                replace_ignore_ascii_case(&out, needle, with)
            } else {
                out.replace(needle.as_str(), with)
            };
        }
        out
    }

    /// A whole tail, scrubbed.
    pub(crate) fn tail(&self, lines: Vec<String>) -> Vec<String> {
        lines.iter().map(|l| self.line(l)).collect()
    }
}

/// `str::replace`, ASCII-case-blind on the needle.
///
/// Hostnames and usernames are ASCII in every shape that reaches here
/// (DNS labels and NNTP AUTHINFO both are), so an ASCII fold is the
/// whole of the case question and needs no Unicode table. Byte indices
/// are safe for the same reason: the needle is ASCII, so every match
/// starts and ends on a character boundary of the haystack whatever
/// non-ASCII is around it.
fn replace_ignore_ascii_case(hay: &str, needle: &str, with: &str) -> String {
    if needle.is_empty() || !needle.is_ascii() {
        return hay.replace(needle, with);
    }
    let low = hay.to_ascii_lowercase();
    let pat = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(hay.len());
    let mut at = 0;
    while let Some(p) = low[at..].find(&pat) {
        let p = at + p;
        out.push_str(&hay[at..p]);
        out.push_str(with);
        at = p + pat.len();
    }
    out.push_str(&hay[at..]);
    out
}

#[cfg(test)]
#[path = "logscrub_tests.rs"]
mod logscrub_tests;
