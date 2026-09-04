//! Pre feed over IRC: the one public told-channel that can name a post
//! whose name is nowhere on the wire.
//!
//! A scanner reads what was posted. When an uploader strips the name -
//! random subject, random inner filenames, encrypted archive headers -
//! there is nothing left to read, and no amount of cleverness recovers
//! it (see the obfuscation research). What DOES exist is a relay: a
//! handful of public IRC channels carry one line per release, and that
//! line pairs the real title with the filename it was posted under. The
//! pairing is the whole point. Match the posted filename we already
//! indexed against the relay's filename field and the release gets its
//! real name, obfuscation or not.
//!
//! This module is two halves that meet at [`PreLine`]:
//! - a defensive parser for the relay wire format, and
//! - a small async IRC client that joins the configured channels and
//!   hands every channel message to a callback.
//!
//! Deliberately absent: no NickServ, no accounts, no registration, no
//! sending anything to a channel. The client speaks the minimum needed
//! to be a well-behaved listener, because that is all a read-only relay
//! consumer needs and every extra capability is another thing that can
//! misbehave against somebody else's network.

use std::time::Duration;
use tracing::warn;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// What a relay line announces about a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PreKind {
    /// First announcement.
    #[default]
    New,
    /// A field arriving late (very often the filename itself - the
    /// field this whole feature exists for).
    Upd,
    /// The release was nuked. Still a naming fact, so it is stored and
    /// the reason is kept.
    Nuk,
}

impl PreKind {
    fn parse(s: &str) -> Option<PreKind> {
        match s.trim().to_ascii_uppercase().as_str() {
            "NEW" => Some(PreKind::New),
            "UPD" => Some(PreKind::Upd),
            "NUK" | "NUKE" | "UNNUK" | "MODNUK" => Some(PreKind::Nuk),
            _ => None,
        }
    }
}

/// One parsed relay line. Every field except `title` is optional,
/// because in practice every field except the title is optional on the
/// wire - a NEW line often carries nothing but a title and a category,
/// and the filename arrives minutes later on an UPD.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreLine {
    pub kind: PreKind,
    /// TT - the real release name. The payload.
    pub title: String,
    /// FN - the filename it was POSTED under. The join key.
    pub filename: String,
    /// SZ, normalized to bytes (0 = absent or unparseable).
    pub size: u64,
    /// FL, file count (0 = absent).
    pub files: u32,
    /// CT - the relay's category string, kept verbatim. We do not map it
    /// onto our own kinds: the release name we just learned is a better
    /// classifier than a free-text field, and re-classifying from the
    /// name is what the ingest path already does.
    pub category: String,
    /// SC - which pre source the relay heard it from. Provenance.
    pub source: String,
    /// RQ, request id half (`12345:alt.binaries.x` splits into this and
    /// `group`). Recorded, not acted on: the request-id ecosystem was
    /// measured extinct, so this is a stored fact and nothing else.
    pub requestid: String,
    /// RQ, group half - or an explicit group field when the relay sends
    /// one.
    pub group: String,
    /// DT, unix seconds (0 = absent or unparseable).
    pub date: i64,
    /// NUKED reason, when the line carries one.
    pub nuke_reason: String,
}

impl PreLine {
    /// True when this line can name something: it has both halves of the
    /// pairing. A title-only line is a fine thing for a pre database to
    /// hold, but it cannot name an obfuscated post, which is the only
    /// job we are asking of this feed.
    pub fn nameable(&self) -> bool {
        !self.title.is_empty() && !self.filename.is_empty()
    }
}

/// Does this field value mean "the relay has nothing here"?
///
/// Deliberately a small closed list, matched case-insensitively after
/// trimming: anything longer or stranger is treated as real data,
/// because a release genuinely named `NONE-GROUP` must survive. `-`
/// and `?` are single-character placeholders relays use in fixed-width
/// output; no real filename or title is one character of punctuation.
pub fn is_absent_marker(v: &str) -> bool {
    let t = v.trim();
    t.eq_ignore_ascii_case("n/a")
        || t.eq_ignore_ascii_case("na")
        || t.eq_ignore_ascii_case("none")
        || t.eq_ignore_ascii_case("null")
        || t.eq_ignore_ascii_case("unknown")
        || t == "-"
        || t == "?"
}

/// Strip IRC formatting so the parser sees plain text.
///
/// Relay bots colour their output heavily, and the codes land INSIDE
/// field values (`[TT: \x0304Some.Release\x03]`), so this has to run
/// before any bracket scanning. Colour is `\x03` optionally followed by
/// `NN[,NN]`; the rest are bare toggles.
pub fn strip_formatting(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            // Colour: eat up to 2 digits, then optionally ',' + up to 2
            // digits. A bare \x03 (colour reset) eats nothing more.
            0x03 => {
                i += 1;
                let mut digits = 0;
                while i < b.len() && b[i].is_ascii_digit() && digits < 2 {
                    i += 1;
                    digits += 1;
                }
                // The comma only belongs to the colour code when a digit
                // follows it - "\x0304,text" is colour 04 then a literal
                // comma, and eating it would corrupt a title.
                if digits > 0 && i + 1 < b.len() && b[i] == b',' && b[i + 1].is_ascii_digit() {
                    i += 1;
                    let mut bg = 0;
                    while i < b.len() && b[i].is_ascii_digit() && bg < 2 {
                        i += 1;
                        bg += 1;
                    }
                }
            }
            // bold, italic, reverse, underline, reset, monospace,
            // hex-colour (\x04 takes 6 hex digits, same shape as above).
            0x02 | 0x0f | 0x11 | 0x16 | 0x1d | 0x1e | 0x1f => i += 1,
            0x04 => {
                i += 1;
                let mut n = 0;
                while i < b.len() && b[i].is_ascii_hexdigit() && n < 6 {
                    i += 1;
                    n += 1;
                }
            }
            _ => {
                // Copy one whole UTF-8 char, not one byte: titles carry
                // non-ASCII and slicing mid-sequence would panic.
                let start = i;
                i += 1;
                while i < b.len() && (b[i] & 0xc0) == 0x80 {
                    i += 1;
                }
                out.push_str(&s[start..i]);
            }
        }
    }
    out
}

/// Pull every `[KEY: value]` group out of a line, in wire order.
///
/// Written as a scanner rather than a split because both halves vary:
/// relays differ in spacing (`[TT:x]` / `[TT: x]`), in order, in which
/// fields they send at all, and titles legitimately contain brackets
/// (`Some.Show.S01E01.[REPACK]-GRP`). Bracket depth handles the last
/// one; anything that does not look like `KEY:` is skipped rather than
/// guessed at.
fn fields(line: &str) -> Vec<(String, String)> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'[' {
            i += 1;
            continue;
        }
        // KEY: short, alphanumeric, then a colon. Anything else and this
        // '[' is just a character in somebody's release name.
        let mut j = i + 1;
        while j < b.len() && b[j].is_ascii_alphanumeric() && j - i <= 8 {
            j += 1;
        }
        if j >= b.len() || b[j] != b':' || j == i + 1 {
            i += 1;
            continue;
        }
        let key = line[i + 1..j].to_ascii_uppercase();
        // Value runs to the ']' that closes THIS '['.
        let mut depth = 1usize;
        let mut k = j + 1;
        while k < b.len() {
            match b[k] {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            k += 1;
        }
        if depth != 0 {
            // Unterminated - a truncated line. Take the rest and stop.
            out.push((key, line[j + 1..].trim().to_string()));
            break;
        }
        out.push((key, line[j + 1..k].trim().to_string()));
        i = k + 1;
    }
    out
}

/// `1.4GB` / `700MB` / `1400M` / `1234567` → bytes. 0 when it makes no
/// sense, which is treated everywhere as "the relay did not say".
fn parse_size(s: &str) -> u64 {
    let s = s.trim();
    // `eaten` counts the ORIGINAL bytes consumed, which is not the
    // length of `num` once thousands separators have been dropped -
    // slicing by num.len() put the unit lookup 1 char short on
    // "1,024 KB" and read it as bytes.
    let mut eaten = 0usize;
    let num: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
        .inspect(|c| eaten += c.len_utf8())
        .filter(|c| *c != ',')
        .collect();
    let Ok(v) = num.parse::<f64>() else { return 0 };
    if !v.is_finite() || v < 0.0 {
        return 0;
    }
    let unit = s[eaten.min(s.len())..].trim_start().to_ascii_uppercase();
    let mult: f64 = match unit.as_bytes().first() {
        Some(b'K') => 1024.0,
        Some(b'M') => 1024.0 * 1024.0,
        Some(b'G') => 1024.0 * 1024.0 * 1024.0,
        Some(b'T') => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        // Bare number = bytes. Relays that send "1400" mean MB about as
        // often as bytes, but guessing wrong inflates a size by 10^6 and
        // sizes are advisory here - take the literal reading.
        _ => 1.0,
    };
    let bytes = v * mult;
    // Guard the cast: an absurd relay value must not wrap to something
    // small and plausible.
    if bytes >= u64::MAX as f64 {
        u64::MAX
    } else {
        bytes as u64
    }
}

/// `20F` / `20` / `20 files` → 20.
fn parse_files(s: &str) -> u32 {
    s.trim()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

/// Relay dates come as unix seconds or as `YYYY-MM-DD HH:MM:SS` (UTC).
/// Both are handled; anything else yields 0 and the caller stamps its
/// own arrival time instead.
fn parse_date(s: &str) -> i64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    // A bare integer that is plausibly a unix timestamp (1990..2100).
    if let Ok(v) = s.parse::<i64>() {
        return if (631_152_000..=4_102_444_800).contains(&v) {
            v
        } else {
            0
        };
    }
    let digits: Vec<i64> = s
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse().ok())
        .collect();
    if digits.len() < 3 {
        return 0;
    }
    let (y, mo, d) = (digits[0], digits[1], digits[2]);
    if !(1990..=2100).contains(&y) || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return 0;
    }
    let (h, mi, sec) = (
        digits.get(3).copied().unwrap_or(0),
        digits.get(4).copied().unwrap_or(0),
        digits.get(5).copied().unwrap_or(0),
    );
    if h > 23 || mi > 59 || sec > 60 {
        return 0;
    }
    // days_from_civil (Howard Hinnant's algorithm) - no chrono in the
    // tree and this is the only date arithmetic the feed needs.
    let y2 = y - i64::from(mo <= 2);
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + h * 3_600 + mi * 60 + sec
}

/// Parse one relay message. `None` when the line is not a pre
/// announcement at all (channel chatter, a bot's own status line, a
/// join notice).
///
/// Defensive by construction: fields are optional, order does not
/// matter, unknown fields are ignored, and the only hard requirement is
/// a non-empty title. A relay that adds a field tomorrow keeps working;
/// one that drops a field keeps working with less.
pub fn parse_line(raw: &str) -> Option<PreLine> {
    let text = strip_formatting(raw);
    let text = text.trim();
    let fs = fields(text);
    if fs.is_empty() {
        // Not the bracket-field family. The relays the 2026 survey
        // actually recommends send none of that - try their plain
        // shapes before giving up. Ordering is safe: a line with any
        // `[KEY: v]` group never reaches here, and none of the plain
        // shapes can produce one.
        return parse_plain(text);
    }
    // The kind prefix ("NEW:", "UPD:", …) sits before the first field.
    // Some relays omit it entirely, which reads as NEW.
    let head = text.split('[').next().unwrap_or("");
    let kind = head
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|t| !t.is_empty())
        .find_map(PreKind::parse)
        .unwrap_or(PreKind::New);
    let mut p = PreLine {
        kind,
        ..Default::default()
    };
    for (k, v) in fs {
        // A relay that has no value for a field often says so in words
        // rather than omitting the field. Measured live on synirc
        // 1 Aug 2026: every line carried `[FN: N/A]`, which was stored
        // verbatim, so `nameable()` answered true for lines that can
        // name nothing AND every such row shared the join key "na" -
        // one bogus key that any filename lookup would collide on. An
        // absent value must reach the rest of the code as absent.
        // Re-measured 2 Sep 2026: 119 of 119 lines `FN: N/A`, and the
        // bot's only sources were srrdb, xrel and xrelp2p, which carry
        // no posted-filename field, so the marker is structural, not
        // a quiet hour (research/SYNIRC-FN-REMEASURE-2026-09.md).
        if v.is_empty() || is_absent_marker(&v) {
            continue;
        }
        match k.as_str() {
            "TT" | "TITLE" | "PRE" => p.title = v,
            "FN" | "FILENAME" | "NAME" => p.filename = v,
            "SZ" | "SIZE" => p.size = parse_size(&v),
            "FL" | "FILES" => p.files = parse_files(&v),
            "CT" | "CAT" | "CATEGORY" => p.category = v,
            "SC" | "SOURCE" => p.source = v,
            "GRP" | "GROUP" | "NG" => p.group = v,
            "DT" | "DATE" | "TS" => p.date = parse_date(&v),
            "RQ" | "REQ" | "REQID" => {
                // "12345:alt.binaries.teevee", or just the id.
                match v.split_once(':') {
                    Some((id, grp)) => {
                        p.requestid = id.trim().to_string();
                        if p.group.is_empty() {
                            p.group = grp.trim().to_string();
                        }
                    }
                    None => p.requestid = v,
                }
            }
            "NUKED" | "NUKE" | "REASON" => {
                p.nuke_reason = v;
                p.kind = PreKind::Nuk;
            }
            // Unknown field. Relays add these; ignoring them is the
            // whole reason this is a scanner and not a fixed grammar.
            _ => {}
        }
    }
    // A "line" with fields but no title names nothing and is not worth a
    // row. This is also what rejects a bot's `[Status: connected]`.
    if p.title.is_empty() {
        return None;
    }
    Some(p)
}

/// The announcement keyword that opens every plain-format line,
/// mapped to what the line is telling us. `None` = not an announcement
/// keyword, so the line is chatter.
fn plain_kind(word: &str) -> Option<PreKind> {
    match word.trim().to_ascii_uppercase().as_str() {
        "PRE" => Some(PreKind::New),
        "INFO" | "UPD" => Some(PreKind::Upd),
        // UNNUKE and MODNUKE still land as Nuk on purpose - phase 1's
        // rule (a nuke is sticky, and nuked only demotes a suggestion,
        // never blocks a fact) already made that call.
        "NUKE" | "NUK" | "UNNUKE" | "MODNUKE" | "OLDNUKE" => Some(PreKind::Nuk),
        _ => None,
    }
}

/// The `pre | SECTION | RELEASE` shape (predataba.se). `None` when the
/// line is not that shape, which is [`parse_plain`]'s cue to keep trying.
fn parse_pipe(t: &str) -> Option<PreLine> {
    let parts: Vec<&str> = t.split('|').map(str::trim).collect();
    let kind = plain_kind(parts[0])?;
    if parts.len() < 3 {
        return None;
    }
    let title = parts[2];
    if title.is_empty() || is_absent_marker(title) {
        return None;
    }
    let mut p = PreLine {
        kind,
        title: title.to_string(),
        ..Default::default()
    };
    if !is_absent_marker(parts[1]) {
        p.category = parts[1].to_string();
    }
    if kind == PreKind::Nuk && parts.len() > 3 {
        p.nuke_reason = parts[3..].join(" ");
    }
    Some(p)
}

/// The three plain wire shapes the 2026 relay survey found live
/// (research/PREDB-RELAYS-DEEP-2026-08.md), tried in order:
///
/// ```text
/// predataba.se : pre | SECTION | RELEASE            (pipe-delimited)
/// corrupt-net  : PRE: [SECTION] RELEASE
/// scenep2p     : (PRE) (SECTION) RELEASE
/// ```
///
/// None of these carry a filename or a timestamp: the caller's arrival
/// clock (`seen_at`) is the pre time, which is fine - relay latency is
/// seconds. The title is anchored from the LEFT (keyword, then
/// section), and what remains is taken opaquely, per the survey's
/// warning that the trailing field has no terminator.
fn parse_plain(text: &str) -> Option<PreLine> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    // predataba.se: split on '|'. The release field is the one shape
    // that cannot collide with its delimiter ('|' never appears in a
    // release name), so the fields are taken verbatim.
    //
    // Tried, not COMMITTED to: a pipe anywhere in the line used to route
    // it here for good, so a corrupt-net line carrying one (in a nuke
    // reason, say) parsed as a broken pipe line and was dropped without
    // the shapes below ever seeing it.
    if t.contains('|')
        && let Some(p) = parse_pipe(t)
    {
        return Some(p);
    }
    // corrupt-net "PRE: [SECTION] RELEASE" / scenep2p
    // "(PRE) (SECTION) RELEASE". Both are keyword, optional bracketed
    // section, then the release.
    let (word, mut rest) = if let Some(r) = t.strip_prefix('(') {
        let (w, r) = r.split_once(')')?;
        (w, r.trim_start())
    } else {
        let (w, r) = t.split_once(':')?;
        (w, r.trim_start())
    };
    let kind = plain_kind(word)?;
    let mut category = String::new();
    for (open, close) in [('[', ']'), ('(', ')')] {
        if let Some(r) = rest.strip_prefix(open) {
            if let Some((sec, tail)) = r.split_once(close) {
                if !is_absent_marker(sec) {
                    category = sec.trim().to_string();
                }
                rest = tail.trim_start();
            }
            break;
        }
    }
    // The title is the next whitespace token. Verbatim would be truer
    // to "treat the tail as opaque", but a relay operator appending a
    // suffix some day would then land INSIDE every stored title with no
    // parse error to notice it by - taking the first token survives
    // both futures, because release names never contain spaces. A
    // trailing ")" from the fully-parenthesized variant is shed.
    let mut it = rest.split_whitespace();
    // ONE wrapping paren from the fully-parenthesized variant, not every
    // trailing one: `trim_end_matches` would eat a release name's own.
    let title = it.next()?;
    let title = title.strip_prefix('(').unwrap_or(title);
    let title = title.strip_suffix(')').unwrap_or(title);
    if title.is_empty() || is_absent_marker(title) {
        return None;
    }
    // Guard against prose that happens to open with a keyword ("PRE:
    // the bot is back up"): a release name is dotted or dashed or
    // underscored, a word is not.
    if !title.contains(['.', '-', '_']) {
        return None;
    }
    let mut p = PreLine {
        kind,
        title: title.to_string(),
        category,
        ..Default::default()
    };
    if kind == PreKind::Nuk {
        p.nuke_reason = it.collect::<Vec<_>>().join(" ");
    }
    Some(p)
}

/// The match key both sides of the join are reduced to: lowercase with
/// every separator removed.
///
/// Exact-match is tried first everywhere this is used - the posted
/// filename and the relay's FN field describe the same bytes and are
/// usually byte-identical. This is the safety net for the cases where
/// they are not: a relay that lowercased the name, or one that wrote
/// `abc_123` where the post said `abc-123`.
pub fn match_key(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

// ===== the IRC client =====

/// Where to listen, and as whom.
#[derive(Debug, Clone)]
pub struct IrcConfig {
    pub host: String,
    pub port: u16,
    /// Require TLS.
    ///
    /// This used to mean "TLS when the network offers it", with an
    /// automatic fallback to the plain port on any connect, certificate
    /// or handshake failure - and the note here claimed plain text cost
    /// only the confidentiality of the fact that we are listening. That
    /// was wrong in the direction that matters. An on-path attacker can
    /// BLOCK 6697 to force the downgrade, answer on 6667, and inject
    /// whatever channel lines it likes; those lines name releases the
    /// exact legs then match on automatically. TLS is what makes the
    /// feed's contents attributable to the relay, not just private.
    pub tls: bool,
    /// Accept the plain-text port when TLS is unavailable.
    ///
    /// Off by default, and deliberately not "off unless it fails": a
    /// downgrade an attacker can trigger is not a fallback. Operators on
    /// a network with no TLS relay can set NZBFAST_PREDB_ALLOW_PLAINTEXT
    /// and get the old behaviour, having chosen it.
    pub allow_plaintext: bool,
    /// Base nick. A random suffix is appended so two nzbfast installs on
    /// one network do not collide (and so a rejoin after a netsplit does
    /// not fight its own ghost).
    pub nick: String,
    pub channels: Vec<String>,
}

impl Default for IrcConfig {
    fn default() -> Self {
        IrcConfig {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            tls: true,
            allow_plaintext: false,
            nick: DEFAULT_NICK.to_string(),
            channels: DEFAULT_CHANNELS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

pub const DEFAULT_HOST: &str = "irc.synirc.net";
/// Plain-text port. The TLS attempt uses [`TLS_PORT`] and falls back
/// here, so this stays the configured value.
pub const DEFAULT_PORT: u16 = 6667;
pub const TLS_PORT: u16 = 6697;
pub const DEFAULT_NICK: &str = "nzbfast";
/// The relay channels that carry the filename field. Editable in
/// settings; this is the default because it is the one the public
/// stacks document. `#nZEDbPRE` used to sit beside it and was dropped
/// 2 Sep 2026: a passive 86-minute listen found its topic reading
/// `DEAD. nZEDb PRE Channel` and zero lines on it against 119 on
/// `#PreNNTmux`, so joining it was a wasted JOIN on every reconnect
/// (research/SYNIRC-FN-REMEASURE-2026-09.md).
pub const DEFAULT_CHANNELS: &[&str] = &["#PreNNTmux"];

/// Why the client stopped, which decides how long before it tries
/// again. The distinction matters: a dropped connection deserves a
/// prompt retry, and being told to go away deserves hours.
#[derive(Debug)]
pub enum IrcStop {
    /// Socket died, handshake timed out, DNS failed. Retry soon.
    Transient(String),
    /// The server said no: KILL, K-line, a `465 ERR_YOUREBANNEDCREEP`,
    /// or an ERROR with a ban-shaped reason. Retry in hours, if at all.
    Rejected(String),
    /// The caller asked us to stop (setting switched off).
    Cancelled,
}

impl std::fmt::Display for IrcStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrcStop::Transient(m) => write!(f, "{m}"),
            IrcStop::Rejected(m) => write!(f, "rejected: {m}"),
            IrcStop::Cancelled => write!(f, "stopped"),
        }
    }
}

/// A nick suffix that differs per process and per reconnect.
///
/// Not a security value - it exists so two installs on one network do
/// not collide - so the cheap std hasher is the right source rather
/// than pulling a CSPRNG into nzbkit for it.
pub fn nick_suffix() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
            .unwrap_or(0),
    );
    h.write_u32(std::process::id());
    let mut v = h.finish();
    // 6 chars of base36 - enough that a collision is not a thing we
    // think about, short enough to stay inside every network's nick cap
    // next to the base nick.
    let mut s = String::new();
    for _ in 0..6 {
        let d = (v % 36) as u32;
        s.push(char::from_digit(d, 36).unwrap_or('0'));
        v /= 36;
    }
    s
}

/// Either kind of socket, so the read loop is written once.
enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => std::pin::Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => std::pin::Pin::new(&mut **s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => std::pin::Pin::new(&mut **s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => std::pin::Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

/// How long the server may take to send us `001` before we give up on
/// the connection. Generous: some networks run ident lookups first.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(90);
/// No traffic at all for this long means the link is dead even though
/// the socket says otherwise (the classic silent netsplit).
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// Server lines are capped at 512 bytes by the protocol; anything much
/// larger is a hostile or broken peer, and reading it unbounded is how
/// a listener turns into a memory sink.
const MAX_LINE: u64 = 8192;

/// What the client reports back for each channel message it sees.
pub struct IrcMessage<'a> {
    pub channel: &'a str,
    pub nick: &'a str,
    pub text: &'a str,
}

/// Connect, register, join, and pump channel messages into `on_msg`
/// until something goes wrong or `stop` says to quit.
///
/// Returns the reason it stopped so the caller can pick a backoff. The
/// function never retries on its own: the retry policy belongs with the
/// caller that owns the setting, and burying it here is how a client
/// ends up hammering a network that has already said no.
pub async fn run_once(
    cfg: &IrcConfig,
    mut on_msg: impl FnMut(IrcMessage<'_>),
    stop: &(dyn Fn() -> bool + Send + Sync),
) -> IrcStop {
    let nick = format!("{}{}", cfg.nick.trim(), nick_suffix());
    let stream = match connect(cfg).await {
        Ok(s) => s,
        Err(e) => return IrcStop::Transient(e),
    };
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = BufReader::new(rd);
    // Registration. No PASS, no SASL, no NickServ - we are an anonymous
    // listener and asking for anything more would be a lie about what
    // this is.
    let hello = format!("NICK {nick}\r\nUSER {nick} 0 * :nzbfast pre listener\r\n");
    if let Err(e) = wr.write_all(hello.as_bytes()).await {
        return IrcStop::Transient(format!("register: {e}"));
    }

    let mut registered = false;
    let mut joined = false;
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    // The previous round truncated a line at MAX_LINE, so what arrives
    // next is that line's TAIL - not a message. Parsed as one it let a
    // peer inject any line it liked simply by padding ahead of it.
    let mut resync = false;
    let opened = tokio::time::Instant::now();
    let mut last_traffic = opened;
    loop {
        if stop() {
            let _ = wr.write_all(b"QUIT :bye\r\n").await;
            return IrcStop::Cancelled;
        }
        // Read in short slices rather than waiting out the whole
        // timeout in one call. The timeouts below are still the real
        // ones; slicing is what lets switching the feature off take
        // effect in seconds instead of at the end of a ten-minute
        // idle window - a connection the user has just turned off
        // must actually close.
        //
        // Cancelling `read_until` mid-line is safe HERE and only
        // here: `buf` is not cleared between slices, so bytes
        // already moved out of the reader stay in it and the next
        // slice continues the same line.
        const POLL: Duration = Duration::from_secs(2);
        let room = MAX_LINE - buf.len() as u64;
        // Bytes, not read_line: IRC has no charset and relay bots
        // send latin-1 titles routinely. read_line would fail the
        // whole connection on the first one; lossy decoding costs a
        // mangled character in a field we do not match on.
        let mut limited = (&mut lines).take(room);
        match tokio::time::timeout(POLL, limited.read_until(b'\n', &mut buf)).await {
            // Nothing this slice. Two clocks: a short one until
            // registration completes, a long idle one afterwards.
            // Without the first, a server that accepts the TCP
            // connection and then says nothing holds a task forever.
            Err(_) => {
                if !registered && opened.elapsed() >= REGISTER_TIMEOUT {
                    return IrcStop::Transient("registration timed out".into());
                }
                if registered && last_traffic.elapsed() >= IDLE_TIMEOUT {
                    return IrcStop::Transient("no traffic for 10 minutes".into());
                }
                continue;
            }
            Ok(Err(e)) => return IrcStop::Transient(format!("read: {e}")),
            Ok(Ok(0)) => return IrcStop::Transient("server closed the connection".into()),
            Ok(Ok(_)) => {}
        }
        // A slice that returned bytes but no terminator is a line
        // still arriving; keep reading it.
        if buf.last() != Some(&b'\n') && (buf.len() as u64) < MAX_LINE {
            continue;
        }
        // An oversized line: the peer sent MAX_LINE bytes with no
        // terminator. Take what there is and resync at the next newline
        // rather than growing the buffer for it.
        //
        // Sampled HERE, after the read, and not before it: the read is
        // what fills the buffer to the cap, so a sample taken ahead of
        // it always reads false on the very slice that truncates. The
        // tail then arrived as a line of its own and a peer could inject
        // any message it liked simply by padding to exactly MAX_LINE
        // ahead of it - which is the attack the resync exists to stop.
        let oversized = buf.last() != Some(&b'\n');
        last_traffic = tokio::time::Instant::now();
        let decoded = String::from_utf8_lossy(&buf);
        let line = decoded.trim_end_matches(['\r', '\n']).to_string();
        buf.clear();
        let line = line.as_str();
        // Whatever followed a truncated line is the rest of it; drop it,
        // and keep dropping until one arrives that we did not cut.
        if std::mem::replace(&mut resync, oversized) {
            continue;
        }
        if line.is_empty() {
            continue;
        }
        let msg = Msg::parse(line);
        // Cloned so an arm may move `msg.trailing` out without the match
        // still holding a borrow of `msg`.
        let cmd = msg.command.clone();
        match cmd.as_str() {
            // Keepalive. Answering is not optional; a client that stops
            // answering is disconnected within a couple of minutes.
            "PING" => {
                let token = msg
                    .trailing
                    .as_deref()
                    .or(msg.params.first().map(String::as_str));
                let pong = match token {
                    Some(t) => format!("PONG :{t}\r\n"),
                    None => "PONG\r\n".to_string(),
                };
                if let Err(e) = wr.write_all(pong.as_bytes()).await {
                    return IrcStop::Transient(format!("send PONG: {e}"));
                }
            }
            // 001 RPL_WELCOME - registration is complete, and only now
            // may we JOIN (join before this and the server drops it).
            "001" => {
                registered = true;
                if !joined {
                    joined = true;
                    for ch in &cfg.channels {
                        let ch = ch.trim();
                        if ch.is_empty() {
                            continue;
                        }
                        let ch = if ch.starts_with('#') {
                            ch.to_string()
                        } else {
                            format!("#{ch}")
                        };
                        if let Err(e) = wr.write_all(format!("JOIN {ch}\r\n").as_bytes()).await {
                            return IrcStop::Transient(format!("send JOIN: {e}"));
                        }
                    }
                }
            }
            // 433 ERR_NICKNAMEINUSE / 432 erroneous / 436 collision.
            // Re-roll the suffix rather than give up; a fresh suffix is
            // one line and the alternative is an install that can never
            // connect because somebody took its name.
            "432" | "433" | "436" => {
                if registered {
                    continue;
                }
                let retry = format!("{}{}", cfg.nick.trim(), nick_suffix());
                if let Err(e) = wr.write_all(format!("NICK {retry}\r\n").as_bytes()).await {
                    return IrcStop::Transient(format!("send NICK: {e}"));
                }
            }
            // Channel-level refusals. These are NOT a reason to drop the
            // connection: the other channels may be fine, and a renamed
            // or removed channel that took the whole client down with it
            // is exactly the reconnect storm this feature must not
            // become. Log once, carry on with what did join.
            "403" | "405" | "471" | "473" | "474" | "475" | "477" | "479" => {
                let what = msg.params.get(1).cloned().unwrap_or_default();
                let why = msg.trailing.clone().unwrap_or_default();
                warn!(target: "predb", "cannot join {what}: {why} - carrying on without it");
            }
            // 465 ERR_YOUREBANNEDCREEP, 464 bad password, 466 about to
            // be banned. Being told to go away.
            "464" | "465" | "466" => {
                let why = msg.trailing.clone().unwrap_or_else(|| msg.command.clone());
                return IrcStop::Rejected(why);
            }
            // A server KILL, or an ERROR line. ERROR carries both
            // ordinary closes ("Ping timeout") and bans ("K-lined"), so
            // the reason text decides which bucket it lands in.
            "KILL" => {
                return IrcStop::Rejected(msg.trailing.unwrap_or_else(|| "killed".into()));
            }
            "ERROR" => {
                let why = msg.trailing.unwrap_or_else(|| "server error".into());
                let low = why.to_ascii_lowercase();
                let banned = [
                    "banned", "k-line", "kline", "g-line", "gline", "z-line", "glined",
                ]
                .iter()
                .any(|m| low.contains(m));
                return if banned {
                    IrcStop::Rejected(why)
                } else {
                    IrcStop::Transient(why)
                };
            }
            "PRIVMSG" | "NOTICE" => {
                let Some(target) = msg.params.first() else {
                    continue;
                };
                // Channel traffic only. A private message to us is not
                // part of the relay and we have no business acting on
                // one - notably, we never reply, so a bot cannot use a
                // PM to make this client emit anything.
                if !target.starts_with('#') && !target.starts_with('&') {
                    continue;
                }
                let Some(text) = &msg.trailing else { continue };
                on_msg(IrcMessage {
                    channel: target,
                    nick: msg.nick(),
                    text,
                });
            }
            _ => {}
        }
    }
}

async fn connect(cfg: &IrcConfig) -> Result<Stream, String> {
    let host = cfg.host.trim();
    if host.is_empty() {
        return Err("no server configured".into());
    }
    // TLS on its own port, falling back to the configured plain port.
    // Written as "try the good thing, accept the ordinary thing" rather
    // than a setting, because the honest answer to "does this network do
    // TLS" is found by asking it.
    if cfg.tls {
        let port = if cfg.port == DEFAULT_PORT {
            TLS_PORT
        } else {
            cfg.port
        };
        match tls_connect(host, port).await {
            Ok(s) => return Ok(s),
            Err(e) if !cfg.allow_plaintext => {
                // No automatic downgrade. Blocking 6697 is something an
                // on-path attacker can do at will, and answering on 6667
                // afterwards lets it write rows the exact legs match on.
                // A feed that is not connected names nothing; a feed
                // connected to an impostor names things wrongly.
                return Err(format!(
                    "TLS to {host}:{port} failed ({e}) - refusing to fall back to \
                     plain text, which anyone on the path can force and then answer. \
                     Set NZBFAST_PREDB_ALLOW_PLAINTEXT=1 to accept that."
                ));
            }
            Err(e) => {
                warn!(
                    target: "predb",
                    "TLS to {host}:{port} failed ({e}); NZBFAST_PREDB_ALLOW_PLAINTEXT \
                     is set, trying plain {}",
                    cfg.port
                );
            }
        }
    }
    let tcp = tokio::time::timeout(
        Duration::from_secs(20),
        TcpStream::connect((host, cfg.port)),
    )
    .await
    .map_err(|_| format!("connect to {host}:{} timed out", cfg.port))?
    .map_err(|e| format!("connect to {host}:{}: {e}", cfg.port))?;
    let _ = tcp.set_nodelay(true);
    Ok(Stream::Plain(tcp))
}

async fn tls_connect(host: &str, port: u16) -> Result<Stream, String> {
    let tcp = tokio::time::timeout(Duration::from_secs(20), TcpStream::connect((host, port)))
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let _ = tcp.set_nodelay(true);
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "bad server name".to_string())?;
    let connector = tokio_rustls::TlsConnector::from(crate::nntp::shared_tls_client_config());
    let s = tokio::time::timeout(Duration::from_secs(20), connector.connect(name, tcp))
        .await
        .map_err(|_| "handshake timed out".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(Stream::Tls(Box::new(s)))
}

/// One parsed IRC protocol line: `[@tags] [:prefix] COMMAND params :trailing`.
struct Msg {
    prefix: String,
    command: String,
    params: Vec<String>,
    trailing: Option<String>,
}

impl Msg {
    fn parse(line: &str) -> Msg {
        let mut rest = line.trim_start();
        // IRCv3 message tags. We request no capabilities so these should
        // not appear, but a server may send them anyway and skipping
        // them costs one branch.
        if let Some(s) = rest.strip_prefix('@') {
            rest = s.split_once(' ').map(|(_, r)| r).unwrap_or("").trim_start();
        }
        let mut prefix = String::new();
        if let Some(s) = rest.strip_prefix(':') {
            let (p, r) = s.split_once(' ').unwrap_or((s, ""));
            prefix = p.to_string();
            rest = r.trim_start();
        }
        // The trailing parameter is everything after " :" and is the one
        // that may contain spaces - which is where the relay line lives.
        let (head, trailing) = match rest.find(" :") {
            Some(i) => (&rest[..i], Some(rest[i + 2..].to_string())),
            None => (rest, None),
        };
        let mut it = head.split_whitespace();
        let command = it.next().unwrap_or("").to_ascii_uppercase();
        let params: Vec<String> = it.map(str::to_string).collect();
        Msg {
            prefix,
            command,
            params,
            trailing,
        }
    }

    /// The sending nick, from `nick!user@host`.
    fn nick(&self) -> &str {
        self.prefix.split(['!', '@']).next().unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_colour_and_bold() {
        let raw = "\x0304,08NEW\x03: \x02[TT: Some.Release-GRP]\x02[FN: abc123]";
        let s = strip_formatting(raw);
        assert_eq!(s, "NEW: [TT: Some.Release-GRP][FN: abc123]");
    }

    #[test]
    fn a_bare_comma_after_colour_survives() {
        // "\x0304,text" is colour 04 then a literal comma - eating the
        // comma would silently corrupt every title with one in it.
        assert_eq!(strip_formatting("\x0304,Hello"), ",Hello");
        assert_eq!(strip_formatting("\x03,Hello"), ",Hello");
    }

    #[test]
    fn strip_keeps_non_ascii_intact() {
        assert_eq!(strip_formatting("\x02Amélie.1080p\x02"), "Amélie.1080p");
    }

    #[test]
    fn parses_a_full_new_line() {
        let raw = "NEW: [DT: 2026-07-28 11:22:33][TT: Some.Film.2026.1080p.WEB-DL.x264-GRP]\
                   [SC: PRE][CT: X264][RQ: 12345:alt.binaries.teevee][SZ: 1400MB][FL: 20F]\
                   [FN: p5cbKvaDJ1Y0PW6DvKCIfztzZ]";
        let p = parse_line(raw).expect("parses");
        assert_eq!(p.kind, PreKind::New);
        assert_eq!(p.title, "Some.Film.2026.1080p.WEB-DL.x264-GRP");
        assert_eq!(p.filename, "p5cbKvaDJ1Y0PW6DvKCIfztzZ");
        assert_eq!(p.size, 1400 * 1024 * 1024);
        assert_eq!(p.files, 20);
        assert_eq!(p.category, "X264");
        assert_eq!(p.source, "PRE");
        assert_eq!(p.requestid, "12345");
        assert_eq!(p.group, "alt.binaries.teevee");
        assert_eq!(p.date, 1_785_237_753);
        assert!(p.nameable());
    }

    /// Found in the field, 1 Aug 2026, within 20 minutes of the first
    /// live deploy: synirc sends `[FN: N/A]` on every line. Stored
    /// verbatim it made `nameable()` lie about 7 lines out of 7, and
    /// gave every one of them the same join key ("na") for a lookup
    /// that is supposed to match one posted filename.
    #[test]
    fn a_written_out_absent_value_is_absent() {
        let p = parse_line("NEW: [TT: Real.Release-GRP][FN: N/A][SZ: N/A][SC: PRE]").unwrap();
        assert_eq!(p.title, "Real.Release-GRP");
        assert_eq!(p.filename, "", "N/A is not a filename");
        assert_eq!(p.size, 0);
        assert_eq!(p.source, "PRE");
        assert!(!p.nameable(), "a line with no real filename names nothing");

        for marker in ["n/a", "NA", "none", "NULL", "unknown", "-", "?"] {
            let line = format!("NEW: [TT: T-GRP][FN: {marker}]");
            assert!(parse_line(&line).unwrap().filename.is_empty(), "{marker}");
        }
        // ...but a real name that merely starts with those letters stays.
        let keep = parse_line("NEW: [TT: T-GRP][FN: NONE.Of.Your.Business-GRP]").unwrap();
        assert_eq!(keep.filename, "NONE.Of.Your.Business-GRP");
        let nasty = parse_line("NEW: [TT: Nan.2026.1080p-GRP][FN: nan.file]").unwrap();
        assert_eq!(nasty.filename, "nan.file");
    }

    #[test]
    fn field_order_does_not_matter() {
        let a = parse_line("NEW: [TT: A.Release-GRP][FN: xyz][SZ: 1G]").unwrap();
        let b = parse_line("NEW: [SZ: 1G][FN: xyz][TT: A.Release-GRP]").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn missing_fields_are_fine() {
        let p = parse_line("NEW: [TT: Only.A.Title-GRP]").unwrap();
        assert_eq!(p.title, "Only.A.Title-GRP");
        assert_eq!(p.size, 0);
        assert!(!p.nameable(), "a title with no filename cannot name a post");
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let p = parse_line("NEW: [TT: X-GRP][WHAT: something new][FN: abc]").unwrap();
        assert_eq!(p.title, "X-GRP");
        assert_eq!(p.filename, "abc");
    }

    #[test]
    fn brackets_inside_a_title_survive() {
        let p = parse_line("UPD: [TT: Some.Show.S01E01.[REPACK]-GRP][FN: q9z]").unwrap();
        assert_eq!(p.kind, PreKind::Upd);
        assert_eq!(p.title, "Some.Show.S01E01.[REPACK]-GRP");
        assert_eq!(p.filename, "q9z");
    }

    #[test]
    fn a_nuke_line_records_the_reason() {
        let p = parse_line("NUK: [TT: Bad.Release-GRP][NUKED: dupe.of.Good.Release-GRP]").unwrap();
        assert_eq!(p.kind, PreKind::Nuk);
        assert_eq!(p.nuke_reason, "dupe.of.Good.Release-GRP");
    }

    #[test]
    fn a_nuked_field_on_any_line_marks_it_nuked() {
        let p = parse_line("NEW: [TT: R-GRP][FN: a][NUKED: bad.crc]").unwrap();
        assert_eq!(p.kind, PreKind::Nuk);
    }

    #[test]
    fn missing_kind_prefix_reads_as_new() {
        let p = parse_line("[TT: R-GRP][FN: a]").unwrap();
        assert_eq!(p.kind, PreKind::New);
    }

    /// The three plain formats, using the survey's verbatim lines
    /// (research/PREDB-RELAYS-DEEP-2026-08.md) with their colour codes
    /// in place - on predataba.se the code lands INSIDE the section
    /// field and stripping has to run first.
    #[test]
    fn the_live_relay_formats_parse() {
        let p = parse_line(
            "pre |\x032 TV-WEB-HD-X265 | The.Tick.2016.S01E11.POLISH.2160p.WEB.H265-FLAME",
        )
        .expect("pipe format");
        assert_eq!(p.kind, PreKind::New);
        assert_eq!(p.title, "The.Tick.2016.S01E11.POLISH.2160p.WEB.H265-FLAME");
        assert_eq!(p.category, "TV-WEB-HD-X265");
        assert_eq!(
            p.date, 0,
            "no DT on the wire - arrival time is the pre time"
        );
        assert!(!p.nameable(), "plain formats carry no filename");

        let p = parse_line(
            "pre | MP3-WEB | VA_-_Megamix_Chart_Hits_2025_(Compiled_And_Mixed_By_DJ_Flim_Flam)-REPACK-WEB-2025-NOiCE",
        )
        .expect("underscored title with parens");
        assert_eq!(
            p.title,
            "VA_-_Megamix_Chart_Hits_2025_(Compiled_And_Mixed_By_DJ_Flim_Flam)-REPACK-WEB-2025-NOiCE"
        );

        let p = parse_line(
            "\x0314PRE:\x03 [\x0314PRE\x03] Succession.S02E01.Sommerpalast.German.DL.720p.WebHD.H264-RWF",
        )
        .expect("corrupt-net format");
        assert_eq!(p.kind, PreKind::New);
        assert_eq!(
            p.title,
            "Succession.S02E01.Sommerpalast.German.DL.720p.WebHD.H264-RWF"
        );
        assert_eq!(p.category, "PRE");

        let p = parse_line(
            "(PRE) (TV-WEB-HD-X264) Succession.S02E01.Sommerpalast.German.DL.720p.WebHD.H264-RWF",
        )
        .expect("scenep2p format");
        assert_eq!(p.category, "TV-WEB-HD-X264");
        assert_eq!(
            p.title,
            "Succession.S02E01.Sommerpalast.German.DL.720p.WebHD.H264-RWF"
        );
        // The fully-parenthesized variant of the same shape sheds its
        // closing paren instead of storing it.
        let p = parse_line("(PRE) (X264) (Some.Film.2026.1080p.WEB.H264-GRP)").unwrap();
        assert_eq!(p.title, "Some.Film.2026.1080p.WEB.H264-GRP");
    }

    #[test]
    fn plain_nuke_lines_carry_kind_and_reason() {
        let p = parse_line("nuke | X264 | Bad.Release.2026-GRP | bad.ar").unwrap();
        assert_eq!(p.kind, PreKind::Nuk);
        assert_eq!(p.title, "Bad.Release.2026-GRP");
        assert_eq!(p.nuke_reason, "bad.ar");
        let p = parse_line("NUKE: [X264] Bad.Release.2026-GRP get.a.better.source").unwrap();
        assert_eq!(p.kind, PreKind::Nuk);
        assert_eq!(p.nuke_reason, "get.a.better.source");
    }

    #[test]
    fn plain_chatter_is_still_chatter() {
        // Keyword openers followed by prose, not a release name.
        assert!(parse_line("PRE: the bot is back up").is_none());
        assert!(parse_line("(PRE) (INFO) hello everyone").is_none());
        // Pipes without an announcement keyword (a topic line, stats).
        assert!(parse_line("stats | 34512 pres | today: 1204").is_none());
        // Too few pipe fields.
        assert!(parse_line("pre | only-a-section").is_none());
        // Absent markers in the title field.
        assert!(parse_line("pre | X264 | N/A").is_none());
    }

    #[test]
    fn chatter_is_not_a_pre_line() {
        assert!(parse_line("hello everyone").is_none());
        assert!(parse_line("NEW: nothing structured here").is_none());
        // Fields but no title: a bot status line, not an announcement.
        assert!(parse_line("[Status: connected][Uptime: 3d]").is_none());
    }

    #[test]
    fn a_truncated_line_still_yields_what_it_had() {
        let p = parse_line("NEW: [TT: Some.Release-GRP][FN: abc").unwrap();
        assert_eq!(p.title, "Some.Release-GRP");
        assert_eq!(p.filename, "abc");
    }

    #[test]
    fn sizes_in_every_shape() {
        assert_eq!(parse_size("1400MB"), 1400 * 1024 * 1024);
        assert_eq!(parse_size("1.4GB"), (1.4 * 1024.0 * 1024.0 * 1024.0) as u64);
        assert_eq!(parse_size("700M"), 700 * 1024 * 1024);
        assert_eq!(parse_size("1,024 KB"), 1024 * 1024);
        assert_eq!(parse_size("123456"), 123_456);
        assert_eq!(parse_size("who knows"), 0);
        // An absurd value must not wrap into something plausible.
        assert_eq!(parse_size("999999999999999999999999TB"), u64::MAX);
    }

    #[test]
    fn file_counts_in_every_shape() {
        assert_eq!(parse_files("20F"), 20);
        assert_eq!(parse_files("20"), 20);
        assert_eq!(parse_files("7 files"), 7);
        assert_eq!(parse_files("F"), 0);
    }

    #[test]
    fn dates_in_both_shapes() {
        assert_eq!(parse_date("1785237753"), 1_785_237_753);
        assert_eq!(parse_date("2026-07-28 11:22:33"), 1_785_237_753);
        assert_eq!(parse_date("2026/07/28T11:22:33Z"), 1_785_237_753);
        assert_eq!(parse_date("1970-01-01 00:00:00"), 0);
        assert_eq!(parse_date("not a date"), 0);
        // Out-of-range values are rejected rather than wrapped into a
        // plausible-looking timestamp.
        assert_eq!(parse_date("2026-13-01 00:00:00"), 0);
        assert_eq!(parse_date("5"), 0);
    }

    #[test]
    fn match_key_ignores_separators_and_case() {
        assert_eq!(match_key("Abc-123_x.y"), "abc123xy");
        assert_eq!(match_key("ABC123XY"), "abc123xy");
    }

    #[test]
    fn irc_line_parsing() {
        let m = Msg::parse(":bot!u@h PRIVMSG #chan :NEW: [TT: X-GRP]");
        assert_eq!(m.command, "PRIVMSG");
        assert_eq!(m.nick(), "bot");
        assert_eq!(m.params, vec!["#chan"]);
        assert_eq!(m.trailing.as_deref(), Some("NEW: [TT: X-GRP]"));

        let p = Msg::parse("PING :1234");
        assert_eq!(p.command, "PING");
        assert_eq!(p.trailing.as_deref(), Some("1234"));

        // IRCv3 tags are skipped, not mistaken for the command.
        let t = Msg::parse("@time=2026-07-28 :s 001 me :Welcome");
        assert_eq!(t.command, "001");

        // A trailing param containing " :" keeps everything after the
        // FIRST one (the protocol's rule), so a relay line with a colon
        // in the title survives.
        let c = Msg::parse(":b PRIVMSG #c :NEW: [TT: A :B-GRP]");
        assert_eq!(c.trailing.as_deref(), Some("NEW: [TT: A :B-GRP]"));
    }

    // ===== the IRC client, against a scripted local server =====

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::BufReader as TokioBufReader;

    /// One line off the mock server's read half, CRLF shed.
    async fn srv_line(r: &mut TokioBufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
        let mut s = String::new();
        r.read_line(&mut s).await.unwrap();
        s.trim_end().to_string()
    }

    /// Drive `run_once` (plain TCP) against `script`, which plays the
    /// server side on the accepted socket. Returns the stop reason and
    /// every (channel, nick, text) the client reported.
    async fn run_against<F, Fut>(
        channels: Vec<String>,
        stop_flag: Arc<AtomicBool>,
        script: F,
    ) -> (IrcStop, Vec<(String, String, String)>)
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            script(sock).await;
        });
        let cfg = IrcConfig {
            host: "127.0.0.1".into(),
            port,
            tls: false,
            allow_plaintext: false,
            nick: "t".into(),
            channels,
        };
        let msgs = std::sync::Mutex::new(Vec::new());
        let stop = move || stop_flag.load(Ordering::Relaxed);
        let out = run_once(
            &cfg,
            |m| {
                msgs.lock().unwrap().push((
                    m.channel.to_string(),
                    m.nick.to_string(),
                    m.text.to_string(),
                ));
            },
            &stop,
        )
        .await;
        server.await.unwrap();
        (out, msgs.into_inner().unwrap())
    }

    /// Registration, PING/PONG, JOIN (with channel-name normalization),
    /// channel refusal carried past, PRIVMSG/NOTICE filtering, and an
    /// ordinary ERROR close reading as Transient.
    #[tokio::test]
    async fn irc_happy_path_delivers_channel_messages() {
        let (stop, msgs) = run_against(
            // One well-formed, one blank (skipped), one missing its '#'.
            vec!["#pre".into(), "  ".into(), "nzedb".into()],
            Arc::new(AtomicBool::new(false)),
            |sock| async move {
                let (rd, mut wr) = sock.into_split();
                let mut rd = TokioBufReader::new(rd);
                let nick_line = srv_line(&mut rd).await;
                assert!(nick_line.starts_with("NICK t"), "{nick_line}");
                assert!(srv_line(&mut rd).await.starts_with("USER "));
                // Keepalive before registration completes.
                wr.write_all(b"PING :tok123\r\n").await.unwrap();
                assert_eq!(srv_line(&mut rd).await, "PONG :tok123");
                // Token-only PING (no trailing form).
                wr.write_all(b"PING tok456\r\n").await.unwrap();
                assert_eq!(srv_line(&mut rd).await, "PONG :tok456");
                wr.write_all(b":srv 001 me :welcome\r\n").await.unwrap();
                assert_eq!(srv_line(&mut rd).await, "JOIN #pre");
                assert_eq!(srv_line(&mut rd).await, "JOIN #nzedb");
                // One channel refuses; the client carries on.
                wr.write_all(b":srv 473 me #pre :invite only\r\n")
                    .await
                    .unwrap();
                // A PM (non-channel target) must never reach the callback.
                wr.write_all(b":spy!u@h PRIVMSG me :psst\r\n")
                    .await
                    .unwrap();
                // No trailing text at all: skipped.
                wr.write_all(b":bot!u@h PRIVMSG #pre\r\n").await.unwrap();
                // The real thing, plus a NOTICE (same arm).
                wr.write_all(b":bot!u@h PRIVMSG #pre :NEW: [TT: X-GRP][FN: a]\r\n")
                    .await
                    .unwrap();
                wr.write_all(b":relay!u@h NOTICE &local :pre line two\r\n")
                    .await
                    .unwrap();
                wr.write_all(b"ERROR :closing link\r\n").await.unwrap();
            },
        )
        .await;
        assert!(
            matches!(&stop, IrcStop::Transient(m) if m == "closing link"),
            "{stop:?}"
        );
        assert_eq!(format!("{stop}"), "closing link");
        assert_eq!(
            msgs,
            vec![
                (
                    "#pre".to_string(),
                    "bot".to_string(),
                    "NEW: [TT: X-GRP][FN: a]".to_string()
                ),
                (
                    "&local".to_string(),
                    "relay".to_string(),
                    "pre line two".to_string()
                ),
            ]
        );
    }

    /// 433 nick-in-use re-rolls the suffix instead of giving up, and a
    /// server close reads as Transient.
    #[tokio::test]
    async fn irc_nick_collision_rerolls() {
        let (stop, msgs) = run_against(
            vec!["#pre".into()],
            Arc::new(AtomicBool::new(false)),
            |sock| async move {
                let (rd, mut wr) = sock.into_split();
                let mut rd = TokioBufReader::new(rd);
                let first = srv_line(&mut rd).await;
                assert!(srv_line(&mut rd).await.starts_with("USER "));
                wr.write_all(b":srv 433 * t :nickname in use\r\n")
                    .await
                    .unwrap();
                let second = srv_line(&mut rd).await;
                assert!(second.starts_with("NICK t"), "{second}");
                assert_ne!(first, second, "a fresh suffix was rolled");
                wr.write_all(b":srv 001 me :welcome\r\n").await.unwrap();
                assert_eq!(srv_line(&mut rd).await, "JOIN #pre");
                // Post-registration 433 is ignored, then the socket dies.
                wr.write_all(b":srv 433 me t2 :in use\r\n").await.unwrap();
            },
        )
        .await;
        assert!(
            matches!(&stop, IrcStop::Transient(m) if m.contains("closed")),
            "{stop:?}"
        );
        assert!(msgs.is_empty());
    }

    /// The go-away family: 465 numerics, KILL, and ban-shaped ERROR all
    /// land in Rejected (hours of backoff), while a mundane ERROR stays
    /// Transient - the reason text decides.
    #[tokio::test]
    async fn irc_rejections_and_ban_classification() {
        for (line, banned, needle) in [
            (":srv 465 me :You are banned\r\n", true, "You are banned"),
            (":srv KILL me :go away\r\n", true, "go away"),
            ("ERROR :K-lined for abuse\r\n", true, "K-lined"),
            ("ERROR :ping timeout\r\n", false, "ping timeout"),
        ] {
            let (stop, _) = run_against(
                vec!["#pre".into()],
                Arc::new(AtomicBool::new(false)),
                move |sock| async move {
                    let (rd, mut wr) = sock.into_split();
                    let mut rd = TokioBufReader::new(rd);
                    srv_line(&mut rd).await;
                    srv_line(&mut rd).await;
                    wr.write_all(line.as_bytes()).await.unwrap();
                },
            )
            .await;
            match (&stop, banned) {
                (IrcStop::Rejected(m), true) | (IrcStop::Transient(m), false) => {
                    assert!(m.contains(needle), "{line:?} -> {stop:?}");
                }
                _ => panic!("{line:?} misclassified: {stop:?}"),
            }
            if banned {
                assert!(format!("{stop}").starts_with("rejected: "));
            }
        }
    }

    /// The stop switch: the client says QUIT and reports Cancelled.
    #[tokio::test]
    async fn irc_stop_switch_quits() {
        let (stop, _) = run_against(
            vec!["#pre".into()],
            Arc::new(AtomicBool::new(true)),
            |sock| async move {
                let (rd, _wr) = sock.into_split();
                let mut rd = TokioBufReader::new(rd);
                loop {
                    let l = srv_line(&mut rd).await;
                    if l == "QUIT :bye" || l.is_empty() {
                        break;
                    }
                }
            },
        )
        .await;
        assert!(matches!(stop, IrcStop::Cancelled), "{stop:?}");
        assert_eq!(format!("{stop}"), "stopped");
    }

    /// A peer that sends MAX_LINE bytes with no terminator is resynced
    /// at the next newline instead of buffered without bound - and the
    /// lines after it still parse.
    #[tokio::test]
    async fn irc_oversized_line_resyncs() {
        let (stop, msgs) = run_against(
            vec!["#pre".into()],
            Arc::new(AtomicBool::new(false)),
            |sock| async move {
                let (rd, mut wr) = sock.into_split();
                let mut rd = TokioBufReader::new(rd);
                srv_line(&mut rd).await;
                srv_line(&mut rd).await;
                wr.write_all(b":srv 001 me :welcome\r\n").await.unwrap();
                assert_eq!(srv_line(&mut rd).await, "JOIN #pre");
                let mut blob = vec![b'a'; (MAX_LINE + 800) as usize];
                blob.extend_from_slice(b"\r\n");
                wr.write_all(&blob).await.unwrap();
                wr.write_all(b":bot!u@h PRIVMSG #pre :NEW: [TT: Y-GRP]\r\n")
                    .await
                    .unwrap();
                wr.write_all(b"ERROR :done\r\n").await.unwrap();
            },
        )
        .await;
        assert!(matches!(stop, IrcStop::Transient(_)), "{stop:?}");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert_eq!(msgs[0].2, "NEW: [TT: Y-GRP]");
    }

    /// The truncation is decided by the read that FILLS the buffer, not
    /// by a sample taken before it. A peer that sends exactly MAX_LINE
    /// bytes with no terminator has its NEXT newline-terminated run
    /// discarded as the tail of that line - even though the tail is a
    /// syntactically perfect PRIVMSG, which is exactly what an injector
    /// would pad ahead of. Only the line after the resync is a message.
    #[tokio::test]
    async fn a_tail_after_an_exactly_max_line_run_is_not_a_message() {
        let (stop, msgs) = run_against(
            vec!["#pre".into()],
            Arc::new(AtomicBool::new(false)),
            |sock| async move {
                let (rd, mut wr) = sock.into_split();
                let mut rd = TokioBufReader::new(rd);
                srv_line(&mut rd).await;
                srv_line(&mut rd).await;
                wr.write_all(b":srv 001 me :welcome\r\n").await.unwrap();
                assert_eq!(srv_line(&mut rd).await, "JOIN #pre");
                // Exactly MAX_LINE bytes, no terminator among them: the
                // bounded read returns with the buffer full and the line
                // still unfinished.
                wr.write_all(&vec![b'a'; MAX_LINE as usize]).await.unwrap();
                wr.write_all(b":bot!u@h PRIVMSG #pre :NEW: [TT: INJECTED-GRP]\r\n")
                    .await
                    .unwrap();
                wr.write_all(b":bot!u@h PRIVMSG #pre :NEW: [TT: LEGIT-GRP]\r\n")
                    .await
                    .unwrap();
                wr.write_all(b"ERROR :done\r\n").await.unwrap();
            },
        )
        .await;
        assert!(matches!(stop, IrcStop::Transient(_)), "{stop:?}");
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert_eq!(msgs[0].2, "NEW: [TT: LEGIT-GRP]");
    }

    /// Config guards: an empty host cannot connect, and TLS against a
    /// non-TLS listener refuses to downgrade unless plaintext was
    /// explicitly allowed - in which case the plain retry proceeds.
    #[tokio::test]
    async fn irc_connect_guards_and_plaintext_fallback() {
        let cfg = IrcConfig {
            host: "  ".into(),
            ..IrcConfig::default()
        };
        let stop = run_once(&cfg, |_| {}, &|| false).await;
        assert!(
            matches!(&stop, IrcStop::Transient(m) if m.contains("no server configured")),
            "{stop:?}"
        );

        // A plain-text listener that answers TLS with garbage.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            // Both runs open with a TLS attempt - feed each a non-TLS
            // greeting so the handshake dies fast, never reading (a
            // ClientHello is binary and no line reader may touch it).
            for _ in 0..2 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let _ = sock.write_all(b"not tls at all\r\n").await;
                drop(sock);
            }
            // Third connection: the second run's plain-text fallback.
            if let Ok((sock, _)) = listener.accept().await {
                let (rd, mut wr) = sock.into_split();
                let mut rd = TokioBufReader::new(rd);
                srv_line(&mut rd).await;
                srv_line(&mut rd).await;
                wr.write_all(b"ERROR :fallback reached\r\n").await.unwrap();
            }
        });
        let mut cfg = IrcConfig {
            host: "127.0.0.1".into(),
            port,
            tls: true,
            allow_plaintext: false,
            nick: "t".into(),
            channels: vec!["#pre".into()],
        };
        let stop = run_once(&cfg, |_| {}, &|| false).await;
        assert!(
            matches!(&stop, IrcStop::Transient(m) if m.contains("refusing to fall back")),
            "{stop:?}"
        );
        cfg.allow_plaintext = true;
        let stop = run_once(&cfg, |_| {}, &|| false).await;
        assert!(
            matches!(&stop, IrcStop::Transient(m) if m == "fallback reached"),
            "{stop:?}"
        );
        server.await.unwrap();
        // The defaults themselves: TLS on, no plaintext, documented nick.
        let d = IrcConfig::default();
        assert!(d.tls && !d.allow_plaintext);
        assert_eq!(d.nick, DEFAULT_NICK);
        assert_eq!(d.port, DEFAULT_PORT);
        assert_eq!(d.channels.len(), DEFAULT_CHANNELS.len());
    }

    #[test]
    fn nick_suffixes_differ() {
        let a = nick_suffix();
        let b = nick_suffix();
        assert_eq!(a.len(), 6);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        // Not a guarantee the type system can make, but a 36^6 space
        // colliding twice in a row would mean the entropy source broke.
        assert_ne!(a, b);
    }
}
