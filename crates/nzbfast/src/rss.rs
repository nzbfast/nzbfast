//! M14k: RSS/newznab feed automation - poll feeds, filter with
//! NZBGet-style rules, auto-enqueue accepted items.
//!
//! Feed config (`--feeds feeds.json`):
//! ```json
//! [{
//!   "url": "https://indexer/rss?apikey=...",
//!   "interval_secs": 900,
//!   "category": "tv",
//!   "rules": [
//!     "Require: size>200M",
//!     "Reject: *480p*",
//!     "Accept: *1080p*",
//!     "Accept: *2160p*"
//!   ]
//! }]
//! ```
//! Rule semantics (the useful subset of NZBGet's language):
//! - `Require:` - every Require must match or the item is skipped.
//! - `Reject:`  - any match skips the item.
//! - `Accept:`  - if any Accept rules exist, the item must match one.
//! - Patterns are case-insensitive wildcards (`*`, `?`) against the
//!   title; a pattern without wildcards matches as a substring.
//! - `size>N` / `size<N` (K/M/G/T suffixes) compare the item's size.
//! - §129 2d: an Accept rule can carry its own filing -
//!   `Accept(category=tv, priority=high): *1080p*` - overriding the
//!   feed's category and the default priority for items it matches
//!   (priority: force/high/normal/low or -2..2).
//! Duplicate detection (M14f) then holds anything already queued or done
//! (or discards / fails them - the `dupe_action` setting).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeedConfig {
    /// This feed's identity, as far as the settings UI is concerned.
    ///
    /// TODO §20c: the url used to be the only key a saved edit could be
    /// matched on, and that is exactly why the url could not be masked -
    /// a client that never saw the real url could not send one back, and
    /// a merge keyed on the url would have read the mask as a NEW feed
    /// and thrown the credential away. So the key had to stop being the
    /// secret. This is opaque, non-secret and derived from nothing (16
    /// random hex): it survives a rename, a reorder, a rules edit and a
    /// re-keyed url, which is what "stable" has to mean for a merge key.
    ///
    /// `#[serde(default)]` and filled in by [`assign_feed_ids`] at load,
    /// so a settings.json written before this field existed migrates
    /// silently and losslessly - see `spawn_rss_poller`, which persists
    /// the ids it minted so they stay stable across the next restart.
    #[serde(default)]
    pub id: String,
    pub url: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub rules: Vec<String>,
}

fn default_interval() -> u64 {
    900
}

impl FeedConfig {
    /// Everything about this feed that decides what one poll's items MEAN:
    /// the address polled, the rules judged against, and the category
    /// stamped on what is enqueued.
    ///
    /// The RSS loop snapshots a feed, awaits a slow fetch, and then applies
    /// the snapshot's rules - so deleting a feed or tightening its rules
    /// while a poll was in flight did not revoke that poll's authority to
    /// enqueue (Codex sweep 12 Aug F6b). `interval_secs` is excluded: it
    /// only decides when the NEXT poll runs.
    pub fn fetch_fingerprint(&self) -> String {
        format!(
            "{}\u{1}{}\u{1}{}",
            self.url,
            self.category,
            self.rules.join("\u{2}")
        )
    }

    /// A stable, non-secret identity for this feed, for keys that go to
    /// disk.
    ///
    /// The url is the identity, but a feed url essentially always carries
    /// the indexer's `apikey=`, so the url itself must never be written
    /// into a spool file. This is a hash of it: stable across restarts,
    /// distinct per feed, and it reveals nothing.
    pub fn scope_key(&self) -> String {
        // FxHash-style: this needs to be stable and cheap, not
        // cryptographic - a collision costs one cross-feed suppression,
        // which is exactly the pre-existing behaviour.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in self.url.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        format!("{h:016x}")
    }

    /// This feed's url as the settings UI is allowed to see it - the
    /// address with every credential-shaped part of it taken out. See
    /// [`mask_feed_url`] for what "credential-shaped" means here.
    pub fn masked_url(&self) -> String {
        mask_feed_url(&self.url)
    }
}

/// A fresh feed id: 16 random hex characters.
///
/// Not a secret and never used as one - it is a merge key, and it is
/// handed to the browser on every `get_config`. Random rather than a
/// counter so that two installs' settings files (or a settings.json
/// pasted between machines) cannot collide on "2", and rather than a
/// hash of the url so that re-keying an indexer account does not
/// silently make the row a different feed.
pub fn new_feed_id() -> String {
    let mut buf = [0u8; 8];
    if getrandom::fill(&mut buf).is_err() {
        // getrandom failing at all means the OS entropy source is gone;
        // an id still has to come out, and uniqueness here only has to
        // hold within one settings file. Time plus a process-local
        // counter gives that.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let c = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        buf = (n ^ c.wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_le_bytes();
    }
    hex::encode(buf)
}

/// Give every feed in `list` an id, and make sure no two share one.
/// Returns whether anything changed, so a caller can persist only when
/// there is something to persist.
///
/// This is the migration for every settings.json and `--feeds` file
/// written before the id existed: they parse (the field defaults to
/// empty), get an id here, and nothing else about them moves.
pub fn assign_feed_ids(list: &mut [FeedConfig]) -> bool {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut changed = false;
    for f in list.iter_mut() {
        let trimmed = f.id.trim().to_string();
        if trimmed != f.id {
            f.id = trimmed.clone();
            changed = true;
        }
        // A duplicate is re-minted rather than refused: ids are ours to
        // keep unique, and a config hand-edited into two identical ones
        // must not silently merge two feeds' saved urls onto each other.
        if f.id.is_empty() || !seen.insert(f.id.clone()) {
            loop {
                let id = new_feed_id();
                if seen.insert(id.clone()) {
                    f.id = id;
                    break;
                }
            }
            changed = true;
        }
    }
    changed
}

/// Query parameters a feed url can carry that are NEVER a credential -
/// the newznab/RSS vocabulary plus the few filter names indexers share,
/// with the value of everything else masked.
///
/// Deny by default, and that direction is deliberate. `redact_apikey`
/// can name the parameter it blanks because WE built the url it guards;
/// a feed url is the indexer's own construction, and its doc comment
/// already records what that costs - sites spell the credential
/// `apikey`, `api_key`, `r`, `i`, or put it in the path, so an
/// allowlist of SECRET names is a guess that fails silently and leaks.
/// An allowlist of harmless names fails the other way: an unusual
/// filter reads as `***`, which costs readability and nothing else.
const FEED_URL_PLAIN_PARAMS: &[&str] = &[
    "t",
    "q",
    "cat",
    "category",
    "categories",
    "limit",
    "offset",
    "extended",
    "maxage",
    "minage",
    "maxsize",
    "minsize",
    "num",
    "o",
    "out",
    "output",
    "format",
    "sort",
    "genre",
    "attrs",
    "page",
    "season",
    "ep",
    "series",
    "group",
    "groups",
    "lang",
    "rid",
    "imdbid",
    "tvdbid",
    "tvmazeid",
    "traktid",
    "tmdbid",
    "del",
    "dl",
];

/// A feed url with every credential-shaped part replaced by `***`,
/// keeping enough of it (scheme, host, path, the ordinary newznab
/// parameters) that a user with three feeds on one indexer can still
/// tell which row is which.
///
/// Three things go: the userinfo (`user:pw@`), any path segment shaped
/// like an opaque token (some sites put the key in the path), and the
/// value of every query parameter outside
/// [`FEED_URL_PLAIN_PARAMS`]. The parameter NAMES stay - the name is
/// what tells the user their key is in there.
///
/// This is a display transform, never a security boundary on its own:
/// what makes the masking safe is that the real url never leaves the
/// daemon, not that this function is exhaustive. It is also the exact
/// string a client sends back for "I did not touch this" (see
/// [`url_is_unchanged`]), so changing what it emits changes a
/// round-trip - it must stay deterministic.
pub fn mask_feed_url(url: &str) -> String {
    let (head, frag) = match url.split_once('#') {
        Some((h, f)) => (h, Some(f)),
        None => (url, None),
    };
    let (base, query) = match head.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (head, None),
    };
    let mut out = mask_url_base(base);
    if let Some(q) = query {
        out.push('?');
        let mut first = true;
        for pair in q.split('&') {
            if !first {
                out.push('&');
            }
            first = false;
            match pair.split_once('=') {
                Some((name, value)) => {
                    out.push_str(name);
                    out.push('=');
                    if value.is_empty()
                        || FEED_URL_PLAIN_PARAMS
                            .iter()
                            .any(|p| name.eq_ignore_ascii_case(p))
                    {
                        out.push_str(value);
                    } else {
                        out.push_str("***");
                    }
                }
                // A bare flag carries no value to hide.
                None => out.push_str(pair),
            }
        }
    }
    if let Some(f) = frag {
        out.push('#');
        // A fragment is never part of what an indexer serves and is not
        // worth reading; if one is there at all, it is not identifying
        // the feed for anybody.
        out.push_str(if f.is_empty() { "" } else { "***" });
    }
    out
}

/// The scheme/authority/path half of [`mask_feed_url`].
fn mask_url_base(base: &str) -> String {
    let (scheme, rest) = match base.find("://") {
        Some(p) => base.split_at(p + 3),
        None => ("", base),
    };
    let (authority, path) = match rest.find('/') {
        Some(p) => rest.split_at(p),
        None => (rest, ""),
    };
    let mut out = String::with_capacity(base.len());
    out.push_str(scheme);
    // `user:pw@host` - the password is a credential and the username is
    // half of one; neither identifies the feed to its owner.
    match authority.rsplit_once('@') {
        Some((_, host)) => {
            out.push_str("***@");
            out.push_str(host);
        }
        None => out.push_str(authority),
    }
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if looks_like_token(seg) {
            out.push_str("***");
        } else {
            out.push_str(seg);
        }
    }
    out
}

/// Does this path segment look like an opaque credential rather than a
/// name? Long, drawn from the hex/base64url alphabet, and carrying a
/// digit - which every 32-hex apikey does and `alt-binaries-teevee`
/// does not.
fn looks_like_token(seg: &str) -> bool {
    seg.len() >= 16
        && seg.bytes().any(|b| b.is_ascii_digit())
        && seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Is this incoming url the settings UI saying "I did not touch it"?
///
/// Two spellings, because two clients say it two ways: blank is the
/// convention every other credential in this file's neighbourhood uses
/// (a blank server password, a blank indexer apikey, a blank notify
/// token all mean "keep the stored one"), and the mask itself is what a
/// dashboard row sends back when the user edited the rules and left the
/// url alone. Either way the stored url is kept, and a genuinely NEW
/// url - which can never equal the mask of the old one - replaces it.
pub fn url_is_unchanged(incoming: &str, stored: &str) -> bool {
    let incoming = incoming.trim();
    incoming.is_empty() || incoming == mask_feed_url(stored)
}

/// What the last poll of one feed actually did.
///
/// The poller used to fold every fetch and parse failure into an empty
/// item list, so a revoked apikey, a typo'd host, a 403 and an indexer
/// that had simply gone away all looked identical to a feed with nothing
/// new to say: silent, forever, with the settings row still reading like
/// a healthy feed. This is the difference, kept per feed url and shipped
/// beside the feed in `get_config`.
///
/// Never build one of these by hand from a raw fetch error - use
/// [`FeedHealth::failed`], which strips the url. A feed url essentially
/// always carries the indexer's `apikey=`, and the fetch layer's errors
/// lead with the url they were given.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FeedHealth {
    /// Unix seconds when the last poll attempt finished. 0 = never
    /// polled (a feed added a moment ago, or a daemon just started).
    pub last_poll: i64,
    /// The last failure, with the url taken out. Empty when the last
    /// poll succeeded.
    pub last_error: String,
    /// Items the last SUCCESSFUL parse produced, before the rules ran.
    /// A feed that fetches fine and yields nothing is a rules or a
    /// retention question, not a connection one, and the two must not
    /// read the same on the row.
    pub items_seen: usize,
}

impl FeedHealth {
    /// A poll that fetched and parsed.
    pub fn ok(now: i64, items_seen: usize) -> FeedHealth {
        FeedHealth {
            last_poll: now,
            last_error: String::new(),
            items_seen,
        }
    }

    /// A poll that failed, with `redact` applied to the message. The
    /// caller passes the daemon's url redactor rather than this module
    /// growing its own copy of it.
    pub fn failed(now: i64, err: &str, redact: impl Fn(&str) -> String) -> FeedHealth {
        let msg = redact(err);
        let msg = msg.trim();
        FeedHealth {
            last_poll: now,
            // Bounded: an indexer that answers a 500 with a whole HTML
            // error page would otherwise put all of it in get_config
            // and in the settings row.
            last_error: msg.chars().take(200).collect(),
            items_seen: 0,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct FeedItem {
    pub title: String,
    /// NZB download URL (enclosure url, else <link>).
    pub link: String,
    pub size: u64,
    /// Dedupe identity: <guid>, else the link.
    pub guid: String,
    /// When the item says it was posted, as unix seconds: RSS
    /// `<pubDate>`, else Atom `<published>`/`<updated>`, else RSS 1.0
    /// `<dc:date>`. `None` is "this feed did not say", and the `age`
    /// terms treat that as unknown rather than as 1970 - see
    /// [`term_matches_at`].
    pub pub_date: Option<i64>,
}

/// A feed's idea of when an item was posted, as unix seconds.
///
/// Two grammars reach here, and which one a feed uses is not something
/// the caller knows: RSS spells its `<pubDate>` RFC 2822
/// ("Tue, 02 Jul 2026 15:04:05 +0000"), Atom spells `<published>` and
/// `<updated>` RFC 3339 ("2026-07-02T15:04:05Z"), and RSS 1.0's
/// `<dc:date>` is RFC 3339 inside an RSS document. So both are tried,
/// picked apart by shape rather than by which element the text came out
/// of - a newznab server serving Atom with an RSS-shaped date in it is
/// exactly the kind of mess this file already expects elsewhere.
///
/// `None` for anything unparseable, and the callers treat that as "the
/// age is unknown" rather than as 1970 - an epoch-shaped fallback would
/// make every undated item infinitely old and `Reject: age>30d` would
/// quietly eat the whole feed.
pub(crate) fn parse_feed_date(s: &str) -> Option<i64> {
    let s = s.trim();
    // RFC 3339 / ISO 8601 starts with the year: four digits then `-`.
    // Anything else goes to the RFC 2822 reader, which is the one that
    // starts with a weekday or a day number.
    let iso =
        s.len() >= 5 && s.as_bytes()[..4].iter().all(u8::is_ascii_digit) && s.as_bytes()[4] == b'-';
    if !iso {
        return crate::newznab::parse_rfc2822(s);
    }
    let (date, rest) = match s.find(['T', 't', ' ']) {
        Some(i) => (&s[..i], &s[i + 1..]),
        // A date with no time at all is legal ISO and means midnight UTC.
        None => (s, ""),
    };
    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let mon: u32 = d.next()?.parse().ok()?;
    let day: u32 = d.next()?.parse().ok()?;
    if !(1980..=3000).contains(&year) || !(1..=12).contains(&mon) || !(1..=31).contains(&day) {
        return None;
    }
    // The zone suffix, cut off the time before it is split on `:` - an
    // offset carries a colon of its own ("+02:00") and would otherwise
    // be read as more of the clock.
    let (time, off) = match rest.find(['Z', 'z']) {
        Some(i) => (&rest[..i], 0),
        None => match rest.rfind(['+', '-']) {
            Some(i) => {
                let z = &rest[i + 1..];
                let mut zp = z.split(':');
                let zh: i64 = zp.next().filter(|v| !v.is_empty())?.parse().ok()?;
                let zm: i64 = zp.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                if !(0..=23).contains(&zh) || !(0..=59).contains(&zm) {
                    return None;
                }
                let v = zh * 3600 + zm * 60;
                (&rest[..i], if rest.as_bytes()[i] == b'-' { -v } else { v })
            }
            // No zone at all: RFC 3339 requires one, feeds in the wild
            // omit it, and UTC is the only defensible reading of a
            // timestamp with no other information attached.
            None => (rest, 0),
        },
    };
    let mut t = time.split(':');
    let h: i64 = t
        .next()
        .filter(|v| !v.is_empty())
        .map_or(Ok(0), str::parse)
        .ok()?;
    let mi: i64 = t.next().map_or(Ok(0), str::parse).ok()?;
    // Fractional seconds are legal and carry nothing this needs.
    let sec: i64 = t
        .next()
        .map(|v| v.split(['.', ',']).next().unwrap_or(v))
        .map_or(Ok(0), str::parse)
        .ok()?;
    if !(0..=23).contains(&h) || !(0..=59).contains(&mi) || !(0..=60).contains(&sec) {
        return None;
    }
    Some(crate::newznab::days_from_civil(year, mon, day) * 86_400 + h * 3600 + mi * 60 + sec - off)
}

/// A duration written the way a filter rule writes one: `2d`, `36h`,
/// `90m`, `1w`, or a bare number of DAYS.
///
/// Days is the bare unit because the thing being measured is a post's
/// age and nobody thinks about that in seconds.
///
/// The unit is matched WHOLE against a table rather than on its first
/// letter, which is the difference between refusing `2mo` and silently
/// reading it as two minutes. Months and years are absent on purpose:
/// `m` has to mean one or the other and minutes is the one an age filter
/// wants, so the other spelling is refused rather than guessed at. An
/// unparseable term is `None`, which [`term_matches_at`] treats exactly
/// as it treats an unknown date - the term asserts nothing, so a typo
/// cannot silently reject a whole feed.
pub(crate) fn parse_age_secs(s: &str) -> Option<i64> {
    let s = s.trim().to_ascii_lowercase();
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let n: i64 = digits.parse().ok()?;
    let mult = match s[digits.len()..].trim() {
        "" | "d" | "day" | "days" => 86_400,
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600,
        "w" | "wk" | "wks" | "week" | "weeks" => 604_800,
        _ => return None,
    };
    n.checked_mul(mult)
}

/// Case-insensitive `*`/`?` wildcard match, anchored to the whole string.
///
/// One line, because the implementation moved down to nzbkit on 23 Aug
/// 2026: Smart Folders rules needed the same matcher (TODO 104 item 2,
/// #18) and `nzbkit::categories` cannot reach up into this crate. Feed
/// terms and Smart Folder patterns are both user-typed wildcards over a
/// release name, so one of them silently disagreeing with the other about
/// what `*x` means is a support call nobody can reproduce.
///
/// Not a pure move: the version that lived here tested the literal
/// compare BEFORE `*`, so a name containing a literal star could eat the
/// pattern's star as an ordinary character and `*x` did not match `*ax`.
/// The shared one orders the wildcards first (as
/// `groups::glob_matches` already did). It can only turn a non-match into
/// a match, never the reverse.
pub fn glob_match(pat: &str, s: &str) -> bool {
    nzbkit::categories::glob_match(pat, s)
}

/// One pattern term against an item: a size comparison, an age
/// comparison, or a title wildcard/substring.
///
/// `now` is passed in rather than read here so the age arm is testable
/// against a fixed clock; [`rules_judge`] reads it once per judgement so
/// every term in one rule list sees the same instant.
///
/// `age>2d` is "posted more than two days ago" and `age<7d` is "posted
/// less than seven days ago" - the two directions a usenet filter
/// actually wants, which are "old enough to have propagated everywhere"
/// and "not so old it is dead". An item whose feed gave no date matches
/// NEITHER: the term asserts nothing about an age it does not know, so a
/// `Reject: age>30d` cannot eat an undated feed and a
/// `Require: age>2h` cannot pass one.
fn term_matches_at(term: &str, item: &FeedItem, now: i64) -> bool {
    let term = term.trim();
    for (op, gt) in [(">", true), ("<", false)] {
        let after = |key: &str| {
            term.strip_prefix(key)
                .and_then(|r| r.trim_start().strip_prefix(op))
        };
        if let Some(rest) = after("size") {
            if let Some(n) = crate::sizes::parse_size(rest.trim()) {
                return if gt { item.size > n } else { item.size < n };
            }
            return false;
        }
        if let Some(rest) = after("age") {
            let (Some(want), Some(posted)) = (parse_age_secs(rest), item.pub_date) else {
                return false;
            };
            let age = now - posted;
            return if gt { age > want } else { age < want };
        }
    }
    if term.contains('*') || term.contains('?') {
        glob_match(term, &item.title)
    } else {
        item.title
            .to_ascii_lowercase()
            .contains(&term.to_ascii_lowercase())
    }
}

/// §129 2d: options an Accept rule may carry in parentheses -
/// `Accept(category=tv, priority=high): *1080p*` - so one feed can file
/// different matches differently. Only meaningful on Accept: Require
/// and Reject can only say no, and "no" has no destination.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RuleOpts {
    pub category: Option<String>,
    pub priority: Option<i32>,
}

/// SAB's priority names, or a bare number. None = not a priority.
pub fn parse_priority(s: &str) -> Option<i32> {
    match s.trim().to_ascii_lowercase().as_str() {
        "force" => Some(2),
        "high" => Some(1),
        "normal" => Some(0),
        "low" => Some(-1),
        other => other.parse().ok().filter(|p| (-2..=2).contains(p)),
    }
}

/// `accept(category=tv, priority=high)` -> ("accept", opts). Unknown
/// option keys and unparseable values are ignored rather than failing
/// the rule: the rules language has always shrugged at what it does not
/// recognise, and a typo must not silently turn a Reject into a no-op
/// AND kill the feed.
fn parse_kind(kind: &str) -> (String, RuleOpts) {
    let kind = kind.trim();
    let (base, rest) = match kind.split_once('(') {
        Some((b, r)) => (b, r.trim_end().strip_suffix(')').unwrap_or(r)),
        None => (kind, ""),
    };
    let mut opts = RuleOpts::default();
    for part in rest.split(',') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "category" | "cat" if !v.is_empty() => opts.category = Some(v.to_string()),
            "priority" | "prio" => opts.priority = parse_priority(v),
            _ => {}
        }
    }
    (base.trim().to_ascii_lowercase(), opts)
}

/// One item's fate under a feed's rules, carrying WHY - the dry-run
/// preview shows it verbatim - and the deciding Accept rule's options.
#[derive(Debug, PartialEq)]
pub struct Judgement {
    pub accept: bool,
    /// The rule that decided it, as written, or a stock phrase for the
    /// default outcomes.
    pub why: String,
    pub opts: RuleOpts,
}

/// Apply a feed's rule list and say which rule decided.
pub fn rules_judge(rules: &[String], item: &FeedItem) -> Judgement {
    rules_judge_at(rules, item, now_secs())
}

/// Wall-clock seconds. `serve`'s own `unix_now` is `pub(super)` inside
/// that module tree and this file is a sibling of it, not a child.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0)
}

/// [`rules_judge`] against a given instant. The clock is read ONCE per
/// judgement, not once per term: two `age` terms in one rule list have
/// to describe the same moment, and a test needs an instant it chose.
pub fn rules_judge_at(rules: &[String], item: &FeedItem, now: i64) -> Judgement {
    let mut has_accept = false;
    let mut accepted: Option<(String, RuleOpts)> = None;
    for rule in rules {
        let Some((kind, expr)) = rule.split_once(':') else {
            continue;
        };
        let hit = term_matches_at(expr, item, now);
        let (base, opts) = parse_kind(kind);
        match base.as_str() {
            "require" => {
                if !hit {
                    return Judgement {
                        accept: false,
                        why: format!("did not satisfy {}", rule.trim()),
                        opts: RuleOpts::default(),
                    };
                }
            }
            "reject" => {
                if hit {
                    return Judgement {
                        accept: false,
                        why: format!("matched {}", rule.trim()),
                        opts: RuleOpts::default(),
                    };
                }
            }
            "accept" => {
                has_accept = true;
                // First matching Accept wins - its options are the
                // deliberate ones for this pattern.
                if hit && accepted.is_none() {
                    accepted = Some((rule.trim().to_string(), opts));
                }
            }
            _ => {}
        }
    }
    match (has_accept, accepted) {
        (true, Some((why, opts))) => Judgement {
            accept: true,
            why: format!("matched {why}"),
            opts,
        },
        (true, None) => Judgement {
            accept: false,
            why: "no Accept rule matched".into(),
            opts: RuleOpts::default(),
        },
        (false, _) => Judgement {
            accept: true,
            why: "accepted (no Accept rules)".into(),
            opts: RuleOpts::default(),
        },
    }
}

/// Position and as-written name of the next element in `xml` whose
/// LOCAL name (the part after any `prefix:`) is `local`. A closing tag
/// never matches: its "name" starts with `/`. Matching the local name
/// is load-bearing - `<atom:entry>` is as good an entry as `<entry>`,
/// and literal-substring scans made every fully-prefixed Atom feed
/// parse to healthy-and-empty (Codex sweep 5 Aug M9).
pub(crate) fn find_elem<'a>(xml: &'a str, local: &str) -> Option<(usize, &'a str)> {
    xml.match_indices('<').find_map(|(at, _)| {
        let name = xml[at + 1..]
            .split(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .next()
            .unwrap_or_default();
        (name.rsplit(':').next().unwrap_or(name) == local).then_some((at, name))
    })
}

/// Raw tag text (`<` up to but excluding `>`) of every element in `xml`
/// whose local name is `local`, self-closing included.
pub(crate) fn elem_tags<'a>(xml: &'a str, local: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some((open, _)) = find_elem(&xml[at..], local) {
        let open = at + open;
        let end = xml[open..].find('>').map(|e| open + e).unwrap_or(xml.len());
        out.push(&xml[open..end]);
        at = end.max(open + 1);
    }
    out
}

pub(crate) fn tag_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    // Keep scanning past a matching element with no closing tag: an RSS
    // item can carry a self-closing `<atom:link rel="self"/>` ahead of
    // the `<link>` whose text is wanted, and stopping at the first
    // local-name hit would lose the real one.
    let mut at = 0;
    while let Some((open, name)) = find_elem(&xml[at..], tag) {
        let open = at + open;
        let gt = xml[open..].find('>')?;
        let start = open + gt + 1;
        if let Some(end) = xml[start..].find(&format!("</{name}>")) {
            return Some(xml[start..start + end].trim());
        }
        at = start;
    }
    None
}

pub(crate) fn unescape(s: &str) -> String {
    // ONE LEFT-TO-RIGHT PASS, which is what makes `&amp;` safe rather
    // than an ordering rule to remember. The chain of `replace` calls
    // this used to be had to decode `&amp;` LAST - doing it first turns
    // `&amp;lt;` (an escaped literal "&lt;") into `&lt;`, which the next
    // pass then wrongly decodes to "<". A single scan never revisits
    // what it has already emitted, so the hazard cannot arise.
    //
    // NUMERIC CHARACTER REFERENCES are decoded too, decimal and hex.
    // They are ordinary, valid XML that this parser used to leave
    // literal - and in a feed's `<link>` that is not cosmetic: `&#35;`
    // stayed as the four characters `&#35;`, so an indexer URL carrying
    // an escaped `#` was passed on with a fragment marker the server
    // never sees, silently truncating the query.
    let stripped = s.replace("<![CDATA[", "").replace("]]>", "");
    let mut out = String::with_capacity(stripped.len());
    let mut rest = stripped.as_str();
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        // Bounded: an unterminated `&` must not scan to the end of a
        // megabyte of feed, and anything that reaches whitespace or a
        // second `&` was never an entity to begin with.
        let semi = rest
            .char_indices()
            .skip(1)
            .take(12)
            .find(|(_, c)| *c == ';' || *c == '&' || c.is_whitespace())
            .filter(|(_, c)| *c == ';')
            .map(|(i, _)| i);
        let decoded = semi.and_then(|semi| match &rest[1..semi] {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "amp" => Some('&'),
            n => n.strip_prefix('#').and_then(|n| {
                match n.strip_prefix(['x', 'X']) {
                    Some(h) => u32::from_str_radix(h, 16).ok(),
                    None => n.parse::<u32>().ok(),
                }
                .and_then(char::from_u32)
            }),
        });
        match (decoded, semi) {
            (Some(c), Some(semi)) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            // Not an entity: the `&` is a literal, exactly as before.
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The value of attribute `name` in a start tag, to the XML attribute
/// grammar rather than to one spelling of it.
///
/// `format!("{name}=\"")` matched exactly one shape and got two things
/// wrong, both of which appear in valid feeds every day. SINGLE QUOTES
/// are as legal as double (`<enclosure url='...'/>`), and so is
/// whitespace either side of the `=`; a feed written that way lost the
/// attribute entirely, which for `url` means the row is dropped and for
/// a Newznab `<error code=.. description=..>` means a real quota
/// refusal reads as an empty result set, so the backoff never engages.
/// And the match was UNANCHORED, so asking for `url` found the tail of
/// `xmlUrl=` or `thumbnailUrl=` and returned that value instead - the
/// wrong link, silently.
pub(crate) fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let b = tag.as_bytes();
    let mut from = 0usize;
    while let Some(hit) = tag[from..].find(name) {
        let at = from + hit;
        from = at + name.len();
        // A whole attribute name: what precedes it is the tag opener or
        // separating whitespace, never the tail of a longer name.
        if at > 0 && !b[at - 1].is_ascii_whitespace() && b[at - 1] != b'<' {
            continue;
        }
        let mut j = from;
        while b.get(j).is_some_and(u8::is_ascii_whitespace) {
            j += 1;
        }
        if b.get(j) != Some(&b'=') {
            continue;
        }
        j += 1;
        while b.get(j).is_some_and(u8::is_ascii_whitespace) {
            j += 1;
        }
        let Some(&q) = b.get(j) else { continue };
        if q != b'"' && q != b'\'' {
            continue;
        }
        j += 1;
        let Some(end) = tag[j..].find(q as char) else {
            continue;
        };
        return Some(&tag[j..j + end]);
    }
    None
}

/// A body that came back HTTP 200 and is not a feed at all.
#[derive(Debug, Clone)]
pub struct FeedParseError(pub String);

impl std::fmt::Display for FeedParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// [`parse_feed`], but refusing a body that is not a feed (Codex sweep
/// 2, 3 Aug ML1).
///
/// The tolerant parser answers an empty list for anything it does not
/// recognise, which is the RIGHT answer for junk INSIDE a feed and the
/// wrong one for a body that is not a feed at all. An indexer whose
/// apikey was revoked serves an HTTP 200 login page, and every caller
/// then recorded "healthy, zero items" - the feed's settings row went
/// on saying it was fine while it silently stopped grabbing anything.
///
/// The check is deliberately shallow: a recognizable feed root and
/// nothing more. A genuinely empty feed is valid and must stay healthy,
/// and the parser's tolerance for namespace prefixes, junk elements and
/// half-formed items is load-bearing - feeds in the wild are messy.
pub fn parse_feed_checked(xml: &str) -> Result<Vec<FeedItem>, FeedParseError> {
    // Compare the LOCAL name, cutting any `prefix:` between the `<` and
    // the element name. A namespace prefix is legal on the root as much
    // as anywhere else - `<atom:feed xmlns:atom="…">` is a perfectly
    // good Atom document, and `<r:RDF>` a perfectly good RSS 1.0 one -
    // but matching the literal strings refused both, so a valid feed
    // went red in Settings and grabbing stopped. That is the same
    // outcome this check exists to prevent, reached from the other
    // side, and the parser below is deliberately prefix-tolerant.
    const FEED_ROOTS: [&str; 4] = ["rss", "feed", "rdf", "channel"];
    match wrong_document(xml, &FEED_ROOTS, "an RSS or Atom feed") {
        Some(what) => Err(FeedParseError(what)),
        None => Ok(parse_feed(xml)),
    }
}

/// Does this body look like the kind of document it was fetched as, and
/// if not, what does it look like instead?
///
/// `roots` are the local element names whose presence near the top means
/// yes; `want` names the document for the fallback sentence. `Some` is a
/// user-facing line naming what arrived instead, because "not a feed"
/// alone sends a user hunting in the wrong place and a login page is by
/// far the commonest answer.
///
/// Shared with §151's Plex readers, which need this exact check against a
/// different root (`MediaContainer`) for the same reason: an expired
/// token is answered with an HTTP 200 that is not the document at all,
/// and a tolerant parser would call that a healthy empty list.
pub(crate) fn wrong_document(xml: &str, roots: &[&str], want: &str) -> Option<String> {
    // Byte-limited scan: only the document's opening needs looking at,
    // and a multi-megabyte body of HTML must not be lowercased whole.
    let head: String = xml.chars().take(4096).collect::<String>().to_lowercase();
    let looks_right = head.match_indices('<').any(|(at, _)| {
        let name = head[at + 1..]
            .split(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .next()
            .unwrap_or_default();
        // `head` is lowercased, so the roots are compared case-blind -
        // XML element names are case-SENSITIVE and Plex's root is
        // `MediaContainer`, which a literal `contains` would never see.
        let local = name.rsplit(':').next().unwrap_or(name);
        roots.iter().any(|r| r.eq_ignore_ascii_case(local))
    });
    if looks_right {
        return None;
    }
    Some(
        if head.contains("<html") || head.contains("<!doctype html") {
            format!(
                "the server answered with a web page, not {want} - \
             the address is probably wrong, or the credential has been \
             revoked and this is a login page"
            )
        } else if head.contains("<error") {
            // A newznab error document IS the answer to "why is this feed
            // empty", and it usually says "Incorrect user credentials".
            // Reporting the generic line instead threw away the one message
            // that names the cause.
            "the server answered with an error, not a document - \
         check the credential and the address"
                .to_string()
        } else if head.trim().is_empty() {
            "the server answered with an empty body".to_string()
        } else {
            format!("the server's answer is not {want}")
        },
    )
}

/// Minimal RSS 2.0 + Atom parser: `<item>` (RSS) and `<entry>` (Atom)
/// blocks with title, enclosure/link, size (enclosure length, else
/// newznab size attr), guid. Tolerant of namespaces and junk - feeds in
/// the wild are messy.
///
/// Both grammars, in one pass each, because [`parse_feed_checked`]
/// ACCEPTS an Atom root and a caller that is told its feed is healthy
/// must actually get its entries. Reading only `<item>` meant a valid
/// Atom feed recorded "healthy, 0 items" for ever and silently grabbed
/// nothing - the same failure `parse_feed_checked` exists to prevent,
/// reached one layer further in.
///
/// Callers that RECORD FEED HEALTH want [`parse_feed_checked`]: this
/// one cannot tell an empty feed from a body that is not a feed.
pub fn parse_feed(xml: &str) -> Vec<FeedItem> {
    let mut out = parse_rss_items(xml);
    // A document is one grammar or the other, so this costs a `find`
    // that fails on every RSS feed there has ever been.
    out.extend(parse_atom_entries(xml));
    out
}

fn parse_rss_items(xml: &str) -> Vec<FeedItem> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some((open, name)) = find_elem(rest, "item") {
        let close_pat = format!("</{name}>");
        let Some(close) = rest[open..].find(&close_pat) else {
            break;
        };
        let item = &rest[open..open + close];
        let title = tag_text(item, "title").map(unescape).unwrap_or_default();
        let enclosure = elem_tags(item, "enclosure").into_iter().next();
        let link = enclosure
            .and_then(|e| attr(e, "url"))
            .map(str::to_string)
            .or_else(|| tag_text(item, "link").map(str::to_string))
            .map(|l| unescape(&l))
            .unwrap_or_default();
        let size = enclosure
            .and_then(|e| attr(e, "length"))
            .and_then(|v| v.parse().ok())
            .or_else(|| {
                // newznab: <newznab:attr name="size" value="123"/>
                item.split("<newznab:attr").skip(1).find_map(|a| {
                    let a = &a[..a.find('>').unwrap_or(a.len())];
                    (attr(a, "name") == Some("size"))
                        .then(|| attr(a, "value")?.parse().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);
        let guid = tag_text(item, "guid")
            .map(unescape)
            .filter(|g| !g.is_empty())
            .unwrap_or_else(|| link.clone());
        // `<pubDate>` is the RSS 2.0 spelling; `<dc:date>` is RSS 1.0's,
        // and newznab servers emit it beside pubDate often enough to be
        // worth the second `find` that costs nothing when it is absent.
        let pub_date = ["pubdate", "pubDate", "date", "published", "updated"]
            .iter()
            .find_map(|t| tag_text(item, t))
            .map(unescape)
            .and_then(|d| parse_feed_date(&d));
        if !title.is_empty() && !link.is_empty() {
            out.push(FeedItem {
                title,
                link,
                size,
                guid,
                pub_date,
            });
        }
        rest = &rest[open + close + close_pat.len()..];
    }
    out
}

/// The Atom half: `<entry>` blocks.
///
/// The differences that matter are all in how the NZB is pointed at.
/// Atom has no `<enclosure>` element - it carries the same thing as a
/// `<link rel="enclosure" href="…" length="…">`, and its plain
/// `<link href="…">` (rel absent, or "alternate") is the human page.
/// The download link is preferred, exactly as the RSS half prefers an
/// enclosure over `<link>`; a feed with only an alternate link still
/// yields an item, because that is what the RSS half does with a bare
/// `<link>` too. `<id>` stands in for `<guid>`.
fn parse_atom_entries(xml: &str) -> Vec<FeedItem> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some((open, name)) = find_elem(rest, "entry") {
        let close_pat = format!("</{name}>");
        let Some(close) = rest[open..].find(&close_pat) else {
            break;
        };
        let entry = &rest[open..open + close];
        let title = tag_text(entry, "title").map(unescape).unwrap_or_default();
        // Every <link .../> in the entry, as its raw tag text.
        let links: Vec<&str> = elem_tags(entry, "link");
        let rel = |l: &str| attr(l, "rel").unwrap_or("alternate").to_ascii_lowercase();
        let download = links
            .iter()
            .find(|l| rel(l) == "enclosure")
            // A feed that declares the type but not the rel still means
            // "this one is the file".
            .or_else(|| {
                links
                    .iter()
                    .find(|l| attr(l, "type").is_some_and(|t| t.contains("nzb")))
            })
            .copied();
        let link = download
            .or_else(|| links.first().copied())
            .and_then(|l| attr(l, "href"))
            .map(str::to_string)
            // Some newznab servers serve Atom with an RSS-shaped
            // <enclosure url="…"> bolted in; take it rather than lose
            // the entry.
            .or_else(|| {
                let tag = elem_tags(entry, "enclosure").into_iter().next()?;
                attr(tag, "url").map(str::to_string)
            })
            .map(|l| unescape(&l))
            .unwrap_or_default();
        let size = download
            .and_then(|l| attr(l, "length"))
            .and_then(|v| v.parse().ok())
            .or_else(|| {
                entry.split("<newznab:attr").skip(1).find_map(|a| {
                    let a = &a[..a.find('>').unwrap_or(a.len())];
                    (attr(a, "name") == Some("size"))
                        .then(|| attr(a, "value")?.parse().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);
        let guid = tag_text(entry, "id")
            .map(unescape)
            .filter(|g| !g.is_empty())
            .unwrap_or_else(|| link.clone());
        // `<published>` is when the entry first appeared and `<updated>`
        // is when it last changed; only the first answers "how old is
        // this post", so it is preferred and `<updated>` is the fallback
        // for the many feeds that ship only the required one.
        let pub_date = ["published", "pubdate", "pubDate", "updated", "date"]
            .iter()
            .find_map(|t| tag_text(entry, t))
            .map(unescape)
            .and_then(|d| parse_feed_date(&d));
        if !title.is_empty() && !link.is_empty() {
            out.push(FeedItem {
                title,
                link,
                size,
                guid,
                pub_date,
            });
        }
        rest = &rest[open + close + close_pat.len()..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(title: &str, size: u64) -> FeedItem {
        FeedItem {
            title: title.into(),
            link: "http://x/nzb".into(),
            size,
            guid: "g".into(),
            pub_date: None,
        }
    }

    /// [`item`] with a posting date, for the age arm.
    fn dated_item(title: &str, posted: i64) -> FeedItem {
        FeedItem {
            pub_date: Some(posted),
            ..item(title, 0)
        }
    }

    /// The 2d refactor folded the old boolean `rules_accept` into
    /// [`rules_judge`]; this shim keeps the pre-2d semantics asserted
    /// below without shipping a dead public function.
    fn rules_accept(rules: &[String], item: &FeedItem) -> bool {
        rules_judge(rules, item).accept
    }

    fn feed(url: &str, category: &str, rules: &[&str]) -> FeedConfig {
        FeedConfig {
            id: new_feed_id(),
            url: url.into(),
            interval_secs: 900,
            category: category.into(),
            rules: rules.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// The scope key is what makes the durable seen-guid set per feed
    /// rather than global. Two feeds must never share one, or an item
    /// with `guid = 123` in feed A suppresses a DIFFERENT item with
    /// `guid = 123` in feed B, across restarts (Codex sweep 12 Aug F12).
    ///
    /// And it must not be the url: a feed url essentially always carries
    /// the indexer's apikey, and this value is written to `rss-seen.json`.
    #[test]
    fn a_feed_scope_key_is_stable_distinct_and_carries_no_credential() {
        let a = feed("https://indexer/rss?apikey=SECRET1", "tv", &[]);
        let b = feed("https://indexer/rss?apikey=SECRET2", "tv", &[]);
        assert_eq!(a.scope_key(), a.clone().scope_key(), "must be stable");
        assert_ne!(a.scope_key(), b.scope_key(), "two feeds, two scopes");
        for k in [a.scope_key(), b.scope_key()] {
            assert!(!k.contains("SECRET"), "the key leaked the url: {k}");
            assert!(!k.contains("apikey"), "the key leaked the url: {k}");
            assert!(k.chars().all(|c| c.is_ascii_hexdigit()), "{k}");
        }
        // Interval is not identity: changing the cadence must not orphan
        // every guid this feed has already judged.
        let mut slower = a.clone();
        slower.interval_secs = 60;
        assert_eq!(a.scope_key(), slower.scope_key());
    }

    /// The RSS loop snapshots a feed, awaits a fetch that can take most of
    /// a minute, then applies the SNAPSHOT's rules and category. The
    /// fingerprint is how a poll checks it still has authority to do that
    /// (Codex sweep 12 Aug F6b): everything that changes what a poll MEANS
    /// is in it, and the cadence - which only decides when the next one
    /// runs - is not.
    #[test]
    fn a_fetch_fingerprint_covers_what_changes_the_meaning_of_a_poll() {
        let base = feed("https://i/rss", "tv", &["accept:*1080p*"]);
        let same = base.clone();
        assert_eq!(base.fetch_fingerprint(), same.fetch_fingerprint());

        let mut slower = base.clone();
        slower.interval_secs = 60;
        assert_eq!(
            base.fetch_fingerprint(),
            slower.fetch_fingerprint(),
            "cadence is not authority"
        );

        for changed in [
            feed("https://other/rss", "tv", &["accept:*1080p*"]),
            feed("https://i/rss", "movies", &["accept:*1080p*"]),
            feed("https://i/rss", "tv", &["accept:*2160p*"]),
            feed("https://i/rss", "tv", &[]),
        ] {
            assert_ne!(
                base.fetch_fingerprint(),
                changed.fetch_fingerprint(),
                "an edit that changes what the poll means must revoke it: {changed:?}"
            );
        }
    }

    #[test]
    fn globs() {
        assert!(glob_match("*1080p*", "Show.S01E02.1080p.WEB"));
        assert!(!glob_match("*1080p*", "Show.S01E02.720p.WEB"));
        assert!(glob_match("show*web", "Show.S01E02.1080p.WEB"));
        assert!(glob_match("s??e02", "S01E02"));
        assert!(!glob_match("s??e02", "S1E02"));
    }

    #[test]
    fn rule_semantics() {
        let rules = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Accept-list: must match one.
        let r = rules(&["Accept: *1080p*", "Accept: *2160p*"]);
        assert!(rules_accept(&r, &item("A.2160p.REMUX", 0)));
        assert!(!rules_accept(&r, &item("A.720p", 0)));
        // Reject beats accept.
        let r = rules(&["Reject: *HDCAM*", "Accept: *1080p*"]);
        assert!(!rules_accept(&r, &item("A.1080p.HDCAM", 0)));
        // Require size window.
        let r = rules(&["Require: size>700M", "Require: size<10G"]);
        assert!(rules_accept(&r, &item("A", 5_000_000_000)));
        assert!(!rules_accept(&r, &item("A", 100_000_000)));
        assert!(!rules_accept(&r, &item("A", 50_000_000_000)));
        // No rules → accept everything.
        assert!(rules_accept(&[], &item("anything", 0)));
        // Substring term (no wildcard).
        let r = rules(&["Reject: hdcam"]);
        assert!(!rules_accept(&r, &item("A.HDCAM.x264", 0)));
    }

    /// §129 2d: an Accept rule's parenthesised options ride the
    /// judgement; Require/Reject stay pure vetoes; junk options are
    /// ignored rather than fatal.
    #[test]
    fn accept_options_carry_category_and_priority() {
        let rules: Vec<String> = [
            "Reject: *HDCAM*",
            "Accept(category=tv, priority=high): *1080p*",
            "Accept: *720p*",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let j = rules_judge(&rules, &item("A.1080p", 0));
        assert!(j.accept);
        assert_eq!(j.opts.category.as_deref(), Some("tv"));
        assert_eq!(j.opts.priority, Some(1));
        assert!(j.why.contains("Accept(category=tv"), "{}", j.why);
        // A plain Accept carries no options.
        let j = rules_judge(&rules, &item("A.720p", 0));
        assert!(j.accept);
        assert_eq!(j.opts, RuleOpts::default());
        // Reject wins and names the rule that decided.
        let j = rules_judge(&rules, &item("A.1080p.HDCAM", 0));
        assert!(!j.accept);
        assert!(j.why.contains("Reject: *HDCAM*"), "{}", j.why);
        // Priority spellings; a bad value is simply not a priority.
        assert_eq!(parse_priority("force"), Some(2));
        assert_eq!(parse_priority("low"), Some(-1));
        assert_eq!(parse_priority("-1"), Some(-1));
        assert_eq!(parse_priority("nonsense"), None);
        // Unknown option keys do not kill the rule.
        let j = rules_judge(&["Accept(colour=blue): *x*".to_string()], &item("x", 0));
        assert!(j.accept);
        assert_eq!(j.opts, RuleOpts::default());
    }

    /// Attributes are read to the XML GRAMMAR, not to one spelling of
    /// it, and the name has to be a whole name.
    ///
    /// Single quotes and whitespace around `=` are as valid as the
    /// double-quoted no-space form, and a feed written either way used
    /// to lose the attribute outright - which for `url` drops the row
    /// and for a Newznab `<error code=.. description=..>` turns a real
    /// quota refusal into an empty result set, so the backoff never
    /// engages. The unanchored match was the quieter half: asking for
    /// `url` found the tail of `xmlUrl=` and returned the WRONG link
    /// with nothing to say so.
    #[test]
    fn attributes_are_read_to_the_xml_grammar() {
        assert_eq!(attr(r#"<a url="x">"#, "url"), Some("x"));
        assert_eq!(attr(r#"<a url='x'>"#, "url"), Some("x"), "single quotes");
        assert_eq!(attr(r#"<a url = "x">"#, "url"), Some("x"), "space around =");
        assert_eq!(attr("<a url	=	'x'>", "url"), Some("x"), "tabs around =");
        // A value containing the OTHER quote character survives.
        assert_eq!(attr(r#"<a url='a"b'>"#, "url"), Some(r#"a"b"#));
        assert_eq!(attr(r#"<a url="a'b">"#, "url"), Some("a'b"));
        // Anchoring: a longer attribute whose tail spells the name is
        // not this attribute.
        assert_eq!(
            attr(r#"<a xmlUrl="wrong" url="right">"#, "url"),
            Some("right")
        );
        assert_eq!(attr(r#"<a thumbnailUrl="wrong">"#, "url"), None);
        // Absent, and malformed, stay None rather than reading past.
        assert_eq!(attr(r#"<a href="x">"#, "url"), None);
        assert_eq!(attr("<a url=>", "url"), None);
        assert_eq!(attr("<a url=x>", "url"), None, "unquoted is not XML");
        assert_eq!(attr(r#"<a url="unterminated>"#, "url"), None);
    }

    /// Entities are decoded in one left-to-right pass, numeric ones
    /// included.
    ///
    /// A decimal or hex character reference is ordinary valid XML that
    /// this parser used to leave literal - and inside a `<link>` that is
    /// not cosmetic: `&#35;` stayed as four characters, so an indexer
    /// URL carrying an escaped `#` was handed on with a fragment marker
    /// the server never sees, truncating the query. The single pass is
    /// also what keeps the old ordering hazard from coming back:
    /// `&amp;lt;` must stay `&lt;`, never become `<`.
    #[test]
    fn entities_including_numeric_references_are_decoded_once() {
        assert_eq!(unescape("a &amp; b"), "a & b");
        assert_eq!(unescape("&lt;i&gt;"), "<i>");
        assert_eq!(unescape("&quot;q&quot; &apos;a&apos;"), "\"q\" 'a'");
        // The ordering hazard, which a single pass cannot reintroduce.
        assert_eq!(unescape("&amp;lt;"), "&lt;");
        // Numeric, decimal and hex, upper and lower x.
        assert_eq!(unescape("a&#35;b"), "a#b");
        assert_eq!(unescape("a&#x23;b"), "a#b");
        assert_eq!(unescape("a&#X23;b"), "a#b");
        assert_eq!(unescape("&#233;t&#233;"), "été");
        assert_eq!(unescape("&#x1F600;"), "\u{1F600}");
        // Not entities: a bare ampersand, an unterminated one, a
        // nonsense name, an out-of-range code point. All stay literal.
        assert_eq!(unescape("a & b"), "a & b");
        assert_eq!(unescape("a &amp b"), "a &amp b");
        assert_eq!(unescape("&nosuch;"), "&nosuch;");
        assert_eq!(unescape("&#xFFFFFFFF;"), "&#xFFFFFFFF;");
        assert_eq!(unescape("&#;"), "&#;");
        // ...and an unterminated `&` at the very end does not hang or
        // eat the tail.
        assert_eq!(unescape("tail &"), "tail &");
        assert_eq!(unescape("&#3"), "&#3");
        // CDATA wrappers still come off.
        assert_eq!(unescape("<![CDATA[a &amp; b]]>"), "a & b");
    }

    #[test]
    fn parses_rss() {
        let xml = r#"<?xml version="1.0"?><rss><channel>
<item><title>Show.S01E02.1080p.WEB</title>
<guid isPermaLink="false">abc-123</guid>
<enclosure url="https://idx/get/abc?apikey=k" length="3221225472" type="application/x-nzb"/>
<newznab:attr name="category" value="5040"/>
</item>
<item><title>Movie &amp; More.2026.720p</title>
<link>https://idx/get/def</link>
<newznab:attr name="size" value="1500000000"/>
</item>
</channel></rss>"#;
        let items = parse_feed(xml);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Show.S01E02.1080p.WEB");
        assert_eq!(items[0].link, "https://idx/get/abc?apikey=k");
        assert_eq!(items[0].size, 3_221_225_472);
        assert_eq!(items[0].guid, "abc-123");
        assert_eq!(items[1].title, "Movie & More.2026.720p");
        assert_eq!(items[1].size, 1_500_000_000);
        assert_eq!(items[1].guid, "https://idx/get/def");
    }

    /// Codex sweep 2, 3 Aug ML1: an HTTP 200 that is not a feed used to
    /// parse to an empty list and be recorded as "healthy, no items",
    /// so a revoked apikey's login page looked exactly like a quiet
    /// feed - for as long as the user left it there.
    #[test]
    fn a_body_that_is_not_a_feed_is_a_failure_not_an_empty_feed() {
        let login = "<!DOCTYPE html><html><head><title>Sign in</title></head>\
                     <body><form><input name=\"user\"></form></body></html>";
        let e = parse_feed_checked(login).expect_err("a login page is not a feed");
        assert!(e.to_string().contains("web page"), "{e}");
        // Nothing of the body itself is echoed - it is attacker-shaped
        // text on its way to the settings row.
        assert!(!e.to_string().contains("Sign in"), "{e}");

        assert!(
            parse_feed_checked("").is_err(),
            "an empty body is not a feed"
        );
        assert!(
            parse_feed_checked("{\"error\":\"bad apikey\"}").is_err(),
            "a JSON error body is not a feed"
        );

        // ...and the tolerance that matters is untouched: a genuinely
        // EMPTY feed is valid and stays healthy, junk inside a feed is
        // still skipped rather than failing the whole poll, and Atom
        // and RDF roots are feeds too.
        let empty = "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel>\
                     <title>Nothing new</title></channel></rss>";
        assert_eq!(parse_feed_checked(empty).unwrap().len(), 0);
        let junky = "<?xml version=\"1.0\"?><rss><channel>\
                     <item><title>no link at all</title></item>\
                     <item><title>Good.Release</title><link>https://x/1</link></item>\
                     </channel></rss>";
        assert_eq!(parse_feed_checked(junky).unwrap().len(), 1);
        assert!(parse_feed_checked("<feed xmlns=\"http://www.w3.org/2005/Atom\"/>").is_ok());
        assert!(parse_feed_checked("<rdf:RDF><channel/></rdf:RDF>").is_ok());

        // An Atom root is ACCEPTED, so its entries have to come back:
        // the empty-root assertions above passed while a real Atom feed
        // recorded "healthy, 0 items" and grabbed nothing for ever.
        let atom = "<?xml version=\"1.0\"?>\
            <feed xmlns=\"http://www.w3.org/2005/Atom\">\
              <title>An indexer</title>\
              <entry>\
                <title>Some.Release.1080p.WEB</title>\
                <id>urn:uuid:abc-123</id>\
                <link rel=\"alternate\" href=\"https://x/details/1\"/>\
                <link rel=\"enclosure\" type=\"application/x-nzb\" \
                      href=\"https://x/getnzb/1&amp;i=7\" length=\"4096\"/>\
              </entry>\
            </feed>";
        let got = parse_feed_checked(atom).expect("a real Atom feed is a feed");
        assert_eq!(got.len(), 1, "the Atom entry was not parsed: {got:?}");
        assert_eq!(got[0].title, "Some.Release.1080p.WEB");
        // The enclosure link wins over the human details page, and the
        // ampersand is unescaped exactly as the RSS half unescapes it.
        assert_eq!(got[0].link, "https://x/getnzb/1&i=7");
        assert_eq!(got[0].size, 4096);
        assert_eq!(got[0].guid, "urn:uuid:abc-123");

        // No enclosure at all: the alternate link is still a link, the
        // same way a bare RSS <link> is. Size falls back to the
        // newznab attr.
        let plain = "<feed xmlns=\"http://www.w3.org/2005/Atom\"><entry>\
            <title>Other.Release</title>\
            <link href=\"https://x/2\"/>\
            <newznab:attr name=\"size\" value=\"1234\"/>\
            </entry></feed>";
        let got = parse_feed(plain);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].link, "https://x/2");
        assert_eq!(got[0].size, 1234);
        // No <id>: the link stands in for the guid, as it does in RSS.
        assert_eq!(got[0].guid, "https://x/2");

        // A namespace PREFIX on the root is legal, and the roots were
        // matched as literal strings - so these valid feeds were
        // refused, the settings row went red and grabbing stopped,
        // which is the failure the check exists to prevent arriving
        // from the other side.
        assert!(
            parse_feed_checked(
                "<?xml version=\"1.0\"?><atom:feed \
                 xmlns:atom=\"http://www.w3.org/2005/Atom\"/>"
            )
            .is_ok(),
            "a prefixed Atom root is still an Atom feed"
        );
        assert!(
            parse_feed_checked("<r:RDF xmlns:r=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"/>")
                .is_ok(),
            "RSS 1.0 may bind RDF to any prefix"
        );
        // A fully PREFIXED Atom document: every descendant carries the
        // prefix too. The root was accepted by local name while the
        // entry scan matched literal `<entry`, so the feed validated
        // and then parsed to healthy-and-empty for ever (Codex sweep
        // 5 Aug M9) - the exact silent failure the checked parser
        // exists to prevent, one layer further in.
        let prefixed = "<?xml version=\"1.0\"?>\
            <atom:feed xmlns:atom=\"http://www.w3.org/2005/Atom\">\
              <atom:entry>\
                <atom:title>Prefixed.Release.2160p</atom:title>\
                <atom:id>urn:uuid:pref-1</atom:id>\
                <atom:link rel=\"alternate\" href=\"https://x/details/9\"/>\
                <atom:link rel=\"enclosure\" type=\"application/x-nzb\" \
                      href=\"https://x/getnzb/9\" length=\"2048\"/>\
              </atom:entry>\
            </atom:feed>";
        let got = parse_feed_checked(prefixed).expect("a prefixed Atom feed is a feed");
        assert_eq!(got.len(), 1, "the prefixed entry was not parsed: {got:?}");
        assert_eq!(got[0].title, "Prefixed.Release.2160p");
        assert_eq!(got[0].link, "https://x/getnzb/9");
        assert_eq!(got[0].size, 2048);
        assert_eq!(got[0].guid, "urn:uuid:pref-1");

        // An RSS item with a self-closing <atom:link rel="self"/> ahead
        // of its real <link>: local-name matching must keep scanning
        // past the close-less element rather than losing the link.
        let selflink = "<rss><channel><item>\
            <title>Rss.With.AtomSelf</title>\
            <atom:link rel=\"self\" href=\"https://x/feed\"/>\
            <link>https://x/3</link>\
            </item></channel></rss>";
        let got = parse_feed(selflink);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].link, "https://x/3");

        // And the refusals must not have loosened with it.
        assert!(
            parse_feed_checked("<!doctype html><html><body>login</body></html>").is_err(),
            "a login page is still not a feed"
        );
        assert!(
            parse_feed_checked("<notafeed><item/></notafeed>").is_err(),
            "an unrelated root is still not a feed"
        );
    }

    /// §G. The recorded failure crosses to the browser and sits on the
    /// settings row, so it goes through the url redactor on the way in -
    /// a feed url essentially always carries the indexer's apikey, and
    /// the fetch layer's errors lead with the url they were handed.
    #[test]
    fn a_recorded_feed_failure_carries_no_apikey() {
        let raw = "https://idx.example/rss?apikey=DEADBEEF&t=tv: status code 403";
        let h = FeedHealth::failed(99, raw, crate::netfetch::redact_url_creds);
        assert!(!h.last_error.contains("DEADBEEF"), "{}", h.last_error);
        assert!(!h.last_error.contains("apikey"), "{}", h.last_error);
        // Still worth reading: the host and what went wrong survive.
        assert!(h.last_error.contains("idx.example"), "{}", h.last_error);
        assert!(h.last_error.contains("403"), "{}", h.last_error);
        assert_eq!(h.last_poll, 99);
        assert_eq!(h.items_seen, 0, "a failed poll saw nothing");
    }

    #[test]
    fn a_feed_error_cannot_grow_without_bound() {
        // An indexer answering a 500 with a whole HTML error page must
        // not put all of it in get_config and in the row.
        let h = FeedHealth::failed(1, &"x".repeat(5000), str::to_string);
        assert_eq!(h.last_error.chars().count(), 200);
    }

    #[test]
    fn a_feed_that_fetched_but_matched_nothing_is_not_an_error() {
        // The distinction the row is for: zero items with no error is a
        // rules or retention question; zero items WITH one is a broken
        // feed, and they used to look identical.
        let h = FeedHealth::ok(5, 0);
        assert!(h.last_error.is_empty());
        assert_eq!(h.items_seen, 0);
        assert_eq!(h.last_poll, 5);
    }

    /// §163 item 1: both date grammars a feed can use, and the shapes
    /// that turn up around them. RSS spells its pubDate RFC 2822 and
    /// Atom spells its published RFC 3339, and a parser that read only
    /// one of them would leave every feed of the other kind undated -
    /// which, because an undated item matches no age term at all, is a
    /// silent "this filter does nothing".
    #[test]
    fn a_feed_date_is_read_in_both_grammars() {
        // 2026-07-02T15:04:05Z
        const T: i64 = 1_783_004_645;
        for s in [
            "Thu, 02 Jul 2026 15:04:05 +0000",
            "Thu, 02 Jul 2026 15:04:05 GMT",
            "2026-07-02T15:04:05Z",
            "2026-07-02t15:04:05z",
            "2026-07-02T15:04:05.123Z",
            "2026-07-02 15:04:05",
            "2026-07-02T15:04:05",
        ] {
            assert_eq!(parse_feed_date(s), Some(T), "{s}");
        }
        // Offsets move the instant, in both directions and on both
        // grammars - a feed served in local time is the commonest way a
        // date is right to the hour and wrong by a day's filtering.
        assert_eq!(
            parse_feed_date("2026-07-02T17:04:05+02:00"),
            Some(T),
            "positive offset"
        );
        assert_eq!(
            parse_feed_date("2026-07-02T11:04:05-04:00"),
            Some(T),
            "negative offset"
        );
        assert_eq!(
            parse_feed_date("Thu, 02 Jul 2026 11:04:05 -0400"),
            Some(T),
            "rfc 2822 offset"
        );
        // A date with no clock is midnight UTC, not a parse failure.
        assert_eq!(parse_feed_date("2026-07-02"), Some(T - 15 * 3600 - 245));
        // And anything that is not a date is None rather than 1970: the
        // whole age arm turns on telling "old" from "we were not told".
        for bad in [
            "",
            "no",
            "2026-13-02T00:00:00Z",
            "2026-07-02T99:00:00Z",
            "-",
        ] {
            assert_eq!(parse_feed_date(bad), None, "{bad:?}");
        }
    }

    /// The unit suffix, including the two decisions in it: a bare number
    /// is DAYS, and `m` is minutes.
    #[test]
    fn an_age_term_reads_its_unit() {
        assert_eq!(parse_age_secs("2d"), Some(172_800));
        assert_eq!(parse_age_secs("2"), Some(172_800), "bare = days");
        assert_eq!(parse_age_secs("36h"), Some(129_600));
        assert_eq!(parse_age_secs("90m"), Some(5_400), "m is minutes");
        assert_eq!(parse_age_secs("30s"), Some(30));
        assert_eq!(parse_age_secs("1w"), Some(604_800));
        assert_eq!(parse_age_secs("2 days"), Some(172_800));
        assert_eq!(parse_age_secs("36 hrs"), Some(129_600));
        assert_eq!(parse_age_secs("0d"), Some(0));
        for bad in ["", "d", "2y", "2mo", "-2d", "abc"] {
            assert_eq!(parse_age_secs(bad), None, "{bad:?}");
        }
    }

    /// The filter itself, in both directions, against a fixed clock.
    #[test]
    fn age_terms_filter_in_both_directions() {
        const NOW: i64 = 1_800_000_000;
        let day = 86_400;
        let fresh = dated_item("Show.S01E01", NOW - 3600); // an hour old
        let old = dated_item("Show.S01E02", NOW - 30 * day); // a month old
        let judge = |rules: &[&str], it: &FeedItem| {
            rules_judge_at(
                &rules.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                it,
                NOW,
            )
            .accept
        };
        // "old enough to have propagated": hold anything under 2 hours.
        assert!(!judge(&["Require: age>2h"], &fresh));
        assert!(judge(&["Require: age>2h"], &old));
        // "not so old it is dead": drop anything over a week.
        assert!(judge(&["Require: age<7d"], &fresh));
        assert!(!judge(&["Require: age<7d"], &old));
        // Reject is the same term from the other side.
        assert!(!judge(&["Reject: age>7d"], &old));
        assert!(judge(&["Reject: age>7d"], &fresh));
        // Spacing around the operator, as the size arm allows.
        assert!(judge(&["Require: age > 2h"], &old));
        // And an age term composes with the rest of the language rather
        // than replacing it.
        assert!(judge(&["Require: age<7d", "Accept: *S01E01*"], &fresh));
        assert!(!judge(&["Require: age<7d", "Accept: *S01E99*"], &fresh));
    }

    /// An item the feed gave no date for matches NEITHER direction. The
    /// alternative - treating a missing date as the epoch - makes every
    /// undated item infinitely old, so one `Reject: age>30d` would
    /// silently swallow a whole feed that simply does not date its
    /// items. "We were not told" is not "it is old".
    #[test]
    fn an_undated_item_matches_no_age_term() {
        const NOW: i64 = 1_800_000_000;
        let undated = item("Show.S01E01", 0);
        assert!(undated.pub_date.is_none());
        let judge = |r: &str| rules_judge_at(&[r.to_string()], &undated, NOW).accept;
        assert!(!judge("Require: age>2h"), "cannot satisfy an unknown age");
        assert!(!judge("Require: age<2h"), "nor the other direction");
        assert!(judge("Reject: age>30d"), "and cannot be rejected on one");
        // A malformed unit is the same non-answer, on a DATED item, so
        // a typo cannot silently reject the feed either.
        let dated = dated_item("Show.S01E01", NOW - 400 * 86_400);
        assert!(!rules_judge_at(&["Require: age>2y".to_string()], &dated, NOW).accept);
        assert!(rules_judge_at(&["Reject: age>2y".to_string()], &dated, NOW).accept);
    }

    /// The date has to come off the wire, not just out of a constructor:
    /// RSS `<pubDate>`, RSS 1.0 `<dc:date>` (prefixed, which is the trap
    /// this file's local-name scan exists for), and Atom `<published>`
    /// with `<updated>` as the fallback.
    #[test]
    fn parsing_a_feed_carries_the_posting_date() {
        let rss = r#"<rss><channel>
          <item><title>A</title><link>http://x/a</link>
            <pubDate>Thu, 02 Jul 2026 15:04:05 +0000</pubDate></item>
          <item><title>B</title><link>http://x/b</link>
            <dc:date>2026-07-02T15:04:05Z</dc:date></item>
          <item><title>C</title><link>http://x/c</link></item>
        </channel></rss>"#;
        let got = parse_feed(rss);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].pub_date, Some(1_783_004_645), "pubDate");
        assert_eq!(got[1].pub_date, Some(1_783_004_645), "prefixed dc:date");
        assert_eq!(got[2].pub_date, None, "no date element at all");

        let atom = r#"<feed>
          <entry><title>A</title><link href="http://x/a"/>
            <published>2026-07-02T15:04:05Z</published>
            <updated>2026-08-01T00:00:00Z</updated></entry>
          <entry><title>B</title><link href="http://x/b"/>
            <updated>2026-07-02T15:04:05Z</updated></entry>
        </feed>"#;
        let got = parse_feed(atom);
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0].pub_date,
            Some(1_783_004_645),
            "published wins over updated"
        );
        assert_eq!(
            got[1].pub_date,
            Some(1_783_004_645),
            "updated is the fallback"
        );
    }

    /// TODO §20c. The mask is the only version of a feed url the
    /// settings UI ever sees, so it has two jobs at once: nothing
    /// credential-shaped may survive it, and enough must survive it that
    /// three feeds on one indexer are still tellable apart.
    #[test]
    fn a_feed_url_keeps_its_shape_and_loses_its_credentials() {
        // The ordinary newznab feed: the key goes, the address and the
        // filters that identify the row stay.
        assert_eq!(
            mask_feed_url("https://idx.example/rss?t=tvsearch&cat=5030&apikey=b8f3c1d9e7a24601"),
            "https://idx.example/rss?t=tvsearch&cat=5030&apikey=***"
        );
        // Deny by default: a credential under a name nobody guessed is
        // masked because it is not on the harmless list, not because
        // "passkey" was foreseen.
        assert_eq!(
            mask_feed_url("https://idx.example/feed?passkey=zzz&r=abc&cat=tv"),
            "https://idx.example/feed?passkey=***&r=***&cat=tv"
        );
        // Userinfo, and a key posing as a path segment.
        assert_eq!(
            mask_feed_url("https://u:pw@idx.example/rss/a1b2c3d4e5f60718/tv"),
            "https://***@idx.example/rss/***/tv"
        );
        // A path segment that is a NAME, not a token: long enough, but
        // no digit in it, so it reads.
        assert_eq!(
            mask_feed_url("https://idx.example/alt-binaries-teevee/rss"),
            "https://idx.example/alt-binaries-teevee/rss"
        );
        // A url with nothing to hide comes back byte-identical, which is
        // what lets `url_is_unchanged` treat "the same url" and "the
        // mask of it" as one case.
        for plain in [
            "https://idx.example/rss",
            "https://idx.example/rss?t=search&q=Some.Show.S01E01.1080p",
            "",
        ] {
            assert_eq!(mask_feed_url(plain), plain, "nothing to mask in {plain}");
        }
        // Deterministic: the round-trip below depends on the same url
        // masking to the same bytes every time.
        let u = "https://idx.example/rss?apikey=k1&cat=5030#frag";
        assert_eq!(mask_feed_url(u), mask_feed_url(u));
        assert_eq!(
            mask_feed_url(u),
            "https://idx.example/rss?apikey=***&cat=5030#***"
        );
        // A scheme-less address is accepted by set_feeds, so it must
        // mask too rather than fall through whole.
        assert_eq!(
            mask_feed_url("idx.example/rss?apikey=secret"),
            "idx.example/rss?apikey=***"
        );
    }

    /// The mask can never be mistaken for a url the user typed, which is
    /// the whole basis of the merge in `set_feeds`.
    #[test]
    fn an_untouched_masked_url_reads_as_unchanged_and_a_new_one_does_not() {
        let stored = "https://idx.example/rss?t=tvsearch&cat=5030&apikey=b8f3c1d9e7a24601";
        assert!(url_is_unchanged(&mask_feed_url(stored), stored));
        // The other spelling of the same thing, the one every other
        // credential in the settings path already uses.
        assert!(url_is_unchanged("", stored));
        assert!(url_is_unchanged("   ", stored));
        // A url the user actually retyped - including the same address
        // with a NEW key, which must replace rather than be kept.
        assert!(!url_is_unchanged(
            "https://idx.example/rss?t=tvsearch&cat=5030&apikey=0000111122223333",
            stored
        ));
        assert!(!url_is_unchanged("https://other.example/rss", stored));
        // The half-edited mask: not the mask any more, so it reads as
        // new here. `set_feeds` refuses it on the `***` marker rather
        // than storing it - this is the case that guard exists for.
        assert!(!url_is_unchanged(
            "https://idx.example/rss?t=tvsearch&cat=5040&apikey=***",
            stored
        ));
    }

    /// The migration: a feeds list written before the id existed parses,
    /// gets ids, and is otherwise untouched.
    #[test]
    fn feeds_written_before_the_id_existed_get_one_and_lose_nothing() {
        let pre_id = r#"[{"url":"https://idx.example/rss?apikey=k1","interval_secs":600,
            "category":"tv","rules":["Accept: *1080p*"]},
            {"url":"https://idx.example/rss?apikey=k2"}]"#;
        let mut list: Vec<FeedConfig> = serde_json::from_str(pre_id).expect("pre-id feeds parse");
        assert!(list.iter().all(|f| f.id.is_empty()), "no ids on disk yet");
        assert!(assign_feed_ids(&mut list), "the migration has work to do");
        assert!(list.iter().all(|f| f.id.len() == 16), "{list:?}");
        assert_ne!(list[0].id, list[1].id, "ids must be distinct");
        // Lossless: everything else about the entries is what was on
        // disk, defaults included.
        assert_eq!(list[0].url, "https://idx.example/rss?apikey=k1");
        assert_eq!(list[0].interval_secs, 600);
        assert_eq!(list[0].category, "tv");
        assert_eq!(list[0].rules, vec!["Accept: *1080p*".to_string()]);
        assert_eq!(list[1].interval_secs, 900, "the default still applies");
        // Idempotent: a second load has nothing to do, which is what
        // stops the daemon rewriting settings.json at every start.
        let ids: Vec<String> = list.iter().map(|f| f.id.clone()).collect();
        assert!(!assign_feed_ids(&mut list), "second pass is a no-op");
        assert_eq!(ids, list.iter().map(|f| f.id.clone()).collect::<Vec<_>>());
        // A hand-edited config with two identical ids cannot be left
        // alone: the merge key would restore one feed's url onto the
        // other. The duplicate is re-minted.
        let first = list[0].id.clone();
        list[1].id = first;
        assert!(assign_feed_ids(&mut list), "a duplicate is work");
        assert_ne!(list[0].id, list[1].id);
        assert_eq!(list[0].id, ids[0], "the FIRST one keeps its id");
    }
}
