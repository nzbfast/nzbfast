//! M23 watchlist: automated grabbing straight off the index.
//!
//! The user names shows and films they want (including ones that haven't
//! been posted yet) with a quality window; the daemon's watcher loop then
//! matches every indexed release against the list, enqueues the best
//! candidate the moment one appears in a scanned group, and keeps
//! upgrading as better encodes arrive - until the target quality is
//! reached. Optionally the superseded download is deleted once the
//! upgrade COMPLETES (never before: the old copy is the fallback if the
//! new one dies).
//!
//! This module is the pure half - item model, quality ranking over
//! `wall::Parsed`, matching, and the grab/upgrade/skip decision - so it
//! is unit-testable without a daemon. The loop (`watchlist_pass`) lives
//! in serve/watchlist.rs.
//!
//! What a "slot" is - the unit the watcher tracks one grab against - is
//! the other half of the model: a film, an episode, a whole season when
//! the post is a pack, or a day when the show is a daily. See
//! [`slot_of`], and [`pack_eligible`] for when a pack is the better way
//! to get a season than going on collecting episodes.
//!
//! 24D: an item may also target a user category by slug. Nothing here
//! runs category rules - the loop classifies each candidate through
//! `categories::classify`, exactly as ingest does, and matching reads
//! the classified `kind` and `key` off the parse. One rule engine, and a
//! release belongs to exactly one kind.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::wall::{Kind, Parsed, norm_title};

// ---------------------------------------------------------------------------
// Item model (what the user edits; persisted as the `watchlist` setting)
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}
fn default_target() -> String {
    "1080p".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchItem {
    /// Stable id assigned by the UI (slot state is keyed on it, so edits
    /// to other fields don't orphan what's already been grabbed).
    pub id: u64,
    /// "tv", "movie", or a user category's slug ("formula-1"). A slug
    /// item matches releases that same category claimed at ingest -
    /// see [`kind_ok`].
    pub kind: String,
    pub title: String,
    /// Films (and custom items whose year is a season): pin the year to
    /// disambiguate remakes ("Dune") or seasons.
    #[serde(default)]
    pub year: Option<u32>,
    /// Anything episodic: which series/seasons to grab - "", "all", "3",
    /// "1-4", "2,4". Empty = every season.
    #[serde(default)]
    pub seasons: String,
    /// Anything episodic: which episodes within those seasons - "",
    /// "all", "1-13", "1,3,5-7". Empty = every episode.
    #[serde(default)]
    pub episodes: String,
    /// Floor: never grab below this ("any" / "480p" … "2160p" / "remux").
    #[serde(default)]
    pub min_quality: String,
    /// Ceiling: stop upgrading once a grab reaches this.
    #[serde(default = "default_target")]
    pub target_quality: String,
    /// Keep grabbing better versions until target_quality is reached.
    #[serde(default = "default_true")]
    pub upgrade: bool,
    /// After an upgrade COMPLETES, delete the superseded download.
    #[serde(default)]
    pub delete_old: bool,
    #[serde(default)]
    pub category: String,
    /// M32: only grab posts at least this old - "2h",
    /// "1d" etc. Skips fresh posts still propagating (empty = no floor).
    #[serde(default)]
    pub min_age: String,
    /// M32: only grab posts at most this old - "400d", "1y" etc. Skips
    /// stale reposts (empty = no ceiling).
    #[serde(default)]
    pub max_age: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Watcher state (what's been grabbed; persisted to watchlist-state.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    /// quality_rank of the best version grabbed so far.
    pub rank: u32,
    pub stem: String,
    /// "1080p WEB" - stamped at grab time for the status UI.
    pub quality: String,
    pub nzo_id: String,
    pub grabbed_at: i64,
    /// Stems of upgrade attempts that FAILED for this slot - never
    /// retried, or a dead post would be re-grabbed every pass forever.
    #[serde(default)]
    pub failed: Vec<String>,
}

/// An upgrade was enqueued over `old_nzo`; once `new_nzo` COMPLETES the
/// old download is deleted (delete_old items only). If the new one FAILS
/// the slot reverts to `prev_*` so a later candidate can retry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDelete {
    /// "itemid:slot" key this pending upgrade belongs to.
    pub slot: String,
    pub new_nzo: String,
    #[serde(default)]
    pub new_stem: String,
    pub old_nzo: String,
    pub prev_rank: u32,
    pub prev_stem: String,
    pub prev_quality: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchState {
    /// "itemid:movie" / "itemid:s01e05" → best grab so far.
    #[serde(default)]
    pub slots: HashMap<String, Slot>,
    #[serde(default)]
    pub pending: Vec<PendingDelete>,
    /// M35 phase 2: item id → when this item last spent an external
    /// indexer search (unix). The watcher runs every 60 s and a
    /// third-party account is metered per day, so an item may only ask
    /// the indexers on its own slow cadence; this is what enforces it
    /// across restarts.
    #[serde(default)]
    pub ext_checked: HashMap<u64, i64>,
    /// §74: item id (as text, so the state file stays a plain JSON
    /// object) → the last grab this item got off the instant path.
    #[serde(default)]
    pub instant: HashMap<String, InstantGrab>,
    /// Item id → why the last pass DECLINED a candidate for this item
    /// ("giveup", "age", or one of "indexer_budget" / "indexer_backoff" /
    /// "indexer_error" with ":name, name" naming the accounts). Every one
    /// of those was a bare `continue` before, so an item that was being
    /// deliberately passed over read exactly like one nothing had ever
    /// been posted for.
    ///
    /// Deliberately not persisted: it describes the pass that just ran,
    /// and a reason restored from disk minutes or days later would be a
    /// claim about work nobody did. Rebuilt from scratch every pass.
    #[serde(skip)]
    pub skips: HashMap<String, String>,
}

/// Which skip reason a row should show when one pass declined the same
/// item for more than one reason. The breaker leads (it is the only one
/// the user can act on), then a spent indexer allowance, then the age
/// window - and a fixed order at all, rather than "whichever came last",
/// so the sub-line does not flicker between two true sentences.
pub fn skip_rank(reason: &str) -> u8 {
    match reason.split(':').next().unwrap_or_default() {
        "giveup" => 3,
        "indexer_budget" | "indexer_backoff" | "indexer_error" => 2,
        "age" => 1,
        _ => 0,
    }
}

/// Record one declined candidate against an item, keeping the
/// highest-ranked reason of the pass. Reporting only - nothing reads
/// this back to decide anything.
pub fn note_skip(skips: &mut HashMap<String, String>, item_id: u64, reason: &str) {
    let e = skips.entry(item_id.to_string()).or_default();
    if skip_rank(reason) > skip_rank(e) {
        *e = reason.to_string();
    }
}

/// One grab that happened because a release ARRIVED, not because the
/// periodic pass came round: what was grabbed, when, and how long after
/// the post went up. Purely a record - nothing decides anything from it -
/// but it is the only place a user can see the feature working.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantGrab {
    pub stem: String,
    /// When it was grabbed (unix).
    pub at: i64,
    /// Grab time minus the release's own first posted time, in seconds.
    /// 0 when the post carried no usable date.
    #[serde(default)]
    pub lag: i64,
}

// ---------------------------------------------------------------------------
// §74: the instant matcher
// ---------------------------------------------------------------------------

/// The cheap "could any watched item possibly want this name?" test,
/// compiled once from the watchlist and run over every release as it
/// arrives.
///
/// It exists to keep the hot path cheap, NOT to decide anything: a yes
/// only means the watchlist pass is worth waking, and that pass then
/// applies the whole ladder (quality, scope, age, packs, duplicates)
/// against the database as it always has. So the contract is one-sided -
/// it must never say no to something [`matches`] would accept, and it is
/// free to say yes to things that go on to be rejected.
///
/// That is why it tests token containment rather than title equality:
/// `matches` compares the normalised title the PARSER extracted, and
/// parsing every arriving name to find out would be the cost this type
/// exists to avoid. Every title the parser can extract is a run of words
/// from the name itself, so containment is a superset of the real test.
#[derive(Debug, Clone, Default)]
#[cfg(feature = "indexer")]
pub struct InstantMatcher {
    /// (item id, normalised title) for every enabled item. `None` is a
    /// TITLELESS custom item, which matches on its category alone and so
    /// accepts every name - the same reading [`title_ok`] gives it.
    titles: Vec<(u64, Option<String>)>,
}

#[cfg(feature = "indexer")]
impl InstantMatcher {
    /// Compile the enabled items. Disabled ones are left out entirely -
    /// waking the pass for something it will not grab is pure cost. So
    /// is a titleless built-in item, which `title_ok` matches nothing
    /// against.
    pub fn compile(items: &[WatchItem]) -> Self {
        InstantMatcher {
            titles: items
                .iter()
                .filter(|i| i.enabled)
                .filter_map(|i| {
                    let t = norm_title(&i.title);
                    match (t.is_empty(), is_custom_kind(&i.kind)) {
                        (true, true) => Some((i.id, None)),
                        (true, false) => None,
                        (false, _) => Some((i.id, Some(t))),
                    }
                })
                .collect(),
        }
    }

    /// Nothing to match against - the caller can skip installing it and
    /// pay nothing at all.
    pub fn is_empty(&self) -> bool {
        self.titles.is_empty()
    }

    /// The ids of every item this name could belong to (empty = none).
    pub fn hits(&self, name: &str) -> Vec<u64> {
        let hay = format!(" {} ", norm_title(name));
        self.titles
            .iter()
            .filter(|(_, want)| {
                want.as_ref()
                    .is_none_or(|w| hay.contains(&format!(" {w} ")))
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Could any watched item want this name?
    pub fn wants(&self, name: &str) -> bool {
        !self.hits(name).is_empty()
    }
}

/// §74: may the arrival path wake the pass again, given the passes it has
/// already asked for this hour? Records the kick when it may.
///
/// `max` 0 means no limit. Refusing is deliberately cheap in consequence:
/// the periodic pass runs a minute later over the same index with the
/// same rules, so a spent allowance costs the seconds, never the grab.
/// That is why the window is trimmed rather than reset - a burst does not
/// lock the path out for a full hour after it ends.
#[cfg(feature = "indexer")]
pub fn kick_allowed(recent: &mut std::collections::VecDeque<i64>, max: u32, now: i64) -> bool {
    if max == 0 {
        return true;
    }
    while recent.front().is_some_and(|t| now - *t >= 3_600) {
        recent.pop_front();
    }
    if recent.len() as u32 >= max {
        return false;
    }
    recent.push_back(now);
    true
}

// ---------------------------------------------------------------------------
// Quality ranking
// ---------------------------------------------------------------------------

fn res_points(res: Option<&str>) -> u32 {
    match res {
        Some("2160p") => 5,
        Some("1080p") => 4,
        Some("720p") => 3,
        Some("576p") => 2,
        Some("480p") => 1,
        _ => 0,
    }
}

/// Points for the things that separate two encodes at the SAME
/// resolution and source: dynamic range, audio, then video codec.
///
/// The whole budget is deliberately small. `quality_rank` promises that
/// resolution dominates and that `threshold_rank` boundaries hold, so
/// these must never lift a release into another resolution's band, nor
/// push a non-remux 2160p up to the "remux" floor of 5500. Ceiling here
/// is 60+60+40 = 160, against 199 of headroom (remux 500 + BluRay 300
/// leaves 5300 for the best non-remux 2160p).
fn extras_points(p: &Parsed) -> u32 {
    let hdr = match p.hdr.as_deref() {
        Some("DV") => 60,
        Some("HDR10+") => 45,
        Some("HDR10") => 40,
        Some("HDR") => 30,
        Some("HLG") => 15,
        _ => 0,
    };
    let audio = match p.acodec.as_deref() {
        Some("Atmos") => 60,
        Some("TrueHD") => 50,
        Some("DTS-X") => 45,
        Some("DTS-HD") => 40,
        Some("DTS") => 30,
        Some("DDP") => 20,
        Some("AC3") | Some("FLAC") => 15,
        Some("AAC") => 10,
        Some("Opus") => 8,
        Some("MP3") => 3,
        _ => 0,
    };
    // Efficiency at a given resolution, not raw preference: a modern
    // codec at the same res is the better encode of the two.
    let video = match p.vcodec.as_deref() {
        Some("AV1") | Some("x265") => 40,
        Some("x264") => 20,
        Some("VC-1") => 5,
        _ => 0,
    };
    hdr + audio + video
}

/// Total order over releases of one title: resolution dominates, then
/// remux, then source, then the encode's own qualities. A rank is only
/// meaningful relative to other ranks and to `threshold_rank` values.
pub fn quality_rank(p: &Parsed) -> u32 {
    let src = match p.source.as_deref() {
        Some("BluRay") => 300,
        Some("WEB") => 200,
        Some("HDTV") => 100,
        Some("DVD") => 50,
        _ => 0,
    };
    res_points(p.res.as_deref()) * 1000 + if p.remux { 500 } else { 0 } + src + extras_points(p)
}

/// What the user would rather have when one title has several encodes.
/// Every field is opt-in: an empty string means "no opinion", which
/// scores nothing either way rather than penalising anything. Values are
/// the parser's own friendly forms ("2160p", "x265", "Atmos", "DV").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QualityPrefs {
    pub res: String,
    pub vcodec: String,
    pub acodec: String,
    pub hdr: String,
}

/// Accepted values per field, in the parser's friendly spelling. A typo
/// that silently matched nothing would look exactly like a preference
/// that never gets satisfied, so unknown values are rejected at the
/// settings boundary rather than stored.
const PREF_RES: &[&str] = &["2160p", "1080p", "720p", "576p", "480p"];
const PREF_VCODEC: &[&str] = &["AV1", "x265", "x264", "VC-1", "XviD", "DivX"];
const PREF_ACODEC: &[&str] = &[
    "Atmos", "TrueHD", "DTS-X", "DTS-HD", "DTS", "DDP", "AC3", "FLAC", "AAC", "Opus", "MP3",
];
const PREF_HDR: &[&str] = &["DV", "HDR10+", "HDR10", "HDR", "HLG"];

impl QualityPrefs {
    /// Are no preferences set at all? Only the tests ask - the ranking
    /// path reads each field directly.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.res.is_empty()
            && self.vcodec.is_empty()
            && self.acodec.is_empty()
            && self.hdr.is_empty()
    }

    /// Parse the setting as it arrives from the API: a JSON string like
    /// `{"res":"2160p","acodec":"Atmos"}`. Absent or empty fields mean
    /// "no opinion"; an unrecognised value is an error, and the caller
    /// keeps whatever was set before.
    pub fn from_json(s: &str) -> Result<QualityPrefs, String> {
        if s.trim().is_empty() {
            return Ok(QualityPrefs::default());
        }
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|e| format!("not valid JSON: {e}"))?;
        QualityPrefs::from_value(&v)
    }

    /// Parse the setting as it comes back OUT of settings.json, where it
    /// is a real object rather than a string - `apply_setting` stores the
    /// parsed form. Reading it back with `as_str` silently yielded None
    /// and dropped the preference on every restart.
    pub fn from_value(v: &serde_json::Value) -> Result<QualityPrefs, String> {
        if let Some(s) = v.as_str() {
            return QualityPrefs::from_json(s);
        }
        let field = |name: &str, allowed: &[&str]| -> Result<String, String> {
            let raw = v.get(name).and_then(|x| x.as_str()).unwrap_or("").trim();
            if raw.is_empty() {
                return Ok(String::new());
            }
            allowed
                .iter()
                .find(|a| a.eq_ignore_ascii_case(raw))
                .map(|a| (*a).to_string())
                .ok_or_else(|| {
                    format!("{name}: unknown value {raw:?} (expected one of {allowed:?}, or empty)")
                })
        };
        Ok(QualityPrefs {
            res: field("res", PREF_RES)?,
            vcodec: field("vcodec", PREF_VCODEC)?,
            acodec: field("acodec", PREF_ACODEC)?,
            hdr: field("hdr", PREF_HDR)?,
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "res": self.res, "vcodec": self.vcodec,
            "acodec": self.acodec, "hdr": self.hdr,
        })
    }
}

/// How much each satisfied preference is worth. Resolution outweighs the
/// rest together, so "I want 4K" is not overturned by a 1080p release
/// that happens to tick the other three.
#[cfg(feature = "indexer")]
fn pref_weight(field: PrefField) -> i64 {
    match field {
        // Strictly greater than HDR + audio + video (4 + 4 + 2).
        PrefField::Res => 11,
        PrefField::Hdr => 4,
        PrefField::Acodec => 4,
        PrefField::Vcodec => 2,
    }
}

#[cfg(feature = "indexer")]
enum PrefField {
    Res,
    Vcodec,
    Acodec,
    Hdr,
}

/// Rank a release against what the user asked for. Releases that satisfy
/// more of the preference always sort above ones that satisfy less, and
/// `quality_rank` breaks ties inside each group - so the order reads
/// "what you asked for, best first, then everything else, best first".
///
/// This never HIDES anything: scene names omit tags all the time (plenty
/// of Atmos releases never say "Atmos"), so a preference biases the order
/// and nothing more. With no preference set it degrades to quality_rank.
#[cfg(feature = "indexer")]
pub fn preference_score(p: &Parsed, prefs: &QualityPrefs) -> i64 {
    // 10_000 clears the whole quality_rank range (max 5_960), so a
    // preference match can never be outvoted by raw quality.
    pref_matches(p, prefs).0 * 10_000 + quality_rank(p) as i64
}

/// Which of the user's preferences this release actually satisfies, as
/// field names ("res" / "vcodec" / "acodec" / "hdr"). The UI marks these
/// so it is obvious WHY a release is at the top, rather than presenting
/// an unexplained order.
#[cfg(feature = "indexer")]
pub fn preference_hits(p: &Parsed, prefs: &QualityPrefs) -> Vec<&'static str> {
    pref_matches(p, prefs).1
}

#[cfg(feature = "indexer")]
fn pref_matches(p: &Parsed, prefs: &QualityPrefs) -> (i64, Vec<&'static str>) {
    let mut weight = 0;
    let mut hits = Vec::new();
    let mut check = |want: &str, got: Option<&str>, field: PrefField, name: &'static str| {
        if !want.is_empty() && got.is_some_and(|g| g.eq_ignore_ascii_case(want)) {
            weight += pref_weight(field);
            hits.push(name);
        }
    };
    check(&prefs.res, p.res.as_deref(), PrefField::Res, "res");
    check(
        &prefs.vcodec,
        p.vcodec.as_deref(),
        PrefField::Vcodec,
        "vcodec",
    );
    check(
        &prefs.acodec,
        p.acodec.as_deref(),
        PrefField::Acodec,
        "acodec",
    );
    check(&prefs.hdr, p.hdr.as_deref(), PrefField::Hdr, "hdr");
    (weight, hits)
}

/// User threshold string → rank floor. "remux" means a 2160p remux
/// (5500 sits above every plain 2160p encode, below any 2160p remux).
pub fn threshold_rank(q: &str) -> u32 {
    match q.trim().to_ascii_lowercase().as_str() {
        "" | "any" => 0,
        "remux" => 5500,
        other => res_points(Some(other)) * 1000,
    }
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// Age spec → seconds: "90m", "2h", "10d", "3w", "6mo", "1y"; a bare
/// number is DAYS (the unit people mean for retention). Empty or
/// unparseable = None (no constraint) - permissive with typed input,
/// like in_range_spec.
pub fn parse_age_spec(spec: &str) -> Option<u64> {
    let s = spec.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let n: u64 = s[..split].parse().ok()?;
    let mult = match s[split..].trim() {
        "m" | "min" => 60,
        "h" => 3600,
        "" | "d" => 86_400,
        "w" => 7 * 86_400,
        "mo" => 30 * 86_400,
        "y" => 365 * 86_400,
        _ => return None,
    };
    // Saturate rather than multiply. The number is user-typed and
    // unbounded, and the release profile builds with overflow checks
    // off - so "9000000000000y", meaning "no practical limit", wrapped
    // to a small window and the item silently stopped grabbing
    // anything. A debug build panicked the pass instead. Saturating
    // gives the value the user was reaching for: a ceiling nothing hits.
    Some(n.saturating_mul(mult))
}

/// M32 age gate: is a post's age (seconds since upload) inside the
/// item's min/max window? Posts with an unknown upload date (0) are
/// never age-rejected - the gate exists to shape choice, not to hide
/// index gaps.
pub fn age_ok(item: &WatchItem, posted_unix: i64, now_unix: i64) -> bool {
    if posted_unix <= 0 {
        return true;
    }
    let age = (now_unix - posted_unix).max(0) as u64;
    if let Some(min) = parse_age_spec(&item.min_age)
        && age < min
    {
        return false;
    }
    if let Some(max) = parse_age_spec(&item.max_age)
        && age > max
    {
        return false;
    }
    true
}

/// Does `n` fall inside a user range spec ("3", "1-4", "1,3,5-7")?
/// Empty / "all" / "*" match everything, and a spec with nothing
/// parseable in it is treated as no constraint rather than "match
/// nothing" - permissive with hand-typed input.
pub fn in_range_spec(spec: &str, n: u32) -> bool {
    let s = spec.trim().to_ascii_lowercase();
    if s.is_empty() || s == "all" || s == "*" {
        return true;
    }
    let mut any_valid = false;
    for chunk in s.split(',') {
        let c = chunk.trim();
        if let Some((a, b)) = c.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                any_valid = true;
                if (a.min(b)..=a.max(b)).contains(&n) {
                    return true;
                }
            }
        } else if let Ok(v) = c.parse::<u32>() {
            any_valid = true;
            if v == n {
                return true;
            }
        }
    }
    !any_valid
}

/// Is this item's kind a user category rather than a built-in?
pub fn is_custom_kind(kind: &str) -> bool {
    !kind.trim().is_empty() && !matches!(kind, "tv" | "movie")
}

/// The item's kind against the release's CLASSIFIED kind. A custom item
/// names its category's slug, and classification is authoritative: once
/// a category claims a stem it no longer answers to "movie", the same
/// rule the kinds gate follows (`gates::allows_with`). So a release
/// belongs to one item's kind, never two.
pub fn kind_ok(item: &WatchItem, p: &Parsed) -> bool {
    match (item.kind.as_str(), &p.kind) {
        ("tv", _) => p.kind == Kind::Tv,
        ("movie", _) => p.kind == Kind::Movie,
        (slug, Kind::Custom(claimed)) => slug == claimed,
        _ => false,
    }
}

/// Does the item's title claim this release?
///
/// A film or a show has a title the parser can isolate, so those compare
/// exactly - "Severance" must not match "Severance Pay".
///
/// Nothing else does. Measured against a corpus of real posts, the
/// parsed "title" of a music, sport, combat, audiobook, comic or anime
/// release swallows most of the stem: "metallica 72 seasons cd flac
/// 2023", "ufc 310 jones vs miocic ppv", "one piece 1085". Exact
/// matching meant a user typing "Metallica" or "UFC" matched NOTHING -
/// the feature looked wired up and grabbed nothing forever. So a custom
/// item matches on containment against the raw stem, the same text the
/// category's own rule matched, with two guards keeping it honest: the
/// category has already narrowed the field to releases the user
/// described, and the comparison is word-boundary aligned, so "Rush"
/// never matches "Rushmore".
///
/// An EMPTY title on a custom item means the whole category - the rule
/// is the filter, and "grab every F1 session" needs no title at all. An
/// empty title on a film or show still matches nothing, as before.
fn title_ok(item: &WatchItem, stem: &str, p: &Parsed) -> bool {
    let want = norm_title(&item.title);
    if !is_custom_kind(&item.kind) {
        return !want.is_empty() && want == norm_title(&p.title);
    }
    if want.is_empty() {
        return true;
    }
    let hay = format!(" {} ", norm_title(stem));
    hay.contains(&format!(" {want} "))
}

/// Does a parsed release satisfy this watch item? Titles compare per
/// [`title_ok`]; an item with a pinned year rejects releases naming a
/// DIFFERENT year (year-less stems still match - many posts omit it).
/// Audio-language tags other than English / multi are rejected for the
/// built-in kinds; untagged means English by scene convention.
pub fn matches(item: &WatchItem, stem: &str, p: &Parsed) -> bool {
    if !kind_ok(item, p) || !title_ok(item, stem, p) {
        return false;
    }
    // A film's year is its release date; a custom event post's year is
    // its season ("Formula1.2026.Round11"). Both are worth pinning, and
    // an episodic post carries no year to compare against anyway.
    if item.kind != "tv"
        && let (Some(want), Some(got)) = (item.year, p.year)
        && want != got
    {
        return false;
    }
    // Episodic scope: "series 3, episodes 1-13" etc. Applied against the
    // parsed marker; posts without one never reach a slot anyway. Custom
    // categories can be episodic too (wrestling, a sports season), so
    // the scope is only skipped for films.
    if item.kind != "movie" {
        if let Some(s) = p.season
            && !in_range_spec(&item.seasons, s)
        {
            return false;
        }
        if let Some(e) = p.episode
            && !in_range_spec(&item.episodes, e)
        {
            return false;
        }
    }
    // The language gate is a heuristic for English-speaking users
    // browsing the general index. A user category is an explicit "I want
    // this" rule the user wrote themselves - a Bundesliga or Tour de
    // France category would otherwise match nothing, since those posts
    // are tagged German or French. Same reading as the default gate,
    // which lets every custom release through.
    if is_custom_kind(&item.kind) {
        return true;
    }
    if !p.langs.is_empty() && !p.langs.iter().any(|l| l == "english" || l == "multi") {
        return false;
    }
    true
}

/// Slot key for one episode ("s01e05"; "s2026e15" for the year-as-season
/// posts an annual sport or soap uses).
pub fn episode_slot(season: u32, episode: u32) -> String {
    format!("s{season:02}e{episode:02}")
}

/// Slot key for a whole-season pack ("s01"). Deliberately an episode key
/// with the episode left off, which is also how the posts themselves are
/// named, so [`slot_parts`] reads both with one parser and the dashboard
/// prints "S01" beside "S01E05" without being taught anything.
pub fn pack_slot(season: u32) -> String {
    format!("s{season:02}")
}

/// Slot key for a daily-dated post ("d:20260721"). Prefixed, because a
/// bare "20260721" would parse as neither an episode nor a season and a
/// future reader would have to guess which of the three a key is.
pub fn date_slot(date: &str) -> String {
    format!("d:{date}")
}

/// The season and episode a slot key names: "s01e05" → (1, Some(5)),
/// "s01" → (1, None), i.e. a PACK. None for every other shape ("movie",
/// "d:…" dailies, "c:…" custom identity keys) - those are not part of a
/// season and no pack covers them.
pub fn slot_parts(slot: &str) -> Option<(u32, Option<u32>)> {
    let rest = slot.strip_prefix('s')?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let season: u32 = digits.parse().ok()?;
    match &rest[digits.len()..] {
        "" => Some((season, None)),
        tail => {
            let ep = tail.strip_prefix('e')?;
            (!ep.is_empty() && ep.bytes().all(|c| c.is_ascii_digit()))
                .then(|| ep.parse().ok().map(|e| (season, Some(e))))
                .flatten()
        }
    }
}

/// Does this slot key name a whole season rather than one episode?
pub fn is_pack_slot(slot: &str) -> bool {
    matches!(slot_parts(slot), Some((_, None)))
}

/// Which slot of the item a release fills: movies have one ("movie"), TV
/// tracks per-episode ("s01e05"), a bare-season post fills that season's
/// PACK slot ("s01"), and a daily-dated show keys on the day it aired
/// ("d:20260721").
///
/// A custom category is any of those shapes, so it takes them all: an
/// episode marker tracks per episode, a bare season is that season's
/// pack, and everything else tracks on the classified identity key
/// (`c:<slug>:formula1:2026:round11 hungary qualifying`). That key is the
/// F1 lesson made load-bearing - a "movie"-style single slot would grab
/// one session and call the whole season done. It already folds in the
/// parsed date, which is why the daily arm below is only needed for the
/// built-in TV kind.
pub fn slot_of(item: &WatchItem, p: &Parsed) -> Option<String> {
    let episodic = || match (p.season, p.episode) {
        (Some(s), Some(e)) => Some(episode_slot(s, e)),
        (Some(s), None) => Some(pack_slot(s)),
        (None, _) => None,
    };
    match item.kind.as_str() {
        "movie" => Some("movie".into()),
        // A daily show carries no SxxEyy at all: the date IS the episode
        // ("The.Daily.Show.2026.07.21"). Without this arm every daily
        // post answered None and a watched daily show grabbed nothing,
        // ever - it looked like a show nobody had posted.
        "tv" => episodic().or_else(|| p.date.as_deref().map(date_slot)),
        _ => match p.season {
            Some(_) => episodic(),
            None => Some(p.key.clone()),
        },
    }
}

/// Full state key for a slot of an item.
pub fn state_key(item_id: u64, slot: &str) -> String {
    format!("{item_id}:{slot}")
}

/// The version an episode slot effectively has: its own grab, or the
/// season pack that covers it, whichever is the better copy. Emptied
/// slots (a failed or deleted grab) count as having nothing.
///
/// A pack is not written into the episode slots it covers, because
/// nothing here knows how many episodes a season HAS - a pack that
/// claimed "s01e01…s01e10" would be inventing that number. So coverage
/// is answered by looking up, at the moment it matters, rather than
/// stored: a season with a pack reads as "have it" for every episode,
/// however many turn out to exist.
pub fn covering<'a>(
    slots: &'a HashMap<String, Slot>,
    item_id: u64,
    slot: &str,
) -> Option<&'a Slot> {
    let filled = |k: String| slots.get(&k).filter(|s| !s.nzo_id.is_empty());
    let own = filled(state_key(item_id, slot));
    let pack = match slot_parts(slot) {
        Some((season, Some(_))) => filled(state_key(item_id, &pack_slot(season))),
        _ => None,
    };
    match (own, pack) {
        (Some(o), Some(p)) => Some(if p.rank > o.rank { p } else { o }),
        (o, p) => o.or(p),
    }
}

/// Extra episode slots a multi-episode release covers beyond its primary
/// one - "s01e02" for S01E01E02. Empty for single episodes, movies and
/// packs. Recording these stops the watchlist re-grabbing a standalone
/// E02 it already owns inside a double-episode post. Range capped so a
/// mis-parse can't flood the state with phantom slots.
pub fn extra_slots(item: &WatchItem, p: &Parsed) -> Vec<String> {
    // Episodic customs (wrestling, a sports season) post doubles too.
    if item.kind == "movie" {
        return Vec::new();
    }
    match (p.season, p.episode, p.episode2) {
        (Some(s), Some(e1), Some(e2)) if e2 > e1 && e2 - e1 <= 10 => {
            (e1 + 1..=e2).map(|e| episode_slot(s, e)).collect()
        }
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Season packs
// ---------------------------------------------------------------------------

/// How many episodes a pack has to bring before it beats going on
/// collecting singles. One is never worth it (that is just a single
/// episode wrapped in a season's worth of bytes); two is.
pub const PACK_MIN_EPISODES: u32 = 2;

/// What the watcher knows about one season of one item at the moment a
/// pack candidate turns up. Counts are of IN-SCOPE episodes only - an
/// item watching episodes 1-13 does not care that the season ran to 22.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeasonState {
    /// Episodes of this season the watcher can see exist at all: a slot,
    /// a candidate this pass, or an episode list from a metadata
    /// provider. Zero means the season is simply unknown - which is not
    /// the same as empty.
    pub known: u32,
    /// ...of which this many already have a grab of their own.
    pub have: u32,
    /// Best `quality_rank` among those grabs (0 when there are none).
    pub best_rank: u32,
    /// `quality_rank` of the pack already tracked for this season, or 0.
    pub pack_rank: u32,
}

/// Gather [`SeasonState`] from what the watcher has: this item's slots,
/// the slot names it found candidates for this pass, and the episode
/// numbers a provider says the season has (empty when nobody knows).
pub fn season_state(
    item: &WatchItem,
    season: u32,
    slots: &HashMap<String, Slot>,
    candidates: &[String],
    listed: &[u32],
) -> SeasonState {
    let prefix = format!("{}:", item.id);
    let mut known: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let mut have: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let mut st = SeasonState::default();
    for e in listed {
        if in_range_spec(&item.episodes, *e) {
            known.insert(*e);
        }
    }
    // Every episode counted here is filtered through the item's CURRENT
    // range, persisted slots included. Editing a watch item replaces its
    // requested range but keeps the slots it already filled, so an item
    // narrowed from E01-E10 to E11-E20 still had ten held episodes on
    // file: the season read as have=10 when the requested scope held
    // none of them, and `pack_eligible` then turned a season pack away
    // as redundant.
    let wanted = |e: u32| in_range_spec(&item.episodes, e);
    for slot in candidates {
        if let Some((s, Some(e))) = slot_parts(slot)
            && s == season
            && wanted(e)
        {
            known.insert(e);
        }
    }
    for (key, slot) in slots {
        let Some(name) = key.strip_prefix(&prefix) else {
            continue;
        };
        match slot_parts(name) {
            Some((s, Some(e))) if s == season && wanted(e) => {
                known.insert(e);
                if !slot.nzo_id.is_empty() {
                    have.insert(e);
                    st.best_rank = st.best_rank.max(slot.rank);
                }
            }
            Some((s, None)) if s == season && !slot.nzo_id.is_empty() => {
                st.pack_rank = st.pack_rank.max(slot.rank);
            }
            _ => {}
        }
    }
    SeasonState {
        known: known.len() as u32,
        have: have.len() as u32,
        ..st
    }
}

/// How many values a range spec names, when it names a bounded set:
/// "1-13" → 13, "1,3,5-7" → 5. None when the spec constrains nothing
/// (empty / "all" / junk), matching [`in_range_spec`]'s permissive
/// reading. Overlapping chunks are counted twice - it is used as an
/// upper bound on "how much did you ask for", where over-counting only
/// ever errs towards allowing a pack.
pub fn spec_count(spec: &str) -> Option<u32> {
    let s = spec.trim().to_ascii_lowercase();
    if s.is_empty() || s == "all" || s == "*" {
        return None;
    }
    let mut n: u32 = 0;
    let mut any_valid = false;
    for chunk in s.split(',') {
        let c = chunk.trim();
        if let Some((a, b)) = c.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                any_valid = true;
                // The inner `+ 1` needs the saturation too: it is
                // evaluated in u32 BEFORE saturating_add ever sees it, so
                // `episodes = "0-4294967295"` wrapped the span to 0. That
                // made spec_count Some(0) < PACK_MIN_EPISODES, so
                // pack_eligible refused every season pack forever - while
                // `in_range_spec` read the identical string as "every
                // episode is in scope". Same saturating convention
                // parse_age_spec adopted after its own field incident.
                n = n.saturating_add((a.max(b) - a.min(b)).saturating_add(1));
            }
        } else if c.parse::<u32>().is_ok() {
            any_valid = true;
            n = n.saturating_add(1);
        }
    }
    any_valid.then_some(n)
}

/// Is a season pack the right way to get this season, or should the
/// watcher go on collecting single episodes?
///
/// A pack is one post covering a whole season, so it is the efficient
/// choice at the start and a wasteful one near the end - it re-downloads
/// everything already on the shelf. The rules, in order:
///
/// 1. Scope decides first: a pack for a season the item does not watch
///    is not this item's, and neither is one for an item that asked for
///    a handful of specific episodes (`episodes = "5"` means episode 5,
///    not the 22 around it).
/// 2. A season already tracking a pack keeps using packs - whether the
///    new one is actually better is [`decide`]'s question, not this one.
/// 3. With nothing of the season in hand, take the pack: it is the whole
///    season in one grab, and there is nothing for it to duplicate.
/// 4. Otherwise a pack must be at least as good as the best single
///    already grabbed. A worse pack never displaces better episodes.
/// 5. ...and it must bring at least [`PACK_MIN_EPISODES`] missing
///    episodes, and at least as many as it repeats. Two missing out of
///    three is a pack; two missing out of twenty is nine downloads of
///    nothing.
///
/// Note what this deliberately does NOT do: grabbing a pack never
/// deletes the singles it covers, and a single that later upgrades one
/// episode never deletes the pack (the pack is still the only copy of
/// every other episode). `upgrade_supersedes_all` in the daemon enforces
/// that from the reach of each release, so nothing here has to.
pub fn pack_eligible(item: &WatchItem, season: u32, pack_rank: u32, st: SeasonState) -> bool {
    if item.kind == "movie" {
        return false;
    }
    if !in_range_spec(&item.seasons, season) {
        return false;
    }
    if spec_count(&item.episodes).is_some_and(|n| n < PACK_MIN_EPISODES) {
        return false;
    }
    if st.pack_rank > 0 {
        return true;
    }
    if st.have == 0 {
        return true;
    }
    if pack_rank < st.best_rank {
        return false;
    }
    let missing = st.known.saturating_sub(st.have);
    missing >= PACK_MIN_EPISODES && missing >= st.have
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// First acceptable version of this slot - grab it.
    Grab,
    /// Strictly better than what we have, and we're below target - grab
    /// it as a replacement (bypasses duplicate-hold).
    Upgrade,
    Skip,
}

pub fn decide(
    current_rank: Option<u32>,
    candidate_rank: u32,
    min_rank: u32,
    target_rank: u32,
    upgrade: bool,
) -> Decision {
    if candidate_rank < min_rank {
        return Decision::Skip;
    }
    match current_rank {
        None => Decision::Grab,
        Some(cur) if upgrade && cur < target_rank && candidate_rank > cur => Decision::Upgrade,
        Some(_) => Decision::Skip,
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wall::parse_release;
    use nzbkit::categories::{BaseBehavior, CustomCategory, classify};

    #[test]
    fn the_skip_reason_a_row_shows_is_the_most_actionable_one() {
        let mut s = HashMap::new();
        note_skip(&mut s, 7, "age");
        assert_eq!(s["7"], "age");
        // A spent indexer allowance outranks the age window...
        note_skip(&mut s, 7, "indexer_budget:NZBGeek, DOGnzb");
        assert_eq!(s["7"], "indexer_budget:NZBGeek, DOGnzb");
        // ...and a given-up target outranks everything.
        note_skip(&mut s, 7, "giveup");
        note_skip(&mut s, 7, "age");
        assert_eq!(s["7"], "giveup");
        // Items don't bleed into each other.
        note_skip(&mut s, 8, "age");
        assert_eq!(s["8"], "age");
        assert_eq!(s["7"], "giveup");
        // An unknown token never displaces a real one.
        note_skip(&mut s, 8, "who knows");
        assert_eq!(s["8"], "age");
    }

    /// The two categories the custom tests classify through - the same
    /// shape a user types into settings.
    fn f1_cats() -> Vec<CustomCategory> {
        vec![
            CustomCategory {
                slug: "formula-1".into(),
                name: "Formula 1".into(),
                pattern: r"^formula\.?1\.".into(),
                not_match: String::new(),
                base: BaseBehavior::Movie,
            },
            CustomCategory {
                slug: "motogp".into(),
                name: "MotoGP".into(),
                pattern: "^motogp".into(),
                not_match: String::new(),
                base: BaseBehavior::Movie,
            },
        ]
    }

    fn item(kind: &str, title: &str) -> WatchItem {
        WatchItem {
            id: 1,
            kind: kind.into(),
            title: title.into(),
            year: None,
            seasons: String::new(),
            episodes: String::new(),
            min_quality: "any".into(),
            target_quality: "1080p".into(),
            upgrade: true,
            delete_old: false,
            category: String::new(),
            min_age: String::new(),
            max_age: String::new(),
            enabled: true,
        }
    }

    #[test]
    fn multi_episode_covers_extra_slots() {
        let tv = item("tv", "Show Name");
        // §7b: a double episode owns both slots so a standalone E02 alt
        // is never re-grabbed.
        let p = parse_release("Show.Name.S01E01E02.1080p.WEB.h264-GRP");
        assert_eq!(slot_of(&tv, &p).as_deref(), Some("s01e01"));
        assert_eq!(extra_slots(&tv, &p), ["s01e02"]);
        // Single episode / movie / pack → no extras.
        let single = parse_release("Show.Name.S01E03.1080p.WEB-GRP");
        assert!(extra_slots(&tv, &single).is_empty());
        assert!(extra_slots(&item("movie", "Film"), &p).is_empty());
        let pack = parse_release("Show.Name.S01.1080p.WEB-GRP");
        assert!(extra_slots(&tv, &pack).is_empty());
    }

    #[test]
    fn rank_ordering() {
        let r = |stem: &str| quality_rank(&parse_release(stem));
        let webdl_1080 = r("Show.Name.S01E02.1080p.WEB-DL.x264-GRP");
        let bluray_1080 = r("Show.Name.S01E02.1080p.BluRay.x264-GRP");
        let remux_1080 = r("Show.Name.S01E02.1080p.BluRay.REMUX-GRP");
        let webdl_2160 = r("Show.Name.S01E02.2160p.WEB-DL.x265-GRP");
        let remux_2160 = r("Show.Name.S01E02.2160p.BluRay.REMUX-GRP");
        let hdtv_720 = r("Show.Name.S01E02.720p.HDTV.x264-GRP");
        assert!(hdtv_720 < webdl_1080);
        assert!(webdl_1080 < bluray_1080);
        assert!(bluray_1080 < remux_1080);
        assert!(remux_1080 < webdl_2160);
        assert!(webdl_2160 < remux_2160);
        assert!(remux_2160 >= threshold_rank("remux"));
        assert!(webdl_2160 < threshold_rank("remux"));
    }

    /// The encode tie-break orders releases that used to rank identically,
    /// without ever disturbing the resolution bands or the remux floor
    /// that `threshold_rank` depends on.
    #[cfg(feature = "indexer")]
    #[test]
    fn encode_extras_break_ties_without_crossing_bands() {
        let r = |stem: &str| quality_rank(&parse_release(stem));
        let plain = r("Film.2024.2160p.WEB-DL.x264-GRP");
        let hevc = r("Film.2024.2160p.WEB-DL.x265-GRP");
        let atmos = r("Film.2024.2160p.WEB-DL.x265.Atmos-GRP");
        let dv = r("Film.2024.2160p.WEB-DL.x265.Atmos.DV.HDR-GRP");
        assert!(plain < hevc, "a modern codec is the better encode");
        assert!(hevc < atmos);
        assert!(atmos < dv);
        // The band below stays below, however loaded it is.
        let best_1080 = r("Film.2024.1080p.BluRay.REMUX.x265.Atmos.DV.HDR-GRP");
        assert!(best_1080 < r("Film.2024.2160p.HDTV.x264-GRP"));
        // And the fully-loaded non-remux 2160p still fails a remux floor.
        assert!(dv < threshold_rank("remux"));
        assert!(r("Film.2024.2160p.BluRay.REMUX.x265.Atmos.DV-GRP") >= threshold_rank("remux"));
    }

    #[cfg(feature = "indexer")]
    #[test]
    fn preference_puts_what_you_asked_for_first() {
        let prefs = QualityPrefs {
            acodec: "Atmos".into(),
            hdr: "DV".into(),
            ..Default::default()
        };
        let s = |stem: &str| preference_score(&parse_release(stem), &prefs);
        let plain_4k = s("Film.2024.2160p.WEB-DL.x265-GRP");
        let atmos_1080 = s("Film.2024.1080p.WEB-DL.x265.Atmos-GRP");
        let atmos_dv_1080 = s("Film.2024.1080p.WEB-DL.x265.Atmos.DV-GRP");
        // Asking for Atmos and DV means a 1080p that has both outranks a
        // 4K that has neither - that is what stating a preference means.
        assert!(atmos_1080 > plain_4k);
        assert!(atmos_dv_1080 > atmos_1080);
        // Resolution outweighs the rest COMBINED when it is asked for.
        let want4k = QualityPrefs {
            res: "2160p".into(),
            ..prefs.clone()
        };
        let t = |stem: &str| preference_score(&parse_release(stem), &want4k);
        assert!(t("Film.2024.2160p.WEB-DL.x265-GRP") > t("Film.2024.1080p.WEB.x265.Atmos.DV-GRP"));
        let every_field = QualityPrefs {
            res: "2160p".into(),
            vcodec: "x265".into(),
            acodec: "Atmos".into(),
            hdr: "DV".into(),
        };
        let e = |stem: &str| preference_score(&parse_release(stem), &every_field);
        assert!(
            e("Film.2024.2160p.WEB-DL.x264-GRP") > e("Film.2024.1080p.WEB-DL.x265.Atmos.DV-GRP"),
            "a requested resolution must outweigh every other preference combined"
        );
        // No preference set ⇒ plain quality order, nothing distorted.
        let none = QualityPrefs::default();
        assert!(none.is_empty());
        let q = |stem: &str| preference_score(&parse_release(stem), &none);
        assert_eq!(
            q("Film.2024.2160p.WEB-DL.x265-GRP") as u32,
            quality_rank(&parse_release("Film.2024.2160p.WEB-DL.x265-GRP"))
        );
        assert!(q("Film.2024.2160p.WEB-DL.x265-GRP") > q("Film.2024.1080p.WEB.x265.Atmos.DV-GRP"));
    }

    #[test]
    fn quality_prefs_parse_and_validate() {
        let p = QualityPrefs::from_json(
            r#"{"res":"2160p","vcodec":"x265","acodec":"atmos","hdr":"dv"}"#,
        )
        .unwrap();
        // Stored in the parser's spelling whatever case was typed, so it
        // compares equal to what a release parses to.
        assert_eq!((p.acodec.as_str(), p.hdr.as_str()), ("Atmos", "DV"));
        // Absent, empty, and no-JSON-at-all all mean "no opinion".
        assert!(QualityPrefs::from_json("").unwrap().is_empty());
        assert!(QualityPrefs::from_json("{}").unwrap().is_empty());
        assert_eq!(QualityPrefs::from_json(r#"{"res":""}"#).unwrap().res, "");
        // settings.json stores the parsed OBJECT, not the string the API
        // sent, so a restart reads this shape back. Getting this wrong
        // dropped the preference on every restart.
        let stored = p.to_json();
        assert_eq!(QualityPrefs::from_value(&stored).unwrap(), p);
        assert!(
            QualityPrefs::from_value(&serde_json::json!({}))
                .unwrap()
                .is_empty()
        );
        // A typo is an error, not a preference that silently never matches.
        assert!(QualityPrefs::from_json(r#"{"acodec":"atoms"}"#).is_err());
        assert!(QualityPrefs::from_json(r#"{"res":"4k"}"#).is_err());
        assert!(QualityPrefs::from_json("not json").is_err());
    }

    #[test]
    fn thresholds() {
        assert_eq!(threshold_rank("any"), 0);
        assert_eq!(threshold_rank(""), 0);
        assert_eq!(threshold_rank("720p"), 3000);
        assert_eq!(threshold_rank("1080p"), 4000);
        assert_eq!(threshold_rank("2160p"), 5000);
        // A 720p release passes a 720p floor regardless of source.
        let p = parse_release("Show.S01E01.720p.HDTV.x264-GRP");
        assert!(quality_rank(&p) >= threshold_rank("720p"));
        assert!(quality_rank(&p) < threshold_rank("1080p"));
    }

    #[test]
    fn matching_titles_and_kinds() {
        let tv = item("tv", "Severance");
        assert!(matches(
            &tv,
            "Severance.S02E03.1080p.WEB.h264-GRP",
            &parse_release("Severance.S02E03.1080p.WEB.h264-GRP")
        ));
        // Separator/case-insensitive.
        assert!(matches(
            &tv,
            "severance_S02E03_720p_HDTV-x",
            &parse_release("severance_S02E03_720p_HDTV-x")
        ));
        // Different show, movie kind, and superset titles all miss.
        assert!(!matches(
            &tv,
            "Severance.Pay.S01E01.1080p.WEB-GRP",
            &parse_release("Severance.Pay.S01E01.1080p.WEB-GRP")
        ));
        assert!(!matches(
            &tv,
            "Severance.2024.1080p.BluRay.x264-GRP",
            &parse_release("Severance.2024.1080p.BluRay.x264-GRP")
        ));

        let mv = item("movie", "Dune Part Two");
        assert!(matches(
            &mv,
            "Dune.Part.Two.2024.2160p.WEB-DL-GRP",
            &parse_release("Dune.Part.Two.2024.2160p.WEB-DL-GRP")
        ));
        assert!(!matches(
            &mv,
            "Dune.Part.Two.S01E01.1080p.WEB-GRP",
            &parse_release("Dune.Part.Two.S01E01.1080p.WEB-GRP")
        ));
    }

    #[test]
    fn matching_year_pin() {
        let mut mv = item("movie", "Dune");
        mv.year = Some(2021);
        assert!(matches(
            &mv,
            "Dune.2021.2160p.BluRay.REMUX-GRP",
            &parse_release("Dune.2021.2160p.BluRay.REMUX-GRP")
        ));
        assert!(!matches(
            &mv,
            "Dune.1984.1080p.BluRay.x264-GRP",
            &parse_release("Dune.1984.1080p.BluRay.x264-GRP")
        ));
    }

    #[test]
    fn matching_language() {
        let tv = item("tv", "Dark");
        // Tagged German-only audio: rejected. MULTI: accepted. Untagged:
        // accepted (scene convention = English).
        assert!(!matches(
            &tv,
            "Dark.S01E01.German.1080p.WEB.x264-GRP",
            &parse_release("Dark.S01E01.German.1080p.WEB.x264-GRP")
        ));
        assert!(matches(
            &tv,
            "Dark.S01E01.MULTI.1080p.WEB.x264-GRP",
            &parse_release("Dark.S01E01.MULTI.1080p.WEB.x264-GRP")
        ));
        assert!(matches(
            &tv,
            "Dark.S01E01.1080p.WEB.x264-GRP",
            &parse_release("Dark.S01E01.1080p.WEB.x264-GRP")
        ));
    }

    #[test]
    fn range_specs() {
        for all in ["", "all", "ALL", "*", " "] {
            assert!(in_range_spec(all, 7), "{all:?} should match everything");
        }
        assert!(in_range_spec("3", 3));
        assert!(!in_range_spec("3", 4));
        assert!(in_range_spec("1-13", 1));
        assert!(in_range_spec("1-13", 13));
        assert!(!in_range_spec("1-13", 14));
        assert!(in_range_spec("1,3,5-7", 6));
        assert!(!in_range_spec("1,3,5-7", 4));
        // Reversed range still works; junk = no constraint.
        assert!(in_range_spec("13-1", 5));
        assert!(in_range_spec("wat", 5));
    }

    #[test]
    fn matching_tv_scope() {
        let mut tv = item("tv", "Severance");
        tv.seasons = "3".into();
        tv.episodes = "1-13".into();
        assert!(matches(
            &tv,
            "Severance.S03E01.1080p.WEB-GRP",
            &parse_release("Severance.S03E01.1080p.WEB-GRP")
        ));
        assert!(matches(
            &tv,
            "Severance.S03E13.1080p.WEB-GRP",
            &parse_release("Severance.S03E13.1080p.WEB-GRP")
        ));
        // Wrong season / episode outside the window.
        assert!(!matches(
            &tv,
            "Severance.S02E03.1080p.WEB-GRP",
            &parse_release("Severance.S02E03.1080p.WEB-GRP")
        ));
        assert!(!matches(
            &tv,
            "Severance.S03E14.1080p.WEB-GRP",
            &parse_release("Severance.S03E14.1080p.WEB-GRP")
        ));
        // "All" scope takes anything.
        tv.seasons = "all".into();
        tv.episodes.clear();
        assert!(matches(
            &tv,
            "Severance.S02E03.1080p.WEB-GRP",
            &parse_release("Severance.S02E03.1080p.WEB-GRP")
        ));
    }

    #[test]
    fn slots() {
        let tv = item("tv", "Severance");
        let mv = item("movie", "Dune");
        assert_eq!(
            slot_of(&tv, &parse_release("Severance.S02E03.1080p.WEB-GRP")).as_deref(),
            Some("s02e03")
        );
        // A season pack fills the SEASON's slot, not an episode's.
        assert_eq!(
            slot_of(&tv, &parse_release("Severance.S02.1080p.WEB-GRP")).as_deref(),
            Some("s02")
        );
        assert_eq!(
            slot_of(&mv, &parse_release("Dune.2021.1080p.WEB-GRP")).as_deref(),
            Some("movie")
        );
        assert_eq!(state_key(7, "s02e03"), "7:s02e03");
    }

    #[test]
    fn decisions() {
        let min = threshold_rank("720p");
        let target = threshold_rank("1080p");
        let hdtv480 = quality_rank(&parse_release("X.S01E01.480p.HDTV-G"));
        let hdtv720 = quality_rank(&parse_release("X.S01E01.720p.HDTV-G"));
        let web1080 = quality_rank(&parse_release("X.S01E01.1080p.WEB-G"));
        let blu1080 = quality_rank(&parse_release("X.S01E01.1080p.BluRay-G"));
        // Below the floor: never grabbed, even with nothing on hand.
        assert_eq!(decide(None, hdtv480, min, target, true), Decision::Skip);
        // First acceptable version.
        assert_eq!(decide(None, hdtv720, min, target, true), Decision::Grab);
        // Better version while below target → upgrade.
        assert_eq!(
            decide(Some(hdtv720), web1080, min, target, true),
            Decision::Upgrade
        );
        // Already at target: a better encode no longer triggers.
        assert_eq!(
            decide(Some(web1080), blu1080, min, target, true),
            Decision::Skip
        );
        // Upgrades disabled: first grab is final.
        assert_eq!(
            decide(Some(hdtv720), web1080, min, target, false),
            Decision::Skip
        );
        // Same or worse rank is never an upgrade.
        assert_eq!(
            decide(Some(web1080), web1080, min, target, true),
            Decision::Skip
        );
        assert_eq!(
            decide(Some(web1080), hdtv720, min, target, true),
            Decision::Skip
        );
    }

    /// 24D: a custom-category item matches through the SAME classify
    /// path ingest uses, and refuses everything that path did not claim.
    #[test]
    fn custom_category_items_match_their_own_releases() {
        let cats = f1_cats();
        let mut it = item("formula-1", "Formula1");
        const QUALI: &str =
            "Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p.H264.English-MWR";
        let quali = classify(QUALI, &cats);
        assert!(matches(&it, QUALI, &quali));
        // A film the category did not claim is not this item's, even
        // though it parses as a perfectly good release.
        const MATRIX: &str = "The.Matrix.1999.1080p.BluRay.x264-GRP";
        assert!(!matches(&it, MATRIX, &classify(MATRIX, &cats)));
        // Another category's release: right shape, wrong slug.
        const GP: &str = "MotoGP.2026.Round05.France.Race.1080p.WEB-DL-GRP";
        let motogp = classify(GP, &cats);
        assert_eq!(motogp.kind, Kind::Custom("motogp".into()));
        assert!(!matches(&it, GP, &motogp));
        // With no categories configured the stem is a plain Movie, so
        // the slug item declines it - classification is what decides.
        assert!(!matches(&it, QUALI, &parse_release(QUALI)));
        // A "movie" item no longer claims what a category took: exactly
        // one kind owns a release.
        assert!(!matches(&item("movie", "Formula1"), QUALI, &quali));
        // Wrong title still misses.
        assert!(!matches(&item("formula-1", "MotoGP"), QUALI, &quali));
        // The year pin works on an event post, whose year IS its season.
        it.year = Some(2026);
        assert!(matches(&it, QUALI, &quali));
        it.year = Some(2025);
        assert!(!matches(&it, QUALI, &quali));
        // Non-English audio is kept: a user category is an explicit want.
        const DE: &str = "Formula1.2026.Round12.Spa.Race.German.1080p.WEB-DL-MWR";
        assert!(matches(
            &item("formula-1", "Formula1"),
            DE,
            &classify(DE, &cats)
        ));
    }

    /// The item the wall's ☆ button writes for a user category, exactly
    /// as it writes it: the card's title, no year pin, no episode scope.
    /// It has to keep matching next season - a card year pinned from the
    /// UI would quietly retire the watch on 1 January.
    #[test]
    fn starring_a_category_card_keeps_watching_next_season() {
        let cats = f1_cats();
        let it = item("formula-1", "Formula1");
        const RACE26: &str = "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.1080p.H264-MWR";
        const RACE27: &str = "Formula1.2027.Round03.Australia.Race.F1TV.WEB-DL.1080p.H264-MWR";
        assert!(matches(&it, RACE26, &classify(RACE26, &cats)));
        assert!(matches(&it, RACE27, &classify(RACE27, &cats)));
        // ...and each session keeps its own slot, so grabbing one does
        // not mark the season done.
        assert_ne!(
            slot_of(&it, &classify(RACE26, &cats)),
            slot_of(&it, &classify(RACE27, &cats))
        );
    }

    /// Why the ☆ button is NOT offered on a built-in music/book/software
    /// card: a non-tv/movie kind only ever answers to a CUSTOM slug, so
    /// such an item would sit there matching nothing forever. If these
    /// ever should be watchable, the fix is here, not in the wall.
    #[test]
    fn builtin_non_video_kinds_match_nothing() {
        const ALBUM: &str = "Metallica-72.Seasons-CD-FLAC-2023-PERFECT";
        const APP: &str = "Sketch.v99.4.1.macOS-TNT";
        let album = parse_release(ALBUM);
        assert_eq!(album.kind, Kind::Music);
        assert!(!matches(&item("music", "Metallica"), ALBUM, &album));
        assert!(!matches(&item("music", ""), ALBUM, &album));
        assert!(!matches(
            &item("software", "Sketch"),
            APP,
            &parse_release(APP)
        ));
    }

    /// The shapes that made the feature look wired-up and grab nothing:
    /// content whose parsed "title" is most of the stem. Exact title
    /// equality matched none of these (measured over a corpus of real
    /// post names), so a custom item matches by containment on the stem.
    #[test]
    fn custom_items_match_the_shapes_a_parser_cannot_title() {
        let cats = vec![
            CustomCategory {
                slug: "music".into(),
                name: "Music".into(),
                pattern: "(?i)(flac|mp3|-cd-)".into(),
                not_match: String::new(),
                base: BaseBehavior::None,
            },
            CustomCategory {
                slug: "combat".into(),
                name: "Combat".into(),
                pattern: "(?i)^ufc".into(),
                not_match: String::new(),
                base: BaseBehavior::Movie,
            },
            CustomCategory {
                slug: "anime".into(),
                name: "Anime".into(),
                pattern: "(?i)(one.piece|subsplease)".into(),
                not_match: String::new(),
                base: BaseBehavior::Tv,
            },
        ];
        let hit = |kind: &str, title: &str, stem: &str| {
            matches(&item(kind, title), stem, &classify(stem, &cats))
        };
        // Music: the album, the rip format and the year all end up in
        // the "title"; the artist is what the user types.
        assert!(hit(
            "music",
            "Metallica",
            "Metallica-72.Seasons-CD-FLAC-2023-PERFECT"
        ));
        assert!(hit(
            "music",
            "Metallica",
            "Metallica-Ride.The.Lightning-Remastered-2016-FLAC"
        ));
        assert!(!hit(
            "music",
            "Metallica",
            "Radiohead-OK.Computer-1997-MP3-320"
        ));
        // Combat sports: numbered events, no year, no episode.
        assert!(hit(
            "combat",
            "UFC",
            "UFC.310.Jones.vs.Miocic.PPV.1080p.WEB-DL-GRP"
        ));
        assert!(hit(
            "combat",
            "UFC 310",
            "UFC.310.Jones.vs.Miocic.PPV.1080p.WEB-DL-GRP"
        ));
        // Anime: the episode number lands inside the title.
        assert!(hit(
            "anime",
            "One Piece",
            "One.Piece.1085.1080p.WEB.x264-VARYG"
        ));
        assert!(hit(
            "anime",
            "Frieren",
            "[SubsPlease] Frieren - 15 (1080p) [ABCD1234]"
        ));
        // Word-boundary aligned, so a shorter name is not a prefix match
        // on a longer one.
        assert!(!hit(
            "music",
            "Metal",
            "Metallica-72.Seasons-CD-FLAC-2023-PERFECT"
        ));
        // An empty title on a custom item means the whole category: the
        // rule already said what the user wants.
        assert!(hit("music", "", "Radiohead-OK.Computer-1997-MP3-320"));
        assert!(hit(
            "combat",
            "  ",
            "UFC.311.Makhachev.vs.Tsarukyan.PPV.1080p-GRP"
        ));
        // ...but an empty title on a film or show still matches nothing,
        // or one blank row would grab the entire index.
        assert!(!matches(&item("movie", ""), MOVIE, &parse_release(MOVIE)));
        assert!(!matches(&item("tv", ""), SHOW, &parse_release(SHOW)));
        // And built-in titles stay EXACT: no containment creep.
        assert!(matches(
            &item("tv", "Severance"),
            SHOW,
            &parse_release(SHOW)
        ));
        assert!(!matches(&item("tv", "Sever"), SHOW, &parse_release(SHOW)));
        assert!(!matches(
            &item("tv", "Severance"),
            "Severance.Pay.S01E01.1080p.WEB-GRP",
            &parse_release("Severance.Pay.S01E01.1080p.WEB-GRP")
        ));
    }

    const MOVIE: &str = "The.Matrix.1999.1080p.BluRay.x264-GRP";
    const SHOW: &str = "Severance.S02E03.1080p.WEB.h264-GRP";

    /// The F1 lesson, at the watchlist layer: sessions of one season get
    /// their own slots, so grabbing the qualifying does not mark the
    /// whole category "have it".
    #[test]
    fn custom_slots_follow_the_identity_key() {
        let cats = f1_cats();
        let it = item("formula-1", "Formula1");
        let s = |stem: &str| slot_of(&it, &classify(stem, &cats)).unwrap();
        let qs = s("Formula1.2026.Round11.Hungary.Qualifying.WEB-DL.1080p-MWR");
        let rs = s("Formula1.2026.Round11.Hungary.Race.WEB-DL.1080p-MWR");
        assert_ne!(qs, rs, "two sessions collapsed into one slot");
        assert!(qs.starts_with("c:formula-1:"), "{qs}");
        // A better encode of the SAME session is the same slot - that is
        // what makes it an upgrade rather than a second download.
        assert_eq!(
            s("Formula1.2026.Round11.Hungary.Qualifying.WEB-DL.2160p-GRP"),
            qs
        );

        // Dated events: a whole matchday is not one thing to grab.
        let foot = vec![CustomCategory {
            slug: "football".into(),
            name: "Football".into(),
            pattern: "^epl".into(),
            not_match: String::new(),
            base: BaseBehavior::None,
        }];
        let f = item("football", "EPL");
        let fs = |stem: &str| slot_of(&f, &classify(stem, &foot)).unwrap();
        let a = fs("EPL.2026.08.22.Arsenal.vs.Spurs.1080p.WEB.h264-VERUM");
        let b = fs("EPL.2026.08.22.Liverpool.vs.Everton.1080p.WEB.h264-VERUM");
        let c = fs("EPL.2026.08.15.Arsenal.vs.Chelsea.1080p.WEB.h264-VERUM");
        assert_ne!(a, b, "two fixtures on one Saturday shared a slot");
        assert_ne!(a, c, "two matchdays shared a slot");
        assert_eq!(a, fs("EPL.2026.08.22.Arsenal.vs.Spurs.720p.WEB.h264-OTHER"));

        // An episodic custom tracks per episode, like TV, and its bare
        // season post fills that season's pack slot, like TV's.
        let wcats = vec![CustomCategory {
            slug: "wrestling".into(),
            name: "Wrestling".into(),
            pattern: "wwe".into(),
            not_match: String::new(),
            base: BaseBehavior::Tv,
        }];
        let w = item("wrestling", "WWE Raw");
        const E15: &str = "WWE.Raw.S2026E015.1080p.WEB.h264-GRP";
        let e15 = classify(E15, &wcats);
        assert!(matches(&w, E15, &e15));
        assert_eq!(slot_of(&w, &e15).as_deref(), Some("s2026e15"));
        assert_eq!(
            slot_of(&w, &classify("WWE.Raw.S12.1080p.WEB-GRP", &wcats)).as_deref(),
            Some("s12")
        );
        // Doubles own both slots, as they do for TV.
        let dbl = classify("WWE.Raw.S2026E015E016.1080p.WEB-GRP", &wcats);
        assert_eq!(extra_slots(&w, &dbl), ["s2026e16"]);
        // Episode scope applies to customs too.
        let mut scoped = w.clone();
        scoped.episodes = "1-14".into();
        assert!(!matches(&scoped, E15, &e15));
    }

    #[test]
    fn custom_item_settings_round_trip() {
        let mut it = item("formula-1", "Formula1");
        it.year = Some(2026);
        it.category = "sport".into();
        let json = serde_json::to_string(&it).unwrap();
        let back: WatchItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, "formula-1");
        assert_eq!(back.year, Some(2026));
        assert_eq!(back.category, "sport");
        // Minimal hand-written form (what an older UI or a hand edit
        // sends): a slug kind needs no other new field.
        let min: WatchItem =
            serde_json::from_str(r#"{"id":9,"kind":"formula-1","title":"Formula1"}"#).unwrap();
        assert_eq!(min.kind, "formula-1");
        assert!(min.enabled && min.upgrade);
        assert!(is_custom_kind(&min.kind));
        assert!(!is_custom_kind("tv") && !is_custom_kind("movie") && !is_custom_kind(""));
    }

    // -----------------------------------------------------------------
    // Season packs
    // -----------------------------------------------------------------

    /// A grabbed slot, for the state maps the pack tests build.
    fn slot(rank: u32, stem: &str) -> Slot {
        Slot {
            rank,
            stem: stem.into(),
            quality: String::new(),
            nzo_id: format!("nzo-{stem}"),
            grabbed_at: 0,
            failed: Vec::new(),
        }
    }

    fn state_of(item_id: u64, entries: &[(&str, Slot)]) -> HashMap<String, Slot> {
        entries
            .iter()
            .map(|(k, s)| (state_key(item_id, k), s.clone()))
            .collect()
    }

    #[test]
    fn slot_keys_parse_back_to_season_and_episode() {
        assert_eq!(slot_parts("s01e05"), Some((1, Some(5))));
        assert_eq!(slot_parts("s01"), Some((1, None)));
        // Year-as-season posts (annual sport, soaps) read the same way.
        assert_eq!(slot_parts("s2026e15"), Some((2026, Some(15))));
        assert_eq!(slot_parts("s2026"), Some((2026, None)));
        // Everything that is not part of a season answers None, so no
        // pack is ever thought to cover it.
        for other in [
            "movie",
            "d:20260721",
            "c:formula-1:formula1:2026:round11",
            "",
            "sxx",
        ] {
            assert_eq!(slot_parts(other), None, "{other}");
            assert!(!is_pack_slot(other), "{other}");
        }
        assert!(is_pack_slot("s01") && !is_pack_slot("s01e05"));
        // The two builders and the parser agree, which is what lets the
        // pack of a season be found from any episode of it.
        assert_eq!(slot_parts(&pack_slot(3)), Some((3, None)));
        assert_eq!(slot_parts(&episode_slot(3, 7)), Some((3, Some(7))));
    }

    #[test]
    fn range_spec_counts() {
        // No constraint = no count, matching in_range_spec's reading.
        for all in ["", "all", "*", " ", "wat"] {
            assert_eq!(spec_count(all), None, "{all:?}");
        }
        assert_eq!(spec_count("5"), Some(1));
        assert_eq!(spec_count("1-13"), Some(13));
        assert_eq!(spec_count("13-1"), Some(13)); // reversed, same span
        assert_eq!(spec_count("1,3,5-7"), Some(5));
    }

    /// The pack preference rule, case by case. A pack is the efficient
    /// way to get a season you have none of, and a wasteful way to get
    /// the last episode of one.
    #[test]
    fn pack_eligibility_follows_what_the_season_already_has() {
        let tv = item("tv", "Show Name");
        let webdl = quality_rank(&parse_release("Show.Name.S01.1080p.WEB-GRP"));
        let hdtv = quality_rank(&parse_release("Show.Name.S01.720p.HDTV-GRP"));
        let bluray = quality_rank(&parse_release("Show.Name.S01.1080p.BluRay-GRP"));

        // Nothing of the season in hand: take the pack, whether or not
        // anything is known about how long the season is.
        let nothing = SeasonState::default();
        assert!(pack_eligible(&tv, 1, webdl, nothing));
        assert!(pack_eligible(
            &tv,
            1,
            webdl,
            SeasonState {
                known: 10,
                ..nothing
            }
        ));

        // Half a season already grabbed: the pack brings as much as it
        // repeats, so it is still worth it...
        let half = SeasonState {
            known: 10,
            have: 5,
            best_rank: hdtv,
            pack_rank: 0,
        };
        assert!(pack_eligible(&tv, 1, webdl, half));
        // ...but not when it repeats more than it brings.
        let mostly = SeasonState {
            known: 10,
            have: 8,
            best_rank: hdtv,
            pack_rank: 0,
        };
        assert!(!pack_eligible(&tv, 1, webdl, mostly));
        // ...nor for a single missing episode, however little we hold.
        let one_left = SeasonState {
            known: 2,
            have: 1,
            best_rank: hdtv,
            pack_rank: 0,
        };
        assert!(!pack_eligible(&tv, 1, webdl, one_left));

        // A pack WORSE than the episodes already collected never
        // displaces them, however much of the season is missing.
        let good_singles = SeasonState {
            known: 10,
            have: 4,
            best_rank: bluray,
            pack_rank: 0,
        };
        assert!(!pack_eligible(&tv, 1, hdtv, good_singles));
        assert!(
            pack_eligible(&tv, 1, bluray, good_singles),
            "equal quality is enough"
        );

        // A season already tracked as a pack keeps using packs: whether
        // this one is actually better is decide()'s question.
        let packed = SeasonState {
            known: 10,
            have: 10,
            best_rank: bluray,
            pack_rank: hdtv,
        };
        assert!(pack_eligible(&tv, 1, webdl, packed));

        // Scope gates it: a season the item does not watch, and an item
        // that asked for one specific episode (a pack is not that).
        let mut scoped = item("tv", "Show Name");
        scoped.seasons = "2-4".into();
        assert!(!pack_eligible(&scoped, 1, webdl, nothing));
        assert!(pack_eligible(&scoped, 3, webdl, nothing));
        scoped.seasons.clear();
        scoped.episodes = "5".into();
        assert!(!pack_eligible(&scoped, 1, webdl, nothing));
        scoped.episodes = "5-9".into();
        assert!(pack_eligible(&scoped, 1, webdl, nothing));

        // A film has no seasons to pack.
        assert!(!pack_eligible(&item("movie", "Film"), 1, webdl, nothing));
    }

    /// `season_state` counts only IN-SCOPE episodes, from every source
    /// the watcher has, and keeps the pack's own rank apart from the
    /// singles'.
    #[test]
    fn season_state_counts_scope_only() {
        let mut tv = item("tv", "Show Name");
        tv.episodes = "1-4".into();
        let slots = state_of(
            1,
            &[
                ("s01e01", slot(4200, "Show.Name.S01E01.1080p.WEB-GRP")),
                // An emptied slot (its grab failed) is known, not had.
                (
                    "s01e02",
                    Slot {
                        nzo_id: String::new(),
                        ..slot(0, "")
                    },
                ),
                // Another season's slots never count towards this one.
                ("s02e01", slot(4200, "Show.Name.S02E01.1080p.WEB-GRP")),
                ("movie", slot(9999, "irrelevant")),
            ],
        );
        // A candidate this pass, and an episode list that runs past the
        // item's scope (episode 9 is not wanted, so it is not missing).
        let st = season_state(&tv, 1, &slots, &["s01e03".into()], &[1, 2, 3, 4, 9]);
        assert_eq!((st.known, st.have), (4, 1));
        assert_eq!(st.best_rank, 4200);
        assert_eq!(st.pack_rank, 0);

        // The season's own pack is tracked separately from the singles.
        let mut with_pack = slots.clone();
        with_pack.insert(
            state_key(1, "s01"),
            slot(3200, "Show.Name.S01.720p.HDTV-GRP"),
        );
        let st = season_state(&tv, 1, &with_pack, &[], &[1, 2, 3, 4]);
        assert_eq!(st.pack_rank, 3200);
        assert_eq!(st.have, 1, "a pack is not counted as an episode grab");

        // Another item's slots are not this item's, even at the same
        // season and episode numbers.
        let other = season_state(
            &item("tv", "Show Name"),
            1,
            &state_of(2, &[("s01e01", slot(4200, "x"))]),
            &[],
            &[],
        );
        assert_eq!((other.known, other.have), (0, 0));
    }

    /// Narrowing an item's episode range leaves the slots it already
    /// filled on disk. Those are no longer episodes it wants, so they
    /// must stop counting - `known` and `have` describe the CURRENT
    /// scope. Counting them made a freshly-narrowed item look fully
    /// served, and `pack_eligible` refused the pack that would actually
    /// have delivered the episodes now being asked for.
    #[test]
    fn a_narrowed_scope_drops_the_slots_it_no_longer_wants() {
        let mut tv = item("tv", "Show Name");
        tv.episodes = "1-10".into();
        let slots = state_of(
            1,
            &[
                ("s01e01", slot(4200, "Show.Name.S01E01.1080p.WEB-GRP")),
                ("s01e02", slot(4200, "Show.Name.S01E02.1080p.WEB-GRP")),
                ("s01e03", slot(4200, "Show.Name.S01E03.1080p.WEB-GRP")),
            ],
        );
        let listed: Vec<u32> = (1..=20).collect();
        let before = season_state(&tv, 1, &slots, &[], &listed);
        assert_eq!((before.known, before.have), (10, 3));

        // The user now wants only the back half. Nothing on disk
        // changed - but nothing on disk is in scope either.
        tv.episodes = "11-20".into();
        let after = season_state(&tv, 1, &slots, &[], &listed);
        assert_eq!(
            (after.known, after.have),
            (10, 0),
            "ten episodes wanted, none of them held"
        );
        assert_eq!(
            after.best_rank, 0,
            "a rank from out of scope is not this scope's"
        );
    }

    /// What a pack means for the episodes under it: they read as "have
    /// it" without the pack ever being written into their slots.
    #[test]
    fn a_pack_covers_the_episodes_of_its_season() {
        let pack = slot(4200, "Show.Name.S01.1080p.WEB-GRP");
        let slots = state_of(1, &[("s01", pack.clone())]);
        // Any episode of that season, including ones nobody has heard of
        // yet - which is the point of not enumerating them.
        for ep in [1u32, 5, 22] {
            let got = covering(&slots, 1, &episode_slot(1, ep));
            assert_eq!(
                got.map(|s| s.stem.as_str()),
                Some(pack.stem.as_str()),
                "e{ep}"
            );
        }
        // Not another season, not the film slot, not another item.
        assert!(covering(&slots, 1, "s02e01").is_none());
        assert!(covering(&slots, 1, "movie").is_none());
        assert!(covering(&slots, 2, "s01e01").is_none());

        // Own grab vs pack: the better copy answers, whichever it is.
        let mut mixed = slots.clone();
        mixed.insert(
            state_key(1, "s01e01"),
            slot(5200, "Show.Name.S01E01.2160p.WEB-GRP"),
        );
        mixed.insert(
            state_key(1, "s01e02"),
            slot(3200, "Show.Name.S01E02.720p.HDTV-GRP"),
        );
        assert_eq!(covering(&mixed, 1, "s01e01").map(|s| s.rank), Some(5200));
        assert_eq!(
            covering(&mixed, 1, "s01e02").map(|s| s.rank),
            Some(4200),
            "the pack is better"
        );

        // An emptied slot has nothing, and falls back to the pack.
        let mut emptied = slots.clone();
        emptied.insert(
            state_key(1, "s01e03"),
            Slot {
                nzo_id: String::new(),
                ..slot(5200, "dead")
            },
        );
        assert_eq!(covering(&emptied, 1, "s01e03").map(|s| s.rank), Some(4200));
        // ...and with no pack either, nothing at all.
        assert!(
            covering(
                &state_of(
                    1,
                    &[(
                        "s01e03",
                        Slot {
                            nzo_id: String::new(),
                            ..slot(5200, "dead")
                        }
                    )]
                ),
                1,
                "s01e03"
            )
            .is_none()
        );
    }

    /// The decision an episode faces once a pack covers it: an equal or
    /// worse encode is already had, a better one is a genuine upgrade.
    #[test]
    fn a_pack_settles_the_episodes_it_covers() {
        let tv = item("tv", "Show Name");
        let min = threshold_rank("any");
        let target = threshold_rank("2160p");
        let pack = quality_rank(&parse_release("Show.Name.S01.1080p.WEB-GRP"));
        let slots = state_of(1, &[("s01", slot(pack, "Show.Name.S01.1080p.WEB-GRP"))]);
        let cur = covering(&slots, 1, "s01e04").map(|s| s.rank);
        let ep = |stem: &str| quality_rank(&parse_release(stem));
        assert_eq!(
            decide(
                cur,
                ep("Show.Name.S01E04.720p.HDTV-GRP"),
                min,
                target,
                tv.upgrade
            ),
            Decision::Skip,
            "a worse single of an episode the pack already covers"
        );
        assert_eq!(
            decide(
                cur,
                ep("Show.Name.S01E04.1080p.WEB-GRP"),
                min,
                target,
                tv.upgrade
            ),
            Decision::Skip,
            "an equal single is not worth a second copy"
        );
        assert_eq!(
            decide(
                cur,
                ep("Show.Name.S01E04.2160p.WEB-GRP"),
                min,
                target,
                tv.upgrade
            ),
            Decision::Upgrade
        );
    }

    // -----------------------------------------------------------------
    // Daily-dated posts
    // -----------------------------------------------------------------

    /// A daily show has no SxxEyy: the date is the episode. Both parser
    /// conventions land on one slot key, so the same show posted either
    /// way is not grabbed twice.
    #[test]
    fn daily_shows_key_on_their_date() {
        let tv = item("tv", "The Daily Show");
        let s = |stem: &str| slot_of(&tv, &parse_release(stem));
        let mon = "The.Daily.Show.2026.07.21.1080p.WEB.h264-GRP";
        let tue = "The.Daily.Show.2026.07.22.1080p.WEB.h264-GRP";
        assert_eq!(s(mon).as_deref(), Some("d:20260721"));
        assert_ne!(s(mon), s(tue), "two nights of a daily shared one slot");
        // Better encode of the SAME night is the same slot - an upgrade,
        // not a second download.
        assert_eq!(s(mon), s("The.Daily.Show.2026.07.21.2160p.WEB.h265-GRP"));
        // The YYMMDD convention normalizes to the same key as YYYY.MM.DD.
        let short = item("tv", "At Midnight");
        assert_eq!(
            slot_of(
                &short,
                &parse_release("At.Midnight.150615.720p.HDTV.x264-GRP")
            )
            .as_deref(),
            Some("d:20150615")
        );
        // A dated post is not part of any season, so no pack covers it
        // and it never collides with an episode key.
        assert_eq!(slot_parts("d:20260721"), None);
        // A show that posts BOTH ways keeps the episode key when it has
        // one: the marker is the better identity where it exists.
        assert_eq!(
            slot_of(
                &tv,
                &parse_release("The.Daily.Show.S2026E140.1080p.WEB-GRP")
            )
            .as_deref(),
            Some("s2026e140")
        );
    }

    /// The 24D collision, closed: a daily-dated CUSTOM post keys on its
    /// date through the classified identity key, so a season of fixtures
    /// no longer shares one slot. (The pure parser carries the date;
    /// `categories::classify` folds it into the key.)
    #[test]
    fn daily_custom_posts_do_not_share_a_slot() {
        let cats = vec![CustomCategory {
            slug: "talk".into(),
            name: "Talk".into(),
            pattern: "(?i)^the.daily.show".into(),
            not_match: String::new(),
            base: BaseBehavior::Tv,
        }];
        let it = item("talk", "The Daily Show");
        let s = |stem: &str| slot_of(&it, &classify(stem, &cats)).unwrap();
        let mon = s("The.Daily.Show.2026.07.21.1080p.WEB.h264-GRP");
        let tue = s("The.Daily.Show.2026.07.22.1080p.WEB.h264-GRP");
        assert_ne!(mon, tue, "two nights of a custom daily shared one slot");
        assert!(mon.contains("20260721"), "{mon}");
        assert_eq!(mon, s("The.Daily.Show.2026.07.21.2160p.WEB.h265-GRP"));
    }

    /// State written before packs and dated slots existed must load, and
    /// keep meaning what it meant: the file is the user's grab history
    /// and a rejected one re-downloads their whole watchlist.
    #[test]
    fn old_state_files_still_load() {
        // A v1 file: slots and pending only, no ext_checked, no `failed`
        // list on the slot, and only episode / movie / custom keys.
        const OLD: &str = r#"{
          "slots": {
            "1:s02e03": {"rank": 4200, "stem": "Severance.S02E03.1080p.WEB-GRP",
                         "quality": "1080p WEB", "nzo_id": "SABnzbd_nzo_a", "grabbed_at": 1750000000},
            "2:movie": {"rank": 5500, "stem": "Dune.2021.2160p.BluRay.REMUX-GRP",
                        "quality": "2160p REMUX", "nzo_id": "SABnzbd_nzo_b", "grabbed_at": 1750000001}
          },
          "pending": []
        }"#;
        let st: WatchState = serde_json::from_str(OLD).unwrap();
        assert_eq!(st.slots.len(), 2);
        assert!(st.ext_checked.is_empty() && st.pending.is_empty());
        assert!(st.slots["1:s02e03"].failed.is_empty());
        // The old keys still answer as they always did...
        assert_eq!(covering(&st.slots, 1, "s02e03").map(|s| s.rank), Some(4200));
        assert_eq!(covering(&st.slots, 2, "movie").map(|s| s.rank), Some(5500));
        // ...and an episode of a season with no pack is still empty,
        // rather than being read as covered by one.
        assert!(covering(&st.slots, 1, "s02e04").is_none());
        // A season the old file knows episodes of reads back correctly,
        // so the first pack decision after an upgrade is well-founded.
        let st2 = season_state(&item("tv", "Severance"), 2, &st.slots, &[], &[]);
        assert_eq!((st2.known, st2.have, st2.pack_rank), (1, 1, 0));
        // And the new state round-trips through the same file format.
        let round: WatchState = serde_json::from_str(&serde_json::to_string(&st).unwrap()).unwrap();
        assert_eq!(round.slots.len(), 2);
    }

    #[test]
    fn age_specs_and_gate() {
        // Units; bare number = days.
        assert_eq!(parse_age_spec("90m"), Some(90 * 60));
        assert_eq!(parse_age_spec("2h"), Some(2 * 3600));
        assert_eq!(parse_age_spec("10d"), Some(10 * 86_400));
        assert_eq!(parse_age_spec("10"), Some(10 * 86_400));
        assert_eq!(parse_age_spec("3w"), Some(3 * 7 * 86_400));
        assert_eq!(parse_age_spec("6mo"), Some(6 * 30 * 86_400));
        assert_eq!(parse_age_spec("1y"), Some(365 * 86_400));
        // Empty / garbage = no constraint.
        assert_eq!(parse_age_spec(""), None);
        assert_eq!(parse_age_spec("soon"), None);
        assert_eq!(parse_age_spec("5parsecs"), None);

        let mut item = WatchItem {
            id: 1,
            kind: "movie".into(),
            title: "X".into(),
            year: None,
            seasons: String::new(),
            episodes: String::new(),
            min_quality: String::new(),
            target_quality: "any".into(),
            upgrade: false,
            delete_old: false,
            category: String::new(),
            min_age: "2h".into(),
            max_age: "10d".into(),
            enabled: true,
        };
        let now = 1_800_000_000i64;
        let hours = |h: i64| now - h * 3600;
        assert!(
            !age_ok(&item, hours(1), now),
            "1h-old post is inside the 2h floor"
        );
        assert!(age_ok(&item, hours(3), now));
        assert!(age_ok(&item, hours(9 * 24), now));
        assert!(
            !age_ok(&item, hours(11 * 24), now),
            "11d-old post crosses the 10d ceiling"
        );
        // Unknown upload date is never rejected.
        assert!(age_ok(&item, 0, now));
        // No constraints = everything passes.
        item.min_age.clear();
        item.max_age.clear();
        assert!(age_ok(&item, hours(1), now) && age_ok(&item, hours(1000 * 24), now));
    }

    /// The instant matcher's whole contract: it may over-accept, but it
    /// must NEVER reject a name the real `matches` would take - a false
    /// no is an arrival the watchlist never hears about.
    #[cfg(feature = "indexer")]
    #[test]
    fn the_instant_matcher_never_rejects_what_matches_accepts() {
        let cats = f1_cats();
        let items = vec![
            item("tv", "Wanted Show"),
            WatchItem {
                id: 2,
                ..item("movie", "Some Film")
            },
            WatchItem {
                id: 3,
                // A titleless custom item: its category IS the filter.
                ..item("formula-1", "")
            },
        ];
        let m = InstantMatcher::compile(&items);
        for name in [
            "Wanted.Show.S02E05.1080p.WEB.h264-GRP",
            "Wanted.Show.S02.2160p.BluRay.REMUX-GRP",
            "Some.Film.2019.1080p.BluRay.x264-GRP",
            "Formula1.2026.Round11.Race.1080p-GRP",
        ] {
            let p = classify(name, &cats);
            let taken = items.iter().any(|i| matches(i, name, &p));
            assert!(taken, "test fixture no longer matches: {name}");
            assert!(
                m.wants(name),
                "the instant matcher would drop an arrival the pass grabs: {name}"
            );
        }
        // Over-accepting is allowed; missing the point is not. A name
        // sharing no title token with anything watched is not worth a
        // pass. (Checked without the titleless custom item above, which
        // deliberately accepts everything - a category with no title
        // filter wakes the pass on every arrival, and that is what the
        // rate limit is for.)
        let titled = InstantMatcher::compile(&items[..2]);
        assert!(!titled.wants("Unrelated.Thing.S01E01.1080p.WEB-GRP"));
        assert!(m.wants("Unrelated.Thing.S01E01.1080p.WEB-GRP"));
        // A disabled item stops waking the pass.
        let off = InstantMatcher::compile(&[WatchItem {
            enabled: false,
            ..item("tv", "Wanted Show")
        }]);
        assert!(off.is_empty() && !off.wants("Wanted.Show.S02E05.1080p.WEB-GRP"));
    }

    /// A titleless BUILT-IN item matches nothing (`title_ok` rejects an
    /// empty want), so it must not be compiled in as "everything" - that
    /// would wake the pass for every post in every watched group.
    #[cfg(feature = "indexer")]
    #[test]
    fn a_titleless_builtin_item_matches_nothing_instantly_either() {
        let blank = item("tv", "");
        let p = classify("Wanted.Show.S02E05.1080p.WEB-GRP", &f1_cats());
        assert!(!matches(&blank, "Wanted.Show.S02E05.1080p.WEB-GRP", &p));
        assert!(InstantMatcher::compile(&[blank]).is_empty());
        // The custom kind is the one that reads blank as "no title
        // filter", and the matcher agrees with `title_ok` there.
        let any_f1 = InstantMatcher::compile(&[item("formula-1", "")]);
        assert!(any_f1.wants("Formula1.2026.Round11.Race.1080p-GRP"));
    }

    /// Which item was hit is what the pass stamps its "instant" record
    /// against, so the ids have to come back, not just a yes.
    #[cfg(feature = "indexer")]
    #[test]
    fn instant_hits_name_the_items_they_belong_to() {
        let items = vec![
            item("tv", "Wanted Show"),
            WatchItem {
                id: 2,
                ..item("movie", "Some Film")
            },
        ];
        let m = InstantMatcher::compile(&items);
        assert_eq!(m.hits("Wanted.Show.S02E05.1080p.WEB-GRP"), [1]);
        assert_eq!(m.hits("Some.Film.2019.1080p.BluRay-GRP"), [2]);
        assert!(m.hits("Neither.Of.Them.2019.1080p-GRP").is_empty());
    }

    /// The instant path's hourly ceiling: it bounds PASSES, and a refused
    /// kick is a delay, never a lost grab. The window slides, so a burst
    /// does not lock the path out for an hour after it ends.
    #[cfg(feature = "indexer")]
    #[test]
    fn the_instant_rate_limit_slides_rather_than_resetting() {
        let mut recent = std::collections::VecDeque::new();
        let t0 = 1_800_000_000i64;
        // Three allowed, then the fourth in the same window is refused.
        for i in 0..3 {
            assert!(kick_allowed(&mut recent, 3, t0 + i));
        }
        assert!(!kick_allowed(&mut recent, 3, t0 + 4));
        // Half an hour on, still inside the window of all three.
        assert!(!kick_allowed(&mut recent, 3, t0 + 1_800));
        // A second before the hour is up, still nothing has aged out.
        assert!(!kick_allowed(&mut recent, 3, t0 + 3_599));
        // On the hour the FIRST kick ages out and frees exactly one slot,
        // which the window then takes - so the very next call is refused
        // again rather than the whole allowance coming back at once.
        assert!(kick_allowed(&mut recent, 3, t0 + 3_600));
        assert!(!kick_allowed(&mut recent, 3, t0 + 3_600));
        // 0 = no limit, and no bookkeeping either.
        let mut none = std::collections::VecDeque::new();
        for i in 0..1000 {
            assert!(kick_allowed(&mut none, 0, t0 + i));
        }
        assert!(none.is_empty());
    }
}
