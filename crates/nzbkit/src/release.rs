//! Scene release-name parsing (moved from nzbfast's wall module so the
//! indexer can classify releases at ingest - M25 browse view).
//!
//! Pure text → structured facts: title / year / SxxEyy / resolution /
//! source / language / release group, plus a dedupe key so five encodes
//! of one film group under one card. Handles ROT13/ROT18-obfuscated
//! stems, software posts, daily datecodes, and hyphen-separated stems.

// ---------------------------------------------------------------------------
// Release-name parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Movie,
    Tv,
    /// Software / installer posts (version tokens, keygen vocabulary) -
    /// never enriched, shown only under the wall's "Other" tab.
    Software,
    /// Music posts - scene albums ("Artist-Album-2021-GROUP") and the
    /// tagged form ("Artist - Album (2021) [FLAC]"). `title` carries
    /// "Artist - Album" so the card reads correctly before any provider
    /// answers; `credit_split` recovers the two halves for MusicBrainz.
    Music,
    /// Books / ebooks ("Author - Title (2019) [epub]"). Same
    /// "Credit - Work" title convention as Music.
    Book,
    /// Obfuscated / unparseable - hidden from the wall by default.
    Other,
    /// A user-defined category (TODO 24D): the slug is the stored `kind`
    /// value ("formula-1"). Never produced by `parse_release` itself -
    /// only `categories::classify` / `apply_custom` rewrite a parse into
    /// this, so the pure parser stays rule-free. Completion behavior
    /// (junk sweep / rename) comes from the category's declared
    /// `BaseBehavior`, resolved via `categories::base_of` - a custom kind
    /// is NEVER implicitly movie-like.
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct Parsed {
    pub kind: Kind,
    pub title: String,
    pub year: Option<u32>,
    pub season: Option<u32>,
    pub episode: Option<u32>,
    /// Second episode of a multi-episode post ("S01E01E02" /
    /// "S01E01-E02") - the covered range is episode..=episode2.
    pub episode2: Option<u32>,
    /// "2160p", "1080p", …
    pub res: Option<String>,
    pub remux: bool,
    /// "BluRay" / "WEB" / "HDTV" / "DVD"
    pub source: Option<String>,
    /// Video codec, friendly form: "x265" / "x264" / "AV1" / "XviD" / …
    pub vcodec: Option<String>,
    /// Audio codec, friendly form (strongest track wins): "Atmos" /
    /// "TrueHD" / "DTS-HD" / "DDP" / "AC3" / "AAC" / …
    pub acodec: Option<String>,
    /// Dynamic range, friendly form: "DV" / "HDR10+" / "HDR10" / "HDR" /
    /// "HLG". A DV release almost always carries an HDR10 base layer and
    /// says so, so the richest format wins rather than the first seen.
    /// None = the name said nothing (or said SDR, which is the absence).
    pub hdr: Option<String>,
    /// Audio-language tags found in the stem ("german", "multi", …).
    /// Empty = untagged, which by scene convention means English.
    pub langs: Vec<String>,
    pub group: Option<String>,
    /// Identity-bearing tokens the title had to drop: what sits between
    /// a movie year and the first piece of release furniture. Empty for
    /// an ordinary film, whose year is followed straight by quality tags
    /// ("The.Matrix.1999.1080p.BluRay"). Non-empty for event posts, where
    /// the year is only the SEASON and the real identity comes after it
    /// ("Formula1.2026.Round11.Hungary.Post-Qualifying.Show.…" → Round11,
    /// Hungary, Post-Qualifying, Show). A non-empty `extra` means
    /// "title + year" is NOT a faithful reduction of this release.
    pub(crate) extra: Vec<String>,
    /// The episode DATE of a daily-dated post, normalized to
    /// "yyyymmdd" - the identity of a match, a race, a show of that day.
    /// Set for both conventions the parser knows ("At.Midnight.150615"
    /// and "The.Daily.Show.2026.07.21"); None for everything else.
    ///
    /// The built-in TV key deliberately ignores it (a show's episodes
    /// all group under one card), but without it stored, nothing
    /// downstream could tell two days of a dated post apart - which is
    /// how a whole football season keyed onto one identity.
    pub date: Option<String>,
    /// Dedupe key: movies "m:<title>:<year>", tv "t:<title>" (a show's
    /// seasons and episodes all group under one card).
    pub key: String,
    /// True when this parse came from the ROT13/ROT18 rescue - the raw
    /// stem on the wire is rotated gibberish and `title` is the decoded
    /// name (UIs can show the readable form).
    pub rescued: bool,
}

fn is_year(tok: &str) -> bool {
    tok.len() == 4 && tok.chars().all(|c| c.is_ascii_digit()) && {
        let y: u32 = tok.parse().unwrap_or(0);
        (1900..2100).contains(&y)
    }
}

/// SxxEyy / Sxx / NxNN → (season, episode, second episode of a
/// multi-episode marker - "S01E01E02" / "S01E01-E02" / "S01E01-02").
fn tv_marker(tok: &str) -> Option<(u32, Option<u32>, Option<u32>)> {
    let t = tok.to_ascii_lowercase();
    if let Some(rest) = t.strip_prefix('s') {
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        // 1-2 digit seasons, plus year-as-season ("S2026E015" - annual
        // sports/soaps) when an episode follows; bare "S2026" stays a
        // year, not a season pack.
        let year_season =
            digits.len() == 4 && is_year(&digits) && rest[digits.len()..].starts_with('e');
        if digits.is_empty() || (digits.len() > 2 && !year_season) {
            return None;
        }
        let season = digits.parse().ok()?;
        let after = &rest[digits.len()..];
        if after.is_empty() {
            return Some((season, None, None)); // season pack
        }
        if let Some(ep) = after.strip_prefix('e') {
            let ed: String = ep.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !ed.is_empty() && ed.len() <= 3 {
                let e1: u32 = ed.parse().ok()?;
                // Double-episode tail: "e02", "-e02" or "-02" right after
                // the first episode's digits, and the token must END
                // there ("s01e01-720p" is quality furniture, not E720).
                // Only a HIGHER number counts - "E05-E03" is a typo, not
                // a range.
                let tail = &ep[ed.len()..];
                let tail = tail.strip_prefix('-').unwrap_or(tail);
                let tail = tail.strip_prefix('e').unwrap_or(tail);
                let e2 = ((2..=3).contains(&tail.len())
                    && tail.bytes().all(|c| c.is_ascii_digit()))
                .then(|| tail.parse::<u32>().ok())
                .flatten()
                .filter(|&e2| e2 > e1);
                return Some((season, Some(e1), e2));
            }
        }
        return None;
    }
    // Bare episode marker "E06" (season unknown).
    if let Some(ed) = t.strip_prefix('e')
        && (2..=3).contains(&ed.len())
        && ed.chars().all(|c| c.is_ascii_digit())
    {
        return Some((0, ed.parse().ok(), None));
    }
    // 3x07 form.
    if let Some((s, e)) = t.split_once('x')
        && !s.is_empty()
        && s.len() <= 2
        && s.chars().all(|c| c.is_ascii_digit())
        && (2..=3).contains(&e.len())
        && e.chars().all(|c| c.is_ascii_digit())
    {
        return Some((s.parse().ok()?, e.parse().ok(), None));
    }
    None
}

/// Token ends the title region / marks release furniture.
fn is_tag(tok: &str) -> bool {
    const TAGS: &[&str] = &[
        // resolution
        "2160p",
        "1080p",
        "1080i",
        "720p",
        "576p",
        "480p",
        "4k",
        "uhd",
        // source
        "bluray",
        "blu",
        "bdrip",
        "brrip",
        "remux",
        "web",
        "web-dl",
        "webdl",
        "dl",
        "webrip",
        "hdtv",
        "dvdrip",
        "dvd",
        "hddvd",
        "hdrip",
        "camrip",
        "ts",
        // codec
        "x264",
        "x265",
        "h264",
        "h265",
        "h",
        "hevc",
        "avc",
        "av1",
        "xvid",
        "divx",
        "vc-1",
        "vc1",
        // audio
        "dts",
        "dts-hd",
        "dtshd",
        "dts-x",
        "dtsx",
        "truehd",
        "atmos",
        "aac",
        "ac3",
        "eac3",
        "dd5",
        "ddp",
        "ddp5",
        "flac",
        "opus",
        "mp3",
        "ma",
        // misc release furniture
        "proper",
        "repack",
        "rerip",
        "extended",
        "unrated",
        "internal",
        "limited",
        "complete",
        "multi",
        "dual",
        "subbed",
        "dubbed",
        "vostfr",
        "hdr",
        "hdr10",
        "hdr10+",
        "dv",
        "dovi",
        "sdr",
        "imax",
        "remastered",
        "criterion",
        "3d",
        "10bit",
        "8bit",
        "retail",
        "readnfo",
        "hybrid",
        "season",
        "series",
        "amzn",
        "nf",
        "dsnp",
        "hulu",
        "atvp",
        "max",
        // sibling-file noise (nfo/sfv/samples post as their own "releases")
        "nfo",
        "sfv",
        "srr",
        "srs",
        "sample",
        "proof",
        "subs",
        "par2",
        "nzb",
        "rar",
        "mkv",
        "mp4",
        "avi",
        "m2ts",
        "iso",
        "img",
        "jpg",
        "png",
        "txt",
        "diz",
        "vob",
        // language / region / broadcast furniture
        "german",
        "french",
        "dutch",
        "spanish",
        "italian",
        "swedish",
        "danish",
        "norwegian",
        "flemish",
        "nordic",
        "english",
        "pal",
        "ntsc",
        "dvdr",
        "pdtv",
        "sdtv",
        "ws",
        "nlsubbed",
        "dl-subbed",
    ];
    TAGS.contains(&tok.to_ascii_lowercase().as_str())
}

fn res_of(tok: &str) -> Option<&'static str> {
    match tok.to_ascii_lowercase().as_str() {
        "2160p" | "4k" | "uhd" => Some("2160p"),
        "1080p" | "1080i" => Some("1080p"),
        "720p" => Some("720p"),
        "576p" => Some("576p"),
        "480p" => Some("480p"),
        _ => None,
    }
}

fn source_of(tok: &str) -> Option<&'static str> {
    match tok.to_ascii_lowercase().as_str() {
        "bluray" | "blu" | "bdrip" | "brrip" => Some("BluRay"),
        "web" | "web-dl" | "webdl" | "webrip" => Some("WEB"),
        "hdtv" => Some("HDTV"),
        "dvdrip" | "dvd" => Some("DVD"),
        _ => None,
    }
}

/// Audio-language markers only - subtitle tags (VOSTFR, NLSUBBED) keep
/// the original audio, so they don't name a language here. Only checked
/// AFTER the title region, so a film titled "Rus" stays untagged.
fn lang_of(tok: &str) -> Option<&'static str> {
    match tok.to_ascii_lowercase().as_str() {
        "german" | "ger" => Some("german"),
        "french" | "fre" | "fra" => Some("french"),
        "dutch" | "flemish" => Some("dutch"),
        "spanish" | "castellano" | "latino" => Some("spanish"),
        "italian" | "ita" => Some("italian"),
        "swedish" => Some("swedish"),
        "danish" => Some("danish"),
        "norwegian" => Some("norwegian"),
        "nordic" => Some("nordic"),
        "korean" | "kor" => Some("korean"),
        "japanese" | "jpn" => Some("japanese"),
        "chinese" | "mandarin" | "cantonese" => Some("chinese"),
        "russian" | "rus" => Some("russian"),
        "polish" => Some("polish"),
        "hungarian" => Some("hungarian"),
        "czech" => Some("czech"),
        "turkish" => Some("turkish"),
        "finnish" => Some("finnish"),
        "hindi" => Some("hindi"),
        "portuguese" => Some("portuguese"),
        "english" | "eng" => Some("english"),
        "multi" | "dual" => Some("multi"),
        _ => None,
    }
}

/// Video codec token → friendly display form. x264/x265 are the encoder
/// names scene encodes use; h264/avc and h265/hevc fold onto them so the
/// rendered name stays consistent whether the post said "x265" or "HEVC".
fn vcodec_of(tok: &str) -> Option<&'static str> {
    match tok.to_ascii_lowercase().as_str() {
        "x265" | "h265" | "hevc" => Some("x265"),
        "x264" | "h264" | "avc" => Some("x264"),
        "av1" => Some("AV1"),
        "xvid" => Some("XviD"),
        "divx" => Some("DivX"),
        "vc-1" | "vc1" => Some("VC-1"),
        _ => None,
    }
}

/// Audio codec token → (priority, friendly form). A release lists several
/// tracks ("AC3 … DTS-HD"); we surface the strongest, so the caller keeps
/// the highest-priority match rather than the first seen.
fn acodec_of(tok: &str) -> Option<(u8, &'static str)> {
    match tok.to_ascii_lowercase().as_str() {
        "atmos" => Some((100, "Atmos")),
        "truehd" => Some((90, "TrueHD")),
        "dts-x" | "dtsx" => Some((85, "DTS-X")),
        "dts-hd" | "dtshd" => Some((80, "DTS-HD")),
        "dts" => Some((70, "DTS")),
        "ddp" | "ddp5" | "eac3" => Some((60, "DDP")),
        "dd5" | "ac3" => Some((50, "AC3")),
        "flac" => Some((45, "FLAC")),
        "aac" => Some((40, "AAC")),
        "opus" => Some((35, "Opus")),
        "mp3" => Some((30, "MP3")),
        _ => None,
    }
}

/// Dynamic-range token → (priority, friendly form). Dolby Vision is
/// shipped as a layer on top of HDR10, so a DV release names both; the
/// caller keeps the highest priority rather than the first seen. "SDR"
/// deliberately maps to nothing: it states the absence, and recording it
/// would make a plain encode look like it carries a format.
fn hdr_of(tok: &str) -> Option<(u8, &'static str)> {
    match tok.to_ascii_lowercase().as_str() {
        "dv" | "dovi" | "dolbyvision" => Some((100, "DV")),
        "hdr10+" | "hdr10plus" => Some((80, "HDR10+")),
        "hdr10" => Some((70, "HDR10")),
        "hdr" => Some((60, "HDR")),
        "hlg" => Some((50, "HLG")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Token roles after the identity marker
//
// Everything a release name puts AFTER its year is either furniture
// (quality/source/codec/edition/group - the stuff that must NOT tell two
// downloads apart) or identity (the round, stage, week, session or event
// that makes this post a different thing from the last one). Callers that
// need to know which is which - the friendly rename, the downloader's
// dupe key - share this one verdict.
// ---------------------------------------------------------------------------

/// What a token sitting after a release's year contributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRole {
    /// Quality / source / codec / container / edition / provenance noise.
    /// Nothing from here to the end of the stem identifies the release,
    /// so a scan can stop at the first one.
    HardFurniture,
    /// Language and region markers. On their own they are furniture (the
    /// same film dubbed twice is still one film), but they must not END
    /// the identity region - "…2026.Hungarian.Grand.Prix.Race…" would
    /// otherwise lose the whole event name to one language tag.
    SoftFurniture,
    /// Part of what makes this release itself.
    Identity,
}

/// Furniture that neither `is_tag` nor the codec tables carry. Only ever
/// consulted for tokens AFTER the year, so title words are never at risk:
/// a film called "Cut" or "Ultimate" still parses by its leading tokens.
const HARD_EXTRA: &[&str] = &[
    // audio spellings TAGS doesn't list ("DD.5.1" splits to a bare "dd")
    "dd",
    "dd2",
    "dd7",
    "ddp7",
    "dtsma",
    "lpcm",
    "pcm",
    "mp2",
    "ac4",
    // "dc" is an edition marker too (Director's Cut), but unlike the
    // EDITION_WORDS block it is an acronym, never a name word, so it
    // stays unconditional furniture here.
    "dc",
    // print provenance
    "int",
    "scr",
    "screener",
    "dvdscr",
    "r5",
    "tc",
    "telesync",
    "telecine",
    "cam",
    "hdcam",
    "workprint",
    "hc",
    "korsub",
    "cd",
    // resolution / colour words TAGS doesn't list
    "hd",
    "fhd",
    "qhd",
    "sd",
    "ultra",
    "hdr10plus",
    "hlg",
    "12bit",
    "vp9",
    // broadcast platforms beyond the TAGS set
    "hmax",
    "pcok",
    "ip",
];

/// Edition markers ("Director's Cut", "Ultimate Edition", "Uncut").
/// Furniture like the rest of HARD_EXTRA - except that these are plain
/// English words a title can end in, so `identity_tail` keeps one when it
/// directly follows an identity word: "Paddock.Uncut" is the show
/// "Paddock Uncut" (tester Gary's F1TV post, 21 Aug 2026), not an uncut
/// print of a show called "Paddock". After a year or other furniture
/// ("Movie.2020.UNCUT.1080p") they stay furniture, so ordinary film
/// shapes still leave `extra` empty and dupe keys unchanged.
const EDITION_WORDS: &[&str] = &[
    "directors",
    "director",
    "theatrical",
    "uncut",
    "uncensored",
    "restored",
    "anniversary",
    "collectors",
    "collector",
    "definitive",
    "ultimate",
    "edition",
    "cut",
];

/// Dub / subtitle markers the language table doesn't carry.
const SOFT_EXTRA: &[&str] = &["truefrench", "vff", "vfq", "vfi", "vf", "vo", "subfrench"];

fn is_hard_furniture(t: &str) -> bool {
    if is_tag(t)
        || res_of(t).is_some()
        || source_of(t).is_some()
        || vcodec_of(t).is_some()
        || acodec_of(t).is_some()
        || HARD_EXTRA.contains(&t)
        || EDITION_WORDS.contains(&t)
    {
        return true;
    }
    // A SECOND four-digit year is furniture: the identity marker was the
    // first one ("Blade.Runner.2049.2017.2160p" keys on 2049).
    if is_year(t) {
        return true;
    }
    // Counted furniture with the number in front ("6ch", "60fps", "v2").
    let counted = |n: &str| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit());
    t.strip_suffix("ch")
        .or_else(|| t.strip_suffix("fps"))
        .is_some_and(counted)
        || t.strip_prefix('v')
            .is_some_and(|n| n.len() <= 2 && counted(n))
}

/// Role of a token that follows a release's identity marker.
pub fn token_role(tok: &str) -> TokenRole {
    let t = tok.to_ascii_lowercase();
    // Languages first: several of them ("german", "english") are also in
    // TAGS, and for identity purposes the softer verdict has to win.
    if lang_of(&t).is_some() || SOFT_EXTRA.contains(&t.as_str()) {
        return TokenRole::SoftFurniture;
    }
    if is_hard_furniture(&t) {
        return TokenRole::HardFurniture;
    }
    // A known tag with a channel count glued on ("AAC5", "DTS5", "DDP51").
    // Trailing digits alone never decide - stripping them leaves nothing
    // for a bare number, so "Round11" / "Week05" / "Stage11" stay identity.
    let stem = t.trim_end_matches(|c: char| c.is_ascii_digit());
    if stem.len() < t.len() && !stem.is_empty() && is_hard_furniture(stem) {
        return TokenRole::HardFurniture;
    }
    TokenRole::Identity
}

/// The identity tokens between a release's year and its furniture, in
/// order. Stops at the first piece of hard furniture; language tags are
/// carried along but a run of NOTHING but language tags is furniture too
/// ("Der.Film.2019.German.DL.1080p" is still one film, so it must reduce
/// to nothing here).
pub fn identity_tail<'a, I: IntoIterator<Item = &'a str>>(after_year: I) -> Vec<&'a str> {
    let mut tail: Vec<&str> = Vec::new();
    let mut any_ident = false;
    let mut prev_ident = false;
    for tok in after_year {
        match token_role(tok) {
            TokenRole::HardFurniture => {
                // An edition word straight after an identity word is the
                // name continuing, not an edition: "Paddock.Uncut.1080p"
                // is the show "Paddock Uncut". Straight after the year or
                // other furniture ("Movie.2020.UNCUT.1080p",
                // "Movie.2020.German.Uncut.1080p") it is the edition it
                // always was, so ordinary film shapes are untouched. See
                // EDITION_WORDS.
                if prev_ident && EDITION_WORDS.contains(&tok.to_ascii_lowercase().as_str()) {
                    tail.push(tok);
                } else {
                    break;
                }
            }
            TokenRole::SoftFurniture => {
                prev_ident = false;
                tail.push(tok);
            }
            TokenRole::Identity => {
                any_ident = true;
                prev_ident = true;
                tail.push(tok);
            }
        }
    }
    if any_ident { tail } else { Vec::new() }
}

/// Junk a reposter appends AFTER the real group tag
/// ("…x264-GRP-Obfuscated", "…-Rakuvfinhel"). Matched whole, so a group
/// that merely contains one of the words ("-RPGroup") is not one of these.
fn is_reposter_tag(tag: &str) -> bool {
    const TAGS: &[&str] = &[
        "obfuscated",
        "obfuscation",
        "scrambled",
        "sample",
        "postbot",
        "xpost",
        "buymore",
        "asrequested",
        "alternativetorequested",
        "gerov",
        "z0ids3n",
        "chamele0n",
        "4planet",
        "altezachen",
        "repackpost",
        "nzbgeek",
        "rp",
    ];
    let low = tag.to_ascii_lowercase();
    TAGS.contains(&low.as_str())
        || (low.starts_with("rakuv") && low[5..].chars().all(|c| c.is_ascii_alphanumeric()))
}

/// Strip those tags off the end of a stem. Repeatedly: they chain
/// ("…-GRP-xpost-Obfuscated"). A stem that is nothing but tags strips to
/// empty, which leaves the parse with no group at all - the caller keeps
/// the stem as posted. Bare "-1" is deliberately not in the list, too many
/// real groups and part numbers end that way.
fn strip_reposter_tags(stem: &str) -> &str {
    let mut s = stem;
    while let Some((head, tag)) = s.rsplit_once('-') {
        if !is_reposter_tag(tag.trim()) {
            break;
        }
        s = head.trim_end_matches(['.', '_', ' ']);
    }
    s
}

/// Release-group tag: the text after the LAST hyphen when it reads as a
/// group rather than release furniture ("…x264-FGT" → "FGT", but
/// "…WEB-DL" → None). Returns the body with the tag removed, and the tag.
fn split_group(stem: &str) -> (&str, Option<&str>) {
    let stem = strip_reposter_tags(stem);
    match stem.rsplit_once('-') {
        Some((b, g)) => {
            let g = g.trim();
            let ok = (2..=20).contains(&g.len())
                && g.chars().all(|c| c.is_ascii_alphanumeric())
                && !g.chars().all(|c| c.is_ascii_digit())
                && !is_tag(g)
                && res_of(g).is_none();
            if ok { (b, Some(g)) } else { (stem, None) }
        }
        None => (stem, None),
    }
}

/// Just the release-group tag - see `split_group`. Exposed so the
/// downloader's dupe key can drop a group tag it would otherwise mistake
/// for part of an event name.
pub fn group_of(stem: &str) -> Option<&str> {
    split_group(stem).1
}

/// The stem sans a short trailing extension token, which would break
/// `looks_obfuscated`'s all-token rules. `extract::release_stem` strips
/// `.rar`, `.par2`, `.volNN+NN` and `.7z.NNN`, but a bare `.7z` (or
/// `.zip`, `.mkv`) survives into the stored stem, so any whole-stem
/// judgement has to take it off first.
/// The trailing token must contain a LETTER to count as an extension.
/// An all-digit tail is a year or a track number, not a suffix: without
/// this, "1917.2019" (the film 1917, posted 2019) strips to "1917",
/// which `looks_obfuscated` calls a blob because it is a single token
/// with no letters - and a readable release then reads as dark, so the
/// apply-gate's "the stem stands" guard lets a mismatched strong claim
/// RENAME it. Same class as the `.7z` bug one layer down; found by
/// Codex's read-only sweep (M7, 10 Aug 2026).
pub fn bare_stem(stem: &str) -> &str {
    stem.rsplit_once('.')
        .filter(|(b, ext)| {
            !b.is_empty()
                && ext.len() <= 4
                && ext.chars().all(|c| c.is_ascii_alphanumeric())
                && ext.chars().any(|c| c.is_ascii_alphabetic())
        })
        .map(|(b, _)| b)
        .unwrap_or(stem)
}

/// Does this stem already SHOW a name a person would want to read?
///
/// THE shared answer to "is this release dark?". The byte-probe picks
/// ask it to decide what is worth fetching; the claims apply-gate asks
/// it to decide whether a proven name may be written. Those two must
/// never disagree. When they drifted (10 Aug 2026 - both judged the raw
/// stem, neither stripped the `.7z` the whole band carries) the prober
/// read eight correct names out of the archives' own headers and the
/// gate threw seven away as conflicts against stems like
/// "uHpvK7XRYNxbvVQbxuW2fGBAPRpMkJuc.7z". One function, one verdict.
pub fn stem_is_a_name(stem: &str) -> bool {
    !looks_obfuscated(bare_stem(stem))
}

/// A single token's trailing year or sequel number, taken off - `None`
/// when the tail is neither, or when the head is not a bare word.
///
/// Both halves are what keeps this from laundering a blob. The DIGITS
/// must read as a year (four, 1900..2100) or a sequel/edition number
/// (one or two): "ABCDEFGHIJK123" and "abcdefghijkl123" end in three,
/// which is neither, so nothing is stripped and both stay the hashes
/// `obfuscated_hash_shapes_are_caught` has pinned since the rule was
/// written. And the HEAD must be all letters, because "a word plus a
/// number" is the whole shape being recognised - "a1b2c3d4e5f6g7h8i9j0k1l2"
/// and "c1bceab2fac4d74f47b0a0e18311ec5c53" carry digits right through
/// and were never that.
///
/// STATED LIMIT, because it is a decision and not an oversight: a head
/// this function would already call a NAME with no tail on it is called
/// a name with one on it too ("qwrtypasdf" and "qwrtypasdf99" get the
/// same verdict, and that verdict is "name"). That is the property being
/// asserted - the tail is not evidence - rather than a new claim about
/// the head, and the alternative is a second, differently-drawn boundary
/// for digit-tailed stems, which is exactly the drift this whole
/// one-verdict function exists to refuse. Nothing downstream is
/// loosened: `get::settle::filedesc_name_is_better` still refuses only
/// the losing direction, so a stem that reads as a name declines a
/// FileDesc HASH and takes a FileDesc NAME exactly as before.
fn strip_year_or_sequel(tok: &str) -> Option<&str> {
    let head = tok.trim_end_matches(|c: char| c.is_ascii_digit());
    let digits = &tok[head.len()..];
    let tail_reads_as_a_number = match digits.len() {
        1 | 2 => true,
        4 => is_year(digits),
        _ => false,
    };
    (tail_reads_as_a_number && !head.is_empty() && head.chars().all(|c| c.is_ascii_alphabetic()))
        .then_some(head)
}

/// Obfuscated stems: hex hashes, base64-ish blobs - nothing to present.
/// pub(crate): the index's junk score reuses the same verdict (M28).
pub fn looks_obfuscated(stem: &str) -> bool {
    let toks: Vec<&str> = stem
        .split(['.', '_', ' ', '-'])
        .filter(|t| !t.is_empty())
        .collect();
    if toks.is_empty() {
        return true;
    }
    // All tokens long hex → hash name ("2137d880a074…").
    if toks
        .iter()
        .all(|t| t.len() >= 8 && t.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return true;
    }
    // Fixed-width HEX blob the whole way across ("d41d8cd98f00b204…"):
    // md5-shaped renames that carry no digits and only a capital or two,
    // so every rule below misses them. Anchored on the whole stem, which
    // means a real title cannot match - titles carry separators.
    //
    // Hex, not alnum: an md5 is hex by definition, and the wider test
    // swallowed a 32-character concatenated title
    // ("ThelordoftheringsReturnoftheking") that every other rule here
    // deliberately passes.
    if stem.len() == 32 && stem.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    if toks.len() != 1 {
        return false;
    }
    // Single token with no letters at all ("141444") is nothing to present.
    if !toks[0].chars().any(|c| c.is_ascii_alphabetic()) {
        return true;
    }
    // A YEAR or a SEQUEL NUMBER run onto the title is not a hash
    // (M4-48, 30 Aug 2026). "Inception2010", "Godzilla1998" and
    // "Terminator2" are honest subjects a poster wrote without
    // separators, and the mixed-alnum rule below called all three
    // blobs - which is not a cosmetic misread: `stem_is_a_name` is what
    // `get::plan` turns into `hint_is_posted_name`, so GH #63's
    // keep-the-honest-subject rule never armed and
    // `get::settle::filedesc_name_is_better` renamed the good file TO
    // the FileDesc hash. A wrong name on a real file.
    //
    // The tail carries NO evidence either way, so it is removed and the
    // SAME question is asked of the head - never a new threshold, which
    // is the fix that looks right and is not: "Terminator2" is eleven
    // characters, so any length that admits it admits an eleven-
    // character blob too. Every rule that catches a digit-free blob
    // still catches it with a year on the end (scattered internal
    // capitals, a long single-case run, a hex word), and the recursion
    // terminates because the head cannot end in a digit.
    if let Some(head) = strip_year_or_sequel(toks[0]) {
        return looks_obfuscated(head);
    }
    // Single mixed-alnum blob with digits ("n1iY94U6fTpMVY9GPD", "2EBoCStAISS").
    if toks[0].len() >= 10
        && toks[0].chars().any(|c| c.is_ascii_digit())
        && toks[0].chars().all(|c| c.is_ascii_alphanumeric())
    {
        return true;
    }
    // Digit-free blob with scattered internal capitals ("MQHeRbSCIoPs",
    // "jvfrZItzZsNF") - real one-word titles cap the first letter only
    // ("Inception"), and even "RoboCop" has just one internal cap.
    if toks[0].len() >= 10
        && toks[0]
            .chars()
            .skip(1)
            .filter(|c| c.is_ascii_uppercase())
            .count()
            >= 3
    {
        return true;
    }
    // Long single-case alphabetic blob ("nzqymzflnjiyztgyntcynzzytq") -
    // lowercase base32 output, which carries no digits and no internal
    // capitals so every rule above misses it. Twenty characters is past
    // any one-word title anybody posts, and the cost of being wrong here
    // is one wasted article fetch.
    toks[0].len() >= 20
        && toks[0].chars().all(|c| c.is_ascii_alphabetic())
        && (toks[0].chars().all(|c| c.is_ascii_lowercase())
            || toks[0].chars().all(|c| c.is_ascii_uppercase()))
}

/// Does this string read as a RELEASE NAME rather than a human title or
/// a muxer's own furniture?
///
/// The question is asked of strings that arrive from outside the posted
/// name - a container's Title tag, a naming oracle's canonical name -
/// and the bar is deliberately high, because a wrong answer renames the
/// user's file. "Sintel" and "Episode 3" are titles, not releases;
/// "Big.Buck.Bunny.2008.1080p.BluRay.x264-GRP" is a release.
///
/// The test is the parser's own furniture, counted: a release name
/// carries at least two independent scene signals, and the muxers that
/// write a plain human title carry none of them. `looks_obfuscated`
/// keeps out the hash-shaped strings a reposter may have written there
/// instead.
pub fn looks_like_release_name(s: &str) -> bool {
    let s = s.trim();
    // Long enough to be a name, short enough to be a filename stem.
    if !(6..=180).contains(&s.len()) || looks_obfuscated(s) {
        return false;
    }
    // A path, or a filename with its extension still on it, is not a
    // release name - it is a member of one, and using it would file the
    // payload under a container name.
    if s.contains('/') || s.contains('\\') {
        return false;
    }
    let p = parse_release(s);
    if p.title.trim().is_empty() {
        return false;
    }
    let signals = [
        p.year.is_some(),
        p.res.is_some(),
        p.source.is_some(),
        p.group.is_some(),
        p.season.is_some() || p.episode.is_some() || p.date.is_some(),
        p.vcodec.is_some(),
        p.remux,
    ]
    .iter()
    .filter(|b| **b)
    .count();
    signals >= 2
}

/// Software / non-video posts ("CCleaner Professional Plus v6.36.11041
/// x64 Setup"): returns the index of the first software marker, which
/// doubles as the title cut point. A version token or a strong keyword
/// decides alone; weak installer vocabulary needs two hits so movie
/// titles containing "Setup" or "The Professional" survive.
fn software_marker(toks: &[&str]) -> Option<usize> {
    let strong = |t: &str| {
        matches!(
            t,
            "keygen" | "keymaker" | "activator" | "preactivated" | "regged"
        )
    };
    // Weak vocabulary splits in two: "namey" words are usually part of
    // the product name itself ("Office Professional Plus") and stay in
    // the title; "furniture" words ("Incl", "x64", "Setup") end it.
    let namey = |t: &str| matches!(t, "pro" | "plus" | "professional" | "edition");
    let furniture = |t: &str| {
        matches!(
            t,
            "crack"
                | "cracked"
                | "patch"
                | "serial"
                | "portable"
                | "installer"
                | "setup"
                | "x64"
                | "x86"
                | "win32"
                | "win64"
                | "windows"
                | "macos"
                | "linux"
                | "multilingual"
                | "software"
                | "incl"
                | "build"
        )
    };
    // "v6.36" as one token, or "v6" whose dot-split successor is a bare
    // number ("v6" "36" "11041") - but never "v2" followed by a year or
    // a word, which is how a title would use it.
    let version = |i: usize, t: &str| {
        t.len() >= 2
            && t.starts_with('v')
            && t[1..].chars().all(|c| c.is_ascii_digit() || c == '.')
            && t[1..].chars().any(|c| c.is_ascii_digit())
            && (t[1..].contains('.')
                || toks.get(i + 1).is_some_and(|n| {
                    !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) && !is_year(n)
                }))
    };
    let mut first_furniture: Option<usize> = None;
    let mut weak_hits = 0;
    for (i, t) in toks.iter().enumerate() {
        let lt = t.to_ascii_lowercase();
        if strong(&lt) || version(i, &lt) {
            // Cut at the earliest furniture marker ("Some.App.Incl.
            // Keygen" → "Some App"), else at the strong marker itself.
            return Some(first_furniture.map_or(i, |w| w.min(i)));
        }
        if namey(&lt) {
            weak_hits += 1;
        } else if furniture(&lt) {
            weak_hits += 1;
            first_furniture.get_or_insert(i);
        }
    }
    // ONE furniture hit decides when the stem carries no video evidence
    // at all - the same shape of gate the music rules below apply, and
    // for the same reason.
    //
    // The case this exists for: vendors who version by YEAR.
    // `Adobe.Illustrator.2026.u6.Multilingual` and
    // `Android Studio 2026.1.3.7 Latest Offline Installer` carry no `v`
    // token and no keygen vocabulary, so they needed two weak hits and
    // had one each - and a bare trailing year parses as a film, so both
    // landed on the wall as 2026 MOVIES, sitting between real releases.
    //
    // Narrow on both axes deliberately. Only the furniture words a film
    // title does not use ("Setup", "Windows", "Patch", "Build" and the
    // rest stay out - each is a plausible title word), and only with no
    // resolution, source or codec anywhere in the stem. A real film that
    // says "Multi" or "Setup" says 1080p and x264 beside it, which is
    // what `movies_with_software_ish_words_stay_movies` pins.
    let furniture_alone = |t: &str| {
        matches!(
            t,
            "multilingual" | "installer" | "portable" | "x64" | "x86" | "win32" | "win64"
        )
    };
    if weak_hits == 1
        && let Some(w) = first_furniture
        && toks
            .get(w)
            .is_some_and(|t| furniture_alone(&t.to_ascii_lowercase()))
        && !toks.iter().any(|t| video_token(&t.to_ascii_lowercase()))
    {
        return Some(w);
    }
    // Without a strong marker, two weak hits decide - but at least one
    // must be furniture, or "Pro" and "Plus" in a film title would do it.
    (weak_hits >= 2).then_some(first_furniture).flatten()
}

/// Does this token say "there is video here"? Resolution, source or
/// codec - the three things every real film or episode release names and
/// a software post never does.
///
/// Token-level rather than the parsed `no_video_evidence` below, because
/// the software test runs before those fields exist.
fn video_token(t: &str) -> bool {
    matches!(
        t,
        "480p"
            | "576p"
            | "720p"
            | "1080p"
            | "1440p"
            | "2160p"
            | "4320p"
            | "bluray"
            | "blu-ray"
            | "brrip"
            | "bdrip"
            | "bdremux"
            | "webrip"
            | "web-dl"
            | "webdl"
            | "hdtv"
            | "dvdrip"
            | "hdrip"
            | "remux"
            | "x264"
            | "x265"
            | "h264"
            | "h265"
            | "hevc"
            | "avc"
            | "xvid"
            | "divx"
    )
}

// ---------------------------------------------------------------------------
// Music and book posts
//
// Usenet carries a great deal of both. Until these kinds existed such a
// post was guessed at by the film rules - an album usually came out
// `Movie` with the artist and title mashed into one name - and no
// provider that knows about albums or books was ever consulted, so the
// card could never be more than a bare stem.
//
// Detection is deliberately conservative: a format marker alone
// decides, but ONLY when the stem carries no video evidence at all. A
// concert BluRay says FLAC too, and it is not an album - measured on a
// live index, 191 of the 221 FLAC-bearing stems were video remuxes.
// ---------------------------------------------------------------------------

/// Audio-format markers strong enough to call a post music on their own.
/// Deliberately excludes the tokens a video release legitimately carries
/// as its audio track (AAC, AC3, DTS, Opus): those name one stream
/// inside a film, not the whole payload. FLAC and MP3 are on the list
/// because the video releases that carry them are excluded earlier, by
/// the no-video-evidence gate.
fn audio_marker(tok: &str) -> bool {
    matches!(
        tok,
        "flac"
            | "mp3"
            | "m4a"
            | "alac"
            | "aiff"
            | "wavpack"
            | "webflac"
            | "web-flac"
            | "ogg"
            | "wma"
            | "24bit"
            | "cdda"
            | "cdm"
            | "cds"
            | "cdr"
            | "vinyl"
            | "vbr"
            | "320kbps"
            | "256kbps"
            | "192kbps"
            | "128kbps"
    )
}

/// Ebook-format markers. `cbr` is deliberately absent: it means both
/// "comic book RAR" and "constant bit rate", so it would drag albums
/// into the book lane.
///
/// `pdf` IS here, and it is the marker the magazine lane runs on: a
/// magazine is posted as its own PDF ("PC_Games_Hardware_Magazin_
/// September_No_09_2026.pdf") and carries no other book evidence at
/// all, so without it every magazine parsed as a MOVIE with a year and
/// sat in the film lane. Its only caller filters on
/// `no_video_evidence`, so a film that somehow names a PDF alongside a
/// resolution or a codec keeps its kind.
fn book_marker(tok: &str) -> bool {
    matches!(
        tok,
        "epub"
            | "epub3"
            | "mobi"
            | "azw"
            | "azw3"
            | "fb2"
            | "djvu"
            | "cbz"
            | "pdf"
            | "ebook"
            | "ebooks"
            | "audiobook"
            | "audiobooks"
    )
}

/// True when the stem shows no sign of being a video release. Music and
/// book detection is gated on this, so a concert BluRay ("…2019.1080p.
/// BluRay.FLAC…") stays a movie and an episode stays TV no matter what
/// audio format it names.
fn no_video_evidence(
    res: &Option<String>,
    vcodec: &Option<String>,
    source: &Option<String>,
    remux: bool,
    season: Option<u32>,
    daily: bool,
) -> bool {
    res.is_none()
        && vcodec.is_none()
        && !remux
        && season.is_none()
        && !daily
        // WEB is not video evidence - "WEB" and "WEB-FLAC" are how a
        // digital-store album is tagged. Every other source is a
        // physical or broadcast VIDEO medium.
        && !matches!(source.as_deref(), Some("BluRay") | Some("HDTV") | Some("DVD"))
}

/// Index of the first music/book format marker (the title cut point),
/// searched from index 1 so a release whose FIRST word happens to be one
/// of these ("Vinyl.S01E01…", a film called "Ebook") keeps its title.
/// Books are checked first: an audiobook says both "audiobook" and
/// "MP3", and OpenLibrary is the provider that knows it.
fn media_marker(toks: &[&str]) -> Option<(Kind, usize)> {
    let mut audio: Option<usize> = None;
    for (i, t) in toks.iter().enumerate().skip(1) {
        let lt = t.to_ascii_lowercase();
        // A marker can ride inside a hyphenated token ("WEB-FLAC").
        for part in std::iter::once(lt.as_str()).chain(lt.split('-')) {
            if book_marker(part) {
                return Some((Kind::Book, i));
            }
            if audio.is_none() && audio_marker(part) {
                audio = Some(i);
            }
        }
    }
    audio.map(|i| (Kind::Music, i))
}

/// The scene's music convention is field-structured in a way the normal
/// tokenizer cannot see: hyphens separate FIELDS and underscores stand
/// in for spaces ("Pink_Floyd-The_Dark_Side_Of_The_Moon-1973-EOS"), so
/// splitting on `.`/`_`/` ` alone glues the year onto the last title
/// word ("Moon-1973") and the release reads as one long movie name.
///
/// Fires on `body` (the stem with its group tag already removed) when
/// the fields are hyphen-separated, carry no video evidence, and either
///
/// - a bare year appears from the third field on AND the body uses
///   underscores for spaces - the `Artist-Album-YEAR-GROUP` shape. Not
///   "the LAST field": scene stems trail furniture behind the year
///   ("…-2011-REMASTERED-GRP"); or
/// - a music/book format marker appears from the third field on -
///   `Artist-Album-CD-FLAC-2019-GROUP`.
///
/// The underscore requirement is what keeps `the-matrix-1999-FGT` a
/// film: a fully hyphenated stem with no underscore anywhere is the
/// downloader's own lowercase movie convention, and it has exactly the
/// same field count and trailing year. The cost is that a scene album
/// whose artist AND title are both single words ("Adele-30-2021-C4")
/// is not recognised by this rule - it has no underscore to prove the
/// convention - and falls through to the movie path as it does today.
fn scene_media(body: &str) -> Option<(Kind, String, String, Option<u32>)> {
    if body.contains(['.', ' ']) {
        return None;
    }
    let mut fields: Vec<&str> = body.split('-').filter(|f| !f.is_empty()).collect();
    // Scene music leads with a disc/track number field, which is how the
    // sidecars and the individual tracks of an album are numbered
    // ("00-piero_piccioni-the_light_at_the_edge_of_the_world-cd-flac-2014",
    // "101-chris_brown-run_it"). Measured on a live index: leaving it in
    // made the artist "00" and the album the artist's name.
    if fields.len() > 3
        && (1..=3).contains(&fields[0].len())
        && fields[0].bytes().all(|c| c.is_ascii_digit())
    {
        fields.remove(0);
    }
    if fields.len() < 3 {
        return None;
    }
    // Any video marker anywhere disqualifies: "the-flash-s01e01-720p"
    // has this exact field shape and is an episode.
    fn word_of(f: &str) -> Vec<&str> {
        f.split('_').filter(|w| !w.is_empty()).collect()
    }
    for f in &fields {
        for w in word_of(f) {
            let lw = w.to_ascii_lowercase();
            if tv_marker(&lw).is_some()
                || res_of(&lw).is_some()
                || vcodec_of(&lw).is_some()
                || matches!(source_of(&lw), Some("BluRay") | Some("HDTV") | Some("DVD"))
                || lw == "remux"
            {
                return None;
            }
        }
    }
    // A format marker from the third field on names the kind outright.
    let marker = fields.iter().skip(2).find_map(|f| {
        word_of(f).into_iter().find_map(|w| {
            let lw = w.to_ascii_lowercase();
            if book_marker(&lw) {
                Some(Kind::Book)
            } else if audio_marker(&lw) {
                Some(Kind::Music)
            } else {
                None
            }
        })
    });
    // A bare year from the third field on. Not "the LAST field" - scene
    // stems trail furniture behind the year ("…-2011-REMASTERED-GRP"),
    // and insisting on the final position made the rule miss those.
    let dated = fields.iter().skip(2).any(|f| is_year(f));
    // Books are named by their marker, so a book stem that reached here
    // by the year rule alone would be mislabelled - the bare
    // `Artist-Album-YEAR-GROUP` shape is the music convention.
    let kind = match marker {
        Some(k) => k,
        None if dated && body.contains('_') => Kind::Music,
        None => return None,
    };
    let year = fields
        .iter()
        .skip(2)
        .find(|f| is_year(f))
        .and_then(|f| f.parse().ok());
    let credit = word_of(fields[0]).join(" ");
    let work = word_of(fields[1]).join(" ");
    if credit.is_empty() || work.is_empty() {
        return None;
    }
    Some((kind, credit, work, year))
}

/// Dedupe key for a music/book card. Deliberately carries NO year,
/// unlike the movie key: the year in a scene album stem is the year of
/// that EDITION ("…-2021-GROUP" on a 1973 record), so keying on it would
/// scatter the remaster, the vinyl rip and the original across three
/// cards for one album. Artist+album is the identity, as it is for a
/// show's seasons under "t:".
fn media_key(kind: &Kind, title: &str) -> String {
    let prefix = if matches!(kind, Kind::Book) {
        "bk"
    } else {
        "mu"
    };
    format!("{prefix}:{}", norm_title(title))
}

/// Put back the lane a FED name dropped.
///
/// Every classification site parses `COALESCE(pre_title, stem)`: the
/// proven name is better identity than an obfuscated stem, and the
/// comments at those sites explain why re-parsing the raw stem there
/// would undo the naming. But a fed title names the WORK, not the file.
/// The Spotnet spot that proves `Luiten, Hetty - Op eigen benen.epub`
/// is titled `Hetty Luiten - Op eigen benen`, and `.epub` - the one
/// token saying "book" - is gone with it. The fed parse then falls
/// through `None => Kind::Movie`, the junk scorer sees an evidence-free
/// movie and scores 60, and a wall whose default hides >= 50 shows no
/// books at all. Measured on a live index 16 Aug 2026: 33 of the 38
/// August rows from e-book groups were filed `movie`, every one of them
/// hidden.
///
/// So when the fed parse produced a bare Movie/Other with no video
/// evidence whatsoever, and the STEM parses to Book or Music, take that
/// kind and re-key. The title stays the fed one - only the lane moves.
///
/// `fed` is the name `p` was parsed from. When it IS the stem there is
/// nothing to recover and the second parse would be pure waste - which
/// matters: the `quality_v*` backfill calls this once per row over a
/// multi-million-row index, and the un-named rows are the majority.
pub fn recover_media_kind(p: &mut Parsed, fed: &str, stem: &str) {
    if fed == stem {
        return;
    }
    if !matches!(p.kind, Kind::Movie | Kind::Other) {
        return;
    }
    // Any video/episode fact at all means the fed name classified on
    // evidence, not by falling through, and it is not ours to overrule.
    if !no_video_evidence(
        &p.res,
        &p.vcodec,
        &p.source,
        p.remux,
        p.season,
        p.date.is_some(),
    ) || p.episode.is_some()
    {
        return;
    }
    let from_stem = parse_release(stem);
    if !matches!(from_stem.kind, Kind::Book | Kind::Music) {
        return;
    }
    p.kind = from_stem.kind.clone();
    p.key = media_key(&p.kind, &p.title);
}

/// Split a "Credit - Work" title into its halves - the artist/author and
/// the album/book. Scene music and book stems name the credit first, and
/// we keep both in `title` so a card reads properly before any provider
/// answers; the providers need them apart. Splits on the FIRST separator:
/// an album or book title may contain one ("Artist - Live - 1975"), an
/// artist name almost never does.
pub fn credit_split(title: &str) -> Option<(&str, &str)> {
    let (credit, work) = title.split_once(" - ")?;
    let (credit, work) = (credit.trim(), work.trim());
    (!credit.is_empty() && !work.is_empty()).then_some((credit, work))
}

// ---------------------------------------------------------------------------
// ROT13 rescue: many obfuscated posts are the real name letter-rotated
// (and some rotate digits by 5 as well - ROT18 - so "720p" hides as
// "275c"). Both variants are tried; a decode is only believed when it
// parses into a clean scene name with real furniture AND reads like
// English, so genuine titles never get mangled by accident.
// ---------------------------------------------------------------------------

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

fn rot5_digits(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0'..='9' => (((c as u8 - b'0' + 5) % 10) + b'0') as char,
            _ => c,
        })
        .collect()
}

/// Common English words that survive into almost every real title -
/// a decode containing one is strong evidence it isn't coincidence.
const COMMON_WORDS: &[&str] = &[
    "the", "a", "an", "and", "of", "to", "in", "on", "at", "is", "it", "for", "with", "from", "my",
    "who", "what", "war", "world", "man", "men", "girl", "boy", "king", "queen", "day", "night",
    "dead", "love", "life", "star", "dark", "black", "white", "story", "game", "house", "big",
    "little", "new", "last", "first", "one", "two",
];

/// (every word pronounceable, contains a common English word). A word
/// of 3+ letters with no vowel at all ("qrs", "xkcd") sinks the decode.
fn english_words(title: &str) -> (bool, bool) {
    let mut any = false;
    let mut common = false;
    for w in title.split(' ') {
        let w = w.to_ascii_lowercase();
        if w.is_empty() || !w.chars().all(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        if w.len() >= 3 && !w.chars().any(|c| "aeiouy".contains(c)) {
            return (false, false);
        }
        any = true;
        if COMMON_WORDS.contains(&w.as_str()) {
            common = true;
        }
    }
    (any, common)
}

/// Try both rotation variants and keep the decode with the most scene
/// furniture. Acceptance bar: parses as movie/tv, reads as English, and
/// carries either 2+ furniture tokens (year/SxxEyy/res/source/remux) or
/// 1 plus a common English word - one lucky token alone proves nothing.
fn rot13_rescue(stem: &str) -> Option<Parsed> {
    let letters = rot13(stem);
    let both = rot5_digits(&letters);
    let mut best: Option<(u32, Parsed)> = None;
    for decoded in [letters, both] {
        if looks_obfuscated(&decoded) {
            continue;
        }
        let p = parse_one(&decoded);
        if !matches!(p.kind, Kind::Movie | Kind::Tv) {
            continue;
        }
        let signals = [
            p.year.is_some(),
            p.season.is_some(),
            p.episode.is_some(),
            p.res.is_some(),
            p.source.is_some(),
            p.remux,
        ]
        .iter()
        .filter(|b| **b)
        .count() as u32;
        let (pronounceable, common) = english_words(&p.title);
        if !pronounceable || signals == 0 || (signals < 2 && !common) {
            continue;
        }
        // Season plausibility breaks ties between the letters-only and
        // ROT18 variants: both decode "qiqevc"→"dvdrip" identically and
        // differ only in digits, so "f58r69" scored the same as S58E69
        // (letters kept) and S03E14 (ROT18) - and the wrong one shipped.
        // A sane season number is the extra bit of evidence.
        let plausible = p.season.map_or(0, |s| u32::from((1..=40).contains(&s)));
        let score = signals * 2 + plausible;
        if best.as_ref().is_none_or(|(s, _)| score > *s) {
            best = Some((score, p));
        }
    }
    best.map(|(_, p)| p)
}

/// Normalized dedupe key body: lowercase alnum words joined by spaces.
/// Unicode-aware on purpose: an ASCII-only filter mapped every CJK,
/// Cyrillic and Greek character to a space, so e.g. every Japanese TV
/// title normalized to "" and collapsed onto the single `titles` row
/// "t:" - one poster and overview shared by unrelated shows. ASCII input
/// is unaffected (`to_lowercase`/`is_alphanumeric` agree with the ASCII
/// forms over ASCII); accented Latin now keeps its letters too.
pub fn norm_title(t: &str) -> String {
    t.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Reversed stems. A reposter writes the whole name backwards
// ("PRG-462x.p0801.4202.eivoM.elpmaxE"), which defeats every furniture
// rule above because none of the tokens read forwards. Only a token that
// could not be anything BUT backwards triggers the flip, and the flipped
// parse has to be strictly better than the forward one to be believed.
// ---------------------------------------------------------------------------

/// A whole token that only makes sense read backwards: a resolution
/// ("p027" = 720p, "p0801" = 1080p) or an SxxEyy marker ("20E10S" =
/// S01E02, "210E10S" = S01E012). Whole-token only, so a real word that
/// merely contains one of these is not one.
fn reads_backwards(tok: &str) -> bool {
    // Every shape below is 4 ("p084") to 7 ("210E10S") characters, and
    // this runs over every token of every furniture-less stem the index
    // scans - so the width decides before anything allocates.
    if !(4..=7).contains(&tok.len()) {
        return false;
    }
    let t = tok.to_ascii_lowercase();
    let b = t.as_bytes();
    // Reversed resolution. Derived from `res_of` rather than listed, so
    // the two cannot drift apart, and shaped so only the "<digits>p"
    // resolutions qualify - "4k" backwards is two characters of nothing.
    let reversed_res = t.strip_prefix('p').is_some_and(|digits| {
        (3..=4).contains(&digits.len())
            && digits.bytes().all(|c| c.is_ascii_digit())
            && res_of(&t.chars().rev().collect::<String>()).is_some()
    });
    if reversed_res {
        return true;
    }
    // Reversed episode marker: episode digits, 'e', season digits, 's'.
    (6..=7).contains(&b.len())
        && b[b.len() - 1] == b's'
        && b[b.len() - 4] == b'e'
        && b[..b.len() - 4].iter().all(u8::is_ascii_digit)
        && b[b.len() - 3..b.len() - 1].iter().all(u8::is_ascii_digit)
}

/// Flip the stem and keep the flipped parse only when it is strictly
/// more informative: the forward parse found NO scene furniture at all,
/// and the flipped one found a pronounceable title plus enough facts to
/// rule out coincidence. Without the title test a flip that recovers a
/// resolution but leaves a bare number for a name would be believed.
///
/// "Forward furniture" has to mean every identity signal, not just the
/// two the flip is hunting for: a year, a source or an air date all say
/// the stem already reads forwards, and "Christmas.p0801.Home.Movies.
/// 2019" flipped to "9102 seivoM emoH".
///
/// The English test cannot carry the rest on its own, because vowels
/// survive a reversal - "epaT" reads as pronounceably as "Tape" - so the
/// acceptance bar is `rot13_rescue`'s furniture count, raised to two
/// signals with no one-plus-a-common-word escape: a reversed title keeps
/// real English words, so the common-word tell that works for ROT13
/// proves nothing here. Season and episode come from ONE SxxEyy token
/// and so count once between them, and only when the season reads
/// plausibly - otherwise the single page marker in
/// "Lecture.Notes.12e34s.Extra" flips it to S43E21 of "artxE".
fn reversed_rescue(stem: &str, direct: &Parsed) -> Option<Parsed> {
    if direct.res.is_some()
        || direct.season.is_some()
        || direct.episode.is_some()
        || direct.year.is_some()
        || direct.source.is_some()
        || direct.date.is_some()
        || direct.group.is_some()
        || direct.remux
    {
        return None;
    }
    if !stem
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(reads_backwards)
    {
        return None;
    }
    let p = parse_one(&stem.chars().rev().collect::<String>());
    if !matches!(p.kind, Kind::Movie | Kind::Tv) || !english_words(&p.title).0 {
        return None;
    }
    let episode = (p.season.is_some() || p.episode.is_some())
        && p.season.is_none_or(|s| (1..=40).contains(&s));
    let signals = [
        episode,
        p.year.is_some(),
        p.res.is_some(),
        p.source.is_some(),
        p.remux,
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if signals < 2 {
        return None;
    }
    (p.res.is_some() || p.season.is_some() || p.episode.is_some()).then_some(p)
}

pub fn parse_release(stem: &str) -> Parsed {
    let direct = parse_one(stem);
    if let Some(mut p) = reversed_rescue(stem, &direct) {
        p.rescued = true;
        return p;
    }
    // ROT13 rescue: only worth trying when the direct parse found NO
    // scene furniture at all - any recognized year/SxxEyy/res/source
    // token means the stem is already plain text, and rotating a real
    // name can only make it worse.
    // A bare Exx token is NOT disqualifying evidence: rotated RAR part
    // suffixes (".e64" = a rot13'd ".rNN") parse as a bare episode, and
    // that alone kept whole obfuscated sets from ever being rescued.
    let bare_ep_only = direct.episode.is_some() && direct.season.unwrap_or(0) == 0;
    if direct.kind != Kind::Software
        && direct.year.is_none()
        && (direct.season.is_none() || bare_ep_only)
        && (direct.episode.is_none() || bare_ep_only)
        && direct.res.is_none()
        && direct.source.is_none()
        && !direct.remux
        && let Some(mut p) = rot13_rescue(stem)
    {
        p.rescued = true;
        return p;
    }
    direct
}

fn parse_one(stem: &str) -> Parsed {
    let other = |title: &str| Parsed {
        kind: Kind::Other,
        title: title.to_string(),
        year: None,
        season: None,
        episode: None,
        episode2: None,
        res: None,
        remux: false,
        source: None,
        vcodec: None,
        acodec: None,
        hdr: None,
        langs: Vec::new(),
        rescued: false,
        group: None,
        extra: Vec::new(),
        date: None,
        key: format!("o:{}", norm_title(title)),
    };
    if looks_obfuscated(stem) {
        return other(stem);
    }

    // Release group: text after the LAST hyphen, if it looks like a tag.
    let (body, group) = split_group(stem);
    let group = group.map(str::to_string);

    // Tokenize on dot/underscore/space; hyphens survive inside tokens
    // ("Spider-Man", "WEB-DL"). Exception: stems with NO other separator
    // and several hyphens are hyphen-separated ("the-flash-s01e01-720p").
    let all_hyphen = !body.contains(['.', '_', ' ']) && body.matches('-').count() >= 3;
    let seps: &[char] = if all_hyphen { &['-'] } else { &['.', '_', ' '] };
    let toks: Vec<&str> = body
        .split(seps)
        .map(|t| t.trim_matches(|c: char| "[]()".contains(c)))
        .filter(|t| !t.is_empty())
        .collect();
    if toks.is_empty() {
        return other(stem);
    }

    // Software posts get their own kind: never enriched as a film, and
    // segregated onto the wall's "Other" tab instead of Movies/TV.
    if let Some(cut) = software_marker(&toks) {
        let title_toks = if cut == 0 { &toks[..] } else { &toks[..cut] };
        let title = title_toks.join(" ");
        return Parsed {
            kind: Kind::Software,
            key: format!("s:{}", norm_title(&title)),
            title,
            year: None,
            season: None,
            episode: None,
            episode2: None,
            rescued: false,
            res: None,
            remux: false,
            source: None,
            vcodec: None,
            acodec: None,
            hdr: None,
            langs: Vec::new(),
            extra: Vec::new(),
            date: None,
            group,
        };
    }

    // Scene music: hyphen-separated fields the normal tokenizer would
    // glue together. Checked before tokenizing because the whole point
    // is that this shape needs a different split.
    if let Some((kind, credit, work, year)) = scene_media(body) {
        let title = format!("{credit} - {work}");
        return Parsed {
            key: media_key(&kind, &title),
            kind,
            title,
            year,
            season: None,
            episode: None,
            episode2: None,
            // A datecode is an episode's identity; an album's is its
            // artist and title, and the year it carries is an edition
            // marker the key deliberately ignores (see `media_key`).
            date: None,
            rescued: false,
            res: None,
            remux: false,
            source: None,
            vcodec: None,
            acodec: None,
            hdr: None,
            langs: Vec::new(),
            extra: Vec::new(),
            group,
        };
    }

    let mut season = None;
    let mut episode = None;
    let mut episode2 = None;
    let mut res = None;
    let mut source = None;
    let mut vcodec = None;
    let mut acodec: Option<String> = None;
    let mut arank = 0u8;
    let mut hdr: Option<String> = None;
    let mut hrank = 0u8;
    let mut langs: Vec<String> = Vec::new();
    let mut remux = false;
    // Daily shows date-code instead of SxxEyy ("At.Midnight.150615.720p").
    let mut daily = false;
    let mut date: Option<String> = None;
    // Index of the first token AFTER the date, so the identity tail can
    // start there (the same trick the movie-year arm uses).
    let mut date_end: Option<usize> = None;
    let is_datecode =
        |t: &str| (t.len() == 6 || t.len() == 8) && t.chars().all(|c| c.is_ascii_digit());
    // A 2-digit month or day in range. At eight digits the daily flag is
    // deliberately looser than this (any run of that width reads as a
    // datecode); only a date that validates becomes an identity.
    let d2 = |s: &str, max: u32| {
        s.len() == 2
            && s.bytes().all(|c| c.is_ascii_digit())
            && s.parse::<u32>().is_ok_and(|v| (1..=max).contains(&v))
    };
    // The normalized "yyyymmdd" a datecode reads as, or None when it is
    // not a date. Six digits are held to a much harder bar than eight:
    // that width is also how ids, sizes and part counts look, and YYMMDD
    // has only one sane reading (20YY, near enough to now to be a real
    // air date). Anything short of that is left alone as an ordinary
    // word rather than guessed at.
    let datecode_of = |t: &str| -> Option<String> {
        let (y, md) = t.split_at(t.len() - 4);
        let (mth, day) = md.split_at(2);
        if !d2(mth, 12) || !d2(day, 31) {
            return None;
        }
        if y.len() == 4 {
            return Some(format!("{y}{mth}{day}"));
        }
        if !y.parse::<u32>().is_ok_and(|v| v <= 39) {
            return None;
        }
        // A four-digit year or an SxxEyy marker anywhere in the stem
        // names the release better than a bare six-digit run ever could,
        // so a stem carrying either is not read as YYMMDD at all. Walked
        // here, at the one token that needs the answer, rather than up
        // front for every stem the index parses.
        let competing = toks
            .iter()
            .enumerate()
            .any(|(j, x)| (j > 0 && is_year(x)) || tv_marker(x).is_some());
        (!competing).then(|| format!("20{y}{mth}{day}"))
    };
    // First tag / TV-marker index = hard end of the title region.
    let mut boundary = toks.len();
    for (i, t) in toks.iter().enumerate() {
        if let Some((s, e, e2)) = tv_marker(t) {
            season.get_or_insert(s);
            if let Some(e) = e {
                if episode.is_none() {
                    episode2 = e2; // pairs with the episode that owns the slot
                }
                episode.get_or_insert(e);
            }
            boundary = boundary.min(i);
        } else if is_tag(t) {
            boundary = boundary.min(i);
        } else if i > 0 && is_datecode(t) && (t.len() == 8 || datecode_of(t).is_some()) {
            daily = true;
            // "150615" (YYMMDD) and "20150615" both normalize to
            // yyyymmdd, so the two conventions compare equal.
            if let Some(d) = datecode_of(t).filter(|_| date.is_none()) {
                date = Some(d);
                date_end = Some(i + 1);
            }
            boundary = boundary.min(i);
        } else if i > 0
            && is_year(t)
            && toks.get(i + 1).is_some_and(|m| {
                m.len() == 2 && m.parse::<u32>().is_ok_and(|v| (1..=12).contains(&v))
            })
            && toks.get(i + 2).is_some_and(|d| {
                d.len() == 2 && d.parse::<u32>().is_ok_and(|v| (1..=31).contains(&v))
            })
        {
            // Dotted daily date ("The.Daily.Show.2026.07.21…") - the
            // year token alone otherwise reads as a movie year and the
            // episode identity (the date) is lost.
            daily = true;
            if date.is_none() {
                date = Some(format!("{t}{}{}", toks[i + 1], toks[i + 2]));
                date_end = Some(i + 3);
            }
            boundary = boundary.min(i);
        } else if i > 0
            && t.len() == 4
            && t.starts_with('0')
            && t.chars().all(|c| c.is_ascii_digit())
        {
            // Leading-zero SSEE code ("0601" = S06E01) - can't be a year.
            season.get_or_insert(t[..2].parse().unwrap_or(0));
            episode.get_or_insert(t[2..].parse().unwrap_or(0));
            boundary = boundary.min(i);
        }
        // Quality facts can hide inside hyphenated tokens when a group
        // wasn't split off ("1080p-REMUX"); check parts too.
        for part in t.split('-') {
            if let Some(r) = res_of(part) {
                res.get_or_insert(r.to_string());
            }
            if let Some(s) = source_of(part) {
                source.get_or_insert(s.to_string());
            }
            if part.eq_ignore_ascii_case("remux") {
                remux = true;
            }
        }
        // Codecs: check the WHOLE token first so hyphenated names
        // ("DTS-HD", "DTS-X", "VC-1") aren't split apart, then the parts
        // for combined furniture ("x265-DTS"). The strongest audio wins.
        for cand in std::iter::once(*t).chain(t.split('-')) {
            if let Some(v) = vcodec_of(cand) {
                vcodec.get_or_insert(v.to_string());
            }
            if let Some((rank, a)) = acodec_of(cand)
                && rank > arank
            {
                arank = rank;
                acodec = Some(a.to_string());
            }
            if let Some((rank, h)) = hdr_of(cand)
                && rank > hrank
            {
                hrank = rank;
                hdr = Some(h.to_string());
            }
        }
    }

    // Music / book format markers ("…(1965) [epub]", "…[FLAC]"). Most of
    // them are already release furniture to `is_tag`, but the ebook ones
    // are not, so the marker also has to close the title region - "Frank
    // Herbert - Dune 1965 epub" must not keep "epub" in its title.
    let media = media_marker(&toks)
        .filter(|_| no_video_evidence(&res, &vcodec, &source, remux, season, daily));
    if let Some((_, i)) = &media {
        boundary = boundary.min(*i);
    }

    // Year: the LAST year-like token before the boundary, never index 0
    // ("2012.2009.1080p" → title "2012", year 2009; "Blade.Runner.2049.
    // 2017.2160p" → title "Blade Runner 2049", year 2017).
    let year_idx = toks[..boundary]
        .iter()
        .enumerate()
        .rev()
        .find(|(i, t)| *i > 0 && is_year(t))
        .map(|(i, _)| i);
    let cut = year_idx.unwrap_or(boundary).min(boundary);
    let year: Option<u32> = year_idx.and_then(|i| toks[i].parse().ok());

    // Language tags live in the furniture after the title region - only
    // look there, so a film titled "Rus" or "Ita" stays untagged.
    for t in &toks[cut..] {
        for part in t.split('-') {
            if let Some(l) = lang_of(part)
                && !langs.iter().any(|x| x == l)
            {
                langs.push(l.to_string());
            }
        }
    }

    let title_toks = &toks[..cut];
    if title_toks.is_empty() {
        return other(stem);
    }
    let mut title = title_toks.join(" ");
    // Single-case stems (ALLCAPS shouting or all-lowercase mumbling) fold
    // to title case; mixed case is left exactly as the poster wrote it.
    if title.chars().filter(|c| c.is_ascii_alphabetic()).count() > 3
        && !(title.chars().any(|c| c.is_ascii_lowercase())
            && title.chars().any(|c| c.is_ascii_uppercase()))
    {
        // Words the plain fold mangles: roman numerals ("PLANET.EARTH.II"
        // became "Planet Earth Ii") and household acronyms ("THE.OFFICE.US"
        // became "The Office Us"). Only multi-word titles qualify - the
        // 2019 film "Us" must stay "Us", and there a lone "us"/"ii" token
        // IS the title, not a suffix. I, V and X are left out on purpose:
        // as single letters they are far more often initials than numerals.
        const KEEP_UPPER: [&str; 28] = [
            "ii", "iii", "iv", "vi", "vii", "viii", "ix", "xi", "xii", "xiii", "xiv", "xv", "us",
            "uk", "usa", "wwe", "nhl", "nba", "nfl", "ufc", "fbi", "cia", "swat", "nasa", "bbc",
            "cnn", "espn", "uefa",
        ];
        let multi = title_toks.len() > 1;
        title = title
            .split(' ')
            .map(|w| {
                let lower = w.to_ascii_lowercase();
                if multi && KEEP_UPPER.contains(&lower.as_str()) {
                    return lower.to_ascii_uppercase();
                }
                let mut cs = w.chars();
                match cs.next() {
                    Some(f) => {
                        f.to_ascii_uppercase().to_string() + &cs.as_str().to_ascii_lowercase()
                    }
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
    }

    let kind = match &media {
        Some((k, _)) => k.clone(),
        None if season.is_some() || daily => Kind::Tv,
        None => Kind::Movie,
    };
    // What the title had to leave behind. Only meaningful for a movie
    // whose title was cut AT its year: that is the shape where the year
    // can be a season rather than a release date, and everything that
    // tells one post from the next ("Round11.Hungary.Post-Qualifying")
    // sits after it. TV already carries its identity in season/episode,
    // and a yearless title was cut at the first tag, so both stay empty.
    //
    // Note this deliberately does NOT change `kind`: these are still
    // Movie posts as far as the rest of the app is concerned, and
    // `finalize_names` gates the junk sweep on Movie | Tv, so demoting
    // them to Other would quietly stop PAR2 cleanup for exactly the
    // releases this field exists to describe.
    let extra: Vec<String> = if kind == Kind::Movie && year_idx == Some(cut) {
        identity_tail(toks[cut + 1..].iter().copied())
            .into_iter()
            .map(str::to_string)
            .collect()
    } else if let Some(end) = date_end {
        // A dated post's identity continues AFTER the date: which
        // fixture, which session, which guest ("EPL.2026.08.22.Arsenal.
        // vs.Spurs"). Two fixtures on one Saturday are not the same
        // event, and the date alone said they were.
        identity_tail(toks[end..].iter().copied())
            .into_iter()
            .map(str::to_string)
            .collect()
    } else {
        Vec::new()
    };
    let key = match kind {
        Kind::Tv => format!("t:{}", norm_title(&title)),
        Kind::Music | Kind::Book => media_key(&kind, &title),
        _ => match year {
            Some(y) => format!("m:{}:{y}", norm_title(&title)),
            None => format!("m:{}", norm_title(&title)),
        },
    };
    Parsed {
        kind,
        title,
        year,
        rescued: false,
        season,
        episode,
        episode2,
        res,
        remux,
        source,
        vcodec,
        acodec,
        hdr,
        langs,
        extra,
        group,
        date,
        key,
    }
}

/// Short quality label for card badges: "2160p REMUX", "1080p WEB", …
pub fn quality_label(p: &Parsed) -> String {
    let mut s = p.res.clone().unwrap_or_default();
    if p.remux {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str("REMUX");
    } else if let Some(src) = &p.source {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(src);
    }
    s
}

// ---------------------------------------------------------------------------
// Friendly-name builder (auto-rename): reassemble a clean, informative name
// from the parsed facts. Shared so downloader and indexer name alike.
// ---------------------------------------------------------------------------

/// Which quality facts a friendly name should carry. Title + year are
/// always present; each of these is an independent user toggle.
#[derive(Debug, Clone, Copy, Default)]
pub struct NameStyle {
    pub resolution: bool,
    pub video_codec: bool,
    pub audio_codec: bool,
    /// Source medium (BluRay/WEB/…) or REMUX.
    pub source: bool,
    /// Trailing release-group tag ("-FGT").
    pub group: bool,
    /// Wrap the year in parentheses: "Title (1999)" rather than
    /// "Title 1999". Off by default. Note that "Title (Year)" is the
    /// folder shape Plex, Jellyfin and Radarr match against, so anyone
    /// feeding a media server usually wants this on.
    pub year_parens: bool,
    /// Wrap the quality facts in square brackets: "… [1080p x265]" rather
    /// than "… 1080p x265". Off by default.
    pub quality_brackets: bool,
    /// Carry the words the parser did not recognise into the name, so
    /// releases that differ only in those words stay distinguishable:
    /// "Formula1 2026 Round11 Hungary Race" and "… Hungary Qualifying"
    /// rather than two folders both called "Formula1 (2026)".
    ///
    /// Only ever adds words to a name we would otherwise DECLINE to
    /// build (see movie_name) - it cannot reshape a film that already
    /// names cleanly, because a film that parses cleanly leaves nothing
    /// in `extra`.
    pub extra_words: bool,
}

/// Quality suffix built from the style-enabled facts, e.g.
/// " [1080p x265 DTS-HD]" (or " 1080p x265 DTS-HD" without
/// `style.quality_brackets`), plus a "-GROUP" tail when `style.group`.
/// Empty string when nothing is enabled or nothing is known - the caller
/// appends it directly to a base name.
pub fn quality_suffix(p: &Parsed, style: &NameStyle) -> String {
    let mut parts: Vec<String> = Vec::new();
    if style.resolution
        && let Some(r) = &p.res
    {
        parts.push(r.clone());
    }
    if style.source {
        if p.remux {
            parts.push("REMUX".to_string());
        } else if let Some(s) = &p.source {
            parts.push(s.clone());
        }
    }
    if style.video_codec
        && let Some(v) = &p.vcodec
    {
        parts.push(v.clone());
    }
    if style.audio_codec
        && let Some(a) = &p.acodec
    {
        parts.push(a.clone());
    }
    let mut out = String::new();
    if !parts.is_empty() {
        out.push(' ');
        if style.quality_brackets {
            out.push('[');
        }
        out.push_str(&parts.join(" "));
        if style.quality_brackets {
            out.push(']');
        }
    }
    if style.group
        && let Some(g) = &p.group
    {
        out.push_str(&format!("-{g}"));
    }
    out
}

/// Split a [`Parsed::date`] ("20260721") into the year a daily show is
/// filed under and the dotted air date its episode is named after
/// ("2026", "2026.07.21") - the `{Series Title} - {Air-Date}` convention
/// every library uses for a show that has no season/episode numbers.
///
/// None unless the string is exactly the normalized 8-digit shape
/// `parse_release` produces AND reads as a real calendar date, so a
/// caller building a filename declines rather than emit half a date.
/// This is deliberately stricter than the `daily` flag: that flag only
/// has to decide "TV, not a movie", while a name written to disk has to
/// be right.
pub fn air_date_parts(date: &str) -> Option<(String, String)> {
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, md) = date.split_at(4);
    let (month, day) = md.split_at(2);
    let num = |s: &str| s.parse::<u32>().ok().filter(|v| *v >= 1);
    let (y, m, d) = (num(year)?, num(month)?, num(day)?);
    if m > 12 || d > days_in_month(y, m) {
        return None;
    }
    Some((year.to_string(), format!("{year}.{month}.{day}")))
}

/// Length of a Gregorian month. The day check used to be a flat
/// `1..=31`, so `Show.2026.02.31` was filed as a daily episode under
/// `Show/Season 2026/Show - 2026.02.31` - a date that does not exist,
/// written into a library, from a name this function's own contract
/// promises to have read as a real calendar date.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        // Proleptic Gregorian, which is what a four-digit year in a
        // release name means: every 4th year, except centuries, except
        // every 400th.
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

/// Friendly base name (no extension) for a movie / loose file:
/// "The Matrix (1999)" plus the style suffix. Path-safe. Returns None when
/// there's nothing better to offer than the original - an obfuscated /
/// unparseable stem, or an empty title.
pub fn movie_name(p: &Parsed, style: &NameStyle) -> Option<String> {
    if p.kind == Kind::Other {
        return None;
    }
    let title = p.title.trim();
    if title.is_empty() {
        return None;
    }
    // A release whose identity lives AFTER the year is not a film with a
    // release date - it is one event in a season ("Formula1.2026.Round11.
    // Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p…"). Reducing it to
    // "Title (Year)" renames every round and every session of the year to
    // the same string, which collides on disk.
    //
    // The words that tell those apart are sitting right there in `extra`
    // - "Round11 Hungary Race" vs "Round11 Hungary Qualifying" - so with
    // extra_words on we keep them and the collision never arises. With it
    // off we decline as before and the poster's own name survives, which
    // is the safer default for anyone who does not want tokens the parser
    // failed to understand appearing in their filenames.
    //
    // Note this arm cannot touch an ordinary film: a film that parses
    // cleanly leaves `extra` EMPTY (measured across editions, cuts, AKA
    // titles, foreign-language and scene-noise shapes), so everything
    // below only ever fires on releases we would otherwise refuse to
    // name at all.
    let mut extra = String::new();
    if !p.extra.is_empty() {
        match extra_words(p) {
            // Either the option is off, or nothing presentable survived
            // the filter and we would be back to the bare colliding
            // "Title (Year)". Both mean: leave it as the poster named it.
            Some(w) if style.extra_words => extra = w,
            _ => return None,
        }
    }
    let suffix = quality_suffix(p, style);
    // Only rename when there's an anchor that makes the name more
    // informative - a year (the hallmark of a real movie post), at least
    // one enabled quality fact, or the event words we just kept. A bare,
    // yearless, quality-less stem ("somefile") could be anything; leave
    // it as the poster named it.
    if p.year.is_none() && suffix.is_empty() && extra.is_empty() {
        return None;
    }
    let mut base = match p.year {
        Some(y) if style.year_parens => format!("{title} ({y})"),
        Some(y) => format!("{title} {y}"),
        None => title.to_string(),
    };
    if !extra.is_empty() {
        base.push(' ');
        base.push_str(&extra);
    }
    base.push_str(&suffix);
    // Nothing nameable survived sanitisation (a title that was all
    // punctuation): decline, as everywhere else here, so the poster's own
    // name stands rather than a placeholder.
    let name = sanitize_name(&base);
    if name.is_empty() { None } else { Some(name) }
}

/// The unrecognised words of a release, filtered down to what is worth
/// putting in a filename, or None if nothing is.
///
/// "Not a codec or a format" needs no list here: anything the parser
/// recognised as resolution, codec, source, language, edition or group
/// was consumed into a typed field and never reaches `extra`. What is
/// left is the release's own vocabulary - "Round11", "Hungary", "Race",
/// "Chiefs", "vs", "Sinner" - plus the occasional scrap. So this filters
/// for presentability rather than meaning: no dictionary, because the
/// useful words here are overwhelmingly proper nouns, event jargon and
/// numbered rounds that no dictionary contains.
fn extra_words(p: &Parsed) -> Option<String> {
    /// Enough to tell two events apart without rebuilding the whole
    /// release name; past this a post is padding, not describing.
    const MAX_WORDS: usize = 6;
    const MAX_LEN: usize = 24;

    let group = p.group.as_deref().unwrap_or_default();
    let mut out: Vec<&str> = Vec::new();
    for w in &p.extra {
        let w = w.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if w.is_empty() || w.len() > MAX_LEN {
            continue;
        }
        // The group already has its own opt-in tag; don't duplicate it.
        if !group.is_empty() && w.eq_ignore_ascii_case(group) {
            continue;
        }
        if w.chars().all(|c| c.is_ascii_digit()) {
            // Short bare numbers are half of an event's identity ("03"
            // in "Week 03", "311" in a UFC card), so keep them - but
            // NOT via looks_obfuscated, which judges whole stems and
            // rightly calls any letterless string unpresentable. A long
            // bare number is a size, a date fragment or an id.
            if w.len() > 4 {
                continue;
            }
        } else if looks_obfuscated(w) {
            // A hash or a scrambled blob describes nothing.
            continue;
        }
        out.push(w);
        if out.len() == MAX_WORDS {
            break;
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out.join(" "))
}

/// Spell a colon out as a separator instead of losing it. A colon is
/// illegal on Windows and carries path meaning there, but in a title it
/// is doing real work ("Alien: Romulus", "Dune: Part Two"), and blanking
/// it to a space read as two titles run together. The convention every
/// library uses: ": " becomes " - ", a bare ":" becomes "-".
fn expand_colons(t: &str) -> String {
    let mut out = String::with_capacity(t.len() + 2);
    let mut chars = t.chars().peekable();
    while let Some(c) = chars.next() {
        if c != ':' {
            out.push(c);
            continue;
        }
        if chars.peek() == Some(&' ') {
            chars.next();
            out.push_str(" - ");
        } else {
            out.push('-');
        }
    }
    out
}

/// Collapse a separator run that colon expansion doubled up ("Title - -
/// Sub", "Title--Sub") back down to one. Only runs of TWO OR MORE hyphens
/// are touched, so a hyphenated word ("Spider-Man") and an ordinary
/// " - " are left exactly as they were.
fn collapse_separators(t: &str) -> String {
    let chars: Vec<char> = t.chars().collect();
    let mut out = String::with_capacity(t.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '-' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        let (mut hyphens, mut spaced) = (0, false);
        while i < chars.len() && (chars[i] == '-' || chars[i] == ' ') {
            if chars[i] == '-' {
                hyphens += 1;
            } else {
                spaced = true;
            }
            i += 1;
        }
        if hyphens < 2 {
            out.extend(&chars[start..i]);
        } else if spaced {
            out.push_str(" - ");
        } else {
            out.push('-');
        }
    }
    out
}

/// Strip path-hostile characters and collapse whitespace for a file/dir
/// name. Keeps brackets/parens (used by the quality suffix).
///
/// The result then goes through the same strong guarantees enqueue-time
/// folder naming uses ([`crate::disk::sanitize_filename`]), with the
/// Windows rules forced ON regardless of host: a finished tree gets moved
/// to a NAS/SMB share, so a leading dot (hidden), a trailing dot (silently
/// truncated) or a reserved device stem ("CON") is a problem everywhere,
/// not just on a Windows box. Without this, stage 4 could emit names that
/// enqueue-time naming had already been fixed to reject.
///
/// Returns an EMPTY string when nothing nameable survives, so callers
/// decline rather than emit `sanitize_filename`'s "unnamed" placeholder or
/// a bare-dot component.
pub fn sanitize_name(t: &str) -> String {
    let expanded = collapse_separators(&expand_colons(t));
    let mapped: String = expanded
        .chars()
        .map(|c| if "/\\:*?\"<>|".contains(c) { ' ' } else { c })
        .collect();
    let collapsed = mapped.split_whitespace().collect::<Vec<_>>().join(" ");
    // A colon at the very start or end leaves a dangling separator behind.
    let collapsed = collapsed
        .trim_start_matches("- ")
        .trim_end_matches(" -")
        .trim();
    // A leading dot is TITLE noise, and dropping it belongs here rather
    // than in the sanitizer. `sanitize_filename_for` stopped deleting
    // leading dots on 30 Aug 2026 (M4-66) because doing so folded two
    // DECLARED member names - `.movie.mkv` and `movie.mkv` - onto one
    // on-disk name, and a declared name is an identity the sanitizer may
    // not quietly discard; it maps the dots to `_` instead. Nothing in
    // this function is a declared name. `t` is a release TITLE - an NZB
    // subject, a spot, a poster's typed line - being turned into
    // something a human wants to read, so `.Hidden Movie (2024)` should
    // name a folder `Hidden Movie (2024)` and not `_Hidden Movie (2024)`.
    // Two different questions, answered in the two different places that
    // own them.
    let collapsed = collapsed.trim_start_matches('.').trim_start();
    if !collapsed.chars().any(|c| c.is_alphanumeric()) {
        return String::new();
    }
    crate::disk::sanitize_filename_for(collapsed, true)
}

#[cfg(test)]
#[path = "release_tests.rs"]
mod release_tests;
