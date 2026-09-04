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
    /// The DATE this post is an edition of, normalized and at one of two
    /// precisions, told apart by LENGTH:
    ///
    /// - eight digits, "yyyymmdd" - a day. The identity of a match, a
    ///   race, a show of that day ("At.Midnight.150615",
    ///   "The.Daily.Show.2026.07.21"), or of one issue of a daily paper
    ///   ("The New York Times - 15 August 2026").
    /// - six digits, "yyyymm" - a MONTH, and only ever a periodical's:
    ///   a monthly magazine has no day to give ("Slam.TruePDF-September.
    ///   2016"), and without a month there is no issue identity at all -
    ///   every September of every year keyed onto one card. Read by
    ///   [`month_issue`], which is armed on the Books lane alone.
    ///
    /// None for everything else. A caller that has to WRITE a calendar
    /// date must go through [`air_date_parts`], which takes the eight-
    /// digit shape and nothing else, so a half date can never be
    /// truncated into a filename.
    ///
    /// The built-in TV key deliberately ignores it (a show's episodes
    /// all group under one card), but without it stored, nothing
    /// downstream could tell two days of a dated post apart - which is
    /// how a whole football season keyed onto one identity.
    pub date: Option<String>,
    /// True when [`Parsed::date`] was read as a broadcast AIR date - the
    /// two daily-TV conventions, a `YYMMDD`/`YYYYMMDD` datecode
    /// ("At.Midnight.150615") or a dotted date ("The.Daily.Show.2026.07.21").
    /// False when the date is a PUBLICATION date instead: the masthead
    /// forms a daily paper and a dated magazine issue are posted under
    /// ("The New York Times - 15 August 2026", "Der Spiegel - 2026-08-15").
    ///
    /// The two must not be conflated, and the reason is
    /// `recover_kind_from_group`. An air date is video evidence - it is
    /// how a show with no SxxEyy names its episode - so a name carrying
    /// one is not a book whatever group it was posted to. A publication
    /// date is the opposite: it is the ONLY thing telling two issues of
    /// one paper apart, and reading it as video evidence stood every
    /// magazine in `alt.binaries.e-book.magazines` back down off the
    /// Books lane to an evidence-free movie at junk 60.
    pub(crate) daily: bool,
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

/// Does `tail` read as a VIDEO CODEC sitting directly behind the
/// quality token `head_last` - "…720p.HDTV" + "x264"?
///
/// `extract::release_stem`'s old-style continuation arm accepts a final
/// dot-token of `<c><digits>` for `c` in `r..=z`, which is the grammar
/// that orders `.r00` through `.z99`. `x264` and `x265` fit it exactly,
/// so `Show.S01E01.720p.HDTV.x264` reduced to `Show.S01E01.720p.HDTV`
/// and `.x264` / `.x265` encodes of one episode collided on a single
/// `(stem, poster, grp)` row. Measured 2 Sep 2026 over 1,024,591 posted
/// file names: 2,245 firings of that arm, of which 17 - four releases -
/// were this shape, all four carrying real `.partNN.rar` or
/// `.volNNN+NN.par2` members whose codec the stem then lost.
///
/// BOTH HALVES ARE LOAD-BEARING and the conjunction is the whole point.
/// Refusing on the quality token ALONE would have refused 208 genuine
/// volume cuts in that same sample (182 behind a bare resolution, 26
/// behind a bare source) - real 100+ volume sets, which is the shattering
/// `release_stem`'s own r-z comment exists to prevent. Refusing on the
/// codec token alone is not safe either: obfuscated posters really do
/// number volumes `<letter><3 digits>`, and the census found
/// `Archers Amendment 788080908778825.z001` and
/// `Bill 889987062850797.x042` doing exactly that, so a bare `.x264`
/// behind a hash name stays a volume. Only a codec BEHIND a resolution
/// or a source is unambiguous - a real `.r07` never follows `1080p` or
/// `BluRay` with nothing in between.
///
/// Derived from `vcodec_of` / `res_of` / `source_of` rather than listing
/// their tokens a second time, the same rule `reads_backwards` follows:
/// a codec added to the vocabulary tomorrow is covered here the same day.
pub(crate) fn codec_behind_quality(head_last: &str, tail: &str) -> bool {
    vcodec_of(tail).is_some() && (res_of(head_last).is_some() || source_of(head_last).is_some())
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

/// Fansub group tag: a leading `[Word]` bracket, and the stem with it
/// (and the separators behind it) removed.
///
/// Anime is not posted in scene shape. `[SubsPlease] Kanojo,
/// Okarishimasu - 09 (1080p) [26591A73].mkv` opens with the group that
/// subtitled it, exactly where a scene name opens with the title, so
/// the tokenizer read "SubsPlease" as the title's first word and every
/// SubsPlease release on the wall carried the subber's name (measured
/// 2 Sep 2026 on a scratch index of
/// alt.binaries.multimedia.anime.highspeed: kind movie, title
/// "SubsPlease Kanojo, Okarishimasu - 09", no episode).
///
/// A bracketed WORD is a group; a bracketed HEX run is repost-bot spam
/// and stays exactly where it is, because `index::ingest::junk_score`
/// damns that shape by name and stripping the tag here would take the
/// evidence away from it. Reposter tags (`[nzbgeek]`) are excluded for
/// the same reason - `strip_reposter_tags` owns those.
fn fansub_tag(stem: &str) -> Option<(&str, &str)> {
    let rest = stem.strip_prefix('[')?;
    let end = rest.find(']')?;
    let tag = rest[..end].trim();
    let body = rest[end + 1..].trim_start_matches(['.', '_', ' ', '-']);
    let hex = tag.len() >= 8 && tag.chars().all(|c| c.is_ascii_hexdigit());
    let ok = (2..=24).contains(&tag.len())
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_ .".contains(c))
        && tag.chars().any(|c| c.is_ascii_alphabetic())
        && !hex
        && !is_reposter_tag(tag)
        && body.chars().any(|c| c.is_ascii_alphanumeric());
    ok.then_some((tag, body))
}

/// A fansub episode number: 1-4 digits, never a year, with the version
/// suffix a re-subbed episode carries taken off ("09v2" is episode 9,
/// posted twice).
fn fansub_number(tok: &str) -> Option<u32> {
    let t = tok
        .rsplit_once('v')
        .filter(|(_, v)| (1..=2).contains(&v.len()) && v.bytes().all(|c| c.is_ascii_digit()))
        .map_or(tok, |(h, _)| h);
    ((1..=4).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_digit()) && !is_year(t))
        .then(|| t.parse().ok())
        .flatten()
}

/// The episode a fansub stem carries AFTER a season token, for the
/// "[Group] Show S2 - 05 (1080p)" shape. The bare "S2" reads as a
/// season PACK, and a pack is not a harmless misread: the watchlist
/// treats one as covering every episode of that season, so a single
/// episode wearing a pack's parse tells a watched show it is done.
/// Scans only as far as the first furniture token, so "[Group] Show S02
/// [1080p]" stays the pack it says it is.
fn fansub_episode_after(toks: &[&str], from: usize) -> Option<u32> {
    for t in toks.iter().skip(from + 1) {
        if is_tag(t) || res_of(t).is_some() || tv_marker(t).is_some() {
            return None;
        }
        if let Some(e) = fansub_number(t) {
            return Some(e);
        }
    }
    None
}

/// The episode a fansub-shaped stem carries, and the token index the
/// title stops at. Only ever asked of a stem that opened with a
/// [`fansub_tag`], because outside that convention every one of these
/// shapes is something else: a trailing bare number is a part counter,
/// a sequel or a track.
///
/// Four conventions, all measured on the highspeed group: `Ep. 04` and
/// its fused form `Ep18`; a number with the episode's own title behind
/// it (`New 09 - I Have a Junior`); `Title - 09`; and a trailing bare
/// number (`Bleach TYBW 41`, `Detective Conan - 1210`) sitting
/// immediately before the quality furniture. A YEAR is never an
/// episode, which is what keeps `[Group] Some Film 2019 1080p` a 2019
/// movie.
fn fansub_episode(toks: &[&str], boundary: usize) -> Option<(usize, u32)> {
    let head = &toks[..boundary];
    let num = fansub_number;
    // Back over the dangling separator the number hung off, so
    // "Kanojo, Okarishimasu - 09" does not title as "Kanojo,
    // Okarishimasu -".
    let trim = |mut i: usize| {
        while i > 0 && !head[i - 1].chars().any(|c| c.is_ascii_alphanumeric()) {
            i -= 1;
        }
        i
    };
    // "Ep. 04" / "Episode 04", and the fused "Ep18" one poster writes
    // instead ("[Exiled-Destiny]_Zipang_Ep18_(E3171C5A)" - 60, movie,
    // titled "Exiled-Destiny Zipang Ep18 E3171C5A"). Checked first: the
    // number belongs to the marker even when more of the title follows.
    for (i, t) in head.iter().enumerate() {
        let lt = t.trim_end_matches('.').to_ascii_lowercase();
        if (lt == "ep" || lt == "episode")
            && let Some(e) = head.get(i + 1).and_then(|n| num(n))
        {
            return Some((trim(i), e));
        }
        if let Some(e) = lt.strip_prefix("ep").and_then(num) {
            return Some((trim(i), e));
        }
    }
    // A number with the episode's own TITLE behind it: the number is
    // followed by the separator that introduces it ("[Abystoma] High
    // School DxD New 09 - I Have a Junior (BD 720p)" - junk 0 but a
    // MOVIE called "High School DxD New 09 - I Have a Junior"). Asked
    // before the trailing-number rule, which by definition cannot see a
    // number that has words after it.
    for i in 1..head.len() {
        if let Some(e) = num(head[i])
            && head
                .get(i + 1)
                .is_some_and(|t| !t.chars().any(|c| c.is_ascii_alphanumeric()))
        {
            return Some((trim(i), e));
        }
    }
    // Trailing bare number, never at index 0 - a stem that is nothing
    // but a number has no title to keep and falls to `other`.
    let i = boundary.checked_sub(1).filter(|&i| i > 0)?;
    num(head[i]).map(|e| (trim(i), e))
}

/// The `Show - NNN - Episode Title` episode a stem carries, and the
/// token index the title stops at. The number must be FENCED by dashes
/// on both sides with a real word in front of it and more words behind
/// it - "Bleach - 187 - Ichigo Rages! The Assassin's Secret.mkv" - which
/// is the shape and the whole of it.
///
/// Only ever asked of a stem whose NEWSGROUP vouches for video, because
/// group-blind this reading is unsafe: "Artist - 01 - Track Title" and
/// "Author - 04 - Chapter Name" are the same shape to the letter, and an
/// episode invented in one of those also disarms
/// `recover_kind_from_group` (it returns early on an episode), which is
/// the whole of the books/music lane rescue. `recover_episode_from_group`
/// owns the gate; this function owns the shape.
///
/// The fence is what separates this from `fansub_episode`'s trailing
/// bare number, which a bracket had to vouch for: a sequel number
/// ("Ghost in the Shell 2") and a part counter trail the title, they are
/// never fenced with the episode's own name behind them. The leading
/// lecture prefix ("003 - Estomago.mp4") cannot reach here either -
/// there is no title in front of its number, and `junk_score` damns
/// that shape on a season/episode-free parse.
fn dashed_episode(toks: &[&str], boundary: usize) -> Option<(usize, u32)> {
    let head = &toks[..boundary];
    let dash = |t: &&str| t.contains('-') && !t.chars().any(|c| c.is_ascii_alphanumeric());
    let word = |t: &&str| t.chars().any(|c| c.is_ascii_alphabetic());
    for i in 1..head.len().saturating_sub(2) {
        if !head.get(i - 1).is_some_and(dash) || !head.get(i + 1).is_some_and(dash) {
            continue;
        }
        // A title in front (not just punctuation and digits) and the
        // episode's own name behind: both halves of the convention.
        if !head[..i].iter().any(word) || !head[i + 2..].iter().any(word) {
            continue;
        }
        if let Some(e) = fansub_number(head[i]) {
            // Back over the dangling separator, so "Bleach - 187" does
            // not title as "Bleach -".
            let mut cut = i;
            while cut > 0 && !head[cut - 1].chars().any(|c| c.is_ascii_alphanumeric()) {
                cut -= 1;
            }
            return Some((cut, e));
        }
    }
    None
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

/// Is this name exactly its own text twice, with no separator? Returns
/// the single half if so.
///
/// THE one home of the de-doubling rule, `pub` for that reason: the
/// naming seam ([`crate::index::Index::apply_named`]) collapses on the
/// way in, the claims arbitration asks whether a standing name is this
/// shape, and the one-shot repair asks the same question of rows
/// written before either. Three readers, one predicate.
///
/// # It is the WIRE that doubles, not us
///
/// Measured 1 Sep 2026 on the live index and confirmed against the
/// article subjects themselves: one poster's tool emits the release
/// name twice inside its own quoted filename, so the doubling is in the
/// subject nzbfast parses, not in anything nzbfast joins -
///
/// ```text
/// (A Bona Fide Killer  S01E06) [02/19] - "A Bona Fide Killer  S01E06A Bona Fide Killer  S01E06.part01.rar" yEnc
/// ```
///
/// So the FILENAME and the `stem` keyed from it stay exactly as posted -
/// they are the wire's, `stem` is half of a release's identity key, and
/// rewriting it would only make the next scan of the same unchanged
/// post mint a second row. Only the NAME collapses.
///
/// # Exact, deliberately
///
/// Halves must match byte for byte, internal double spaces included. A
/// whitespace-normalising variant was measured over the same index and
/// found ZERO rows the exact test misses, while it would newly damn
/// every "New York New York" shape - a repeated title separated by a
/// space, which the exact test can never match because the separator
/// lands in one half only.
///
/// # The length floor
///
/// A half of at least [`MIN_DOUBLED_HALF`] bytes. The 362 exactly
/// doubled stems on the live index have halves of 11 bytes and up
/// except a single "fdrfdr" at 3; the floor sits in that gap, so a
/// short word that happens to be its own echo is left alone.
pub fn undoubled(name: &str) -> Option<&str> {
    let t = name.trim();
    let half = t.len() / 2;
    (t.len().is_multiple_of(2)
        && half >= MIN_DOUBLED_HALF
        && t.is_char_boundary(half)
        && t[..half] == t[half..])
        .then(|| &t[..half])
}

/// Shortest half [`undoubled`] will call a doubling. See its note.
pub const MIN_DOUBLED_HALF: usize = 8;

/// Move the two identity fields a media library matches on - TITLE and
/// YEAR - from a parse of a PROVED name onto a parse of a claimed one,
/// and only where the two CONTRADICT. Returns whether anything moved.
///
/// # The question this answers, and where it was already answered
///
/// GH #63 asked which of two names for one payload is the real one, and
/// the project answered it in `get::settle::filedesc_name_is_better` /
/// `unpack::FileSlot::hint_beats`: a name is given up only in the
/// losing direction, never on arrival order. Wave-7 row W7-06 is that
/// same question asked one layer later, by `naming.rs`, where it
/// had no answer at all - measured 31 Aug 2026, a job whose .nzb named
/// a DIFFERENT FILM renamed a payload the recovery set had proved, took
/// its subtitle sidecar with it, and filed the folder under the wrong
/// title (`research/POST-SETTLE-NAME-AUTHORITY-2026-08-31.md`, probe 5).
///
/// This lives beside [`stem_is_a_name`] rather than in either caller so
/// the two layers cannot answer it differently: that is the whole
/// lesson of the 10 Aug drift recorded above, one naming tier over.
///
/// # Why title and year, and nothing else
///
/// They are the two fields that are DURABLE, measured rather than
/// assumed. Resolution is partly self-correcting - `smart::measured_res`
/// reads the container and replaces a differing claim, and it is the
/// project's single answer for that field, so taking it here would be a
/// second answer to a question that already has one. A year is filled
/// by `Index::movie_year` only when there is none, so a WRONG one is
/// never corrected by anything. A title is re-derived from disk by
/// nothing at all.
///
/// # Why it CORRECTS rather than refuses
///
/// Refusing the rename outright was the obvious shape and is wrong in
/// the ordinary case: nearly every honest movie post ships a recovery
/// set declaring its payload, so "the declared name wins" flat would
/// mean the metadata renamer never strips a group tag again. Decoration
/// is not a contradiction. Correcting the two fields leaves the renamer
/// doing exactly what the user switched it on for, on the right film.
///
/// # The direction that is refused
///
/// Nothing is ever CLEARED. A proved parse with no year leaves the
/// claimed year standing, and an empty proved title is not a title.
/// Callers owe the other half of the losing-direction rule - a proved
/// stem that is DARK is not evidence of anything, so ask
/// [`stem_is_a_name`] before parsing it.
pub fn adopt_proved_identity(claimed: &mut Parsed, proved: &Parsed) -> bool {
    let mut moved = false;
    if !proved.title.is_empty() && norm_title(&proved.title) != norm_title(&claimed.title) {
        claimed.title.clone_from(&proved.title);
        moved = true;
    }
    if let Some(y) = proved.year
        && claimed.year != Some(y)
    {
        claimed.year = Some(y);
        moved = true;
    }
    moved
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
            | "cbr"
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
///
/// A DATE is the opposite of a year here and IS carried. A dated title
/// is a periodical, and the date is the whole of what tells two issues
/// apart: without it "The New York Times - 15 August 2026" and the
/// 16th's edition key identically and one card swallows the year's
/// worth of papers. A MONTHLY carries the six-digit month precision for
/// the same reason and at the only precision it has ("bk:slam:201609"),
/// which is how Slam September 2016 stopped keying onto Slam September
/// 2017. The two widths cannot collide: a day is eight digits.
///
/// An album never reaches here with a date. `scene_media` sets
/// `date: None` at the site, saying so, and `month_issue` is armed on a
/// BOOK format marker, which a music stem does not carry - so the
/// deliberate decision to keep an album's edition year out of its key
/// is untouched by either periodical reading.
fn media_key(kind: &Kind, title: &str, date: Option<&str>) -> String {
    let prefix = if matches!(kind, Kind::Book) {
        "bk"
    } else {
        "mu"
    };
    match date {
        Some(d) => format!("{prefix}:{}:{d}", norm_title(title)),
        None => format!("{prefix}:{}", norm_title(title)),
    }
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
    // `p.daily`, not `p.date.is_some()`: an AIR date is video evidence,
    // a masthead PUBLICATION date is a book's identity. See `Parsed::daily`.
    if !no_video_evidence(&p.res, &p.vcodec, &p.source, p.remux, p.season, p.daily)
        || p.episode.is_some()
    {
        return;
    }
    let from_stem = parse_release(stem);
    if !matches!(from_stem.kind, Kind::Book | Kind::Music) {
        return;
    }
    p.kind = from_stem.kind.clone();
    p.key = media_key(&p.kind, &p.title, p.date.as_deref());
}

/// The media lane a NEWSGROUP vouches for, or None when it says nothing.
///
/// Anything with "book" in it is a book group - `alt.binaries.e-book`,
/// `.ebook`, `.audiobooks`, `.mp3.abooks` - and is asked first so
/// `.mp3.audiobooks` (both words) is books; the German audiobook groups
/// say "hoerbuecher". Then the music families. Named by substring on
/// purpose: the interest presets in the daemon list the groups, and a
/// second copy of that list here would drift.
pub fn group_media_kind(grp: &str) -> Option<Kind> {
    let g = grp.to_ascii_lowercase();
    if g.contains("book") || g.contains("hoerbu") {
        return Some(Kind::Book);
    }
    if ["sounds", "music", "mp3", "flac", "lossless"]
        .iter()
        .any(|w| g.contains(w))
    {
        return Some(Kind::Music);
    }
    None
}

/// Does the stem end in a plain file extension: a final dot-token of
/// two to four alphanumerics carrying at least one letter, with no
/// space in it ("jpg", "m3u", "ene", "mkv")? A trailing "(320)" or
/// " 13 (1994)" is not one.
fn has_plain_extension(stem: &str) -> bool {
    let Some(ext) = stem.rsplit('.').next() else {
        return false;
    };
    ext != stem
        && (2..=4).contains(&ext.len())
        && ext.chars().all(|c| c.is_ascii_alphanumeric())
        && ext.chars().any(|c| c.is_ascii_alphabetic())
}

/// "8.1.6", "13.0.6.5": three or more dot-joined numbers somewhere in
/// the text.
fn has_dotted_version(text: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .any(|w| {
            let parts: Vec<&str> = w.split('.').collect();
            parts.len() >= 3
                && parts
                    .iter()
                    .all(|q| !q.is_empty() && q.chars().all(|c| c.is_ascii_digit()))
        })
}

/// The stem `recover_kind_from_group` should reason over: the raw one,
/// or - for a parse that only exists because `rot13_rescue` decoded it -
/// the decoded stem with its rotated volume tail cut. Answers the raw
/// stem for anything else, a reversed rescue included: rotating a
/// reversed name yields nothing `release_stem` will cut, so the probe
/// falls through by construction rather than by a special case.
fn rot13_plain_stem(stem: &str, p: &Parsed) -> String {
    if !p.rescued {
        return stem.to_string();
    }
    volume_tail_cut(&rot13(stem)).unwrap_or_else(|| stem.to_string())
}

/// Put back the lane the GROUP proves, when the name proves nothing.
///
/// A post named "Perry Rhodan 3390 - Die Stunde der Deponentin
/// (Ungekuerzt)" - 13 files, 231 MB, in alt.binaries.mp3.audiobooks -
/// carries no format marker and no video evidence, so it falls through
/// `None => Kind::Movie`, the junk scorer sees an evidence-free movie
/// (60) and a wall whose default hides >= 50 never shows it. Measured
/// 2 Sep 2026 on a fresh scratch index of the `books` preset: 0.0% of
/// alt.binaries.audiobooks and alt.binaries.mp3.audiobooks rows sat on
/// the Books lane, though 64% and 49% of them read as names.
///
/// The group is evidence. A name in a book group is a book, and a name
/// in a music group is an album, unless the name itself says video
/// (S01E01, 1080p, BluRay...) or software, or the parser gave up on it
/// (`Kind::Other` - an obfuscated stem must not become a "book" with a
/// hash for a title). Only the lane and the key move; the title stays.
pub fn recover_kind_from_group(p: &mut Parsed, grp: &str, stem: &str) {
    if p.kind != Kind::Movie {
        return;
    }
    // A file with an extension the markers did not claim is furniture
    // or something else entirely: cover art ("00-kmfdm-enemy-web-2026.
    // jpg"), a playlist ("Hype.m3u"), an .nzb, a rot13 volume
    // (".cneg6.ene"). Measured on the first cut of this rule: 193 such
    // rows in one lap of alt.binaries.sounds.mp3 became visible "music"
    // cards. Content that IS a book or a track already carries its
    // marker and never reaches here; a folder or a set has no extension.
    // ...and when the parse was RESCUED out of a rotation, both tests
    // below have to be asked of the decode. ".ene" is ".rar" - a
    // volume suffix, not the ".jpg" this guard exists to keep off the
    // Music lane - and it would otherwise stand every rescued album
    // and magazine down on the strength of its own obfuscation.
    let stem = &rot13_plain_stem(stem, p);
    if has_plain_extension(stem) {
        return;
    }
    // A dotted version number is software that forgot to say so
    // ("Topaz Video AI Pro 8.1.6"), not an album. Asked of the STEM:
    // the tokenizer split those dots and the title reads "8 1 6".
    if has_dotted_version(stem) {
        return;
    }
    // `p.daily`, not `p.date.is_some()`. This is the interaction that
    // makes the whole publication-date reading safe: a date that is an
    // AIR date is video evidence and must stand a name down off the
    // Books lane, but a masthead date is the identity of the issue, and
    // asking `date.is_some()` here sent every dated magazine back to an
    // evidence-free movie at junk 60 - the exact state the group prior
    // exists to end. See `Parsed::daily`.
    if !no_video_evidence(&p.res, &p.vcodec, &p.source, p.remux, p.season, p.daily)
        || p.episode.is_some()
    {
        return;
    }
    // A title with no word in it ("7 23", "12895-1 11") is a numbered
    // scan or a version, not something to put on a card.
    if !title_has_word(&p.title) {
        return;
    }
    let Some(kind) = group_media_kind(grp) else {
        return;
    };
    p.kind = kind;
    p.key = media_key(&p.kind, &p.title, p.date.as_deref());
}

/// Does this title carry a real word - three or more letters, all
/// letters - rather than being numbers and punctuation ("7 23",
/// "12895-1 11")? Both group-aware passes ask it, and they must agree:
/// a title with nothing to read is not a card on any lane.
fn title_has_word(title: &str) -> bool {
    title
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| w.len() >= 3 && w.chars().all(|c| c.is_ascii_alphabetic()))
}

/// Does this NEWSGROUP vouch for video, positively?
///
/// Deliberately NOT "`group_media_kind` said nothing": None there is the
/// answer for every group on Usenet that is not a book or music group,
/// `alt.binaries.boneless` and `alt.binaries.sounds.mp3.complete_cd`'s
/// neighbours included, and an episode read on the strength of an
/// absence would fire everywhere. This asks for a positive word, and
/// stands down outright when the group says book or music, so the two
/// answers can never both be yes and the books/music lane rescue keeps
/// every row it has today.
///
/// Matched on dot-separated TOKENS, not substrings: "tv" as a substring
/// is inside too many ordinary words to be evidence of anything.
/// Measured on `alt.binaries.multimedia.anime.highspeed` (2 Sep 2026),
/// which is why the token and not a leading component: that group says
/// "anime" in fourth position and nothing in first. The TV tokens carry
/// the same convention and no corpus of this lane's own - they are here
/// because a fenced `Show - NNN - Title` in a television group is an
/// episode by the same reading, not because a scan proved it.
pub fn group_vouches_video(grp: &str) -> bool {
    if group_media_kind(grp).is_some() {
        return false;
    }
    const VIDEO: [&str; 7] = [
        "anime", "tv", "tvseries", "teevee", "hdtv", "cartoon", "cartoons",
    ];
    grp.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|t| VIDEO.contains(&t))
}

/// Read the episode out of `Show - NNN - Episode Title` when the GROUP
/// is what vouches for the reading.
///
/// "Bleach - 187 - Ichigo Rages! The Assassin's Secret.mkv" is episode
/// 187 of Bleach to any reader, and was an evidence-free MOVIE titled
/// with the whole line: junk 60, hidden by the wall's default, and one
/// card per episode. Measured 2 Sep 2026 on a scratch index of the anime
/// preset: all 176 hidden un-bracketed rows on
/// alt.binaries.multimedia.anime.highspeed were one poster's dump in
/// that shape (memo section 7). It is the absolute numbering
/// `fansub_episode` already reads, minus the bracket that gates it.
///
/// The gate is the newsgroup, and it has to be, because the shape is
/// not the parser's to read alone: "Artist - 01 - Track Title" and
/// "Author - 04 - Chapter Name" are identical to it. Reading an episode
/// there would file a track as television AND silently disarm
/// `recover_kind_from_group`, which returns early on
/// `p.episode.is_some()` and is the whole of the books/music rescue -
/// so this runs AFTER that function, and `group_vouches_video` refuses
/// every group it answers for.
///
/// SEASON 1, for the reasons written at the fansub site in `parse_one`:
/// the wall's per-season episode grid, the SxxEyy card suffix and
/// `watchlist::slot_of` all go quiet on a season-less episode.
///
/// Only evidence-free Movies are touched, which is exactly the set that
/// is hidden today: a row that already parsed a resolution, a source, a
/// season or a year classified on its own evidence and is not ours to
/// overrule. `fed` is the name `p` was parsed from - the re-parse has to
/// read the same text, or the title it hands back names a different
/// thing.
pub fn recover_episode_from_group(p: &mut Parsed, grp: &str, fed: &str) {
    if p.kind != Kind::Movie || p.rescued || p.year.is_some() {
        return;
    }
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
    if !group_vouches_video(grp) {
        return;
    }
    let hinted = parse_one(fed, true);
    // Adopted only when the re-parse actually read the shape. Nothing
    // else about the hinted parse is allowed to matter: it differs from
    // `p` in the episode read and in nothing else, and taking the whole
    // struct would quietly overwrite a custom category's kind.
    if hinted.kind != Kind::Tv || hinted.episode.is_none() || !title_has_word(&hinted.title) {
        return;
    }
    p.kind = hinted.kind;
    p.title = hinted.title;
    p.season = hinted.season;
    p.episode = hinted.episode;
    p.key = hinted.key;
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

/// A ROTATED release-volume tail, and the stem left once it is cut off.
///
/// `.cneg581.ene` is `.part581.rar`, `.iby55+6.cne7` is `.vol00+1.par2`,
/// `.e64` is `.r51`. A poster who rotates a name rotates the whole
/// posted FILE name with it, tail included, so `release_stem` - which
/// runs before any of this on the ingest path - cannot see the suffix
/// and leaves it on the stem, where it both hides the evidence and
/// lands in the title ("... cneg7 ene").
///
/// Asked by running the product's OWN suffix grammar over the decode
/// rather than by listing rotated tails here: a second copy of that
/// grammar would drift from `release_stem` the first time a volume
/// shape was added there, and this crate has paid for exactly that
/// before (the `.vol-NN` cut and `nzb::kind()`).
fn volume_tail_cut(decoded: &str) -> Option<String> {
    let reduced = crate::names::release_stem(decoded);
    (reduced.len() < decoded.len()).then_some(reduced)
}

/// Try both rotation variants and keep the decode with the most scene
/// furniture. Acceptance bar: parses as one of the media kinds, reads
/// as English, and carries either 2+ furniture tokens (year/SxxEyy/
/// res/source/remux/a rotated volume tail) or 1 plus a common English
/// word - one lucky token alone proves nothing.
///
/// MUSIC AND BOOKS ARE ACCEPTED, AND THE ROTATED TAIL IS WHAT PAYS FOR
/// THEM (2 Sep 2026). Measured on a scratch index of the music and
/// books interest presets: `Trbetr Zvpunry - Flzcubavpn [Qryhkr
/// Rqvgvba] (7569)(875).cneg7.ene` in alt.binaries.sounds.mp3 is
/// George Michael's Symphonica and reached the wall as its own rotated
/// text at junk 60; `Zbovyvgl.Vaqvn.GehrCQS-Nhthfg.7560.cqs.iby55+6.
/// cne7` in alt.binaries.e-book.magazines is a TruePDF magazine and
/// counted as a "readable" row. Neither could ever qualify while the
/// bar was "Movie or Tv with scene signals": an album carries a year
/// at best and a magazine a date, so both sat at one signal with no
/// common word, and neither is a film in the first place.
///
/// THE ALTERNATIVE, REJECTED: damn a rotated name as obfuscated so it
/// stops reaching the wall at all. It is cheaper and it is wrong on
/// two counts. First, nothing tells a rotated name from a plain one
/// WITHOUT decoding it - a damn rule would have to key on this very
/// tail test, and having paid for the decode, throwing the name away
/// is strictly worse than keeping it. Second, `stem_obfuscated` means
/// "carries no semantic content", which a rotation does not: it is a
/// reversible transport encoding over a real name, and these four
/// stems decode to four real releases in the two groups the user
/// asked for. Hiding them would have answered "the wall shows
/// nonsense" with "the wall shows less".
fn rot13_rescue(stem: &str) -> Option<Parsed> {
    let letters = rot13(stem);
    let both = rot5_digits(&letters);
    let mut best: Option<(u32, Parsed)> = None;
    for decoded in [letters, both] {
        // Cut the rotated tail BEFORE parsing, not just to score it:
        // left on, ".cneg7.ene" tokenizes into the title and "iby55+6"
        // reads as furniture-shaped noise.
        let (decoded, tail) = match volume_tail_cut(&decoded) {
            Some(reduced) => (reduced, true),
            None => (decoded, false),
        };
        if looks_obfuscated(&decoded) {
            continue;
        }
        let p = parse_one(&decoded, false);
        if !matches!(p.kind, Kind::Movie | Kind::Tv | Kind::Music | Kind::Book) {
            continue;
        }
        let signals = [
            p.year.is_some(),
            // A dated post SPENDS its year token on the date, so a
            // counter that knows only about years loses the fact
            // entirely the moment the parser gets better at reading it -
            // the same trap `junk_score`'s evidence-free rule hit when
            // the masthead dates landed. Measured on a rot13'd magazine
            // ("Zbovyvgl.Vaqvn.GehrCQS-Nhthfg.7560.cqs.iby55+6.cne7" =
            // "Mobility.India.TruePDF-August.2015.pdf"): with the month
            // read, year went None, the count fell from two to one and
            // the rescue REFUSED a name it had been decoding correctly.
            p.date.is_some(),
            p.season.is_some(),
            p.episode.is_some(),
            p.res.is_some(),
            p.source.is_some(),
            p.remux,
            tail,
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
    let p = parse_one(&stem.chars().rev().collect::<String>(), false);
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
    let direct = parse_one(stem, false);
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

/// Single-case titles (ALLCAPS shouting or all-lowercase mumbling) fold
/// to title case; a mixed-case title is left exactly as the poster wrote
/// it. `multi` says the title region carried more than one token.
///
/// Lifted out of `parse_one` on 2 Sep 2026 for the size gate, at the one
/// seam in that function that is a pure string transform: it reads
/// nothing but the title and that one flag, which is why it could move
/// without carrying half the parse with it.
fn single_case_fold(title: String, multi: bool) -> String {
    if title.chars().filter(|c| c.is_ascii_alphabetic()).count() <= 3
        || (title.chars().any(|c| c.is_ascii_lowercase())
            && title.chars().any(|c| c.is_ascii_uppercase()))
    {
        return title;
    }
    // Words the plain fold mangles: roman numerals ("PLANET.EARTH.II"
    // became "Planet Earth Ii") and household acronyms ("THE.OFFICE.US"
    // became "The Office Us"). Only multi-word titles qualify - the
    // 2019 film "Us" must stay "Us", and there a lone "us"/"ii" token
    // IS the title, not a suffix. I, V and X are left out on purpose:
    // as single letters they are far more often initials than numerals.
    const KEEP_UPPER: [&str; 28] = [
        "ii", "iii", "iv", "vi", "vii", "viii", "ix", "xi", "xii", "xiii", "xiv", "xv", "us", "uk",
        "usa", "wwe", "nhl", "nba", "nfl", "ufc", "fbi", "cia", "swat", "nasa", "bbc", "cnn",
        "espn", "uefa",
    ];
    title
        .split(' ')
        .map(|w| {
            let lower = w.to_ascii_lowercase();
            if multi && KEEP_UPPER.contains(&lower.as_str()) {
                return lower.to_ascii_uppercase();
            }
            let mut cs = w.chars();
            match cs.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + &cs.as_str().to_ascii_lowercase(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `dashed_ep` turns on the un-bracketed `Show - NNN - Episode Title`
/// reading, and is only ever true for a re-parse asked for by
/// [`recover_episode_from_group`] - the shape needs a newsgroup behind
/// it before it means anything (see that function).
fn parse_one(stem: &str, dashed_ep: bool) -> Parsed {
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
        daily: false,
        key: format!("o:{}", norm_title(title)),
    };
    if looks_obfuscated(stem) {
        return other(stem);
    }

    // Fansub convention: a leading bracketed WORD is the group that
    // subtitled the release, not the first word of the title. See
    // `fansub_tag`. Its presence is what gates every anime convention
    // below - outside it a trailing bare number is a part counter or a
    // sequel, and reading one as an episode would move films.
    let fansub = fansub_tag(stem);
    // Bracket runs are the same convention's field separator
    // ("[1080P][BDRip][HEVC-10bit][FLAC]"). The tokenizer splits on
    // dot/underscore/space only, so that run arrives as ONE token and
    // not a single quality fact in it is ever read. Flattened only on
    // the fansub path: a bracket elsewhere is furniture the existing
    // `trim_matches` already handles, and widening the separator set
    // for every stem the index parses is a far bigger change than this.
    let flat: String;
    let src: &str = match fansub {
        Some((_, body)) => {
            flat = body.replace(['[', ']'], ".");
            &flat
        }
        None => stem,
    };

    // Release group: text after the LAST hyphen, if it looks like a tag.
    let (body, group) = split_group(src);
    let group = group
        .map(str::to_string)
        .or_else(|| fansub.map(|(t, _)| t.to_string()));

    // Tokenize on dot/underscore/space; hyphens survive inside tokens
    // ("Spider-Man", "WEB-DL"). Exception: stems with NO other separator
    // and several hyphens are hyphen-separated ("the-flash-s01e01-720p").
    let all_hyphen = !body.contains(['.', '_', ' ']) && body.matches('-').count() >= 3;
    let seps: &[char] = if all_hyphen { &['-'] } else { &['.', '_', ' '] };
    // A closing bracket abutting an opening one is a separator. Music
    // posts write the year and the bitrate that way and nothing else
    // between them - "Symphonica [Deluxe Edition] (2014)(320)" - and
    // the per-token `trim_matches` below only strips the OUTER pair, so
    // the whole thing stayed one token "2014)(320": no year parsed, and
    // the punctuation carried into the title. Measured 2 Sep 2026; the
    // shape also gates the ROT13 rescue of that album, which needs the
    // year as its second signal.
    let spaced;
    let body: &str = if body.contains(")(") {
        spaced = body.replace(")(", &format!("){}(", seps[0]));
        &spaced
    } else {
        body
    };
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
    //
    // Unless the post's own extension says book or audio: "Joseph
    // Hansen - Dave Brandstetter 04 The Man Everybody Was Afraid Of
    // (v5.0).epub" is an ebook whose edition number reads as a version
    // token, and as Software it scored junk 95 and never reached the
    // Books wall (scratch index, 2 Sep 2026). The trailing format
    // marker is the stronger evidence, so it wins.
    let ends_in_media = toks.len() > 1
        && toks.last().is_some_and(|t| {
            let lt = t.to_ascii_lowercase();
            book_marker(&lt) || audio_marker(&lt)
        });
    if let Some(cut) = software_marker(&toks).filter(|_| !ends_in_media) {
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
            daily: false,
            group,
        };
    }

    // Scene music: hyphen-separated fields the normal tokenizer would
    // glue together. Checked before tokenizing because the whole point
    // is that this shape needs a different split.
    if let Some((kind, credit, work, year)) = scene_media(body) {
        let title = format!("{credit} - {work}");
        return Parsed {
            key: media_key(&kind, &title, None),
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
            daily: false,
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
    // An AIR date only, never a masthead one - the flag is video
    // evidence and is stored as `Parsed::daily`, which says why.
    let mut daily = false;
    let mut date: Option<String> = None;
    // Index of the first token AFTER the date, so the identity tail can
    // start there (the same trick the movie-year arm uses).
    let mut date_end: Option<usize> = None;
    // True when `date` came from a masthead PUBLICATION date rather than
    // a daily-TV air date. Only used to trim the separator the date hung
    // off ("The New York Times - " keeps a dangling hyphen otherwise).
    let mut pub_dated = false;
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
        } else if i > 0 && is_tag(t) {
            // Never at index 0: a tag there would leave NO title, and a
            // stem with no title is filed `Other` with junk 100 - which
            // is what happened to every "Max <Author> - <Book>.epub" in
            // alt.binaries.e-book, because "max" is the HBO Max source
            // tag (measured 2 Sep 2026 on a scratch index: "Max Allan
            // Collins & Jeff Gelb (ed) - [Flesh and Blood 03] - Guilty
            // as Sin (epub).epub" scored 100). A leading token is the
            // title's first word whatever else it spells.
            boundary = boundary.min(i);
        } else if i > 0
            && let Some(d) = date_at(&toks, i)
        {
            // Every date convention the parser knows, air and masthead
            // alike - `date_at` is the one place that decides which.
            // `boundary` closes the title region at the date whichever
            // it is: the year token a date spends must not also be read
            // as a movie year below.
            daily |= d.air;
            if date.is_none()
                && let Some(v) = d.date
            {
                date = Some(v);
                date_end = Some(d.end);
                pub_dated = !d.air;
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

    // A MONTHLY periodical's issue date, read HERE and not in the token
    // loop, and gated on the Books lane `media` has just settled - both
    // reasons are written at `month_issue`. The month closes the title
    // region, which is also what SPENDS the year token, exactly as a
    // masthead day does.
    if date.is_none()
        && matches!(&media, Some((Kind::Book, _)))
        && let Some((d, i, end)) = month_issue(&toks, boundary)
    {
        date = Some(d);
        date_end = Some(end);
        pub_dated = true;
        boundary = i;
    }

    // Anime episode numbering. Absolute-numbered fansub posts carry no
    // SxxEyy at all, so without this every one of them was an
    // evidence-free Movie: junk 60 and hidden by the wall's default
    // (measured 2 Sep 2026 - see `fansub_tag`).
    //
    // SEASON 1, deliberately, and not None. Absolute numbering has no
    // season, and recording none would be the honest answer to that
    // question alone - but three readers need one and all three go
    // quiet without it. The wall's per-season episode grid skips every
    // row with `r.season==null` (web/wall.html), so a season-less show
    // page lists releases and offers not one episode chip; the card's
    // "SxxEyy" suffix needs both halves; and `watchlist::slot_of`
    // answers None for (None, Some(ep)), which makes the release
    // ungrabbable - a watched show that nobody ever posted. Series 1 is
    // also what the posters themselves mean: a fansub set that IS on a
    // later season puts it in the title ("... S2 - 05"), which parses
    // as a season the ordinary way and never reaches here.
    //
    // The un-bracketed `Show - NNN - Episode Title` variant is the same
    // absolute numbering with no group tag to vouch for it, so its
    // newsgroup does instead and `dashed_ep` is how that answer arrives
    // (see `recover_episode_from_group`). Measured 2 Sep 2026 on the
    // same scratch index: all 176 hidden un-bracketed rows on
    // alt.binaries.multimedia.anime.highspeed were one poster's Bleach
    // dump in exactly that shape, evidence-free movies at junk 60 with
    // one card each.
    let mut dashed_hit = false;
    if fansub.is_some() && episode.is_none() {
        if season.is_none() {
            if let Some((cut, ep)) = fansub_episode(&toks, boundary) {
                season = Some(1);
                episode = Some(ep);
                boundary = cut;
            }
        } else if let Some(ep) = fansub_episode_after(&toks, boundary) {
            episode = Some(ep);
        }
    } else if dashed_ep
        && episode.is_none()
        && season.is_none()
        && let Some((cut, ep)) = dashed_episode(&toks, boundary)
    {
        season = Some(1);
        episode = Some(ep);
        boundary = cut;
        dashed_hit = true;
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
    let mut cut = year_idx.unwrap_or(boundary).min(boundary);
    let year: Option<u32> = year_idx.and_then(|i| toks[i].parse().ok());
    // The hyphen the episode number hung off is left dangling by every
    // fansub shape that cuts at it ("Attack on Titan - S04E28" titled
    // "Attack on Titan -"), by the dashed episode read, and by every
    // masthead date ("The New York Times - 15 August 2026"). Only on
    // those three paths: elsewhere a token of pure punctuation at the
    // end of a title region is rare enough that trimming it would be a
    // change to every stem the index parses for no measured gain.
    // `cut == boundary` holds the publication-date arm to the case
    // where the date IS what closed the title region - a year earlier
    // in the name cut it first, and then the punctuation is not the
    // date's separator.
    while (fansub.is_some() || dashed_hit || (pub_dated && cut == boundary))
        && cut > 0
        && !toks[cut - 1].chars().any(|c| c.is_ascii_alphanumeric())
    {
        cut -= 1;
    }

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
    // A fansub stem whose title region carries no LETTER is a number
    // and nothing else ("[SubsPlease] 09 (1080p).mkv"): stripping the
    // group tag took the only word off it, so there is no name here.
    // Falling to `other` is what keeps that dark - a bare "09" title
    // with a resolution beside it clears junk_score's evidence-free
    // rule and would put a card called "09" on the wall.
    if title_toks.is_empty()
        || (fansub.is_some()
            && !title_toks
                .iter()
                .any(|t| t.chars().any(|c| c.is_ascii_alphabetic())))
    {
        return other(stem);
    }
    let title = single_case_fold(title_toks.join(" "), title_toks.len() > 1);

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
        //
        // Bounded by the media marker, because a dated BOOK's marker
        // sits after the date and `token_role` has never heard of it:
        // "The New York Times - 15 August 2026.pdf" reduced to an
        // `extra` of ["pdf"], which is `movie_name` declining to offer
        // a name for every issue of every paper. The marker is the end
        // of the identity, not part of it - the same thing `boundary`
        // already says about the title region.
        let stop = media.as_ref().map_or(toks.len(), |(_, i)| *i).max(end);
        identity_tail(toks[end..stop].iter().copied())
            .into_iter()
            .map(str::to_string)
            .collect()
    } else {
        Vec::new()
    };
    let key = match kind {
        Kind::Tv => format!("t:{}", norm_title(&title)),
        Kind::Music | Kind::Book => media_key(&kind, &title, date.as_deref()),
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
        daily,
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
///
/// The width check is load-bearing and not a formality: [`Parsed::date`]
/// also carries a six-digit MONTH precision for a monthly periodical
/// ("202609"), and that value must be DECLINED here rather than sliced
/// into a "2026.09" that reads as a day nobody wrote. Pinned by
/// `release_tests.rs::air_date_parts_declines_a_month_precision_date`.
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

/// What token `i` of a stem says about the release's DATE.
///
/// One place, four conventions, because the answer they feed is not
/// just "which date" but "which KIND of date" - and getting that second
/// half wrong is what put every dated magazine back on the movie lane.
/// See [`Parsed::daily`]. Lifted out of `parse_one`'s token loop when
/// the masthead forms landed and the function crossed its size ceiling;
/// the arms are in the same order the chain had them, which is the
/// order that decides ties.
///
/// The fifth convention, a MONTHLY issue's month+year, is deliberately
/// NOT an arm here: it is only safe on the Books lane, and the lane is
/// not known until the token loop has finished. [`month_issue`] reads it
/// after, and says why.
struct DateRead {
    /// The date, normalized to "yyyymmdd". None for the one shape that
    /// says TV without saying WHEN: an 8-digit run whose month or day
    /// does not validate. That width alone has always been enough for
    /// the `daily` flag, which only has to decide "TV, not a movie",
    /// while a date has to be right.
    date: Option<String>,
    /// Index of the first token AFTER the date, so the identity tail
    /// can start there (the same trick the movie-year arm uses).
    end: usize,
    /// An AIR date - a daily-TV convention - rather than a masthead
    /// PUBLICATION date.
    air: bool,
}

fn date_at(toks: &[&str], i: usize) -> Option<DateRead> {
    let t = toks[i];
    let air = |date, end| {
        Some(DateRead {
            date,
            end,
            air: true,
        })
    };
    // A 2-digit month or day in range.
    let d2 = |s: &str, max: u32| {
        s.len() == 2
            && s.bytes().all(|c| c.is_ascii_digit())
            && s.parse::<u32>().is_ok_and(|v| (1..=max).contains(&v))
    };
    // A datecode ("At.Midnight.150615.720p"). The normalized "yyyymmdd"
    // it reads as, or None when it is not a date. Six digits are held to
    // a much harder bar than eight: that width is also how ids, sizes
    // and part counts look, and YYMMDD has only one sane reading (20YY,
    // near enough to now to be a real air date). Anything short of that
    // is left alone as an ordinary word rather than guessed at.
    // "150615" and "20150615" normalize the same, so the two
    // conventions compare equal.
    if (t.len() == 6 || t.len() == 8) && t.chars().all(|c| c.is_ascii_digit()) {
        let (y, md) = t.split_at(t.len() - 4);
        let (mth, day) = md.split_at(2);
        let ok = d2(mth, 12) && d2(day, 31);
        if ok && y.len() == 4 {
            return air(Some(format!("{y}{mth}{day}")), i + 1);
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
        let read = (ok && !competing && y.parse::<u32>().is_ok_and(|v| v <= 39))
            .then(|| format!("20{y}{mth}{day}"));
        // Eight digits still say TV even when they do not say when.
        return (read.is_some() || t.len() == 8).then(|| DateRead {
            date: read,
            end: i + 1,
            air: true,
        });
    }
    // Dotted daily date ("The.Daily.Show.2026.07.21…") - the year token
    // alone otherwise reads as a movie year and the episode identity
    // (the date) is lost.
    if is_year(t)
        && toks.get(i + 1).is_some_and(|m| d2(m, 12))
        && toks.get(i + 2).is_some_and(|d| d2(d, 31))
    {
        return air(Some(format!("{t}{}{}", toks[i + 1], toks[i + 2])), i + 3);
    }
    // A masthead PUBLICATION date: "The New York Times - 15 August
    // 2026", "Der Spiegel - 2026-08-15". Before these two arms the year
    // token was read as a movie/edition year, the day was left stranded
    // in the title ("The New York Times - 15 August") and every issue of
    // one paper keyed onto ONE card.
    let (date, end) = spelled_date(toks, i).or_else(|| iso_date(t).map(|d| (d, i + 1)))?;
    Some(DateRead {
        date: Some(date),
        end,
        air: false,
    })
}

/// The month a spelled-out month name names, 1..=12, or None. Full
/// names and the three-letter abbreviations both (plus "sept", which is
/// four): a masthead writes its date either way, and a magazine post
/// copies the masthead. A trailing comma is part of the American order
/// ("August 15, 2026") and is trimmed here rather than at each caller.
fn month_of(tok: &str) -> Option<u32> {
    const MONTHS: [&str; 12] = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ];
    let lt = tok.to_ascii_lowercase();
    let lt = lt.trim_end_matches(',');
    if lt == "sept" {
        return Some(9);
    }
    if lt.len() < 3 {
        return None;
    }
    MONTHS
        .iter()
        .position(|m| *m == lt || (lt.len() == 3 && m.starts_with(lt)))
        .map(|i| i as u32 + 1)
}

/// The day-of-month a token spells, 1..=31, or None. Accepts the
/// ordinal and punctuation a masthead date carries ("15", "15,",
/// "15th") and nothing wider: two digits is also how a track number, a
/// disc number and a channel count look, so anything that is not a bare
/// short run of digits is left alone as the word it is.
fn day_of(tok: &str) -> Option<u32> {
    let t = tok.trim_end_matches(',');
    let t = ["st", "nd", "rd", "th"]
        .iter()
        .find_map(|suf| t.strip_suffix(suf))
        .unwrap_or(t);
    (t.len() == 1 || t.len() == 2)
        .then(|| t.parse::<u32>().ok())
        .flatten()
        .filter(|d| (1..=31).contains(d))
}

/// A PUBLICATION date spelled with a month NAME, read at `i` and
/// normalized to "yyyymmdd" with the index of the first token after it.
///
/// Both orders a paper prints: "15 August 2026" (day first) and
/// "August 15, 2026" (month first). Deliberately not the numeric forms -
/// those are already read as air dates by the datecode and dotted arms,
/// and a spelled month is the one shape that cannot also be a track
/// number, a size or an id. The date is validated against the real
/// calendar (`days_in_month`), so "31 February 2026" stays three
/// ordinary words.
fn spelled_date(toks: &[&str], i: usize) -> Option<(String, usize)> {
    let (m, d) = match (month_of(toks.get(i + 1)?), month_of(toks[i])) {
        // "15 August 2026"
        (Some(m), _) => (m, day_of(toks[i])?),
        // "August 15, 2026"
        (None, Some(m)) => (m, day_of(toks.get(i + 1)?)?),
        _ => return None,
    };
    let y: u32 = toks.get(i + 2).filter(|t| is_year(t))?.parse().ok()?;
    (d <= days_in_month(y, m)).then(|| (format!("{y}{m:02}{d:02}"), i + 3))
}

/// A PUBLICATION date written ISO and hyphenated, "2026-08-15", as
/// "yyyymmdd". One token, because the tokenizer splits on `.`/`_`/` `
/// and never on a hyphen - which is why this form used to land whole in
/// the title ("Der Spiegel - 2026-08-15") with no year and no date read
/// off it at all.
fn iso_date(tok: &str) -> Option<String> {
    let b = tok.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, m, d) = (&tok[..4], &tok[5..7], &tok[8..10]);
    if !is_year(y) || !m.bytes().chain(d.bytes()).all(|c| c.is_ascii_digit()) {
        return None;
    }
    let (yn, mn, dn) = (y.parse().ok()?, m.parse().ok()?, d.parse::<u32>().ok()?);
    (dn >= 1 && (1..=12).contains(&mn) && dn <= days_in_month(yn, mn)).then(|| format!("{y}{m}{d}"))
}

/// A MONTHLY issue's publication date - "Slam.TruePDF-September.2016",
/// "New Scientist - September 2016", "The.Chap.TruePDF-June.July.2016" -
/// as "yyyymm" (the month precision [`Parsed::date`] documents), the
/// index of the month token, and the index of the first token after the
/// year.
///
/// The fifth date convention, and the one that is NOT an arm of
/// [`date_at`]: a monthly is safe to read only on the Books lane, and
/// the lane is not known inside `parse_one`'s token loop, because
/// `media_marker` is only honoured once the loop has finished counting
/// video evidence - so this runs after it, where that answer is already
/// in hand.
///
/// Without it a monthly had no issue identity at all: the month sat in
/// the TITLE ("Slam TruePDF-September") and `media_key` drops the year
/// on purpose, so Slam September 2016 and Slam September 2017 keyed
/// identically and one card swallowed every year's September. Measured
/// 2 Sep 2026 on `alt.binaries.e-book.magazines`; pinned with its
/// before-state in `release_tests.rs::a_monthly_issue_is_a_month_and_a_year`.
///
/// Two things the caller relies on. The month index it returns becomes
/// the title `boundary`, and `year_idx` searches `toks[..boundary]`, so
/// the year token lands in the DATE and not in `year` as well - one
/// fact, one field. Two would let a single date count as two
/// independent signals in `looks_like_release_name` and would put a
/// "2016" badge on an issue that is not a 2016 edition of anything.
/// And nothing here sets `Parsed::daily`: a masthead date is a
/// publication date, never video evidence, which is what keeps
/// `recover_kind_from_group` armed over these names.
fn month_issue(toks: &[&str], boundary: usize) -> Option<(String, usize, usize)> {
    for i in 1..boundary.min(toks.len()) {
        let Some(m) = fenced_month(toks, i) else {
            continue;
        };
        // A DOUBLE issue names both months before the year ("The Chap
        // TruePDF-June July 2016"). It is one issue, so the first month
        // is its identity and the second is skipped rather than read:
        // a June/July double and a plain June issue of the same year
        // cannot both exist, and keying on June makes a repost of the
        // double land on the card it landed on last time.
        let second = usize::from(toks.get(i + 1).and_then(|t| month_of(t)).is_some());
        let yi = i + 1 + second;
        let Some(y) = toks.get(yi).filter(|t| is_year(t)) else {
            continue;
        };
        return Some((format!("{y}{m:02}"), i, yi + 1));
    }
    None
}

/// The month token `i` names when a SEPARATOR fences it off the
/// publication's name, or None.
///
/// The fence is the whole of what makes this safe, and it is the same
/// reasoning `dashed_episode` is built on: the shape alone is not
/// enough, because "Sweet November 2001" and "Author - One Day in
/// September 2016.epub" are a month before a year to the letter and
/// reading either as an issue would eat the words in front of the
/// month. A masthead does not write those - it writes the publication,
/// a separator, then the issue - so a month with an ordinary WORD in
/// front of it is not one.
fn fenced_month(toks: &[&str], i: usize) -> Option<u32> {
    let t = toks[i];
    if t.contains('-') {
        // The hyphen a format token leaves in front of the month
        // ("TruePDF-September"), which the tokenizer never splits on.
        // Something has to sit ahead of that hyphen, or the token is
        // the title's own first word.
        let parts: Vec<&str> = t.split('-').collect();
        if !parts[1..].iter().any(|q| month_of(q).is_some()) {
            return None;
        }
        // First month named wins, so a "September-October" double keys
        // on September exactly as the two-token form does.
        return parts.iter().find_map(|q| month_of(q));
    }
    // A whole-token month needs a token of pure punctuation to fence it
    // ("New Scientist - September 2016").
    month_of(t).filter(|_| !toks[i - 1].chars().any(|c| c.is_ascii_alphanumeric()))
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
