//! The album fold: one poster's per-TRACK music and audiobook posts,
//! merged into the one release they were posted as.
//!
//! `alt.binaries.sounds.mp3` posts an album as one article set PER
//! TRACK - `02-elsa_hewitt-out-reaching_hands.mp3`,
//! `25-steve_luck-small_song_of_hope.mp3` - so every track becomes its
//! own complete single-file release, its own wall card, and the album
//! itself exists only as the furniture the same session carries
//! (`00-artist-album-freeweb-2020.jpg`, `.nfo`, `.m3u`, `.sfv`).
//! Measured 2 Sep 2026 on a fresh scratch index of the `music` preset
//! (research/INTEREST-PRESETS-BOOKS-MUSIC-ANIME-2026-09-02.md section
//! 4): 1,939 "titles" on the Music tab, of which the first two rows of
//! cards were fourteen tracks of one album. `alt.binaries.audiobooks`
//! is the same shape with a different suffix - `Clive Cussler, Paul
//! Kemprecos - (NUMA Files 8) Medusa - D094.mp3`,
//! `Stephen R. Donaldson-The Runes of the Earth-Unabridged-CD15-07.mp3`.
//!
//! The shape NOT to disturb is the album-per-post one: a scene-named
//! album (`Paul_McCartney_And_Wings-Red_Rose_Speedway-2LP-Special_
//! Edition-32BIT-WAVPACK-1973-REETKEVER`, 114 files) is already ONE
//! row with the right name, and it never enters this fold's population
//! because that population is single-FILE rows.
//!
//! `sessionfold.rs` folds lone files into a session release for
//! OBFUSCATED sets keyed on (poster, group, time window); this is the
//! NAMED variant, and it takes that module's walk verbatim (posting
//! time, overlapping windows, a settle margin) for that module's
//! reasons. What differs is the key and the identity.
//!
//! # Which name is load-bearing
//!
//! Three names are in play and they do different jobs. Measured on the
//! 2 Sep scratch index, a scene mp3 post looks like this, and one
//! handle posts album after album for the better part of an hour:
//!
//! ```text
//!   00-kate_carr-subtropical_to_temperate_oceanic-freeweb-2014.jpg/.m3u/.nfo/.sfv
//!   01-kate_carr-subtropical_i.mp3   ...   06-kate_carr-temperate_oceanic_iii.mp3
//!   Kate_Carr-Subtropical_to_Temperate_Oceanic-FREEWEB-2014-MFW      <- par2 set
//!   00-kate_carr-transect...-freeweb-2026.jpg                        <- next album
//! ```
//!
//! * **The `00-` FURNITURE stem is what separates one album from the
//!   next, and nothing else can do that job.** A poster window is not
//!   one session, it is a queue of albums; each distinct furniture name
//!   opens one and owns the tracks up to the next name. The tracks
//!   cannot separate themselves (a `freeweb` compilation names a
//!   different artist in every track), and the par2 set lands at the
//!   END of its own burst, so cutting on anchors alone would bracket
//!   each album by the previous album's tail. This is the half the
//!   fold cannot work without.
//! * **The par2 ANCHOR is what the album is CALLED.** It is the one row
//!   already wearing the whole scene release name - the furniture name
//!   plus the group tag - and on a fresh index it is already a junk-0,
//!   kind=music card. So the fold merges the tracks INTO it and
//!   rewrites no stem at all: the card that was always right simply
//!   gains its own bytes and its own files. It cannot separate albums
//!   (see above) and it is not always there.
//! * **The common PREFIX of the track stems is the fallback, and it is
//!   evidence of nothing on its own.** On scene music it is inert by
//!   construction, because those tracks share no prefix. It earns its
//!   place on AUDIOBOOKS, which carry no furniture at all and number
//!   their loose files in the tail (`... 04 of 14.mp3`, `... - D094.mp3`,
//!   `...-CD15-07.mp3`, `... - 155 - ... - 155.mp3`). Those posts have
//!   anchors too, and the prefix arm uses them the same way.
//!
//! Only when an album brought no par2 at all is the furniture name
//! WRITTEN as the stem, and that is the weaker outcome: it loses the
//! release group tag, which is part of what predb joins on.
//!
//! Where the cut cannot be made, nothing is folded. Two albums whose
//! furniture is interleaved in time, a repeated track number (a second
//! album that brought no furniture of its own), a repeated index under
//! one prefix - each refuses its candidate rather than guessing, because
//! a garbage union of two albums is worse than the track cards it would
//! replace and no later pass takes it back.
//!
//! # Stated limits
//!
//! * **`complete` means what it has always meant, which is less than a
//!   reader may hope.** `RelAgg::complete` is "every file we have SEEN
//!   has all its parts" (`nfiles >= 1 && ncomplete == nfiles`, the
//!   rule since 20 Jul), and it is recomputed here from the merged
//!   file rows rather than asserted. Every member was individually
//!   complete before the fold, so the folded row is complete too - but
//!   that is not a claim that the ALBUM is whole. Nothing in an OVER
//!   listing says how many tracks the album has (the `.m3u` and `.sfv`
//!   would, and we hold their headers, not their bytes), so a fold
//!   that saw eleven of twelve tracks reads complete and downloads
//!   eleven. That is the same trade `split_merge` and `session_fold`
//!   already make, and it is the reason this fold never writes a track
//!   COUNT it did not observe.
//! * **A single track posted alone stays its own row**, and so does
//!   any group of fewer than [`MIN_TRACKS`]: a music group with one
//!   track in it is a legitimate post, not a broken album.
//! * A track the scan backfills later, behind the parked cursor, is
//!   not folded into an album this pass already made - the same
//!   park-at-the-top trade every sibling fold documents. It stays a
//!   track card.
//! * **Members must be individually `complete`**, which on a
//!   shallow-scanned group excludes most of them: measured 2 Sep, 157
//!   of 244 `alt.binaries.audiobooks` track rows were still partial and
//!   so out of the population. That is deliberate - folding partial
//!   tracks would build an album that reads whole and is not - and it
//!   means this fold's yield rises as a group is deepened, rather than
//!   arriving all at once.

use super::*;

/// Fewer tracks than this is not an album, it is a post. The floor is
/// `sessionfold`'s, for the same reason: the screens' power comes from
/// repetition, and it is what keeps a lone track (or a two-track
/// single) a row of its own.
const MIN_TRACKS: usize = 4;

/// Widest posting span one album may cover, seconds. An album goes up
/// in minutes; an hour holds any of them with room, and a (poster,
/// grp) pair posting for longer than this is a standing handle rather
/// than one upload.
const MAX_SPAN: i64 = 3_600;

/// Ceiling on members one album may take. An "album" past this is a
/// dump, and a dump is skipped rather than half-read.
const MEMBER_CAP: usize = 500;

/// Ceiling on rows read per (poster, grp) window group. The measured
/// scene handle posts album after album under one address - 5,400 s of
/// one window on the 2 Sep scratch index - so this is a work bound,
/// not a shape test: past it the group is left for a later pass rather
/// than sorted in one hold of the index write mutex.
const GROUP_CAP: usize = 5_000;

/// Audio payload extensions. A row without one is not a track, and the
/// fold's population is tracks plus their furniture and nothing else.
const AUDIO_EXT: [&str; 11] = [
    ".mp3", ".flac", ".m4a", ".m4b", ".aac", ".ogg", ".opus", ".wav", ".ape", ".wv", ".wma",
];

/// Sidecar extensions an album post carries beside its tracks. `.nzb`
/// is deliberately NOT here: an NZB sidecar is a pointer to a release,
/// not a part of one.
const FURNITURE_EXT: [&str; 8] = [
    ".jpg", ".jpeg", ".png", ".nfo", ".m3u", ".sfv", ".cue", ".log",
];

/// One candidate row, as the window query reads it.
#[derive(Clone)]
struct AlbMember {
    id: i64,
    stem: String,
    first_posted: i64,
    first_seen: i64,
    has_par2: bool,
}

/// Strip a trailing plain extension from a stem, returning the body.
/// `None` when there is none - a track always has one, so a stem
/// without one is not this fold's business.
pub(super) fn strip_ext(stem: &str) -> Option<&str> {
    let dot = stem.rfind('.')?;
    (has_ext(stem, &AUDIO_EXT) || has_ext(stem, &FURNITURE_EXT)).then(|| &stem[..dot])
}

/// Stems keep the case the poster typed (`release_stem` cuts, it does
/// not lowercase), and SQLite's `LIKE` is ASCII case-insensitive - so
/// the Rust side must be too, or the SQL population and the Rust
/// screens would disagree about `.MP3`.
pub(super) fn has_ext(stem: &str, set: &[&str]) -> bool {
    stem.rfind('.').is_some_and(|d| {
        let ext = stem[d..].to_ascii_lowercase();
        set.contains(&ext.as_str())
    })
}

/// The leading `NN-` / `NNN-` disc-and-track field scene music opens
/// every filename with (`00-` for the sidecars, `101-` on disc two),
/// as (number, rest). Underscores are not accepted as the separator:
/// the convention hyphenates its fields, and `01_of_12` is a part
/// counter, not a track index.
pub(super) fn track_field(body: &str) -> Option<(u32, &str)> {
    let nd = body.bytes().take_while(u8::is_ascii_digit).count();
    if !(1..=3).contains(&nd) || body.as_bytes().get(nd) != Some(&b'-') {
        return None;
    }
    Some((body[..nd].parse().ok()?, &body[nd + 1..]))
}

/// The album name a furniture row carries: its stem with the extension
/// and the leading track field removed, which is exactly the scene
/// release directory (`00-gelugugu-masterpiece_cooking-freeweb-2020.
/// jpg` -> `gelugugu-masterpiece_cooking-freeweb-2020`).
///
/// The three-field floor is `scene_media`'s: fewer fields than that is
/// not the convention and would not parse as music on the far side
/// either, so folding to it would trade N track cards for one card
/// with a worse name.
pub(super) fn furniture_album(stem: &str) -> Option<String> {
    let body = strip_ext(stem)?;
    let (_, rest) = track_field(body)?;
    (rest.split('-').filter(|f| !f.is_empty()).count() >= 3 && rest.len() >= 8)
        .then(|| rest.to_string())
}

/// The audiobook arm's key: the stem with its extension and up to two
/// trailing numeric index tokens removed (`... medusa - d094` ->
/// `... medusa`, `...-unabridged-cd15-07` -> `...-unabridged`), with
/// the tail that was removed. `None` when nothing numeric trails,
/// which is the case for every scene music track (`02-elsa_hewitt-out-
/// reaching_hands`) and is why this arm cannot fire on them.
pub(super) fn track_prefix(stem: &str) -> Option<(String, String)> {
    let body = strip_ext(stem)?;
    let mut cut = of_counter(body).unwrap_or(body.len());
    let mut index: Option<u32> = None;
    // An explicit "NN of MM" counter is the whole tail; running the
    // token loop after it would eat the title's own last word.
    for _ in 0..if cut < body.len() { 0 } else { 2 } {
        let head = &body[..cut];
        // A tail token is separator, then up to two letters (`d`, `cd`,
        // `pt`), then one to four digits, and nothing else.
        let Some(sep) = head.rfind(['-', '_', ' ', '.']) else {
            break;
        };
        let tok = head[sep + 1..].trim();
        let nl = tok.bytes().take_while(u8::is_ascii_alphabetic).count();
        let digits = &tok[nl..];
        if nl > 2
            || digits.is_empty()
            || digits.len() > 4
            || !digits.bytes().all(|c| c.is_ascii_digit())
        {
            break;
        }
        index = index.or_else(|| digits.parse().ok());
        cut = sep;
    }
    if cut == body.len() {
        return None;
    }
    // The DOUBLED index, which is what the measured corpus's complete
    // rows wear: `David Baldacci - Deliver Us From Evil - 155 - Deliver
    // Us From Evil - 155`. Cutting the tail alone leaves the first copy
    // of the number in the base, so every track keys differently and
    // the arm folds nothing. Cut at the earlier copy instead - and only
    // at a copy of the SAME number, so an unrelated number in the title
    // ("Vol 8") is never mistaken for the index.
    if let Some(n) = index
        && let Some(earlier) = repeated_index(&body[..cut], n)
    {
        cut = earlier;
    }
    let base = body[..cut].trim_end_matches(['-', '_', ' ', '.']).trim();
    // A base with no word in it is a numbering scheme, not a title, and
    // one this short cannot be a book either.
    let wordy = base
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| w.len() >= 3 && w.bytes().all(|c| c.is_ascii_alphabetic()));
    (base.len() >= 12 && wordy).then(|| (base.to_string(), body[cut..].to_string()))
}

/// Start of the separator before the last standalone occurrence of the
/// number `n` in `base`, when something follows it. See the doubled
/// index in [`track_prefix`].
fn repeated_index(base: &str, n: u32) -> Option<usize> {
    let b = base.as_bytes();
    let sep = |c: u8| matches!(c, b' ' | b'-' | b'_' | b'.');
    let mut best = None;
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() || (i > 0 && !sep(b[i - 1])) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        // Bounded on both sides, at most four digits, the same value,
        // and NOT at either end - a cut to nothing is not a name.
        if i > 0 && j < b.len() && sep(b[j]) && j - i <= 4 && base[i..j].parse() == Ok(n) {
            best = Some(i - 1);
        }
        i = j;
    }
    best
}

/// Start of a trailing `NN of MM` part counter (`Clive Cussler -
/// Trojan Odyssey 04 of 14`), which is how the audiobook corpus
/// numbers loose files most often - 25 of one handle's rows on the
/// 2 Sep scratch index. Returns the index of the separator before the
/// counter, so the caller cuts a whole tail rather than a token.
fn of_counter(body: &str) -> Option<usize> {
    let idx = body.to_ascii_lowercase().rfind(" of ")?;
    let after = body[idx + 4..].trim();
    if after.is_empty() || after.len() > 4 || !after.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // `trim_end` only shortens, so `before`'s indices are `body`'s.
    let before = body[..idx].trim_end();
    let nd = before.bytes().rev().take_while(u8::is_ascii_digit).count();
    if nd == 0 || nd > 4 || nd == before.len() {
        return None;
    }
    let start = before.len() - nd;
    matches!(before.as_bytes()[start - 1], b' ' | b'-' | b'_' | b'.').then_some(start - 1)
}

/// One album the screens have named: the row to keep, the stem to give
/// it (`None` = keep the row's own, which is the anchor case), and
/// every row that merges into it, the kept row included.
struct AlbumPlan {
    keep: i64,
    stem: Option<String>,
    members: Vec<AlbMember>,
}

/// Cut one (poster, grp) window group into the albums it holds.
///
/// The measured shape (2 Sep scratch index, `alt.binaries.sounds.mp3`,
/// one handle `"@" <a.@a>` posting for 5,400 s straight):
///
/// ```text
///   1786725486  00-kate_carr-subtropical..._to_temperate_oceanic-freeweb-2014.m3u/.jpg/.nfo/.sfv
///   1786725487  01-kate_carr-subtropical_i.mp3
///   ...         02..06
///   1786725532  Kate_Carr-Subtropical_to_Temperate_Oceanic-FREEWEB-2014-MFW   <- par2 anchor
///   1786725540  00-kate_carr-transect...-freeweb-2026.jpg                     <- next album
/// ```
///
/// So a poster window is not one session, it is a QUEUE of albums, and
/// the `00-` furniture is what cuts it: each distinct furniture name
/// opens an album, and that album owns every track up to the next
/// furniture name. Nothing else in the window can do that job - a
/// freeweb compilation's tracks name a different artist each, and the
/// anchor lands at the END of its own burst, so anchors alone would
/// bound each album by the previous album's tail.
///
/// The anchor is what the album is CALLED. It is the par2 sidecar set,
/// the one row already wearing the full scene release name (the
/// furniture name plus the group tag, `...-2014` -> `...-2014-MFW`),
/// and it is already a correct, junk-0, kind=music card - so the fold
/// merges the tracks INTO it and rewrites no stem at all. Only when a
/// post brought no par2 does the furniture name get written as the
/// stem, which is the weaker outcome: it loses the group tag, and the
/// group tag is part of what predb joins on.
fn album_fold_plans(members: Vec<AlbMember>, anchors: Vec<AlbMember>, hi: i64) -> Vec<AlbumPlan> {
    let (furniture, tracks): (Vec<AlbMember>, Vec<AlbMember>) = members
        .into_iter()
        .partition(|m| has_ext(&m.stem, &FURNITURE_EXT));
    if furniture.is_empty() {
        return album_fold_by_prefix(tracks, &anchors);
    }
    // Each furniture row's album name, parsed ONCE: the loops below are
    // albums x rows, and re-parsing (which allocates) inside them is
    // what would make a 5,000-row handle expensive.
    let named: Vec<(Option<String>, &AlbMember)> = furniture
        .iter()
        .map(|f| (furniture_album(&f.stem).map(|n| n.to_ascii_lowercase()), f))
        .collect();
    // Each distinct furniture name, at the time its first row landed.
    let mut starts: std::collections::HashMap<String, i64> = Default::default();
    for (name, f) in &named {
        let Some(name) = name else { continue };
        let e = starts.entry(name.clone()).or_insert(f.first_posted);
        *e = (*e).min(f.first_posted);
    }
    let mut order: Vec<(String, i64)> = starts.into_iter().collect();
    order.sort_by_key(|(name, at)| (*at, name.clone()));
    let mut out = Vec::new();
    for (i, (name, start)) in order.iter().enumerate() {
        // An album STARTING inside the window's final MAX_SPAN strip
        // may extend past `hi`; folding the visible half now would
        // split it for good. The next window opens at `hi - MAX_SPAN`,
        // so a deferred album is seen whole there.
        if *start >= hi - MAX_SPAN {
            continue;
        }
        // The album owns everything up to the next album's first
        // furniture row, and no more than MAX_SPAN in any case.
        let end = order
            .get(i + 1)
            .map(|(_, next)| *next)
            .unwrap_or(i64::MAX)
            .min(start.saturating_add(MAX_SPAN))
            .min(hi);
        let mut mine: Vec<AlbMember> = Vec::new();
        let mut ok = true;
        for (fname, f) in &named {
            let is_mine = fname.as_deref() == Some(name.as_str());
            if is_mine {
                // Furniture posted outside its own album's interval is
                // a second copy or a repost, not this burst.
                ok &= f.first_posted >= *start && f.first_posted < end;
                mine.push((*f).clone());
            } else if fname.is_some() && f.first_posted >= *start && f.first_posted < end {
                // Two albums' furniture interleaved: the one thing this
                // cut cannot resolve, so neither is folded. A sidecar
                // this parser could NOT name is not evidence of a second
                // album and does not refuse one - it simply stays the
                // row it already was.
                ok = false;
            }
        }
        if !ok {
            continue;
        }
        let mut nums: Vec<u32> = Vec::new();
        for t in &tracks {
            if t.first_posted < *start || t.first_posted >= end {
                continue;
            }
            // A track is `NN-artist-title.ext`. An audio row in the
            // interval that is NOT numbered is unexplained - it may be
            // a second post's, and nothing here can say - so it is left
            // as its own row rather than merged on a guess. Under-merge
            // is this fold's chosen failure in every ambiguous case.
            let Some((n, _)) = strip_ext(&t.stem).and_then(track_field) else {
                continue;
            };
            nums.push(n);
            mine.push(t.clone());
        }
        let ntracks = nums.len();
        nums.sort_unstable();
        let distinct = {
            let mut d = nums.clone();
            d.dedup();
            d.len()
        };
        // Track numbers must be DISTINCT: a repeated `01-` is a second
        // album that brought no furniture of its own. Contiguity is
        // deliberately NOT required - scene multi-disc numbering runs
        // 101.. then 201.., and a missing track is exactly the case
        // the fold should still serve.
        if !ok || distinct != ntracks || ntracks < MIN_TRACKS || mine.len() > MEMBER_CAP {
            continue;
        }
        // The anchor: same interval, and its stem is the furniture name
        // with the release group tag appended (or, rarely, exactly it).
        let anchor = anchors.iter().find(|a| {
            a.first_posted >= *start && a.first_posted < end && anchor_matches(&a.stem, name)
        });
        let (keep, stem) = match anchor {
            Some(a) => {
                mine.push(a.clone());
                (a.id, None)
            }
            // No par2 in this post: fall back to writing the furniture
            // name, which is the release directory minus its group tag.
            None => (
                mine.iter().map(|m| m.id).min().unwrap_or(0),
                furniture.iter().find_map(|f| {
                    furniture_album(&f.stem).filter(|n| n.eq_ignore_ascii_case(name))
                }),
            ),
        };
        if stem.is_none() && anchor.is_none() {
            continue;
        }
        out.push(AlbumPlan {
            keep,
            stem,
            members: mine,
        });
    }
    out
}

/// Does `stem` name the album `name` (lowercased) - either exactly, or
/// as the scene release name that appends the group tag to it?
///
/// The remainder after `name-` has to LOOK like a group tag, and that
/// is the whole of the difference from the old rule. `starts_with` plus
/// a `-` accepted any remainder at all, including another title: in
/// alt.binaries.audiobooks, tracks keyed to `author - short name` were
/// matched by a neighbouring PAR2 called
/// `Author - Short Name-Longer Sequel-GRP`, and since arm B searches
/// anchors an hour either side of the album's own span, two books by
/// one poster an hour apart were enough. The first book's tracks joined
/// the sequel's row, the wall card showed the sequel, and a grab
/// fetched the sequel's PAR2 beside the first book's MP3s.
///
/// A real group tag is one token - `-MFW`, `-FREEWEB` - so requiring
/// the remainder to carry no further separator separates the two
/// cleanly. It keeps every shape the fold was built for: the scene
/// anchor `Gelugugu-Masterpiece_Cooking-FREEWEB-2020-MFW` over album
/// `gelugugu-masterpiece_cooking-freeweb-2020` leaves `mfw`.
pub(crate) fn anchor_matches(stem: &str, name: &str) -> bool {
    let low = stem.to_ascii_lowercase();
    if low == name {
        return true;
    }
    if !low.starts_with(name) || low.as_bytes().get(name.len()) != Some(&b'-') {
        return false;
    }
    let tag = &low[name.len() + 1..];
    !tag.is_empty() && !tag.contains(['-', '_', ' ', '.'])
}

/// ARM B, the audiobook arm: no furniture, so the only name available
/// is what the track stems agree on once their trailing index token is
/// removed. Each surviving prefix is its own album, which is also what
/// separates two books by one poster in one window - the arm needs no
/// single-album guard because the key itself is the separator.
fn album_fold_by_prefix(tracks: Vec<AlbMember>, anchors: &[AlbMember]) -> Vec<AlbumPlan> {
    let mut by_base: std::collections::HashMap<String, (Vec<AlbMember>, Vec<String>)> =
        Default::default();
    for t in tracks {
        let Some((base, tail)) = track_prefix(&t.stem) else {
            continue;
        };
        let e = by_base.entry(base).or_default();
        e.1.push(tail.to_ascii_lowercase());
        e.0.push(t);
    }
    let mut out: Vec<AlbumPlan> = by_base
        .into_iter()
        .filter(|(_, (ms, tails))| {
            let mut t = tails.clone();
            t.sort();
            t.dedup();
            let span = ms.iter().map(|m| m.first_posted).max().unwrap_or(0)
                - ms.iter().map(|m| m.first_posted).min().unwrap_or(0);
            // A repeated index means two things wearing one prefix,
            // which is the one shape a shared prefix cannot tell apart
            // from an album.
            (MIN_TRACKS..=MEMBER_CAP).contains(&ms.len()) && t.len() == ms.len() && span <= MAX_SPAN
        })
        .map(|(base, (mut ms, _))| {
            // The same anchor rule arm A uses, and for the same
            // measured reason: a loose-file audiobook post carries a
            // par2 set named after the book (`Clive Cussler - Trojan
            // Odyssey` beside `... 04 of 14.mp3`), and that row is the
            // identity. Without this the fold would try to WRITE that
            // name onto a track row and be refused by the UNIQUE the
            // anchor already holds.
            let lo = ms.iter().map(|m| m.first_posted).min().unwrap_or(0);
            let hi = ms.iter().map(|m| m.first_posted).max().unwrap_or(0);
            let low = base.to_ascii_lowercase();
            let anchor = anchors.iter().find(|a| {
                a.first_posted >= lo.saturating_sub(MAX_SPAN)
                    && a.first_posted <= hi.saturating_add(MAX_SPAN)
                    && anchor_matches(&a.stem, &low)
            });
            match anchor {
                Some(a) => {
                    ms.push(a.clone());
                    AlbumPlan {
                        keep: a.id,
                        stem: None,
                        members: ms,
                    }
                }
                None => AlbumPlan {
                    keep: ms.iter().map(|m| m.id).min().unwrap_or(0),
                    stem: Some(base),
                    members: ms,
                },
            }
        })
        .collect();
    out.sort_by_key(|p| p.keep);
    out
}

impl Index {
    /// One budgeted slice of the album fold: merge each poster's
    /// per-track music or audiobook post into the album it was posted
    /// as. Returns (albums folded, rows folded away, caught up).
    ///
    /// The walk is `session_fold`'s verbatim - posting-time windows
    /// overlapped by `MAX_SPAN` behind a settle margin - and the
    /// containment argument in that module's header applies here
    /// unchanged, since this fold's spans are bounded by the same
    /// constant.
    pub fn album_fold(
        &mut self,
        now: i64,
        budget: std::time::Duration,
    ) -> rusqlite::Result<(usize, usize, bool)> {
        const WINDOW: i64 = 4 * 3_600;
        const SETTLE: i64 = 2 * 3_600;
        let started = std::time::Instant::now();
        let deadline = started + budget;
        let horizon = now.saturating_sub(SETTLE);
        // The oldest posting on record, an O(1) probe of
        // `idx_rel_posted`. Starting a first walk at zero would spend a
        // hundred calls' budgets crossing fifty empty years.
        let min_posted: i64 = self.db.query_row(
            "SELECT COALESCE(MIN(first_posted), ?1) FROM releases WHERE first_posted>0",
            [horizon],
            |r| r.get(0),
        )?;
        let mut cursor: i64 = self
            .kv_get("album_fold_at")
            .and_then(|v| v.parse().ok())
            .unwrap_or(min_posted);
        // THE REWIND, and this fold needs it where `session_fold` does
        // not. That fold's quarry arrives a few sessions a day, so
        // parking at the top loses almost nothing. This one's quarry is
        // a standing backlog that arrives from BELOW: a group's deepen
        // leg pushes MIN(first_posted) further into history every lap,
        // and a walk that had already caught up would sail over every
        // album it uncovered, permanently. Measured 2 Sep on a
        // from-empty scratch index, which is the case that proves it:
        // the first lap caught up over a nearly empty table, and five
        // laps and 5,138 rows later the fold had folded nothing at all.
        //
        // So when the walk is caught up AND the floor has dropped below
        // anything walked before, it starts again from the new floor.
        // Bounded two ways: only from a caught-up state, so a rewind
        // never preempts forward progress; and cheap over the span it
        // already folded, because a folded album leaves no single-file
        // rows for the population query to return (measured: 843 ms and
        // 736 ms for whole re-walks of a 10k-row index).
        match self
            .kv_get("album_fold_floor")
            .and_then(|v| v.parse::<i64>().ok())
        {
            // The floor is where this walk STARTED, not the table's
            // minimum: writing the minimum when the walk had not
            // reached it would suppress the rewind that uncovers it.
            None => self.kv_set("album_fold_floor", &cursor.to_string())?,
            Some(f) if min_posted < f && cursor.saturating_add(WINDOW) > horizon => {
                cursor = min_posted;
                self.kv_set("album_fold_floor", &min_posted.to_string())?;
                self.kv_set("album_fold_at", &cursor.to_string())?;
            }
            Some(_) => {}
        }
        let (mut albums, mut folded) = (0usize, 0usize);
        let mut caught_up = false;
        let run: rusqlite::Result<()> = (|| {
            loop {
                if cursor.saturating_add(WINDOW) > horizon {
                    caught_up = true;
                    break;
                }
                let hi = cursor + WINDOW;
                let (a, n, seen, complete) = self.album_fold_window(cursor, hi, now, deadline)?;
                albums += a;
                folded += n;
                if !complete {
                    // Deadline mid-window: park at the window START.
                    // A folded album rescans to nothing (its members
                    // are gone and the kept row now has files>1), so
                    // revisiting is idempotent.
                    break;
                }
                cursor = if seen == 0 { hi } else { hi - MAX_SPAN };
                self.kv_set("album_fold_at", &cursor.to_string())?;
                if started.elapsed() >= budget {
                    break;
                }
            }
            Ok(())
        })();
        if folded > 0 {
            for (key, add) in [("album_fold_rows", folded), ("album_fold_albums", albums)] {
                let cur: u64 = self.kv_get(key).and_then(|v| v.parse().ok()).unwrap_or(0);
                self.kv_set(key, &(cur + add as u64).to_string())?;
            }
        }
        run?;
        if caught_up && (folded > 0 || self.kv_get("album_fold_lap_v1").is_none()) {
            self.kv_set("album_fold_lap_v1", "1")?;
            // A folded album wears a scene release name and a true
            // total size, which is precisely what the correlation walk
            // wants to be asked about again - and the folded row keeps
            // its old id, BELOW the parked backlog cursor, so without
            // this bump it would never be scored.
            let g: u64 = self
                .kv_get("predb_seed_gen")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            self.kv_set("predb_seed_gen", &(g + 1).to_string())?;
        }
        Ok((albums, folded, caught_up))
    }

    /// One posting-time window: collect the population, group it by
    /// (poster, grp), and fold what the arms can name. Returns
    /// (albums, rows folded, population rows seen, complete).
    fn album_fold_window(
        &mut self,
        lo: i64,
        hi: i64,
        now: i64,
        deadline: std::time::Instant,
    ) -> rusqlite::Result<(usize, usize, usize, bool)> {
        let mut groups: std::collections::HashMap<(String, String), Vec<AlbMember>> =
            Default::default();
        let mut anchors: std::collections::HashMap<(String, String), Vec<AlbMember>> =
            Default::default();
        let mut seen = 0usize;
        {
            // The extension test is in SQL and not in Rust so a window
            // over a movie-only index returns nothing at all rather
            // than a stem per row for Rust to throw away. `LIKE` is
            // ASCII case-insensitive, which is what `has_ext` mirrors.
            let exts: Vec<String> = AUDIO_EXT
                .iter()
                .chain(FURNITURE_EXT.iter())
                .map(|e| format!("stem LIKE '%{e}'"))
                .collect();
            let sql = format!(
                "SELECT id, stem, poster, grp, first_posted, first_seen, has_par2
                   FROM releases
                  WHERE first_posted>=?1 AND first_posted<?2
                    AND pre_title='' AND complete=1 AND files=1
                    AND poster<>'' AND ({})",
                exts.join(" OR ")
            );
            let mut stmt = self.db.prepare_cached(&sql)?;
            let rows = stmt.query_map([lo, hi], |r| {
                Ok((
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    AlbMember {
                        id: r.get(0)?,
                        stem: r.get(1)?,
                        first_posted: r.get(4)?,
                        first_seen: r.get(5)?,
                        has_par2: r.get(6)?,
                    },
                ))
            })?;
            for row in rows {
                let (poster, grp, m) = row?;
                seen += 1;
                groups.entry((poster, grp)).or_default().push(m);
            }
        }
        if !groups.is_empty() {
            // The anchors: the par2 sidecar set every scene mp3 post
            // carries, which is the ONE row already wearing the full
            // release name. Read as its own pass over the same
            // `idx_rel_posted` range rather than in the query above,
            // because an anchor is multi-FILE (`x.par2` plus its
            // volumes) and so falls outside the `files=1` population by
            // construction.
            let mut stmt = self.db.prepare_cached(
                "SELECT id, stem, poster, grp, first_posted, first_seen, has_par2
                   FROM releases
                  WHERE first_posted>=?1 AND first_posted<?2
                    AND pre_title='' AND poster<>'' AND has_par2=1",
            )?;
            let rows = stmt.query_map([lo, hi], |r| {
                Ok((
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    AlbMember {
                        id: r.get(0)?,
                        stem: r.get(1)?,
                        first_posted: r.get(4)?,
                        first_seen: r.get(5)?,
                        has_par2: r.get(6)?,
                    },
                ))
            })?;
            for row in rows {
                let (poster, grp, m) = row?;
                if groups.contains_key(&(poster.clone(), grp.clone())) {
                    anchors.entry((poster, grp)).or_default().push(m);
                }
            }
        }
        let (mut albums, mut folded) = (0usize, 0usize);
        let mut cands: Vec<(Vec<AlbMember>, Vec<AlbMember>)> = groups
            .into_iter()
            .filter(|(_, v)| (MIN_TRACKS..=GROUP_CAP).contains(&v.len()))
            .map(|(k, v)| {
                let a = anchors.remove(&k).unwrap_or_default();
                (v, a)
            })
            .collect();
        // Deterministic order under replay: by lowest member id.
        cands.sort_by_key(|(v, _)| v.iter().map(|m| m.id).min().unwrap_or(0));
        for (members, anchor) in cands {
            for plan in album_fold_plans(members, anchor, hi) {
                let n = self.album_fold_merge(&plan, now)?;
                if n > 0 {
                    albums += 1;
                    folded += n;
                }
            }
            if std::time::Instant::now() >= deadline {
                return Ok((albums, folded, seen, false));
            }
        }
        Ok((albums, folded, seen, true))
    }

    /// Merge one named album's members into the row that carries its
    /// identity. Returns rows folded away (0 = a gate refused it).
    ///
    /// Two shapes, and the difference is the whole point of the pass:
    ///
    /// * the album has a par2 anchor, so the kept row ALREADY wears the
    ///   scene release name and no stem is written - the tracks simply
    ///   join the card that was always the right one; or
    /// * it has none, so the furniture name is written onto the
    ///   lowest-id member. Keeping a TRACK's own stem would leave the
    ///   wall a card called "14 Blue Sky", and keeping a furniture stem
    ///   would leave one the junk scorer hides as a `.jpg`. That
    ///   rewrite is maintained the way `split_merge` maintains its own
    ///   - `stem_fold` in the same UPDATE, `rel_fts` by hand, because
    ///   rel_fts is external-content over stems and has no UPDATE
    ///   trigger.
    fn album_fold_merge(&mut self, plan: &AlbumPlan, now: i64) -> rusqlite::Result<usize> {
        let AlbumPlan {
            keep,
            stem: new_stem,
            members,
        } = plan;
        let keep = *keep;
        let (poster, grp, old_stem): (String, String, String) = self.db.query_row(
            "SELECT poster, grp, stem FROM releases WHERE id=?1",
            [keep],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let album = new_stem.as_deref().unwrap_or(&old_stem);
        if new_stem.is_some() {
            // `releases` is UNIQUE(stem, poster, grp). A row already
            // wearing this name in this poster's group is either the
            // album posted properly beside its tracks or an earlier
            // fold's output; either way it is not this pass's to
            // reconcile, so the album is left alone rather than merged
            // into something it did not observe.
            let taken: i64 = self.db.query_row(
                "SELECT COUNT(*) FROM releases WHERE stem=?1 AND poster=?2 AND grp=?3 AND id<>?4",
                rusqlite::params![album, poster, grp, keep],
                |r| r.get(0),
            )?;
            if taken > 0 {
                return Ok(0);
            }
        }
        let others: Vec<i64> = members
            .iter()
            .map(|m| m.id)
            .filter(|i| *i != keep)
            .collect();
        let list = others
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let tx = self.db.unchecked_transaction()?;
        // Members hold distinct filenames (distinct stems in one
        // (poster, grp) is what UNIQUE guarantees, and a stem is a
        // filename's own derivative), so OR IGNORE here is belt and
        // braces rather than the load-bearing rule it is in
        // `split_merge`.
        tx.execute(
            &format!("UPDATE OR IGNORE files SET release_id=?1 WHERE release_id IN ({list})"),
            [keep],
        )?;
        tx.execute(
            &format!("DELETE FROM files WHERE release_id IN ({list})"),
            [],
        )?;
        // Per-track audit rows: every member was scored as one track
        // against whole-release pres, which is the ratio-veto shape.
        // The folded album starts clean.
        tx.execute(
            &format!("DELETE FROM pre_corr WHERE release_id IN ({list}) OR release_id=?1"),
            [keep],
        )?;
        // §131 identity substrate: the message-id keys move WITH the
        // articles, as in every fold - a later posted-NZB or spot
        // lookup must still resolve a release that visibly survived.
        tx.execute(
            &format!("UPDATE OR IGNORE msgid_map SET release_id=?1 WHERE release_id IN ({list})"),
            [keep],
        )?;
        #[expect(clippy::type_complexity)]
        let (pmin, pmax, pck, sidx, stot): (
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
        ) = tx.query_row(
            &format!(
                "SELECT MIN(pesto_ctr_min), MAX(pesto_ctr_max), MIN(pesto_clock),
                        MAX(sess_idx), MAX(sess_total)
                   FROM releases WHERE id IN ({list}) OR id=?1"
            ),
            [keep],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        tx.execute(&format!("DELETE FROM releases WHERE id IN ({list})"), [])?;
        // Counted from the POST-merge file rows, never from member
        // sums: `complete` here is `RelAgg`'s "every file we have seen
        // has all its parts", which is a statement about the tracks in
        // hand and not a claim that the album is whole (module header).
        let agg = super::aggregates::RelAgg::recompute(&tx, keep)?;
        let fp = members
            .iter()
            .map(|m| m.first_posted)
            .filter(|v| *v > 0)
            .min()
            .unwrap_or(0);
        let fs = members.iter().map(|m| m.first_seen).min().unwrap_or(now);
        let has_par2 = members.iter().any(|m| m.has_par2);
        // Classified the way INGEST classifies, recoveries included -
        // not with a bare `classify`. Measured on the scratch index the
        // first cut of this fold: a bare classify turned
        // `Letna-Colors-FREEWEB-2007-MFW` from the music its own ingest
        // had made it back into an evidence-free "movie", and made a
        // folded audiobook a junk-60 movie the wall then hid, which is
        // strictly worse than the track cards it replaced. The album's
        // stem IS its name here, so each recovery takes it twice.
        let mut p = crate::categories::classify(album, &self.custom);
        crate::release::recover_media_kind(&mut p, album, album);
        crate::release::recover_kind_from_group(&mut p, &grp, album);
        // ...and the third one, which this fold reaches for real. The
        // population is scoped by EXTENSION and not by group - the
        // window query is `stem LIKE '%.mp3'` and its ten neighbours
        // over every group there is - so an audio dump in an anime or
        // a television group is squarely in it, and that is exactly
        // where `group_vouches_video` answers yes.
        //
        // Measured 2 Sep 2026 on the shape, and it is the audiobook
        // case again rather than a new one. A member track
        // `Bleach - 187 - Ichigo Rages - 01.mp3` carries its own format
        // marker, so ingest makes it music at junk 0 - visible. The
        // album this fold writes over it wears no extension, has no
        // music group to be rescued by, and falls through to an
        // evidence-free movie at junk 60, which the wall's default
        // hides: six visible cards traded for one invisible one. With
        // this pass it is season 1 episode 187 of Bleach at junk 0,
        // which is what the group vouches for and what ingest itself
        // would have written.
        //
        // It cannot cost an album its Music lane, either, and that is
        // by construction rather than by luck: `group_vouches_video`
        // stands down on every group `group_media_kind` speaks for, so
        // in the music and book groups this fold was built for the
        // pass never runs at all.
        //
        // Gated the way ingest gates it, and the gate is taken BEFORE
        // the pass for ingest's reason: the rule records a season, and
        // `stem_obfuscated`'s second arm is guarded on
        // `p.season.is_none()`, so asking afterwards would make the
        // blob test more lenient than it was.
        if !stem_obfuscated(album, &p) {
            crate::release::recover_episode_from_group(&mut p, &grp, album);
        }
        tx.execute(
            "UPDATE releases
                SET stem=?2, total_bytes=?3, files=?4, complete=?5, has_par2=?6,
                    first_posted=?7, first_seen=?8, have_parts=?9, need_parts=?10,
                    kind=?11, res=?12, title_key=?13, junk=?14, langs=?15,
                    vcodec=?16, acodec=?17, hdr=?18,
                    pesto_ctr_min=?19, pesto_ctr_max=?20, pesto_clock=?21,
                    sess_idx=?22, sess_total=?23,
                    nfiles_complete=?24, nfiles_exe=?25, stem_fold=?26
              WHERE id=?1",
            rusqlite::params![
                keep,
                album,
                agg.tbytes,
                agg.nfiles,
                agg.complete(),
                has_par2,
                fp,
                fs,
                agg.have,
                agg.need,
                kind_str(&p.kind),
                p.res.as_deref().unwrap_or_default(),
                p.key,
                junk_score(album, &p, agg.tbytes.max(0) as u64, agg.nexe > 0),
                p.langs.join(" "),
                p.vcodec.as_deref().unwrap_or_default(),
                p.acodec.as_deref().unwrap_or_default(),
                p.hdr.as_deref().unwrap_or_default(),
                pmin,
                pmax,
                pck,
                sidx,
                stot,
                agg.ncomplete,
                agg.nexe,
                super::fold::stored(album)
            ],
        )?;
        // rel_fts is external-content over stems and has no UPDATE
        // trigger, so the rewrite maintains it by hand; the member
        // deletions above were covered by rel_fts_ad.
        if self.fts && old_stem != *album {
            tx.execute(
                "INSERT INTO rel_fts(rel_fts, rowid, stem) VALUES('delete', ?1, ?2)",
                rusqlite::params![keep, old_stem],
            )?;
            tx.execute(
                "INSERT INTO rel_fts(rowid, stem) VALUES(?1, ?2)",
                rusqlite::params![keep, album],
            )?;
        }
        tx.commit()?;
        Ok(others.len())
    }
}
