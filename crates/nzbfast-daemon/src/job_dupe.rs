//! The keys a release name reduces to for duplicate detection.
//!
//! `exact_dupe_key` for the byte-identical post, `dupe_key` (with
//! `dated_key` under it) for SAB's smart-dedupe identity, `flatten_name`
//! for the house reduction both are built on, and `is_proper` for the
//! releases that are meant to replace an earlier one (TODO 106 code
//! motion out of job.rs, behaviour unchanged).

/// Series/movie identity from a release name (SAB "smart dedupe" model):
/// `Show.Name.S01E02.1080p.WEB` → `show name/s1e2`,
/// `Movie.Title.2026.2160p` → `movie title/2026`. Quality/group noise is
/// exactly what must NOT distinguish duplicates, so only the title before
/// the marker, the marker itself, and (for a year marker) whatever
/// identity follows it go into the key.
/// "head/<date> <identity tail>" for a dated post: everything before the
/// date names the competition or show, everything identity-bearing after
/// it names the event of that day. The group tag is trimmed off the tail
/// (it is noise, and on some posts it is the last token), matching the
/// movie-year arm below.
pub(crate) fn dated_key(
    tokens: &[&str],
    date_at: usize,
    tail_from: usize,
    date: &str,
    raw_name: &str,
) -> String {
    let group = nzbkit::release::group_of(raw_name).map(str::to_ascii_lowercase);
    let mut tail = nzbkit::release::identity_tail(tokens[tail_from..].iter().copied());
    if tail.last().is_some_and(|l| Some(*l) == group.as_deref()) && tokens.last() == tail.last() {
        tail.pop();
    }
    let head = tokens[..date_at].join(" ");
    if tail.is_empty() {
        format!("{head}/{date}")
    } else {
        format!("{head}/{date} {}", tail.join(" "))
    }
}

/// The "exact" duplicate identity: the whole release name, flattened the
/// same way `dupe_key` flattens it. `Show.Name.S01E02.x264-Grp` and
/// `Show Name S01E02 x264-Grp` still meet, but a different release of
/// the same episode does not - which is the point of
/// `dupe_scope = "exact"`: a quality upgrade an *arr chose is not a
/// duplicate, a re-send of the same release is.
pub(crate) fn exact_dupe_key(name: &str) -> String {
    flatten_name(name)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

// `flatten_name` moved to `crate::smart` (TODO 276 item 3) - it is the
// house release-name reduction and `newznab::release_ident` wanted it,
// which made the indexer depend on the daemon. Re-exported so every
// caller in here still spells it `flatten_name`.
pub(crate) use crate::smart::flatten_name;

pub fn dupe_key(name: &str) -> Option<String> {
    // Full non-alphanumeric flattening (not just ./_/-): friendly-named
    // posts write "Title (2026)" and the parenthesized year token never
    // matched the scene form's bare "2026", so the same film in two
    // naming styles didn't dedupe (and the wall's have-badge missed).
    let flat = flatten_name(name);
    let tokens: Vec<&str> = flat.split_whitespace().collect();
    // Episode marker wins over a year token (`Show.2026.S01E02` is an
    // episode, not a movie from 2026).
    for (i, t) in tokens.iter().enumerate() {
        // SxxEyy (also SxxEyyEzz double episodes - key on the first ep).
        if let Some(rest) = t.strip_prefix('s') {
            let mut it = rest.splitn(2, 'e');
            if let (Some(s), Some(e)) = (it.next(), it.next()) {
                let e_first: String = e.chars().take_while(|c| c.is_ascii_digit()).collect();
                if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) && !e_first.is_empty() {
                    let (s, e): (u32, u32) = (s.parse().ok()?, e_first.parse().ok()?);
                    return Some(format!("{}/s{s}e{e}", tokens[..i].join(" ")));
                }
            }
        }
    }
    for (i, t) in tokens.iter().enumerate() {
        // NxNN alternate episode form (3x07 ≡ S03E07) - same constraints
        // as the wall parser (1-2 digit season, 2-3 digit episode, so
        // "4x4" truck titles don't match). Without this the dupe check
        // was skipped and a 3x07 alt of an owned S03E07 fully downloaded.
        if let Some((s, e)) = t.split_once('x')
            && !s.is_empty()
            && s.len() <= 2
            && s.bytes().all(|c| c.is_ascii_digit())
            && (2..=3).contains(&e.len())
            && e.bytes().all(|c| c.is_ascii_digit())
        {
            let (s, e): (u32, u32) = (s.parse().ok()?, e.parse().ok()?);
            return Some(format!("{}/s{s}e{e}", tokens[..i].join(" ")));
        }
    }
    // Daily-date episodes, both conventions normalized to yyyymmdd so a
    // dotted post dedupes against a compact one. Must outrank the movie-
    // year arm: it keyed every "Show.2026.07.21" episode to `show/2026`,
    // so all of a year's daily episodes after the first were held as
    // paused duplicates of episode one.
    //
    // The date alone is not the identity, for the same reason a season
    // year alone was not: a matchday holds five fixtures and a fight
    // card holds prelims and a main card. Keyed on `epl/20260822`,
    // "Arsenal.vs.Spurs" and "Liverpool.vs.Everton" were one release -
    // the second admitted PAUSED at priority -3 and never promoted
    // (park only frees a held duplicate when the first FAILS), and
    // adopted by the watchlist as a slot it already owned. So the
    // identity tail after the date counts, exactly as it does after a
    // year, and by the same rules: it stops at the first piece of hard
    // furniture, so two encodes of one event still share a key.
    let d2 = |s: &str, max: u32| {
        s.len() == 2
            && s.bytes().all(|c| c.is_ascii_digit())
            && s.parse::<u32>().is_ok_and(|v| (1..=max).contains(&v))
    };
    for (i, t) in tokens.iter().enumerate() {
        if i == 0 || !t.bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // Dotted: year token + MM + DD tokens ("2026 07 21" after
        // separator flattening).
        if t.len() == 4
            && (t.starts_with("19") || t.starts_with("20"))
            && tokens.get(i + 1).is_some_and(|m| d2(m, 12))
            && tokens.get(i + 2).is_some_and(|d| d2(d, 31))
        {
            let date = format!("{t}{}{}", tokens[i + 1], tokens[i + 2]);
            return Some(dated_key(&tokens, i, i + 3, &date, name));
        }
        // Compact: YYMMDD / YYYYMMDD ("At.Midnight.150615…").
        if t.len() == 6 || t.len() == 8 {
            let (y, md) = t.split_at(t.len() - 4);
            let (mth, day) = md.split_at(2);
            if d2(mth, 12) && d2(day, 31) {
                let year = if y.len() == 2 {
                    format!("20{y}")
                } else {
                    y.to_string()
                };
                return Some(dated_key(
                    &tokens,
                    i,
                    i + 1,
                    &format!("{year}{mth}{day}"),
                    name,
                ));
            }
        }
    }
    // Release group: taken from the RAW name, because the flattening
    // above dissolved the hyphen that marks it. A group tag is pure
    // noise, so it must never end up in the identity tail below.
    let group = nzbkit::release::group_of(name).map(str::to_ascii_lowercase);
    for (i, t) in tokens.iter().enumerate() {
        // Movie year 1900–2099, not in first position (that's a title).
        if i > 0
            && t.len() == 4
            && (t.starts_with("19") || t.starts_with("20"))
            && t.chars().all(|c| c.is_ascii_digit())
        {
            // A year is not always a release date. Event posts use it as
            // the SEASON and put their identity after it - the round, the
            // country, the session ("Formula1.2026.Round11.Hungary.Pre-
            // Qualifying.Show.F1TV.WEB-DL.1080p.H264.English-MWR"). Keyed
            // on title+year alone, every session of every round of the
            // year collapsed onto "formula1/2026" and each one after the
            // first was held as a paused duplicate at priority -3. Same
            // bug the daily-date arm above exists to prevent, one shape
            // over.
            //
            // The tail stops at the first piece of hard furniture, so an
            // ordinary film - whose year is followed straight by quality
            // tags - keys exactly as it always did, and two encodes of
            // one release still share a key: resolution, source, codec,
            // edition and group can never reach the tail.
            let mut tail = nzbkit::release::identity_tail(tokens[i + 1..].iter().copied());
            if tail.last().is_some_and(|l| Some(*l) == group.as_deref())
                && tokens.last() == tail.last()
            {
                tail.pop();
            }
            let head = tokens[..i].join(" ");
            return Some(if tail.is_empty() {
                format!("{head}/{t}")
            } else {
                format!("{head}/{t} {}", tail.join(" "))
            });
        }
    }
    None
}

/// PROPER/REPACK releases deliberately replace an earlier post - never
/// hold them as duplicates. ("REAL" is excluded: too many titles contain
/// the word; scene REALs virtually always also carry PROPER.)
pub fn is_proper(name: &str) -> bool {
    let flat = name.to_ascii_lowercase().replace(['.', '_', '-'], " ");
    flat.split_whitespace()
        .any(|t| matches!(t, "proper" | "repack" | "rerip"))
}
