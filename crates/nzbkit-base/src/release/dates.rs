//! Reading a DATE out of a release name, and writing one back out: the
//! token shapes a date can arrive in (dotted, spelled, ISO, a monthly
//! issue), the calendar arithmetic that decides whether the numbers are a
//! real day, and [`air_date_parts`], which splits a normalized date into
//! the `{Series Title} - {Air-Date}` halves every library files a daily
//! show under.
//!
//! Cut out of `release.rs` on 7 Sep 2026 (claim `debt-split-hot-files-7sep`)
//! at 3,391 of the size gate's 4,000-line file ceiling. Verbatim move; the
//! public items keep their `release::` paths through the `pub use` beside
//! the `mod` declaration, so no caller changes.

use super::*;

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
pub(super) struct DateRead {
    /// The date, normalized to "yyyymmdd". None for the one shape that
    /// says TV without saying WHEN: an 8-digit run whose month or day
    /// does not validate. That width alone has always been enough for
    /// the `daily` flag, which only has to decide "TV, not a movie",
    /// while a date has to be right.
    pub(super) date: Option<String>,
    /// Index of the first token AFTER the date, so the identity tail
    /// can start there (the same trick the movie-year arm uses).
    pub(super) end: usize,
    /// An AIR date - a daily-TV convention - rather than a masthead
    /// PUBLICATION date.
    pub(super) air: bool,
}

pub(super) fn date_at(toks: &[&str], i: usize) -> Option<DateRead> {
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
pub(super) fn month_of(tok: &str) -> Option<u32> {
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
pub(super) fn day_of(tok: &str) -> Option<u32> {
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
pub(super) fn spelled_date(toks: &[&str], i: usize) -> Option<(String, usize)> {
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
pub(super) fn iso_date(tok: &str) -> Option<String> {
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
pub(super) fn month_issue(toks: &[&str], boundary: usize) -> Option<(String, usize, usize)> {
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
pub(super) fn fenced_month(toks: &[&str], i: usize) -> Option<u32> {
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
pub(super) fn days_in_month(year: u32, month: u32) -> u32 {
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
