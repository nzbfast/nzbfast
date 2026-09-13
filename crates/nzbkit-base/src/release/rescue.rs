//! The two RESCUE passes `parse_release` falls back to when the plain
//! read of a stem yields nothing worth having: the ROT13/ROT18 decode and
//! the whole-name reversal. Each is a decode plus the evidence test that
//! decides whether to believe it, and neither is reachable from anywhere
//! but `parse_release`.
//!
//! Cut out of `release.rs` on 7 Sep 2026 (claim `debt-split-hot-files-7sep`)
//! at 3,391 of the size gate's 4,000-line file ceiling. Verbatim move,
//! banner comments included; the only rewrite is `fn` -> `pub(super) fn`
//! so the parser can still call them.

use super::*;

// ---------------------------------------------------------------------------
// ROT13 rescue: many obfuscated posts are the real name letter-rotated
// (and some rotate digits by 5 as well - ROT18 - so "720p" hides as
// "275c"). Both variants are tried; a decode is only believed when it
// parses into a clean scene name with real furniture AND reads like
// English, so genuine titles never get mangled by accident.
// ---------------------------------------------------------------------------

pub(super) fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

pub(super) fn rot5_digits(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0'..='9' => (((c as u8 - b'0' + 5) % 10) + b'0') as char,
            _ => c,
        })
        .collect()
}

/// Common English words that survive into almost every real title -
/// a decode containing one is strong evidence it isn't coincidence.
pub(super) const COMMON_WORDS: &[&str] = &[
    "the", "a", "an", "and", "of", "to", "in", "on", "at", "is", "it", "for", "with", "from", "my",
    "who", "what", "war", "world", "man", "men", "girl", "boy", "king", "queen", "day", "night",
    "dead", "love", "life", "star", "dark", "black", "white", "story", "game", "house", "big",
    "little", "new", "last", "first", "one", "two",
];

/// (every word pronounceable, contains a common English word). A word
/// of 3+ letters with no vowel at all ("qrs", "xkcd") sinks the decode.
pub(super) fn english_words(title: &str) -> (bool, bool) {
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
pub(super) fn volume_tail_cut(decoded: &str) -> Option<String> {
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
pub(super) fn rot13_rescue(stem: &str) -> Option<Parsed> {
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
pub(super) fn reads_backwards(tok: &str) -> bool {
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
pub(super) fn reversed_rescue(stem: &str, direct: &Parsed) -> Option<Parsed> {
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
