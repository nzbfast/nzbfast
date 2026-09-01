//! The fold that answers "will these two names be ONE file object on a
//! case-insensitive volume" - [`case_fold_key`], and the measurement
//! that chose it.
//!
//! Split out of `disk.rs` under the size gate (TODO 106): that file was
//! at 2,901 of the flat 3,000-line ceiling when this landed, and this is
//! one subject end to end (the fold, why it is spelled the way it is,
//! and the pins that hold it there).
//!
//! Read this before changing the expression. Every identity-key site in
//! the tree that folds at all now calls this one function, so a rule
//! changed here changes what collides with what in three modules that do
//! not look like each other.

/// Fold `name` to the key a case-insensitive volume would file it under.
///
/// Callers gate this on [`super::case_insensitive_dir`] - the answer
/// belongs to the destination VOLUME, never to the build target - and
/// keep the exact name when that probe says the volume is sensitive.
///
/// # Why not `str::to_lowercase`
///
/// Because it is not what a case-insensitive volume does, and the gap is
/// data. M4-61 (30 Aug 2026) measured `unpack::PublishedNames` publishing
/// two verified files that APFS filed as ONE object: the claim map saw no
/// collision because `to_lowercase` left them as two keys, both publishes
/// reported success, and the second RENAMED OVER the first. One payload
/// gone, rc=0, two "renamed" lines in a log ring.
///
/// M4-44 (31 Aug 2026) measured the whole gap rather than the one pair,
/// by building APFS's OWN equivalence partition on the dev box - one file
/// created per BMP codepoint, classes read off the inodes - and scoring
/// each candidate fold against it. Over the 62,084 codepoints that are
/// legal in a filename, against 1,599 real multi-member classes:
///
/// | fold | under-folds | over-folds |
/// |---|---|---|
/// | `to_lowercase` (what every site used) | 1,020 | 0 |
/// | this function | 925 | **0** |
/// | this function + NFD | **0** | **0** |
///
/// A single-codepoint sweep cannot see the case that matters most,
/// though: `ß` against `ss` is a one-char name against a two-char one.
/// Measured separately, over all 104 BMP characters whose fold expands to
/// more than one character - `ß`, the `ﬁ`/`ǆ` ligatures, the Greek
/// iota-subscript forms - **APFS files all 104 as one object with their
/// expansion, `to_lowercase` catches 1 of them, and this catches 104.**
/// `Straße.mkv` beside `STRASSE.MKV` is the shape a real post has.
///
/// # What it is
///
/// Unicode DEFAULT full case folding, reached through the standard
/// library rather than through a table:
///
/// * `to_lowercase` first, so the context-sensitive final-sigma rule runs
///   over the whole string once (`ΟΔΟΣ` and `οδος` reach the same key).
/// * then uppercase, which is where the stdlib performs the multi-char
///   expansions that plain lowercasing never does (`ß` -> `SS`);
/// * then lowercase again, which is the fixed point.
///
/// with U+0130 and U+0131 HELD OUT of the uppercase leg. Those two are
/// exactly where Rust's `to_uppercase` implements the TURKIC tailoring
/// (`ı` -> `I`) rather than the default fold, under which `ı` folds to
/// itself. APFS keeps `I`/`ı` and `I`/`İ` apart; without the hold-out
/// this merges them, which is the one direction that costs a file.
///
/// # What it deliberately does NOT do, and the one thing to know
///
/// **Normalization.** A case-insensitive volume is also normalization-
/// insensitive, and that is the whole of the 925 residue above: 438
/// classes of singleton canonical decomposition - `U+037E` GREEK QUESTION
/// MARK filed as `;`, `U+1FEF` as a backtick, the precomposed Greek
/// accents, the CJK compatibility ideographs. Adding NFD closes it
/// EXACTLY, to zero either way, and no case-fold table of any strength
/// closes any of it. That half needs a normalization dependency in
/// `nzbkit` (`icu_normalizer` is already in `Cargo.lock` transitively but
/// is not a direct dependency of this crate), which is a binary-size
/// decision on the iOS store build - TODO 281 IO3b - and not one to make
/// in passing. It is measured, priced and left.
///
/// **And no fold is stable against a volume.** The candidate was first
/// scored against Python 3.9's `str.casefold` and "disagreed" on 26
/// codepoints; APFS was then asked directly and said the CANDIDATE was
/// right on all 26 - the reference was Unicode 13.0 and the characters
/// were added later. A fold is a table, a volume is a different table
/// baked when it was formatted, and they drift. Where a caller can ask
/// the filesystem instead - `super::same_file_object`, which needs no
/// table and is right on volumes nobody here has measured - it should,
/// and `unpack::PublishedNames::collides_on_disk` is that done. This
/// function is for the comparisons that happen before anything exists on
/// disk to stat.
///
/// # Over-folding, and why one caller does not use this
///
/// Every site that calls this pays a BOUNDED, visible price for an
/// over-fold - a `{slot:03}-` prefix, a `.dup-<fid>` suffix, a junk file
/// left in the output folder - against a silent loss for an under-fold,
/// so folding harder is the right trade there. `nzbfast::rarfix`'s
/// duplicate-target guard is NOT one of them and must not be converted:
/// it resolves a collision by DROPPING an entry, so an over-fold there
/// costs a file. Measured zero over-folds on APFS, but the 104 expansions
/// above are precisely what a 1:1 upcase table cannot reproduce, and
/// NTFS's `$UpCase` is 1:1 - so on Windows `straße.txt` beside
/// `strasse.txt` is two files, and this fold would drop one of them.
pub fn case_fold_key(s: &str) -> String {
    let lowered = s.to_lowercase();
    // Fast path: the two Turkic dotted/dotless i are the only characters
    // whose uppercase leg has to be suppressed, and nearly no name has
    // one, so nearly every call is two stdlib passes and no per-char loop.
    if !lowered.contains(['\u{0130}', '\u{0131}']) {
        return lowered.to_uppercase().to_lowercase();
    }
    let mut up = String::with_capacity(lowered.len());
    for c in lowered.chars() {
        if c == '\u{0130}' || c == '\u{0131}' {
            up.push(c);
        } else {
            up.extend(c.to_uppercase());
        }
    }
    up.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::case_fold_key;

    /// Pairs MEASURED as one file object on the dev box's APFS volume on
    /// 31 Aug 2026 (one file created per name, classes read off the
    /// inodes). Each must reach one key, and the `lowercase` column is
    /// what `str::to_lowercase` answered - five of these thirteen were
    /// two distinct keys before this function existed, which is five
    /// shapes of silent overwrite.
    #[test]
    fn every_pair_apfs_files_as_one_object_reaches_one_key() {
        let one = [
            ("K", "\u{212A}", "kelvin sign"),
            ("s", "\u{017F}", "long s"),
            ("\u{00C5}", "\u{212B}", "A-ring / angstrom sign"),
            ("SS", "\u{00DF}", "SS / eszett"),
            ("\u{1E9E}", "\u{00DF}", "capital eszett / eszett"),
            ("\u{03A3}", "\u{03C3}", "Sigma / sigma"),
            ("\u{03C2}", "\u{03C3}", "final sigma / sigma"),
            ("\u{03A9}", "\u{2126}", "Omega / ohm sign"),
            ("STRASSE", "stra\u{00DF}e", "the shape a German post has"),
            ("\u{FB01}le.txt", "file.txt", "fi ligature"),
            ("\u{01C4}ungla", "\u{01C6}ungla", "DZ-caron digraph"),
            ("README.NFO", "readme.nfo", "the ordinary case"),
            ("\u{017F}ample.par2", "sample.par2", "long s in a set name"),
        ];
        for (a, b, why) in one {
            assert_eq!(
                case_fold_key(a),
                case_fold_key(b),
                "APFS files {a:?} and {b:?} as ONE object ({why}); the fold \
                 must too, or two publishes both report success and the \
                 second renames over the first"
            );
        }
    }

    /// The hold-out, and the one direction that costs a file. APFS keeps
    /// these apart; a fold that merges them makes `rarfix` drop an entry
    /// and every other site rename one needlessly. `to_uppercase` maps
    /// `\u{0131}` -> `I` (the Turkic tailoring), so without the hold-out
    /// in the uppercase leg all three of these merge.
    #[test]
    fn the_turkic_dotted_and_dotless_i_stay_apart() {
        for (a, b) in [("I", "\u{0131}"), ("i", "\u{0131}"), ("I", "\u{0130}")] {
            assert_ne!(
                case_fold_key(a),
                case_fold_key(b),
                "APFS keeps {a:?} and {b:?} apart - merging them is the \
                 over-fold direction, which drops a file in rarfix"
            );
        }
        // The whole-name shapes, so the fast path and the per-char path
        // are both exercised: the second name carries a held-out char and
        // takes the loop, the first does not.
        assert_ne!(
            case_fold_key("Istanbul.mkv"),
            case_fold_key("\u{0131}stanbul.mkv")
        );
    }

    /// A key must be its own key. Two things depend on it: the sites feed
    /// a disambiguated candidate (`001-<name>`) back through the same
    /// function, and the Greek final-sigma rule runs on every pass, so a
    /// non-idempotent expression would answer differently for a name
    /// depending on how many times it had been asked.
    #[test]
    fn the_fold_is_a_fixed_point() {
        for n in [
            "Stra\u{00DF}e.mkv",
            "\u{039F}\u{0394}\u{039F}\u{03A3}",
            "\u{039F}\u{0394}\u{039F}\u{03A3}.txt",
            "\u{0130}stanbul.mkv",
            "001-README.NFO",
            "",
        ] {
            let k = case_fold_key(n);
            assert_eq!(case_fold_key(&k), k, "not a fixed point for {n:?}");
        }
    }

    /// Greek word-final sigma reaches one key from either spelling, in
    /// both positions. This is why the expression lowercases FIRST rather
    /// than uppercasing first: the rule is context-sensitive and needs to
    /// see the whole string.
    #[test]
    fn final_sigma_reaches_one_key_from_either_spelling() {
        assert_eq!(
            case_fold_key("\u{039F}\u{03A3}"),
            case_fold_key("\u{03BF}\u{03C2}")
        );
        assert_eq!(
            case_fold_key("\u{03BF}\u{03C3}"),
            case_fold_key("\u{03BF}\u{03C2}")
        );
        assert_eq!(
            case_fold_key("\u{039F}\u{03A3}.txt"),
            case_fold_key("\u{03BF}\u{03C2}.txt")
        );
    }

    /// STRICTLY stronger than what every site used before, and never
    /// weaker: anything `to_lowercase` merged must still merge. A fold
    /// that traded one of those away would be a new overwrite, not a fix.
    #[test]
    fn it_never_splits_a_pair_to_lowercase_already_merged() {
        for (a, b) in [
            ("README", "readme"),
            ("Movie.MKV", "movie.mkv"),
            ("\u{00C4}pfel", "\u{00E4}pfel"),
            ("\u{0411}\u{041E}\u{041B}", "\u{0431}\u{043E}\u{043B}"),
        ] {
            assert_eq!(
                a.to_lowercase(),
                b.to_lowercase(),
                "fixture is not a to_lowercase pair"
            );
            assert_eq!(case_fold_key(a), case_fold_key(b));
        }
    }

    /// The STATED LIMIT, pinned so nobody reads a green suite as "the
    /// fold is what the volume does". A case-insensitive volume is also
    /// normalization-insensitive: APFS files `U+037E` GREEK QUESTION MARK
    /// as `;` and `U+1FEF` as a backtick, and this fold does not, because
    /// that half needs NFD and NFD needs a dependency. 925 codepoints in
    /// 438 classes, measured. If this test ever FAILS, the normalization
    /// half has been closed - delete it and say so.
    #[test]
    fn the_normalization_half_is_still_open() {
        for (a, b) in [
            (";", "\u{037E}"),
            ("`", "\u{1FEF}"),
            ("\u{00B7}", "\u{0387}"),
        ] {
            assert_ne!(
                case_fold_key(a),
                case_fold_key(b),
                "APFS files {a:?} and {b:?} as one object and this fold \
                 does not - if that is now closed, this pin is stale"
            );
        }
    }
}
