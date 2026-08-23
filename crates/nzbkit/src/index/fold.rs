//! Unicode-aware case folding for stem matching (TODO 5 phase 2c).
//!
//! SQLite's built-in `LOWER()` is **ASCII-only** - it lowercases `A-Z`
//! and leaves every other codepoint exactly as it found it. So does
//! `COLLATE NOCASE`. On an index whose stems are Cyrillic or Greek that
//! is not a rounding error, it is the whole feature missing: a user
//! typing `война` never matches the stem `ВОЙНА.И.МИР`, because the SQL
//! side folds neither and the Rust side mirrored it with
//! `to_ascii_lowercase`.
//!
//! FTS5's `unicode61` tokenizer *does* fold the full Unicode range, so
//! the M28 FTS path has always answered these queries correctly. The
//! gap is everything that is not FTS: the `LIKE` fallback that serves
//! non-FTS builds and punctuation-only queries, and the Rust-side
//! verification of an FTS candidate in the NZBLNK ladder - which
//! rejected a correctly-found Cyrillic row because its own `contains`
//! test was still ASCII-folded.
//!
//! Two normalizations live here, and the difference between them is
//! load-bearing:
//!
//! * [`sql_twin`] is the exact Unicode analogue of the SQL expression
//!   `REPLACE(REPLACE(REPLACE(LOWER(x),'.',' '),'_',' '),'-',' ')` -
//!   lowercase, separators to spaces, and **no whitespace collapsing**,
//!   because SQL does none either. This is what the `releases.stem_fold`
//!   column stores, so a `LIKE '%term%'` against it has byte-for-byte
//!   the same substring semantics as the same `LIKE` against the SQL
//!   expression. Widen one without the other and the two arms of the
//!   search silently disagree.
//! * [`query`] is `sql_twin` plus whitespace collapsing, and is what
//!   both sides of a *Rust* comparison use (query terms, and the NZBLNK
//!   candidate check). It replaces the two hand-rolled `norm` closures
//!   that used to sit in query.rs.
//!
//! Deliberately NOT done here: diacritic stripping. `unicode61` runs
//! with `remove_diacritics=1`, which strips the Latin ones - measured on
//! the bundled SQLite, an FTS query for `cafe` answers `Café`, and this
//! fold does not. (Greek tonos survives even there: `ελληνικα` does NOT
//! answer `ΕΛΛΗΝΙΚΆ` on the FTS path either, since that needs
//! `remove_diacritics=2`.) Matching FTS here would mean carrying a
//! decomposition table for a fallback path, and the divergence is in the
//! safe direction - the fold is stricter, never looser.

/// The separator characters a release stem is spelled with. Kept next
/// to the SQL expression it mirrors: the three `REPLACE` calls in
/// `query::stem_fold_arm` - and in the `pre_title` twins that sit
/// beside it in query.rs and browse.rs - are these, in this order.
const SEPARATORS: [char; 3] = ['.', '_', '-'];

/// Lowercase + separators-to-spaces, the exact Unicode analogue of the
/// SQL `REPLACE(REPLACE(REPLACE(LOWER(x),'.',' '),'_',' '),'-',' ')`.
///
/// Greek final sigma is normalized away (`ς` -> `σ`). Rust's
/// `to_lowercase` is context-sensitive there - `ΟΔΥΣΣΕΥΣ` lowercases to
/// `οδυσσευς` with a *final* sigma - so a user who types the medial form
/// (which is what most Greek keyboards and every copy-paste from a
/// lowercase source produce mid-word) would miss a stem that had been
/// folded from capitals. Folding both spellings to `σ` makes the two
/// sides agree whichever way round the capitals fall. `unicode61` does
/// the same thing, so this also keeps the FTS and LIKE paths aligned.
pub(crate) fn sql_twin(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if SEPARATORS.contains(&c) {
            out.push(' ');
        } else if c.is_ascii() {
            // The overwhelmingly common case, and `to_lowercase` on a
            // `char` allocates an iterator per character.
            out.push(c.to_ascii_lowercase());
        } else {
            for lc in c.to_lowercase() {
                out.push(if lc == 'ς' { 'σ' } else { lc });
            }
        }
    }
    out
}

/// [`sql_twin`] with runs of whitespace collapsed to one space and the
/// ends trimmed - the form both sides of a Rust-side comparison take.
pub(crate) fn query(s: &str) -> String {
    sql_twin(s).split_whitespace().collect::<Vec<_>>().join(" ")
}

/// What `releases.stem_fold` holds for a given stem: the fold when it
/// says something SQL's own `LOWER()` cannot, and the empty string when
/// it does not.
///
/// The column is deliberately SPARSE. A pure-ASCII stem - which is very
/// nearly all of them - folds identically under `LOWER()` and under
/// Unicode, so storing the fold would be a second copy of every stem in
/// the index (measured shape: ~60 bytes x 16.5 M rows) to answer a
/// question the existing expression already answers. An empty string
/// costs a single byte of record header instead.
///
/// So does an accented *lowercase* stem, which is why the cheap
/// `is_ascii` gate is not the only test: `Wörld` folds to `wörld` both
/// ways, because `LOWER()` leaves `ö` alone and only had to handle the
/// `W`. Only a stem carrying a non-ASCII character that actually
/// CHANGES under Unicode lowercasing earns a stored value.
///
/// Readers must therefore always spell the fold arm as
/// `stem_fold <> '' AND stem_fold LIKE ...`, ORed with the existing SQL
/// expression - never as a replacement for it.
pub(crate) fn stored(stem: &str) -> String {
    if stem.is_ascii() {
        return String::new();
    }
    let folded = sql_twin(stem);
    // The ASCII-only fold SQLite would compute for itself. Built the
    // same way as `sql_twin` so the comparison is of the LOWERCASING
    // only, not of two different separator rules.
    let ascii: String = stem
        .chars()
        .map(|c| {
            if SEPARATORS.contains(&c) {
                ' '
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    if folded == ascii {
        String::new()
    } else {
        folded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole feature rests on: what Rust stores for an
    /// uppercase stem contains what a Rust-folded lowercase query asks
    /// for, across the two scripts SQLite's `LOWER()` does not touch.
    #[test]
    fn cyrillic_and_greek_fold_to_a_matching_pair() {
        for (stem, typed) in [
            ("ВОЙНА.И.МИР.S01E01.1080p-GRP", "война и мир"),
            ("ΟΔΥΣΣΕΙΑ.2019.1080p.BluRay-GRP", "οδυσσεια"),
            ("ΕΛΛΗΝΙΚΑ.ΝΕΑ.S02E03-GRP", "ελληνικα νεα"),
        ] {
            let stored = stored(stem);
            assert!(!stored.is_empty(), "{stem} earned no stored fold");
            assert_eq!(stored, sql_twin(stem));
            // Every term of the typed query is a substring of it, which
            // is exactly what the `LIKE '%term%'` arm asks of SQLite.
            for term in query(typed).split(' ') {
                assert!(
                    stored.contains(term),
                    "{stored:?} does not contain {term:?}"
                );
            }
        }
    }

    /// Greek final sigma: capitals carry no sigma distinction, so the
    /// fold has to erase it or the two spellings never meet.
    #[test]
    fn greek_final_sigma_folds_to_the_medial_form() {
        assert_eq!(sql_twin("ΟΔΥΣΣΕΥΣ"), "οδυσσευσ");
        assert_eq!(sql_twin("οδυσσεύς"), "οδυσσεύσ");
        assert_eq!(query("ΟΔΥΣΣΕΥΣ"), query("οδυσσευς"));
    }

    /// The sparseness rule. An ASCII stem, and a non-ASCII stem that
    /// `LOWER()` already folds correctly, both store nothing.
    #[test]
    fn only_a_stem_lower_cannot_fold_earns_a_stored_value() {
        assert_eq!(stored("Show.Name.S01E02-GRP"), "");
        assert_eq!(stored("Wörld.Tour.2019"), "");
        assert_eq!(stored("Café.Society.1080p"), "");
        assert_eq!(stored("ВОЙНА"), "война");
        // Mixed: the Latin half folds either way, the Cyrillic half
        // does not, so the row is stored and carries BOTH halves.
        assert_eq!(stored("МИР.S01E02.WEB"), "мир s01e02 web");
    }

    /// `sql_twin` collapses nothing, because the SQL expression it
    /// mirrors collapses nothing; `query` collapses, because both sides
    /// of a Rust comparison do.
    #[test]
    fn only_the_query_form_collapses_whitespace() {
        assert_eq!(sql_twin("A..B"), "a  b");
        assert_eq!(query("A..B"), "a b");
        assert_eq!(query("  Show._.Name  "), "show name");
    }
}
