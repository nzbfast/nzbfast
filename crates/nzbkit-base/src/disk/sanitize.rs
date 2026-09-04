//! Making one path COMPONENT safe: [`sanitize_filename`] and the
//! character rules behind it.
//!
//! Split out of `disk.rs` under the size gate (TODO 106) on 30 Aug
//! 2026, when two lanes' growth put that file 68 lines over the flat
//! 3,000 ceiling in one merge - neither over on its own. This is one
//! subject end to end (the char map, the trim, the leading-dot mapping,
//! the reserved DOS device names, and the `Cf` table the char map
//! consults) and nothing else in `disk.rs` names any of it, which is
//! what made it a seam rather than a slice. `disk.rs` re-exports both
//! public doors, so no caller outside changed.
//!
//! The TREE-preserving name that sits on top of this - the one every
//! member name actually goes through - is `disk/relpath.rs`, which
//! calls `sanitize_filename_for` per component and falls back to it
//! whole for a path it will not preserve. Read that module's header
//! before changing anything here: its output is a comparison KEY as
//! well as a path, so a rule changed in this file changes what matches
//! what, in places that do not look like path code.

/// True for a Unicode FORMAT character - general category `Cf`.
///
/// `char::is_control()` is general category `Cc` ONLY (the C0 and C1
/// ranges), and `Cf` is the category that actually makes a filename
/// lie: it is Unicode's own name for characters that affect how text
/// renders without being rendered themselves. U+202E RIGHT-TO-LEFT
/// OVERRIDE is the sharp one - a PAR2 FileDesc of
/// `readme\u{202e}gpj.exe` lands as a file whose 16 bytes end `.exe`
/// and whose DISPLAYED name in Finder, Explorer and the terminal ends
/// `.jpg`. Measured 30 Aug 2026 end to end: it reached disk verbatim,
/// and the `[extract] renamed ... → readme\u{202e}gpj.exe` line printed
/// by the engine was spoofed too, so the log a user reads to check what
/// happened told the same lie the directory listing did. The
/// zero-width half (U+200B..U+200D, U+2060, U+FEFF, U+00AD, the
/// U+E0020 tag block) is the quieter one: two names that differ by an
/// invisible character are two files a person cannot tell apart.
///
/// Cost, stated rather than hidden: a name that legitimately carries a
/// soft hyphen or an Arabic number sign gets a `_` there. That is the
/// same trade every other mapping in [`sanitize_filename_for`] makes,
/// and a filename is not running text.
///
/// `Cs` (surrogates) needs no arm - a Rust `&str` cannot hold one. `Co`
/// (private use) is deliberately NOT here: those characters are
/// VISIBLE (a box, or a vendor glyph), so they spoof nothing, and
/// mapping them would break a legitimate name on a system that has the
/// font.
///
/// The table is Unicode 15.1.0 - 170 characters in 21 ranges - and
/// there is no Unicode-category crate anywhere in this workspace to
/// ask instead (`unicode-ident` is a proc-macro dependency and exposes
/// identifier classes only). Re-derive it, rather than hand-editing,
/// when a Unicode version adds to the category:
///
/// ```text
/// python3 - <<'EOF'
/// import unicodedata as u
/// print(u.unidata_version,
///       [hex(c) for c in range(0x110000) if u.category(chr(c)) == 'Cf'])
/// EOF
/// ```
///
/// It prints `unidata_version` first for a reason: an interpreter
/// carries whatever Unicode version it was built against, and the
/// system `python3` on this dev box is 13.0 (161 characters), which
/// would read as this table being four ranges too wide rather than as
/// the interpreter being two releases behind. Check that number before
/// changing anything here.
///
/// `format_chars_match_the_unicode_category` pins the whole table
/// against the characters this repo cares about, in both directions.
fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00ad}'                     // SOFT HYPHEN
        | '\u{0600}'..='\u{0605}'      // ARABIC NUMBER SIGN .. NUMBER MARK ABOVE
        | '\u{061c}'                   // ARABIC LETTER MARK
        | '\u{06dd}'                   // ARABIC END OF AYAH
        | '\u{070f}'                   // SYRIAC ABBREVIATION MARK
        | '\u{0890}'..='\u{0891}'      // ARABIC POUND .. PIASTRE MARK ABOVE
        | '\u{08e2}'                   // ARABIC DISPUTED END OF AYAH
        | '\u{180e}'                   // MONGOLIAN VOWEL SEPARATOR
        | '\u{200b}'..='\u{200f}'      // ZERO WIDTH SPACE .. RIGHT-TO-LEFT MARK
        | '\u{202a}'..='\u{202e}'      // LEFT-TO-RIGHT EMBEDDING .. RIGHT-TO-LEFT OVERRIDE
        | '\u{2060}'..='\u{2064}'      // WORD JOINER .. INVISIBLE PLUS
        | '\u{2066}'..='\u{206f}'      // LEFT-TO-RIGHT ISOLATE .. NOMINAL DIGIT SHAPES
        | '\u{feff}'                   // ZERO WIDTH NO-BREAK SPACE (BOM)
        | '\u{fff9}'..='\u{fffb}'      // INTERLINEAR ANNOTATION ANCHOR .. TERMINATOR
        | '\u{110bd}'                  // KAITHI NUMBER SIGN
        | '\u{110cd}'                  // KAITHI NUMBER SIGN ABOVE
        | '\u{13430}'..='\u{1343f}'    // EGYPTIAN HIEROGLYPH FORMAT CONTROLS
        | '\u{1bca0}'..='\u{1bca3}'    // SHORTHAND FORMAT LETTER OVERLAP .. UP STEP
        | '\u{1d173}'..='\u{1d17a}'    // MUSICAL SYMBOL BEGIN BEAM .. END PHRASE
        | '\u{e0001}'                  // LANGUAGE TAG
        | '\u{e0020}'..='\u{e007f}'    // TAG SPACE .. CANCEL TAG
    )
}

/// Make a filename safe as a single path component. Neutralises path
/// separators and NUL, ASCII control characters (which have no place in a
/// filename and can confuse terminals/loggers), and - so a crafted archive
/// entry or NZB name is portable and can't open a device on Windows - the
/// reserved DOS device names (CON, NUL, COM1..9, LPT1..9, AUX, PRN),
/// trailing dots/spaces that Windows silently strips, and (on Windows
/// only) the characters Win32/NTFS refuses outright: `:` `<` `>` `"` `|`
/// `?` `*`.
pub fn sanitize_filename(name: &str) -> String {
    sanitize_filename_for(name, cfg!(windows))
}

/// `sanitize_filename` with the platform as a parameter, so the Windows-only
/// guarantee is asserted by the suite on every host. A `cfg!`-only guard would
/// leave that test vacuous on the Mac and Linux boxes we actually develop and
/// run CI on - the trap an earlier filesystem-behaviour test fell into.
pub fn sanitize_filename_for(name: &str, windows: bool) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            // Windows only: ':' carries path meaning even with no separator.
            // "C:evil.dll" is a DRIVE-RELATIVE path, and `Path::join` DISCARDS
            // the base when the joined name has a prefix - so an archive entry
            // named that way escapes the download directory entirely (it lands
            // in the process's cwd on C:, which for the installed app is the
            // directory holding nzbfast.exe = first in the DLL search order).
            // "payload.mkv:hidden" is the other half: an NTFS alternate data
            // stream, where the payload writes into the stream and the visible
            // file is left 0 bytes. Neither is a legal Windows filename, so
            // mapping it costs nothing there; on Unix ':' is legal and common
            // in release names ("Movie: The Sequel.mkv"), so leave it alone.
            ':' if windows => '_',
            // The rest of the Win32/NTFS illegal set. Unlike ':' these carry
            // no path meaning - they simply make the create FAIL: NTFS
            // validates the leaf name and NtCreateFile returns
            // STATUS_OBJECT_NAME_INVALID (ERROR_INVALID_NAME, 123), which
            // `relpath::winbind::create_at` propagates straight out of
            // `FileWriter::create_under`, so a poster-declared
            // "Who Are You?.flac" (or a PAR2 FileDesc named `What*.mkv`, or an
            // ID3-composed track title carrying a quote) cannot be written at
            // all and the job fails with an OS error for a name this function
            // exists to make portable. Windows-gated for the same reason ':'
            // is: all six are legal and ordinary on unix, and mapping them
            // there would corrupt a legitimate name.
            '<' | '>' | '"' | '|' | '?' | '*' if windows => '_',
            c if c.is_control() => '_',
            // M4-67: `is_control()` is general category Cc ONLY, and the
            // characters that make a filename lie are Cf - see
            // [`is_format_char`], which carries the measurement.
            c if is_format_char(c) => '_',
            // M4-104: U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR
            // are category Zl/Zp, not Cf, so `is_format_char` correctly
            // says no - but both are `White_Space`, which means the trim
            // below removes them at the ENDS of a name and leaves them
            // untouched in the MIDDLE, where a published filename renders
            // as two lines in a terminal, a log, an *arr import record and
            // the dashboard. NOT `is_whitespace()`: that is also true of
            // U+00A0 NO-BREAK SPACE, which is legitimate in release names,
            // and of ordinary ASCII space - the question here is the
            // CATEGORY, and only these two carry it.
            '\u{2028}' | '\u{2029}' => '_',
            c => c,
        })
        .collect();
    // Windows FOLDS trailing dots and spaces ("evil. " and "evil" are one
    // file there), so strip them for a stable, portable name. The strip is
    // repeated to a fixed point in ONE pass rather than as an alternating
    // trim chain, because the old `.trim().trim_matches('.').trim()` was not
    // one: peeling the outer dots exposed INTERIOR dots as the new ends, and
    // ". .. ." came out as ".." (". . ." as "."). Both are non-empty, so they
    // used to be returned verbatim - a single path component that escapes its
    // parent. Every caller joins this straight onto a root
    // (`out_dir/<category>/<stem>`) and nothing re-checks containment, so a
    // category or NZB name of ". .. ." put the payload outside the download
    // root, and "Remove + delete files" then ran `remove_dir_all` on that
    // parent. Trailing-side now, a result can never END in a dot, so ".." and
    // "." are unreachable by construction and the all-dot guard below is the
    // belt rather than the brace.
    let trimmed = cleaned
        .trim_start()
        .trim_end_matches(|c: char| c == '.' || c.is_whitespace());
    // A name that is nothing but dots and spaces has no meaning worth
    // preserving, and this is what keeps ".", ".." and "..." out. It runs
    // BEFORE the leading-dot mapping below on purpose: those three must stay
    // "unnamed" (they are traversal, or nobody's directory), not become "_",
    // "__" and "___".
    if trimmed.is_empty() || trimmed.chars().all(|c| c == '.') {
        return "unnamed".to_string();
    }
    // M4-66: leading dots are MAPPED, one `_` each, and never deleted.
    //
    // Deleting them was a genuine many-to-one collapse of two names that are
    // both legal and distinct on every filesystem this product targets -
    // Windows folds TRAILING dots, not leading ones - so a PAR2 set declaring
    // both `.movie.mkv` and `movie.mkv` had two payloads and one on-disk
    // name. Measured 30 Aug 2026 on a two-FileDesc no-RAR post: on a CLEAN
    // run `PublishedNames` caught the collision and the second file landed
    // under the `{slot:03}-` convention, so nothing was lost; add ONE damaged
    // article and the collision resolves the other way, repair addresses the
    // set member by its canonical name, finds the other file's bytes there
    // and REBUILDS over them (the W4-18 mechanism `get::publishplan` already
    // writes up), and the displaced payload survives only as
    // `movie.bin.dup-<hex>` - a machine name, at rc=0, with nothing in the
    // log saying a declared name was lost.
    //
    // Mapping rather than PRESERVING the dot, which is the other repair the
    // row offered: a leading-dot name is furniture to this product, in at
    // least three passes that would then skip or sweep a real payload -
    // `smart::nzbname::is_furniture` (a dotfile can never be the main
    // payload), `repair.rs`'s unclaimed-file scan, and `identity.rs`'s
    // release-name candidates - so honouring the dot trades a name collision
    // for an invisibility bug. `_` is what every other unsafe character in
    // this function already maps to, is legal everywhere, and keeps the
    // result visible.
    //
    // The whole leading RUN maps, one `_` per dot, so `.a` and `..a` stay
    // distinct too; collapsing to a single dot would re-create the very
    // defect one character over. What it does NOT buy is injectivity against
    // a poster's LITERAL `_movie.mkv`, which is the same residue every other
    // `_` mapping here leaves and is what `PublishedNames` is for.
    let dots = trimmed.len() - trimmed.trim_start_matches('.').len();
    let trimmed = if dots > 0 {
        format!("{}{}", "_".repeat(dots), &trimmed[dots..])
    } else {
        trimmed.to_string()
    };
    // Reserved DOS device names match case-insensitively on the stem before
    // the first dot (CON, con.txt, and "CON " all open the console device).
    // Normalise for the match: uppercase, map the Unicode superscript digits
    // Windows folds to 1/2/3 (COM\u{B9} opens COM1), and drop a trailing '$'
    // (CLOCK$/CONIN$/CONOUT$ handles).
    let raw_stem = trimmed.split('.').next().unwrap_or(&trimmed).trim();
    let stem: String = raw_stem
        .trim_end_matches('$')
        .chars()
        .map(|c| match c {
            '\u{B9}' => '1', // superscript one
            '\u{B2}' => '2', // superscript two
            '\u{B3}' => '3', // superscript three
            c => c.to_ascii_uppercase(),
        })
        .collect();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK" | "CONIN" | "CONOUT"
    ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.len() == 4
        && stem.as_bytes()[3].is_ascii_digit()
        && stem.as_bytes()[3] != b'0');
    if reserved {
        format!("_{trimmed}")
    } else {
        trimmed
    }
}

/// The file extension, immune to the trailing dot or space Windows
/// folds away - the same trim [`sanitize_filename_for`] applies before
/// it does anything else. `std::path::Path::extension()` does not do
/// this: `Path::new("comic.cbr.").extension()` is `Some("")` and
/// `Path::new("comic.cbr ").extension()` is `Some("cbr ")`, so a name
/// carrying either tail defeats every `Path::extension()`-based
/// deny-list guard, silently, in the destructive direction - it makes a
/// container that IS the deliverable (`.cbr`, `.cbz`, ...) read as "not
/// final" and earns it the archive chase (T6).
///
/// Otherwise mirrors `Path::extension()`: a name that is only leading
/// dots after a dot, or with no dot at all, has none.
pub(crate) fn trimmed_extension(name: &str) -> Option<&str> {
    let trimmed = name.trim_end_matches(|c: char| c == '.' || c.is_whitespace());
    let after_leading_dots = trimmed.trim_start_matches('.');
    let (_, ext) = after_leading_dots.rsplit_once('.')?;
    (!ext.is_empty()).then_some(ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Cf table in `is_format_char` is hand-maintained (no
    /// Unicode-category crate exists in this workspace), so it is pinned
    /// against an INDEPENDENTLY spelled copy of the same ranges, at every
    /// boundary in both directions. A mistyped hex digit or an off-by-one
    /// endpoint fails here rather than silently letting one character
    /// through forever - which is the failure mode a hit count can never
    /// show, because the table going quiet reads exactly like a clean tree.
    ///
    /// Re-derive both spellings together when a Unicode version adds to the
    /// category; the command is in `is_format_char`'s own doc comment.
    #[test]
    fn format_chars_match_the_unicode_category() {
        // Unicode 15.1.0, general category Cf: 170 characters in 21 ranges.
        const CF: &[(u32, u32)] = &[
            (0x00ad, 0x00ad),
            (0x0600, 0x0605),
            (0x061c, 0x061c),
            (0x06dd, 0x06dd),
            (0x070f, 0x070f),
            (0x0890, 0x0891),
            (0x08e2, 0x08e2),
            (0x180e, 0x180e),
            (0x200b, 0x200f),
            (0x202a, 0x202e),
            (0x2060, 0x2064),
            (0x2066, 0x206f),
            (0xfeff, 0xfeff),
            (0xfff9, 0xfffb),
            (0x110bd, 0x110bd),
            (0x110cd, 0x110cd),
            (0x13430, 0x1343f),
            (0x1bca0, 0x1bca3),
            (0x1d173, 0x1d17a),
            (0xe0001, 0xe0001),
            (0xe0020, 0xe007f),
        ];
        let total: u32 = CF.iter().map(|(a, b)| b - a + 1).sum();
        assert_eq!(total, 170, "the range list is no longer Unicode 15.1's Cf");
        assert_eq!(CF.len(), 21);
        // Every member matches...
        let mut seen = 0u32;
        for &(a, b) in CF {
            for cp in a..=b {
                let c = char::from_u32(cp).expect("Cf holds no surrogate");
                assert!(is_format_char(c), "U+{cp:04X} is Cf and was not matched");
                seen += 1;
            }
            // ...and the characters just OUTSIDE each range do not, which is
            // what catches an off-by-one endpoint or a mistyped digit.
            for edge in [a.checked_sub(1), b.checked_add(1)] {
                let Some(cp) = edge else { continue };
                if CF.iter().any(|&(x, y)| (x..=y).contains(&cp)) {
                    continue; // adjacent ranges: not an outside edge
                }
                let Some(c) = char::from_u32(cp) else {
                    continue;
                };
                assert!(
                    !is_format_char(c),
                    "U+{cp:04X} is outside Cf and was matched"
                );
            }
        }
        assert_eq!(seen, 170);
        // Neighbours that are emphatically NOT Cf, so `is_format_char`
        // correctly says no to all of them: U+00A0 is Zs (and `trim`
        // already handles it), U+2065 is unassigned, U+E000 is private
        // use - visible characters this function deliberately does not
        // map. U+2028/U+2029 are Zl/Zp and ARE mapped, but by a dedicated
        // arm in `sanitize_filename_for` (M4-104) rather than by this
        // function - see `line_and_paragraph_separators_are_mapped_not_left_to_trim`.
        for cp in [
            0x0020u32, 0x0041, 0x00a0, 0x2028, 0x2029, 0x2065, 0xe000, 0x1f600,
        ] {
            let c = char::from_u32(cp).unwrap();
            assert!(!is_format_char(c), "U+{cp:04X} is not Cf but was matched");
        }
    }

    /// M4-104: U+2028/U+2029 are `White_Space` but not Cf, so the trim
    /// removed them at the ends of a name and left them untouched in the
    /// middle - a published filename that renders as two lines. Pin the
    /// category rather than the literals: mapped in the middle, AND a
    /// legitimate `White_Space` neighbour (U+00A0 NO-BREAK SPACE, common
    /// in release names) must survive untouched, in the same test, or the
    /// fix trades one wrong name for a worse one.
    #[test]
    fn line_and_paragraph_separators_are_mapped_not_left_to_trim() {
        assert_eq!(
            sanitize_filename_for("Movie\u{2028}Name.mkv", false),
            "Movie_Name.mkv"
        );
        assert_eq!(
            sanitize_filename_for("Movie\u{2029}Name.mkv", false),
            "Movie_Name.mkv"
        );
        // A no-break space in the middle of a release name is legitimate
        // and must not be touched - only the category matters here.
        assert_eq!(
            sanitize_filename_for("Movie\u{00a0}Name.mkv", false),
            "Movie\u{00a0}Name.mkv"
        );
    }

    /// T6: a trailing dot or space must not defeat the extension read -
    /// `Path::extension()` answers `Some("")` or `Some("cbr ")` for these,
    /// neither of which matches a deny-list entry, which is exactly how a
    /// `.cbr` comic earned the archive chase.
    #[test]
    fn trailing_dot_or_space_does_not_hide_the_extension() {
        assert_eq!(trimmed_extension("comic.cbr"), Some("cbr"));
        assert_eq!(trimmed_extension("comic.cbr."), Some("cbr"));
        assert_eq!(trimmed_extension("comic.cbr.."), Some("cbr"));
        assert_eq!(trimmed_extension("comic.cbr "), Some("cbr"));
        assert_eq!(trimmed_extension("comic.cbr . "), Some("cbr"));
        assert_eq!(trimmed_extension("comic.CBR"), Some("CBR"));
    }

    /// Otherwise mirrors `Path::extension()`, including its hidden-file
    /// carve-out - widening that is a different question than T6 asks.
    /// `"trailing."` is deliberately NOT in this list: `Path::extension()`
    /// answers `Some("")` there, which is exactly the shape T6 exists to
    /// stop being trusted, and `trimmed_extension` answers `None` instead.
    #[test]
    fn trimmed_extension_matches_path_extension_elsewhere() {
        for name in [
            "movie.mkv",
            "noext",
            "..",
            ".",
            "",
            ".hidden",
            ".hidden.txt",
            "a.b.c",
        ] {
            assert_eq!(
                trimmed_extension(name),
                std::path::Path::new(name)
                    .extension()
                    .map(|e| e.to_str().unwrap()),
                "mismatch for {name:?}"
            );
        }
    }
}
