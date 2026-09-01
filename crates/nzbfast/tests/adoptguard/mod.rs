//! The guard that keeps the next fixture out of the `payload` trap, the
//! one waiver that says a fixture is deliberately in it, and the pin
//! that keeps the guard's parser attached to the lines it reads.
//!
//! A sibling module the way `harness/`, `scratch/` and `payloads/` are,
//! and declared by the SEVEN test binaries that reach a daemon or a
//! `nzbfast get`: `e2e`, `daemon`, `http_wedge`, `index_size_cap`,
//! `leak_soak`, `queue_soak` and `integration`. It was e2e-only for its
//! first day (31 Aug 2026) - `payloads/mod.rs` documents the trap and
//! hands out the generator that escapes it, and this refuses a fixture
//! that fell in - and the daemon binary was the follow-up named under
//! "What this does not close" in
//! `research/PAYLOAD-TRAP-GATE-DECISION-2026-08-31.md`, over a
//! generator measured WORSE than the one that motivated the original.

use std::path::Path;

/// Declare that a fixture's repair is MEANT to come out of the adoption
/// scan rather than out of the recovery set, and say why.
///
/// `dir` is the fixture's STAGING directory - the one whose child the
/// guard is handed. On the `nzbfast get` side that is `Fixture::dir`
/// (the guard sees `dir/out`); on the daemon side it is the directory
/// passed to `harness::serve`, which is where the daemon's own log is
/// written (the guard sees `dir/daemon-<port>.log`). ONE spelling for
/// both, deliberately: the daemon binary has no `Fixture`, and two
/// spellings of one waiver is how the next lane learns only the one in
/// front of it.
///
/// [`refuse_a_solve_that_solved_nothing`] refuses a repair that
/// completed with zero blocks rebuilt from parity and some adopted,
/// because four fixtures named for repairing from a recovery set were
/// silently in that state on 30 Aug 2026. A handful of fixtures are
/// legitimately there - a FileDesc naming the join of two posted halves
/// has no parity route by construction - and this is how they say so, at
/// the fixture, with the reason, rather than in a frozen list somewhere
/// else.
///
/// It is deliberately ONE-DIRECTIONAL: declaring adoption a fixture no
/// longer performs is not an error. A lane converting a fixture off a
/// repeating generator would otherwise have to delete this call in the
/// same commit, which is a collision between two lanes for no gain.
///
/// SCOPE IS THE DIRECTORY, so a suite that restarts a daemon in the same
/// `dir` waives both. `harness::serve` names its log per PORT for
/// exactly that reason, and a fixture wanting a narrower scope gives
/// each leg its own directory the way `daemon_donor` already does.
///
/// NO `dead_code` WAIVER, and that was measured rather than assumed: a
/// `[[test]]` target is compiled with `--cfg test`, so `guard_tests`
/// below is live in all seven binaries and calls this, which keeps it
/// reachable even in the five that have no adopting fixture of their
/// own. Checked with the waiver removed - clean in every one.
pub(crate) fn adoption_is_the_premise(dir: &Path, why: &str) {
    assert!(!why.trim().is_empty(), "the waiver needs a reason");
    std::fs::write(dir.join(ADOPTION_MARKER), why).unwrap();
}

/// The name of the marker [`adoption_is_the_premise`] writes and
/// [`refuse_a_solve_that_solved_nothing`] reads. A dotfile in the
/// fixture's STAGING directory, which is not the directory the repair's
/// adoption scan slides over, so it can never itself become a donor.
///
/// Measured on both sides rather than assumed. On the `get` path the
/// scan slides over the job directory under `--out`, and the marker sits
/// one level above it. On the daemon path the log lives in the directory
/// handed to `harness::serve` and every `--out` in the seven binaries is
/// a `complete` CHILD of that directory - censused 31 Aug 2026, 56 sites,
/// no exception, including the one that passes a RELATIVE `complete`
/// under a `current_dir` of the same directory.
const ADOPTION_MARKER: &str = ".adoption-is-the-premise";

/// **The forward guard on the repeating-payload trap** (31 Aug 2026,
/// follow-up 13c.1; the decision and its numbers are in
/// `research/PAYLOAD-TRAP-GATE-DECISION-2026-08-31.md`).
///
/// A repair that completes having rebuilt ZERO blocks from parity and
/// adopted some is a repair the recovery set did not do. Four fixtures
/// named for repairing from a recovery set were in exactly that state on
/// 30 Aug 2026 and every one of them was green
/// (`research/E2E-PARITY-BUDGET-CENSUS-2026-08-30.md`), because
/// `e2e.rs::payload` repeats itself every 131,072 bytes and the sliding
/// scan found each hole's twin elsewhere in the same file. Nothing said
/// so: the census that found it was taken with a temporary log dump that
/// no longer exists.
///
/// This is that census made permanent and made cheap. It fires on the
/// MECHANISM rather than on a proxy for it - three source-level screens
/// were measured first and the sharpest of them was 17 waivers against 0
/// enforced sites, with a real defect it could not see at all, because
/// what separates a defect from a sound fixture here is what the fixture
/// ASSERTS. Over the census's own table of nine adopters this trigger
/// fires on six, four of them the real defects, and stays silent on the
/// three whose parity did real work.
///
/// `sibling` is any path whose PARENT is the fixture's staging directory
/// - `dir/out` on the `get` path, `dir/daemon-<port>.log` on the daemon
/// path - which is where [`adoption_is_the_premise`] writes its marker.
///
/// FIX A HIT by building the damaged file with
/// `payloads::unique_payload` so the recovery set is the only route to a
/// repair - which is what all four of those fixtures did. If adoption
/// really is the fixture's premise, say so with
/// [`adoption_is_the_premise`], which takes a reason and puts it at the
/// fixture. NEVER quiet a hit by loosening this parser.
///
/// STATED LIMITS, so a green line is not read as more than it is. It
/// sees only what the log SAYS, in the spellings the production report
/// sites print today; a spelling it cannot read is a REFUSAL rather than
/// a quiet zero, and a rename that drops the vocabulary altogether is
/// what `the_production_report_sites_still_say_what_this_parser_reads`
/// below exists to refuse, anchored on the FIELD each site reads rather than
/// on the words it prints. It says nothing about a repair that rebuilt
/// one block and adopted a thousand - that shape is legitimate (a
/// hash-named copy of the same file is on disk and harvesting it is the
/// point), and the census read every such fixture by hand.
pub(crate) fn refuse_a_solve_that_solved_nothing(log: &str, sibling: &Path) {
    let excused = sibling
        .parent()
        .is_some_and(|d| d.join(ADOPTION_MARKER).exists());
    for line in log.lines() {
        if !line.contains("block(s) rebuilt") {
            continue;
        }
        let rebuilt = count_before(line, "block(s) rebuilt").unwrap_or_else(|| {
            panic!(
                "the repair line's rebuilt count no longer parses - this guard has \
                 gone blind, fix the parser rather than deleting it:\n{line}"
            )
        });
        // `repair.rs` omits the clause entirely at zero; `unpack.rs`
        // always prints it. Absent therefore means none adopted - but a
        // line that says "adopted" in a shape neither spelling covers is
        // a drift, not a zero.
        let adopted = match (
            count_before(line, "block(s) adopted from"),
            count_before(line, "adopted,"),
        ) {
            (Some(n), _) | (None, Some(n)) => n,
            (None, None) if line.contains("adopted") => panic!(
                "the repair line reports adoption in a spelling this guard cannot \
                 read - fix the parser rather than deleting it:\n{line}"
            ),
            (None, None) => 0,
        };
        if rebuilt == 0 && adopted > 0 && !excused {
            panic!(
                "this repair solved NOTHING from parity: {adopted} block(s) adopted, \
                 0 rebuilt. The recovery set was never load-bearing, so the row does \
                 not test what its name says - see `refuse_a_solve_that_solved_nothing`. \
                 Build the damaged file with `payloads::unique_payload`, or, if \
                 adoption really is this fixture's premise, call \
                 `adoptguard::adoption_is_the_premise(<staging dir>, <reason>)`.\n\
                 {line}\n(read from {})",
                sibling.display()
            );
        }
    }
}

/// The integer immediately to the left of `tail` on `line`, if there is
/// one. Returns `None` when `tail` is absent, so the caller can tell a
/// missing clause from an unparseable one.
fn count_before(line: &str, tail: &str) -> Option<u64> {
    let head = line.split_once(tail)?.0;
    head.rsplit(|c: char| !c.is_ascii_digit())
        .find(|s| !s.is_empty())?
        .parse()
        .ok()
}

/// Three views of `src`, all the same length as it, so a byte range
/// taken on one indexes the others and the original.
///
/// * `code` - comments and the INSIDE of every string, raw string and
///   char literal blanked. Paren matching and "does this invocation read
///   the field" run on this: the report lines themselves say `file(s)`,
///   so a scanner that counted parens inside a literal would lose its
///   place immediately.
/// * `text` - comments blanked, literals kept. Only `#[path = "..."]`
///   needs it, and it needs both the word and the value.
/// * `lits` - EVERYTHING blanked except the inside of string literals.
///   The needle checks run on this and the distinction is not a nicety:
///   the parser's adoption needle is `adopted,`, the argument list of
///   the very line it reads carries `r.blocks_adopted,`, and a needle
///   check over `text` therefore says "the word is there" about a line
///   that no longer prints it. MEASURED: with the check on `text`, the
///   one mutation this pin exists for - `repair.rs` renaming its clause
///   to `harvested out of` - passed green.
///
/// All three ignore comments, because every one of these report sites
/// carries a paragraph above it quoting the line it prints, this file
/// included.
fn blanked(src: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut code = src.to_vec(); // comments AND string interiors blanked
    let mut text = src.to_vec(); // comments blanked, literals kept
    let mut lits = vec![b' '; src.len()]; // string interiors ONLY
    let n = src.len();
    let mut i = 0;
    // Blank `[a, b)` in `code`, and in `text` too when `also_text`.
    // `also` is true for a COMMENT (blanked everywhere) and false for a
    // string or char interior (blanked in `code`, kept in `text`, and
    // copied into `lits`, which keeps nothing else).
    let blank = |code: &mut Vec<u8>,
                 text: &mut Vec<u8>,
                 lits: &mut Vec<u8>,
                 a: usize,
                 b: usize,
                 also: bool| {
        for k in a..b.min(n) {
            if !also {
                lits[k] = code[k];
            }
            code[k] = b' ';
            if also {
                text[k] = b' ';
            }
        }
    };
    while i < n {
        match src[i] {
            b'/' if i + 1 < n && src[i + 1] == b'/' => {
                let end = src[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(n, |p| i + p);
                blank(&mut code, &mut text, &mut lits, i, end, true);
                i = end;
            }
            b'/' if i + 1 < n && src[i + 1] == b'*' => {
                // Rust block comments NEST.
                let (start, mut depth) = (i, 0usize);
                while i < n {
                    if src[i] == b'/' && i + 1 < n && src[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if src[i] == b'*' && i + 1 < n && src[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                blank(&mut code, &mut text, &mut lits, start, i, true);
            }
            b'r' if matches!(src.get(i + 1), Some(b'"') | Some(b'#')) => {
                let mut h = i + 1;
                while src.get(h) == Some(&b'#') {
                    h += 1;
                }
                if src.get(h) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let hashes = h - i - 1;
                let close: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                let body = h + 1;
                let end = src[body..]
                    .windows(close.len().max(1))
                    .position(|w| w == close.as_slice())
                    .map_or(n, |p| body + p);
                blank(&mut code, &mut text, &mut lits, body, end, false);
                i = (end + close.len()).min(n);
            }
            b'"' => {
                let body = i + 1;
                let mut j = body;
                while j < n && src[j] != b'"' {
                    j += if src[j] == b'\\' { 2 } else { 1 };
                }
                blank(&mut code, &mut text, &mut lits, body, j.min(n), false);
                i = (j + 1).min(n);
            }
            b'\'' => {
                // A char literal, or a lifetime. Decode one char past
                // the quote (or one escape) and see whether a closing
                // quote follows; anything else is `'a` and only the
                // quote is consumed.
                let mut j = i + 1;
                if src.get(j) == Some(&b'\\') {
                    j += 2;
                    while j < n && src[j] != b'\'' {
                        j += 1;
                    }
                } else {
                    while j < n && (src[j] & 0xC0) == 0x80 {
                        j += 1;
                    }
                    j += 1;
                    while j < n && (src[j] & 0xC0) == 0x80 {
                        j += 1;
                    }
                }
                if src.get(j) == Some(&b'\'') {
                    blank(&mut code, &mut text, &mut lits, i + 1, j, false);
                    i = j + 1;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    (code, text, lits)
}

/// The logging macros a repair report can leave in a daemon log.
/// `println!`/`eprintln!` are in the list because the engine uses both
/// beside `tracing` - `repair.rs`'s "mapped repair declined" line is a
/// `println!` twenty lines above one of the sites below.
const LOG_MACROS: &[&str] = &[
    "info", "warn", "error", "debug", "trace", "println", "eprintln",
];

/// Byte ranges of every logging-macro invocation in `code`, whole,
/// including nested arguments.
fn log_invocations(code: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for name in LOG_MACROS {
        let pat: Vec<u8> = name.bytes().chain(std::iter::once(b'!')).collect();
        let mut from = 0usize;
        while let Some(p) = code[from..]
            .windows(pat.len())
            .position(|w| w == pat.as_slice())
        {
            let at = from + p;
            from = at + pat.len();
            // A whole word: `warn!` and not `dwarn!`.
            if at > 0 && (code[at - 1].is_ascii_alphanumeric() || code[at - 1] == b'_') {
                continue;
            }
            let mut o = at + pat.len();
            while code.get(o).is_some_and(|c| c.is_ascii_whitespace()) {
                o += 1;
            }
            if code.get(o) != Some(&b'(') {
                continue;
            }
            let (mut depth, mut j) = (0usize, o);
            while j < code.len() {
                match code[j] {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            assert!(
                depth == 0 && j < code.len(),
                "unbalanced parens after a `{name}!` - this scanner has lost its \
                 place and every verdict after it is worthless"
            );
            out.push((at, j + 1));
        }
    }
    out
}

/// The byte range of the `{ .. }` block that follows `at`, brace-matched
/// on the blanked copy. `None` when there is no `{` after it at all.
fn brace_body(code: &[u8], at: usize) -> Option<(usize, usize)> {
    let start = at + code[at..].iter().position(|c| *c == b'{')?;
    let (mut depth, mut i) = (0usize, start);
    while i < code.len() {
        match code[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((start, i + 1));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Byte offsets of every occurrence of `needle` in `hay`.
fn find_all(hay: &[u8], needle: &str) -> Vec<usize> {
    let n = needle.as_bytes();
    hay.windows(n.len())
        .enumerate()
        .filter(|(_, w)| *w == n)
        .map(|(i, _)| i)
        .collect()
}

/// Every Rust source file under a crate's `src`, recursively.
fn rust_sources(root: &Path, into: &mut Vec<std::path::PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(root)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", root.display()))
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rust_sources(&p, into);
        } else if p.extension().is_some_and(|x| x == "rs") {
            into.push(p);
        }
    }
}

/// What follows a `#[cfg(test)]` at byte `at`: the byte range of the
/// whole item when it opens a BLOCK, and the file it attaches when it is
/// a brace-less `mod <name>;`.
///
/// THE BRACE-LESS SHAPE IS THE WHOLE REASON THIS IS A FUNCTION. A
/// scanner that looks for the next `{` after a `#[cfg(test)]` runs
/// straight past `#[cfg(test)] use collect::collect_packet_files_bounded;`
/// (live in `par2repair.rs`) and past `#[cfg(test)] mod unit_tests;` and
/// masks whatever PRODUCTION item comes next instead. That is the exact
/// hole `tools/size-gate.py` and `tools/lock-gate.py` both carried, on
/// 58 files, with a 575-line function sitting behind it unseen; their
/// `--selftest` pins both shapes so nobody narrows them back, and the
/// fixture below does the same for this one.
fn cfg_test_item(
    file: &Path,
    code: &[u8],
    text: &[u8],
    at: usize,
) -> (Option<(usize, usize)>, Option<std::path::PathBuf>) {
    let n = code.len();
    let mut i = at + "#[cfg(test)]".len();
    let mut path_attr: Option<String> = None;
    loop {
        while i < n && code[i].is_ascii_whitespace() {
            i += 1;
        }
        if code.get(i) != Some(&b'#') {
            break;
        }
        // Skip one attribute, bracket-matched on the blanked copy so a
        // `]` inside its string cannot end it early.
        let start = i;
        i += 1;
        let mut depth = 0usize;
        while i < n {
            match code[i] {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    i += 1;
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                _ => {}
            }
            i += 1;
        }
        // `#[path = "..."]`: the VALUE is blanked in `code`, so read the
        // attribute out of `text`, where strings are kept.
        let raw = String::from_utf8_lossy(&text[start..i.min(n)]).to_string();
        if let Some(rest) = raw.split_once("path").and_then(|(_, r)| r.split_once('"')) {
            path_attr = rest.1.split_once('"').map(|(v, _)| v.to_string());
        }
    }
    let item = i;
    // The first `{` or `;` at depth zero decides which shape this is.
    let (mut depth, mut j) = (0usize, i);
    while j < n {
        match code[j] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'{' if depth == 0 => break,
            b';' if depth == 0 => {
                // Brace-less. A `mod <name>;` attaches a file; anything
                // else (`use`, `static`, `type`) is a one-liner with no
                // body to mask and no file to exclude.
                let head = String::from_utf8_lossy(&code[item..j]).to_string();
                let mut w = head.split_whitespace();
                if w.next() != Some("mod") {
                    return (None, None);
                }
                let name = match w.next() {
                    Some(x) => x.to_string(),
                    None => return (None, None),
                };
                let dir = file.parent().unwrap();
                if let Some(rel) = path_attr {
                    return (None, Some(dir.join(rel)));
                }
                let stem = file.file_stem().unwrap();
                for cand in [
                    dir.join(format!("{name}.rs")),
                    dir.join(stem).join(format!("{name}.rs")),
                ] {
                    if cand.is_file() {
                        return (None, Some(cand));
                    }
                }
                panic!(
                    "`#[cfg(test)] mod {name};` in {} resolves to no file - this \
                     scanner cannot say which source is test-only, so every \
                     verdict it gives is worthless",
                    file.display()
                );
            }
            _ => {}
        }
        j += 1;
    }
    if j >= n {
        return (None, None);
    }
    // Braced: mask the whole item, attributes included.
    let (mut d, mut k) = (0usize, j);
    while k < n {
        match code[k] {
            b'{' => d += 1,
            b'}' => {
                d -= 1;
                if d == 0 {
                    break;
                }
            }
            _ => {}
        }
        k += 1;
    }
    assert!(
        d == 0 && k < n,
        "unbalanced braces after a `#[cfg(test)]` in {} - this scanner has lost \
         its place",
        file.display()
    );
    (Some((at, k + 1)), None)
}

/// The guard's own selftest, in the spirit of the build-free gates: what
/// it protects against is a parser that has quietly stopped matching,
/// which reads as a clean suite forever. Both production spellings are
/// pinned by the line they must read, so is the refusal that keeps a
/// third spelling from becoming a silent zero - and so, since 31 Aug
/// 2026, are the PRODUCTION SITES those spellings come from.
#[cfg(test)]
mod guard_tests {
    use super::*;

    /// `crates/nzbfast/src/repair.rs`'s in-place report: the adoption
    /// clause is OMITTED at zero, so absent legitimately means none.
    const IN_PLACE: &str = "[repair] repair complete in 53.69ms ✔ (native, in place: \
         0 block(s) rebuilt across 1 file(s), 1 recreated, 1000 block(s) adopted from a.001, a.002)";
    /// `crates/nzbfast/src/unpack.rs`'s report, which always prints it.
    const UNPACKED: &str = "[par2] repaired ✔ (0 block(s) rebuilt, 12 adopted, 2 file(s) patched)";

    #[test]
    fn both_production_spellings_are_read() {
        assert_eq!(count_before(IN_PLACE, "block(s) rebuilt"), Some(0));
        assert_eq!(count_before(IN_PLACE, "block(s) adopted from"), Some(1000));
        assert_eq!(count_before(UNPACKED, "block(s) rebuilt"), Some(0));
        assert_eq!(count_before(UNPACKED, "adopted,"), Some(12));
        // A clause that is not there reads as absent, never as a zero
        // it invented.
        assert_eq!(count_before(UNPACKED, "block(s) adopted from"), None);
    }

    #[test]
    fn a_repair_that_solved_something_passes() {
        let unexcused = std::env::temp_dir().join("nzbfast-guard-none").join("out");
        refuse_a_solve_that_solved_nothing(
            "[repair] repair complete in 1ms ✔ (native, in place: 75 block(s) rebuilt \
             across 2 file(s), 1925 block(s) adopted from b.bin)",
            &unexcused,
        );
        refuse_a_solve_that_solved_nothing(
            "[par2] repaired ✔ (7 block(s) rebuilt, 0 adopted, 1 file(s) patched)",
            &unexcused,
        );
        refuse_a_solve_that_solved_nothing("[par2] no damage, set verifies ✔", &unexcused);
    }

    #[test]
    #[should_panic(expected = "solved NOTHING from parity")]
    fn a_repair_that_solved_nothing_is_refused() {
        refuse_a_solve_that_solved_nothing(
            IN_PLACE,
            &std::env::temp_dir().join("nzbfast-guard-none").join("out"),
        );
    }

    /// A rename that keeps the word is a REFUSAL and never a quiet zero -
    /// the one drift a parser can still see from the log alone.
    #[test]
    #[should_panic(expected = "spelling this guard cannot read")]
    fn an_unreadable_adoption_clause_is_refused() {
        refuse_a_solve_that_solved_nothing(
            "[repair] repair complete ✔ (native, in place: 0 block(s) rebuilt across 1 \
             file(s); 200 blocks were adopted elsewhere)",
            &std::env::temp_dir().join("nzbfast-guard-none").join("out"),
        );
    }

    /// The production files whose logging macros hold a `RepairReport`
    /// and print one of its counts, with how many such invocations each
    /// has. ANCHORED ON THE FIELD, which is the whole point: a rename of
    /// the log text does not rename `RepairReport::blocks_rebuilt`, so
    /// this population survives the one drift the log-side parser cannot
    /// see - a spelling that drops the vocabulary altogether.
    const REPORT_SITES: &[(&str, usize)] = &[
        ("nzbfast/src/get/settle/noset.rs", 1),
        ("nzbfast/src/repair/nativepass.rs", 1),
        ("nzbfast/src/unpack.rs", 2),
    ];

    /// The production files with a logging macro whose TEXT says
    /// `block(s) rebuilt`, and how many. This is the population
    /// `refuse_a_solve_that_solved_nothing` will actually parse, so a
    /// NEW line joining it is a refusal: somebody has to say whether the
    /// parser can read it.
    ///
    /// It is one larger than [`REPORT_SITES`] and the extra is
    /// `repair.rs`'s MAPPED report, which formats its count from a local
    /// rather than from a report. That site is legitimately outside the
    /// field-anchored population and outside the adoption rule below:
    /// the mapped route rebuilds straight out of the live ledger and has
    /// no adoption scan behind it, so there is no count for it to drop.
    ///
    /// BOTH ROSTERS MOVED ON 31 Aug 2026 and the reason is the arm
    /// earning its keep: origin/main hoisted the whole native pass out
    /// of `repair.rs` into `repair/nativepass.rs` for the size gate, and
    /// the IN-PLACE report went with it while the MAPPED one stayed. A
    /// pin that only asked "are the words still right" would have said
    /// yes; this one said the population had moved, which is the
    /// question a reader has to answer.
    ///
    /// AND AGAIN THE SAME DAY, for the same reason one directory over:
    /// the no-set path came out of `get/settle.rs` into
    /// `get/settle/noset.rs` (TODO 106), and `disk_par2_fallback` - the
    /// site both rosters name here - went with it. A pure move, so the
    /// counts are unchanged and only the paths shift. Two hoists in one
    /// day is what a size-gate ceiling does to a roster keyed on file
    /// paths; keep the counts as the thing being asserted and let the
    /// paths follow the code.
    const REBUILT_LINES: &[(&str, usize)] = &[
        ("nzbfast/src/get/settle/noset.rs", 1),
        ("nzbfast/src/repair.rs", 1),
        ("nzbfast/src/repair/nativepass.rs", 1),
        ("nzbfast/src/unpack.rs", 2),
    ];

    /// The one production helper that spells the successful repair's
    /// adoption clause. Both `repair/nativepass.rs`'s in-place report
    /// and `get/settle/noset.rs`'s disk-fallback report call it rather than
    /// writing the words out, so the pin follows it one hop.
    const CLAUSE_FN: &str = "adopted_from_clause";

    /// Both crates' source, every Rust file under `src`.
    fn all_sources() -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for c in ["nzbfast", "nzbkit"] {
            let src = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("crates/nzbfast has a parent")
                .join(c)
                .join("src");
            rust_sources(&src, &mut out);
        }
        assert!(
            out.len() > 200,
            "only {} sources reached - this scan has lost its tree",
            out.len()
        );
        out
    }

    /// Every source file that is TEST code: attached by a
    /// `#[cfg(test)] mod <name>;` somewhere, or by a plain `mod <name>;`
    /// inside a file that already is.
    ///
    /// The closure matters as much as the first hop. `unit_tests.rs` and
    /// its siblings are already inside test scope, so the modules THEY
    /// declare carry no `#[cfg(test)]` of their own - and a one-hop rule
    /// would scan those as production and report a unit test's
    /// `println!` as a live report site.
    fn test_only_sources(
        all: &[std::path::PathBuf],
    ) -> std::collections::BTreeSet<std::path::PathBuf> {
        let mut attached: std::collections::BTreeSet<std::path::PathBuf> =
            std::collections::BTreeSet::new();
        let read = |p: &Path| std::fs::read(p).unwrap();
        // First hop: the `#[cfg(test)]` declarations in every file.
        for p in all {
            let src = read(p);
            let (code, text, _) = blanked(&src);
            for at in find_all(&code, "#[cfg(test)]") {
                if let (_, Some(f)) = cfg_test_item(p, &code, &text, at) {
                    attached.insert(f);
                }
            }
        }
        // Closure: a `mod x;` inside a test file attaches a test file.
        loop {
            let mut grew = false;
            for p in attached.clone() {
                if !p.is_file() {
                    continue;
                }
                let src = read(&p);
                let (code, _, _) = blanked(&src);
                let dir = p.parent().unwrap();
                let stem = p.file_stem().unwrap();
                for at in find_all(&code, "mod ") {
                    let rest = &code[at + 4..];
                    let end = match rest.iter().position(|c| *c == b';' || *c == b'{') {
                        Some(e) if rest[e] == b';' => e,
                        _ => continue,
                    };
                    let name = String::from_utf8_lossy(&rest[..end]).trim().to_string();
                    if name.is_empty()
                        || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                    {
                        continue;
                    }
                    for cand in [
                        dir.join(format!("{name}.rs")),
                        dir.join(stem).join(format!("{name}.rs")),
                    ] {
                        if cand.is_file() && attached.insert(cand) {
                            grew = true;
                        }
                    }
                }
            }
            if !grew {
                break;
            }
        }
        attached
    }

    /// `p` as `<crate>/src/...`, the spelling the rosters above use.
    fn roster_name(p: &Path) -> String {
        let s = p.to_string_lossy().replace('\\', "/");
        let at = s.rfind("/crates/").expect("a path outside crates/");
        s[at + "/crates/".len()..].to_string()
    }

    /// **THE PIN** (31 Aug 2026, item 2 of the daemon-binary follow-up).
    ///
    /// `refuse_a_solve_that_solved_nothing` reads LOG TEXT. It refuses a
    /// rename that keeps the word "adopted" - there is a case for that
    /// above - but a rename that drops the word entirely ("harvested",
    /// say) disarms it in silence and reads as a clean suite forever.
    /// That is the failure mode this repo keeps writing gates about, and
    /// `repair.rs` is actively being reworked by the recovery-set lane.
    ///
    /// So the sites are found by the FIELD they read and then held to
    /// the words the parser needs. Three arms, and the third is the one
    /// that found something: a site holding a report and printing its
    /// `blocks_rebuilt` must print `blocks_adopted` too, because the
    /// guard takes an absent clause for a zero. `get/settle/noset.rs`'s
    /// disk-fallback report failed exactly that on the day this was
    /// written - it printed the rebuilt count alone, on the one path
    /// whose own `consumed` vector is the adoption scan's output, so a
    /// settle-path repair that solved nothing from parity was invisible
    /// to the guard. Fixed in the same commit.
    ///
    /// FAILING TO FIND IS FAILING. A tree with no sources, a file whose
    /// parens do not balance, a roster entry naming a file with no site,
    /// or a site in a file no roster names is a refusal - never a quiet
    /// pass. FIX A HIT by making the production line say what the parser
    /// reads, or by teaching the parser AND this pin together; never by
    /// deleting a roster row so the survivors agree.
    #[test]
    fn the_production_report_sites_still_say_what_this_parser_reads() {
        let (mut sites, mut rebuilt_lines) = (Vec::new(), Vec::new());
        let (mut invocations, mut scanned) = (0usize, 0usize);
        let all = all_sources();
        let test_only = test_only_sources(&all);
        assert!(
            test_only.len() > 100,
            "only {} test-only sources resolved - the `#[cfg(test)]` scan has \
             stopped matching, so unit-test log lines are about to be read as \
             production report sites",
            test_only.len()
        );
        for p in &all {
            if test_only.contains(p) {
                continue;
            }
            scanned += 1;
            let src = std::fs::read(p).unwrap();
            let (mut code, mut text, mut lits) = blanked(&src);
            // An INLINE `#[cfg(test)] mod tests { .. }` is test code in
            // a production file; mask it the same way.
            for at in find_all(&code, "#[cfg(test)]") {
                if let (Some((a, b)), _) = cfg_test_item(p, &code.clone(), &text.clone(), at) {
                    for k in a..b {
                        code[k] = b' ';
                        text[k] = b' ';
                        lits[k] = b' ';
                    }
                }
            }
            let name = roster_name(p);
            for (a, b) in log_invocations(&code) {
                invocations += 1;
                let (c, t) = (&code[a..b], &lits[a..b]);
                let has = |h: &[u8], n: &str| h.windows(n.len()).any(|w| w == n.as_bytes());
                if has(t, "block(s) rebuilt") {
                    rebuilt_lines.push(name.clone());
                }
                let (reads_rebuilt, reads_adopted) =
                    (has(c, "blocks_rebuilt"), has(c, "blocks_adopted"));
                if !reads_rebuilt && !reads_adopted {
                    continue;
                }
                sites.push(name.clone());
                let at = format!("{name} (bytes {a}..{b})");
                // ARM A - the rename guard.
                assert!(
                    !reads_rebuilt || has(t, "block(s) rebuilt"),
                    "{at} prints a report's `blocks_rebuilt` in words \
                     `refuse_a_solve_that_solved_nothing` cannot read. It looks \
                     for `block(s) rebuilt`; keep that spelling, or move the \
                     parser and this pin in the same commit."
                );
                assert!(
                    !reads_adopted
                        || has(t, "block(s) adopted from")
                        || has(t, "adopted,")
                        || has(c, CLAUSE_FN),
                    "{at} prints a report's `blocks_adopted` in words \
                     `refuse_a_solve_that_solved_nothing` cannot read. It looks \
                     for `block(s) adopted from` or `adopted,`, or for a call \
                     to `{CLAUSE_FN}`, whose own wording is pinned below; keep \
                     one of those, or move the parser and this pin in the same \
                     commit."
                );
                // ARM C - the completeness rule. The guard reads the
                // rebuilt count off this line and takes a missing
                // adoption clause for a zero, so a line that reports one
                // and not the other is a hole rather than a shorter
                // sentence.
                assert!(
                    !reads_rebuilt || reads_adopted,
                    "{at} reports a repair's `blocks_rebuilt` and never its \
                     `blocks_adopted`, so a repair that solved NOTHING from \
                     parity reads here as one that adopted nothing - which is \
                     the exact shape `refuse_a_solve_that_solved_nothing` \
                     exists to refuse. Print the adoption clause, in \
                     `repair.rs`'s spelling."
                );
            }
        }
        // ARM B - the two rosters, held exactly in BOTH directions.
        let tally = |v: &[String]| {
            let mut m = std::collections::BTreeMap::new();
            for n in v {
                *m.entry(n.clone()).or_insert(0usize) += 1;
            }
            m
        };
        let want = |r: &[(&str, usize)]| {
            r.iter()
                .map(|(n, c)| ((*n).to_string(), *c))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        sites.sort();
        rebuilt_lines.sort();
        assert_eq!(
            tally(&sites),
            want(REPORT_SITES),
            "the set of production sites printing a RepairReport's counts has \
             moved. A NEW one must be read and added here (does the parser \
             read its words?); a site that has GONE means the parser may have \
             lost its subject."
        );
        assert_eq!(
            tally(&rebuilt_lines),
            want(REBUILT_LINES),
            "the set of production lines saying `block(s) rebuilt` has moved. \
             Every one of them is parsed by \
             `refuse_a_solve_that_solved_nothing`, so a new one has to be read \
             before it is trusted."
        );
        // THE SHARED CLAUSE. Two of the sites above hand their wording
        // to one helper, so that is where the words have to be - and
        // there must be exactly ONE of it, because a second copy is how
        // two spellings start and only one of them gets renamed.
        let mut clause_defs = 0usize;
        for p in &all {
            if test_only.contains(p) {
                continue;
            }
            let src = std::fs::read(p).unwrap();
            let (code, _, lits) = blanked(&src);
            for at in find_all(&code, &format!("fn {CLAUSE_FN}")) {
                clause_defs += 1;
                let body = brace_body(&code, at).unwrap_or_else(|| {
                    panic!(
                        "`fn {CLAUSE_FN}` in {} has no body this scanner can read",
                        p.display()
                    )
                });
                assert!(
                    lits[body.0..body.1]
                        .windows(21)
                        .any(|w| w == b"block(s) adopted from"),
                    "`{CLAUSE_FN}` in {} no longer prints `block(s) adopted \
                     from`, so the two report sites that hand it their wording \
                     print something `refuse_a_solve_that_solved_nothing` \
                     cannot read.",
                    p.display()
                );
            }
        }
        assert_eq!(
            clause_defs, 1,
            "expected exactly one `fn {CLAUSE_FN}` in production - a second is \
             a second spelling waiting to be renamed on its own"
        );

        // FAILING TO FIND IS FAILING: an inert scanner shows a zero here
        // rather than a green.
        assert!(
            scanned > 100 && invocations > 500,
            "only {invocations} logging invocations over {scanned} production \
             files - this scanner has stopped matching and every verdict above \
             it is worthless"
        );
    }

    /// The scanner's own pins. Both halves are load-bearing and neither
    /// is visible in the real-tree run above: a `blanked` that stopped
    /// blanking would report the same rosters, because the words it
    /// would wrongly see sit in comments that quote the very lines under
    /// test; and a `log_invocations` that lost paren balance would slice
    /// the wrong text with nothing to say so.
    ///
    /// The fixture is assembled from ordinary literals rather than
    /// written out as one, because it has to contain a raw string and a
    /// raw string cannot hold itself.
    #[test]
    fn the_scanner_ignores_comments_and_string_parens() {
        let hash = "#";
        let src = [
            "// info!(\"1 block(s) rebuilt\", r.blocks_rebuilt) in a line comment\n".to_string(),
            "/* nor /* nested */".to_string(),
            " info!(\"{} block(s) rebuilt\", r.blocks_adopted) */\n".to_string(),
            "fn f() {\n".to_string(),
            "    let _ = \"info!( an unclosed paren ( inside a string\";\n".to_string(),
            format!("    let _ = r{hash}\"raw info!( not a site either\"{hash};\n"),
            "    let _ = '(';\n".to_string(),
            "    info!(target: \"par2\", \"repaired ({} block(s) rebuilt, {} adopted, \\\n"
                .to_string(),
            "        {} file(s) patched)\", r.blocks_rebuilt, r.blocks_adopted, n);\n".to_string(),
            "}\n".to_string(),
        ]
        .concat()
        .into_bytes();

        let (code, text, lits) = blanked(&src);
        for (what, v) in [("code", &code), ("text", &text), ("lits", &lits)] {
            assert_eq!(v.len(), src.len(), "blanking moved a byte offset in {what}");
        }

        // Exactly one site: the two in comments and the two inside
        // strings are all invisible, and the one real invocation is
        // paren-matched past `file(s)` and past `'('`.
        let found = log_invocations(&code);
        assert_eq!(found.len(), 1, "found {found:?}");
        let (a, b) = found[0];
        let has = |h: &[u8], n: &str| h.windows(n.len()).any(|w| w == n.as_bytes());
        let (inv, printed) = (&code[a..b], &lits[a..b]);
        assert!(has(printed, "block(s) rebuilt"), "sliced the wrong text");
        assert!(has(printed, "adopted,"), "the slice stopped short");
        assert!(
            has(printed, "file(s) patched)"),
            "a paren inside a string cut the slice"
        );

        // THE NEEDLE VIEW HOLDS ONLY WHAT IS PRINTED, and this is the
        // pin on the false negative that got past the first cut of this
        // scanner: the argument list carries `r.blocks_adopted,`, which
        // ENDS IN `adopted,` - so a needle check over anything that
        // keeps code would report the word present on a line that had
        // just been renamed to say `harvested`. Driven against the real
        // `repair.rs` before this was fixed, that mutation passed green.
        assert!(
            !has(&lits, "blocks_adopted"),
            "a field name reached the printed-text view"
        );
        // ...and the FIELD view holds only code. The two reads in the
        // comments above are gone from it entirely, which is what stops
        // a commented-out report site standing in for a live one.
        assert!(has(inv, "blocks_rebuilt") && has(inv, "blocks_adopted"));
        assert_eq!(
            code.windows(14).filter(|w| *w == b"blocks_rebuilt").count(),
            1,
            "a field name inside a comment read as a field"
        );
        // The `text` view is what `#[path = "..."]` is read out of, so
        // it keeps both the attribute word and its value.
        assert!(has(&text, "an unclosed paren"), "text lost a literal");
    }

    /// The marker excuses the fixture that wrote it and nothing else.
    #[test]
    fn the_waiver_excuses_only_its_own_fixture() {
        let dir = std::env::temp_dir().join(format!("nzbfast-guard-waiver-{}", std::process::id()));
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        adoption_is_the_premise(&dir, "because");
        refuse_a_solve_that_solved_nothing(IN_PLACE, &out);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
