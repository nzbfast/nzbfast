//! Y1 (wave-4 follow-up, 31 Aug 2026): the TERMINATION pin for the
//! late-set pass.
//!
//! Row M4-58 asked what a reconstruct CYCLE - two recovery sets each
//! naming the other's packet files - does to this pass, and predicted
//! "a deadlock or an unbounded retry". The answer landed as a pass pin
//! (`two_sets_naming_each_others_packets_terminate_with_an_honest_verdict`
//! in `crates/nzbfast/tests/e2e_norar/repairpins.rs`) resting on two
//! findings. The first is a construction argument: a FileDesc binds its
//! covered file by content MD5, so a genuine two-way cycle needs a
//! mutual MD5 fixed point across two files, which is preimage-strength.
//! The second was STRUCTURAL - [`super::apply_nonactivated_disk_sets`]
//! was a single `for` over one `disk_sets_scoped` snapshot, so "an
//! unbounded retry" had nowhere to live - and it is that second finding
//! this module used to pin.
//!
//! IT NO LONGER HOLDS, BY DESIGN, and this module changed with it (31
//! Aug 2026). W4-12 is a genuine par2-of-par2 CHAIN where one pass
//! provably cannot reach the third link: applying the middle set is what
//! CREATES the inner one, and a census taken before the loop began
//! cannot contain it. Measured on the baseline, `movie.bin` was
//! delivered at 0 bytes. The pass is a bounded fixpoint now - re-census
//! after any set REPAIRS, retry ids that failed, stop on no progress -
//! so the old pin would have to be either deleted or relaxed, and the
//! note it carried said which: "FIX A HIT by deciding the cycle question
//! first, not by relaxing the depth". That is what these pins are.
//!
//! WHAT MAKES THE LOOP TERMINATE, in the order the assertions below
//! check it:
//!
//! * the ROUND loop is a bounded `for _ in 0..MAX_LATE_SET_ROUNDS`, and
//!   nothing in the function is a `loop` or a `while` - so the outer
//!   bound holds whatever any inner arm does;
//! * a round only CONTINUES when some set repaired, and every repaired
//!   id joins `settled`, which the set loop skips - so a set is run at
//!   most once per round and never again after it succeeds;
//! * the discovery call is at loop depth exactly 1 and the repair at
//!   exactly 2 - one round loop wrapping one set loop, and no third;
//! * the one call site in `crates/nzbfast/src/get/settle.rs` is still at
//!   loop depth 0, so the pass as a whole runs once per settle.
//!
//! AND X5-10 IS PINNED HERE TOO, because it is a statement about the
//! same loop: nothing this pass proves spent may be DELETED inside it. A
//! donor two sets both need is not spent until the second one is done
//! with it, so `sweep_spent_sources` is at loop depth 0 in this file,
//! and in settle.rs it comes AFTER the late-set call rather than before.
//! Measured on the baseline: `b.bin` delivered at 0 bytes, 12 runs of
//! 12.
//!
//! WHY THIS IS STRUCTURAL AND NOT BEHAVIOURAL, which is unchanged and is
//! the reason this module reads source at all. A second pass over the
//! same sets is very nearly IDEMPOTENT: the sets are still not in
//! `active`, `published_here` still holds, and the repair the second
//! time round answers `NoDamage` - which logs nothing, patches nothing
//! and changes no verdict. So a retry loop is invisible to every log
//! assertion and every byte comparison an e2e fixture could make. That
//! was measured by reading the arms, not assumed. Source-scanning
//! reflection tests are the house answer to that shape
//! (`crates/nzbfast/tests/integration/settings_catalogue.rs` is the
//! standing precedent), and `include_str!` binds the text at compile
//! time so the scan cannot go stale against a moved path.
//!
//! Loop DEPTH rather than a count of loops in the body: an inner `for`
//! over a report's file list is nobody's defect, and a gate that
//! reddens on one is a gate that gets loosened. Depth reddens on
//! exactly the edits this is about and on nothing else.

use std::collections::HashMap;

/// Blank every comment and every literal in `src`, preserving byte
/// offsets so a later index into the result indexes the original.
///
/// Needed because both files carry braces the brace walk must not see:
/// `info!`/`warn!` format strings are full of `{}` and `{needed}`, and
/// both files carry apostrophes in prose. It also has to tell
/// `leaf.starts_with('.')` - a real char literal in the scanned
/// function's own file - from `&'a str` in settle.rs, which is a
/// lifetime and has no closing quote to find.
///
/// `Err` on an unterminated construct: a lexer that has lost its place
/// must say so rather than hand back a brace count nobody can trust.
fn code_only(src: &str) -> Result<String, String> {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0usize;
    while i < b.len() {
        // A raw or byte string opener: `r"`, `r#`, `br"`, `br#`, `b"`.
        // Only when the letter starts a token, or `for` would look like
        // one every time it ended in `r`.
        let fresh = i == 0 || !ident(b[i - 1]);
        let raw = if fresh {
            match b[i] {
                b'r' => Some(i + 1),
                b'b' if b.get(i + 1) == Some(&b'r') => Some(i + 2),
                _ => None,
            }
            .filter(|&q| matches!(b.get(q), Some(b'"') | Some(b'#')))
        } else {
            None
        };
        if let Some(q) = raw {
            let hashes = b[q..].iter().take_while(|&&c| c == b'#').count();
            let open = q + hashes;
            if b.get(open) != Some(&b'"') {
                return Err(format!("raw string opener at byte {i} has no quote"));
            }
            let mut j = open + 1;
            loop {
                if j >= b.len() {
                    return Err(format!("unterminated raw string at byte {i}"));
                }
                if b[j] == b'"'
                    && b[j + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|&&c| c == b'#')
                        .count()
                        == hashes
                {
                    j += 1 + hashes;
                    break;
                }
                j += 1;
            }
            blank(&mut out, i, j);
            i = j;
            continue;
        }
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(b.len(), |p| i + p);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                // Rust block comments NEST, so this is a depth walk and
                // not a search for the first `*/`.
                let mut depth = 1usize;
                let mut j = i + 2;
                while depth > 0 {
                    match (b.get(j), b.get(j + 1)) {
                        (None, _) => return Err(format!("unterminated block comment at byte {i}")),
                        (Some(b'/'), Some(b'*')) => {
                            depth += 1;
                            j += 2;
                        }
                        (Some(b'*'), Some(b'/')) => {
                            depth -= 1;
                            j += 2;
                        }
                        _ => j += 1,
                    }
                }
                blank(&mut out, i, j);
                i = j;
            }
            b'"' => {
                let mut j = i + 1;
                loop {
                    match b.get(j) {
                        None => return Err(format!("unterminated string at byte {i}")),
                        Some(b'\\') => j += 2,
                        Some(b'"') => {
                            j += 1;
                            break;
                        }
                        _ => j += 1,
                    }
                }
                blank(&mut out, i, j);
                i = j;
            }
            b'\'' => {
                // Char literal or lifetime. `'\n'` and `'\''` are the
                // escape shape; `'x'` and `'é'` are one character wide;
                // anything else is a lifetime or a loop label, which
                // has no closing quote and must be left alone.
                let end = match b.get(i + 1) {
                    Some(b'\\') => {
                        // Past the backslash AND the character it
                        // escapes, or `'\''` ends on its own escape.
                        let mut j = i + 3;
                        while b.get(j).is_some_and(|&c| c != b'\'') {
                            j += 1;
                        }
                        b.get(j).map(|_| j + 1)
                    }
                    Some(&c) => {
                        let w = if c < 0x80 {
                            1
                        } else if c >= 0xF0 {
                            4
                        } else if c >= 0xE0 {
                            3
                        } else {
                            2
                        };
                        (b.get(i + 1 + w) == Some(&b'\'')).then_some(i + 2 + w)
                    }
                    None => return Err(format!("file ends in a quote at byte {i}")),
                };
                match end {
                    Some(j) => {
                        blank(&mut out, i, j);
                        i = j;
                    }
                    // A lifetime: step over the quote only.
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).map_err(|e| e.to_string())
}

/// Loop-brace depth at every occurrence of `needle`, keyed by byte
/// offset. Depth counts only braces opened by a `for` / `while` /
/// `loop` header, so a function body, a `match` arm and an `if` block
/// are all depth 0.
///
/// `Err` if the braces do not balance, which is the one thing that
/// would make every depth below it a lie.
fn loop_depths(code: &str, needle: &str) -> Result<HashMap<usize, usize>, String> {
    let b = code.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    // (is this brace a loop body, ...) - `true` is one level of depth.
    let mut stack: Vec<bool> = Vec::new();
    // A loop header seen but not yet closed by its `{`, with the
    // paren/bracket depth it was seen at: a closure body inside the
    // iterator expression (`for x in v.map(|y| { .. })`) opens a brace
    // deeper in, and it is not this loop's body.
    let mut pending: Option<usize> = None;
    let mut nest = 0usize;
    let mut hits: HashMap<usize, usize> = HashMap::new();
    let mut i = 0usize;
    while i < b.len() {
        if code[i..].starts_with(needle) && (i == 0 || !ident(b[i - 1])) {
            hits.insert(i, stack.iter().filter(|&&l| l).count());
        }
        match b[i] {
            b'(' | b'[' => nest += 1,
            b')' | b']' => nest = nest.saturating_sub(1),
            b'{' => {
                // Only the brace at the header's OWN paren depth is the
                // loop body, and only it consumes the header: a closure
                // brace inside the iterator expression must leave the
                // pending header for the real body still to come.
                let body = pending == Some(nest);
                if body {
                    pending = None;
                }
                stack.push(body);
            }
            b'}' => {
                if stack.pop().is_none() {
                    return Err(format!("a closing brace with nothing open at byte {i}"));
                }
            }
            b';' => pending = None,
            c if ident(c) && (i == 0 || !ident(b[i - 1])) => {
                let w = b[i..].iter().take_while(|&&c| ident(c)).count();
                let word = &code[i..i + w];
                // `for<'a>` is a higher-ranked bound, not a loop.
                let hrtb = word == "for" && b.get(i + w) == Some(&b'<');
                if matches!(word, "for" | "while" | "loop") && !hrtb {
                    pending = Some(nest);
                }
                i += w;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    if !stack.is_empty() {
        return Err(format!("{} brace(s) never closed", stack.len()));
    }
    Ok(hits)
}

/// The one depth of the one occurrence, or the reason there is not one.
fn only_depth(src: &str, needle: &str) -> Result<usize, String> {
    let code = code_only(src)?;
    let hits = loop_depths(&code, needle)?;
    match hits.len() {
        1 => Ok(*hits.values().next().expect("one hit")),
        n => Err(format!(
            "`{needle}` occurs {n} times in code, expected exactly 1"
        )),
    }
}

const LATESETS: &str = include_str!("../latesets.rs");
const SETTLE: &str = include_str!("../settle.rs");

/// The brace-matched body of `fn <name>`, off an already comment- and
/// literal-blanked source. `Err` rather than an empty string on every
/// way of not finding one, because "the function was renamed and the
/// scan silently matched nothing" is the rubber stamp this whole family
/// exists to refuse.
fn fn_body<'a>(code: &'a str, name: &str) -> Result<&'a str, String> {
    let sig = format!("fn {name}(");
    let at = code
        .find(&sig)
        .ok_or_else(|| format!("`fn {name}` not found"))?;
    if code[at + sig.len()..].contains(&sig) {
        return Err(format!("`fn {name}` occurs more than once"));
    }
    let open = at
        + code[at..]
            .find('{')
            .ok_or_else(|| format!("`fn {name}` has no body"))?;
    let b = code.as_bytes();
    let mut depth = 0usize;
    for (j, &c) in b.iter().enumerate().skip(open) {
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&code[open..=j]);
                }
            }
            _ => {}
        }
    }
    Err(format!("`fn {name}`'s body never closes"))
}

/// Does `code` use `word` as a whole token anywhere?
fn has_word(code: &str, word: &str) -> bool {
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let b = code.as_bytes();
    code.match_indices(word).any(|(i, _)| {
        (i == 0 || !ident(b[i - 1])) && b.get(i + word.len()).is_none_or(|&c| !ident(c))
    })
}

/// Y1, first half. The late-set pass is a BOUNDED fixpoint: one round
/// loop wrapping one set loop, the round loop's own bound a `for` over a
/// constant range, and no `loop` or `while` anywhere in the function.
///
/// Reverting the property is what this must fail on: turning the round
/// loop into `loop { .. }` or `while changed { .. }` fails the
/// no-unbounded-construct arm, and a third loop around either call moves
/// its depth. Both were driven against the real file before this landed.
///
/// FIX A HIT by keeping the bound, not by relaxing the assertion: the
/// cycle question M4-58 asked is answered here by `settled` (a set that
/// succeeded is never run again) AND by this cap (which holds even if
/// some future arm stops inserting into it), and either one alone is a
/// guard nothing falsifies.
#[test]
fn the_late_set_pass_is_a_bounded_fixpoint() {
    let code = code_only(LATESETS).expect("latesets.rs lexes");
    let body = fn_body(&code, "apply_nonactivated_disk_sets").expect("the pass has a body");
    assert!(
        !has_word(body, "loop") && !has_word(body, "while"),
        "the late-set pass may iterate only through bounded `for` loops - a \
         `loop` or a `while` here is exactly the unbounded retry M4-58's row \
         predicted, and `settled` alone is not a bound anything checks"
    );
    assert!(
        body.contains("for _ in 0..MAX_LATE_SET_ROUNDS"),
        "the round loop must be bounded by the named constant, so the cap is \
         a fact about the source and not about which arms happen to run"
    );
    assert!(
        code.contains("const MAX_LATE_SET_ROUNDS: usize = 8;"),
        "MAX_LATE_SET_ROUNDS must stay a small compile-time constant - a \
         computed bound is one a reader cannot check"
    );
    // A set that succeeded is never handed to the repair again, which is
    // what makes a cycle finite rather than merely capped.
    assert!(
        body.contains("settled.contains(&id)") && body.contains("settled.insert(id)"),
        "the set loop must skip ids this pass has already finished with - \
         without that a cycle spins until the round cap every time"
    );
    assert_eq!(
        only_depth(LATESETS, "disk_sets_scoped("),
        Ok(1),
        "the late-set discovery must be the body of the ONE round loop - at \
         depth 0 it is the single snapshot W4-12 loses the payload to, and \
         deeper it is a re-scan per SET"
    );
    assert_eq!(
        only_depth(LATESETS, "repair_dir_set_with_donors_scoped("),
        Ok(2),
        "the late-set repair must be the body of the ONE set loop inside the \
         ONE round loop - anything else is a third loop nothing here bounds"
    );
    assert_eq!(
        only_depth(SETTLE, "apply_nonactivated_disk_sets("),
        Ok(0),
        "the late-set pass must run once per settle - a loop around the CALL \
         is the same defect one level up and is the likelier way to write it"
    );
}

/// X5-13, and the half no behavioural row can reach: the pass may be
/// cancelled BETWEEN sets and never inside one.
///
/// `cancel_tests` grades what a latch raised BEFORE the call does - zero
/// repairs, measured in bytes on disk. The bound the row actually claims
/// is the other one, "at most ONE more set repair after the latch goes
/// up", and that is a fact about WHERE the reads are rather than about
/// any run: a test that raced a real latch against a real repair would
/// be asserting on the scheduler, which is this week's whole flake
/// theme. So it is pinned here, the way the round cap next door is.
///
/// THREE FACTS, and each one alone is satisfiable by a broken pass.
/// Both edges must exist (a check at the round edge only leaves a whole
/// round of set repairs uninterruptible, which on a par2-of-par2 post is
/// the entire pass); the SET edge must come before the repair call in
/// the same loop (after it, the check has already paid for the thing it
/// was meant to refuse); and the ROUND edge must come before the census
/// (`disk_sets_scoped` walks and PARSES every par2 file in the
/// directory, which is the second-longest thing here).
///
/// FIX A HIT by moving the read, never by deleting it, and never by
/// pushing one INSIDE `repair_dir_set_with_donors_scoped` - a repair
/// torn down halfway leaves a set half-applied, which is strictly worse
/// than the wait it saves and which no caller afterwards could tell from
/// a set that simply failed.
#[test]
fn the_late_set_pass_can_be_cancelled_between_sets_and_never_inside_one() {
    let code = code_only(LATESETS).expect("latesets.rs lexes");
    let checks = loop_depths(&code, "stopped(cancel,").expect("latesets.rs braces balance");
    let mut depths: Vec<usize> = checks.values().copied().collect();
    depths.sort_unstable();
    assert_eq!(
        depths,
        vec![1, 2],
        "the pass must read the cancel latch at BOTH edges - once in the round \
         loop (depth 1) and once in the set loop (depth 2). Got {checks:?}"
    );
    let census = *loop_depths(&code, "disk_sets_scoped(")
        .expect("latesets.rs braces balance")
        .keys()
        .next()
        .expect("the pass takes a census");
    let repair = *loop_depths(&code, "repair_dir_set_with_donors_scoped(")
        .expect("latesets.rs braces balance")
        .keys()
        .next()
        .expect("the pass repairs a set");
    let at = |d: usize| {
        *checks
            .iter()
            .find(|&(_, &v)| v == d)
            .map(|(k, _)| k)
            .unwrap_or_else(|| panic!("no cancel check at loop depth {d}"))
    };
    assert!(
        at(1) < census,
        "the ROUND edge must be read before the census it is meant to skip - \
         a check after `disk_sets_scoped` has already paid for the walk"
    );
    assert!(
        at(2) < repair,
        "the SET edge must be read before the repair it is meant to refuse - \
         a check after `repair_dir_set_with_donors_scoped` bounds nothing, \
         because the expensive thing has already run"
    );
}

/// Y1, second half - X5-10. Nothing this pass proves spent is DELETED
/// while a set that has not run yet might still need it.
///
/// Two facts, one per file: the late pass's own sweep is outside both of
/// its loops, and settle's deferred sweep of the ACTIVE sets' donors
/// comes after the late pass rather than before it. The second is an
/// ORDER assertion and not a presence one on purpose - the call existing
/// one line earlier is precisely the defect, and a presence check passes
/// it.
///
/// FIX A HIT by moving the sweep later, never by deleting it: a donor
/// left behind is F9's residue, which is a different row.
#[test]
fn nothing_is_swept_until_every_set_has_spoken() {
    assert_eq!(
        only_depth(LATESETS, "sweep_spent_sources("),
        Ok(0),
        "the late pass may sweep only outside its loops - a sweep inside them \
         deletes a donor the next set in the same pass still needs"
    );
    let settle = code_only(SETTLE).expect("settle.rs lexes");
    let late = settle
        .find("apply_nonactivated_disk_sets(")
        .expect("settle.rs calls the late-set pass");
    let sweep = settle
        .find("sweep_spent_sources(&spent)")
        .expect("settle.rs sweeps the deferred spent sources");
    assert!(
        late < sweep,
        "settle must sweep the sets' proven-spent donors AFTER the late-set \
         pass, not before it - the late pass is where the second set that \
         needs one runs"
    );
}

/// The scanner's own arms, because a source scan that has quietly
/// stopped matching reports a clean tree forever. Every case is a shape
/// one of the two scanned files actually carries.
#[test]
fn the_source_scanner_reads_the_shapes_these_two_files_carry() {
    // Braces inside a format string, which both files are full of.
    assert_eq!(code_only(r#"a("{x}") b"#).as_deref(), Ok(r#"a(     ) b"#));
    // A real char literal, and a lifetime, which have to part company.
    assert_eq!(code_only("x.f('.') y").as_deref(), Ok("x.f(   ) y"));
    assert_eq!(code_only("&'a str").as_deref(), Ok("&'a str"));
    assert_eq!(code_only(r"c('\'')").as_deref(), Ok("c(    )"));
    // Comments, including the nesting Rust allows.
    assert_eq!(code_only("a // b {\nc").as_deref(), Ok("a       \nc"));
    assert_eq!(
        code_only("a /* /* { */ */ b").as_deref(),
        Ok("a               b")
    );
    assert_eq!(code_only(r##"a r#"{"# b"##).as_deref(), Ok("a        b"));
    // Losing its place is a refusal, never a brace count.
    assert!(code_only("a /* b").is_err());
    assert!(code_only("a \"b").is_err());

    let d = |src: &str, n: &str| only_depth(&code_only(src).unwrap(), n);
    assert_eq!(d("fn f() { g(); }", "g("), Ok(0), "a fn body is not a loop");
    assert_eq!(d("fn f() { match x { A => g(), } }", "g("), Ok(0));
    assert_eq!(d("fn f() { for a in b { g(); } }", "g("), Ok(1));
    assert_eq!(d("fn f() { loop { for a in b { g(); } } }", "g("), Ok(2));
    assert_eq!(d("fn f() { while c { g(); } }", "g("), Ok(1));
    // The two shapes that would otherwise steal a loop's brace.
    assert_eq!(
        d("fn f() { for a in b.map(|y| { y }) { g(); } }", "g("),
        Ok(1),
        "a closure in the iterator expression is not the loop body"
    );
    assert_eq!(
        d("fn f<T>(t: T) where T: for<'a> Fn(&'a u8) { g(); }", "g("),
        Ok(0),
        "a higher-ranked bound is not a loop"
    );
    // Absent and duplicated are both failures, never a quiet zero.
    assert!(d("fn f() { }", "g(").is_err());
    assert!(d("fn f() { g(); g(); }", "g(").is_err());
    assert!(loop_depths("fn f() { ", "g(").is_err());
    assert!(loop_depths("} fn f() { }", "g(").is_err());

    // `fn_body` and `has_word`, the two arms the bounded-fixpoint pin
    // rests on. Every way of not finding a body is a refusal, because a
    // silent empty body passes every `!contains` above it.
    let fb = |src: &str, n: &str| fn_body(&code_only(src).unwrap(), n).map(str::to_string);
    assert_eq!(fb("fn f(a: u8) { g(); }", "f").as_deref(), Ok("{ g(); }"));
    assert_eq!(
        fb("fn f(a: u8) {\n  if x { y }\n}", "f").as_deref(),
        Ok("{\n  if x { y }\n}"),
        "the body runs to its OWN closing brace, not the first one"
    );
    assert!(fb("fn g() { }", "f").is_err(), "a renamed fn is a refusal");
    assert!(
        fb("fn f(a: u8) { } fn f(b: u8) { }", "f").is_err(),
        "two definitions of the name is a refusal, not the first one"
    );
    assert!(fb("fn f(a: u8) { g();", "f").is_err(), "an unclosed body");
    assert!(
        !has_word(&fb("fn f(a: u8) { /* loop { */ x; }", "f").unwrap(), "loop"),
        "the body is read off BLANKED source, so a commented-out loop is gone \
         and its brace never counts"
    );
    assert!(has_word("a loop {", "loop") && has_word("loop {", "loop"));
    assert!(
        !has_word("a looped b", "loop") && !has_word("a xloop b", "loop"),
        "a word arm that matched a substring would pass a body with no loop \
         in it and fail one with a `looped` identifier"
    );
    assert!(has_word("x;while c", "while") && !has_word("meanwhile", "while"));

    // And the real files lex to balanced braces, which is the floor
    // under every assertion in the pin above.
    for (name, src) in [("latesets.rs", LATESETS), ("settle.rs", SETTLE)] {
        let code = code_only(src).unwrap_or_else(|e| panic!("{name} does not lex: {e}"));
        assert!(
            loop_depths(&code, "fn ").is_ok_and(|h| h.len() > 3),
            "{name} must lex to balanced braces and reach its own functions"
        );
    }
}
