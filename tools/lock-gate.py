#!/usr/bin/env python3
"""Refuse new poison-intolerant lock sites in production code. TODO 102b.

`crates/nzbkit-base/src/sync.rs` exists because a panicking worker used to take the
whole daemon down with it: every other thread touching the same mutex inherited
the poison and panicked in turn. `lock_ok()` / `read_ok()` / `write_ok()`
recover the guard instead, and the 1 Aug sweep converted ~1,000 sites to them.

Then new code went back to `.lock().unwrap()`. The 3 Aug scorecard predicted
that a second sweep would not hold either, and it was right - `spawn_watch_folder`
alone had grown three fresh sites by 4 Aug. This is the gate it asked for
instead.

Why a script and not clippy's `disallowed-methods`: that lint cannot see
`#[cfg(test)]`, so with CI's `-D warnings` it would fail on ~70 test-side sites
where `.unwrap()` is the RIGHT call - a test SHOULD die on a poisoned lock. The
alternative was ~70 `#[allow]` annotations sprayed across files that other
concurrent sessions are editing. This resolves test scope properly instead.

Why the site regex spans NEWLINES, which cost it its own credibility for
nineteen days: it used to be `\\.(lock|read|write)\\(\\)\\.unwrap\\(\\)` applied
one line at a time, and rustfmt breaks a long method chain across lines, so
`.lock()` and `.unwrap()` land on separate lines and the pattern never saw
them. The gate printed "0 poison-intolerant lock sites in production" from the
day it landed and that zero was false: 99 sites matched the split shape on
22 Aug 2026, ~80 of them production, including `sab_warnings` in
`crates/nzbfast-api/src/sabcompat.rs` - request-path code polled by
`mode=status`, exactly what the gate was built to cover. A lane that ran the
documented gates, read the zero and shipped was trusting nothing. The matcher
now runs over the whole file text with `\\s*` (which includes `\\n`) between the
two calls, and a hit is reported at the line the `.lock()` is on. `\\s` cannot
cross a comment, so the span can only ever be the rustfmt wrap it is there for.

Why the scope resolver EVALUATES a cfg predicate rather than matching one
spelling, added 23 Aug 2026. It recognised the literal `#[cfg(test)]` and
nothing else, and this repo also uses the combined form widely - fifteen
`#[cfg(all(test, feature = "indexer"))]` and seven `#[cfg(all(test, unix))]`
on the day, in `crates/nzbfast/src/nettools.rs` and
`crates/nzbfast/src/serve/groupscan.rs` among others. Every `.lock().unwrap()`
inside one of those was reported as a PRODUCTION site. Found while adding a
test to groupscan.rs, which was then rewritten to use atomics - better code
anyway - so nothing on the tree tripped it and the defect stayed latent
rather than live.

This one runs the OPPOSITE way to the newline widening above: it produced
FALSE POSITIVES only, never false negatives, and it has to stay that way. A
careless widening - anything that treats "the predicate mentions test" as
test scope - hands a waiver to `#[cfg(any(unix, test))]`, which is compiled
into every unix release build (six live in this tree), and to
`#[cfg(not(test))]`, which is the exact opposite of test scope. That is the
rubber stamp this whole gate family exists to refuse. So cfg_is_test_only()
evaluates the predicate three-valued with `test` off and calls it test scope
only when the answer is definitely FALSE; an unparseable predicate is
production. The selftest pins both ends.

Usage:
    tools/lock-gate.py            # gate: exit 1 if any production site exists
    tools/lock-gate.py --list     # report every site, test ones included
    tools/lock-gate.py --selftest # prove the gate still sees both shapes

`.lock().expect("...")` was added on 22 Aug 2026 as well: nothing in
production used it at the time (the only three sites were test-scoped, in
crates/nzbkit-base/src/nntp/unit_tests.rs, where `.expect()` is the right call), so
this is about refusing the first new one, not a sweep.
"""

import os
import re
import sys

CRATES = "crates"
# `.lock()`, `.read()` and `.write()` are all std lock APIs; `.unwrap()` on any
# of them is the poison-intolerant shape. `read`/`write` do collide with
# io::Read / io::Write, so a hit is reported with its line for eyeballing
# rather than auto-rewritten. The `\s*` is what sees the rustfmt-wrapped
# chain - see the module docstring for the false zero it cost. `.expect("..")`
# is the same shape with a message: it panics on a poisoned guard exactly as
# `.unwrap()` does. Its argument is matched only when it is a plain string
# literal, so the display text stays readable; any other argument still hits,
# the match just ends at the opening paren.
SITE = re.compile(
    r"\.(lock|read|write)\(\)\s*\.(?:unwrap\(\)|expect\((?:\"(?:\\.|[^\"\\])*\"\))?)"
)
# The opening of a `#[cfg(..)]` attribute. Its PREDICATE is not a regex job -
# see cfg_is_test_only() for why the bare `#[cfg(test)]` spelling this gate
# shipped with was not enough.
CFG_ATTR = re.compile(r"\s*#\[\s*cfg\s*\(")
# A bare `#[` at a position, for stepping over attributes stacked between a
# cfg and the item it guards.
ATTR_OPEN = re.compile(r"\s*#\[")
# `#[cfg(test)] mod foo;` makes the WHOLE of foo.rs test code. Missing this is
# how a naive version of this script reported crates/nzbkit/src/extract/
# testutil.rs - 2 sites of pure test scaffolding - as a production regression.
# The `#[path = "x_tests.rs"] mod x_tests;` hook puts an attribute between the
# cfg and the mod; without tolerating it, every file attached that way reads as
# production and its honest test `.lock().unwrap()`s report as regressions.
MOD_DECL = re.compile(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;")
# A wrapped attribute is rare but real, and joining the whole rest of the file
# at every cfg line would be quadratic. Nothing in this tree wraps a cfg over
# more than three lines.
CFG_ATTR_MAX_LINES = 8


def balanced_end(text, open_idx, opener="(", closer=")"):
    """Index just past the bracket matching the one at `open_idx`, or None.

    String literals are skipped whole: `#[cfg(feature = "a)b")]` would
    otherwise close a paren early.
    """
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
            continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def split_top(s):
    """Split a cfg predicate list on its TOP-LEVEL commas."""
    args, depth, cur, i, n = [], 0, [], 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            cur.append(s[i : j + 1])
            i = j + 1
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        if c == "," and depth == 0:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    args.append("".join(cur))
    return [a.strip() for a in args if a.strip()]


def value_without_test(pred):
    """Three-valued evaluation of a cfg predicate with `test` OFF.

    True / False when the predicate is decided whatever the other options
    are, None when it depends on one of them. Every term other than `test`
    is unknown - this gate has no idea which features or targets a given
    build turns on, and does not need to.
    """
    pred = pred.strip()
    m = re.match(r"(all|any|not)\s*\(", pred)
    if m and balanced_end(pred, m.end() - 1) == len(pred):
        op = m.group(1)
        args = [value_without_test(a) for a in split_top(pred[m.end() : -1])]
        if op == "not":
            if len(args) != 1 or args[0] is None:
                return None
            return not args[0]
        if not args:
            return op == "all"  # Rust: all() is true, any() is false
        if op == "all":
            if any(v is False for v in args):
                return False
            return True if all(v is True for v in args) else None
        if any(v is True for v in args):
            return True
        return False if all(v is False for v in args) else None
    if pred == "test":
        return False
    return None


def cfg_is_test_only(pred):
    """Is an item under `#[cfg(<pred>)]` compiled ONLY in a test build?

    The gate shipped matching the literal `#[cfg(test)]` and nothing else,
    and this repo also uses the combined form widely - fifteen
    `#[cfg(all(test, feature = "indexer"))]` and seven `#[cfg(all(test,
    unix))]` on 23 Aug 2026, in nettools.rs and serve/groupscan.rs among
    others. Every `.lock().unwrap()` inside one of those read as a
    PRODUCTION regression. Found while adding a test to groupscan.rs; the
    test was rewritten to use atomics, so nothing on the tree tripped it and
    the defect stayed latent.

    The direction of the fix is the whole point and the selftest pins BOTH
    ends of it. A predicate counts as test scope only when it is definitely
    FALSE with `test` off, so:

      - `test`                      -> False -> test scope
      - `all(test, feature = "x")`  -> False -> test scope, either order
      - `all(feature = "x")`        -> None  -> PRODUCTION, no `test` term
      - `not(test)`                 -> True  -> PRODUCTION
      - `any(unix, test)`           -> None  -> PRODUCTION, and correctly so:
        that item is compiled into every unix release build. Six of those
        are live in this tree.

    An unparseable predicate evaluates to None, which is production - a
    widening that cannot tell what it is looking at must not hand out a
    waiver. Nothing here can turn a real production site into a pass.
    """
    return value_without_test(pred) is False


def cfg_test_attr_at(lines, i):
    """True if line `i` opens a `#[cfg(..)]` that is off outside a test build."""
    m = CFG_ATTR.match(lines[i])
    if not m:
        return False
    text = "\n".join(lines[i : i + CFG_ATTR_MAX_LINES])
    close = balanced_end(text, m.end() - 1)
    if close is None:
        return False
    return cfg_is_test_only(text[m.end() : close - 1])


def strip_noise(line):
    """Blank out string literals and line comments before counting braces.

    This repo's copy is full of braces inside strings (`format!("{n}/{d}")`,
    the i18n keys, the SABnzbd JSON shapes), and a naive brace counter closes
    a module dozens of lines early because of them.
    """
    line = re.sub(r'"(\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(\\.|[^'\\])'", "''", line)
    return re.sub(r"//.*", "", line)


def test_only_modules(path, lines):
    """Names of child modules this file declares as test-only.

    `#[cfg(test)] mod foo;` and `#[cfg(all(test, feature = "indexer"))] mod
    foo;` alike - the predicate is judged by cfg_is_test_only(), not by
    spelling.
    """
    text = "\n".join(lines)
    names = set()
    for m in CFG_ATTR.finditer(text):
        close = balanced_end(text, m.end() - 1)
        if close is None or not text[close:].lstrip(" \t").startswith("]"):
            continue
        if not cfg_is_test_only(text[m.end() : close - 1]):
            continue
        pos = text.index("]", close) + 1
        # Step over any further attributes stacked between the cfg and the
        # `mod` - the `#[path = "x_tests.rs"]` hook is the common one.
        while True:
            a = ATTR_OPEN.match(text, pos)
            if not a:
                break
            end = balanced_end(text, a.end() - 1, "[", "]")
            if end is None:
                break
            pos = end
        d = MOD_DECL.match(text, pos)
        if d:
            names.add(d.group(1))
    return names


def test_line_mask(lines):
    """True for every line inside an inline `#[cfg(test)]` block.

    A BRACE-LESS item has to end at its `;`, and getting that wrong is the
    other half of the false zero: `#[cfg(test)] static TEST_DELAY: ...;` and
    `#[cfg(test)] mod lane_tests;` open no block at all, so a brace-only
    scanner ran on to the next `{` it could find - which is the body of
    whatever production function came NEXT - and masked it as test code.
    That is how `pause_int` in sabcompat.rs (the SAB `pause_int`
    field, on every `mode=queue`) and `move_dest_root` in serve/mover.rs
    read as test scope on 22 Aug 2026.
    """
    mask = [False] * len(lines)
    i = 0
    while i < len(lines):
        if cfg_test_attr_at(lines, i):
            depth, started, ended, j = 0, False, False, i
            while j < len(lines):
                s = strip_noise(lines[j])
                depth += s.count("{") - s.count("}")
                if "{" in s:
                    started = True
                if started and depth <= 0:
                    ended = True
                    break
                # No block was ever opened, so this is a `static`/`const`/
                # `use`/`mod` declaration and its `;` is the whole of it.
                if not started and ";" in s:
                    ended = True
                    break
                j += 1
            if ended:
                for k in range(i, min(j + 1, len(lines))):
                    mask[k] = True
                i = j + 1
                continue
        i += 1
    return mask


def scan(lines):
    """(0-based line index, display text) for every site in `lines`.

    The match is found in the joined text so a wrapped chain is seen, but it
    is ANCHORED at the line the `.lock()` sits on: that is the line a reader
    greps for, and the line the `#[cfg(test)]` mask is asked about.

    A wrapped site's own line is just `.lock()`, which tells a reader nothing
    about WHAT is being locked, so the display walks back over the leading
    `.foo` continuation lines to whatever the chain hangs off and prints the
    whole thing collapsed onto one line.
    """
    text = "\n".join(lines)
    out = []
    for m in SITE.finditer(text):
        first = text.count("\n", 0, m.start())
        start, back = first, 0
        while start > 0 and back < 4 and lines[start].strip().startswith("."):
            start -= 1
            back += 1
        offset = sum(len(l) + 1 for l in lines[:start])
        out.append((first, re.sub(r"\s+", " ", text[offset : m.end()]).strip()))
    return out


def sites(lines, whole_file_is_test=False):
    """Split one file's sites into (production, test) by (lineno, text)."""
    mask = test_line_mask(lines)
    prod, test = [], []
    for i, display in scan(lines):
        (test if whole_file_is_test or mask[i] else prod).append((i + 1, display))
    return prod, test


def collect():
    """Return (production_sites, test_sites) as (path, lineno, text) tuples."""
    test_files = set()
    contents = {}
    for root, _dirs, files in os.walk(CRATES):
        if f"{os.sep}fuzz{os.sep}" in root + os.sep:
            continue
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(root, f)
            contents[p] = open(p, encoding="utf8", errors="replace").read().split("\n")

    for p, lines in contents.items():
        for name in test_only_modules(p, lines):
            d = os.path.dirname(p)
            base = p[:-3]  # strip .rs, for the `foo/` sibling-dir layout
            for cand in (os.path.join(d, name + ".rs"), os.path.join(base, name + ".rs")):
                if cand in contents:
                    test_files.add(cand)

    prod, test = [], []
    for p, lines in contents.items():
        # tests/ and benches/ are whole test targets; so is any module a parent
        # declared #[cfg(test)].
        whole_file_is_test = (
            f"{os.sep}tests{os.sep}" in p or f"{os.sep}benches{os.sep}" in p or p in test_files
        )
        p_hits, t_hits = sites(lines, whole_file_is_test)
        prod += [(p, n, line) for n, line in p_hits]
        test += [(p, n, line) for n, line in t_hits]
    return prod, test


# (name, expected production hits, source). The WRAPPED cases are the ones
# that motivated the widening: every one of them scores 0 against the
# single-line regex this gate shipped with.
SELFTEST = [
    (
        "the flat shape the gate always caught",
        1,
        "fn warn(d: &Daemon) {\n"
        "    let n = d.queue.lock().unwrap().len();\n"
        "}\n",
    ),
    (
        "sabcompat's sab_warnings, as rustfmt wraps it",
        1,
        "fn sab_warnings(d: &Daemon) -> Vec<String> {\n"
        "    let waiting: Vec<String> = d\n"
        "        .queue\n"
        "        .lock()\n"
        "        .unwrap()\n"
        "        .iter()\n"
        "        .map(|j| j.name.clone())\n"
        "        .collect();\n"
        "    waiting\n"
        "}\n",
    ),
    (
        "an RwLock read wrapped the same way",
        1,
        "fn peek(s: &State) -> usize {\n"
        "    s.map\n"
        "        .read()\n"
        "        .unwrap()\n"
        "        .len()\n"
        "}\n",
    ),
    (
        "the house call, wrapped",
        0,
        "fn warn(d: &Daemon) -> usize {\n"
        "    d.queue\n"
        "        .lock_ok()\n"
        "        .len()\n"
        "}\n",
    ),
    (
        "a wrapped site inside #[cfg(test)] - .unwrap() is right there",
        0,
        "fn prod(d: &Daemon) -> usize {\n"
        "    d.queue.lock_ok().len()\n"
        "}\n"
        "\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    use super::*;\n"
        "    #[test]\n"
        "    fn counts() {\n"
        "        let n = D\n"
        "            .queue\n"
        "            .lock()\n"
        "            .unwrap()\n"
        "            .len();\n"
        "        assert_eq!(n, 0);\n"
        "    }\n"
        "}\n",
    ),
    (
        "a brace-less #[cfg(test)] item must not swallow the next function",
        1,
        "#[cfg(test)]\n"
        "pub(super) static DELETE_BARRIER: Mutex<Option<Arc<Barrier>>> = Mutex::new(None);\n"
        "\n"
        "pub(super) fn pause_int(d: &Daemon) -> String {\n"
        "    d.pause_until\n"
        "        .lock()\n"
        "        .unwrap()\n"
        "        .map(|t| t.as_secs())\n"
        "        .unwrap_or(0)\n"
        "        .to_string()\n"
        "}\n",
    ),
    (
        "the same, for a `#[cfg(test)] mod foo;` child declaration",
        1,
        "#[cfg(test)]\n"
        "mod lane_tests;\n"
        "\n"
        "fn dest_root(&self) -> Option<PathBuf> {\n"
        "    self.move_completed_cats\n"
        "        .read()\n"
        "        .unwrap()\n"
        "        .first()\n"
        "        .cloned()\n"
        "}\n",
    ),
    (
        "the flat .expect() shape - a message does not make the panic go away",
        1,
        "fn warn(d: &Daemon) {\n"
        '    let n = d.queue.lock().expect("queue poisoned").len();\n'
        "}\n",
    ),
    (
        "the same .expect(), as rustfmt wraps it",
        1,
        "fn peek(s: &State) -> usize {\n"
        "    s.map\n"
        "        .read()\n"
        '        .expect("map poisoned")\n'
        "        .len()\n"
        "}\n",
    ),
    (
        "an .expect() inside a #[cfg(test)] child module stays test scope",
        0,
        "fn prod(d: &Daemon) -> usize {\n"
        "    d.queue.lock_ok().len()\n"
        "}\n"
        "\n"
        "#[cfg(test)]\n"
        "mod unit_tests {\n"
        "    #[test]\n"
        "    fn counts() {\n"
        '        let n = D.queue.lock().expect("poisoned").len();\n'
        "        assert_eq!(n, 0);\n"
        "    }\n"
        "}\n",
    ),
    (
        "a combined #[cfg(all(test, feature))] block is still test scope",
        0,
        "fn prod(d: &Daemon) -> usize {\n"
        "    d.queue.lock_ok().len()\n"
        "}\n"
        "\n"
        '#[cfg(all(test, feature = "indexer"))]\n'
        "mod group_burst_tests {\n"
        "    use super::*;\n"
        "    #[test]\n"
        "    fn counts() {\n"
        "        let n = SEEN.lock().unwrap().len();\n"
        "        assert_eq!(n, 0);\n"
        "    }\n"
        "}\n",
    ),
    (
        "the same with the terms the other way round, and wrapped",
        0,
        '#[cfg(all(feature = "indexer", test))]\n'
        "mod sampler_stays_sequential {\n"
        "    #[test]\n"
        "    fn ordered() {\n"
        "        let n = SEEN\n"
        "            .lock()\n"
        "            .unwrap()\n"
        "            .len();\n"
        "        assert_eq!(n, 0);\n"
        "    }\n"
        "}\n",
    ),
    (
        "an all() with NO test term is production and must stay in scope",
        1,
        '#[cfg(all(feature = "indexer"))]\n'
        "mod wall {\n"
        "    pub fn seen(s: &State) -> usize {\n"
        "        s.map.lock().unwrap().len()\n"
        "    }\n"
        "}\n",
    ),
    (
        "any(unix, test) ships in every unix build, so it is production",
        1,
        "#[cfg(any(unix, test))]\n"
        "fn sock_count(s: &State) -> usize {\n"
        "    s.socks\n"
        "        .read()\n"
        "        .unwrap()\n"
        "        .len()\n"
        "}\n",
    ),
    (
        "not(test) contains the word and is the OPPOSITE of test scope",
        1,
        "#[cfg(not(test))]\n"
        "fn real_pause(d: &Daemon) -> u64 {\n"
        "    d.pause_until.lock().unwrap().unwrap_or_default()\n"
        "}\n",
    ),
    (
        "a brace-less combined cfg must not swallow the next function",
        1,
        '#[cfg(all(test, unix))]\n'
        "mod lane_tests;\n"
        "\n"
        "fn dest_root(&self) -> Option<PathBuf> {\n"
        "    self.move_completed_cats\n"
        "        .read()\n"
        "        .unwrap()\n"
        "        .first()\n"
        "        .cloned()\n"
        "}\n",
    ),
    (
        "whitespace is not allowed to cross a comment",
        0,
        "fn open(p: &Path) -> Vec<u8> {\n"
        "    let f = File::open(p).unwrap();\n"
        "    // f.read()\n"
        "    let v = read_all(f);\n"
        "    v.unwrap()\n"
        "}\n",
    ),
]


def selftest():
    bad = 0
    for name, want, src in SELFTEST:
        lines = src.split("\n")
        got = len(sites(lines)[0])
        if got != want:
            verb = "MISSED" if want else "false-positived on"
            print(f"  selftest FAIL: {verb} {name} ({got} hits, wanted {want})", file=sys.stderr)
            bad += 1
    # The whole point of the widening: assert the OLD pattern really is blind
    # to the wrapped shape, so nobody narrows it back for tidiness.
    old = re.compile(r"\.(lock|read|write)\(\)\.unwrap\(\)")
    wrapped = SELFTEST[1][2]
    if old.search(wrapped):
        print("  selftest FAIL: the wrapped fixture is not actually wrapped -", file=sys.stderr)
        print("    the single-line regex can see it, so it proves nothing.", file=sys.stderr)
        bad += 1
    # And the tally the selftest claims for test scope: a file a parent declares
    # as `#[cfg(test)] mod unit_tests;` is test scope in its entirety, so an
    # `.expect()` there must land on the test side, not the production one.
    child = 'fn counts() {\n    let n = D.queue.lock().expect("poisoned").len();\n}\n'
    p_hits, t_hits = sites(child.split("\n"), whole_file_is_test=True)
    if p_hits or len(t_hits) != 1:
        print("  selftest FAIL: a whole-file test module's .expect() was not test-scoped", file=sys.stderr)
        bad += 1
    # The child-declaration side of the combined form: a `#[cfg(all(test,
    # ..))] mod foo;` has to make foo.rs test scope exactly as the bare
    # spelling does, and a cfg with no `test` term must not.
    for decl, want in (
        ("#[cfg(test)]\nmod a_tests;\n", {"a_tests"}),
        ('#[cfg(all(test, feature = "indexer"))]\nmod b_tests;\n', {"b_tests"}),
        ('#[cfg(all(feature = "indexer", test))]\n#[path = "c.rs"]\nmod c_tests;\n', {"c_tests"}),
        ("#[cfg(all(test, unix))]\npub(crate) mod d_tests;\n", {"d_tests"}),
        ('#[cfg(all(feature = "indexer"))]\nmod wall;\n', set()),
        ("#[cfg(any(unix, test))]\nmod portable;\n", set()),
        ("#[cfg(not(test))]\nmod real;\n", set()),
    ):
        got = test_only_modules("x.rs", decl.split("\n"))
        if got != want:
            print(
                f"  selftest FAIL: child-module scope for {decl.splitlines()[0]!r}"
                f" resolved to {sorted(got)}, wanted {sorted(want)}",
                file=sys.stderr,
            )
            bad += 1
    # And the predicate evaluator itself, at the two ends that matter. A
    # careless widening that says yes to everything is a rubber stamp.
    for pred, want in (
        ("test", True),
        ('all(test, feature = "indexer")', True),
        ('all(feature = "indexer", test)', True),
        ("all(test, unix)", True),
        ('all(test, any(feature = "a", feature = "b"))', True),
        ('all(feature = "indexer")', False),
        ("all(unix, windows)", False),
        ("any(unix, test)", False),
        ("not(test)", False),
        ('feature = "indexer"', False),
        ("unix", False),
    ):
        if cfg_is_test_only(pred) != want:
            print(
                f"  selftest FAIL: cfg_is_test_only({pred!r}) is"
                f" {cfg_is_test_only(pred)}, wanted {want}",
                file=sys.stderr,
            )
            bad += 1
    # An unknown flag must be a REFUSAL naming it, never a silent skip that
    # falls through to the ordinary clean gate verdict about a request
    # nobody honoured - the shape reproduced live on size-gate.py 31 Aug 2026.
    for args, want_bad in (
        (["--this-flag-does-not-exist"], True),
        ([], False),
        (["--list"], False),
        (["--selftest"], False),
    ):
        got_bad = unrecognised_argv(args) is not None
        if got_bad != want_bad:
            print(
                f"  selftest FAIL: unrecognised_argv({args!r}) flagged={got_bad},"
                f" wanted {want_bad}",
                file=sys.stderr,
            )
            bad += 1
    if bad:
        print(f"\nlock-gate: {bad} selftest case(s) failed - the gate is not doing its job.", file=sys.stderr)
        return 1
    print(
        f"lock-gate: selftest ok ({len(SELFTEST) + 19} cases, flat and rustfmt-wrapped,"
        " unwrap and expect, bare and combined cfg, 4 argv cases)"
    )
    return 0


KNOWN_FLAGS = {"--selftest", "--list"}


def unrecognised_argv(argv):
    """First arg outside the known set, or None."""
    for a in argv:
        if a not in KNOWN_FLAGS:
            return a
    return None


def main():
    if "--selftest" in sys.argv:
        return selftest()

    bad_arg = unrecognised_argv(sys.argv[1:])
    if bad_arg is not None:
        print(
            f"lock-gate: unrecognised argument {bad_arg!r} - known flags are "
            "--list, --selftest, or no args for the gate. A stale checkout "
            "may be missing a flag this script now supports - merge "
            "origin/main.",
            file=sys.stderr,
        )
        return 1

    prod, test = collect()
    if "--list" in sys.argv:
        for label, rows in (("production", prod), ("test", test)):
            print(f"\n=== {label}: {len(rows)} ===")
            for p, n, line in sorted(rows):
                print(f"  {p}:{n}\n      {line[:100]}")
        return 0

    if not prod:
        print(f"lock-gate: 0 poison-intolerant lock sites in production ({len(test)} in tests, fine)")
        return 0

    print(f"lock-gate: {len(prod)} poison-intolerant lock site(s) in PRODUCTION code:\n", file=sys.stderr)
    for p, n, line in sorted(prod):
        print(f"  {p}:{n}\n      {line[:100]}", file=sys.stderr)
    print(
        "\n  Use the poison-recovering forms from nzbkit::sync instead:\n"
        "      .lock().unwrap()   ->  .lock_ok()\n"
        "      .read().unwrap()   ->  .read_ok()\n"
        "      .write().unwrap()  ->  .write_ok()\n"
        "  The same goes for .lock().expect(\"...\"): the message does not stop\n"
        "  the panic, only .lock_ok() does.\n"
        "\n  A poisoned lock means another thread panicked. Inheriting that panic\n"
        "  is what took the whole daemon down before the 1 Aug sweep. See the\n"
        "  module docs in crates/nzbkit-base/src/sync.rs.\n"
        "\n  In tests .unwrap() / .expect() are correct and this gate ignores it - a test SHOULD\n"
        "  die on a poisoned lock.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
