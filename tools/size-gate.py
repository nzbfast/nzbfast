#!/usr/bin/env python3
"""Refuse file and function growth past the recorded baseline. TODO 102 / 106.

The scorecard kept measuring the same drift: TODO 43 split `serve()` to 1,819
lines and it regrew to 2,234 within days; `get_with_progress()` reached 3,942
lines - 2.5x the longest function in any competitor - without any list even
naming it. The 3 Aug offender list missed it because a naive brace counter
died on the first string literal containing a brace. This gate exists so the
§106 splits stay split.

Semantics (recalibrated 31 Aug 2026 - the note above BASELINE_FILES has
the measurements; research/DEV-TOOLCHAIN-REVIEW-2026-08-31.md the review):
  - Every PRODUCTION `.rs` file under crates/ (fuzz dirs excluded) must
    stay under FILE_CEILING raw lines. A file that is WHOLLY test code
    (under tests/ or benches/, or a `#[cfg(test)] mod foo;` target) gets
    TEST_FILE_CEILING instead - the argument that already exempts test
    functions, one level up: a table of cases is allowed to be long.
  - Every PRODUCTION function must stay under FN_CEILING lines. Test
    functions are reported but not gated.
  - A target that cannot come under its ceiling in one commit is
    allow-listed in BASELINE at its measured size, with a comment naming
    the split debt. An entry's limit is its recorded size plus a FLAT
    slack (BASELINE_SLACK / FN_BASELINE_SLACK), so ordinary feature work
    does not trip it while regrowth does. ADDING an entry is legal - the
    pressure valve that keeps a mid-feature ceiling cross from forcing a
    split under time pressure. A false-refusal-prone gate gets switched
    off - that is the fmt-hook lesson.
  - The recorded numbers only move DOWN. When a target drops back under
    its ceiling the gate FAILS until its entry is deleted, in the same
    commit as the split. That is the ratchet, and it is unchanged.

Test scope is resolved properly (inline `#[cfg(test)]` blocks AND
`#[cfg(test)] mod foo;` making the whole of foo.rs test code) - same
resolver family as tools/lock-gate.py, same reason: naive path-based
counting has already produced one wrong scorecard round.

`--headroom` exists because `--list` cannot answer the question the recurring
split chips actually ask. It sorts by SIZE, so a function at 500 of 500 ranks
below one at 400 of 9,000, and it prints neither the limit nor which KIND of
ceiling a target is under - and the two regimes still split differently. A
flat-ceiling file converts a split line for line into headroom; a BASELINED
one resets to the flat slack constant however big the cut is, so the real win
there is driving the target under its own ceiling and DELETING the entry.
(Under the pre-31-Aug 2% slack the regimes behaved OPPOSITELY - the gain
SHRANK as the split grew - which is how a 31 Aug 2026 chip paired
`tests/e2e_norar/mod.rs` (flat) with `tests/daemon.rs` (baselined) as one
problem and half of it was not buildable. The flat-slack recalibration
retired that trap.)

Usage:
    tools/size-gate.py            # gate: exit 1 on any violation
    tools/size-gate.py --list     # report the largest files and functions
    tools/size-gate.py --headroom # report what is CLOSEST to its ceiling,
                                  #   with the limit and the ceiling KIND
    tools/size-gate.py --selftest # prove the scope resolver still works
"""

import contextlib
import io
import os
import re
import sys

CRATES = "crates"
FILE_CEILING = 4000  # production .rs raw lines; the worst competitor file is ~5,400
TEST_FILE_CEILING = 12000  # whole-file test code - append-heavy case tables
FN_CEILING = 500  # production function lines; rustnzb ships zero over 500
BASELINE_SLACK = 200  # FLAT slack on a baselined file entry (was 2% of itself)
FN_BASELINE_SLACK = 50  # FLAT slack on a baselined fn entry

# The baseline is the RATCHET half of the gate: a target that cannot come
# under its ceiling in one commit is recorded at its measured size, its
# limit is that size plus a FLAT slack, and the recorded number only ever
# moves DOWN. An entry whose target drops under its own ceiling REDS the
# gate until the entry is deleted, so burn-down is enforced, not hoped.
#
# RECALIBRATED 31 Aug 2026, a deliberate decision recorded in
# research/DEV-TOOLCHAIN-REVIEW-2026-08-31.md. Four changes, and the
# measurements that forced them:
#   * Whole-file TEST code gets its own ceiling (TEST_FILE_CEILING), on
#     the argument this gate already accepted for functions - "a table of
#     cases is allowed to be long". The two eternal entries here were both
#     test files (tests/daemon.rs at 9,132 after four split rounds,
#     tests/e2e.rs at 6,280 after three) with ~10,000 lines still to move
#     at one hand-read subject seam per round, forever. Both entries are
#     GONE under the test ceiling. Their split history - which seams were
#     taken, which were deliberately left, and why - is in this file's own
#     git log and in research/SIZE-GATE-BASELINED-MARGINS-2026-08-29.md.
#   * The production FILE_CEILING moved 3,000 -> 4,000. The census behind
#     it: ~114 commits in the 30 days to 31 Aug existed ONLY to satisfy
#     this gate, and the files with the LEAST headroom were the MOST
#     edited (serve/daemon.rs: 42 lines free, 133 commits in 14 days;
#     pool.rs: 44 free, 87 commits) - at that churn a split bought days.
#     The worst competitor file is ~5,400 lines, so the yardstick holds.
#   * Slack became FLAT (BASELINE_SLACK) instead of 2% of the entry's own
#     size. The 2% rule was measurably perverse: cutting MORE lines bought
#     LESS headroom, so re-baselining after any split left ~70-130 lines
#     whatever the effort, and seam size was dictated by the gate rather
#     than by design (nntp.rs: 776 lines moved where ~400 covered the
#     problem). Under flat slack a split+ratchet resets free to the same
#     constant however big the cut is.
#   * ADDING an entry is now legal - the pressure valve. Crossing a
#     ceiling mid-feature is answered by a one-line entry at the measured
#     size WITH a comment naming the split debt, instead of by stopping
#     the feature to split under time pressure. The ratchet is unchanged:
#     entries only move down, stale entries red, and the split still
#     happens - as designed work on a chosen seam, on its own schedule.
BASELINE_FILES = {
    # "path/relative/to/repo/root.rs": raw lines measured (gate arithmetic,
    # which reads one HIGHER than `wc -l` - measure with the gate).
    # Every entry carries a comment naming the debt and the intended seam.
    #
    # EMPTY since 4 Sep 2026. The one entry it held, container.rs at 4,037,
    # was paid off the same day by the split its comment named: the inline
    # `mod tests` moved to crates/postfast/src/container/tests.rs, taking
    # the production file to 2,090 lines with its whole ceiling free. The
    # valve worked as designed - four lanes were live in that file the
    # afternoon it crossed, and none of them had to stop and split under
    # time pressure. It is the ratchet that made the entry temporary:
    # a listed target that falls under its ceiling REDS until the entry is
    # deleted, so the split and the delete land together or not at all.
}

BASELINE_FNS = {
    # "path::fn_name": lines measured
    # spawn_download_worker was here at 688, then 719, then 770 from
    # pre-gate concurrent work, and reached 831 as the §154 no-servers
    # hold and the §96.5 block-account budgets landed inside it. Three
    # self-contained stretches of the loop moved to tasks/runner.rs:
    # the M14g guard ladder (`download_guards`, which sleeps on the
    # caller's behalf and answers `only_force` or "do not pick"), the
    # per-job hub hand-over (`reset_hub_for_job`), and the figures read at
    # network-drain before the next iteration zeroes them
    # (`settle_job_tail`). 417 lines now - under the ceiling, so its entry
    # is GONE.
    # queue_json was here at 652, then 670 after the 8 Aug burst. `resume_at`
    # and the watch_failed row builder came out whole (609), and the lane's
    # own comment trim (61537f5d) merged over it: 604. The #34 SAB-parity
    # round then took it to 782 in one commit - it added ~30 keys to the
    # slot and ~25 to the header. Two more self-contained blocks came out:
    # the whole queue ROW (`slot_json` + the `SlotCtx` snapshot it is built
    # against - it reads no daemon state of its own), and the six notice
    # rings (`queue_notices`). 475 now - under the ceiling, so its entry
    # is GONE.
    # spawn_index_scan was here at 582 and reached 648 - the §131 spot
    # legs landed inside it. Four self-contained blocks of its pass moved
    # to tasks/indexer.rs, where the rest of the index upkeep
    # already lives: the Spotnet scan + promote leg (spot_pass), the
    # category reconcile (reclassify_pending_rows), the retention prune
    # and planner-statistics refresh (retention_and_statistics), and the
    # size-cap eviction (evict_pass_and_republish). 316 lines now - under
    # the ceiling, so its entry is GONE.
}


# The two limit rules, factored out of main() so the REPORT and the VERDICT
# cannot drift apart. A report that disagrees with the gate it ships inside
# is worse than no report: it is a wrong number carrying the gate's
# authority, which is exactly the class of defect the split chips already
# hit by computing these by hand. Both return the same expression main()
# used before, unchanged, plus the name of the regime it came from.
def file_limit(path, is_test):
    """(limit, kind) for a file. kind is 'flat' or 'baselined'."""
    if path in BASELINE_FILES:
        return BASELINE_FILES[path] + BASELINE_SLACK, "baselined"
    return (TEST_FILE_CEILING if is_test else FILE_CEILING), "flat"


def fn_limit(key):
    """(limit, kind) for a `path::name` production function key."""
    if key in BASELINE_FNS:
        return BASELINE_FNS[key] + FN_BASELINE_SLACK, "baselined"
    return FN_CEILING, "flat"


def split_gain(size, free, kind, ceiling, slack):
    """Headroom a split can BUY, at its very best. None means 'line for line'.

    FLAT: the limit is a constant, so every line removed is a line of
    headroom gained, without bound. None.

    BASELINED: the house convention is to ratchet the baseline down to the
    target's new exact size in the same commit as the split, so after ANY
    cut the new free is exactly the flat slack. Returns slack - free (floor
    0): what a split+ratchet buys over doing nothing. Under the pre-31-Aug
    2% rule this number SHRANK as the split grew - measured in
    research/SIZE-GATE-BASELINED-MARGINS-2026-08-29.md, and the rule was
    retired for it. The real escape is unchanged: drive the target under
    its own ceiling outright, which deletes the entry; `to_flat` in the
    row says how many lines that is.
    """
    if kind != "baselined":
        return None
    if size <= ceiling:
        # Already under its ceiling: the gate refuses the stale entry
        # rather than applying it, so there is nothing to model.
        return None
    return max(0, slack - free)


CFG_TEST = re.compile(r"\s*#\[cfg\(test\)\]")
# The `#[path = "x_tests.rs"] mod x_tests;` hook puts an attribute between
# the cfg and the mod, and the old pattern stopped dead at it - every file
# attached that way was scored as PRODUCTION code, so a long table-driven
# test in one would have tripped the fn ceiling for no reason. Tolerate any
# run of attributes in between.
CFG_TEST_MOD = re.compile(
    r"\s*#\[cfg\(test\)\]\s*(?:\n\s*)?(?:#\[[^\]]*\]\s*(?:\n\s*)?)*"
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;"
)
FN_START = re.compile(
    r"(?:^|[\s{}();])(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?"
    r"(?:async\s+)?(?:unsafe\s+)?(?:extern\s*\"[^\"]*\"\s+)?fn\s+(\w+)"
)


def strip_noise(text):
    """Blank strings and comments, preserving line structure and braces.

    A real tokenizer, not a per-line regex: the 3 Aug offender list was built
    with a per-line version and stopped dead at the first multi-line string
    with an unbalanced brace, silently dropping the biggest function in the
    repo from its own report. Handles nested block comments, escapes, raw
    strings (r#".."#, b"..", br#".."#), and char-literal-vs-lifetime.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    if text[i] == "\n":
                        out.append("\n")
                    i += 1
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 1
                elif text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 1
        elif c in "rb" and re.match(r'(?:r#*"|br#*"|rb#*"|b")', text[i:]):
            m = re.match(r'(?:b?r)(#*)"', text[i:])
            if m:  # raw string: ends at "### with the same hash count
                hashes = m.group(1)
                i += m.end()
                end = text.find('"' + hashes, i)
                end = n if end == -1 else end + 1 + len(hashes)
                out.extend("\n" * text.count("\n", i, end))
                i = end
            else:  # b"..." plain byte string
                i += 2
                while i < n and text[i] != '"':
                    if text[i] == "\\":
                        i += 1
                    elif text[i] == "\n":
                        out.append("\n")
                    i += 1
                i += 1
        elif c == "'":
            m = re.match(r"'(?:\\[^']*|[^'\\])'", text[i:])
            if m:  # char literal; otherwise a lifetime - keep scanning
                i += m.end()
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def test_line_mask(clean_lines):
    """True for every line inside an inline `#[cfg(test)]` block.

    A BRACE-LESS item has to end at its `;`. This scanner used to end an
    item only on braces, so `#[cfg(test)] static DUPE_ADMIT_BARRIER: ...;`
    and `#[cfg(test)] mod lane_tests;` - which open no block at all - ran
    on to the next `{` the file could offer, which is the body of whatever
    came NEXT, and masked it as test code. Measured 22 Aug 2026: 58 files
    carried a wrong mask, 24 functions were scored as test code that are
    production, and one of them was over the ceiling and hidden by it -
    `Daemon::enqueue`, 575 lines, with the brace-less static declared
    directly above its `impl` block. That is the same defect tools/
    lock-gate.py carried; both scanners are the same resolver family and
    the fix is the same one.
    """
    mask = [False] * len(clean_lines)
    i = 0
    while i < len(clean_lines):
        if CFG_TEST.match(clean_lines[i]):
            depth, started, ended, j = 0, False, False, i
            while j < len(clean_lines):
                s = clean_lines[j]
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
                for k in range(i, min(j + 1, len(clean_lines))):
                    mask[k] = True
                i = j + 1
                continue
        i += 1
    return mask


def functions(clean_lines):
    """Yield (name, start_line_0based, span_lines) for every fn with a body."""
    text = "\n".join(clean_lines)
    line_of = []
    ln = 0
    for ch in text:
        line_of.append(ln)
        if ch == "\n":
            ln += 1
    for m in FN_START.finditer(text):
        # Scan from the signature to the first `{` or `;`. A `;` first means
        # a trait method declaration or extern item - no body, no entry.
        j = m.end()
        while j < len(text) and text[j] not in "{;":
            j += 1
        if j >= len(text) or text[j] == ";":
            continue
        depth = 0
        k = j
        while k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        start = line_of[m.start(1)]
        end = line_of[min(k, len(text) - 1)]
        yield m.group(1), start, end - start + 1


def collect():
    contents = {}
    for root, _dirs, files in os.walk(CRATES):
        if f"{os.sep}fuzz{os.sep}" in root + os.sep:
            continue
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(root, f)
            contents[p] = open(p, encoding="utf8", errors="replace").read()

    test_files = set()
    clean = {p: strip_noise(t).split("\n") for p, t in contents.items()}
    for p, lines in clean.items():
        for name in CFG_TEST_MOD.findall("\n".join(lines)):
            d = os.path.dirname(p)
            base = p[:-3]
            for cand in (os.path.join(d, name + ".rs"), os.path.join(base, name + ".rs")):
                if cand in contents:
                    test_files.add(cand)

    files_out = []  # (path, raw_lines, whole_file_is_test)
    fns_out = []  # (path, name, line_1based, span, is_test)
    for p, text in contents.items():
        # NB: this reads one HIGHER than `wc -l` on newline-terminated
        # text, so a file `wc` calls 3,000 lines is 3,001 to the ceiling
        # test below and FAILS. Measure headroom with the gate, not with
        # wc. Undocumented until 23 Aug 2026, by which time it had cost
        # two sessions in one evening - one mid-push, one misreading the
        # cause as the `.split("\n")` in `clean` above, which yields the
        # same number but feeds `#[cfg(test)]` scope resolution and
        # never reaches the ceiling. Do not "fix" either: the scope
        # resolver is what --selftest pins.
        whole_file_is_test = (
            f"{os.sep}tests{os.sep}" in p or f"{os.sep}benches{os.sep}" in p or p in test_files
        )
        files_out.append((p, text.count("\n") + 1, whole_file_is_test))
        mask = test_line_mask(clean[p])
        for name, start, span in functions(clean[p]):
            is_test = whole_file_is_test or (start < len(mask) and mask[start])
            fns_out.append((p, name, start + 1, span, is_test))
    return files_out, fns_out


def largest_prod_fns(fns):
    """{path::name: (span, line)} for production fns - main()'s own reduction.

    A name can appear more than once in a file (two `impl` blocks, a cfg
    pair); main() gates the LARGEST, so the report must score the largest
    too or it would report a margin the gate does not use.
    """
    out = {}
    for p, name, line, span, is_test in fns:
        if is_test:
            continue
        key = f"{p}::{name}"
        if span > out.get(key, (0, 0))[0]:
            out[key] = (span, line)
    return out


def _row(label, size, limit, kind, ceiling, slack):
    free = limit - size
    return {
        "label": label,
        "size": size,
        "limit": limit,
        "free": free,
        "kind": kind,
        # The row's OWN ceiling - files carry two (production and test)
        # since the 31 Aug recalibration, so the note under a baselined
        # row must name the one that actually deletes its entry.
        "ceiling": ceiling,
        "slack": slack,
        "gain": split_gain(size, free, kind, ceiling, slack),
        # Lines that would have to come off for a baselined target to drop
        # under its ceiling, which DELETES its entry and changes the
        # regime. None where that does not apply.
        "to_flat": (size - ceiling) if kind == "baselined" and size > ceiling else None,
    }


def headroom_rows(files, fns):
    """(file_rows, fn_rows), each sorted by free ASCENDING.

    Ascending, so line 1 is the thing about to redden main. `--list` sorts
    by SIZE, which ranks a 500-of-500 function below a 400-of-9,000 one.
    """
    frows = [
        _row(
            p + ("  [test]" if t else ""),
            n,
            *file_limit(p, t),
            TEST_FILE_CEILING if t else FILE_CEILING,
            BASELINE_SLACK,
        )
        for p, n, t in files
    ]
    nrows = []
    for key, (span, line) in largest_prod_fns(fns).items():
        p, name = key.rsplit("::", 1)
        nrows.append(_row(f"{p}:{line}  {name}", span, *fn_limit(key), FN_CEILING, FN_BASELINE_SLACK))
    # Deterministic: tightest first, then biggest, then by name.
    def keyf(r):
        return (r["free"], -r["size"], r["label"])

    return sorted(frows, key=keyf), sorted(nrows, key=keyf)


HEADROOM_LEGEND = """  The two ceilings are different IN KIND, not in degree. Read this before
  pricing any split, and never pair a tight flat row with a tight baselined
  one as though they were one problem.
  flat      = the {ceiling} ceiling. A split converts LINE FOR LINE into
              headroom: take N lines out and there are N more.
  baselined = the limit is the recorded baseline + {slack} flat slack, and the
              house ratchet re-centres on the new size, so a split+ratchet
              resets free to +{slack} however big the cut is. The `^` note
              under each such row is what that buys over doing nothing. The
              real win is driving the target under its own ceiling, which
              DELETES the entry. {remedy}"""

FILE_REMEDY = (
    "Send new rows to a child\n              module instead (tests/daemon.rs already has 39), or drive the\n"
    "              file under its ceiling outright, which deletes the entry."
)
FN_REMEDY = (
    "Lift self-contained stretches out to\n              sibling functions until the body is under the flat ceiling, which\n"
    "              deletes the entry."
)


def narrowest_line(frows, nrows):
    """The tightest file and the tightest production fn, as one line.

    The gate is PASS/FAIL, so its clean line said nothing about how close
    anything was - and this class recurred five times in the four days to
    31 Aug 2026, twice reddening main outright, every instance found by a
    human running `--list` and doing the subtraction by hand. Nobody runs
    `--list` on a push; everybody runs the gate. So the number rides on the
    line the gate ALREADY prints.

    It is deliberately NOT a warn tier. A refusal at some threshold is a
    real judgement with a real trade - a gate red for a reason nobody can
    act on gets loosened until it means nothing, and a warning nobody must
    act on decays the same way - and that decision is not this patch's to
    make. This is a number on a line that was already there.
    """
    bits = []
    for tag, rows in (("file", frows), ("fn", nrows)):
        if not rows:
            continue
        r = rows[0]
        # The fn label is column-padded for the table; collapse it inline.
        label = " ".join(r["label"].split())
        bits.append(f"{tag} {label} {r['free']:,} free of {r['limit']:,}")
    if not bits:
        return None
    return "  narrowest: " + "; ".join(bits) + "  (`--headroom` for the rest)"


def print_headroom(title, rows, top, ceiling_desc, slack, remedy):
    print(f"=== {title} (headroom ascending) ===")
    print("     free      size     limit  used  ceiling")
    shown = rows[:top]
    # A baselined target is the one this report exists to distinguish, and it
    # does NOT reliably rank near the top: its free is up to 2% of a large
    # size, so on 31 Aug 2026 neither baselined FILE was in the tightest
    # twelve while every flat row above them was under 100 lines. Cutting
    # them off at the fold would hide exactly the class the reader came for.
    cut = [r for r in rows[top:] if r["kind"] == "baselined"]
    for r in shown + cut:
        # FLOOR, never round: 2,990 of 3,000 rounds to 100% and reads as
        # "at the limit" when there are ten lines left. Only an exact 100%
        # may print 100.
        used = int(100 * r["size"] / r["limit"]) if r["limit"] else 0
        print(
            f"  {r['free']:7,}  {r['size']:8,}  {r['limit']:8,}  {used:3d}%  "
            f"{r['kind']:<9}  {r['label']}"
        )
        if r["kind"] == "baselined":
            gain = (
                "buys nothing"
                if not r["gain"]
                else f"buys at most +{r['gain']:,} (free resets to the flat +{r['slack']:,})"
            )
            flat = (
                f"; {r['to_flat']:,} lines takes it under its {r['ceiling']:,} ceiling and deletes the entry"
                if r["to_flat"]
                else ""
            )
            print(f"             ^ a split+ratchet {gain}{flat}")
    if cut:
        print(f"  ({len(cut)} baselined row(s) shown from below the fold - see the legend)")
    print(HEADROOM_LEGEND.format(ceiling=ceiling_desc, slack=slack, remedy=remedy))


def report_headroom(top=25):
    files, fns = collect()
    frows, nrows = headroom_rows(files, fns)
    # Failing to find is failing: an inert scanner shows a zero rather than
    # a clean-looking report. Both corpora are in the thousands on this tree.
    if not frows or not nrows:
        print(
            f"size-gate: --headroom reached {len(frows)} file(s) and {len(nrows)} production "
            "fn(s) - run it from the repo root; a report over nothing is not a report.",
            file=sys.stderr,
        )
        return 1
    print_headroom(
        "files closest to their ceiling",
        frows,
        top,
        f"{FILE_CEILING:,}-line production (or {TEST_FILE_CEILING:,}-line whole-file-test)",
        BASELINE_SLACK,
        FILE_REMEDY,
    )
    print()
    print_headroom(
        "production fns closest to their ceiling", nrows, top, f"{FN_CEILING:,}-line", FN_BASELINE_SLACK, FN_REMEDY
    )
    print(f"\n  ({len(frows):,} files, {len(nrows):,} production fns scored)")
    return 0


# (name, fn name, expected is_test, source). The BRACE-LESS cases are the
# ones that motivated the fix in test_line_mask: each of them scores
# is_test=True against the brace-only scanner this gate shipped with, which
# exempts a production function from FN_CEILING outright.
SELFTEST = [
    (
        "a plain production fn",
        "big",
        False,
        "fn big() {\n    let x = 1;\n}\n",
    ),
    (
        "a fn inside a real #[cfg(test)] mod block",
        "counts",
        True,
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn counts() {\n        assert!(true);\n    }\n}\n",
    ),
    (
        "a production fn AFTER a #[cfg(test)] mod block, which must not be swallowed",
        "big",
        False,
        "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n\nfn big() {\n    let x = 1;\n}\n",
    ),
    (
        "daemon_enqueue's shape: a brace-less #[cfg(test)] static above an impl",
        "enqueue",
        False,
        "#[cfg(test)]\n"
        "pub(in crate::serve) static DUPE_ADMIT_BARRIER: Mutex<\n"
        "    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,\n"
        "> = Mutex::new(None);\n"
        "\n"
        "impl Daemon {\n"
        "    fn enqueue(&self) -> Result<String> {\n"
        "        Ok(String::new())\n"
        "    }\n"
        "}\n",
    ),
    (
        "the same, for a `#[cfg(test)] mod foo;` child declaration",
        "dest_root",
        False,
        "#[cfg(test)]\nmod lane_tests;\n\nfn dest_root() -> u8 {\n    0\n}\n",
    ),
    (
        "a brace-less #[cfg(test)] use, which is also test scope itself",
        "prod",
        False,
        "#[cfg(test)]\nuse std::sync::Barrier;\n\nfn prod() {\n    let x = 1;\n}\n",
    ),
]

# The tokenizer half. `strip_noise` is what kept the 3 Aug offender list
# honest, and a brace inside a string or a comment is the thing that broke
# the version before it - so both are asserted here rather than assumed.
SELFTEST_NOISE = [
    (
        "a brace inside a string literal does not open a block",
        'fn f() {\n    let s = "}{";\n    let y = 1;\n}\nfn g() {\n    let z = 1;\n}\n',
        {"f": 4, "g": 3},
    ),
    (
        "a brace inside a raw string does not open a block",
        'fn f() {\n    let s = r#"} { "#;\n}\nfn g() {\n    let z = 1;\n}\n',
        {"f": 3, "g": 3},
    ),
    (
        "a brace inside a comment does not open a block",
        "fn f() {\n    // }\n    let y = 1;\n}\nfn g() {\n    let z = 1;\n}\n",
        {"f": 4, "g": 3},
    ),
]


# Floors for the --headroom real-tree pin below. Comfortably under the tree
# as measured 31 Aug 2026 (775 files, 6,674 production fns) and enormously
# over zero: what this refuses is a report that has quietly stopped reaching
# anything, which reads as a clean tree forever.
HEADROOM_FILE_FLOOR = 500
HEADROOM_FN_FLOOR = 4000

# Fixture corpus for the headroom row builder: (path, raw lines) plus the
# baselines to score it against. Sizes are chosen so both regimes appear and
# so ordering is unambiguous.
HEADROOM_FIXTURE_FILES = [
    ("crates/a/flat_tight.rs", 3990, False),  # flat production, 10 free of 4,000
    ("crates/a/flat_roomy.rs", 1100, False),  # flat production, 2,900 free
    ("crates/a/tests/table.rs", 11950, True),  # whole-file TEST, 50 free of 12,000
    ("crates/a/based.rs", 9184, False),  # baselined 9,132 -> limit 9,332, 148 free
]
HEADROOM_FIXTURE_BASE = {"crates/a/based.rs": 9132}

# Number of assertions in selftest_headroom(). Printed on a green run so a
# case deleted to quiet a mutation shows up in the output - the count is the
# only thing that can report an arm removed rather than fixed.
HEADROOM_CASES = 29

# Same convention, for selftest_argv() below.
ARGV_CASES = 6


def selftest_headroom():
    """Pin the --headroom report: the arithmetic, the asymmetry, the counts.

    The arithmetic cases are deliberately written against LITERAL expected
    numbers rather than against the module's own expressions - a pin that
    recomputes what it is pinning proves nothing.
    """
    bad = 0
    ran = 0

    def check(ok, msg):
        """One assertion. Counted whether it passes or fails, so HEADROOM_CASES
        below can refuse a case that was DELETED rather than fixed."""
        nonlocal bad, ran
        ran += 1
        if not ok:
            print(f"  selftest FAIL: {msg}", file=sys.stderr)
            bad += 1

    def fail(msg):
        nonlocal bad, ran
        ran += 1
        print(f"  selftest FAIL: {msg}", file=sys.stderr)
        bad += 1

    # 1. The two limit rules, both regimes, both tables.
    saved_f, saved_n = dict(BASELINE_FILES), dict(BASELINE_FNS)
    try:
        BASELINE_FILES.clear()
        BASELINE_FILES.update({"crates/a/based.rs": 9132})
        BASELINE_FNS.clear()
        BASELINE_FNS.update({"crates/a/x.rs::big": 700})
        check(
            file_limit("crates/a/flat.rs", False) == (4000, "flat"),
            f"file_limit on an unlisted production file gave {file_limit('crates/a/flat.rs', False)}, "
            "wanted (4000, 'flat')",
        )
        check(
            file_limit("crates/a/tests/t.rs", True) == (12000, "flat"),
            f"file_limit on a whole-file test gave {file_limit('crates/a/tests/t.rs', True)}, "
            "wanted (12000, 'flat') - the 31 Aug test carve-out",
        )
        check(
            file_limit("crates/a/based.rs", False) == (9332, "baselined"),
            f"file_limit on a baselined file gave {file_limit('crates/a/based.rs', False)}, "
            "wanted (9332, 'baselined') - base 9,132 + the flat 200",
        )
        check(
            fn_limit("crates/a/x.rs::small") == (500, "flat"),
            f"fn_limit on an unlisted fn gave {fn_limit('crates/a/x.rs::small')}, wanted (500, 'flat')",
        )
        check(
            fn_limit("crates/a/x.rs::big") == (750, "baselined"),
            f"fn_limit on a baselined fn gave {fn_limit('crates/a/x.rs::big')}, "
            "wanted (750, 'baselined') - base 700 + the flat 50",
        )

        # 2. THE TWO REGIMES, which is the whole reason this mode exists.
        # Flat converts line for line, so there is no bound to model.
        check(
            split_gain(3990, 10, "flat", FILE_CEILING, BASELINE_SLACK) is None,
            "split_gain on a flat target must be None (line for line), not a number",
        )
        # Baselined: a split+ratchet resets free to the flat slack, so with
        # 130 free it buys 200 - 130 = 70, whatever the size of the cut.
        check(
            split_gain(9184, 130, "baselined", FILE_CEILING, BASELINE_SLACK) == 70,
            f"split_gain(9184, 130, baselined) gave "
            f"{split_gain(9184, 130, 'baselined', FILE_CEILING, BASELINE_SLACK)}, wanted 70",
        )
        # ...and it is CONSTANT in the size of the target. This is the
        # falsifiable form of the 31 Aug recalibration: under the retired 2%
        # rule these three differed (and FELL as the split grew, measured in
        # research/SIZE-GATE-BASELINED-MARGINS-2026-08-29.md), so a revert
        # to proportional slack fails this case by producing three numbers.
        gains = [split_gain(s, 130, "baselined", FILE_CEILING, BASELINE_SLACK) for s in (9184, 6000, 4500)]
        check(
            gains == [70, 70, 70],
            f"split_gain must be the constant slack minus free, independent of size; measured {gains}",
        )
        # A target already sitting on MORE free than the slack gains nothing
        # from a ratchet - the floor is 0, never a negative "gain".
        check(
            split_gain(9184, 250, "baselined", FILE_CEILING, BASELINE_SLACK) == 0,
            f"split_gain with free above the slack gave "
            f"{split_gain(9184, 250, 'baselined', FILE_CEILING, BASELINE_SLACK)}, wanted 0",
        )
        # A baselined target already under its ceiling has a stale entry the
        # gate refuses outright, so there is nothing to model.
        check(
            split_gain(100, 2, "baselined", FILE_CEILING, BASELINE_SLACK) is None,
            "split_gain on a baselined target under its ceiling must be None",
        )

        # 3. The row builder, over a fixture corpus with EXACT counts and
        # EXACT order - ascending by free, so line 1 is the urgent one.
        BASELINE_FILES.clear()
        BASELINE_FILES.update(HEADROOM_FIXTURE_BASE)
        BASELINE_FNS.clear()
        fixture_fns = [
            ("crates/a/x.rs", "tight", 10, 497, False),
            ("crates/a/x.rs", "roomy", 90, 20, False),
            ("crates/a/x.rs", "a_test", 200, 900, True),  # test fns are not gated
            # The same name twice: main() gates the LARGEST, so the report
            # must score the largest too or it reports a margin nothing uses.
            ("crates/a/y.rs", "dup", 10, 100, False),
            ("crates/a/y.rs", "dup", 400, 480, False),
        ]
        frows, nrows = headroom_rows(HEADROOM_FIXTURE_FILES, fixture_fns)
        check(len(frows) == 4, f"headroom_rows built {len(frows)} file rows over a 4-file fixture")
        check(
            [r["label"] for r in frows]
            == [
                "crates/a/flat_tight.rs",
                "crates/a/tests/table.rs  [test]",
                "crates/a/based.rs",
                "crates/a/flat_roomy.rs",
            ],
            f"file rows are not sorted by free ascending (test rows scored on their own ceiling): "
            f"{[r['label'] for r in frows]}",
        )
        check(
            [(r["free"], r["kind"]) for r in frows]
            == [(10, "flat"), (50, "flat"), (148, "baselined"), (2900, "flat")],
            f"file row free/kind wrong: {[(r['free'], r['kind']) for r in frows]}",
        )
        check(frows[2]["to_flat"] == 5184, f"to_flat on the baselined row is {frows[2]['to_flat']}, wanted 5184")
        check(len(nrows) == 3, f"headroom_rows built {len(nrows)} fn rows over a fixture with 3 production fns")
        check(
            nrows[0]["free"] == 3 and "tight" in nrows[0]["label"],
            f"tightest fn row is {nrows[0]['label']} at {nrows[0]['free']} free, wanted tight at 3",
        )
        dup = [r for r in nrows if "dup" in r["label"]]
        check(
            len(dup) == 1 and dup[0]["size"] == 480,
            f"a duplicated fn name must score its LARGEST span; got {[r['size'] for r in dup]}",
        )
        check(
            not any("a_test" in r["label"] for r in nrows),
            "a test fn reached the headroom report - only production fns are gated",
        )

        # 4. A baselined row BELOW the fold is still printed. It does not
        # reliably rank near the top (its free is up to 2% of a large size -
        # on 31 Aug 2026 neither baselined FILE was in the tightest twelve),
        # so cutting it off at the fold hides the class the reader came for.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_headroom("t", frows, 1, "4,000-line", BASELINE_SLACK, FILE_REMEDY)
        text = buf.getvalue()
        check("crates/a/based.rs" in text, "a baselined row below the fold was dropped from the report")
        check("flat_roomy" not in text, "a FLAT row below the fold was printed - only baselined rows are rescued")
        check("buys at most +52" in text, "the baselined row printed no split-gain note")

        # 5a. The narrowest line the GATE itself prints. This is the only
        # margin most lanes ever see - nobody runs --list on a push.
        line = narrowest_line(frows, nrows)
        check(
            line is not None and "crates/a/flat_tight.rs 10 free of 4,000" in line,
            f"narrowest_line did not name the tightest file: {line!r}",
        )
        check(
            line is not None and "fn crates/a/x.rs:10 tight 3 free of 500" in line,
            f"narrowest_line did not name the tightest production fn: {line!r}",
        )
        check(narrowest_line([], []) is None, "narrowest_line over nothing must be None, not a line about nothing")

        # 5. used% must FLOOR: 2,990 of 3,000 is 99, never 100. Rounded up it
        # reads as "at the limit" with ten lines still to spend.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_headroom("t", [frows[0]], 5, "4,000-line", BASELINE_SLACK, FILE_REMEDY)
        check("100%" not in buf.getvalue(), "used% rounded 3,990 of 4,000 up to 100 - it must floor")
    finally:
        BASELINE_FILES.clear()
        BASELINE_FILES.update(saved_f)
        BASELINE_FNS.clear()
        BASELINE_FNS.update(saved_n)

    # 6. The real tree. A report that has quietly stopped reaching anything
    # reads as a clean tree forever, so floor what it reaches and require
    # every baselined entry to appear as a row of its own.
    try:
        files, fns = collect()
    except OSError as e:
        fail(f"could not read the tree for the headroom pin ({e}) - run from the repo root")
        return bad
    frows, nrows = headroom_rows(files, fns)
    check(
        len(frows) >= HEADROOM_FILE_FLOOR,
        f"--headroom reached {len(frows)} files, floor is {HEADROOM_FILE_FLOOR} - run from the repo root",
    )
    check(
        len(nrows) >= HEADROOM_FN_FLOOR,
        f"--headroom reached {len(nrows)} production fns, floor is {HEADROOM_FN_FLOOR}",
    )
    # A floor of zero is an assertion about nothing, which is how a floor
    # stops being a floor. Found by mutation: lowering HEADROOM_FILE_FLOOR to
    # 0 was the one arm-mutation the rest of this selftest could not see.
    check(
        HEADROOM_FILE_FLOOR > 0 and HEADROOM_FN_FLOOR > 0,
        f"the headroom floors must be positive; they are "
        f"{HEADROOM_FILE_FLOOR} and {HEADROOM_FN_FLOOR}",
    )
    labelled = {r["label"].split("  [")[0] for r in frows if r["kind"] == "baselined"}
    check(
        labelled == set(BASELINE_FILES),
        f"baselined file rows {sorted(labelled)} do not match BASELINE_FILES {sorted(BASELINE_FILES)}",
    )
    # The case count itself, so an arm DELETED to quiet a mutation is a
    # failure rather than a quieter green.
    if ran != HEADROOM_CASES:
        print(
            f"  selftest FAIL: headroom ran {ran} cases, HEADROOM_CASES says {HEADROOM_CASES} - "
            "a case was added or deleted without moving the count",
            file=sys.stderr,
        )
        bad += 1
    return bad


def selftest_argv():
    """Pin argument recognition: an unknown flag must be a REFUSAL, never a
    silent skip that falls through to the ordinary clean verdict about a
    request nobody honoured. Reproduced 31 Aug 2026 against origin/main:
    `tools/size-gate.py --this-flag-does-not-exist` printed the clean gate
    line at exit 0."""
    bad = 0
    ran = 0

    def check(ok, msg):
        nonlocal bad, ran
        ran += 1
        if not ok:
            print(f"  selftest FAIL: {msg}", file=sys.stderr)
            bad += 1

    check(
        unrecognised_argv(["--this-flag-does-not-exist"]) == "--this-flag-does-not-exist",
        "an unknown flag must be reported, not silently ignored",
    )
    check(unrecognised_argv([]) is None, "no args must not be treated as unrecognised")
    check(unrecognised_argv(["--list"]) is None, "--list must still be recognised")
    check(unrecognised_argv(["--headroom"]) is None, "--headroom must still be recognised")
    check(unrecognised_argv(["--headroom=10"]) is None, "--headroom=N must still be recognised")
    check(unrecognised_argv(["--selftest"]) is None, "--selftest must still be recognised")

    if ran != ARGV_CASES:
        print(
            f"  selftest FAIL: argv ran {ran} cases, ARGV_CASES says {ARGV_CASES} - "
            "a case was added or deleted without moving the count",
            file=sys.stderr,
        )
        bad += 1
    return bad


def selftest():
    bad = 0
    for name, fn_name, want_test, src in SELFTEST:
        clean = strip_noise(src).split("\n")
        mask = test_line_mask(clean)
        got = None
        for n, start, _span in functions(clean):
            if n == fn_name:
                got = start < len(mask) and mask[start]
        if got is None:
            print(f"  selftest FAIL: never found fn {fn_name} in {name}", file=sys.stderr)
            bad += 1
        elif got != want_test:
            scored = "test" if got else "production"
            wanted = "test" if want_test else "production"
            print(f"  selftest FAIL: scored {fn_name} as {scored}, wanted {wanted} - {name}", file=sys.stderr)
            bad += 1
    for name, src, spans in SELFTEST_NOISE:
        got = {n: span for n, _start, span in functions(strip_noise(src).split("\n"))}
        if got != spans:
            print(f"  selftest FAIL: {name} measured {got}, wanted {spans}", file=sys.stderr)
            bad += 1
    # The point of the brace-less fix: assert the OLD brace-only scanner
    # really does swallow the next item, so nobody simplifies it back.
    src = SELFTEST[3][3]
    clean = strip_noise(src).split("\n")
    if not _brace_only_mask(clean)[5]:
        print(
            "  selftest FAIL: the brace-less fixture is not actually brace-less -\n"
            "    the old scanner does not swallow it, so it proves nothing.",
            file=sys.stderr,
        )
        bad += 1
    bad += selftest_headroom()
    bad += selftest_argv()
    if bad:
        print(f"\nsize-gate: {bad} selftest case(s) failed - the gate is not doing its job.", file=sys.stderr)
        return 1
    print(
        f"size-gate: selftest ok ({len(SELFTEST)} scope cases, {len(SELFTEST_NOISE)} tokenizer cases, "
        f"{HEADROOM_CASES} headroom cases, {ARGV_CASES} argv cases)"
    )
    return 0


def _brace_only_mask(clean_lines):
    """The scanner this gate shipped with, kept ONLY for the selftest above."""
    mask = [False] * len(clean_lines)
    i = 0
    while i < len(clean_lines):
        if CFG_TEST.match(clean_lines[i]):
            depth, started, j = 0, False, i
            while j < len(clean_lines):
                s = clean_lines[j]
                depth += s.count("{") - s.count("}")
                if "{" in s:
                    started = True
                if started and depth <= 0:
                    break
                j += 1
            if started:
                for k in range(i, min(j + 1, len(clean_lines))):
                    mask[k] = True
                i = j + 1
                continue
        i += 1
    return mask


KNOWN_FLAGS = {"--selftest", "--headroom", "--list"}


def unrecognised_argv(argv):
    """First arg outside the known set (bare, or `--headroom=N`), or None."""
    for a in argv:
        if a in KNOWN_FLAGS or a.startswith("--headroom="):
            continue
        return a
    return None


def main():
    if "--selftest" in sys.argv:
        return selftest()

    # An unrecognised flag is a REFUSAL naming it, never a silent skip - a
    # stale checkout running a flag this script has not learned yet must not
    # read as a clean verdict about a request nobody honoured. Reproduced
    # 31 Aug 2026: `--this-flag-does-not-exist` fell through every check
    # below and printed the ordinary clean gate at exit 0.
    bad_arg = unrecognised_argv(sys.argv[1:])
    if bad_arg is not None:
        print(
            f"size-gate: unrecognised argument {bad_arg!r} - known flags are "
            "--list, --headroom[=N], --selftest, or no args for the gate. "
            "A stale checkout may be missing a flag this script now supports "
            "- merge origin/main.",
            file=sys.stderr,
        )
        return 1

    for a in sys.argv[1:]:
        # `--headroom=N` for a longer or shorter fold; the default 25 matches
        # --list's. A junk N is a refusal rather than a silent default - a
        # report that quietly ignores what was asked for is how a reader ends
        # up trusting a number nobody produced.
        if a == "--headroom":
            return report_headroom()
        if a.startswith("--headroom="):
            n = a.split("=", 1)[1]
            if not n.isdigit() or int(n) < 1:
                print(f"size-gate: --headroom={n} is not a positive count", file=sys.stderr)
                return 1
            return report_headroom(int(n))

    files, fns = collect()

    if "--list" in sys.argv:
        print("=== largest files (raw lines) ===")
        for p, n, t in sorted(files, key=lambda x: -x[1])[:25]:
            print(f"  {n:7,}  {p}" + ("  [test]" if t else ""))
        print("\n=== longest production functions ===")
        prod = [f for f in fns if not f[4]]
        for p, name, line, span, _ in sorted(prod, key=lambda x: -x[3])[:25]:
            print(f"  {span:7,}  {p}:{line}  {name}")
        print("\n=== longest test functions (not gated) ===")
        test = [f for f in fns if f[4]]
        for p, name, line, span, _ in sorted(test, key=lambda x: -x[3])[:10]:
            print(f"  {span:7,}  {p}:{line}  {name}")
        # At the FOOT on purpose: three handoffs and two chip queues pipe
        # this mode through `head -4` / `head -6`, so nothing may move above
        # the first rows.
        print(
            "\n  (this mode sorts by SIZE and prints no limit - to price a split, use\n"
            "   --headroom, which sorts by what is CLOSEST to its ceiling and says\n"
            "   which KIND of ceiling that is. The two kinds do not split alike.)"
        )
        return 0

    errors = []

    seen_files = {p: (n, t) for p, n, t in files}
    for p, n, t in sorted(files):
        limit, _kind = file_limit(p, t)
        if n > limit:
            errors.append(
                f"file {p} is {n:,} raw lines (limit {limit:,})"
                + (" - it has REGROWN past its baseline" if p in BASELINE_FILES else "")
            )
    for p, base in sorted(BASELINE_FILES.items()):
        if p not in seen_files:
            errors.append(f"baseline entry for missing file {p} - delete the entry")
        else:
            n, t = seen_files[p]
            own = TEST_FILE_CEILING if t else FILE_CEILING
            if n <= own:
                errors.append(
                    f"{p} is now {n:,} lines, under its {own:,} ceiling - "
                    "delete its baseline entry (the recorded numbers only move down)"
                )

    prod_fns = largest_prod_fns(fns)
    for key, (span, line) in sorted(prod_fns.items()):
        limit, _kind = fn_limit(key)
        if span > limit:
            p, name = key.rsplit("::", 1)
            errors.append(
                f"fn {name} ({p}:{line}) is {span:,} lines (limit {limit:,})"
                + (" - it has REGROWN past its baseline" if key in BASELINE_FNS else "")
            )
    for key, base in sorted(BASELINE_FNS.items()):
        if key not in prod_fns:
            errors.append(f"baseline entry for missing fn {key} - delete the entry")
        elif prod_fns[key][0] <= FN_CEILING:
            errors.append(
                f"{key} is now {prod_fns[key][0]:,} lines, under the {FN_CEILING:,} ceiling - "
                "delete its baseline entry (the list only shrinks)"
            )

    if not errors:
        n_files = sum(1 for p in BASELINE_FILES)
        n_fns = sum(1 for k in BASELINE_FNS)
        print(
            f"size-gate: clean ({len(files)} files, {len(prod_fns)} production fns; "
            f"{n_files} file + {n_fns} fn baseline entries still to burn down)"
        )
        line = narrowest_line(*headroom_rows(files, fns))
        if line:
            print(line)
        return 0

    print(f"size-gate: {len(errors)} violation(s):\n", file=sys.stderr)
    for e in errors:
        print(f"  {e}", file=sys.stderr)
    print(
        "\n  New code should stay under the ceilings, and a split at a real seam\n"
        "  is the first choice. If the work in hand cannot absorb one, ADD a\n"
        "  baseline entry at the measured size with a comment naming the split\n"
        "  debt - that is the pressure valve, legal since the 31 Aug 2026\n"
        "  recalibration. The ratchet is unchanged: recorded numbers only move\n"
        "  DOWN, and a listed target that drops under its ceiling reds until\n"
        "  its entry is deleted, in the same commit as the split.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
