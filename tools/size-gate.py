#!/usr/bin/env python3
"""Refuse file and function growth past the recorded baseline. TODO 102 / 106.

The scorecard kept measuring the same drift: TODO 43 split `serve()` to 1,819
lines and it regrew to 2,234 within days; `get_with_progress()` reached 3,942
lines - 2.5x the longest function in any competitor - without any list even
naming it. The 3 Aug offender list missed it because a naive brace counter
died on the first string literal containing a brace. This gate exists so the
§106 splits stay split.

Semantics:
  - Every `.rs` file under crates/ (fuzz dirs excluded) must stay under
    FILE_CEILING raw lines; every PRODUCTION function must stay under
    FN_CEILING lines. Test functions are reported but not gated - a table
    of cases is allowed to be long.
  - Today's offenders are allow-listed in BASELINE with their measured
    size. An entry's limit is its recorded size plus 2% slack, so ordinary
    feature work does not trip it while regrowth does. A false-refusal-prone
    gate gets switched off - that is the fmt-hook lesson.
  - The list only shrinks. When a target drops back under the ceiling the
    gate FAILS until its entry is deleted, in the same commit as the split.
    That is the ratchet.

Test scope is resolved properly (inline `#[cfg(test)]` blocks AND
`#[cfg(test)] mod foo;` making the whole of foo.rs test code) - same
resolver family as tools/lock-gate.py, same reason: naive path-based
counting has already produced one wrong scorecard round.

Usage:
    tools/size-gate.py            # gate: exit 1 on any violation
    tools/size-gate.py --list     # report the largest files and functions
"""

import os
import re
import sys

CRATES = "crates"
FILE_CEILING = 3000  # raw lines; the worst competitor file is ~5,400
FN_CEILING = 500  # production function lines; rustnzb ships zero over 500
SLACK = 1.02  # ordinary feature work must not trip an allow-listed entry

# Measured 4 Aug 2026 (post-v1.0.16). Delete each entry as its target is
# split - the gate refuses stale entries, so deletion is enforced, not hoped.
BASELINE_FILES = {
    # path (relative to repo root): raw lines measured
    # serve/mod.rs was here at 13,837, then 12,988, then 13,310. Phase 4
    # moved its flat free functions out to sibling modules and dispersed
    # its 4,800-line inline `mod tests`; it is 852 lines now, so its entry
    # is GONE. Nothing is left to grandfather.
    # 11,803, then 12,429 after the 8 Aug §129 burst. Two concurrent
    # sessions split it at different seams and both landed: the
    # mid-download password and prefer_external_unrar tests went to
    # tests/daemon_unpackroute/, the five M11 playback rigs to
    # tests/stream_live/. 10,678 with both, so the entry ratchets DOWN.
    # ...and 11,146 after the #34 SAB-parity round. What a credential may
    # do - the full key, the add-only nzbkey, and the bootstrap hatch
    # between them - is one subject and six tests, and moved whole to
    # tests/daemon_authkey/. 10,466. Regrown to 10,699 through the §99
    # try-order and §100 retry merges; the four passworded-archive legs -
    # set_password after the fact, the passwords file consulted at
    # completion, the ENOSPC republish, and the prompt that must not
    # leave the archive packed - are one subject and moved whole to
    # tests/daemon_password/. 10,030.
    "crates/nzbfast/tests/daemon.rs": 10030,
    # 7471 when first measured; two concurrent 5 Aug sessions landed
    # test growth (one-pass rigs + the round-6 crc-retry pricing leg).
    "crates/nzbfast/tests/e2e.rs": 7641,
    # 7165 when first measured, 7375, then 7629 after the 8 Aug burst.
    # Two concurrent sessions emptied it in turn, both on the
    # cleanup_mode_tests pattern: `trash_tests` + `out_umask_tests` to
    # smart/, then the 3,268-line inline `mod tests` to smart/tests.rs
    # + sweep_rename_tests.rs (one file of them would have been over
    # the ceiling on its own). 3,966 with both.
    "crates/nzbfast/src/smart.rs": 3966,
    # 7081 when first measured; peaked at 10,828 during the fault/tuner
    # campaign. TODO 113 ratchet: the payout/safety rigs moved to
    # pool/rig_tests.rs (their own child module), 10,828 -> 7,855, then
    # the session_loop split (1,084 -> 461, its fn entry deleted) paid
    # ~170 lines of extraction overhead (signatures + docs): 8,011.
    # 8,282 after the §114 consumer-steer graduation merged over the
    # split (note_decoded seam + handed/steer-inbox plumbing; its rigs
    # live in rig_tests.rs, which absorbs the test growth), 8,492 after
    # the 8 Aug burst. The remaining inline `mod tests` - 2,443 lines,
    # a third of the file - moved to pool/inline_tests.rs: 6,051.
    # That left ONE line of margin under the limit, so the very next
    # commit to touch the file (§129 3g's response fence) put it back over
    # at 6,421, then 6,483 through the merge. Out of test code to move, so
    # this round took the production seam instead: one worker's whole
    # session lifecycle - dial, pipeline, read, and the dozen ways a
    # session ends - is 1,791 contiguous lines and moved whole to
    # pool/session.rs. 4,698, which is margin measured in hundreds of
    # lines rather than one. Regrown to 5,010 through the §146 tail
    # give-up + shipped-PoolConfig merges; the M11 QueueControl handle
    # (struct + whole impl) moved bodily to pool/queue.rs: 4,224. Regrown
    # to 4,350; the tail dup race and the B3 in-flight wire budget - how
    # the pool spends EXTRA wire on an article somebody else already
    # holds, and the bound on how much wire may be in flight - are the
    # tail of `impl Shared` and moved whole to pool/hedge.rs: 3,946.
    # Regrown to 4,121. This time the whole tail of the file below
    # `fetch_all_sharded` - the worker task, the spare filler, the
    # read-stall note, and every way a run is sealed or a work item
    # requeued/failed - is one subject (sealing) and moved whole to
    # pool/runlife.rs: 3,677. Regrown to 3,745 - five lines of margin -
    # so the Providers-card cap gauge could not land without a split:
    # everything the pool REPORTS rather than does (the per-server
    # gauges, the event ring, the two refusal records) is one subject
    # and moved whole to pool/livestats.rs: 3,365.
    "crates/nzbkit/src/pool.rs": 3365,
    # rig_tests.rs was here at 2,988 (born in the TODO 113 split of the
    # pool's payout/safety rigs), then 3,125 when the §114 consumer-steer
    # rigs replaced the pool-gate ones, then 3,372 through the §129
    # fault campaign. Cut where its own subject changes: every leg that
    # runs MORE THAN ONE fault at a time - the gauntlet matrix, the
    # fight legs, early fanout, the hedge/dup races, live-target
    # parking, the 3g fence - is pool/fault_rigs.rs now. 1,988 lines,
    # under the ceiling, so its entry is GONE. The two shared rig
    # helpers are `pub(super)` and imported by path: a sibling cfg(test)
    # mod is not in scope through `use super::*`, but it is reachable by
    # name, so no third testkit module was needed.
    # 6,192, then 6,480 after the 8 Aug burst. Its 3,018-line inline
    # `mod tests` moved out and split at its own nested-one-pass banner
    # (mod_tests.rs + nested_tests.rs, neither big enough to want an
    # entry of its own): 3,467. Regrown to 3,550 on 13 Aug by the §160
    # plain-member repair and §156.1 chase-spill appends, past the slack.
    # Its instrumentation is one subject and left whole: the latched
    # shape bits with their token/English rendering and the nested
    # prevalence tally are extract/shape.rs now (326 lines, no entry of
    # its own): 3,242.
    "crates/nzbkit/src/extract/mod.rs": 3242,
    # serve/tasks.rs was here at 6,400 (6,056 when first measured, then
    # 6,213 from pre-gate concurrent work) and the 8 Aug merges took it to
    # 6,723 - past the slack, the only file-level offender left on main.
    # It has no inline `mod tests` to give up, so five PRODUCTION seams
    # came out whole to serve/tasks/: the metadata lanes (enrich.rs), the
    # watch folder and its six failure states (watchfolder.rs), index
    # upkeep either side of the scan loop (indexer.rs), the stall tracker
    # + slow-job watchdog (stall.rs), and connection tuning (tuner.rs).
    # 2,684 lines now - under the ceiling, so its entry is GONE. Both of
    # its fn entries below keep their path: spawn_download_worker and
    # spawn_index_scan stayed in the parent.
    # 5946 when first measured; pre-gate concurrent sessions landed 6106,
    # and the 5 Aug session union 6231 (event taxonomy, 5ab52b20), which
    # the §129 mover lane then owed a lowering it could not safely take
    # (the boot() extraction was rewriting the file at that moment). It
    # reached 6,465 instead. Two clusters of `impl Daemon` came out to
    # SIBLING modules, so `pub(super)` still means "pub in serve" and no
    # call site moved: what a finished job is called (out_dir,
    # rename_style, job_suffix, episode_titles, resolve_identity,
    # finalize_names) is serve/naming.rs, and the Daemon half of the
    # mover (move_dest_root, mover_enqueue/process, identify_video,
    # relocate_completed) went to serve/mover.rs beside the lanes that
    # call it. 5,570 - margin measured in hundreds of lines, which is
    # the lesson of the pool.rs round. Regrown to 5,714 through the D3
    # search-log and §73 preview merges; the whole `enqueue` add path
    # moved to daemon_enqueue.rs (a daemon child, the daemon_index
    # shape): 5,266. Regrown to 5,473; two more children on that same
    # shape took every way a job is sent round again (the M32 auto-retry
    # cooldown, the manual retry, and the move-retry ladder under both)
    # to daemon_retry.rs, and the queue on disk - save_queue out,
    # load_queue back - to daemon_persist.rs: 4,910. Regrown to 5,018;
    # two more children on the same shape took what each provider has
    # COST us (bytes billed per server per UTC day, the reliability
    # tally, and the §96.5 block-account arithmetic on top of both) to
    # daemon_usage.rs, and what the daemon does with connections when
    # nothing is downloading (the warm pool, the idle-release policy,
    # and the offline switch over the top) to daemon_idle.rs: 4,630.
    # Regrown to 4,748 - past the slack this time, and caught at a merge
    # rather than in the commit that spent the margin. TWO sessions then
    # split it in parallel; the lanes turned out to be disjoint (no
    # function moved twice, and daemon.rs auto-merged), so both are kept
    # rather than one backed out. How a JOB stops running is one subject
    # end to end (will_auto_retry, the failure report, the sidecar abort,
    # the delete quarantine, park into history, note_queue_idle,
    # save_giveup) and moved whole to daemon_park.rs, a seventh child on
    # the daemon_index shape. How the DAEMON stops is the other - the
    # graceful wind-down shared by mode=shutdown and SIGTERM/SIGINT, the
    # signal handlers over it, and the pause timer that stops the queue
    # only for a while (armed, persisted, restored across a restart) -
    # and moved whole to daemon_shutdown.rs, an eighth. Those are free
    # functions rather than a second `impl Daemon`, so that one is
    # re-exported from daemon.rs and every call site still names it
    # unqualified. 3,783 with both, still over the ceiling: entry stays.
    "crates/nzbfast/src/serve/daemon.rs": 3783,
    # 5,150, then 5,397 after the 8 Aug burst. The inline `mod tests`
    # (the repair math and the mapped driver) moved to
    # par2repair/inline_tests.rs, beside unit_tests.rs: 4,206. Regrown
    # to 4,337 through the 133.1 self-prove and Codex-sweep merges;
    # `impl Reconstructor` moved whole to par2repair/reconstruct.rs
    # (a child of the defining module, so the private fields stay in
    # scope): 3,791.
    "crates/nzbkit/src/par2repair.rs": 3791,
    # rar.rs was here at 4,088 and reached 4,363 as the shatter-fold and
    # fuzz-crash rounds landed. Its inline `mod tests` (1,255 lines) moved
    # to rar/tests.rs beside v4_header_tests.rs, and the fixture writers
    # (a public module, its `nzbkit::rar::fixtures` path unchanged) to
    # rar/fixtures.rs. 2,494, under the ceiling, so its entry is GONE.
    "crates/nzbkit/src/nntp.rs": 3688,
    # release.rs was here at 3,505 and reached 3,586 as the dark-verdict
    # and year-is-an-extension rounds landed. Its inline `mod tests` was
    # 1,427 lines - nearly half the file - and moved whole to
    # release_tests.rs (the mock.rs pattern). 2,159, under the ceiling,
    # so its entry is GONE.
    # extract/crypto.rs was here at 3,365 and reached 3,502. Its inline
    # `mod tests` moved to extract/crypto_tests.rs, leaving 2,112 - under
    # the ceiling, so its entry is GONE.
    # repair.rs was here at 3,305 and reached 3,362 - nine lines of slack
    # left. The recovery-volume side-fetch driver (its own banner in the
    # module doc: the side pool, the volume consumer, the two helpers
    # that price a volume) moved to repair/sidefetch.rs with its tests,
    # leaving 2,909 - under the ceiling, so its entry is GONE too.
}

BASELINE_FNS = {
    # "path::fn_name": lines measured
    # spawn_download_worker was here at 688, then 719, then 770 from
    # pre-gate concurrent work, and reached 831 as the §154 no-servers
    # hold and the §96.5 block-account budgets landed inside it. Three
    # self-contained stretches of the loop moved to serve/tasks/runner.rs:
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
    # to serve/tasks/indexer.rs, where the rest of the index upkeep
    # already lives: the Spotnet scan + promote leg (spot_pass), the
    # category reconcile (reclassify_pending_rows), the retention prune
    # and planner-statistics refresh (retention_and_statistics), and the
    # size-cap eviction (evict_pass_and_republish). 316 lines now - under
    # the ceiling, so its entry is GONE.
}

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
    """True for every line inside an inline `#[cfg(test)]` block."""
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

    files_out = []  # (path, raw_lines)
    fns_out = []  # (path, name, line_1based, span, is_test)
    for p, text in contents.items():
        files_out.append((p, text.count("\n") + 1))
        whole_file_is_test = (
            f"{os.sep}tests{os.sep}" in p or f"{os.sep}benches{os.sep}" in p or p in test_files
        )
        mask = test_line_mask(clean[p])
        for name, start, span in functions(clean[p]):
            is_test = whole_file_is_test or (start < len(mask) and mask[start])
            fns_out.append((p, name, start + 1, span, is_test))
    return files_out, fns_out


def main():
    files, fns = collect()

    if "--list" in sys.argv:
        print("=== largest files (raw lines) ===")
        for p, n in sorted(files, key=lambda x: -x[1])[:25]:
            print(f"  {n:7,}  {p}")
        print("\n=== longest production functions ===")
        prod = [f for f in fns if not f[4]]
        for p, name, line, span, _ in sorted(prod, key=lambda x: -x[3])[:25]:
            print(f"  {span:7,}  {p}:{line}  {name}")
        print("\n=== longest test functions (not gated) ===")
        test = [f for f in fns if f[4]]
        for p, name, line, span, _ in sorted(test, key=lambda x: -x[3])[:10]:
            print(f"  {span:7,}  {p}:{line}  {name}")
        return 0

    errors = []

    seen_files = {p: n for p, n in files}
    for p, n in sorted(files):
        limit = FILE_CEILING
        if p in BASELINE_FILES:
            limit = int(BASELINE_FILES[p] * SLACK)
        if n > limit:
            errors.append(
                f"file {p} is {n:,} raw lines (limit {limit:,})"
                + (" - it has REGROWN past its baseline" if p in BASELINE_FILES else "")
            )
    for p, base in sorted(BASELINE_FILES.items()):
        if p not in seen_files:
            errors.append(f"baseline entry for missing file {p} - delete the entry")
        elif seen_files[p] <= FILE_CEILING:
            errors.append(
                f"{p} is now {seen_files[p]:,} lines, under the {FILE_CEILING:,} ceiling - "
                "delete its baseline entry (the list only shrinks)"
            )

    prod_fns = {}
    for p, name, line, span, is_test in fns:
        if is_test:
            continue
        key = f"{p}::{name}"
        if span > prod_fns.get(key, (0, 0))[0]:
            prod_fns[key] = (span, line)
    for key, (span, line) in sorted(prod_fns.items()):
        limit = FN_CEILING
        if key in BASELINE_FNS:
            limit = int(BASELINE_FNS[key] * SLACK)
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
        return 0

    print(f"size-gate: {len(errors)} violation(s):\n", file=sys.stderr)
    for e in errors:
        print(f"  {e}", file=sys.stderr)
    print(
        "\n  New code must stay under the ceilings. If a listed target was just\n"
        "  split, delete its baseline entry in the same commit. Do not raise a\n"
        "  baseline number to make this pass - the splits are TODO 106 and the\n"
        "  numbers only go down.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
