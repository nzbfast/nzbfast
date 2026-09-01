#!/usr/bin/env python3
"""roundtrip.py - prove every corpus leg round-trips through nzbfast.

    python3 roundtrip.py [legdir ...]       default: every leg under corpus/norar
    python3 roundtrip.py --selftest         the grader's own arms, no client
    python3 roundtrip.py --arrival PLAN L   re-run leg L under an arrival plan

Per leg: serve the leg's articles over loopback NNTP (nzbserve, the
nested-corpus rig), run the real `nzbfast get` against the leg's NZB
into a fresh directory, and grade the END STATE against deobf.json.

WHAT "GRADED" MEANS HERE, and why it is more than the expected files.
The first cut of this grader proved expected paths and explicit
forbidden basenames and said nothing about anything else on disk, which
is precisely the shape that hides a cleanup or collision defect: a
leftover hash name, a duplicate disambiguated into a second copy, a
`.nzbfast-partial` never reaped, a symlink standing in for a payload.
The arms below were commissioned by the wave-4 adversarial review of
this corpus (30 Aug 2026, private notes) as a PREREQUISITE for any of
its adversarial rows becoming corpus legs.

  1. CLOSED-WORLD OUTPUT. Anything in the output tree that no
     expectation claimed and no `allowed_extra` pattern names is a
     failure. See `output_policy` below for how a leg opts in or out
     and why the opt-out exists.
  2. PATH MULTIPLICITY. The tree is a LIST of raw directory entries,
     never a dict keyed by a normalized path. Two real entries cannot
     collapse into one before grading, and one file cannot satisfy two
     expectations - every expectation claims a DISTINCT entry.
  3. THE DESTINATION FILESYSTEM IS MODELLED. Each entry records its
     raw spelling, NFC and NFD forms, case-folded identity and
     (dev, ino); the volume is probed for case folding and unicode
     normalization. A collision row may then name different acceptable
     spellings per volume while keeping ONE no-data-loss invariant.
  4. SPECIAL FILES ARE REFUSED. Grading is by `lstat`: a symlink,
     FIFO, socket or device satisfies nothing unless the row expects
     it by name. The lexical outside-output check is joined by a
     realpath check, so a symlink cannot make an inside path point out.
  5. SPEND IS GRADED WHERE SPEND IS THE BUG. `budget` sets upper
     bounds on repair blocks, bytes on disk, output amplification,
     attempts and wall time. Final bytes alone cannot see a phantom
     repair or an amplification.
  6. ARRIVAL ORDER IS CONTROLLABLE. `--arrival` drives a stall proxy
     in front of nzbserve that holds chosen article requests, so a row
     whose bug needs a particular order can be run under that order
     rather than under whatever the scheduler happened to pick.
  7. HONEST FAILURE IS EXPRESSIBLE. `honest_failure` accepts a nonzero
     exit that retained the right bytes and said why. It never accepts
     rc=0 with wrong or missing output.

MANIFEST COMPATIBILITY, and it is load-bearing. The 50 posted legs were
generated before these arms existed. A manifest with no `schema` key is
a schema-1 manifest and is graded with closed-world OFF, exactly as
before; `generate.py` writes `schema: 2`, which turns it ON. The three
arms that are on for EVERY schema - multiplicity, lstat/special files
and realpath containment - cannot fire on a healthy run, which was
measured over the whole corpus rather than assumed (see the commit that
introduced them). Everything else is opt-in through the manifest.

deobf.json keys this grader reads:

    expected[]        {path|paths|path_by_volume, sha256, bytes}
    forbidden[]       basenames that must not survive anywhere
    race_disjunction  bool - a documented crossed-claim outcome
    known_gap         {log_contains, note} - a documented nzbfast gap
    schema            2 = the arms above default on
    output_policy     {closed_world: bool, allowed_extra: [glob...],
                       reason: str}
    allow_special     [{path: glob, kind: symlink|fifo|socket|device}]
    budget            {metric: upper bound}  (see METRICS)
    honest_failure    {log_contains, rc_must_be_nonzero, retained: []}
    arrival_plans     {name: plan}  (see ArrivalPlan)

Environment: NZBFAST points at the binary (default: the repo's release
build, then the debug build); NZBSERVE as in generate.py. The run sets
NZBFAST_OPEN=1 and NZBFAST_NO_ENRICH=1 itself.
"""

import fnmatch
import hashlib
import json
import os
import re
import selectors
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
NZBSERVE = os.environ.get(
    "NZBSERVE",
    os.path.join(HERE, "..", "nested-corpus", "nzbserve", "target", "release", "nzbserve"),
)


def msg(s):
    print(f"[roundtrip] {s}")


def die(s):
    print(f"[roundtrip] ERROR: {s}", file=sys.stderr)
    sys.exit(1)


def find_nzbfast():
    p = os.environ.get("NZBFAST")
    if p:
        return p
    for sub in ("release", "debug"):
        c = os.path.join(ROOT, "target", sub, "nzbfast")
        if os.path.exists(c):
            return c
    die("no nzbfast binary - build one or set NZBFAST")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- item 3
# The destination filesystem.


class VolumeProfile:
    """What the volume under a path does to a name. Probed, never
    assumed: this repo's own boxes are case-INSENSITIVE NFD-preserving
    APFS, a CI runner is case-sensitive ext4, and a collision row's
    correct end state differs between them while its no-data-loss
    invariant does not."""

    def __init__(self, case_sensitive, preserves_nfd, unicode_note):
        self.case_sensitive = case_sensitive
        self.preserves_nfd = preserves_nfd
        self.unicode_note = unicode_note

    def __repr__(self):
        return (
            f"<volume case_sensitive={self.case_sensitive} "
            f"preserves_nfd={self.preserves_nfd} {self.unicode_note}>"
        )

    @property
    def kind(self):
        return "case_sensitive" if self.case_sensitive else "case_insensitive"

    def as_dict(self):
        return {
            "case_sensitive": self.case_sensitive,
            "preserves_nfd": self.preserves_nfd,
            "unicode": self.unicode_note,
        }


def probe_volume(dirpath):
    """Create throwaway names in `dirpath` and read back what the
    filesystem did with them. Two questions: does it fold case, and
    does it hand back the bytes it was given (NFD preserved) or a
    normalized form."""
    probe = os.path.join(dirpath, ".nzbfast-volume-probe")
    os.makedirs(probe, exist_ok=True)
    try:
        lower = os.path.join(probe, "casefold")
        with open(lower, "w") as f:
            f.write("x")
        case_sensitive = not os.path.exists(os.path.join(probe, "CASEFOLD"))

        # e-acute written DECOMPOSED. A preserving volume lists it back
        # decomposed; HFS+ and some network volumes hand back a
        # different normalization entirely.
        nfd_name = unicodedata.normalize("NFD", "é-probe")
        with open(os.path.join(probe, nfd_name), "w") as f:
            f.write("x")
        listed = [n for n in os.listdir(probe) if n.endswith("-probe")]
        preserves_nfd = bool(listed) and listed[0] == nfd_name
        note = "nfd-preserving" if preserves_nfd else "normalizing"
        if listed and unicodedata.normalize("NFC", listed[0]) != unicodedata.normalize(
            "NFC", nfd_name
        ):
            note = "unicode-mangling"
        return VolumeProfile(case_sensitive, preserves_nfd, note)
    finally:
        shutil.rmtree(probe, ignore_errors=True)


# ---------------------------------------------------------------- item 2
# The output tree, as a LIST.


class Entry:
    """One raw directory entry. `rel` is the exact bytes-as-str the
    filesystem handed back - the normalized forms are DERIVED and are
    never the identity."""

    __slots__ = (
        "rel",
        "abspath",
        "kind",
        "size",
        "dev",
        "ino",
        "nlink",
        "claimed_by",
        "_sha",
    )

    def __init__(self, rel, abspath, st):
        self.rel = rel
        self.abspath = abspath
        self.kind = kind_of(st)
        self.size = st.st_size
        self.dev = st.st_dev
        self.ino = st.st_ino
        self.nlink = st.st_nlink
        self.claimed_by = None
        self._sha = None

    @property
    def nfc(self):
        return unicodedata.normalize("NFC", self.rel)

    @property
    def nfd(self):
        return unicodedata.normalize("NFD", self.rel)

    @property
    def fold(self):
        return self.nfc.casefold()

    @property
    def base(self):
        return os.path.basename(self.rel)

    def sha256(self):
        if self._sha is None:
            self._sha = sha256_file(self.abspath)
        return self._sha

    def as_dict(self):
        return {
            "path": self.rel,
            "nfc": self.nfc,
            "fold": self.fold,
            "kind": self.kind,
            "bytes": self.size,
            "id": [self.dev, self.ino],
            "nlink": self.nlink,
        }


def kind_of(st):
    m = st.st_mode
    if stat.S_ISLNK(m):
        return "symlink"
    if stat.S_ISREG(m):
        return "file"
    if stat.S_ISDIR(m):
        return "dir"
    if stat.S_ISFIFO(m):
        return "fifo"
    if stat.S_ISSOCK(m):
        return "socket"
    if stat.S_ISBLK(m) or stat.S_ISCHR(m):
        return "device"
    return "other"


def scan_tree(out):
    """Every entry under `out`, one object each, by LSTAT. Directories
    come back too - an empty one is debris a closed-world row should
    see, and a non-empty one is implied by its files."""
    entries = []
    empty_dirs = []
    for root, dirs, files in os.walk(out, followlinks=False):
        for d in list(dirs):
            p = os.path.join(root, d)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                # A symlinked directory is an entry to judge, not a
                # tree to descend - os.walk with followlinks=False
                # already refuses to descend, but it still lists it
                # under `dirs`, where nothing else would look at it.
                dirs.remove(d)
                entries.append(Entry(os.path.relpath(p, out), p, st))
            elif not os.listdir(p):
                empty_dirs.append(Entry(os.path.relpath(p, out), p, st))
        for f in files:
            p = os.path.join(root, f)
            entries.append(Entry(os.path.relpath(p, out), p, os.lstat(p)))
    return entries, empty_dirs


# ---------------------------------------------------------------- matching


def wanted_paths(exp, profile):
    """The acceptable relative paths for one expectation. `path` is the
    single-path shorthand; `paths` is an explicit alternation; and
    `path_by_volume` picks by the probed volume, which is how a
    collision row says the same thing about two different filesystems
    without giving up the invariant that the bytes are all still there."""
    by_vol = exp.get("path_by_volume")
    if by_vol:
        for key in (profile.kind, "any"):
            if key in by_vol:
                v = by_vol[key]
                return list(v) if isinstance(v, list) else [v]
        return []
    if exp.get("paths"):
        return list(exp["paths"])
    p = exp.get("path")
    return [] if p is None else [p]


def _norm_sep(p):
    return p.replace("/", os.sep)


def match_expected(expected, entries, profile):
    """Claim one DISTINCT entry per expectation. Passes, strongest
    evidence first: exact raw spelling, then NFC equality, then
    case-folded equality (only where the volume folds case, otherwise a
    case variant is reported as the near-miss it is). Path-null
    expectations claim by content afterwards, so a named file is never
    consumed by an anywhere-expectation that some other name would have
    satisfied."""
    problems = []
    named = [(i, e) for i, e in enumerate(expected) if wanted_paths(e, profile)]
    anywhere = [(i, e) for i, e in enumerate(expected) if not wanted_paths(e, profile)]
    unresolved = []

    def claim(idx, exp, pred):
        for ent in entries:
            if ent.claimed_by is None and pred(ent):
                ent.claimed_by = idx
                return ent
        return None

    pending = []
    for idx, exp in named:
        wants = [_norm_sep(p) for p in wanted_paths(exp, profile)]
        ent = claim(idx, exp, lambda e, w=wants: e.rel in w)
        if ent is None:
            pending.append((idx, exp, wants))
        else:
            check_content(exp, ent, problems)
    still = []
    for idx, exp, wants in pending:
        nfcs = {unicodedata.normalize("NFC", w) for w in wants}
        ent = claim(idx, exp, lambda e, n=nfcs: e.nfc in n)
        if ent is None:
            still.append((idx, exp, wants))
        else:
            check_content(exp, ent, problems)
    for idx, exp, wants in still:
        folds = {unicodedata.normalize("NFC", w).casefold() for w in wants}
        ent = claim(idx, exp, lambda e, f=folds: e.fold in f) if not profile.case_sensitive else None
        if ent is None:
            unresolved.append((idx, exp, wants))
            near = [e.rel for e in entries if e.claimed_by is None and e.fold in folds]
            hint = f" (a case variant is on disk: {near})" if near else ""
            problems.append(f"expected {wants[0]} missing{hint}")
        else:
            check_content(exp, ent, problems)

    for idx, exp in anywhere:
        ent = claim(
            idx,
            exp,
            lambda e, x=exp: e.kind == "file"
            and e.size == x["bytes"]
            and e.sha256() == x["sha256"],
        )
        if ent is None:
            problems.append(
                f"expected content ({exp['bytes']} B, {exp['sha256'][:12]}...) found nowhere"
            )
    return problems, unresolved


def check_content(exp, ent, problems):
    if ent.kind != "file":
        problems.append(f"expected {ent.rel} is a {ent.kind}, not a regular file")
        return
    if ent.size != exp["bytes"] or ent.sha256() != exp["sha256"]:
        problems.append(f"expected {ent.rel} present but wrong bytes")


# ------------------------------------------------------------ items 1/4/5/7


def policy(deobf):
    """Closed-world is ON for a schema-2 manifest and OFF for the
    schema-1 manifests the 50 posted legs carry, unless the leg says
    otherwise. The opt-out is per row and must carry a reason: a leg
    whose contract genuinely retains uncovered junk or recovery
    furniture has to SAY so, which is the difference between a
    documented allowance and a grader that never looked."""
    pol = dict(deobf.get("output_policy") or {})
    if pol.get("closed_world") is None:
        pol["closed_world"] = int(deobf.get("schema", 1)) >= 2
    pol.setdefault("allowed_extra", [])
    return pol


def extra_allowed(rel, patterns):
    base = os.path.basename(rel)
    posix = rel.replace(os.sep, "/")
    for pat in patterns:
        if fnmatch.fnmatch(posix, pat) or fnmatch.fnmatch(base, pat):
            return True
    return False


def closed_world_problems(deobf, entries, empty_dirs):
    pol = policy(deobf)
    if not pol["closed_world"]:
        return []
    pats = pol["allowed_extra"]
    problems = []
    for e in entries:
        if e.claimed_by is None and not extra_allowed(e.rel, pats):
            problems.append(f"unexpected output: {e.rel} ({e.kind}, {e.size} B)")
    for d in empty_dirs:
        if not extra_allowed(d.rel, pats):
            problems.append(f"unexpected empty directory: {d.rel}")
    return problems


def special_problems(deobf, entries, empty_dirs):
    """lstat is the grader's eye. A symlink, FIFO, socket or device is
    a failure wherever it sits, whether or not an expectation happened
    to want that path - a file symlink inside the output must not
    satisfy an expected hash by following a target outside the job."""
    allow = deobf.get("allow_special") or []

    def permitted(e):
        posix = e.rel.replace(os.sep, "/")
        for a in allow:
            if a.get("kind") not in (None, e.kind):
                continue
            pat = a.get("path", "*")
            if fnmatch.fnmatch(posix, pat) or fnmatch.fnmatch(e.base, pat):
                return True
        return False

    problems = []
    for e in list(entries) + list(empty_dirs):
        if e.kind in ("file", "dir"):
            continue
        if not permitted(e):
            problems.append(f"special file in the output: {e.rel} is a {e.kind}")
    return problems


def containment_problems(out, entries, empty_dirs):
    """The lexical check that the job dir gained nothing beside out/
    stays in `run_leg`. This is its other half: every entry's REALPATH
    must still be inside the output, so a symlink (or a symlinked
    parent) cannot make an inside path point out."""
    out_real = os.path.realpath(out)
    problems = []
    for e in list(entries) + list(empty_dirs):
        rp = os.path.realpath(e.abspath)
        if rp != out_real and not rp.startswith(out_real + os.sep):
            problems.append(f"output entry points outside the job: {e.rel} -> {rp}")
    return problems


# The measurable metrics. `harness` values are measured by this script
# and always exist; `log` values are counted out of the client's own
# output, where an absent line legitimately means zero - so each of
# those regexes is pinned against a captured real log line in
# --selftest, which is the only thing standing between a broken pattern
# and a budget that passes everything.
LOG_METRICS = {
    # settle.rs: warn!(target: "verify", "✘ {} - {}/{} blocks bad", ..)
    "bad_blocks": (re.compile(r"(\d+)/(\d+) blocks bad"), "sum1"),
    # repair.rs: "unrepairable: {needed} blocks needed, only {have} .."
    #            "recovery short ({needed} blocks needed, {have} in the NZB)"
    "repair_blocks_needed": (re.compile(r"(\d+) blocks needed"), "max1"),
    # repair.rs: "removed {swept} spent source file(s) .."
    "spent_sources_removed": (re.compile(r"removed (\d+) spent source file"), "sum1"),
    # par2repair: each repair pass announces itself once per set.
    "repair_attempts": (re.compile(r"(?m)^.*\brepairing\b.*$"), "count"),
}
HARNESS_METRICS = (
    "wall_secs",
    "output_bytes",
    "output_files",
    "output_amplification",
)


def collect_metrics(log, entries, wall_secs, expected_bytes):
    m = {
        "wall_secs": round(wall_secs, 3),
        "output_bytes": sum(e.size for e in entries if e.kind == "file"),
        "output_files": sum(1 for e in entries if e.kind == "file"),
    }
    m["output_amplification"] = (
        round(m["output_bytes"] / expected_bytes, 4) if expected_bytes else None
    )
    for name, (rx, how) in LOG_METRICS.items():
        hits = rx.findall(log)
        if how == "count":
            m[name] = len(hits)
        else:
            vals = [int(h[0] if isinstance(h, tuple) else h) for h in hits]
            m[name] = (sum(vals) if how == "sum1" else max(vals)) if vals else 0
    return m


def budget_problems(deobf, metrics):
    """A budget naming a metric this grader cannot measure is a
    REFUSAL, never a quiet pass - a typo'd key would otherwise read as
    a leg that was graded on its spend and was not."""
    budget = deobf.get("budget") or {}
    problems = []
    for key, limit in budget.items():
        if key not in LOG_METRICS and key not in HARNESS_METRICS:
            problems.append(f"budget names an unknown metric: {key}")
            continue
        got = metrics.get(key)
        if got is None:
            problems.append(f"budget names {key} but the run produced no such measurement")
        elif got > limit:
            problems.append(f"over budget: {key} = {got} > {limit}")
    return problems


def honest_failure_verdict(deobf, entries, log, rc, profile):
    """Item 7. A nonzero exit is an acceptable end state when the row
    says so AND the client said why AND the bytes it promised to keep
    are still there byte-exact. rc=0 is never rescued by this - it goes
    through the full expected/forbidden/closed-world grading like any
    other run."""
    hf = deobf.get("honest_failure")
    if not hf or rc == 0:
        return None
    want = hf.get("log_contains")
    if want and want not in log:
        return [f"honest-failure row exited {rc} without its diagnostic ({want!r})"]
    problems, _ = match_expected(hf.get("retained", []), entries, profile)
    if problems:
        return [f"honest-failure row exited {rc} but {p}" for p in problems]
    return ["HONEST-FAIL"]


# ------------------------------------------------------------------- grade


def load_deobf(legdir):
    dpath = os.path.join(legdir, "deobf.json")
    if os.path.exists(dpath):
        return json.load(open(dpath))
    man = json.load(open(os.path.join(legdir, "manifest.json")))
    deobf = {
        "leg": man["leg"],
        "expected": [
            {"path": p.get("path"), "sha256": p["sha256"], "bytes": p["bytes"]}
            for p in man["payloads"]
        ],
        "forbidden": [],
    }
    # x2-depth10-ladder deliberately exceeds nzbfast's depth-5 cap (see
    # bench/nested-corpus/README.md) - the deepest layer stays a healthy
    # archive rather than the final payload.
    if man["leg"].startswith("x2-"):
        deobf["known_gap"] = {
            "log_contains": "",
            "note": "nested extraction is capped at depth 5 by design",
        }
    return deobf


def grade(legdir, out, log, rc, wall_secs=0.0, deobf=None, report=None):
    """deobf.json when the leg has one (the no-RAR tier: exact names);
    otherwise the nested-corpus manifest.json payload pins, graded by
    content anywhere in the tree (classify.py's rule - archive legs end
    in extraction, whose landed names are the member names).

    Returns a list of problems; the singleton lists ["RACE"], ["GAP"]
    and ["HONEST-FAIL"] are the documented alternative outcomes."""
    if deobf is None:
        deobf = load_deobf(legdir)
    profile = probe_volume(out)
    entries, empty_dirs = scan_tree(out)
    if report is not None:
        report["volume"] = profile.as_dict()
        report["entries"] = [e.as_dict() for e in entries]

    if rc != 0:
        if deobf.get("race_disjunction") and "blocks bad" in log:
            return ["RACE"]  # documented alternative outcome, not a failure
        gap = deobf.get("known_gap")
        if gap and gap["log_contains"] in log:
            return ["GAP"]  # documented nzbfast gap - the leg still measures
        hf = honest_failure_verdict(deobf, entries, log, rc, profile)
        if hf is not None:
            return hf
        return [f"nzbfast exited {rc}"]
    if (deobf.get("honest_failure") or {}).get("rc_must_be_nonzero"):
        return ["this row must end nonzero; nzbfast exited 0"]

    problems, _ = match_expected(deobf["expected"], entries, profile)

    for bad in deobf.get("forbidden", []):
        for e in entries:
            if e.base == bad or unicodedata.normalize("NFC", e.base) == unicodedata.normalize(
                "NFC", bad
            ):
                problems.append(f"forbidden (obfuscated) name survived: {e.rel}")

    problems += special_problems(deobf, entries, empty_dirs)
    problems += containment_problems(out, entries, empty_dirs)
    problems += closed_world_problems(deobf, entries, empty_dirs)

    expected_bytes = sum(e["bytes"] for e in deobf["expected"])
    metrics = collect_metrics(log, entries, wall_secs, expected_bytes)
    if report is not None:
        report["metrics"] = metrics
    problems += budget_problems(deobf, metrics)

    # A leg with a documented gap may also miss its payload at rc=0
    # (the depth-cap leg finishes cleanly with the deepest layer still
    # an archive). The gap is reported, never silently passed.
    if problems and deobf.get("known_gap") is not None:
        return ["GAP"]
    return problems


# ---------------------------------------------------------------- item 6
# Arrival order.


class ArrivalPlan:
    """A stall plan for article requests, applied by `StallProxy`.

        {"stall": [{"match": "*.par2*", "delay_ms": 1500,
                    "after_others": 8, "only_first": true}]}

    `match` is an fnmatch pattern against the requested message-id.
    A held command is forwarded when BOTH conditions its rule states
    are met - `delay_ms` since it arrived, and `after_others` other
    commands forwarded since. `only_first` stalls the first request for
    an id and lets retries through, which is the mock rig's `Chaos::
    stall` semantics: the test then proves recovery rather than
    permanent failure.

    `max_hold_ms` (default 5 s) is a CEILING and it is load-bearing.
    `after_others` counts commands the proxy forwards, and a client
    with a bounded window can stop sending: if every connection is
    waiting on a held request, nothing new is ever forwarded and the
    gate never opens. Measured, not theorised - a plan with
    `after_others: 3` over this corpus's baseline leg wedged the run
    until the client's own timeout. The ceiling turns a would-be
    deadlock into a bounded delay, which still reorders arrival, and
    the run reports how many requests were actually held so a plan that
    matched nothing cannot read as a pass.

    WHY THE REQUEST AND NOT THE RESPONSE. NNTP answers one connection's
    commands in the order it received them, so holding a COMMAND is
    enough to control the order its answer arrives in, and it needs no
    response parsing at all - no dot-stuffing, no multi-line framing,
    nothing that can desynchronize the stream and turn a scheduling
    test into a protocol bug."""

    def __init__(self, spec):
        self.rules = []
        for r in (spec or {}).get("stall", []):
            self.rules.append(
                {
                    "match": r.get("match", "*"),
                    "delay_ms": int(r.get("delay_ms", 0)),
                    "after_others": int(r.get("after_others", 0)),
                    "max_hold_ms": int(r.get("max_hold_ms", 5000)),
                    "only_first": bool(r.get("only_first", False)),
                }
            )
        self.seen = {}
        self.lock = threading.Lock()

    def rule_for(self, mid):
        for r in self.rules:
            if fnmatch.fnmatch(mid, r["match"]):
                if r["only_first"]:
                    with self.lock:
                        n = self.seen.get(mid, 0)
                        self.seen[mid] = n + 1
                    if n:
                        return None
                return r
        return None


ARTICLE_CMD = re.compile(rb"^(ARTICLE|BODY|HEAD|STAT)\s+(<[^>]*>)", re.I)


class StallProxy:
    """A loopback NNTP proxy that holds chosen article requests. Client
    bytes are parsed only far enough to see a command line and its
    message-id; everything else - and every byte coming back - is
    forwarded verbatim."""

    def __init__(self, upstream_port, plan):
        self.upstream_port = upstream_port
        self.plan = plan
        self.forwarded = 0
        self.stalled = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self._threads = []

    def start(self):
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._threads.append(t)
        return self

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                cs, _ = self.sock.accept()
            except OSError:
                return
            t = threading.Thread(target=self._serve, args=(cs,), daemon=True)
            t.start()
            self._threads.append(t)

    def _serve(self, cs):
        us = socket.socket()
        try:
            us.connect(("127.0.0.1", self.upstream_port))
        except OSError:
            cs.close()
            return
        held = []  # (release_after_forwarded, ready_at, line)
        buf = b""
        sel = selectors.DefaultSelector()
        sel.register(cs, selectors.EVENT_READ, "client")
        sel.register(us, selectors.EVENT_READ, "server")
        try:
            while not self._stop.is_set():
                for key, _ in sel.select(timeout=0.05):
                    who = key.data
                    try:
                        data = key.fileobj.recv(65536)
                    except OSError:
                        data = b""
                    if not data:
                        return
                    if who == "server":
                        cs.sendall(data)
                        continue
                    buf += data
                    while b"\r\n" in buf:
                        line, buf = buf.split(b"\r\n", 1)
                        line += b"\r\n"
                        rule = self._rule(line)
                        if rule is None:
                            self._forward(us, line)
                        else:
                            with self._lock:
                                gate = self.forwarded + rule["after_others"]
                            now = time.monotonic()
                            held.append(
                                (
                                    gate,
                                    now + rule["delay_ms"] / 1000.0,
                                    now + rule["max_hold_ms"] / 1000.0,
                                    line,
                                )
                            )
                            self.stalled += 1
                self._release(us, held)
        finally:
            sel.close()
            for s in (cs, us):
                try:
                    s.close()
                except OSError:
                    pass

    def _rule(self, line):
        m = ARTICLE_CMD.match(line)
        if not m:
            return None
        mid = m.group(2).decode("latin-1")
        return self.plan.rule_for(mid)

    def _forward(self, us, line):
        us.sendall(line)
        with self._lock:
            self.forwarded += 1

    def _release(self, us, held):
        now = time.monotonic()
        with self._lock:
            fwd = self.forwarded
        keep = []
        for gate, ready_at, deadline, line in held:
            if (fwd >= gate and now >= ready_at) or now >= deadline:
                self._forward(us, line)
            else:
                keep.append((gate, ready_at, deadline, line))
        held[:] = keep


# -------------------------------------------------------------- the runner


def run_leg(legdir, nzbfast, arrival=None, keep_out=None):
    leg = os.path.basename(os.path.abspath(legdir))
    nzb = os.path.join(legdir, f"{leg}.nzb")
    if not os.path.exists(nzb):
        die(f"{leg}: no NZB - run generate.py first")
    deobf = load_deobf(legdir)
    plan_spec = None
    if arrival:
        plans = deobf.get("arrival_plans") or {}
        if arrival not in plans:
            die(f"{leg}: no arrival plan named {arrival!r} (have: {sorted(plans)})")
        plan_spec = plans[arrival]
    port = free_port()
    srv = subprocess.Popen(
        [NZBSERVE, "serve", legdir, "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    proxy = None
    try:
        deadline = time.time() + 30
        ready = False
        while time.time() < deadline:
            line = srv.stdout.readline()
            if "NNTP ready" in line:
                ready = True
                break
            if srv.poll() is not None:
                break
        if not ready:
            die(f"{leg}: nzbserve never came up on {port}")
        client_port = port
        if plan_spec is not None:
            proxy = StallProxy(port, ArrivalPlan(plan_spec)).start()
            client_port = proxy.port

        with tempfile.TemporaryDirectory(prefix=f"captrip-{leg}-") as tmp:
            cfgdir = os.path.join(tmp, "cfg")
            job = os.path.join(tmp, "job")
            out = os.path.join(job, "out")
            os.makedirs(cfgdir)
            os.makedirs(job)
            cfg = os.path.join(cfgdir, "config.json")
            with open(cfg, "w") as f:
                json.dump(
                    {
                        "servers": [
                            {
                                "host": "127.0.0.1",
                                "port": client_port,
                                "tls": False,
                                "retention_days": 0,
                            }
                        ]
                    },
                    f,
                )
            env = dict(os.environ, NZBFAST_OPEN="1", NZBFAST_NO_ENRICH="1")
            t0 = time.monotonic()
            r = subprocess.run(
                [nzbfast, "--config", cfg, "get", nzb, "--out", out,
                 "--connections", "4", "--window", "3", "--decoders", "4"],
                capture_output=True,
                text=True,
                env=env,
                timeout=180,
            )
            wall = time.monotonic() - t0
            log = r.stdout + r.stderr
            report = {}
            problems = grade(legdir, out, log, r.returncode, wall, deobf, report)
            # Containment: the job dir's parent gained nothing beside out/.
            stray = [n for n in os.listdir(job) if n != "out"]
            if stray:
                problems.append(f"files escaped the output dir: {stray}")
            if keep_out:
                os.makedirs(keep_out, exist_ok=True)
                with open(os.path.join(keep_out, f"{leg}.json"), "w") as f:
                    json.dump(
                        {"leg": leg, "rc": r.returncode, "problems": problems, **report},
                        f,
                        indent=2,
                    )
                with open(os.path.join(keep_out, f"{leg}.log"), "w") as f:
                    f.write(log)
            tag = f"{leg}[{arrival}]" if arrival else leg
            if proxy:
                # An arrival plan that stalled nothing is a plan whose
                # pattern has stopped matching, which reads exactly like
                # a leg that passed under adverse order and did not.
                msg(f"{tag}: proxy forwarded {proxy.forwarded}, held {proxy.stalled}")
                if proxy.stalled == 0:
                    problems.append(
                        f"arrival plan {arrival!r} stalled no request - the plan "
                        "matched nothing, so this run proves nothing"
                    )
            if problems == ["RACE"]:
                msg(f"{tag}: PASS (crossed-claim race outcome, documented - finding F1)")
                return True
            if problems == ["HONEST-FAIL"]:
                msg(f"{tag}: PASS (honest failure - rc {r.returncode}, retained bytes intact)")
                return True
            if problems == ["GAP"]:
                note = (deobf.get("known_gap") or {}).get(
                    "note", "nested extraction is capped at depth 5 by design"
                )
                msg(f"{tag}: GAP (documented) - {note}")
                return True
            if problems:
                for p in problems:
                    msg(f"{tag}: FAIL - {p}")
                sys.stderr.write(log[-4000:] + "\n")
                return False
            msg(f"{tag}: PASS")
            return True
    finally:
        if proxy:
            proxy.stop()
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()



# ---------------------------------------------------------------- selftest


REAL_LOG_LINES = {
    # Captured from a real `nzbfast get` over this corpus. These pin the
    # LOG_METRICS patterns: a regex that has quietly stopped matching
    # counts zero, and zero is under every budget - so a broken pattern
    # reads as a leg that was graded on its spend and was not.
    "bad_blocks": "  WARN verify: \u2718 Damaged.Head.mkv - 13/1986 blocks bad",
    "repair_blocks_needed": (
        "  WARN repair: unrepairable: 1984 blocks needed, only 397 recovery "
        "blocks in the NZB"
    ),
    "spent_sources_removed": (
        "  INFO repair: removed 2 spent source file(s) the repair adopted from"
    ),
    "repair_attempts": "  INFO par2: repairing Damaged.Head.mkv from 397 blocks",
}


class _Selftest:
    def __init__(self):
        self.fail = 0
        self.n = 0

    def case(self, name, cond):
        self.n += 1
        if not cond:
            self.fail += 1
            print(f"  FAIL  {name}")
        return bool(cond)


_REACHED = {"entries": 0, "grades": 0, "proxy_lines": 0}


def _entry(tmp, rel, data=b"", kind="file"):
    """An Entry with a real lstat behind it and an overridden spelling -
    the point of most cases here is a name the local filesystem cannot
    be made to create (an NFC/NFD pair on a normalization-insensitive
    volume is the one that matters), so the entry is built from a real
    file and then re-labelled."""
    _REACHED["entries"] += 1
    real = os.path.join(tmp, "e%d" % abs(hash(rel)))
    with open(real, "wb") as f:
        f.write(data)
    e = Entry(rel, real, os.lstat(real))
    e.kind = kind
    e.size = len(data)
    e._sha = hashlib.sha256(data).hexdigest()
    return e


def _exp(path, data):
    return {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _write(root, rel, data=b"x"):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    return p


CASE_INSENSITIVE = VolumeProfile(False, True, "nfd-preserving")
CASE_SENSITIVE = VolumeProfile(True, True, "nfd-preserving")


def selftest():  # noqa: C901 - one flat list of cases, by design
    t = _Selftest()
    reached = _REACHED
    for k in reached:
        reached[k] = 0

    def G(*a, **k):
        reached["grades"] += 1
        return grade(*a, **k)

    with tempfile.TemporaryDirectory(prefix="roundtrip-selftest-") as tmp:
        # -- item 3: the volume is PROBED, never assumed ---------------
        prof = probe_volume(tmp)
        t.case("volume probe answers both questions",
               isinstance(prof.case_sensitive, bool) and isinstance(prof.preserves_nfd, bool))
        t.case("volume probe leaves nothing behind",
               not os.path.exists(os.path.join(tmp, ".nzbfast-volume-probe")))
        t.case("volume kind names the fold behaviour",
               prof.kind in ("case_sensitive", "case_insensitive"))

        # -- item 2: multiplicity -------------------------------------
        a, b = b"AAAA", b"BBBB"
        nfc = unicodedata.normalize("NFC", "caf\u00e9.bin")
        nfd = unicodedata.normalize("NFD", "caf\u00e9.bin")
        ents = [_entry(tmp, nfc, a), _entry(tmp, nfd, b)]
        t.case("an NFC and an NFD spelling are TWO entries", ents[0].rel != ents[1].rel)
        t.case("and they share one NFC key", ents[0].nfc == ents[1].nfc)
        probs, _ = match_expected([_exp(nfc, a), _exp(nfd, b)], ents, CASE_SENSITIVE)
        t.case("both distinct entries can be claimed at once", probs == [])
        # The v1 grader keyed a dict on the NFC path, so the second
        # entry OVERWROTE the first and one of these two expectations
        # was graded against the other's bytes.
        ents = [_entry(tmp, nfc, a), _entry(tmp, nfd, b)]
        probs, _ = match_expected([_exp(nfc, b), _exp(nfd, a)], ents, CASE_SENSITIVE)
        t.case("an NFC/NFD collapse cannot swap two files' bytes",
               len(probs) == 2 and all("wrong bytes" in p for p in probs))
        ents = [_entry(tmp, "one.bin", a)]
        probs, _ = match_expected([_exp("one.bin", a), _exp("one.bin", a)], ents, CASE_SENSITIVE)
        t.case("one file cannot satisfy two expectations",
               len(probs) == 1 and "missing" in probs[0])
        ents = [_entry(tmp, "x.bin", a)]
        probs, _ = match_expected(
            [{"path": None, "bytes": 4, "sha256": hashlib.sha256(a).hexdigest()},
             {"path": None, "bytes": 4, "sha256": hashlib.sha256(a).hexdigest()}],
            ents, CASE_SENSITIVE)
        t.case("nor two anywhere-expectations",
               len(probs) == 1 and "found nowhere" in probs[0])
        ents = [_entry(tmp, "named.bin", a), _entry(tmp, "spare.bin", a)]
        probs, _ = match_expected(
            [_exp("named.bin", a),
             {"path": None, "bytes": 4, "sha256": hashlib.sha256(a).hexdigest()}],
            ents, CASE_SENSITIVE)
        t.case("a named expectation is not consumed by an anywhere one", probs == [])

        # -- item 3: per-volume acceptable names ----------------------
        ents = [_entry(tmp, "COLLIDE.bin", a)]
        exp = {"path_by_volume": {"case_insensitive": ["COLLIDE.bin"],
                                  "case_sensitive": ["collide.bin"]},
               "bytes": 4, "sha256": hashlib.sha256(a).hexdigest()}
        probs, _ = match_expected([exp], ents, CASE_INSENSITIVE)
        t.case("path_by_volume takes the insensitive spelling", probs == [])
        ents = [_entry(tmp, "COLLIDE.bin", a)]
        probs, _ = match_expected([exp], ents, CASE_SENSITIVE)
        t.case("and refuses it on a case-sensitive volume",
               len(probs) == 1 and "missing" in probs[0])
        ents = [_entry(tmp, "COLLIDE.bin", a)]
        probs, _ = match_expected([_exp("collide.bin", a)], ents, CASE_INSENSITIVE)
        t.case("a case variant is claimed where the volume folds case", probs == [])
        ents = [_entry(tmp, "COLLIDE.bin", a)]
        probs, _ = match_expected([_exp("collide.bin", a)], ents, CASE_SENSITIVE)
        t.case("and is reported as the near miss it is where it does not",
               len(probs) == 1 and "case variant is on disk" in probs[0])
        ents = [_entry(tmp, "alt.bin", a)]
        probs, _ = match_expected(
            [{"paths": ["first.bin", "alt.bin"], "bytes": 4,
              "sha256": hashlib.sha256(a).hexdigest()}], ents, CASE_SENSITIVE)
        t.case("an explicit alternation accepts either spelling", probs == [])

    # -- items 1, 4 and the containment half, over a REAL tree --------
    with tempfile.TemporaryDirectory(prefix="roundtrip-tree-") as tmp:
        out = os.path.join(tmp, "out")
        os.makedirs(out)
        pay = b"payload-bytes"
        _write(out, "Real.Name.bin", pay)
        _write(out, "Xk2vRq81LmZ", b"leftover-hash")
        base = {"leg": "t", "expected": [_exp("Real.Name.bin", pay)], "forbidden": []}
        t.case("schema 1 keeps the open world (the 50 posted legs)",
               G(tmp, out, "", 0, 0.0, dict(base)) == [])
        v2 = dict(base, schema=2)
        probs = G(tmp, out, "", 0, 0.0, v2)
        t.case("schema 2 closes it and names the leftover hash",
               len(probs) == 1 and "unexpected output: Xk2vRq81LmZ" in probs[0])
        v2a = dict(base, schema=2, output_policy={"allowed_extra": ["Xk2vRq81LmZ"]})
        t.case("an allowed_extra pattern is the documented opt-out",
               G(tmp, out, "", 0, 0.0, v2a) == [])
        v2g = dict(base, schema=2, output_policy={"allowed_extra": ["*.par2"]})
        probs = G(tmp, out, "", 0, 0.0, v2g)
        t.case("and a glob that does not cover it still refuses", len(probs) == 1)
        v1off = dict(base, schema=2, output_policy={"closed_world": False})
        t.case("a schema-2 row can opt OUT per row",
               G(tmp, out, "", 0, 0.0, v1off) == [])
        os.makedirs(os.path.join(out, "emptydir"))
        probs = G(tmp, out, "", 0, 0.0, dict(base, schema=2,
                                                 output_policy={"allowed_extra": ["Xk2vRq81LmZ"]}))
        t.case("an empty directory is debris too",
               len(probs) == 1 and "unexpected empty directory" in probs[0])
        os.rmdir(os.path.join(out, "emptydir"))

        # A symlink must not stand in for a payload, and must not make
        # an inside path point out.
        outside = os.path.join(tmp, "outside.bin")
        with open(outside, "wb") as f:
            f.write(pay)
        os.remove(os.path.join(out, "Real.Name.bin"))
        os.symlink(outside, os.path.join(out, "Real.Name.bin"))
        probs = G(tmp, out, "", 0, 0.0, dict(base))
        t.case("a symlink does not satisfy an expected file",
               any("is a symlink, not a regular file" in p for p in probs))
        t.case("a symlink is refused as a special file",
               any("special file in the output" in p for p in probs))
        t.case("and realpath catches it pointing outside the job",
               any("points outside the job" in p for p in probs))
        allow = dict(base, allow_special=[{"path": "Real.Name.bin", "kind": "symlink"}])
        probs = G(tmp, out, "", 0, 0.0, allow)
        t.case("allow_special waives the KIND check only, never containment",
               not any("special file in the output" in p for p in probs)
               and any("points outside the job" in p for p in probs))
        os.remove(os.path.join(out, "Real.Name.bin"))
        _write(out, "Real.Name.bin", pay)

        os.symlink(tmp, os.path.join(out, "escape"))
        probs = G(tmp, out, "", 0, 0.0, dict(base))
        t.case("a symlinked DIRECTORY is judged, not descended",
               any("escape" in p and "points outside" in p for p in probs))
        os.remove(os.path.join(out, "escape"))

        fifo = os.path.join(out, "pipe")
        os.mkfifo(fifo)
        probs = G(tmp, out, "", 0, 0.0, dict(base))
        t.case("a FIFO is refused", any("pipe is a fifo" in p for p in probs))
        os.remove(fifo)

        t.case("forbidden names still bite",
               any("forbidden (obfuscated) name survived" in p
                   for p in G(tmp, out, "", 0, 0.0,
                                  dict(base, forbidden=["Xk2vRq81LmZ"]))))

        # -- item 5: spend ------------------------------------------
        exp_bytes = len(pay)
        ents, _ = scan_tree(out)
        m = collect_metrics("", ents, 1.5, exp_bytes)
        t.case("amplification is measured against the expected bytes",
               m["output_amplification"] > 1.0 and m["output_files"] == 2)
        t.case("wall time is a harness metric", m["wall_secs"] == 1.5)
        probs = G(tmp, out, "", 0, 9.0, dict(base, budget={"wall_secs": 1.0}))
        t.case("a wall-time overrun is a failure",
               any("over budget: wall_secs" in p for p in probs))
        probs = G(tmp, out, "", 0, 0.0, dict(base, budget={"output_amplification": 1.0}))
        t.case("an amplification overrun is a failure",
               any("over budget: output_amplification" in p for p in probs))
        probs = G(tmp, out, "", 0, 0.0, dict(base, budget={"output_amplification": 99.0}))
        t.case("and a budget that holds is silent", probs == [])
        probs = G(tmp, out, "", 0, 0.0, dict(base, budget={"repair_blks": 3}))
        t.case("a budget metric this grader cannot measure is a REFUSAL",
               any("unknown metric: repair_blks" in p for p in probs))
        log = "\n".join(REAL_LOG_LINES.values())
        m = collect_metrics(log, ents, 0.0, exp_bytes)
        t.case("bad_blocks reads a real verify line", m["bad_blocks"] == 13)
        t.case("repair_blocks_needed reads a real repair line",
               m["repair_blocks_needed"] == 1984)
        t.case("spent_sources_removed reads a real sweep line",
               m["spent_sources_removed"] == 2)
        t.case("repair_attempts counts a real repair announcement",
               m["repair_attempts"] == 1)
        for name, line in REAL_LOG_LINES.items():
            rx, _how = LOG_METRICS[name]
            t.case(f"the {name} pattern still matches its captured line",
                   rx.search(line) is not None)
        probs = G(tmp, out, log, 0, 0.0, dict(base, budget={"bad_blocks": 0}))
        t.case("a repair-spend overrun is a failure",
               any("over budget: bad_blocks = 13 > 0" in p for p in probs))

        # -- item 7: honest failure ---------------------------------
        hf = dict(base, honest_failure={
            "log_contains": "unrepairable",
            "retained": [_exp("Real.Name.bin", pay)],
        })
        t.case("a nonzero exit with the diagnostic and the bytes is honest",
               G(tmp, out, "WARN repair: unrepairable: ...", 3, 0.0, hf) == ["HONEST-FAIL"])
        t.case("a nonzero exit without the diagnostic is not",
               G(tmp, out, "boom", 3, 0.0, hf) == [
                   "honest-failure row exited 3 without its diagnostic ('unrepairable')"])
        hf2 = dict(base, honest_failure={
            "log_contains": "unrepairable",
            "retained": [_exp("Never.Written.bin", pay)],
        })
        probs = G(tmp, out, "unrepairable", 3, 0.0, hf2)
        t.case("a nonzero exit that lost the retained bytes is not",
               len(probs) == 1 and "Never.Written.bin" in probs[0])
        broken = dict(base, expected=[_exp("Gone.bin", pay)], honest_failure={
            "log_contains": "unrepairable", "retained": []})
        probs = G(tmp, out, "unrepairable", 0, 0.0, broken)
        t.case("rc=0 is NEVER rescued by honest_failure",
               any("expected Gone.bin missing" in p for p in probs))
        must = dict(base, honest_failure={"log_contains": "", "rc_must_be_nonzero": True})
        t.case("a row that must end nonzero refuses rc=0",
               G(tmp, out, "", 0, 0.0, must) == [
                   "this row must end nonzero; nzbfast exited 0"])

        # -- the documented alternatives are unchanged ---------------
        t.case("race_disjunction still answers RACE",
               G(tmp, out, "13/14 blocks bad", 2, 0.0,
                     dict(base, race_disjunction=True)) == ["RACE"])
        t.case("known_gap still answers GAP at nonzero",
               G(tmp, out, "capped", 2, 0.0,
                     dict(base, known_gap={"log_contains": "capped", "note": "x"})) == ["GAP"])
        t.case("known_gap still answers GAP at rc=0 with a missing payload",
               G(tmp, out, "", 0, 0.0,
                     dict(base, expected=[_exp("Gone.bin", pay)],
                          known_gap={"log_contains": "", "note": "x"})) == ["GAP"])
        t.case("a plain nonzero exit is still a failure",
               G(tmp, out, "", 7, 0.0, dict(base)) == ["nzbfast exited 7"])

    # -- policy resolution ------------------------------------------
    t.case("closed world is off for a schema-1 manifest",
           policy({}) ["closed_world"] is False)
    t.case("and on for a schema-2 one", policy({"schema": 2})["closed_world"] is True)
    t.case("an explicit false wins over the schema",
           policy({"schema": 2, "output_policy": {"closed_world": False}})["closed_world"]
           is False)
    t.case("an explicit true wins for a schema-1 row",
           policy({"output_policy": {"closed_world": True}})["closed_world"] is True)

    # -- item 6: arrival order --------------------------------------
    plan = ArrivalPlan({"stall": [{"match": "*par2*", "delay_ms": 5, "only_first": True}]})
    t.case("a plan matches the ids it names", plan.rule_for("<a-par2-1@x>") is not None)
    t.case("and only those", plan.rule_for("<a-body-1@x>") is None)
    t.case("only_first stalls the first request", plan.rule_for("<b-par2-1@x>") is not None)
    t.case("and lets the retry through", plan.rule_for("<b-par2-1@x>") is None)
    t.case("an empty plan stalls nothing", ArrivalPlan({}).rule_for("<x@y>") is None)
    for line, want in (
        (b"ARTICLE <a@b>\r\n", "<a@b>"),
        (b"body <a@b>\r\n", "<a@b>"),
        (b"STAT <a@b>\r\n", "<a@b>"),
        (b"GROUP alt.test\r\n", None),
        (b"QUIT\r\n", None),
    ):
        m = ARTICLE_CMD.match(line)
        got = m.group(2).decode() if m else None
        t.case(f"the command parser reads {line!r} as {want}", got == want)

    order = _proxy_order(t, reached)
    t.case("the proxy really reorders arrival", order == ["<b@x>", "<c@x>", "<a@x>"])

    print(f"roundtrip --selftest: {t.n} cases, {t.fail} failed; reached "
          f"{reached['entries']} entries, {reached['grades']} real-tree grades, "
          f"{reached['proxy_lines']} proxied commands")
    # Failing to find is failing: a selftest that reached nothing is not
    # a green, it is a scanner that has stopped running.
    if reached["entries"] < 12 or reached["grades"] < 20 or reached["proxy_lines"] < 3 or t.n < 55:
        print("roundtrip --selftest: REFUSED - the run reached less than it must")
        return 1
    return 1 if t.fail else 0


def _proxy_order(t, reached):
    """Drive StallProxy against a two-line fake NNTP server and read the
    order the SERVER saw. A plan that reorders nothing would still pass
    every unit case above, so this is the arm that says the proxy works
    at all."""
    got = []
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
        conn, _ = srv.accept()
        buf = b""
        with conn:
            while len(got) < 3:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    m = ARTICLE_CMD.match(line + b"\r\n")
                    if m:
                        got.append(m.group(2).decode())
                        conn.sendall(b"430\r\n")

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    plan = ArrivalPlan({"stall": [{"match": "<a@x>", "after_others": 2}]})
    proxy = StallProxy(srv.getsockname()[1], plan).start()
    try:
        c = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        for mid in (b"<a@x>", b"<b@x>", b"<c@x>"):
            c.sendall(b"ARTICLE " + mid + b"\r\n")
            time.sleep(0.02)
        deadline = time.time() + 5
        while len(got) < 3 and time.time() < deadline:
            time.sleep(0.02)
        c.close()
    finally:
        proxy.stop()
        srv.close()
    reached["proxy_lines"] += len(got)
    t.case("the proxy forwarded every command exactly once", len(got) == 3)
    t.case("the proxy counted the one it held", proxy.stalled == 1)
    return got


def main():
    argv = sys.argv[1:]
    if "--selftest" in argv:
        sys.exit(selftest())
    arrival = None
    if "--arrival" in argv:
        i = argv.index("--arrival")
        arrival = argv[i + 1]
        del argv[i : i + 2]
    keep_out = None
    if "--report-dir" in argv:
        i = argv.index("--report-dir")
        keep_out = argv[i + 1]
        del argv[i : i + 2]
    legs = argv
    if not legs:
        base = os.path.join(HERE, "corpus", "norar")
        if not os.path.isdir(base):
            die("no corpus/norar - run generate.py first")
        legs = sorted(
            os.path.join(base, d)
            for d in os.listdir(base)
            if os.path.isdir(os.path.join(base, d))
        )
    if not legs:
        die("no leg directories found")
    nzbfast = find_nzbfast()
    msg(f"client: {nzbfast}")
    ok = True
    for legdir in legs:
        ok = run_leg(legdir, nzbfast, arrival, keep_out) and ok
    if not ok:
        die("one or more legs failed the round trip")
    msg(f"all {len(legs)} leg(s) round-trip clean")


if __name__ == "__main__":
    main()
