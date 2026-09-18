#!/usr/bin/env python3
"""cstripe-mac.py - the CREATE's NTT stripe width, on the Mac/BSD rigs.

The aarch64 half of the create-width family (lane
`create-width-aarch64-leg-16sep`, owed item 2 of
an internal note). The Windows half is
`cstripe-i5.ps1` beside it and this file is a PORT of it, not a new design:
same plan format, same arms, same per-leg gates, same `legs-<label>.jsonl`
schema, so `cstripesum.py` reduces a round from either side unchanged and the
three arms (x86 nibble, GFNI-256, NEON) are directly comparable.

WHY A CREATE HARNESS RATHER THAN nttwork.py. nttwork.py is this box's REPAIR
rig: it builds a set once and then times `parfast r` over damage it re-applies
per leg. A create round has no damage and no repair - the timed tool IS the
thing that produces the output, so the gate is not "the members came back" but
"every arm wrote byte-identical recovery volumes", and the payload is written
once per cell and never touched again. The arms, the rig lock, the load
reading, the mirroring and the leg record are the same, and come from the same
pdrv.py.

DRIVEN BY A PLAN FILE, plan.txt in the ROUND DIRECTORY (`ROUND=<dir>`), one
cell per line, identical to the PowerShell half's:

    <label> <block_bytes> <n_slices> <rows> <members> <reps> <arm>[,<arm>...]

an arm being `w<words>` (NZBFAST_NTT_W pinned to that width) or `auto`
(nothing pinned), EITHER of which may carry an optional `t<threads>` suffix
(`w1024t4`, `w512t4`, `autot4`) that pins NZBFAST_NTT_THREADS for that leg.
Arms run in plan order on odd reps and reversed on even ones, on ONE corpus and
ONE binary.

**THE THREAD COUNT RIDES THE ARM AND NOT THE CELL, deliberately.** It was added
16 Sep 2026 by lane `neon-create-width-thread-count-16sep` to test the
idle-cores hypothesis in an internal note, and the
obvious design - an optional eighth column on the cell line - was rejected. A
thread count on the CELL forces one round per thread count, which puts the A/A
floor and the effect it licenses in different rounds over different corpora;
and this family is judged on whether arms SEPARATE, so a floor measured
somewhere else is not a floor. On the ARM, `w1024t4 w512t4 autot4` mirror
within ONE cell over ONE corpus exactly as `w1024 w512 auto` do, the floor is
measured at the SAME thread count as the effect, and `cstripesum.py` groups by
`arm` already, so it reduces a thread round with no change at all. The cost is
that a plan line carrying two thread counts would interleave them - which is a
feature here, not a bug, and any cell may still carry exactly one.

**AND THE FLOOR PAIR MUST BE AT THE SAME THREAD COUNT.** On this arm the floor
is `auto` against `w512` (see below); with thread pins that is `autot4` against
`w512t4`, never `autot4` against `w512`. `cstripesum.py --ref w512t4`.

An arm with NO `t` suffix pins nothing, which is what every plan file written
before this change means and still means: an internal note/
plan-antigua.txt` and its siblings parse and run exactly as they did.

**WHICH PAIR OF ARMS IS THE A/A FLOOR IS A FACT ABOUT THE BOX.** `auto` is a
floor only against whichever arm pins the width that box would have chosen
anyway. On the x86 nibble arms at 1 MiB and up `default_stripe_words` returns
1,024, so there auto-against-w1024 is the floor. **On aarch64 (and on GFNI) it
returns 512 at every block size**, so here `auto` runs W 512: the EFFECT is
`w512` against `w1024` (cstripesum.py's default view) and the FLOOR is
`auto` against `w512`, which is `cstripesum.py --ref w512`. In the default view
the `auto` row is a REAL A/B on this arm, not a floor, and reading it as one
reports the effect size as the noise.

WHAT EVERY LEG ASSERTS, or the round aborts - every gate the PowerShell half
carries, none dropped:
  - rc 0 from the create;
  - the create took the TRANSFORM (a `create ntt rows` or `create
    stripe-first:` line), because a width A/B over the fold is nothing;
  - the width the transform actually ran at equals the arm's pin, read off that
    same line, and EVERY span in a multi-batch leg agrees - a pin the binary
    ignored must never bank as a measurement of that pin;
  - and the THREAD COUNT the transform actually ran at equals the arm's thread
    pin, on exactly the same terms and for exactly the same reason. That line
    has always carried `threads=`, and this driver has always parsed it into
    `ran_t` and banked it as `ntt_threads` - but until 16 Sep 2026 NOTHING
    CHECKED IT, so a thread pin the binary ignored would have banked silently
    as a measurement of that pin. The requested count is banked beside the
    observed one as `ntt_threads_req` (null when the arm pinned none) so a
    reader can see the two agree without re-deriving either;
  - the recovery volumes are byte-identical to the cell's first leg, file set
    and all;
  - the payload files are unchanged in length.
And every leg line carries the plan's LEAF FILL (`NZBFAST_NTT_FILL=1`), for the
reason par2ntt's LeafFill docstring gives: a flat result from a kernel the fill
gate refused looks exactly like a kernel that ran and bought nothing, and this
family has paid for that confusion once already.

NZBFAST_NTT_PAIRED_CAPW IS DELIBERATELY NOT SET, and it matters MORE here than
on the GFNI box. It pins the paired leaf's packed-source scratch, which follows
the stripe width, so pinning it would hold one leaf kernel's shape still while
the arm moves the other - and unlike the GFNI family, **aarch64 HAS a paired
leaf** (`conjugate::enabled` ships it "where the nibble kernels are the
selected ones (AVX2 without GFNI, NEON)"), so below the additive gate there is
really something to hold still. Read the kernel split off each leg's own
`fill=` field, never off this docstring.

THE PER-CORE QUIET ARM IS BANKED, NOT JUST PRINTED. `pdrv.require_quiet_box`
ends in `_require_quiet_per_core`, which landed 16 Sep 2026 because the box-wide
ceiling waves a single saturated core through - measured on apple-m3-ultra, where
`spotlightknowledged.updater` held 100.2% of ONE core while the box total of
181.5% sat comfortably under a 320% ceiling. This driver's first cut wrapped
`require_quiet_box` to swallow its SystemExit and threw the RETURN VALUE away
with it, so that arm's verdict reached the round log and never a leg record.
Every leg now carries `foreign_1core`. It is NOT a second spelling of
`foreign_before`/`foreign_after`: those are `foreign_cpu()`, a `ps -o pcpu` sum
that on macOS decays over about ten seconds, and this is
`foreign_cpu_window()`, a one second delta confirmed by minimum of three
samples. Both in % of one core, both banked, neither derivable from the other.

THE TWO PORTING DIFFERENCES, stated rather than silent - neither is a gate:

 1. **No src.tgz build step.** The PowerShell half ships a source tarball to a
    rig, builds parfast there under the lock, and refuses a binary older than
    the build start. A Mac round runs in the repo worktree, so this driver
    takes `BIN=` (a prebuilt `parfast`) the way nttwork.py does. What that
    gate actually protects - "one binary across every cell, and the log can
    name it" - is kept: `pdrv.bin_facts` prints the sha256 and `-VV` of the
    binary, and this driver re-reads that sha256 at the top of EVERY cell and
    aborts if it moved, which the PowerShell half does not do.
 2. **`load_before` / `load_after` are the 1-minute load average**, a float,
    where the Windows record carries `Win32_Processor.LoadPercentage`, an
    integer percent. Same field names because the schema is shared; different
    units because the boxes are. `cstripesum.py` reads neither. `foreign_cpu`
    IS comparable: both sides mean "percent of one core, outside our own
    process tree".

RUN:
    BIN=target/release/parfast ROUND=~/cw-aarch64 FIX=~/cw-aarch64/fix \
      [ID=<claim-id>] [COORD=~/bench-out/COORDINATION-m3.txt] cstripe-mac.py
READ:
    harness/cstripesum.py <round>/legs-*.jsonl          # the effect
    harness/cstripesum.py --ref w512 <round>/legs-*.jsonl  # the floor
    harness/cstripesum.py --ref w512t4 <round>/legs-*.jsonl # ...at t4
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pdrv  # noqa: E402
from pdrv import RigLock, bin_facts, box_facts, foreign_cpu, harness_facts, rig_stamp, sha256_file  # noqa: E402

# The last per-core quiet reading, in % of ONE core, set by the guard wrapper
# in __main__ and banked on the next leg record. Module state rather than a
# return value threaded through run_leg, because the guard is called from
# INSIDE pdrv.run_leg and monkeypatched from outside it.
LAST_1CORE = None

UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1.0}

# The arm grammar, in ONE place so the plan validator and the leg both read the
# same rule: a width (`w1024`) or `auto`, either optionally carrying a thread
# pin (`w1024t4`, `autot4`). See the docstring for why the thread count is a
# property of the ARM rather than of the cell.
ARM_RE = re.compile(r"(auto|w(\d+))(?:t(\d+))?$")


def parse_arm(arm, label):
    """-> (pin_w or None, pin_t or None). Raises on anything else.

    A bad arm is a PLAN-FAIL and not a warning: the arm string is what names
    the leg file, the leg record and every reducer grouping, so a typo that
    fell through to `auto` would bank a leg under a name that is not what ran.
    """
    m = ARM_RE.fullmatch(arm)
    if not m:
        raise SystemExit("PLAN-FAIL bad arm %r in cell %s - expected w<words>, auto, "
                         "or either with a t<threads> suffix" % (arm, label))
    pin_w = int(m.group(2)) if m.group(2) else None
    pin_t = int(m.group(3)) if m.group(3) else None
    if pin_t is not None and pin_t < 1:
        raise SystemExit("PLAN-FAIL arm %r in cell %s pins %d threads" % (arm, label, pin_t))
    return pin_w, pin_t


# `create ntt rows 0+1024 (n=10240, mapped, 0 tail(s) padded, W=1024, 2
# stripe(s), threads=12, probe ok): 1.23s` - the batched mapped arm; and
# `create stripe-first: 3277 rows in 8 chunk(s) of 64 stripes (n=32768, bands,
# W=512, threads=12, probe ok): 1.23s` - the one-pass arm. Either is the
# transform; both carry the width this leg actually ran at. `.*?` and not
# `[^)]*?` between the anchors: both lines carry parentheses of their own
# inside that span, so a class that stops at the first `)` matches neither.
NTT_RE = re.compile(r"create ntt rows (\d+)\+(\d+) \(n=(\d+),.*?W=(\d+), (\d+) stripe\(s\), "
                    r"threads=(\d+), probe ok\): ([0-9.]+)([^0-9.\s]+)")
SF_RE = re.compile(r"create stripe-first: (\d+) rows in (\d+) chunk\(s\) of (\d+) stripes "
                   r"\(n=(\d+), (.*?), W=(\d+), threads=(\d+), probe ok\): ([0-9.]+)([^0-9.\s]+)")
FILL_RE = re.compile(r"\[ntt-fill\] needed (\d+) leaves (\d+) sources (\d+) fill min (\d+) "
                     r"median (\d+) max (\d+) kernels dense (\d+) paired (\d+) additive (\d+) gate (\S+)")

# Every knob an arm may pin, cleared from the DRIVER's environment: a child
# inherits it, and an inherited pin would turn the `auto` arm into a pinned one.
KNOBS = ("NZBFAST_NTT", "NZBFAST_NTT_W", "NZBFAST_NTT_THREADS", "NZBFAST_NTT_PAIRED_CAPW",
         "NZBFAST_NTT_ADDITIVE", "NZBFAST_NTT_ADDITIVE_MIN", "NZBFAST_CREATE_STRIPE_FIRST",
         "NZBFAST_CREATE_NTT_MIN_ROWS", "NZBFAST_CREATE_NTT_MIN_PRESENT")


def secs(v, u):
    if u not in UNITS:
        raise SystemExit("unknown time unit %r on a transform line" % u)
    return float(v) * UNITS[u]


def stamp():
    return pdrv.utcnow()


def coord(verb, text):
    if not COORD:
        return
    with open(COORD, "a") as fh:
        fh.write("%s %s %s %s\n" % (verb, stamp(), ID, text))


def write_corpus(work, members, block, per_member):
    """The payload, written ONCE per cell and never touched by a leg.

    One random buffer per cell, rewritten with a counter in its first eight
    bytes per block - the PowerShell half's scheme and its reasoning: the
    transform's cost does not depend on the bytes (GF arithmetic is data
    independent), and drawing tens of GiB from a CSPRNG would cost more than
    the round's legs.
    """
    buf = bytearray(os.urandom(block))
    blk = 0
    for name in members:
        with open(os.path.join(work, name), "wb", buffering=0) as fh:
            for _ in range(per_member):
                buf[0:8] = blk.to_bytes(8, "little")
                fh.write(buf)
                blk += 1


def main():
    box_facts()
    bin_facts([BIN])
    harness_facts()
    bin_sha = sha256_file(BIN)
    print("ROUND dir=%s fixture=%s id=%s coord=%s ts=%s"
          % (ROUND, FIX, ID, COORD or "-", stamp()), flush=True)
    coord("CLAIM", CLAIM_TEXT)

    os.makedirs(FIX, exist_ok=True)
    # Keep Spotlight out of the fixture. A freshly written 16 GiB corpus is
    # exactly what `hybridsearchd` walks, and on this box it has been measured
    # at several cores while doing it - the local equivalent of the Windows
    # Search trap cstripe-i5.ps1's sibling notes record. A marker file in the
    # fixture directory is local and reversible; `mdutil -i off` is a change to
    # the whole volume's indexing and belongs to whoever owns the machine.
    open(os.path.join(FIX, ".metadata_never_index"), "a").close()

    for line in open(os.path.join(ROUND, "plan.txt")):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        f = line.split()
        if len(f) < 7:
            raise SystemExit("PLAN-FAIL short line %r" % line)
        label, block, nslices, rows = f[0], int(f[1]), int(f[2]), int(f[3])
        nmem, reps = int(f[4]), int(f[5])
        arms = f[6].split(",")
        for a in arms:
            parse_arm(a, label)
        if nslices % nmem:
            raise SystemExit("PLAN-FAIL %s: %d slices do not divide into %d members"
                             % (label, nslices, nmem))
        # ONE binary across every cell - the half of the PowerShell build gate
        # that a prebuilt-binary round can and must keep.
        if sha256_file(BIN) != bin_sha:
            raise SystemExit("BIN-FAIL %s: the binary changed under the round" % label)
        cell(label, block, nslices, rows, nmem, reps, arms)
    print("ALL DONE %s" % stamp(), flush=True)


def cell(label, block, nslices, rows, nmem, reps, arms):
    out = os.path.join(ROUND, "legs-%s.jsonl" % label)
    legdir = os.path.join(ROUND, "legs-%s" % label)
    os.makedirs(legdir, exist_ok=True)
    shown = []
    for a in arms:
        w, t = parse_arm(a, label)
        pins = []
        if w:
            pins.append("NZBFAST_NTT_W=%d" % w)
        if t:
            pins.append("NZBFAST_NTT_THREADS=%d" % t)
        shown.append(a + "{%s}" % ",".join(pins))
    print("ARMS label=%s %s" % (label, " ".join(shown)), flush=True)

    work = os.path.join(FIX, "c-%s" % label)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    members = ["m%d.bin" % i for i in range(1, nmem + 1)]
    t0 = time.monotonic()
    write_corpus(work, members, block, nslices // nmem)
    st = os.statvfs(work)
    print("CORPUS label=%s block=%d slices=%d rows=%d members=%d payload_gb=%.2f write_s=%.1f free_gb=%.1f"
          % (label, block, nslices, rows, nmem, nslices * block / (1024 ** 3),
             time.monotonic() - t0, st.f_bavail * st.f_frsize / (1024 ** 3)), flush=True)
    memlen = {n: os.path.getsize(os.path.join(work, n)) for n in members}

    gold = None
    gold_names = []
    for rep in range(1, reps + 1):
        order = list(arms) if rep % 2 else list(reversed(arms))
        for arm in order:
            gold, gold_names = leg(label, block, nslices, rows, nmem, rep, arm,
                                   work, legdir, out, members, memlen, gold, gold_names)
    shutil.rmtree(work)
    st = os.statvfs(FIX)
    print("CELL-DONE %s ts=%s free_gb=%.1f"
          % (label, stamp(), st.f_bavail * st.f_frsize / (1024 ** 3)), flush=True)


def leg(label, block, nslices, rows, nmem, rep, arm, work, legdir, out,
        members, memlen, gold, gold_names):
    # A leg starts from payload only: any volume a previous leg left is an
    # input the create would refuse or reuse.
    for name in os.listdir(work):
        if name not in memlen:
            os.unlink(os.path.join(work, name))
    env = {"NZBFAST_REPAIR_TIMING": "1", "NZBFAST_NTT_FILL": "1", "NZBFAST_NO_ENRICH": "1"}
    pin_w, pin_t = parse_arm(arm, label)
    if pin_w:
        env["NZBFAST_NTT_W"] = str(pin_w)
    if pin_t:
        env["NZBFAST_NTT_THREADS"] = str(pin_t)
    tag = "%s-r%d-%s" % (label, rep, arm)
    lb = os.path.join(legdir, tag)
    l0 = os.getloadavg()[0]
    r = pdrv.run_leg(BIN, ["c", "-q", "-q", "-s%d" % block, "-c%d" % rows, "set.par2"] + members,
                     work, lb, env)
    l1 = os.getloadavg()[0]
    if r["rc"] != 0:
        raise SystemExit("GATE-FAIL %s create rc=%d - see %s.err" % (tag, r["rc"], lb))
    err = open(lb + ".err", errors="replace").read()

    # --- the output gate ---------------------------------------------------
    vols = sorted(n for n in os.listdir(work) if n.endswith(".par2"))
    if not vols:
        raise SystemExit("GATE-FAIL %s wrote no par2 volumes" % tag)
    vol_bytes = sum(os.path.getsize(os.path.join(work, v)) for v in vols)
    if gold is None:
        gold = {v: sha256_file(os.path.join(work, v)) for v in vols}
        gold_names = vols
        print("GOLD label=%s volumes=%d bytes=%d from=%s" % (label, len(vols), vol_bytes, tag), flush=True)
    else:
        if vols != gold_names:
            raise SystemExit("GATE-FAIL %s volume SET differs from the cell's first leg" % tag)
        bad = [v for v in vols if sha256_file(os.path.join(work, v)) != gold[v]]
        if bad:
            raise SystemExit("GATE-FAIL %s volumes differ: %s" % (tag, ",".join(bad)))
    # The payload must be exactly what every other leg read.
    for n in members:
        if os.path.getsize(os.path.join(work, n)) != memlen[n]:
            raise SystemExit("GATE-FAIL %s payload %s changed length" % (tag, n))
    for v in vols:
        os.unlink(os.path.join(work, v))

    # --- the path and the pin ----------------------------------------------
    # ALL the matches, not the first: the batched arm prints one line per
    # BATCH, and a round that read only the first would bank a pin it had
    # checked on a fraction of the leg's transform work.
    ntt_all = NTT_RE.findall(err)
    sf_all = SF_RE.findall(err)
    if not ntt_all and not sf_all:
        raise SystemExit("PATH-FAIL %s the create did not take the transform - "
                         "a width A/B over the fold measures nothing" % tag)
    route = "stripe-first" if sf_all else "batched"
    wseen, tseen, ntt_s, corpus = [], [], 0.0, "mapped"
    for m in sf_all:
        wseen.append(int(m[5]))
        tseen.append(int(m[6]))
        ntt_s += secs(m[7], m[8])
        corpus = "bands" if m[4].startswith("bands") else m[4]
    for m in ntt_all:
        wseen.append(int(m[3]))
        tseen.append(int(m[5]))
        ntt_s += secs(m[6], m[7])
    ran_w, ran_t = wseen[0], tseen[0]
    if any(w != ran_w for w in wseen):
        raise SystemExit("PATH-FAIL %s the transform ran two widths in one leg: %s"
                         % (tag, ",".join(str(w) for w in wseen)))
    if pin_w and ran_w != pin_w:
        raise SystemExit("PIN-FAIL %s NZBFAST_NTT_W=%d but the transform ran W=%d"
                         % (tag, pin_w, ran_w))
    # THE THREAD PIN GETS THE WIDTH PIN'S TREATMENT, both halves of it. The
    # spans must agree with each other - a leg that ran two thread counts is
    # not a measurement of either - and the count that ran must be the count
    # the arm asked for. Without this the driver parsed `threads=` and banked
    # it and nothing ever compared it to the request, which is precisely the
    # shape the width gate exists to refuse.
    if any(t != ran_t for t in tseen):
        raise SystemExit("PATH-FAIL %s the transform ran two thread counts in one leg: %s"
                         % (tag, ",".join(str(t) for t in tseen)))
    if pin_t and ran_t != pin_t:
        raise SystemExit("THREAD-PIN-FAIL %s NZBFAST_NTT_THREADS=%d but the transform ran "
                         "threads=%d - a pin the binary ignored must never bank as a "
                         "measurement of that pin" % (tag, pin_t, ran_t))
    fm = FILL_RE.search(err)
    g = fm.groups() if fm else None
    fill = ("min%s/med%s/max%s/d%sp%sa%s" % (g[3], g[4], g[5], g[6], g[7], g[8])) if g else "none"
    rig = rig_stamp()
    rec = {
        "label": label, "block": block, "slices": nslices, "rows": rows, "members": nmem,
        "rep": rep, "arm": arm, "stripe_w": pin_w if pin_w else "default", "rig": rig,
        "rc": r["rc"], "route": route, "corpus": corpus,
        "wall": r["wall"], "cpu": r["cpu"], "peak_mb": r["peak_mb"],
        "ntt_s": round(ntt_s, 4), "ntt_W": ran_w, "ntt_threads": ran_t,
        # The REQUESTED count beside the OBSERVED one, null when the arm pinned
        # none, so a reader sees the two agree without re-deriving the arm.
        "ntt_threads_req": pin_t, "ntt_spans": len(wseen),
        "vol_count": len(vols), "vol_bytes": vol_bytes,
        "fill_leaves": int(g[1]) if g else None, "fill_sources": int(g[2]) if g else None,
        "fill_min": int(g[3]) if g else None, "fill_median": int(g[4]) if g else None,
        "fill_max": int(g[5]) if g else None,
        "leaf_dense": int(g[6]) if g else None, "leaf_paired": int(g[7]) if g else None,
        "leaf_additive": int(g[8]) if g else None, "additive_gate": g[9] if g else None,
        "load_before": round(l0, 2), "load_after": round(l1, 2),
        "foreign_before": r["foreign_cpu"], "foreign_after": r["foreign_after"],
        # `foreign_cpu` (both fields above) and `foreign_1core` are DIFFERENT
        # QUANTITIES and a reader must not average them together. The first two
        # are `pdrv.foreign_cpu()`, a `ps -o pcpu` sum over every foreign
        # process, which on macOS is a short DECAYING average; this one is
        # `pdrv.foreign_cpu_window()`, a delta sampler over a one second window,
        # taken by the per-core arm just before the tool started and confirmed
        # by MINIMUM of three samples when the first is over 25% of one core.
        # Both are in % of ONE core. Kept beside each other rather than in place
        # of each other: every banked `foreign_cpu` field on this fleet is the
        # first quantity, so replacing it would move something a year of logs is
        # expressed in, and only the second can answer "was one core pinned".
        "foreign_1core": round(LAST_1CORE, 1) if LAST_1CORE is not None else None,
    }
    with open(out, "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    print("LEG %s rc=%d out=OK route=%s corpus=%s wall=%s cpu=%s peak_mb=%s ntt=%s W=%d T=%d/%s "
          "spans=%d fill=%s load=%.2f/%.2f foreign=%s/%s 1core=%s rig=%s"
          % (tag, r["rc"], route, corpus, r["wall"], r["cpu"], r["peak_mb"], rec["ntt_s"],
             ran_w, ran_t, pin_t if pin_t else "-", len(wseen), fill, l0, l1,
             r["foreign_cpu"], r["foreign_after"], rec["foreign_1core"], rig), flush=True)
    return gold, gold_names


if __name__ == "__main__":
    for knob in KNOBS:
        os.environ.pop(knob, None)
    BIN = os.path.abspath(os.environ["BIN"])
    ROUND = os.path.abspath(os.path.expanduser(os.environ["ROUND"]))
    FIX = os.path.abspath(os.path.expanduser(os.environ.get("FIX", os.path.join(ROUND, "fix"))))
    ID = os.environ.get("ID", "create-width-mac")
    CLAIM_TEXT = os.environ.get("CLAIM_TEXT", "create NTT stripe width round; holds ~/.parfast-rig.lock. Will post DONE.")
    COORD = os.environ.get("COORD", "")
    if COORD:
        COORD = os.path.abspath(os.path.expanduser(COORD))
    # The quiet-box guard WAITS out a busy box on pdrv's budget but does not
    # abort the round, for nttwork.py's reason: the reading travels on every
    # leg record either way and this round reads CPU. A shared dev Mac running
    # other lanes' gate suites never reaches an idle ceiling, and a round that
    # refuses to start is not safer than one that records what it ran beside.
    pdrv.set_quiet_budget(int(os.environ.get("CW_QUIET_TRIES", "2")),
                          int(os.environ.get("CW_QUIET_WAIT", "30")))
    _real_guard = pdrv.require_quiet_box

    def _guard(where, tries=None, wait=None):
        # THE RETURN VALUE IS THE PER-CORE READING AND IT MUST NOT BE THROWN
        # AWAY. `require_quiet_box` ends in `_require_quiet_per_core`, whose
        # whole contract is that the reading comes back "so the caller can put
        # it on the leg line - a contaminated leg that still ran has to be
        # judgeable afterwards". The first cut of this wrapper returned None,
        # so the arm's verdict reached the round LOG and never the BANK, and a
        # reducer could not take a per-cell median of it. Stash it for the leg
        # record instead. A busy box that never gets a reading keeps None,
        # which banks as null and reads as "not sampled" rather than as zero.
        global LAST_1CORE
        try:
            LAST_1CORE = _real_guard(where, tries, wait)
        except SystemExit:
            total, top = foreign_cpu()
            LAST_1CORE = None
            print("WARN-BUSY-CONTINUE foreign_cpu=%.0f%% at=%s top=%s" % (total, where, top), flush=True)
        return LAST_1CORE

    pdrv.require_quiet_box = _guard
    lock = RigLock(os.path.join(ROUND, "cstripe.lock"))
    lock.take()
    done = "ABORTED"
    try:
        main()
        done = "finished"
    finally:
        coord("DONE", "%s; rig lock released" % done)
        lock.release()
