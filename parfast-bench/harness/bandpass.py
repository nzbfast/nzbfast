#!/usr/bin/env python3
"""bandpass.py - what a stripe-first BAND PASS costs the create, in rows of
crossover: the fold against the forced transform at a ladder of row counts,
run once per PASS COUNT, on one box and one fixture.

Claim `create-band-pass-cost`, against the section "The windowed CREATE
ladder" of an internal note, item 4.

THE QUESTION. The create's admission is
`par2gen::ntt_range::rows_and_present_admitted` -> `create_ntt_min_rows
(block_size)` = `ntt_min_missing(block_size)` - the RESIDENT gate - and it
is asked with no window and no pass term, whether the create then makes ONE
pass over the corpus or eight. The repair's windowed admission does scale
its gate (`ntt_window_row_ask`), and the window's true cost there was
measured at +17 rows of crossover at S ~ 2,050 and ~+139 at S ~ 1,035. So:
does a BAND PASS cost the create rows the same way, or is it nearly free?
If it is free the create is right as it stands; if it is not, the band
count is the term its admission is missing.

WHY THIS IS NOT THE REPAIR'S QUESTION, stated once so nobody re-derives it.
The repair's window is a subset of SOURCES over all stripes, which is what
`ntt_window_row_gate(sources, gate, k)` prices. The create's band is a
subset of STRIPES over all sources - every source is read in every chunk.
A source-count ask has nothing to say about a stripe-wise decomposition,
so this harness does not compare against that ask at all; it compares each
banded ladder against the create's OWN resident ladder on the same box and
fixture, and the quantity is EXCESS IN ROWS.

`NZBFAST_PAR2GEN_MAP=0` IS ON EVERY ARM, INCLUDING THE RESIDENT ONE, and
that is a round-design requirement rather than a tuning knob. The mapped
route is tried first whenever `mapped_payload_fits_memory` holds, and it
takes the whole payload in ONE pass - so on a box with more RAM than
corpus every leg maps, nothing bands, and the round measures nothing while
looking well-formed (rounds/cwinmin-2026-09-16/, item 4 of the
section above). It is on the resident arm too so the control differs from
the banded ladders in the BUDGET and in nothing else.

THE PASS COUNT IS READ OFF THE BINARY'S OWN LINE AND NEVER OFF THE `-m`
ASKED FOR. Three routes print a success line and the pass count is a
different capture group in each - `W window(s)` for copied windows, 1 for
mapped, `C chunk(s)` for bands - and the budget is clamped by MemBudget
before `create_ntt_window` ever sees it, so the rung asked for and the rung
got are two numbers. Every leg carries `route` and `passes`, and a ladder
whose legs did not all reach the SAME route and pass count is refused by
the reducer rather than averaged.

`probe ok` IS PART OF EVERY ROUTE MATCH. Both `windowed_attempt` and
`stripe_first` verify one row against the fold and, on a disagreement or a
window whose plan will not build, zero the accumulator, warn, and let the
fold recompute every row - having already charged their cold plan builds.
`plan prep` then reads `cold > 0` and a path assert keyed on it alone calls
'ntt' a leg that was entirely a fold. Requiring the success line refuses
that leg instead.

ARMS are env on ONE binary, spelled exactly as wcomb.ps1's `Run-Create`
spells them so the two harnesses' legs are the same legs:
  fold / fold2    NZBFAST_NTT=0
  force / force2  NZBFAST_CREATE_NTT_MIN_ROWS=0
`fold2` and `force2` are the A/A copies - the SAME arm again, never a
different setting - and the four run ABBA within a rep. The A/A floor is a
MAX over reps, so adding reps cannot lower it.

READ CPU, NEVER WALL. The crossover is a ratio of work; wall divides the
fold by the pool and adds storage to both arms. Both are recorded and the
verdict is CPU. On apple-m3-ultra in particular the wall column cannot be
rescued by any pre-round step: `spotlightknowledged.updater` carries a
VARIABLE one-to-three-core foreign load there that neither quiet gate can
see (.claude/skills/bench-suite item 0g,
an internal note). `foreign_cpu`
and `foreign_after` travel on every leg and rowgate.py prints the median
per ladder; a round on that box states the figure rather than claiming a
quiet one.

OUTPUT is rowgate.py's own jsonl schema with `phase: "create"`, so
`rowgate.py read` reduces these legs with the house A/A floor, verdict and
log-interpolated crossover, beside every other create ladder on the fleet.
IT GROUPS BY (label, threads) AND NOT BY BUDGET: every budget gets its own
LABEL here, and the runner refuses to write two budgets under one.

RUN:
  BIN=~/bp/parfast R=~/bp/work MEMBERS=16 MEMBER_MIB=64 SLICE=65536 \
    LABEL=p2 BUDGET=512 RUNGS=128,160,192,224,256,320 THREADS=32 REPS=2 \
    OUT=~/bp/legs.jsonl python3 bandpass.py
  BUDGET=big is the resident control (no -m at all).
  probe    one leg per budget, force arm, to read `route` and `passes`
           before a ladder is spent:
  BIN=... R=... BUDGETS=big,512,256,128 RUNGS=256 python3 bandpass.py probe
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pdrv  # noqa: E402

# An NZBFAST_* left in the launching shell would silently join every arm.
for _k in [k for k in os.environ if k.startswith("NZBFAST_")]:
    del os.environ[_k]

BIN = os.path.abspath(os.environ["BIN"])
R = os.path.abspath(os.environ["R"])
MEMBERS = int(os.environ.get("MEMBERS", "16"))
MEMBER_MIB = int(os.environ.get("MEMBER_MIB", "64"))
SLICE = int(os.environ.get("SLICE", "65536"))
REPS = int(os.environ.get("REPS", "2"))
TIMEOUT = int(os.environ.get("TIMEOUT", "3600"))
OUT = os.environ.get("OUT", os.path.join(R, "bandpass.jsonl"))
RUNGS = [int(x) for x in os.environ.get("RUNGS", "192").split(",")]
THREADS = [int(x) for x in os.environ.get("THREADS", "32").split(",")]
ARMS = os.environ.get("ARMS", "fold,force,force2,fold2").split(",")

N_SLICES = MEMBERS * MEMBER_MIB * (1 << 20) // SLICE

ARM_ENV = {
    "fold": {"NZBFAST_NTT": "0"},
    "fold2": {"NZBFAST_NTT": "0"},
    "force": {"NZBFAST_CREATE_NTT_MIN_ROWS": "0"},
    "force2": {"NZBFAST_CREATE_NTT_MIN_ROWS": "0"},
}

# The three success lines, one per route. `probe ok` is part of every match.
RE_WIN = re.compile(r"create ntt rows \d+\+\d+ \(n=(\d+), (\d+) window\(s\) of (\d+),[^\n]*?probe ok\)")
RE_MAP = re.compile(r"create ntt rows \d+\+\d+ \(n=(\d+), mapped,[^\n]*?probe ok\)")
RE_BAND = re.compile(r"create stripe-first: (\d+) rows in (\d+) chunk\(s\) of (\d+) stripes \(n=(\d+),[^\n]*?probe ok\)")
RE_COLD = re.compile(r"plan prep: \S+ over (\d+) cold build\(s\)")


def say(*a):
    print(*a, flush=True)


def members():
    return ["m%02d.bin" % i for i in range(MEMBERS)]


def build_fixture():
    os.makedirs(R, exist_ok=True)
    for name in members():
        p = os.path.join(R, name)
        if os.path.exists(p) and os.path.getsize(p) == MEMBER_MIB << 20:
            continue
        say("fixture: %s (%d MiB)" % (name, MEMBER_MIB))
        with open("/dev/urandom", "rb") as src, open(p, "wb") as dst:
            left = MEMBER_MIB << 20
            while left:
                b = src.read(min(left, 1 << 22))
                dst.write(b)
                left -= len(b)
    say("fixture ready: %d x %d MiB at %d B slices -> n = %d slices"
        % (MEMBERS, MEMBER_MIB, SLICE, N_SLICES))


def clean():
    for p in os.listdir(R):
        if p.startswith("bp.") and p.endswith(".par2"):
            os.remove(os.path.join(R, p))


def digest():
    """One hash over every recovery file, name-ordered: the SET identity.

    The cross-arm comparison this round rests on is that the fold and the
    transform write the SAME recovery bytes at a rung; a leg whose digest
    differs from its rung's first is not a slower answer, it is a wrong one.
    """
    h = hashlib.sha256()
    for p in sorted(x for x in os.listdir(R) if x.startswith("bp.") and x.endswith(".par2")):
        h.update(p.encode())
        with open(os.path.join(R, p), "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
    return h.hexdigest()[:16]


def leg(m, budget, arm, threads, rep, label):
    clean()
    env = dict(os.environ)
    env["NZBFAST_REPAIR_TIMING"] = "1"
    # ON EVERY ARM, the resident control included - see the header.
    env["NZBFAST_PAR2GEN_MAP"] = "0"
    env.update(ARM_ENV[arm])
    args = ["c", "-q", "-t%d" % threads, "-s%d" % SLICE, "-c%d" % m]
    if budget != "big":
        args.append("-m%s" % budget)
    args += ["bp.par2"] + members()
    f0 = pdrv.foreign_cpu()[0]
    t0 = time.time()
    r = subprocess.run(["/usr/bin/time", "-l", BIN] + args, cwd=R, env=env,
                       capture_output=True, text=True, timeout=TIMEOUT)
    wall = time.time() - t0
    f1 = pdrv.foreign_cpu()[0]
    log = r.stdout + r.stderr
    rec = {
        "phase": "create", "label": label, "budget": budget, "arm": arm,
        "m": m, "threads": threads, "rep": rep, "rc": r.returncode,
        "wall": round(wall, 3), "n": N_SLICES, "slice": SLICE,
        "foreign_cpu": round(f0, 1), "foreign_after": round(f1, 1),
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    mm = re.search(r"([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys", log)
    if mm:
        rec["cpu"] = round(float(mm.group(2)) + float(mm.group(3)), 2)
    # THE ROUTE, off the binary's own success line and never off the -m.
    win, mp, band = RE_WIN.search(log), RE_MAP.search(log), RE_BAND.search(log)
    if band:
        rec["route"], rec["passes"] = "band", int(band.group(2))
        rec["chunk_stripes"] = int(band.group(3))
    elif win:
        rec["route"], rec["passes"] = "copied", int(win.group(2))
        rec["window_slices"] = int(win.group(3))
    elif mp:
        rec["route"], rec["passes"] = "mapped", 1
    else:
        rec["route"], rec["passes"] = "fold", 0
    rec["cold"] = sum(int(x) for x in RE_COLD.findall(log))
    # `path` is what rowgate.py asserts on: a force leg must be 'ntt' and a
    # fold leg must be 'fold', and it REFUSES the whole reduction otherwise.
    # Taken from the ROUTE line rather than from `cold` alone, so a probe
    # failure that fell back to the fold after charging its plan builds is
    # refused rather than counted as a transform.
    rec["path"] = "fold" if rec["route"] == "fold" else "ntt"
    rec["timing"] = [l.strip() for l in log.splitlines()
                     if l.strip().startswith("create ") or "plan prep" in l]
    if r.returncode == 0:
        rec["digest"] = digest()
    else:
        rec["err"] = log[-1500:]
    return rec


def run_probe():
    budgets = os.environ.get("BUDGETS", "big").split(",")
    t = THREADS[0]
    m = RUNGS[0]
    say("PROBE n=%d slice=%d threads=%d rows=%d budgets=%s"
        % (N_SLICES, SLICE, t, m, budgets))
    for b in budgets:
        rec = leg(m, b, "force", t, 0, "probe")
        say("PROBE -m%-5s rc=%s route=%-6s passes=%-3s win/stripes=%s cpu=%s wall=%.2f cold=%s"
            % (b, rec["rc"], rec["route"], rec["passes"],
               rec.get("window_slices") or rec.get("chunk_stripes"),
               rec.get("cpu"), rec["wall"], rec.get("cold")))
        for l in rec["timing"]:
            say("   | %s" % l)
        if rec["rc"] != 0:
            say("   ERR %s" % rec.get("err", "")[-400:])
    clean()


def run_ladder():
    label = os.environ["LABEL"]
    budget = os.environ.get("BUDGET", "big")
    # rowgate.py's read_ladder groups by (label, threads) and NOT by budget:
    # two budgets under one label merge into one table with two routes'
    # cells averaged at each m, silently. Refuse it here instead.
    if os.path.exists(OUT):
        for line in open(OUT):
            r = json.loads(line)
            if r.get("label") == label and str(r.get("budget")) != str(budget):
                sys.exit("REFUSED: label %s already carries budget %s in %s - "
                         "rowgate.py groups by (label, threads), so a second "
                         "budget under this label would merge into one table. "
                         "Give every budget its own LABEL."
                         % (label, r.get("budget"), OUT))
    say("LADDER label=%s budget=%s rungs=%s threads=%s reps=%d arms=%s n=%d"
        % (label, budget, RUNGS, THREADS, REPS, ARMS, N_SLICES))
    seen = {}
    with open(OUT, "a") as f:
        for t in THREADS:
            for m in RUNGS:
                for rep in range(REPS):
                    order = ARMS if rep % 2 == 0 else list(reversed(ARMS))
                    for arm in order:
                        rec = leg(m, budget, arm, t, rep, label)
                        key = (t, m)
                        if rec.get("digest"):
                            if key in seen and seen[key] != rec["digest"]:
                                rec["ok"] = False
                                rec["why"] = "digest %s != %s at this rung" % (
                                    rec["digest"], seen[key])
                            else:
                                seen.setdefault(key, rec["digest"])
                                rec["ok"] = True
                        else:
                            rec["ok"] = False
                        f.write(json.dumps(rec) + "\n")
                        f.flush()
                        say("LEG %s m=%-4d t=%-3d %-6s r%d rc=%s cpu=%-7s wall=%-7.2f "
                            "route=%-6s passes=%-3s cold=%-3s foreign=%.0f/%.0f%% ok=%s %s"
                            % (label, m, t, arm, rep, rec["rc"], rec.get("cpu"),
                               rec["wall"], rec["route"], rec["passes"],
                               rec.get("cold"), rec["foreign_cpu"],
                               rec["foreign_after"], rec.get("ok"),
                               rec.get("digest", rec.get("why", ""))))
    clean()
    say("LADDER done -> %s" % OUT)


def main():
    build_fixture()
    if len(sys.argv) > 1 and sys.argv[1] == "probe":
        run_probe()
    else:
        run_ladder()


if __name__ == "__main__":
    main()
