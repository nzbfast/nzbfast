#!/usr/bin/env python3
"""RAR5 creation LEVEL LADDER: rladder.py --payload DIR --work DIR --rounds N
   --bin ours=PATH --bin rar=PATH --unrar PATH [--only mixed,small] [--label box]

One row per rung, so the cost of each level in CPU per byte saved is readable
straight off the table. The rungs are the writer's own levels - lazy parser
and the cost-based optimal parse (`-mo`), each at 128 KiB (the writer's
default through 7 Sep 2026) and at rar's own 32 MiB (where the tree match
finder is on, since it arms at 4 MiB). The rungs name their dictionaries
explicitly and so are unaffected by the default moving to 2 MiB on 8 Sep 2026;
`ours-2m` is that new default's rung - beside rar 7.23's `-m1`, `-m3`, `-m5` and `-m5 -mcx`, its
exhaustive search. Added 7 Sep 2026 for the public-position re-bench; the
seven-shape competitive race is `crace.py` and stays as it is.

Per cell: outputs removed, the child run under a monotonic clock and reaped
with wait4 so user/sys/maxrss are THIS cell's, packed bytes summed, and every
RAR output verified with `unrar t` before it counts. Rounds run the rung order
and then its reverse, as crace.py's mirror does, so no rung holds one position.

Payloads: `mixed` is the 1 GiB mixed.bin, `small` the 400-file set.
"""
import argparse, glob, os, statistics, subprocess, sys, tempfile, time

# name: (tool, argv template). `ours` is rar5cli; `rar` is RARLab's.
RUNGS = [
    ("ours-128k",     "ours", "{ours} a -m3 -md131072 {out}.rar {inputs}"),
    ("ours-128k-mo",  "ours", "{ours} a -m3 -mo -md131072 {out}.rar {inputs}"),
    ("ours-2m",       "ours", "{ours} a -m3 -md2097152 {out}.rar {inputs}"),
    ("ours-4m",       "ours", "{ours} a -m3 -md4194304 {out}.rar {inputs}"),
    ("ours-32m",      "ours", "{ours} a -m3 -md33554432 {out}.rar {inputs}"),
    ("ours-32m-mo",   "ours", "{ours} a -m3 -mo -md33554432 {out}.rar {inputs}"),
    ("rar-m1",        "rar",  "{rar} a -ma5 -m1 -ep -idq -y -o+ {out}.rar {inputs}"),
    ("rar-m3",        "rar",  "{rar} a -ma5 -m3 -ep -idq -y -o+ {out}.rar {inputs}"),
    ("rar-m5",        "rar",  "{rar} a -ma5 -m5 -ep -idq -y -o+ {out}.rar {inputs}"),
    ("rar-m5-mcx",    "rar",  "{rar} a -ma5 -m5 -mcx -ep -idq -y -o+ {out}.rar {inputs}"),
]
# Research builds only (--features parallel,ratio-lab); stride 1 is the control.
for sample in (1, 2, 4, 8):
    for optimal in (False, True):
        suffix = "-mo" if optimal else ""
        RUNGS.append((f"ours-32m-s{sample}{suffix}", "lab",
                      f"env RARS_TREE_SAMPLE_STRIDE={sample} {{lab}} a -m3 "
                      f"{'-mo ' if optimal else ''}-md33554432 {{out}}.rar {{inputs}}"))

for depth in (8, 16, 32, 64):
    for optimal in (False, True):
        suffix = "-mo" if optimal else ""
        RUNGS.append((f"ours-32m-chain{depth}{suffix}", "lab",
                      f"env RARS_TREE_CHAIN_DEPTH={depth} {{lab}} a -m3 "
                      f"{'-mo ' if optimal else ''}-md33554432 {{out}}.rar {{inputs}}"))

for optimal in (False, True):
    suffix = "-mo" if optimal else ""
    RUNGS.append((f"ours-32m-hash8{suffix}", "lab",
                  f"env RARS_TREE_HASH8=1 {{lab}} a -m3 "
                  f"{'-mo ' if optimal else ''}-md33554432 {{out}}.rar {{inputs}}"))

for optimal in (False, True):
    suffix = "-mo" if optimal else ""
    RUNGS.append((f"ours-32m-multihash{suffix}", "lab",
                  f"env RARS_TREE_MULTI_HASH=1 {{lab}} a -m3 "
                  f"{'-mo ' if optimal else ''}-md33554432 {{out}}.rar {{inputs}}"))

for finder, variable in (("hash8", "RARS_TREE_HASH8"), ("multihash", "RARS_TREE_MULTI_HASH")):
    for optimal in (False, True):
        suffix = "-mo" if optimal else ""
        RUNGS.append((f"ours-32m-{finder}{suffix}-mh", "lab",
                      f"env {variable}=1 {{lab}} a -m3 -mh "
                      f"{'-mo ' if optimal else ''}-md33554432 {{out}}.rar {{inputs}}"))

for optimal in (False, True):
    suffix = "-mo" if optimal else ""
    RUNGS.append((f"ours-32m-multihash2{suffix}-mh", "lab",
                  f"env RARS_TREE_MULTI_HASH=8,16 {{lab}} a -m3 -mh "
                  f"{'-mo ' if optimal else ''}-md33554432 {{out}}.rar {{inputs}}"))

PAYLOADS = {"mixed": "mixed.bin", "small": "small/*"}


def outputs(out):
    return sorted(glob.glob(out + "*"))


def clear(out):
    for f in outputs(out):
        os.remove(f)


def run_cell(cmd):
    with tempfile.TemporaryFile() as o, tempfile.TemporaryFile() as e:
        t0 = time.perf_counter()
        p = subprocess.Popen(cmd, shell=True, stdout=o, stderr=e)
        _, status, ru = os.wait4(p.pid, 0)
        wall = time.perf_counter() - t0
        rc = os.waitstatus_to_exitcode(status)
        e.seek(0); o.seek(0)
        tail = (e.read() or o.read())[-200:].decode(errors="replace")
    return wall, ru.ru_utime, ru.ru_stime, ru.ru_maxrss, rc, tail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--bin", action="append", default=[])
    ap.add_argument("--unrar", required=True)
    ap.add_argument("--only", default="mixed,small")
    ap.add_argument("--arms", default="", help="comma-separated rung names; default original rungs (sampling rungs require explicit selection)")
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    bins = dict(b.split("=", 1) for b in a.bin)
    bins.setdefault("lab", bins.get("ours", "ours"))
    sets = [s for s in a.only.split(",") if s in PAYLOADS]
    rungs = [r for r in RUNGS if (not a.arms and r[1] != "lab") or r[0] in a.arms.split(",")]
    requested = set(a.arms.split(",")) if a.arms else set()
    unknown = requested - {r[0] for r in RUNGS}
    if unknown:
        ap.error("unknown arms: " + ",".join(sorted(unknown)))
    if not sets or not rungs:
        ap.error("select at least one valid payload and rung")
    os.makedirs(a.work, exist_ok=True)
    for s in sets:
        for f in glob.glob(os.path.join(a.payload, PAYLOADS[s])):
            with open(f, "rb") as fh:
                while fh.read(1 << 24):
                    pass
    res, packed = {}, {}
    for r in range(a.rounds):
        rot = rungs[r % len(rungs):] + rungs[: r % len(rungs)]
        for order in (rot, rot[::-1]):
            for s in sets:
                inputs = " ".join(sorted(glob.glob(os.path.join(a.payload, PAYLOADS[s]))))
                for name, tool, tmpl in order:
                    out = os.path.join(a.work, f"{s}-{name}")
                    clear(out)
                    cmd = tmpl.format(out=out, inputs=inputs, **{k: bins.get(k, k) for k in ("rar", "ours", "lab")})
                    wall, ut, st, rss, rc, tail = run_cell(cmd)
                    files = outputs(out)
                    size = sum(os.path.getsize(f) for f in files)
                    if rc == 0 and files:
                        v = subprocess.run([a.unrar, "t", "-inul", "-p-", sorted(files)[0]], capture_output=True)
                        ver = "ok" if v.returncode == 0 else f"UNRAR-T-FAIL({v.returncode})"
                    else:
                        ver = f"RC={rc} {tail.strip()[-100:]}"
                    mb = 1048576 if sys.platform == "darwin" else 1024
                    print(f"RUNG {a.label} round={r} set={s} arm={name} wall_s={wall:.3f} "
                          f"user_s={ut:.2f} sys_s={st:.2f} maxrss_mb={rss / mb:.0f} "
                          f"bytes={size} files={len(files)} verify={ver}", flush=True)
                    if ver != "ok":
                        raise SystemExit("invalid archive: cell excluded; outputs retained for diagnosis")
                    res.setdefault((s, name), []).append((wall, ut, st, rss))
                    packed[(s, name)] = size
                    clear(out)
    print("== medians (wall s, user s, sys s, peak RSS MB, packed bytes)")
    for s in sets:
        for name, _, _ in rungs:
            if (s, name) in res:
                v = res[(s, name)]
                mb = 1048576 if sys.platform == "darwin" else 1024
                print(f"MEDRUNG {a.label} {s:6s} {name:13s} "
                      f"wall={statistics.median(x[0] for x in v):8.2f} "
                      f"user={statistics.median(x[1] for x in v):8.2f} "
                      f"sys={statistics.median(x[2] for x in v):6.2f} "
                      f"rss={statistics.median(x[3] for x in v) / mb:7.0f} "
                      f"bytes={packed[(s, name)]}")


main()
